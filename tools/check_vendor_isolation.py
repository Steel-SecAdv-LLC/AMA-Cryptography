#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — Vendor Isolation Gate (INVARIANT-1, enforced three ways)

INVARIANT-1 says no third-party cryptographic implementation may be linked,
imported or called by the shipped library.  Until this script existed, that
claim rested on:

* ``tools/check_corpus_originality.py``, which AST-scans for *subprocess*
  invocations of external crypto binaries (``openssl``, ``gpg``, …); and
* comments, naming, documentation and intent.

Nothing checked the three things that actually decide the question:

``linkage``
    What the built shared object *depends on* and what symbols it expects an
    external library to supply.  A ``find_package(OpenSSL)`` added to
    CMakeLists.txt, a system header that pulls in a vendor's inline
    implementation, or a `-lcrypto` inherited from a toolchain file would all
    produce a library that AMA's Python-level checks cannot see at all.

``runtime``
    What is actually resident in ``sys.modules`` after ``import
    ama_cryptography``.  Source scanning misses transitive imports: a module
    AMA imports for an unrelated reason that itself imports ``cryptography``
    puts an OpenSSL binding in the process, and no ``import`` statement in
    this repository names it.

``the comparator boundary``
    ``benchmarks/`` is explicitly authorised to invoke peer implementations —
    that is what a comparative benchmark *is* — and ``benchmarks/requirements-
    bench.txt`` pins them.  Authorisation for benchmarking is not
    authorisation for anything else, and the only thing keeping the
    comparators on their side of the line was that no package module happened
    to import ``benchmarks``.

All three are checked here, and the binary formats are parsed in-tree with
``struct`` rather than by shelling out to ``readelf`` / ``otool`` /
``dumpbin``: this gate must run on every platform the wheels are built on,
including runners where those tools are absent, and a gate that silently
skips is the failure mode this repository's audit exists to remove.

Forbidden vendors
-----------------
OpenSSL, libsodium, wolfSSL, Botan, Nettle, libgcrypt and mbedTLS may not
supply any internal cryptographic operation, primitive, helper, fallback or
processing step.  They are authorised **only** as explicitly isolated
benchmark comparators under ``benchmarks/``, and may not become required for
a normal build or for any non-benchmark execution path.

Checks
------
``--source ama_cryptography``
    No module under the package may import a forbidden vendor binding, and
    none may import ``benchmarks`` (which would drag the comparators into the
    package's own import graph).  Also flags a ``ctypes`` load whose library
    name is a forbidden vendor, which no ``import`` statement would reveal.

``--runtime``
    Imports the package in a clean subprocess and fails if any forbidden
    top-level module is resident afterwards.

``--library PATH``
    Parses the native library's own dependency records — ELF ``DT_NEEDED``
    plus undefined ``.dynsym`` entries, Mach-O ``LC_LOAD_DYLIB``, PE import
    directory — and fails on a forbidden vendor name or symbol prefix.

With no check selected, every check that can run in the current environment
runs.  ``--library`` is skipped only when no path is given; a path that is
given and cannot be parsed is an error, never a skip.

Exit codes
----------
``0``  every selected check passed
``1``  a violation was found, or a requested check could not be performed
``2``  usage error
"""

from __future__ import annotations

import argparse
import ast
import json
import struct
import subprocess
import sys
from pathlib import Path
from typing import Iterable, NamedTuple, Sequence


class Vendor(NamedTuple):
    """One forbidden implementation and every name it travels under."""

    name: str
    #: Top-level Python modules that bind it.
    modules: frozenset[str]
    #: Substrings that identify its shared library by file name.
    library_names: tuple[str, ...]
    #: Exported-symbol prefixes that identify it in a dynamic symbol table.
    symbol_prefixes: tuple[str, ...]


VENDORS: tuple[Vendor, ...] = (
    Vendor(
        name="OpenSSL",
        # `cryptography` and `pyOpenSSL` are OpenSSL bindings; `_ssl` and
        # `_hashlib` are CPython's own OpenSSL-backed stdlib accelerators and
        # are NOT listed — INVARIANT-1's stdlib carve-out admits `hashlib` for
        # hashing, and excluding them here would make this gate fail on a
        # stock interpreter rather than on an AMA defect.  See the module
        # docstring in tools/check_corpus_originality.py for the boundary.
        modules=frozenset({"OpenSSL", "cryptography"}),
        library_names=("libcrypto", "libssl", "libeay32", "ssleay32"),
        symbol_prefixes=("EVP_", "OPENSSL_", "SSL_", "X509_", "RAND_bytes"),
    ),
    Vendor(
        name="libsodium",
        modules=frozenset({"nacl"}),
        library_names=("libsodium",),
        symbol_prefixes=("sodium_", "crypto_sign_ed25519", "crypto_box_"),
    ),
    Vendor(
        name="wolfSSL",
        modules=frozenset({"wolfssl", "wolfcrypt"}),
        library_names=("libwolfssl", "wolfssl"),
        symbol_prefixes=("wolfSSL_", "wc_"),
    ),
    Vendor(
        name="Botan",
        modules=frozenset({"botan", "botan2", "botan3"}),
        library_names=("libbotan",),
        symbol_prefixes=("botan_",),
    ),
    Vendor(
        name="Nettle",
        modules=frozenset({"nettle"}),
        library_names=("libnettle", "libhogweed"),
        symbol_prefixes=("nettle_",),
    ),
    Vendor(
        name="libgcrypt",
        modules=frozenset({"gcrypt"}),
        library_names=("libgcrypt",),
        symbol_prefixes=("gcry_",),
    ),
    Vendor(
        name="mbedTLS",
        modules=frozenset({"mbedtls"}),
        library_names=("libmbedcrypto", "libmbedtls", "libmbedx509"),
        symbol_prefixes=("mbedtls_",),
    ),
    # Not in the owner's forbidden list, but they are peer implementations
    # pinned by benchmarks/requirements-bench.txt and would be exactly as
    # wrong inside the package.
    Vendor(
        name="PyCryptodome",
        modules=frozenset({"Crypto", "Cryptodome"}),
        library_names=(),
        symbol_prefixes=(),
    ),
)

#: The comparator package.  Authorised to import every vendor above; not
#: authorised to be imported BY the shipped package.
COMPARATOR_PACKAGE = "benchmarks"

_MODULE_TO_VENDOR: dict[str, str] = {
    module: vendor.name for vendor in VENDORS for module in vendor.modules
}


class Violation(NamedTuple):
    check: str
    where: str
    detail: str


# --------------------------------------------------------------------------
# Source check
# --------------------------------------------------------------------------

_CTYPES_LOADERS = {"CDLL", "cdll", "LoadLibrary", "WinDLL", "OleDLL", "find_library"}


def _root_module(dotted: str) -> str:
    return dotted.split(".", 1)[0]


def _string_literals(node: ast.AST) -> Iterable[str]:
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            yield child.value


def check_source(package_dir: Path) -> list[Violation]:
    """No package module may import a forbidden vendor or the comparators."""
    violations: list[Violation] = []
    files = sorted(package_dir.rglob("*.py"))
    if not files:
        return [
            Violation(
                "source",
                str(package_dir),
                "no Python sources found — refusing to report a clean scan of nothing",
            )
        ]

    for path in files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:  # pragma: no cover - a broken tree fails elsewhere
            violations.append(Violation("source", str(path), f"could not parse: {exc}"))
            continue

        for node in ast.walk(tree):
            lineno = getattr(node, "lineno", 0)
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                # `from . import x` has module=None; relative imports are
                # in-package by construction.
                if node.level == 0 and node.module:
                    names = [node.module]

            for dotted in names:
                root = _root_module(dotted)
                if root in _MODULE_TO_VENDOR:
                    violations.append(
                        Violation(
                            "source",
                            f"{path}:{lineno}",
                            f"imports {dotted!r} — {_MODULE_TO_VENDOR[root]} binding",
                        )
                    )
                elif root == COMPARATOR_PACKAGE:
                    violations.append(
                        Violation(
                            "source",
                            f"{path}:{lineno}",
                            f"imports {dotted!r} — the comparator package is "
                            f"authorised to use peer implementations and must "
                            f"not enter the shipped package's import graph",
                        )
                    )

            # A ctypes load names its library as a string, so no import
            # statement mentions it.  This is the shape a "transparent
            # fallback" would most plausibly take.
            if isinstance(node, ast.Call):
                func = node.func
                attr = func.attr if isinstance(func, ast.Attribute) else None
                ident = func.id if isinstance(func, ast.Name) else None
                if (attr in _CTYPES_LOADERS) or (ident in _CTYPES_LOADERS):
                    for literal in _string_literals(node):
                        lowered = literal.lower()
                        for vendor in VENDORS:
                            if any(lib in lowered for lib in vendor.library_names):
                                violations.append(
                                    Violation(
                                        "source",
                                        f"{path}:{lineno}",
                                        f"ctypes load of {literal!r} — {vendor.name}",
                                    )
                                )
    return violations


# --------------------------------------------------------------------------
# Runtime check
# --------------------------------------------------------------------------

_RUNTIME_PROBE = """
import json, sys
import ama_cryptography  # noqa: F401
print("@@AMA@@" + json.dumps(sorted({m.split(".", 1)[0] for m in sys.modules})))
"""


def check_runtime(repo_root: Path) -> list[Violation]:
    """After importing the package, no forbidden binding may be resident."""
    proc = subprocess.run(
        [sys.executable, "-c", _RUNTIME_PROBE],
        capture_output=True,
        text=True,
        cwd=repo_root,
    )
    if proc.returncode != 0:
        return [
            Violation(
                "runtime",
                "import ama_cryptography",
                "the package could not be imported, so no runtime evidence "
                "exists; build the native library first "
                f"(exit {proc.returncode}): {proc.stderr.strip()[-400:]}",
            )
        ]

    marker = "@@AMA@@"
    line = next(
        (ln for ln in proc.stdout.splitlines() if ln.startswith(marker)),
        None,
    )
    if line is None:
        return [
            Violation(
                "runtime",
                "import ama_cryptography",
                "the probe produced no module inventory — refusing to report clean",
            )
        ]

    resident = set(json.loads(line[len(marker) :]))
    violations = [
        Violation(
            "runtime",
            "sys.modules",
            f"{module!r} is resident after importing the package — " f"{_MODULE_TO_VENDOR[module]}",
        )
        for module in sorted(resident & set(_MODULE_TO_VENDOR))
    ]
    if COMPARATOR_PACKAGE in resident:
        violations.append(
            Violation(
                "runtime",
                "sys.modules",
                f"{COMPARATOR_PACKAGE!r} is resident after importing the package",
            )
        )
    return violations


# --------------------------------------------------------------------------
# Library check — ELF / Mach-O / PE parsed in-tree
# --------------------------------------------------------------------------


class BinaryInfo(NamedTuple):
    fmt: str
    dependencies: tuple[str, ...]
    undefined_symbols: tuple[str, ...]


def _parse_elf(data: bytes) -> BinaryInfo:
    if data[4] != 2:
        raise ValueError("only 64-bit ELF is supported")
    little = data[5] == 1
    end = "<" if little else ">"

    (e_shoff,) = struct.unpack_from(end + "Q", data, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(end + "HHH", data, 0x3A)

    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (
            sh_name,
            sh_type,
            _sh_flags,
            _sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            _sh_info,
            _sh_align,
            sh_entsize,
        ) = struct.unpack_from(end + "IIQQQQIIQQ", data, off)
        sections.append(
            {
                "name_off": sh_name,
                "type": sh_type,
                "offset": sh_offset,
                "size": sh_size,
                "link": sh_link,
                "entsize": sh_entsize,
            }
        )

    shstr = sections[e_shstrndx]

    def cstr(base: int, offset: int) -> str:
        stop = data.index(b"\0", base + offset)
        return data[base + offset : stop].decode("utf-8", "replace")

    by_name = {cstr(shstr["offset"], s["name_off"]): s for s in sections}

    dependencies: list[str] = []
    dynamic = by_name.get(".dynamic")
    dynstr = by_name.get(".dynstr")
    if dynamic is not None and dynstr is not None:
        dt_needed = 1
        for off in range(dynamic["offset"], dynamic["offset"] + dynamic["size"], 16):
            tag, val = struct.unpack_from(end + "qQ", data, off)
            if tag == 0:  # DT_NULL
                break
            if tag == dt_needed:
                dependencies.append(cstr(dynstr["offset"], val))

    undefined: list[str] = []
    dynsym = by_name.get(".dynsym")
    if dynsym is not None and dynsym["entsize"]:
        strtab = sections[dynsym["link"]]
        count = dynsym["size"] // dynsym["entsize"]
        for i in range(count):
            off = dynsym["offset"] + i * dynsym["entsize"]
            st_name, _st_info, _st_other, st_shndx = struct.unpack_from(end + "IBBH", data, off)
            if st_shndx == 0 and st_name:  # SHN_UNDEF
                undefined.append(cstr(strtab["offset"], st_name))

    return BinaryInfo("ELF", tuple(dependencies), tuple(undefined))


def _parse_macho(data: bytes) -> BinaryInfo:
    magics = {
        0xFEEDFACF: ("<", True),
        0xCFFAEDFE: ("<", True),
        0xFEEDFACE: ("<", False),
        0xCEFAEDFE: ("<", False),
    }
    (magic,) = struct.unpack_from("<I", data, 0)
    if magic not in magics:
        raise ValueError("not a thin Mach-O image")
    end, is64 = magics[magic]
    header_size = 32 if is64 else 28
    (ncmds,) = struct.unpack_from(end + "I", data, 16)

    lc_load_dylib = 0x0C
    lc_load_weak_dylib = 0x80000018
    lc_reexport_dylib = 0x8000001F

    dependencies: list[str] = []
    offset = header_size
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from(end + "II", data, offset)
        if cmd in (lc_load_dylib, lc_load_weak_dylib, lc_reexport_dylib):
            (name_off,) = struct.unpack_from(end + "I", data, offset + 8)
            raw = data[offset + name_off : offset + cmdsize]
            dependencies.append(raw.split(b"\0", 1)[0].decode("utf-8", "replace"))
        offset += cmdsize
    return BinaryInfo("Mach-O", tuple(dependencies), ())


def _parse_pe(data: bytes) -> BinaryInfo:
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise ValueError("not a PE image")
    (num_sections,) = struct.unpack_from("<H", data, e_lfanew + 6)
    (opt_size,) = struct.unpack_from("<H", data, e_lfanew + 20)
    opt_off = e_lfanew + 24
    (magic,) = struct.unpack_from("<H", data, opt_off)
    # 0x20B = PE32+, 0x10B = PE32; the data-directory offset differs.
    dd_off = opt_off + (112 if magic == 0x20B else 96)
    import_rva, _import_size = struct.unpack_from("<II", data, dd_off + 8)

    sec_off = opt_off + opt_size
    sections = []
    for i in range(num_sections):
        off = sec_off + i * 40
        virt_size, virt_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append((virt_addr, max(virt_size, raw_size), raw_ptr))

    def rva_to_off(rva: int) -> int | None:
        for virt_addr, size, raw_ptr in sections:
            if virt_addr <= rva < virt_addr + size:
                return int(raw_ptr) + (rva - int(virt_addr))
        return None

    dependencies: list[str] = []
    if import_rva:
        table = rva_to_off(import_rva)
        if table is not None:
            while True:
                entry = data[table : table + 20]
                if len(entry) < 20 or entry == b"\0" * 20:
                    break
                (name_rva,) = struct.unpack_from("<I", entry, 12)
                name_off = rva_to_off(name_rva)
                if name_off is not None:
                    stop = data.index(b"\0", name_off)
                    dependencies.append(data[name_off:stop].decode("utf-8", "replace"))
                table += 20
    return BinaryInfo("PE", tuple(dependencies), ())


def parse_binary(path: Path) -> BinaryInfo:
    data = path.read_bytes()
    if data[:4] == b"\x7fELF":
        return _parse_elf(data)
    if data[:2] == b"MZ":
        return _parse_pe(data)
    if len(data) >= 4 and struct.unpack_from("<I", data, 0)[0] in (
        0xFEEDFACF,
        0xCFFAEDFE,
        0xFEEDFACE,
        0xCEFAEDFE,
    ):
        return _parse_macho(data)
    raise ValueError(f"unrecognised binary format (first bytes: {data[:8]!r})")


def check_library(path: Path) -> list[Violation]:
    """The built library may not depend on, or import symbols from, a vendor."""
    if not path.is_file():
        return [Violation("library", str(path), "no such file — refusing to report clean")]
    try:
        info = parse_binary(path)
    except (ValueError, struct.error, IndexError) as exc:
        return [Violation("library", str(path), f"could not parse: {exc}")]

    violations: list[Violation] = []
    for dependency in info.dependencies:
        lowered = dependency.lower()
        for vendor in VENDORS:
            if any(lib in lowered for lib in vendor.library_names):
                violations.append(
                    Violation(
                        "library",
                        f"{path} [{info.fmt}]",
                        f"links against {dependency!r} — {vendor.name}",
                    )
                )
    for symbol in info.undefined_symbols:
        for vendor in VENDORS:
            if any(symbol.startswith(prefix) for prefix in vendor.symbol_prefixes):
                violations.append(
                    Violation(
                        "library",
                        f"{path} [{info.fmt}]",
                        f"imports undefined symbol {symbol!r} — {vendor.name}",
                    )
                )
    return violations


# --------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify that no forbidden vendor performs internal work."
    )
    parser.add_argument(
        "--package",
        type=Path,
        default=Path("ama_cryptography"),
        help="package directory to scan (default: ama_cryptography)",
    )
    parser.add_argument(
        "--library",
        type=Path,
        action="append",
        default=[],
        help="built native library to inspect; repeatable",
    )
    parser.add_argument("--source", action="store_true", help="run only the source check")
    parser.add_argument("--runtime", action="store_true", help="run only the runtime import check")
    parser.add_argument(
        "--no-runtime",
        action="store_true",
        help="skip the runtime check (for trees with no built native library)",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    selected_source = args.source or not (args.source or args.runtime)
    selected_runtime = (args.runtime or not (args.source or args.runtime)) and not args.no_runtime

    repo_root = Path(__file__).resolve().parent.parent
    violations: list[Violation] = []
    ran: list[str] = []

    if selected_source:
        violations += check_source(args.package)
        ran.append(f"source ({args.package})")
    if selected_runtime:
        violations += check_runtime(repo_root)
        ran.append("runtime (import ama_cryptography)")
    for library in args.library:
        violations += check_library(library)
        ran.append(f"library ({library})")

    if not ran:
        print("ERROR: no check was selected.", file=sys.stderr)
        return 2

    if violations:
        print("VENDOR ISOLATION FAILED (INVARIANT-1):", file=sys.stderr)
        for violation in violations:
            print(f"  [{violation.check}] {violation.where}: {violation.detail}", file=sys.stderr)
        print(
            "\nThe listed implementations are authorised only as explicitly "
            "isolated benchmark comparators under benchmarks/.  They may not "
            "supply internal functionality, act as a fallback, or influence a "
            "non-benchmark execution path.",
            file=sys.stderr,
        )
        return 1

    print("OK: vendor isolation holds. Checks run:")
    for name in ran:
        print(f"  - {name}")
    print(f"  vendors screened: {', '.join(v.name for v in VENDORS)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
