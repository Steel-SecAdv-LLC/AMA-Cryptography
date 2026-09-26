#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Compare the documented public API against what a user can actually reach.

The fact this gate protects
---------------------------
An API reference is a contract. The reader cannot check it without writing the
program, and when it is wrong they conclude the library is broken. Before this
gate the reference asserted, among other things:

* that eight submodules are "always available" after ``import ama_cryptography``.
  Five of those eight raise ``AttributeError``; the package's PEP 562
  ``__getattr__`` resolves *symbol* names, not submodule names. The two it
  listed as lazily loaded are in fact imported eagerly.
* that ``secure_mlock()`` returns ``True`` on success. It returns ``None`` and
  raises on failure, so ``if secure_mlock(buf):`` takes the failure branch on
  every successful lock.
* that ``with SecureBuffer(32) as buf`` yields something with a ``.data``
  attribute. ``__enter__`` yields the ``bytearray`` itself.
* that ``get_pqc_status()`` returns a dict, printed with a worked JSON example.
  It returns a ``PQCStatus`` enum.
* that ``ama_randombytes`` is exported from the shared library and linkable by
  an out-of-tree caller, with the ``extern`` declaration to use.
  ``cmake/ama_exports.map`` names it in the ``local:`` list; ``nm --dynamic``
  finds nothing. The recipe has never linked.
* that ``src/c/neon/`` holds eight files including an Ed25519 kernel. There are
  seven, and no Ed25519 NEON kernel has ever existed.

Each is a different failure — a name, a return type, a context-manager
protocol, a linker symbol, a file inventory — and each needs a different
oracle. They are checked here together because they fail the same way: silently,
until a user hits them.

What is checked
---------------
1. **Bare-import reachability.** The exact set of public submodules bound as
   attributes by ``import ama_cryptography``, against the documented set.
2. **Signatures and required parameters**, for a declared contract table:
   parameter names in order, and which have no default.
3. **Return types**, by *calling* the function where that is safe and asserting
   the runtime type — a stronger oracle than an annotation, which can itself be
   wrong.
4. **Context-manager return values** — what ``__enter__`` actually yields.
5. **C export map versus produced symbols.** Every name the version script
   localises must be absent from the built library's dynamic symbols, and every
   ``AMA_API`` prototype in the public header must be present. That is the
   bidirectional check: a localised name silently exported is an unintended ABI
   surface, and a documented name silently localised is a broken link recipe.
   And every exported ``ama_*`` symbol must be declared ``AMA_API`` in a header
   the build installs (``PUBLIC_HEADER`` in CMakeLists.txt): the version script
   exports the ``ama_*`` wildcard, so an undeclared non-static helper is
   otherwise public ABI with no prototype anyone can see.
6. **HSS/LMS exports**, named explicitly because their absence was documented.
7. **Architecture-specific implementation claims**, e.g. the per-directory SIMD
   kernel inventory and the algorithms each covers.

Where a built library is not available (a documentation-only CI lane) the
symbol checks report as skipped rather than passing vacuously, and the exit
status distinguishes the two: a run that skipped them exits 3, never 0.
``--require-library`` turns the skip into exit 2 instead.

Exit status
-----------
0  every documented API claim matches the package, the C export checks included
1  at least one does not
2  the check could not run (including ``--require-library`` with no library)
3  every claim that was checked matches, but the C export checks were SKIPPED
   because no built library was found — not a pass
"""

from __future__ import annotations

import argparse
import contextlib
import importlib
import inspect
import io
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Sequence

REPO = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Declared contracts
# ---------------------------------------------------------------------------

#: The pure-Python public submodules a bare ``import ama_cryptography`` binds.
#: Anything here that stops being bound, and anything bound that is not here,
#: fails — both directions, because the documented list was wrong in both (it
#: promised five modules that raise AttributeError and described two eager
#: imports as lazy).
EXPECTED_BARE_IMPORT_SUBMODULES: frozenset[str] = frozenset(
    {
        "double_helix_engine",
        "equations",
        "exceptions",
        "pqc_backends",
        "secure_memory",
    }
)

#: Compiled Cython FFI bindings.  ``pqc_backends`` imports whichever of these
#: the build produced, so they appear as package attributes on a built tree and
#: not on a source checkout.  They are an optimisation, never a correctness
#: dependency, and they are not part of the documented public surface — so the
#: comparison above tolerates their presence and says nothing about it either
#: way.  Treating a build-config difference as API drift would make this gate
#: fail on exactly the tree it is meant to protect.
CYTHON_BINDING_SUBMODULES: frozenset[str] = frozenset(
    {
        "dilithium_binding",
        "ed25519_binding",
        "hkdf_binding",
        "hmac_binding",
        "math_engine",
        "sha3_binding",
    }
)

#: ``(module, qualified name, ordered parameters, required parameters)``.
#: These are the signatures whose drift caused a documented example to raise.
SIGNATURE_CONTRACTS: tuple[tuple[str, str, tuple[str, ...], frozenset[str]], ...] = (
    (
        "ama_cryptography.legacy_compat",
        "create_crypto_package",
        ("codes", "helix_params", "kms", "author", "use_rfc3161", "tsa_url", "monitor"),
        frozenset({"codes", "helix_params", "kms", "author"}),
    ),
    (
        "ama_cryptography.legacy_compat",
        "verify_crypto_package",
        ("codes", "helix_params", "package", "hmac_key", "monitor", "require_quantum_signatures"),
        frozenset({"codes", "helix_params", "package", "hmac_key"}),
    ),
    (
        "ama_cryptography.legacy_compat",
        "generate_key_management_system",
        ("author", "ethical_vector"),
        frozenset({"author"}),
    ),
    (
        "ama_cryptography.secure_memory",
        "secure_mlock",
        ("data",),
        frozenset({"data"}),
    ),
    (
        "ama_cryptography.secure_memory",
        "secure_munlock",
        ("data",),
        frozenset({"data"}),
    ),
    (
        "ama_cryptography.secure_memory",
        "secure_memzero",
        ("data",),
        frozenset({"data"}),
    ),
    (
        "ama_cryptography.secure_memory",
        "SecureBuffer",
        ("size", "lock"),
        frozenset({"size"}),
    ),
    (
        "ama_cryptography.key_management",
        "SecureKeyStorage",
        ("storage_path", "master_password", "allow_legacy_kdf"),
        frozenset({"storage_path"}),
    ),
)

#: ``(module, name, callable producing a call, expected runtime type)``.
#: The type is asserted from a real call, not from ``__annotations__`` — an
#: annotation is a claim about the code in exactly the way this gate exists to
#: stop trusting.
RETURN_TYPE_CONTRACTS: tuple[tuple[str, str, str], ...] = (
    ("ama_cryptography.pqc_backends", "get_pqc_status", "PQCStatus"),
    ("ama_cryptography.pqc_backends", "get_pqc_backend_info", "dict"),
    ("ama_cryptography.secure_memory", "secure_mlock", "NoneType"),
    ("ama_cryptography.secure_memory", "secure_munlock", "NoneType"),
    ("ama_cryptography.secure_memory", "secure_memzero", "NoneType"),
    ("ama_cryptography.secure_memory", "is_available", "bool"),
    ("ama_cryptography.secure_memory", "get_status", "dict"),
)

#: ``(module, name, constructor args, type __enter__ must yield)``.
CONTEXT_MANAGER_CONTRACTS: tuple[tuple[str, str, tuple[Any, ...], str], ...] = (
    ("ama_cryptography.secure_memory", "SecureBuffer", (32,), "bytearray"),
)

#: Symbols the version script deliberately localises.  Each must be ABSENT from
#: the built library's dynamic symbol table.  Documented as linkable, any of
#: these is a recipe that fails at link time.
MUST_NOT_BE_EXPORTED: tuple[str, ...] = (
    "ama_randombytes",
    "ama_ascon_permutation_for_test",
    "ama_slhdsa_sign_internal",
    "ama_slhdsa_verify_internal",
    "ama_aes256_gcm_encrypt_vaes_avx2",
    "ama_sha256_init",
    "ama_keccak_f1600_generic",
)

#: Symbols documentation names as part of the ABI.  Each must be PRESENT.
#: The HSS/LMS entries are here by name because their absence was documented.
MUST_BE_EXPORTED: tuple[str, ...] = (
    "ama_lms_verify",
    "ama_hss_verify",
    "ama_lms_pubkey_params",
    "ama_lms_signature_length",
    "ama_lms_signing_available",
    "ama_hss_pubkey_levels",
    "ama_ed25519_keypair",
    "ama_ed25519_sign",
    "ama_ed25519_expand_secret_key",
    "ama_ed25519_sign_expanded",
    "ama_ed25519_verify",
    "ama_keypair_generate",
    "ama_context_init",
    "ama_context_free",
    "ama_secure_memzero",
    "ama_hkdf",
    "ama_sha3_256",
)

#: Architecture-specific implementation claims: directory -> the algorithms the
#: documentation says it covers, one ``.c`` translation unit each.  README.md
#: claimed eight NEON algorithms including Ed25519 against seven files.
SIMD_INVENTORY: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "src/c/neon",
        (
            "ama_aes_gcm_neon.c",
            "ama_argon2_neon.c",
            "ama_chacha20poly1305_neon.c",
            "ama_dilithium_neon.c",
            "ama_kyber_neon.c",
            "ama_sha3_neon.c",
            "ama_sphincs_neon.c",
        ),
    ),
    (
        "src/c/sve2",
        (
            "ama_aes_gcm_sve2.c",
            "ama_argon2_sve2.c",
            "ama_chacha20poly1305_sve2.c",
            "ama_dilithium_sve2.c",
            "ama_ed25519_sve2.c",
            "ama_kyber_sve2.c",
            "ama_sha3_sve2.c",
            "ama_sphincs_sve2.c",
        ),
    ),
    ("src/c/avx512", ("ama_sha3_x4_avx512.c",)),
)


@dataclass
class Report:
    failures: list[str] = field(default_factory=list)
    checked: int = 0
    skipped: list[str] = field(default_factory=list)

    def fail(self, detail: str) -> None:
        self.failures.append(detail)

    def ok(self) -> None:
        self.checked += 1


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def check_bare_import(report: Report) -> None:
    """Which public submodules a bare ``import ama_cryptography`` binds."""
    script = (
        "import types, ama_cryptography as a;"
        "print(' '.join(sorted(n for n, v in vars(a).items()"
        " if isinstance(v, types.ModuleType)"
        " and getattr(v, '__name__', '').startswith('ama_cryptography.')"
        " and not n.startswith('_'))))"
    )
    environment = dict(os.environ)
    environment.setdefault("PYTHONPATH", str(REPO))
    environment["PYTHONWARNINGS"] = "ignore"
    completed = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        env=environment,
        check=False,
    )
    if completed.returncode != 0:
        report.fail(
            "a bare `import ama_cryptography` failed:\n      "
            + "\n      ".join(completed.stderr.strip().splitlines()[-6:])
        )
        return
    bound = frozenset(completed.stdout.split()) - CYTHON_BINDING_SUBMODULES
    if bound != EXPECTED_BARE_IMPORT_SUBMODULES:
        extra = sorted(bound - EXPECTED_BARE_IMPORT_SUBMODULES)
        missing = sorted(EXPECTED_BARE_IMPORT_SUBMODULES - bound)
        report.fail(
            "the set of submodules bound by a bare `import ama_cryptography` "
            f"changed. Newly bound: {extra or 'none'}. No longer bound: "
            f"{missing or 'none'}. wiki/API-Reference.md publishes this list; "
            "update both together, and remember the package's PEP 562 "
            "__getattr__ resolves SYMBOL names, not submodule names."
        )
        return
    report.ok()


def check_signatures(report: Report) -> None:
    for module_name, name, parameters, required in SIGNATURE_CONTRACTS:
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:  # pragma: no cover
            report.fail(f"cannot import {module_name}: {exc!r}")
            continue
        target = getattr(module, name, None)
        if target is None:
            report.fail(f"{module_name} no longer provides {name!r}")
            continue
        signature = inspect.signature(target)
        actual = tuple(
            parameter.name
            for parameter in signature.parameters.values()
            if parameter.name != "self"
            and parameter.kind
            not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
        )
        if actual != parameters:
            report.fail(f"{module_name}.{name} parameters are {actual}, documented as {parameters}")
            continue
        actual_required = frozenset(
            parameter.name
            for parameter in signature.parameters.values()
            if parameter.name != "self"
            and parameter.default is inspect.Parameter.empty
            and parameter.kind
            not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
        )
        if actual_required != required:
            report.fail(
                f"{module_name}.{name} required parameters are "
                f"{sorted(actual_required)}, documented as {sorted(required)}"
            )
            continue
        report.ok()


_RETURN_CALL_ARGS: dict[str, tuple[Any, ...]] = {
    "get_pqc_status": (),
    "get_pqc_backend_info": (),
    "is_available": (),
    "get_status": (),
}


def check_return_types(report: Report) -> None:
    """Assert return types from real calls, not from annotations."""
    for module_name, name, expected in RETURN_TYPE_CONTRACTS:
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:  # pragma: no cover
            report.fail(f"cannot import {module_name}: {exc!r}")
            continue
        target = getattr(module, name, None)
        if target is None:
            report.fail(f"{module_name} no longer provides {name!r}")
            continue
        if name in _RETURN_CALL_ARGS:
            args: tuple[Any, ...] = _RETURN_CALL_ARGS[name]
        else:
            # The memory primitives take a buffer; give each its own so a wipe
            # in one check cannot mask a failure in another.
            args = (bytearray(32),)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                if name == "secure_munlock":
                    # Unlocking a page that was never locked is not a defined
                    # operation: Linux's munlock(2) tolerates it, Windows'
                    # VirtualUnlock returns ERROR_NOT_LOCKED and the wrapper
                    # raises. This check is about the RETURN TYPE, so it has to
                    # exercise the call the way a caller would — lock first.
                    module.secure_mlock(*args)
                value = target(*args)
        except Exception as exc:
            report.fail(f"{module_name}.{name}{args!r} raised {exc!r}")
            continue
        actual = type(value).__name__
        if actual != expected:
            report.fail(
                f"{module_name}.{name}() returns {actual} ({value!r}), documented as "
                f"{expected}. A documented boolean that is really None makes "
                "`if f(...):` take the failure branch on every success."
            )
            continue
        report.ok()


def check_context_managers(report: Report) -> None:
    for module_name, name, args, expected in CONTEXT_MANAGER_CONTRACTS:
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:  # pragma: no cover
            report.fail(f"cannot import {module_name}: {exc!r}")
            continue
        factory = getattr(module, name, None)
        if factory is None:
            report.fail(f"{module_name} no longer provides {name!r}")
            continue
        try:
            with factory(*args) as yielded:
                actual = type(yielded).__name__
        except Exception as exc:
            report.fail(f"`with {module_name}.{name}{args!r}` raised {exc!r}")
            continue
        if actual != expected:
            report.fail(
                f"`with {module_name}.{name}{args!r} as x` yields {actual}, "
                f"documented as {expected}. Every attribute the documentation "
                "shows on `x` is an AttributeError when this is wrong."
            )
            continue
        report.ok()


_AMA_API = re.compile(r"AMA_API\s+[A-Za-z_][\w \*]*?\b(ama_[A-Za-z0-9_]+)\s*\(")

#: A real C entry point is a plain identifier.  Anything else on the export
#: table is a linker or compiler artefact rather than something a consumer
#: was meant to call.
_PLAIN_SYMBOL = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


#: Magic bytes to object format.  Mach-O appears in both byte orders and in the
#: fat/universal wrapper, because a macOS runner may produce any of them.
_OBJECT_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"\xfe\xed\xfa\xce", "macho"),
    (b"\xfe\xed\xfa\xcf", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\xca\xfe\xba\xbe", "macho"),
)


def object_format(library: Path) -> str:
    """``elf`` / ``pe`` / ``macho``, read from the file's magic bytes.

    Not from the file extension: a CI lane may hand this an unsuffixed path, a
    versioned ``.so.5.0.0`` or a ``.dll`` whose name says nothing about what is
    inside it.
    """
    with library.open("rb") as handle:
        head = handle.read(4)
    for magic, name in _OBJECT_MAGIC:
        if head.startswith(magic):
            return name
    raise RuntimeError(
        f"{library} is not an object file this gate can read "
        f"(magic {head!r}); it reads ELF, PE and Mach-O."
    )


def _nm_symbols(library: Path, argv: Sequence[str]) -> frozenset[str]:
    completed = subprocess.run(
        ["nm", *argv, str(library)], capture_output=True, text=True, check=False
    )
    if completed.returncode != 0:
        raise RuntimeError(f"nm failed on {library}: {completed.stderr.strip()}")
    names: set[str] = set()
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] in {"T", "W", "i", "D", "B", "R", "S"}:
            # Mach-O prefixes C symbols with an underscore; ELF does not.
            names.add(parts[0][1:] if parts[0].startswith("_ama_") else parts[0])
    return frozenset(names)


#: The same request in the two spellings macOS may answer to.  `--dynamic` is
#: GNU-only and Mach-O has no dynamic-symbol section to ask for: a dylib's
#: exports are its defined external symbols.  Xcode ships LLVM's nm, which
#: takes the long options; cctools nm takes only the classic short ones, and
#: which of the two is `/usr/bin/nm` depends on the runner image.  Asking both
#: is tool-invocation portability, not a fallback: the answer either names
#: ama_* symbols or `dynamic_symbols` refuses it.
_MACHO_NM_ARGV: tuple[tuple[str, ...], ...] = (
    ("-g", "--defined-only", "--format=posix"),
    ("-g", "-U", "-P"),
)


def _macho_symbols(library: Path) -> frozenset[str]:
    attempts: list[str] = []
    for argv in _MACHO_NM_ARGV:
        try:
            names = _nm_symbols(library, argv)
        except RuntimeError as exc:
            attempts.append(f"nm {' '.join(argv)}: {exc}")
            continue
        if any(name.startswith("ama_") for name in names):
            return names
        attempts.append(f"nm {' '.join(argv)}: exited 0 but named no ama_* symbol")
    raise RuntimeError(f"no nm invocation read {library} as Mach-O. " + "; ".join(attempts))


def pe_export_names(library: Path) -> frozenset[str]:
    """The names in a PE image's export directory.

    ``nm --dynamic`` does not read PE: run against a MinGW-built DLL that
    demonstrably exports ``ama_sha3_256`` it prints "no symbols" and **exits
    zero**, so the caller sees an empty set and reports every documented symbol
    as missing.  That is what the windows-latest lane reported on a098d8ba —
    sixteen ABI failures that did not exist, and, worse, a reading under which a
    genuinely dropped export would have been indistinguishable from the noise.

    So the export directory is read directly, which needs no toolchain on the
    host and gives the same answer everywhere.  Layout: PE/COFF specification
    §3 (headers), §5.3 (the ``.edata`` export directory).
    """
    image = library.read_bytes()

    def u16(offset: int) -> int:
        return int.from_bytes(image[offset : offset + 2], "little")

    def u32(offset: int) -> int:
        return int.from_bytes(image[offset : offset + 4], "little")

    pe = u32(0x3C)  # IMAGE_DOS_HEADER.e_lfanew
    if image[pe : pe + 4] != b"PE\0\0":
        raise RuntimeError(f"{library}: no PE signature at e_lfanew {pe:#x}")
    sections = u16(pe + 6)
    optional_size = u16(pe + 20)
    optional = pe + 24
    magic = u16(optional)
    if magic == 0x20B:  # PE32+
        directories = optional + 112
    elif magic == 0x10B:  # PE32
        directories = optional + 96
    else:
        raise RuntimeError(f"{library}: unknown optional-header magic {magic:#x}")

    # Section table maps a relative virtual address onto a file offset.
    table = optional + optional_size
    layout = [
        (u32(entry + 12), u32(entry + 8), u32(entry + 20))  # rva, virtual size, raw offset
        for entry in (table + 40 * index for index in range(sections))
    ]

    def offset_of(rva: int) -> int:
        for start, size, raw in layout:
            if start <= rva < start + size:
                return raw + (rva - start)
        raise RuntimeError(f"{library}: RVA {rva:#x} is in no section")

    export_rva = u32(directories)
    if export_rva == 0:  # no export directory at all
        return frozenset()
    export = offset_of(export_rva)
    name_count = u32(export + 24)
    names_rva = u32(export + 32)
    names_table = offset_of(names_rva)

    names: set[str] = set()
    for index in range(name_count):
        start = offset_of(u32(names_table + 4 * index))
        end = image.index(b"\0", start)
        names.add(image[start:end].decode("ascii"))
    return frozenset(names)


def dynamic_symbols(library: Path) -> frozenset[str]:
    """Every name an out-of-tree consumer can resolve against ``library``.

    Fails closed.  A reader that cannot understand the format in front of it
    must say so, because the alternative — returning an empty set — is
    indistinguishable from "this library exports nothing", which is how a
    gate reports a catastrophe it did not observe.
    """
    kind = object_format(library)
    if kind == "pe":
        names = pe_export_names(library)
    elif kind == "macho":
        names = _macho_symbols(library)
    else:
        names = _nm_symbols(library, ("--dynamic", "--defined-only", "--format=posix"))

    if not any(name.startswith("ama_") for name in names):
        raise RuntimeError(
            f"read 0 ama_* symbols from {library} ({kind}). Either the reader "
            "cannot see this image's exports or the library carries none; "
            "both are defects, and neither may be reported as a documentation "
            f"failure. Symbols read: {len(names)}."
        )
    return names


def localised_symbols(repo: Path) -> frozenset[str]:
    """The names ``cmake/ama_exports.map`` keeps off the ABI.

    The version script is the single declaration of what is internal; CMake
    generates the macOS unexported-symbols list from this same block, so the
    two platforms cannot disagree about it the way they did before.

    Indentation-insensitive on purpose: the first version matched exactly eight
    leading spaces, so re-indenting the file would have emptied this set and
    every rule built on it would have passed over nothing.
    """
    script = (repo / "cmake" / "ama_exports.map").read_text(encoding="utf-8")
    body = script.split("local:", 1)[1] if "local:" in script else ""
    return frozenset(re.findall(r"^\s*(ama_[A-Za-z0-9_]+)\s*;", body, re.MULTILINE))


#: ``PUBLIC_HEADER "a.h;b.h"`` on a CMake target: the headers ``install()``
#: ships to a consumer.  Read from CMakeLists.txt rather than listed here, so a
#: header added to (or dropped from) the installed set moves this gate with it.
_PUBLIC_HEADER_PROPERTY = re.compile(r'\bPUBLIC_HEADER\s+"([^"]+)"')

#: C comments, so a prototype that is commented out -- or prose that happens to
#: read ``AMA_API ... ama_x(`` -- is not counted as a declaration.
_C_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)


def installed_public_headers(repo: Path) -> tuple[Path, ...]:
    """Every header the build installs for an out-of-tree consumer.

    Fails closed: a CMakeLists.txt this cannot read a ``PUBLIC_HEADER`` list
    from, or a listed header that does not exist, raises rather than yielding
    an empty declared set -- against which every export would be reported
    undeclared, burying a real finding in noise.
    """
    cmake = (repo / "CMakeLists.txt").read_text(encoding="utf-8")
    listed: set[str] = set()
    for match in _PUBLIC_HEADER_PROPERTY.finditer(cmake):
        listed.update(part.strip() for part in match.group(1).split(";") if part.strip())
    if not listed:
        raise RuntimeError(
            f"no PUBLIC_HEADER property found in {repo / 'CMakeLists.txt'}; "
            "the installed-header set cannot be derived, so the declared ABI is unknown"
        )
    headers = tuple(sorted(repo / name for name in listed))
    missing = [path.relative_to(repo).as_posix() for path in headers if not path.is_file()]
    if missing:
        raise RuntimeError(
            f"CMakeLists.txt installs public header(s) that do not exist: {', '.join(missing)}"
        )
    return headers


def declared_public_symbols(repo: Path) -> frozenset[str]:
    """The ``ama_*`` functions an installed header declares ``AMA_API``.

    ``AMA_API`` is the criterion, not "mentioned in a public header": on PE the
    export table is generated from ``AMA_API`` declarations
    (cmake/generate_pe_def.cmake), so a name declared without it is exported on
    ELF and Mach-O and absent on Windows -- one ABI per platform.
    """
    declared: set[str] = set()
    for header in installed_public_headers(repo):
        source = _C_COMMENT.sub(" ", header.read_text(encoding="utf-8"))
        declared.update(_AMA_API.findall(source))
    return frozenset(declared)


def check_exports(report: Report, repo: Path, library: Optional[Path]) -> None:
    if library is None:
        report.skipped.append(
            "C export verification (no built libama_cryptography.so found — "
            "build with `cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build`)"
        )
        return
    exported = dynamic_symbols(library)

    # EVERY name the version script localises, not a hand-picked few. This was
    # seven names, and the cost of that showed the first time the check reached
    # a macOS runner: the dylib published all thirty, and the seven-name subset
    # reported three. A subset of an invariant is not the invariant.
    localised = localised_symbols(repo)
    unnamed = sorted(set(MUST_NOT_BE_EXPORTED) - localised)
    if unnamed:
        # Non-vacuity. If the `local:` block ever fails to parse, this rule
        # would check nothing and pass, which is the shape of a gate that
        # reports success because it looked at an empty set.
        report.fail(
            "cmake/ama_exports.map does not localise "
            f"{', '.join(unnamed)}, which this gate names explicitly. Either "
            "the version script lost them or the `local:` block no longer "
            "parses — and an export rule over an empty set passes vacuously."
        )
    else:
        report.ok()

    for name in sorted(localised):
        if name in exported:
            report.fail(
                f"{name} IS exported by {library.name}, but cmake/ama_exports.map "
                "localises it. An internal helper on the public ABI is a "
                "guard-bypass surface a consumer can resolve by name."
            )
        else:
            report.ok()

    for name in MUST_BE_EXPORTED:
        if name not in exported:
            report.fail(
                f"{name} is NOT exported by {library.name}. Documentation names "
                "it as part of the ABI, so an out-of-tree caller gets an "
                "undefined reference at link time."
            )
        else:
            report.ok()

    # No compiler-generated clone may reach the ABI.  GCC's partial inlining,
    # constant propagation and IPA-SRA emit `name.part.N`, `name.constprop.N`,
    # `name.isra.N`, `name.cold` and `name.localalias` with default visibility;
    # the ELF version script's `local:` catch-all hides them, and MinGW's ld
    # auto-exported `ama_hmac_sha256.part.0` from the DLL until CMakeLists
    # passed --exclude-all-symbols.  A consumer that resolves one calls a
    # fragment of a public entry point with a compiler-chosen signature and
    # none of that entry point's argument checks, which is the same
    # guard-bypass surface the localised names above exist to keep off the ABI.
    clones = sorted(name for name in exported if not _PLAIN_SYMBOL.fullmatch(name))
    if clones:
        report.fail(
            "compiler-generated symbol(s) on the exported ABI: "
            f"{', '.join(clones)}. A clone suffix (.part.N, .constprop.N, "
            ".isra.N, .cold, .localalias) is an internal fragment of a public "
            "entry point, not an entry point: it has a compiler-chosen "
            "signature and none of that entry point's argument checks. Fix it "
            "by restricting the export set at the link step -- the version "
            "script on ELF, the exported-symbols list on Mach-O, a .def on PE "
            "-- and never by naming the clones, which change with the "
            "optimiser (measured: suppressing -fpartial-inlining moved "
            "ama_hmac_sha256.part.0 to ama_hmac_sha256.constprop.0)."
        )
    else:
        report.ok()

    # Every AMA_API prototype in the public header must be reachable, unless
    # the version script deliberately localises it.
    header = (repo / "include" / "ama_cryptography.h").read_text(encoding="utf-8")
    declared = frozenset(_AMA_API.findall(header))
    unreachable = sorted(declared - exported - localised)
    if unreachable:
        report.fail(
            "declared AMA_API in include/ama_cryptography.h but not exported and "
            f"not localised on purpose: {', '.join(unreachable)}. Either the "
            "build dropped a translation unit or the header promises an entry "
            "point the library does not carry."
        )
    else:
        report.ok()

    # The reverse direction: every ama_* entry point the library exports must
    # be declared AMA_API in a header the build installs.  The version script
    # exports the `ama_*` wildcard, so without this a non-static helper added
    # anywhere under src/c becomes public ABI silently -- resolvable by name,
    # with no prototype a consumer can see, and (being undeclared) absent from
    # the PE .def, so exported on two platforms and not the third.  Clones are
    # excluded here only because the rule above already reports each one.
    declared_public = declared_public_symbols(repo)
    undeclared = sorted(
        name
        for name in exported
        if name.startswith("ama_") and _PLAIN_SYMBOL.fullmatch(name) and name not in declared_public
    )
    if undeclared:
        installed = ", ".join(
            str(path.relative_to(repo)) for path in installed_public_headers(repo)
        )
        report.fail(
            f"{len(undeclared)} ama_* symbol(s) exported by {library.name} but "
            f"declared AMA_API in no installed public header ({installed}): "
            f"{', '.join(undeclared)}. Each is public ABI with no published "
            "prototype. Either declare it AMA_API in an installed header (it is "
            "API) or localise it in cmake/ama_exports.map / give it internal "
            "linkage (it is not)."
        )
    else:
        report.ok()


def check_simd_inventory(report: Report, repo: Path) -> None:
    for directory, expected_files in SIMD_INVENTORY:
        base = repo / directory
        if not base.is_dir():
            report.fail(f"{directory} does not exist; the documentation describes it")
            continue
        actual = tuple(sorted(path.name for path in base.glob("*.c")))
        if actual != expected_files:
            report.fail(
                f"{directory} holds {len(actual)} translation unit(s) {actual}; "
                f"the documented inventory is {len(expected_files)} "
                f"{expected_files}. README.md publishes both the count and the "
                "per-algorithm list — it once claimed an Ed25519 NEON kernel "
                "that has never existed."
            )
            continue
        report.ok()


#: Shared-library basenames by platform.  Globbing ``libama_cryptography.so*``
#: unconditionally — which this gate did while it was written on Linux — finds
#: nothing on macOS or Windows, so the export checks reported "skipped" on two
#: of the three platforms the matrix covers.
_LIBRARY_PATTERNS: tuple[str, ...] = (
    "libama_cryptography.so*",
    "libama_cryptography.*dylib",
    "libama_cryptography.dll*",
    "ama_cryptography.dll",
)


def find_library(
    repo: Path, explicit: Optional[Path] = None, directory: Optional[Path] = None
) -> Optional[Path]:
    if explicit is not None:
        return explicit if explicit.is_file() else None
    searched = [directory] if directory is not None else []
    searched += [repo / "build" / "lib", repo / "ama_cryptography", repo / "build"]
    for candidate_dir in searched:
        if candidate_dir is None or not candidate_dir.is_dir():
            continue
        for pattern in _LIBRARY_PATTERNS:
            matches = sorted(candidate_dir.glob(pattern))
            if matches:
                return matches[-1]
    return None


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=REPO)
    parser.add_argument(
        "--library", type=Path, default=None, help="explicit path to the built shared object"
    )
    parser.add_argument(
        "--library-dir",
        type=Path,
        default=None,
        help=(
            "directory holding the built shared object; the same spelling "
            "tools/check_doc_examples.py takes, so one CI line cannot be right "
            "for one gate and wrong for the other"
        ),
    )
    parser.add_argument(
        "--require-library",
        action="store_true",
        help="fail rather than skip when no built library is available",
    )
    args = parser.parse_args(argv)
    repo: Path = args.repo

    if not (repo / "ama_cryptography" / "__init__.py").is_file():
        print(f"FATAL: {repo} does not look like the repository root.", file=sys.stderr)
        return 2
    if str(repo) not in sys.path:
        sys.path.insert(0, str(repo))

    report = Report()
    check_bare_import(report)
    check_signatures(report)
    check_return_types(report)
    check_context_managers(report)
    check_simd_inventory(report, repo)

    library = find_library(repo, args.library, args.library_dir)
    if library is None and args.require_library:
        print(
            "FATAL: --require-library was given but no built " "libama_cryptography.so was found.",
            file=sys.stderr,
        )
        return 2
    check_exports(report, repo, library)

    if report.failures:
        print(
            f"PUBLIC API DOC CHECK FAILED — {len(report.failures)} documented "
            "claim(s) do not match the package:",
            file=sys.stderr,
        )
        for failure in report.failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(f"OK    {report.checked} public-API claim(s) verified against the package")
    for skipped in report.skipped:
        print(f"SKIP  {skipped}")
    if report.skipped:
        # The module docstring has always promised this and the code used to
        # return 0 here: a run that never examined the exported ABI read, to
        # any caller, exactly like one that did.
        print(
            f"INCOMPLETE — {len(report.skipped)} check(s) skipped; exit 3 is not "
            "a pass. Pass --library/--library-dir, or --require-library to make "
            "a missing library an error."
        )
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
