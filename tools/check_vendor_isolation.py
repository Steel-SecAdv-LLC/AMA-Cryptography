#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — Vendor Isolation Gate (INVARIANT-1, enforced five ways)

INVARIANT-1 says no third-party cryptographic implementation may be linked,
imported or called by the shipped library.  Until this script existed, that
claim rested on:

* ``tools/check_corpus_originality.py``, which AST-scans for *subprocess*
  invocations of external crypto binaries (``openssl``, ``gpg``, …); and
* comments, naming, documentation and intent.

Nothing checked the four things that actually decide the question:

``linkage``
    What the built shared object *depends on*, what symbols it expects an
    external library to supply, and what symbols it defines itself.  The
    third is what a *static* link leaves behind: it produces no dependency
    record and imports nothing, so the first two see a clean library while
    vendor code runs inside it.

``build configuration``
    A ``find_package(OpenSSL)`` added to CMakeLists.txt, or a ``-lcrypto``
    inherited from a toolchain file, is the shortest path from "no vendor" to
    "vendor executing inside the library" — and if the link is static and the
    build hides its symbols, the artefact carries no trace of it.  The build
    files are where that decision is written down, so that is where it is
    checked.

``runtime``
    What is actually resident in ``sys.modules`` after ``import
    ama_cryptography``.  Source scanning misses transitive imports: a module
    AMA imports for an unrelated reason that itself imports ``cryptography``
    puts an OpenSSL binding in the process, and no ``import`` statement in
    this repository names it.

``the C tree``
    Where the only ``#include <openssl/...>`` lines in this repository
    actually live.  The vendored ed25519-donna carries an OpenSSL SHA-512 and
    an OpenSSL ``RAND_bytes`` as the ``#else`` arm of its hash and RNG
    selection — the arm taken when nothing else is defined.  They are not
    compiled, because ``src/c/ed25519_donna_shim.c`` defines
    ``ED25519_REFHASH`` and ``ED25519_CUSTOMRANDOM`` first; two lines in one
    file are the whole of what stands between the shipped library and OpenSSL
    doing its Ed25519 hashing and its randomness.  Nothing verified those
    lines were still there: the source scan below reads ``ama_cryptography``
    and has never looked at ``src/c`` at all.  A build that lost them would
    take the OpenSSL arm, and whether that then fails to link depends on
    whether the headers happen to be installed on the machine — which is not
    a boundary, it is a coincidence.

``the comparator boundary``
    ``benchmarks/`` is explicitly authorised to invoke peer implementations —
    that is what a comparative benchmark *is* — and ``benchmarks/requirements-
    bench.txt`` pins them.  Authorisation for benchmarking is not
    authorisation for anything else, and the only thing keeping the
    comparators on their side of the line was that no package module happened
    to import ``benchmarks``.

All five are checked here, and the binary formats are parsed in-tree with
``struct`` rather than by shelling out to ``readelf`` / ``otool`` /
``dumpbin``: this gate must run on every platform the wheels are built on,
including runners where those tools are absent, and a gate that silently
skips is the failure mode this repository's audit exists to remove.

Parsing them in-tree carries its own obligation, which the first version of
this file did not meet: the parser has to accept what the platform actually
ships.  macOS wheels are ``universal2``, so the artefact there is a *fat*
wrapper around two Mach-O images and not a Mach-O image at all.  The parser
recognised only thin images, so on macOS it reported "unrecognised binary
format" — fail-closed, and therefore not a false clean, but the linkage
check could not examine the shipped artefact on that platform at all.  Every
slice of a universal binary is now parsed and the results are **unioned**: a
vendor present in one architecture is a vendor in the shipped artefact, and
reading only the host's slice would be an evasion path.

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

``--build-config``
    No ``CMakeLists.txt``, ``cmake/**.cmake`` or ``setup.py`` outside
    ``benchmarks/`` may search for, find, or link a forbidden vendor.
    Commands are matched, not words: ``CMakeLists.txt`` names OpenSSL in a
    status message and in the comment recording why it is deliberately not
    probed, and a scan that cannot tell a mention from a link would fire on
    the documentation of the boundary it is enforcing.

``--runtime``
    Imports the package in a clean subprocess and fails if any forbidden
    top-level module is resident afterwards.

``--library PATH``
    Parses the native library's own linkage records — ELF ``DT_NEEDED`` plus
    ``.dynsym``, Mach-O ``LC_LOAD_DYLIB`` plus ``LC_SYMTAB`` (thin or
    universal), PE import directory — and fails on a forbidden vendor name
    or symbol prefix, whether the symbol is imported (dynamic link) or
    defined by the image itself (static link).

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
import re
import struct
import subprocess
import sys
from pathlib import Path, PurePosixPath
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
    #: Header roots that identify it in a C `#include` — `<openssl/sha.h>`,
    #: `<sodium.h>`, and so on.  Empty for a vendor with no C surface.
    include_roots: tuple[str, ...] = ()


VENDORS: tuple[Vendor, ...] = (
    Vendor(
        name="OpenSSL",
        # `cryptography` and `pyOpenSSL` are OpenSSL bindings; `_ssl` and
        # `_hashlib` are CPython's own OpenSSL-backed stdlib accelerators and
        # are NOT listed — they are the interpreter's linkage, not AMA's.
        # INVARIANT-1 confines stdlib `hashlib` to the import-time trust
        # bootstrap (enforced with exact per-file counts by
        # tools/check_stdlib_hash_boundary.py); listing the interpreter's
        # own modules here would make this gate fail on a stock interpreter
        # rather than on an AMA defect.  See the module docstring in
        # tools/check_corpus_originality.py for the boundary.
        modules=frozenset({"OpenSSL", "cryptography"}),
        library_names=("libcrypto", "libssl", "libeay32", "ssleay32"),
        symbol_prefixes=("EVP_", "OPENSSL_", "SSL_", "X509_", "RAND_bytes"),
        include_roots=("openssl",),
    ),
    Vendor(
        name="libsodium",
        modules=frozenset({"nacl"}),
        library_names=("libsodium",),
        symbol_prefixes=("sodium_", "crypto_sign_ed25519", "crypto_box_"),
        include_roots=("sodium",),
    ),
    Vendor(
        name="wolfSSL",
        modules=frozenset({"wolfssl", "wolfcrypt"}),
        library_names=("libwolfssl", "wolfssl"),
        symbol_prefixes=("wolfSSL_", "wc_"),
        include_roots=("wolfssl",),
    ),
    Vendor(
        name="Botan",
        modules=frozenset({"botan", "botan2", "botan3"}),
        library_names=("libbotan",),
        symbol_prefixes=("botan_",),
        include_roots=("botan",),
    ),
    Vendor(
        name="Nettle",
        modules=frozenset({"nettle"}),
        library_names=("libnettle", "libhogweed"),
        symbol_prefixes=("nettle_",),
        include_roots=("nettle",),
    ),
    Vendor(
        name="libgcrypt",
        modules=frozenset({"gcrypt"}),
        library_names=("libgcrypt",),
        symbol_prefixes=("gcry_",),
        include_roots=("gcrypt",),
    ),
    Vendor(
        name="mbedTLS",
        modules=frozenset({"mbedtls"}),
        library_names=("libmbedcrypto", "libmbedtls", "libmbedx509"),
        symbol_prefixes=("mbedtls_",),
        include_roots=("mbedtls", "psa"),
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
# C source check
# --------------------------------------------------------------------------
#
# The Python source check below scans the package.  It has never scanned
# `src/c/`, which is where the only `#include <openssl/...>` lines in this
# repository actually are: the vendored ed25519-donna carries OpenSSL arms for
# its hash and its RNG, and both are the `#else` — the arm taken when no
# alternative macro is defined.
#
#     ed25519-hash.h:197         #include <openssl/sha.h>     (SHA512_Init …)
#     ed25519-randombytes.h:78   #include <openssl/rand.h>    (RAND_bytes)
#
# They are not compiled today, because `src/c/ed25519_donna_shim.c` defines
# ED25519_REFHASH and ED25519_CUSTOMRANDOM before pulling the unit in.  That
# is two lines in one file standing between the shipped library and OpenSSL
# performing its Ed25519 hashing and its randomness — and until this check
# existed, nothing verified they were still there.  A build that lost them
# would take the OpenSSL arm; whether that then fails to link depends on
# whether the headers happen to be installed, which is not a boundary.
#
# So the rule is positive rather than absentee: outside the vendored tree no
# forbidden vendor header may be included at all, inside it every such
# include must be a KNOWN fallback arm, and every in-tree translation unit
# that compiles the vendored tree must define the macros that disable them.

#: Vendored upstream files that legitimately carry a forbidden-vendor include
#: in a fallback arm, and the macro that must be defined to avoid it.  A
#: vendor include found anywhere else — or here but not listed — is a
#: violation, so a new one cannot arrive unnoticed.
VENDORED_FALLBACK_INCLUDES: dict[str, tuple[str, str]] = {
    "src/c/vendor/ed25519-donna/ed25519-hash.h": ("OpenSSL", "ED25519_REFHASH"),
    "src/c/vendor/ed25519-donna/ed25519-randombytes.h": ("OpenSSL", "ED25519_CUSTOMRANDOM"),
}

_C_INCLUDE_RE = re.compile(r"^\s*#\s*include\s*[<\"](?P<path>[^>\"]+)[>\"]", re.M)
_C_DEFINE_RE = re.compile(r"^\s*#\s*define\s+(?P<name>[A-Za-z_]\w*)", re.M)


def _c_sources(root: Path) -> list[Path]:
    return sorted(list(root.rglob("*.c")) + list(root.rglob("*.h")))


def _vendor_for_include(include_path: str) -> str | None:
    head = include_path.split("/")[0]
    stem = head[:-2] if head.endswith(".h") else head
    for vendor in VENDORS:
        for root in vendor.include_roots:
            if stem == root:
                return vendor.name
    return None


def check_c_source(c_root: Path, repo_root: Path) -> list[Violation]:
    """No forbidden vendor may be reachable from the C tree."""
    violations: list[Violation] = []
    files = _c_sources(c_root)
    if not files:
        return [
            Violation(
                "c source",
                str(c_root),
                "no C sources found — refusing to report a clean scan of nothing",
            )
        ]

    seen_fallbacks: set[str] = set()
    for path in files:
        rel = path.relative_to(repo_root).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in _C_INCLUDE_RE.finditer(text):
            vendor_name = _vendor_for_include(match.group("path"))
            if vendor_name is None:
                continue
            line = text.count("\n", 0, match.start()) + 1
            known = VENDORED_FALLBACK_INCLUDES.get(rel)
            if known is not None and known[0] == vendor_name:
                seen_fallbacks.add(rel)
                continue
            violations.append(
                Violation(
                    "c source",
                    f"{rel}:{line}",
                    f"includes <{match.group('path')}> — {vendor_name} may not perform "
                    f"an internal operation. If this is a vendored upstream's fallback "
                    f"arm, record it in VENDORED_FALLBACK_INCLUDES with the macro that "
                    f"disables it, and make every translation unit that compiles the "
                    f"vendored tree define that macro.",
                )
            )

    for rel, (vendor_name, _macro) in VENDORED_FALLBACK_INCLUDES.items():
        if rel not in seen_fallbacks:
            violations.append(
                Violation(
                    "c source",
                    rel,
                    f"declared as carrying a {vendor_name} fallback arm, but no such "
                    f"include was found. A stale entry here weakens the check: remove "
                    f"it, or restore the file this gate is meant to be watching.",
                )
            )

    required_macros = sorted({macro for _v, macro in VENDORED_FALLBACK_INCLUDES.values()})
    compilers = [
        path
        for path in files
        if "vendor" not in path.relative_to(repo_root).parts
        and any(
            "vendor/" in m.group("path")
            for m in _C_INCLUDE_RE.finditer(path.read_text(encoding="utf-8", errors="replace"))
        )
    ]
    if not compilers:
        violations.append(
            Violation(
                "c source",
                str(c_root),
                "no translation unit includes the vendored tree, so the macros that "
                "disable its forbidden-vendor arms are unverifiable. If the vendored "
                "code is gone, remove VENDORED_FALLBACK_INCLUDES with it.",
            )
        )
    for path in compilers:
        rel = path.relative_to(repo_root).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        defined = {m.group("name") for m in _C_DEFINE_RE.finditer(text)}
        for macro in required_macros:
            if macro not in defined:
                violations.append(
                    Violation(
                        "c source",
                        rel,
                        f"compiles the vendored tree without defining {macro}. Without "
                        f"it the upstream takes its forbidden-vendor fallback arm, and "
                        f"the boundary holds only by whichever headers happen to be "
                        f"absent from the build machine.",
                    )
                )
    return violations


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
# Build-configuration check
# --------------------------------------------------------------------------

#: CMake commands that can put a vendor into the link line or make the build
#: depend on finding one.  ``message()``, ``option()`` and the like are
#: deliberately absent: ``CMakeLists.txt`` names OpenSSL in a status string
#: and in the comment explaining why it is *not* probed, and a scan that
#: cannot tell a mention from a link would fire on the very documentation
#: that records the boundary.
_CMAKE_VENDOR_COMMANDS = (
    "find_package",
    "find_library",
    "pkg_check_modules",
    "pkg_search_module",
    "target_link_libraries",
    "link_libraries",
)

#: Files that decide what the build links, beyond the sources themselves.
_BUILD_CONFIG_GLOBS = ("CMakeLists.txt", "**/CMakeLists.txt", "cmake/**/*.cmake", "setup.py")

#: Directories that hold generated or third-party trees rather than this
#: repository's own build configuration.  ``build/`` in particular is full of
#: CMake's own generated files, which name every package CMake knows how to
#: find; scanning them would report the toolchain's vocabulary as AMA's
#: choices.
_BUILD_CONFIG_SKIP_DIRS = frozenset(
    {".git", "build", "_build", "dist", ".venv", "venv", "node_modules", "__pycache__"}
)

#: A library's version suffix: an optional separator, then a digit, then
#: whatever the packager appended (``-3``, ``.3``, ``-3-x64``, ``2``).
_VERSION_SUFFIX_RE = re.compile(r"[-_.]?\d[\w.+-]*$")


def _strip_cmake_comments(text: str) -> str:
    """Remove ``#`` comments, leaving quoted strings intact.

    A ``#`` inside a quoted argument is data, not a comment, and dropping the
    rest of such a line would hide whatever followed it on that line from the
    scan.  Bracket comments (``#[[ ... ]]``) are handled by the same rule
    that handles line comments: everything from the ``#`` is dropped, and the
    closing ``]]`` sits on a later line that is scanned normally — which can
    only make the scan see more, never less.
    """
    out: list[str] = []
    in_string = False
    index = 0
    while index < len(text):
        char = text[index]
        if in_string:
            if char == "\\":
                out.append(text[index : index + 2])
                index += 2
                continue
            if char == '"':
                in_string = False
            out.append(char)
        elif char == '"':
            in_string = True
            out.append(char)
        elif char == "#":
            newline = text.find("\n", index)
            if newline == -1:
                break
            index = newline
            continue
        else:
            out.append(char)
        index += 1
    return "".join(out)


def _vendor_link_tokens() -> dict[str, str]:
    """``token -> vendor name`` for every spelling a vendor links under.

    Derived from :data:`VENDORS` rather than written out again, so a vendor
    added to the table is screened here without a second edit.  Both the
    ``libfoo`` and the ``-lfoo`` spelling are generated: CMake accepts either
    in a link-libraries list.
    """
    tokens: dict[str, str] = {}
    for vendor in VENDORS:
        for name in vendor.library_names:
            tokens.setdefault(name.lower(), vendor.name)
            if name.lower().startswith("lib"):
                tokens.setdefault(name[3:].lower(), vendor.name)
        for module in vendor.modules:
            tokens.setdefault(module.lower(), vendor.name)
        tokens.setdefault(vendor.name.lower(), vendor.name)
    return tokens


def check_build_config(repo_root: Path) -> list[Violation]:
    """No build file may search for, find, or link a forbidden vendor.

    This is the leg the other three cannot cover.  ``check_library`` reads a
    *built* artefact, so it sees a vendor only if the link left a trace in
    it; a static link with hidden visibility leaves none.  ``check_source``
    and ``check_runtime`` read Python.  Nothing read the build files — and a
    ``find_package(OpenSSL)`` plus ``target_link_libraries(... OpenSSL::Crypto)``
    is the shortest path from "no vendor" to "vendor executing inside the
    library", which is precisely why this module's own docstring named it as
    the threat.  Naming a threat is not checking for it.

    ``benchmarks/`` is exempt by the comparator boundary: a comparative
    benchmark that cannot link its comparators measures nothing.
    """
    tokens = _vendor_link_tokens()
    command_re = re.compile(
        r"\b(" + "|".join(_CMAKE_VENDOR_COMMANDS) + r")\s*\(([^)]*)\)",
        re.IGNORECASE | re.DOTALL,
    )
    flag_re = re.compile(r"-l\s*([A-Za-z0-9_.+-]+)")
    arg_split_re = re.compile(r"[\s\"'$<>{},;:]+")

    def _lookup(candidate: str) -> str | None:
        """A vendor for one spelling, allowing the version suffix libraries carry.

        Botan links as ``botan-3``, OpenSSL ships ``libcrypto-3-x64`` on
        Windows and ``libcrypto.so.3`` on Linux, and none of those is an
        exact match for the base name.  A trailing version suffix — an
        optional separator followed by a digit and whatever follows it — is
        therefore stripped before the second lookup.

        The digit is what keeps this narrow.  ``ama_cryptography`` does not
        begin with ``crypto`` and so is never considered; a target that did
        would still have to end in a version-shaped suffix to match.
        """
        vendor = tokens.get(candidate.lower())
        if vendor is not None:
            return vendor
        trimmed = _VERSION_SUFFIX_RE.sub("", candidate.lower())
        if trimmed and trimmed != candidate.lower():
            return tokens.get(trimmed)
        return None

    def _vendor_for_argument(argument: str) -> tuple[str, str] | None:
        """``(matched spelling, vendor)`` for one link-command argument.

        Two spellings reach the linker and neither is the other: a bare name
        (``crypto``, ``OpenSSL::Crypto`` after splitting) and an absolute path
        to the library file (``/usr/lib/libcrypto.so.3``).  The second is
        matched on the file name up to its first dot, which is where a
        SONAME's version digits begin.
        """
        vendor = _lookup(argument)
        if vendor is not None:
            return argument, vendor
        stem = PurePosixPath(argument.replace("\\", "/")).name.split(".", 1)[0]
        if stem and stem != argument:
            vendor = _lookup(stem)
            if vendor is not None:
                return stem, vendor
        return None

    violations: list[Violation] = []
    seen: set[Path] = set()
    paths: list[Path] = []
    for pattern in _BUILD_CONFIG_GLOBS:
        for path in sorted(repo_root.glob(pattern)):
            resolved = path.resolve()
            if not path.is_file() or resolved in seen:
                continue
            relative = path.relative_to(repo_root)
            if set(relative.parts) & _BUILD_CONFIG_SKIP_DIRS:
                continue
            if relative.parts and relative.parts[0] == COMPARATOR_PACKAGE:
                continue
            seen.add(resolved)
            paths.append(path)

    def _report(where: str, token: str, vendor: str, context: str) -> None:
        violations.append(
            Violation(
                "build-config",
                where,
                f"{context} names {token!r} — {vendor} may not be linked into the library",
            )
        )

    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        scanned = _strip_cmake_comments(text) if path.suffix != ".py" else text
        where = str(path.relative_to(repo_root))

        for match in command_re.finditer(scanned):
            command, arguments = match.group(1), match.group(2)
            for argument in arg_split_re.split(arguments):
                hit = _vendor_for_argument(argument)
                if hit is not None:
                    _report(where, hit[0], hit[1], f"{command}()")

        for match in flag_re.finditer(scanned):
            hit = _vendor_for_argument(match.group(1))
            if hit is not None:
                _report(where, f"-l{match.group(1)}", hit[1], "linker flag")

    if not paths:
        violations.append(
            Violation(
                "build-config",
                str(repo_root),
                "no build files found — refusing to report clean having " "examined nothing",
            )
        )
    return violations


#: Container recipes.  These are build inputs too — they decide what is present
#: at build time and what ships in the runtime image — and nothing read them.
#: ``docker/Dockerfile`` and ``docker/Dockerfile.alpine`` each carried an
#: explicit INVARIANT-1 paragraph ("libssl-dev is NOT installed", "openssl-dev
#: is deliberately absent") while ``docker/Dockerfile.c-api`` installed
#: ``libssl-dev`` in its builder and ``libssl3`` in its output stage, and
#: ``Dockerfile.alpine``'s own runtime stage installed ``libssl3`` — the
#: runtime half of the thing its builder stage says is absent.  The
#: build-config scan globbed CMake and setup.py only, so it reported clean
#: over all three.
_CONTAINER_GLOBS = ("docker/Dockerfile*", "oss-fuzz/Dockerfile*", "Dockerfile*")

#: Package-manager invocations that put a library into an image.
#: The line-continuation alternative comes FIRST.  With ``[^\n]`` first the
#: engine consumes the backslash, then finds a bare newline that neither
#: alternative can match, and the invocation is truncated at the end of its
#: first physical line — which is where every package name in these files
#: begins.  A Dockerfile ``RUN apk add --no-cache \`` would have been read as
#: installing nothing at all.
_PACKAGE_INSTALL_RE = re.compile(
    r"\b(?:apt-get|apt|apk|dnf|yum|zypper|pacman)\b[^\n]*?"
    r"\b(?:install|add)\b(?P<rest>(?:\\\n|[^\n])*)",
    re.IGNORECASE,
)

#: One package name inside such an invocation.
_PACKAGE_NAME_RE = re.compile(r"[A-Za-z0-9_.+-]+")

#: Package-name affixes a distribution adds around the library it wraps:
#: ``libssl-dev``, ``libssl3``, ``openssl-dev``, ``libsodium-dev``,
#: ``libgcrypt20-dev``.  Stripped so the base name can be looked up in the
#: same vendor table the linker scan uses, rather than maintaining a second
#: table of distribution spellings that would drift from it.
_PACKAGE_AFFIX_RE = re.compile(r"^(?:lib)?(?P<base>.+?)(?:-?\d[\w.+]*)?(?:-(?:dev|devel|libs))?$")


def check_container_recipes(repo_root: Path) -> list[Violation]:
    """No container recipe may install a forbidden vendor's package.

    Installing OpenSSL does not link it — nothing in this tree does — but it
    puts a CVE-prone library on disk in an image whose own comments say it is
    not there, and a runtime image is exactly where a future `dlopen` would
    find one.  The rule the Dockerfiles already state in prose is now checked.
    """
    tokens = _vendor_link_tokens()
    violations: list[Violation] = []
    paths: list[Path] = []
    seen: set[Path] = set()
    for pattern in _CONTAINER_GLOBS:
        for path in sorted(repo_root.glob(pattern)):
            resolved = path.resolve()
            if not path.is_file() or resolved in seen:
                continue
            relative = path.relative_to(repo_root)
            if set(relative.parts) & _BUILD_CONFIG_SKIP_DIRS:
                continue
            seen.add(resolved)
            paths.append(path)

    if not paths:
        return [
            Violation(
                "container",
                str(repo_root),
                "no container recipes found — refusing to report clean having " "examined nothing",
            )
        ]

    for path in paths:
        where = str(path.relative_to(repo_root))
        text = path.read_text(encoding="utf-8", errors="replace")
        # Drop comment lines: these files explain the exclusion in prose, and a
        # gate that fires on its own rationale is a gate that gets deleted.
        scanned = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        for match in _PACKAGE_INSTALL_RE.finditer(scanned):
            for name in _PACKAGE_NAME_RE.findall(match.group("rest")):
                if name.startswith("-"):
                    continue  # an option (--no-cache, -y), not a package
                base = _PACKAGE_AFFIX_RE.sub(r"\g<base>", name.lower())
                vendor = tokens.get(name.lower()) or tokens.get(base)
                if vendor is not None:
                    violations.append(
                        Violation(
                            "container",
                            where,
                            f"installs package {name!r} — {vendor} may not be "
                            f"present in a shipped image (INVARIANT-1)",
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
    #: Externally visible symbols the image DEFINES itself.
    #:
    #: A vendor linked *dynamically* leaves two traces — a dependency record
    #: and undefined symbols — and both are checked above.  A vendor linked
    #: *statically* leaves neither: its code is inside this image, so there is
    #: nothing to import.  The one linkage-level trace it does leave is its
    #: own symbols appearing among this image's, which is what this field
    #: carries.  It is not complete on its own (a static link whose symbols
    #: are all local, or an image stripped of everything but its exports,
    #: shows nothing here) — see ``check_library``'s docstring for what the
    #: linkage check can and cannot see, and which control covers the rest.
    defined_symbols: tuple[str, ...] = ()


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
    defined: list[str] = []
    dynsym = by_name.get(".dynsym")
    if dynsym is not None and dynsym["entsize"]:
        strtab = sections[dynsym["link"]]
        count = dynsym["size"] // dynsym["entsize"]
        for i in range(count):
            off = dynsym["offset"] + i * dynsym["entsize"]
            st_name, _st_info, _st_other, st_shndx = struct.unpack_from(end + "IBBH", data, off)
            if not st_name:
                continue
            if st_shndx == 0:  # SHN_UNDEF
                undefined.append(cstr(strtab["offset"], st_name))
            else:
                defined.append(cstr(strtab["offset"], st_name))

    return BinaryInfo("ELF", tuple(dependencies), tuple(undefined), tuple(defined))


#: Read with ``"<I"`` at offset 0 → ``(struct endianness, is 64-bit)``.
#:
#: A native little-endian image stores ``MH_MAGIC_64`` as ``CF FA ED FE``, so
#: the little-endian read yields ``0xFEEDFACF`` — the *swapped* spellings
#: (``0xCFFAEDFE`` / ``0xCEFAEDFE``) are therefore what a BIG-endian image
#: looks like through the same read, and its fields must be decoded with
#: ``">"``.  Both swapped spellings were mapped to ``"<"`` when this parser
#: was written, which would have decoded every subsequent field of a
#: big-endian image byte-reversed: ``ncmds`` in the millions, load commands
#: read from nonsense offsets.  No such image ships today (Mach-O big-endian
#: means 32-bit PowerPC), but a parser that is wrong for an input it accepts
#: is a defect regardless of whether the input is current.
_MACHO_MAGICS: dict[int, tuple[str, bool]] = {
    0xFEEDFACF: ("<", True),
    0xCFFAEDFE: (">", True),
    0xFEEDFACE: ("<", False),
    0xCEFAEDFE: (">", False),
}

#: Universal ("fat") wrapper magics, read big-endian — the fat header is
#: always big-endian on disk, whatever the slices inside it are.
_FAT_MAGIC = 0xCAFEBABE
_FAT_MAGIC_64 = 0xCAFEBABF

#: An implausible slice count means this is not a universal binary.  Java
#: class files share ``0xCAFEBABE`` and put their version where ``nfat_arch``
#: lives, so the count alone does not settle it — every slice is also
#: bounds-checked and required to start with a Mach-O magic, and anything
#: that fails raises rather than returning a partial answer.
_MAX_FAT_SLICES = 32


def _parse_macho(data: bytes) -> BinaryInfo:
    (magic,) = struct.unpack_from("<I", data, 0)
    if magic not in _MACHO_MAGICS:
        raise ValueError("not a thin Mach-O image")
    end, is64 = _MACHO_MAGICS[magic]
    header_size = 32 if is64 else 28
    (ncmds,) = struct.unpack_from(end + "I", data, 16)

    lc_symtab = 0x02
    lc_load_dylib = 0x0C
    lc_load_weak_dylib = 0x80000018
    lc_reexport_dylib = 0x8000001F

    dependencies: list[str] = []
    undefined: list[str] = []
    defined: list[str] = []

    offset = header_size
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from(end + "II", data, offset)
        if cmdsize < 8:
            raise ValueError(f"Mach-O load command at {offset} has size {cmdsize}")
        if cmd in (lc_load_dylib, lc_load_weak_dylib, lc_reexport_dylib):
            (name_off,) = struct.unpack_from(end + "I", data, offset + 8)
            raw = data[offset + name_off : offset + cmdsize]
            dependencies.append(raw.split(b"\0", 1)[0].decode("utf-8", "replace"))
        elif cmd == lc_symtab:
            symoff, nsyms, stroff, strsize = struct.unpack_from(end + "IIII", data, offset + 8)
            _read_macho_symbols(data, end, is64, symoff, nsyms, stroff, strsize, undefined, defined)
        offset += cmdsize

    return BinaryInfo("Mach-O", tuple(dependencies), tuple(undefined), tuple(defined))


def _read_macho_symbols(
    data: bytes,
    end: str,
    is64: bool,
    symoff: int,
    nsyms: int,
    stroff: int,
    strsize: int,
    undefined: list[str],
    defined: list[str],
) -> None:
    """Split one ``LC_SYMTAB``'s external symbols into undefined and defined.

    Without this the Mach-O branch reported an empty symbol set, so the
    symbol half of the vendor screen — the half that catches a vendor whose
    dependency record is absent — was inert on macOS while reporting the
    library clean.

    ``n_type`` is a bitfield: ``N_STAB`` (0xE0) marks debug entries, which
    carry no linkage meaning; ``N_EXT`` (0x01) marks external visibility; and
    ``N_TYPE`` (0x0E) selects the kind, of which ``N_UNDF`` (0x0) is
    "imported from elsewhere".  Only external symbols are collected: a static
    function named ``EVP_something`` in AMA's own code is not evidence of a
    vendor, and screening locals would make the gate fire on the tree's own
    private names.
    """
    n_stab, n_type_mask, n_ext, n_undf = 0xE0, 0x0E, 0x01, 0x00
    entry_size = 16 if is64 else 12
    value_fmt = "Q" if is64 else "I"

    end_of_symbols = symoff + nsyms * entry_size
    if symoff < 0 or stroff < 0 or end_of_symbols > len(data) or stroff + strsize > len(data):
        raise ValueError("Mach-O LC_SYMTAB points outside the image")

    for index in range(nsyms):
        off = symoff + index * entry_size
        n_strx, n_type, _n_sect, _n_desc, _n_value = struct.unpack_from(
            end + "IBBH" + value_fmt, data, off
        )
        if n_type & n_stab or not n_type & n_ext or not n_strx:
            continue
        if n_strx >= strsize:
            raise ValueError("Mach-O symbol name offset outside the string table")
        start = stroff + n_strx
        stop = data.index(b"\0", start, stroff + strsize)
        name = data[start:stop].decode("utf-8", "replace")
        if n_type & n_type_mask == n_undf:
            undefined.append(name)
        else:
            defined.append(name)


def _parse_macho_universal(data: bytes) -> BinaryInfo:
    """Parse every architecture slice of a universal binary and union them.

    macOS wheels ship ``universal2`` artefacts, so the file this gate is
    pointed at on macOS is normally a fat wrapper and not a Mach-O image at
    all.  The parser rejected it as an unrecognised format, which
    ``check_library`` correctly reported as a violation rather than as clean
    — but the effect was that the linkage check could not actually examine
    the artefact on the one platform whose shipped binary is fat.

    Every slice is parsed and the results unioned.  A union, not an
    intersection or a host-slice-only read: a vendor present in only one
    architecture is a vendor in the shipped artefact, and picking a single
    slice would be an evasion path.
    """
    magic, nfat_arch = struct.unpack_from(">II", data, 0)
    if magic not in (_FAT_MAGIC, _FAT_MAGIC_64):
        raise ValueError("not a universal Mach-O image")
    if not 1 <= nfat_arch <= _MAX_FAT_SLICES:
        raise ValueError(f"implausible universal-binary slice count: {nfat_arch}")

    wide = magic == _FAT_MAGIC_64
    arch_size = 32 if wide else 20
    offset_fmt = ">QQ" if wide else ">II"

    dependencies: list[str] = []
    undefined: list[str] = []
    defined: list[str] = []

    for index in range(nfat_arch):
        base = 8 + index * arch_size
        if base + arch_size > len(data):
            raise ValueError("universal-binary arch table extends past end of file")
        slice_off, slice_size = struct.unpack_from(offset_fmt, data, base + 8)
        if slice_off + slice_size > len(data) or slice_size < 28:
            raise ValueError(
                f"universal-binary slice {index} at {slice_off}+{slice_size} "
                f"lies outside the {len(data)}-byte file"
            )
        info = _parse_macho(data[slice_off : slice_off + slice_size])
        dependencies.extend(info.dependencies)
        undefined.extend(info.undefined_symbols)
        defined.extend(info.defined_symbols)

    return BinaryInfo(
        f"Mach-O universal ({nfat_arch} slices)",
        tuple(dict.fromkeys(dependencies)),
        tuple(dict.fromkeys(undefined)),
        tuple(dict.fromkeys(defined)),
    )


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
    export_rva, _export_size = struct.unpack_from("<II", data, dd_off)
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

    # Imports: the descriptor's DLL name feeds `dependencies`, and its
    # Import Lookup Table's hint/name entries feed `undefined_symbols` —
    # they are what the image pulls in by name.  This used to return
    # empty symbol tuples, which left the 'undefined symbols' and 'defined
    # external symbols' legs of check_library inert on PE: a statically
    # linked libcrypto inside ama_cryptography.dll produced zero violations
    # while the identical Mach-O gap had already earned a dedicated fix
    # (_read_macho_symbols).
    thunk_size = 8 if magic == 0x20B else 4
    ordinal_flag = 1 << (thunk_size * 8 - 1)
    dependencies: list[str] = []
    undefined: list[str] = []
    if import_rva:
        table = rva_to_off(import_rva)
        if table is not None:
            while True:
                entry = data[table : table + 20]
                if len(entry) < 20 or entry == b"\0" * 20:
                    break
                (ilt_rva,) = struct.unpack_from("<I", entry, 0)
                (name_rva,) = struct.unpack_from("<I", entry, 12)
                (iat_rva,) = struct.unpack_from("<I", entry, 16)
                name_off = rva_to_off(name_rva)
                if name_off is not None:
                    stop = data.index(b"\0", name_off)
                    dependencies.append(data[name_off:stop].decode("utf-8", "replace"))
                # The ILT (OriginalFirstThunk) survives binding; images that
                # zero it still carry the same entries in the IAT.
                thunk_off = rva_to_off(ilt_rva or iat_rva) if (ilt_rva or iat_rva) else None
                while thunk_off is not None and thunk_off + thunk_size <= len(data):
                    (thunk,) = struct.unpack_from(
                        "<Q" if thunk_size == 8 else "<I", data, thunk_off
                    )
                    if thunk == 0:
                        break
                    if not thunk & ordinal_flag:
                        # Hint/name entry: 2-byte hint, then the NUL-terminated
                        # name.  Ordinal imports carry no name and are skipped.
                        hint_off = rva_to_off(thunk & 0x7FFFFFFF)
                        if hint_off is not None:
                            stop = data.index(b"\0", hint_off + 2)
                            undefined.append(data[hint_off + 2 : stop].decode("utf-8", "replace"))
                    thunk_off += thunk_size
                table += 20

    # Exports: the names this image defines for others to import — the trace
    # a statically linked vendor leaves when nothing imports it.
    defined: list[str] = []
    if export_rva:
        export_off = rva_to_off(export_rva)
        if export_off is not None and export_off + 40 <= len(data):
            (num_names,) = struct.unpack_from("<I", data, export_off + 24)
            (names_rva,) = struct.unpack_from("<I", data, export_off + 32)
            names_off = rva_to_off(names_rva)
            if names_off is not None:
                for i in range(num_names):
                    if names_off + 4 * i + 4 > len(data):
                        break
                    (entry_rva,) = struct.unpack_from("<I", data, names_off + 4 * i)
                    entry_off = rva_to_off(entry_rva)
                    if entry_off is not None:
                        stop = data.index(b"\0", entry_off)
                        defined.append(data[entry_off:stop].decode("utf-8", "replace"))
    return BinaryInfo("PE", tuple(dependencies), tuple(undefined), tuple(defined))


def parse_binary(path: Path) -> BinaryInfo:
    data = path.read_bytes()
    if data[:4] == b"\x7fELF":
        return _parse_elf(data)
    if data[:2] == b"MZ":
        return _parse_pe(data)
    if len(data) >= 8 and struct.unpack_from(">I", data, 0)[0] in (_FAT_MAGIC, _FAT_MAGIC_64):
        return _parse_macho_universal(data)
    if len(data) >= 4 and struct.unpack_from("<I", data, 0)[0] in _MACHO_MAGICS:
        return _parse_macho(data)
    raise ValueError(f"unrecognised binary format (first bytes: {data[:8]!r})")


def _vendor_for_symbol(symbol: str) -> str | None:
    """The vendor a symbol name belongs to, or ``None``.

    Mach-O prefixes every C symbol with an underscore, so ``EVP_DigestInit``
    is spelled ``_EVP_DigestInit`` there.  One leading underscore is stripped
    before matching, which cannot cause a miss on ELF or PE: a name that
    matched before stripping still matches, and a name that starts with an
    underscore only becomes *more* likely to match.
    """
    bare = symbol[1:] if symbol.startswith("_") else symbol
    for vendor in VENDORS:
        for prefix in vendor.symbol_prefixes:
            if symbol.startswith(prefix) or bare.startswith(prefix):
                return vendor.name
    return None


def check_library(path: Path) -> list[Violation]:
    """The built library may not depend on, or import symbols from, a vendor.

    Three linkage traces are screened, and between them they cover both ways
    a vendor can arrive:

    * a **dependency record** (ELF ``DT_NEEDED``, Mach-O ``LC_LOAD_DYLIB``,
      PE import directory) — a dynamic link;
    * **undefined symbols** — a dynamic link whose dependency record was
      satisfied indirectly (a transitively loaded library, or a
      ``-Wl,--as-needed`` build that dropped the record but kept the import);
    * **defined external symbols** — a *static* link, which leaves no
      dependency record and imports nothing, and would otherwise pass this
      check while executing vendor code inside the image.

    What this check cannot see, stated plainly rather than implied away: a
    static link whose symbols are all local (``-fvisibility=hidden`` plus an
    internalising LTO pass), or an image stripped down to its exports, leaves
    no linkage trace at all.  That case is covered upstream instead — by the
    build configuration (no vendor is searched for, found, or linked by
    ``CMakeLists.txt``, which ``tests/test_vendor_isolation_gate.py``
    asserts) and by the source scan.  This function is the linkage leg of a
    three-legged control, not the whole of it.
    """
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
        vendor_name = _vendor_for_symbol(symbol)
        if vendor_name is not None:
            violations.append(
                Violation(
                    "library",
                    f"{path} [{info.fmt}]",
                    f"imports undefined symbol {symbol!r} — {vendor_name}",
                )
            )
    for symbol in info.defined_symbols:
        vendor_name = _vendor_for_symbol(symbol)
        if vendor_name is not None:
            violations.append(
                Violation(
                    "library",
                    f"{path} [{info.fmt}]",
                    f"defines symbol {symbol!r} — {vendor_name} appears to be "
                    "linked statically into this image",
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
    parser.add_argument(
        "--build-config",
        action="store_true",
        help="run only the build-configuration check (CMake / setup.py link lines)",
    )
    parser.add_argument("--runtime", action="store_true", help="run only the runtime import check")
    parser.add_argument(
        "--c-root",
        type=Path,
        default=Path("src/c"),
        help="C source tree to scan (default: src/c)",
    )
    parser.add_argument(
        "--no-runtime",
        action="store_true",
        help="skip the runtime check (for trees with no built native library)",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    explicit = args.source or args.runtime or args.build_config
    selected_source = args.source or not explicit
    selected_build_config = args.build_config or not explicit
    selected_runtime = (args.runtime or not explicit) and not args.no_runtime

    repo_root = Path(__file__).resolve().parent.parent
    violations: list[Violation] = []
    ran: list[str] = []

    if selected_source:
        violations += check_source(args.package)
        ran.append(f"source ({args.package})")
        violations += check_c_source(repo_root / args.c_root, repo_root)
        ran.append(f"C source ({args.c_root})")
    if selected_build_config:
        violations += check_build_config(repo_root)
        ran.append("build config (CMake / setup.py link lines)")
        violations += check_container_recipes(repo_root)
        ran.append("container recipes (Dockerfile package installs)")
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
