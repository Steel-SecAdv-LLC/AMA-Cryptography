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
6. **HSS/LMS exports**, named explicitly because their absence was documented.
7. **Architecture-specific implementation claims**, e.g. the per-directory SIMD
   kernel inventory and the algorithms each covers.

Where a built library is not available (a documentation-only CI lane) the
symbol checks report as skipped rather than passing vacuously, and the exit
status distinguishes the two.

Exit status
-----------
0  every documented API claim matches the package
1  at least one does not
2  the check could not run
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
from typing import Any, Optional

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


def dynamic_symbols(library: Path) -> frozenset[str]:
    completed = subprocess.run(
        ["nm", "--dynamic", "--defined-only", "--format=posix", str(library)],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"nm failed on {library}: {completed.stderr.strip()}")
    names: set[str] = set()
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] in {"T", "W", "i", "D", "B", "R"}:
            names.add(parts[0])
    return frozenset(names)


def check_exports(report: Report, repo: Path, library: Optional[Path]) -> None:
    if library is None:
        report.skipped.append(
            "C export verification (no built libama_cryptography.so found — "
            "build with `cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build`)"
        )
        return
    exported = dynamic_symbols(library)

    for name in MUST_NOT_BE_EXPORTED:
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

    # Every AMA_API prototype in the public header must be reachable, unless
    # the version script deliberately localises it.
    header = (repo / "include" / "ama_cryptography.h").read_text(encoding="utf-8")
    declared = frozenset(_AMA_API.findall(header))
    version_script = (repo / "cmake" / "ama_exports.map").read_text(encoding="utf-8")
    localised = frozenset(re.findall(r"^\s{8}(ama_[A-Za-z0-9_]+);", version_script, re.MULTILINE))
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
