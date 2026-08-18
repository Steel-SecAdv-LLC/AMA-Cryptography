#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
INVARIANT-1 boundary gate: stdlib ``hashlib`` in the shipped package.

CPython's ``hashlib`` is not a neutral helper.  In every build that links
libcrypto — which includes every manylinux wheel and every mainstream distro
Python — its constructors resolve to OpenSSL: ``hashlib.sha3_256`` *is*
``_hashlib.openssl_sha3_256``, the SHA-3 family included.  A production
``hashlib`` call inside ``ama_cryptography`` is therefore OpenSSL performing
an AMA cryptographic primitive in-process, which INVARIANT-1 forbids.  Fifty
such call sites accumulated under documentation claiming zero external crypto
dependencies before the 2026-08 sweep converted them to the library's own
kernels (``native_sha256/384/512``, ``native_sha3_256/384/512``,
``native_pbkdf2_hmac_sha256/512``).

What legitimately remains is the TRUST BOOTSTRAP: code that must hash before
the native library may be used, plus deliberately-independent comparators.
This gate pins that boundary exactly, the same way the vendor-isolation gate
pins linkage: every ``hashlib`` / ``_hashlib`` reference in the package must
sit in an allowlisted file, and each allowlisted file must carry EXACTLY the
number of references its entry records — so a new use inside an allowlisted
file fails just as loudly as a new file.  Docstrings and comments do not
count; the scan is over the AST.

Why the bootstrap cannot be converted:

* ``pqc_backends`` hashes every candidate shared object BEFORE mapping it
  (constructors execute on dlopen).  The library cannot hash itself into
  trust; something outside it must hold the scale.
* ``_self_test`` / ``__init__`` / ``_build_sign`` compute the source/artefact
  digests that decide whether the package may operate at all.  Using the
  native library here would let a tampered library attest tampered sources.
* ``_self_test``'s SHA3-256 KAT also runs ``hashlib`` against the FIPS 202
  vectors as a cross-implementation check — a comparator compared against
  fixed constants, never a producer of trusted values.
* ``hybrid_combiner._hkdf_python`` is the RuntimeError-guarded test-only
  reference whose value is exactly its independence from the native path.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_DIR = REPO_ROOT / "ama_cryptography"

#: file name -> (expected reference count, rationale).  The count includes
#: import statements and every ``hashlib.<attr>`` / ``_hashlib.<attr>``
#: attribute access.  Change a bootstrap file and this gate makes you come
#: here and say why.
ALLOWLIST: dict[str, tuple[int, str]] = {
    "__init__.py": (
        2,
        "stale-source fast check: hashes .py files against the recorded "
        "digest before the native library is trusted (import + 1 use)",
    ),
    "pqc_backends.py": (
        3,
        "pre-load digest verification: every candidate shared object is "
        "hashed BEFORE dlopen maps it, so the hash cannot come from the "
        "library under test (import + POSIX fd path + Windows read path)",
    ),
    "_self_test.py": (
        7,
        "signed-integrity digest chain over the .py sources and native "
        "library (import + 5 uses), plus the SHA3-256 KAT cross-check that "
        "runs hashlib against fixed FIPS 202 vectors as an independent "
        "comparator (1 use)",
    ),
    "_build_sign.py": (
        6,
        "build-time signer: computes the digests the artefact will bind "
        "before any built library exists to compute them (import + 5 uses)",
    ),
    "hybrid_combiner.py": (
        4,
        "test-only HKDF reference implementation, RuntimeError-guarded "
        "behind _test_only_allow_python; its purpose is independence from "
        "the native path it cross-checks (import + 3 uses)",
    ),
}


def count_hash_references(tree: ast.AST) -> int:
    """Import statements plus attribute reads of ``hashlib`` / ``_hashlib``."""
    count = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id in ("hashlib", "_hashlib"):
                count += 1
        elif isinstance(node, ast.Import):
            count += sum(1 for a in node.names if a.name in ("hashlib", "_hashlib"))
        elif isinstance(node, ast.ImportFrom):
            if node.module in ("hashlib", "_hashlib"):
                count += 1
    return count


def scan_package(package_dir: Path) -> list[str]:
    """Return failure messages; empty means the boundary holds."""
    failures: list[str] = []
    seen: set[str] = set()
    py_files = sorted(package_dir.glob("*.py"))
    if not py_files:
        return [f"{package_dir}: no Python files found — refusing to pass an empty scan"]
    for path in py_files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:  # pragma: no cover - a broken tree fails elsewhere
            failures.append(f"{path.name}: unparseable ({exc}); cannot verify the boundary")
            continue
        count = count_hash_references(tree)
        entry = ALLOWLIST.get(path.name)
        if count and entry is None:
            failures.append(
                f"{path.name}: {count} hashlib/_hashlib reference(s), but the file is "
                "not in the trust-bootstrap allowlist. Production hashing belongs on "
                "the native kernels (native_sha256/384/512, native_sha3_256/384/512, "
                "native_pbkdf2_hmac_sha256/512). If this file genuinely joined the "
                "bootstrap, add it to ALLOWLIST in tools/check_stdlib_hash_boundary.py "
                "with the exact count and the reason."
            )
        elif entry is not None:
            seen.add(path.name)
            expected, rationale = entry
            if count != expected:
                failures.append(
                    f"{path.name}: {count} hashlib/_hashlib reference(s), allowlist "
                    f"records {expected} ({rationale}). A new use inside a bootstrap "
                    "file is not covered by the file's rationale — convert it to the "
                    "native kernels, or update the allowlist entry with why the "
                    "bootstrap grew."
                )
    for name in sorted(set(ALLOWLIST) - seen):
        failures.append(
            f"{name}: allowlisted but absent from {PACKAGE_DIR.name}/ — remove the "
            "stale entry so the allowlist cannot quietly cover a future file"
        )
    return failures


def main() -> int:
    failures = scan_package(PACKAGE_DIR)
    if failures:
        print("FAIL  stdlib-hash boundary (INVARIANT-1):")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    total = len(ALLOWLIST)
    print(
        f"OK    stdlib hashlib confined to the {total}-file trust bootstrap "
        "(counts pinned; production hashing is native)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
