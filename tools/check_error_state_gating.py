#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — FIPS 140-3 §4.9.2 Error-State Gating Check
=============================================================

Asserts that every public entry point in ``ama_cryptography/pqc_backends.py``
which reaches the native library refuses to run while the module is in the
FIPS error state.

Why
---
FIPS 140-3 §4.9.2 requires a module whose power-on self-tests have failed to
enter an error state in which *all* cryptographic output is inhibited.  For
most of this library's life that requirement was satisfied only by
``crypto_api``, which calls ``check_operational()`` on its public methods.
``pqc_backends`` — the layer that actually performs key generation, signing,
KEM encapsulation, AEAD, HMAC and KDF — called straight through to the C
library with no state check at all.  Eighty public functions, none of them
gated.  A module that had logged ``FIPS 140-3 POST FAILURE`` at import went on
signing and generating keys for any caller that reached past ``crypto_api``,
which is exactly what every one of this project's own internal modules does.
The error state inhibited nothing that mattered.

The fix is one call to ``check_crypto_permitted()`` at the top of each such
function.  That fix is one line, which is precisely why it needs a machine to
enforce it: the next primitive added to this module will be written by
someone who has never read this file, and a convention that depends on memory
is a convention that decays.  A gap here is silent — the function works, the
tests pass, and the only symptom is a FIPS violation that appears solely on
the failure path nobody exercises.

What this checks
----------------
Every module-level ``def`` in ``pqc_backends.py`` that

  * has a public name (no leading underscore), and
  * contains an attribute access on ``_native_lib``

must call ``check_crypto_permitted()`` somewhere in its body.

Deliberate exemptions live in ``EXEMPT`` below, each with a stated reason.
The exemption list is itself checked: an entry naming a function that no
longer exists is an error, so the list cannot rot into a silent allowlist.

Usage
-----
    python tools/check_error_state_gating.py

Exit status: 0 when every public native entry point is gated, 1 otherwise.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET = REPO_ROOT / "ama_cryptography" / "pqc_backends.py"

GUARD = "check_crypto_permitted"

#: The ctypes handle on the shared library.
NATIVE_HANDLE = "_native_lib"

#: Prefix of the module-level Cython binding callables (``_cy_hmac_fn``,
#: ``_cy_sha3_fn``, ``_cy_ed25519_sign_fn`` …).
#:
#: These have to count, and the reason is not hypothetical.  ``hmac_sha3_256``
#: dispatches to ``_cy_hmac_fn`` when the Cython extension is built and only
#: falls back to the ctypes wrapper otherwise.  A rule that looked solely for
#: ``_native_lib`` therefore declared it out of scope, and on precisely the
#: builds this project recommends — the ones with the fast bindings compiled —
#: HMAC ran in the error state.  A backend chosen for speed must not also be a
#: way around the guard.
CYTHON_PREFIX = "_cy_"

#: Functions that legitimately reach ``_native_lib`` without the guard.
#: Each entry must carry the reason it is safe; the check refuses to run if an
#: entry names a function that no longer exists.
EXEMPT: Dict[str, str] = {
    "lms_signing_available": (
        "capability probe: returns a bool describing what this build supports. "
        "Raising here would break feature detection in exactly the degraded "
        "state the probe exists to report on, and it emits no cryptographic "
        "output of its own."
    ),
}


def _reaches_native(node: ast.FunctionDef) -> bool:
    """True when the function body reaches compiled code by either route.

    Both routes count: the ctypes handle on the shared library, and the Cython
    binding callables that bypass it entirely.
    """
    for sub in ast.walk(node):
        if (
            isinstance(sub, ast.Attribute)
            and isinstance(sub.value, ast.Name)
            and sub.value.id == NATIVE_HANDLE
        ):
            return True
        if isinstance(sub, ast.Name) and sub.id.startswith(CYTHON_PREFIX):
            return True
    return False


def _calls_guard(node: ast.FunctionDef) -> bool:
    """True when the function body calls the error-state guard."""
    return any(
        isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id == GUARD
        for sub in ast.walk(node)
    )


def audit(
    path: Path, exempt: Dict[str, str] | None = None
) -> Tuple[List[Tuple[str, int]], List[str], int]:
    """Return ``(ungated, stale_exemptions, checked_count)``.

    ``exempt`` defaults to :data:`EXEMPT`; it is a parameter so the audit logic
    can be exercised over a synthetic module without the real exemption list
    reporting every one of its entries as stale.
    """
    if exempt is None:
        exempt = EXEMPT
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    ungated: List[Tuple[str, int]] = []
    seen: set = set()
    checked = 0

    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name.startswith("_"):
            continue
        if not _reaches_native(node):
            continue

        seen.add(node.name)
        if node.name in exempt:
            continue

        checked += 1
        if not _calls_guard(node):
            ungated.append((node.name, node.lineno))

    stale = sorted(name for name in exempt if name not in seen)
    return ungated, stale, checked


def main() -> int:
    if not TARGET.is_file():
        print(f"ERROR: {TARGET} not found", file=sys.stderr)
        return 1

    ungated, stale, checked = audit(TARGET)
    rel = TARGET.relative_to(REPO_ROOT)

    if stale:
        print(
            "ERROR: stale entries in EXEMPT — these functions no longer exist "
            "or no longer reach the native library, so the exemption is dead "
            "weight that would silently cover a future function of the same "
            "name:",
            file=sys.stderr,
        )
        for name in stale:
            print(f"  - {name}", file=sys.stderr)
        return 1

    if ungated:
        print(
            f"ERROR: {len(ungated)} public entry point(s) in {rel} reach the "
            f"native library without calling {GUARD}().\n"
            "\n"
            "FIPS 140-3 §4.9.2 requires that a module whose power-on "
            "self-tests failed inhibit ALL cryptographic output. Each function "
            "below would still produce output in the error state:\n",
            file=sys.stderr,
        )
        for name, lineno in ungated:
            print(f"  {rel}:{lineno}: {name}()", file=sys.stderr)
        print(
            f"\nFix: add `{GUARD}()` as the first statement after the "
            "docstring. If the function genuinely emits no cryptographic "
            "output, add it to EXEMPT in this file with the reason.",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: all {checked} public native entry points in {rel} are gated on "
        f"{GUARD}() ({len(EXEMPT)} documented exemption(s))."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
