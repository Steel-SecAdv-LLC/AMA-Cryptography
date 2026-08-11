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
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET = REPO_ROOT / "ama_cryptography" / "pqc_backends.py"

#: The Cython binding modules.  Each is a public submodule
#: (``ama_cryptography.ed25519_binding`` …) whose ``cy_*`` functions call the C
#: kernel directly — bypassing ``pqc_backends``' gated wrappers, and, when the
#: package directory is on ``sys.path``, bypassing POST itself.  They are not
#: valid Python (``cdef`` etc.), so they get a line-based check rather than the
#: AST one used for ``pqc_backends.py``.
BINDING_PYX = (
    "src/cython/ed25519_binding.pyx",
    "src/cython/hmac_binding.pyx",
    "src/cython/sha3_binding.pyx",
    "src/cython/dilithium_binding.pyx",
    "src/cython/hkdf_binding.pyx",
)

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
EXEMPT: dict[str, str] = {
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
    path: Path, exempt: dict[str, str] | None = None
) -> tuple[list[tuple[str, int]], list[str], int]:
    """Return ``(ungated, stale_exemptions, checked_count)``.

    ``exempt`` defaults to :data:`EXEMPT`; it is a parameter so the audit logic
    can be exercised over a synthetic module without the real exemption list
    reporting every one of its entries as stale.
    """
    if exempt is None:
        exempt = EXEMPT
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    ungated: list[tuple[str, int]] = []
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


def audit_pyx(path: Path) -> list[tuple[str, int]]:
    """Return ``[(funcname, lineno), ...]`` for ungated ``cy_*`` binding funcs.

    A line-based scan because ``.pyx`` is not valid Python.  Every module-level
    ``def cy_...`` must call ``check_crypto_permitted()`` somewhere in its body,
    and before the first native ``ama_`` call, so the guard cannot be placed
    after cryptographic output has already been produced.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    def_re = re.compile(r"^def (cy_\w+)\s*\(")
    ungated: list[tuple[str, int]] = []

    starts = [(i, m.group(1)) for i, line in enumerate(lines) if (m := def_re.match(line))]
    for idx, (start, name) in enumerate(starts):
        end = starts[idx + 1][0] if idx + 1 < len(starts) else len(lines)
        body = _strip_leading_docstring(lines[start + 1 : end])
        guard_line = next((j for j, ln in enumerate(body) if f"{GUARD}()" in ln), None)
        native_line = next(
            (j for j, ln in enumerate(body) if re.search(r"\bama_\w+\s*\(", ln)), None
        )
        if guard_line is None:
            ungated.append((name, start + 1))
        elif native_line is not None and native_line < guard_line:
            # Guard present but after a native call — output already produced.
            ungated.append((name, start + 1))
    return ungated


def _strip_leading_docstring(body: list[str]) -> list[str]:
    """Drop a leading triple-quoted docstring so its prose (which mentions the
    ``ama_*`` symbols by name) is not mistaken for a native call site."""
    i = 0
    while i < len(body) and body[i].strip() == "":
        i += 1
    if i < len(body):
        stripped = body[i].strip()
        for quote in ('"""', "'''"):
            if stripped.startswith(quote):
                # Single-line docstring?
                if len(stripped) >= 6 and stripped.endswith(quote) and stripped != quote:
                    return body[i + 1 :]
                for j in range(i + 1, len(body)):
                    if quote in body[j]:
                        return body[j + 1 :]
                return body[i + 1 :]
    return body[i:]


def main() -> int:
    if not TARGET.is_file():
        print(f"ERROR: {TARGET} not found", file=sys.stderr)
        return 1

    ungated, stale, checked = audit(TARGET)
    rel = TARGET.relative_to(REPO_ROOT)

    # Cython binding modules.
    pyx_ungated: list[tuple[str, str, int]] = []
    pyx_checked = 0
    for rel_pyx in BINDING_PYX:
        pyx_path = REPO_ROOT / rel_pyx
        if not pyx_path.is_file():
            print(f"ERROR: expected binding {rel_pyx} not found", file=sys.stderr)
            return 1
        found = audit_pyx(pyx_path)
        pyx_checked += _count_cy_funcs(pyx_path)
        pyx_ungated.extend((rel_pyx, name, lineno) for name, lineno in found)

    if pyx_ungated:
        print(
            f"ERROR: {len(pyx_ungated)} Cython binding entry point(s) call the "
            f"native library without a leading {GUARD}().\n\n"
            "These are public submodules; a direct importer reaches them without "
            "pqc_backends' gate. Each must call the guard before any ama_* call:\n",
            file=sys.stderr,
        )
        for rel_pyx, name, lineno in pyx_ungated:
            print(f"  {rel_pyx}:{lineno}: {name}()", file=sys.stderr)
        return 1

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
        f"OK: all {checked} public native entry points in {rel} and "
        f"{pyx_checked} Cython binding entry points are gated on {GUARD}() "
        f"({len(EXEMPT)} documented exemption(s))."
    )
    return 0


def _count_cy_funcs(path: Path) -> int:
    return sum(
        1
        for line in path.read_text(encoding="utf-8").splitlines()
        if re.match(r"^def cy_\w+\s*\(", line)
    )


if __name__ == "__main__":
    sys.exit(main())
