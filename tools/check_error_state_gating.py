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
  * calls a native symbol

must call ``check_crypto_permitted()`` **before** the first such call.

Both halves of that sentence were once weaker than they read.

*Ordering.*  The Python audit asked only whether a guard appeared anywhere in
the body, while ``audit_pyx`` — the same gate over the ``.pyx`` bindings — had
always rejected a guard placed after a native call.  Two halves of one gate
enforcing different rules is the kind of gap that survives review, and the
weaker half was guarding the larger surface.  A guard reached after the C
kernel has run does not inhibit anything: the output exists.  FIPS 140-3
§4.9.2 is about not producing it.

*Reachability.*  A native symbol resolved and called in one expression
(``getattr(_native_lib, name)(...)``) was matched; the same call split across
two statements was not, because the binding is not a call and the call is of a
plain local name.  A function written that way reached the C kernel while the
gate recorded it as making no native call — and a function that makes no
native call is never asked for a guard.  Local names bound to a native symbol
are now tracked and calls through them counted.

Neither shape appears in the current tree.  They are closed because nothing
was stopping them, and because a gate is only worth what its weakest branch
enforces.

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

#: The two error-state guards.  ``check_crypto_permitted`` gates the native
#: surface (permissive on the POST thread); ``check_operational`` is the
#: stricter form the high-level ``crypto_api`` surface uses.  Either inhibits
#: output in the ERROR state, so either satisfies the gate.
GUARDS = ("check_crypto_permitted", "check_operational")

#: Prefix of the module-level Cython binding callables (``_cy_hmac_fn`` …).
#: ``hmac_sha3_256`` dispatches to ``_cy_hmac_fn`` when the Cython extension is
#: built and only falls back to the ctypes wrapper otherwise, so a rule that
#: looked solely at ``_native_lib`` missed the fast path this project
#: recommends.  A backend chosen for speed must not be a way around the guard.
CYTHON_PREFIX = "_cy_"

#: Modules the AST gate scans.  It reliably detects a DIRECT native call
#: (``*.ama_*(...)`` or ``_cy_*(...)``) in a public function or method, which is
#: how ``pqc_backends`` — including the whole ``AmaContext`` class — reaches the
#: library.  Modules that reach native only INDIRECTLY through a private helper
#: (``hybrid_combiner`` via ``_hkdf_native``, ``ascon`` via ``_require_native``)
#: are not listed here, because a body-level scan cannot see the reach; those
#: surfaces are enforced behaviourally instead — ``tests/test_post_failclosed.py``
#: drives each in the ERROR state and asserts it refuses, which exercises the
#: real code path rather than approximating it.
MODULES = ("ama_cryptography/pqc_backends.py",)

#: Functions/methods that reach a native symbol without the guard for a stated
#: safe reason.  Keyed by ``name`` or ``Class.method``.  The check refuses to
#: run if an entry names something that no longer exists, so the list cannot rot
#: into a silent allowlist.
EXEMPT: dict[str, str] = {
    "lms_signing_available": (
        "capability probe: returns a bool describing what this build supports. "
        "Raising here would break feature detection in exactly the degraded "
        "state the probe exists to report on, and it emits no cryptographic "
        "output of its own."
    ),
    "AmaContext.close": (
        "resource cleanup: frees the native context (ama_context_free) and must "
        "succeed in the ERROR state so a faulted module still releases memory. "
        "It produces no cryptographic output."
    ),
}


def _is_native_lib_ref(node: ast.AST) -> bool:
    """True for a reference to the native handle — ``_native_lib`` or
    ``self._native_lib`` (the receiver AmaContext methods use)."""
    if isinstance(node, ast.Name):
        return node.id == "_native_lib"
    if isinstance(node, ast.Attribute):
        return node.attr == "_native_lib"
    return False


def _native_handle_aliases(node: ast.AST) -> set[str]:
    """Local names bound to a native symbol without calling it.

    ``_native_call_lines`` matches ``getattr(_native_lib, name)(...)`` — the
    symbol resolved and called in one expression.  Split across two statements
    the same call disappeared from the scan::

        fn = getattr(_native_lib, name)   # binding, not a call
        fn(a, b)                          # call of a plain local name

    Neither line matches on its own, so a function using this shape reached
    the C kernel while the gate reported it as making no native call at all —
    and a function that makes no native call is never required to carry a
    guard.  No current code uses the shape; the point is that nothing stopped
    it, and the two-line form is the natural way to write a loop that resolves
    a symbol once and calls it repeatedly.

    Both routes to a bare symbol are collected: ``getattr(_native_lib, ...)``
    and direct attribute access ``_native_lib.ama_x`` (as a value, not a call).
    """
    aliases: set[str] = set()
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Assign):
            continue
        value = sub.value
        bound = (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "getattr"
            and bool(value.args)
            and _is_native_lib_ref(value.args[0])
        ) or (isinstance(value, ast.Attribute) and value.attr.startswith("ama_"))
        if not bound:
            continue
        for target in sub.targets:
            if isinstance(target, ast.Name):
                aliases.add(target.id)
    return aliases


def _native_call_lines(node: ast.AST) -> list[int]:
    """Line numbers of every native call in the body, by any route.

    Matches an ``ast.Call`` whose function is:

    * an attribute ``*.ama_*`` (so ``_native_lib.ama_x``, ``self._native_lib.ama_x``
      and ``lib.ama_x`` are all caught — the receiver is irrelevant);
    * a ``_cy_*`` Cython binding;
    * a dynamically resolved symbol ``getattr(_native_lib, name)(...)`` — the
      indirection ``_native_shake`` / ``_native_hkdf_sha2`` use to reach the C
      kernel.  Missing this form is what let the SHAKE and HKDF-SHA-2 surfaces
      route past the guard undetected; or
    * a local name bound to a native symbol earlier in the same function (see
      :func:`_native_handle_aliases`).

    Attribute *access* without a call — the ``lib.ama_x.argtypes =`` idiom in the
    ctypes setup helpers, or an un-called ``getattr(_native_lib, x, None)`` probe
    — is deliberately not matched: it configures or inspects a signature, it does
    not perform cryptography.  An alias binding is likewise not a call; only a
    later call *through* the alias counts.
    """
    aliases = _native_handle_aliases(node)
    lines: list[int] = []
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        fn = sub.func
        if isinstance(fn, ast.Attribute) and fn.attr.startswith("ama_"):
            lines.append(sub.lineno)
        elif isinstance(fn, ast.Name) and fn.id.startswith(CYTHON_PREFIX):
            lines.append(sub.lineno)
        elif isinstance(fn, ast.Name) and fn.id in aliases:
            lines.append(sub.lineno)
        # getattr(_native_lib, name)(...) — the outer Call's func is itself a
        # getattr Call on the native handle.  Only the *called* form counts.
        elif (
            isinstance(fn, ast.Call)
            and isinstance(fn.func, ast.Name)
            and fn.func.id == "getattr"
            and fn.args
            and _is_native_lib_ref(fn.args[0])
        ):
            lines.append(sub.lineno)
    return lines


def _calls_native(node: ast.AST) -> bool:
    """True when the body makes a native call by any route."""
    return bool(_native_call_lines(node))


def _calls_guard(node: ast.AST) -> bool:
    """True when the body calls an error-state guard.

    Receiver-agnostic, mirroring ``_calls_native``: both the direct form the
    package convention uses (``check_crypto_permitted()`` after a ``from …
    import``) and the module-qualified form (``_module_state.
    check_crypto_permitted()``, ``st.check_operational()``) are real guard
    calls, and flagging the qualified form would report a gated function as
    ungated.  The symmetric risk — a same-named method on an unrelated object
    satisfying the check — is accepted for the same reason ``_calls_native``
    accepts any ``*.ama_*`` receiver: this gate enforces the convention;
    ``tests/test_post_failclosed.py`` proves the behaviour by driving each
    surface in the ERROR state.
    """
    return bool(_guard_call_lines(node))


def _guard_call_lines(node: ast.AST) -> list[int]:
    """Line numbers of every error-state guard call in the body."""
    lines: list[int] = []
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        fn = sub.func
        if isinstance(fn, ast.Name) and fn.id in GUARDS:
            lines.append(sub.lineno)
        elif isinstance(fn, ast.Attribute) and fn.attr in GUARDS:
            lines.append(sub.lineno)
    return lines


def _iter_public_functions(tree: ast.Module):
    """Yield ``(display_name, node)`` for every public function and method.

    Descends one level into public classes so class methods — the blind spot
    that let ``AmaContext`` run crypto in the ERROR state — are covered.  A
    method is public when neither its own name nor its enclosing class name
    starts with an underscore (dunders and private members are excluded)."""
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not node.name.startswith("_"):
                yield node.name, node
        elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if not sub.name.startswith("_"):
                        yield f"{node.name}.{sub.name}", sub


def audit(
    path: Path, exempt: dict[str, str] | None = None
) -> tuple[list[tuple[str, int]], list[str], int]:
    """Return ``(ungated, stale_exemptions, checked_count)`` for one module.

    ``exempt`` defaults to :data:`EXEMPT`; it is a parameter so the audit logic
    can be exercised over a synthetic module without the real exemption list
    reporting every one of its entries as stale.
    """
    if exempt is None:
        exempt = EXEMPT
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    ungated: list[tuple[str, int]] = []
    seen: set[str] = set()
    checked = 0

    for display, node in _iter_public_functions(tree):
        native_lines = _native_call_lines(node)
        if not native_lines:
            continue
        seen.add(display)
        if display in exempt:
            continue
        checked += 1
        guard_lines = _guard_call_lines(node)
        if not guard_lines:
            ungated.append((display, node.lineno))
        elif min(native_lines) < min(guard_lines):
            # Guard present but reached only after a native call has already
            # run — the module is in the ERROR state, output has been produced,
            # and the guard raises too late to inhibit it.  ``audit_pyx`` has
            # rejected this ordering since it was written; the Python half
            # asked only whether a guard appeared anywhere in the body, so the
            # two halves of the same gate enforced different rules.
            ungated.append((display, min(native_lines)))

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
    guard_alt = "|".join(re.escape(g) for g in GUARDS)
    guard_re = re.compile(rf"\b(?:{guard_alt})\s*\(\s*\)")
    ungated: list[tuple[str, int]] = []

    starts = [(i, m.group(1)) for i, line in enumerate(lines) if (m := def_re.match(line))]
    for idx, (start, name) in enumerate(starts):
        end = starts[idx + 1][0] if idx + 1 < len(starts) else len(lines)
        # Strip comments before matching so a commented-out ``# check_crypto_permitted()``
        # cannot satisfy the guard check, and a ``# ... ama_foo()`` mention in a comment
        # is not mistaken for a native call.  Require the guard as a real, no-arg call
        # (optional inner whitespace), not a bare substring.
        body = [_strip_comment(ln) for ln in _strip_leading_docstring(lines[start + 1 : end])]
        guard_line = next((j for j, ln in enumerate(body) if guard_re.search(ln)), None)
        native_line = next(
            (j for j, ln in enumerate(body) if re.search(r"\bama_\w+\s*\(", ln)), None
        )
        if guard_line is None:
            ungated.append((name, start + 1))
        elif native_line is not None and native_line < guard_line:
            # Guard present but after a native call — output already produced.
            ungated.append((name, start + 1))
    return ungated


def _strip_comment(line: str) -> str:
    """Drop a trailing ``#`` comment so a commented-out guard or ``ama_*`` call is
    not read as a real one.  Naive (no string-literal awareness), which is safe
    here: the guard and native call sites this scans are never inside string
    literals in the ``.pyx`` bindings."""
    return line.split("#", 1)[0]


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
    total_ungated: list[tuple[str, str, int]] = []
    total_checked = 0
    seen_exempt: set[str] = set()

    for rel_mod in MODULES:
        mod_path = REPO_ROOT / rel_mod
        if not mod_path.is_file():
            print(f"ERROR: module {rel_mod} not found", file=sys.stderr)
            return 1
        ungated, _stale, checked = audit(mod_path)
        total_checked += checked
        total_ungated.extend((rel_mod, name, lineno) for name, lineno in ungated)
        # Track which exemptions matched somewhere so staleness is computed
        # across the union of scanned modules, not per file.
        tree = ast.parse(mod_path.read_text(encoding="utf-8"), filename=str(mod_path))
        for display, node in _iter_public_functions(tree):
            if _calls_native(node) and display in EXEMPT:
                seen_exempt.add(display)

    # Cython binding modules (line-based, not AST).
    pyx_ungated: list[tuple[str, str, int]] = []
    pyx_checked = 0
    for rel_pyx in BINDING_PYX:
        pyx_path = REPO_ROOT / rel_pyx
        if not pyx_path.is_file():
            print(f"ERROR: expected binding {rel_pyx} not found", file=sys.stderr)
            return 1
        pyx_checked += _count_cy_funcs(pyx_path)
        pyx_ungated.extend((rel_pyx, name, lineno) for name, lineno in audit_pyx(pyx_path))

    stale = sorted(name for name in EXEMPT if name not in seen_exempt)
    if stale:
        print(
            "ERROR: stale entries in EXEMPT — these no longer exist or no longer "
            "reach a native symbol, so the exemption is dead weight that would "
            "silently cover a future function of the same name:",
            file=sys.stderr,
        )
        for name in stale:
            print(f"  - {name}", file=sys.stderr)
        return 1

    if total_ungated or pyx_ungated:
        n = len(total_ungated) + len(pyx_ungated)
        print(
            f"ERROR: {n} public entry point(s) reach the native library without "
            "an error-state guard.\n\n"
            "FIPS 140-3 §4.9.2 requires that a module whose power-on self-tests "
            "failed inhibit ALL cryptographic output. Each below would still "
            "produce output in the error state:\n",
            file=sys.stderr,
        )
        for rel_mod, name, lineno in total_ungated:
            print(f"  {rel_mod}:{lineno}: {name}", file=sys.stderr)
        for rel_pyx, name, lineno in pyx_ungated:
            print(f"  {rel_pyx}:{lineno}: {name}() [Cython binding]", file=sys.stderr)
        print(
            f"\nFix: call one of {GUARDS} before the first native call. If the "
            "function genuinely emits no cryptographic output, add it to EXEMPT "
            "with the reason.",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: all {total_checked} public native entry points across "
        f"{len(MODULES)} module(s) and {pyx_checked} Cython binding entry points "
        f"are gated ({len(EXEMPT)} documented exemption(s))."
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
