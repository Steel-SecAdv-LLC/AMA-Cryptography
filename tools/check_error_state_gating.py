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

A third variant of the same class — a symbol *selected* between two native
references, ``fn = _native_lib.ama_a if cond else _native_lib.ama_b`` — did
appear in the current tree, and had since 2026-07-28: ``native_nistp_ecdsa_verify``
in ``pqc_backends.py``, a public module-level entry point in the one module
this gate audits.  It was invisible for the same reason as the split binding,
so the audit skipped the function entirely and its guard was unenforced;
deleting that guard left the tool's output unchanged.  Conditional and
annotated bindings are now tracked too, and the entry-point count went from
85 to 86.

An earlier revision of this docstring asserted that neither shape appeared in
the tree.  That was true of the two shapes it described and false of the class
they belong to, which is the more useful thing for a reader to know: the
lesson is that a gate matching a fixed list of syntactic shapes is only as
complete as that list, so the matcher now recurses through the forms that
*are* the resulting callable rather than enumerating spellings.  It
deliberately does not walk the whole expression: ``x = wrapper(_native_lib.ama_y)``
does not bind ``x`` to the native symbol, and a gate that demands a guard
there would fire on correct code.

Deliberate exemptions live in ``EXEMPT`` below, each with a stated reason.
The exemption list is itself checked: an entry naming a function that no
longer exists is an error, so the list cannot rot into a silent allowlist.

Which modules are scanned
-------------------------
``MODULES`` was hand-maintained, which meant a new module reaching the native
library was unaudited *by default* rather than by decision (audit M16).  A
discovery step now AST-scans ``ama_cryptography/**/*.py`` for the forms that
reach the library — ``_native_lib`` as a Name/Attribute, ``getattr(x,
"_native_lib", …)``, or a ``_cy_*`` call — and requires every module it finds
to appear in ``MODULES`` (audited) or in ``EXEMPT_MODULES`` (exempted with a
reason for why the body-level AST audit is not its enforcement — indirect
reach through a private helper, a presence check, or delegation to
``pqc_backends``' gated wrappers).  A native-reaching module in neither list
fails the check.  ``EXEMPT_MODULES`` is staleness-checked the same way
``EXEMPT`` is: an entry that no longer reaches the library is an error.

Usage
-----
    python tools/check_error_state_gating.py

Exit status: 0 when every public native entry point is gated, 1 otherwise.
"""

from __future__ import annotations

import ast
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Optional

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
#: library.
#:
#: ``ascon`` is here now, and the reason it was not is worth recording because
#: it was a wrong reason rather than a missing one.  The note that stood here
#: said ``ascon`` reaches native "only INDIRECTLY through a private helper
#: (``_require_native``) … because a body-level scan cannot see the reach".
#: The reach was never the problem: ``ascon.hash256`` and the two AEAD entry
#: points each call ``lib.ama_ascon_*(...)`` in their own bodies, and
#: ``_native_call_lines`` is receiver-agnostic, so the scan saw every one of
#: them.  What it could not see was the GUARD, which sits inside
#: ``_require_native``.  :func:`guard_delegating_helpers` now follows exactly
#: one level of that indirection — a private function whose FIRST executable
#: statement is a guard call — so the module can be enforced statically
#: instead of being excluded on a premise that did not hold.
#:
#: ``hybrid_combiner`` stays out, and for that one the original note IS
#: accurate: it reaches native through ``_hkdf_native``, which is where both
#: the guard and the native call live, so the public functions' bodies contain
#: neither.  It is enforced behaviourally by ``tests/test_post_failclosed.py``,
#: which drives each surface in the ERROR state and asserts it refuses.
MODULES = (
    "ama_cryptography/pqc_backends.py",
    "ama_cryptography/ascon.py",
    # Added by the discovery step below (audit M16): both have a directly
    # auditable public native surface, so they are audited rather than exempted.
    # ``agent_binding`` reaches ``_native_lib.ama_*`` in five public methods
    # (derive_key, signing_context, authorize, …), each guarded with
    # check_crypto_permitted().  ``secure_memory`` reaches native in
    # secure_mlock/secure_munlock — page locking that emits no key material, so
    # both are in EXEMPT below — and auditing the module means a future public
    # function there that DOES emit cryptographic output is caught by default.
    "ama_cryptography/agent_binding.py",
    "ama_cryptography/secure_memory.py",
)

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
    "secure_mlock": (
        "page locking: calls ama_secure_mlock to pin a page in RAM and returns a "
        "status int. It emits no key material and produces no cryptographic "
        "output, so it is outside INVARIANT-39's output-inhibition scope (audit "
        "M16). The module's actual entropy surface, secure_random_bytes, routes "
        "through secure_token_bytes and is gated."
    ),
    "secure_munlock": (
        "page unlocking: the ama_secure_munlock counterpart to secure_mlock; "
        "must succeed in the ERROR state so a faulted module still releases the "
        "locked pages, and it emits no key material."
    ),
}

#: Modules that reach the native library but are NOT in :data:`MODULES`, each
#: with the reason the AST audit is not the right enforcement for them.  The
#: discovery step in :func:`main` requires every native-reaching package module
#: to appear in ``MODULES`` or here — so a NEW module that reaches the library is
#: audited or exempted on purpose, not unaudited by silent omission (audit M16).
#:
#: These all reach native only INDIRECTLY — through a private helper, a presence
#: check, or delegation to ``pqc_backends``' already-gated wrappers — so a
#: body-level AST scan of their public functions sees no direct native call to
#: require a guard on.  Their behaviour is enforced elsewhere, as noted.
#:
#: Like ``EXEMPT``, this list is staleness-checked: an entry naming a module that
#: no longer reaches the native library is an error, so it cannot rot into a
#: silent allowlist.
EXEMPT_MODULES: dict[str, str] = {
    "ama_cryptography/_self_test.py": (
        "POST and integrity verification. Reaches native only through private "
        "helpers (_load_integrity_trust_anchor reads the compiled trust anchor; "
        "the signed-integrity path calls native Ed25519 verify) — this module "
        "RUNS power-on self-test and SETS the error state, so gating it with "
        "check_crypto_permitted would be circular. It emits no cryptographic "
        "output on a caller's behalf."
    ),
    "ama_cryptography/crypto_api.py": (
        "High-level API. Reaches native only through pqc_backends' guarded "
        "wrappers (no direct _native_lib.ama_* call in any public function); its "
        "own _native_lib references are the INVARIANT-7 presence check, and it "
        "additionally calls check_operational() on its public methods."
    ),
    "ama_cryptography/hybrid_combiner.py": (
        "Reaches native through _hkdf_native, where both the guard and the "
        "native call live, so the public functions' own bodies contain neither. "
        "Enforced behaviourally by tests/test_post_failclosed.py, which drives "
        "each surface in the ERROR state and asserts it refuses."
    ),
    "ama_cryptography/key_management.py": (
        "Reaches native only through pqc_backends' already-gated wrappers "
        "(native_hmac_sha512, native_argon2id, native_secp256k1_pubkey_from_privkey, "
        "…); its own _native_lib reference is the INVARIANT-7 call-time presence "
        "check (_enforce_invariant7), which emits no cryptographic output."
    ),
    "ama_cryptography/legacy_compat.py": (
        "Reaches native only through the INVARIANT-7 call-time presence check "
        "(getattr(pqc_backends, '_native_lib', None) is None); all cryptographic "
        "output is delegated to pqc_backends' gated wrappers."
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

    A symbol *selected* between two such references counts too.  Matching only
    the two flat shapes above missed::

        fn = _native_lib.ama_nistp_ecdsa_verify_raw_ex if raw else \\
             _native_lib.ama_nistp_ecdsa_verify_ex
        rc = int(fn(...))

    which is an ``ast.IfExp``, not an ``Attribute``.  That shape is not
    hypothetical and is not new: ``native_nistp_ecdsa_verify`` in
    ``pqc_backends.py`` — a public module-level entry point, in the one module
    this gate audits — has used it since 2026-07-28, predating the
    alias-tracking commit whose docstring said "Neither shape appears in the
    current tree".  Measured before this fix: ``_native_call_lines`` returned
    ``[]`` and ``_calls_native`` returned ``False`` for that function, so
    ``audit()`` skipped it at the "no native lines" guard and never asked
    whether it was gated.  Deleting its ``check_crypto_permitted()`` from a
    copy of the module left the audit's output completely unchanged.  The
    function *is* correctly guarded today; the defect was that the gate had
    silently stopped enforcing it, which is precisely the regression this
    module exists to prevent.

    The recursion is deliberately narrow — ``IfExp`` branches and ``BoolOp``
    operands, both of which *are* the resulting callable — rather than a walk
    of the whole expression.  A blanket walk would also match
    ``x = wrapper(_native_lib.ama_y)``, where ``x`` is not the native symbol,
    and would then demand a guard on functions that make no native call: a
    gate that fires on correct code teaches people to bypass it.
    """
    aliases: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Assign):
            targets, value = list(sub.targets), sub.value
        elif isinstance(sub, ast.AnnAssign) and sub.value is not None:
            # `fn: Callable[..., int] = _native_lib.ama_x` is the same binding
            # wearing an annotation, and was equally invisible.
            targets, value = [sub.target], sub.value
        else:
            continue
        if not _binds_native_symbol(value):
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                aliases.add(target.id)
    return aliases


def _binds_native_symbol(value: ast.expr) -> bool:
    """Whether an assigned expression yields a native symbol to call later."""
    if (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id == "getattr"
        and bool(value.args)
        and _is_native_lib_ref(value.args[0])
    ):
        return True
    if isinstance(value, ast.Attribute) and value.attr.startswith("ama_"):
        return True
    if isinstance(value, ast.IfExp):
        # Either branch reaching the C kernel is enough; recursion handles a
        # chain of them.
        return _binds_native_symbol(value.body) or _binds_native_symbol(value.orelse)
    if isinstance(value, ast.BoolOp):
        return any(_binds_native_symbol(operand) for operand in value.values)
    return False


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


def _calls_guard(node: ast.AST, delegating: Optional[set[str]] = None) -> bool:
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
    return bool(_guard_call_lines(node, delegating))


def guard_delegating_helpers(tree: ast.AST) -> set[str]:
    """Module-local private functions that ARE a guard, for this gate's purpose.

    A function qualifies when its first executable statement (a docstring does
    not count) is a bare call to one of :data:`GUARDS`.  ``ascon._require_native``
    is the shape:

        def _require_native() -> Any:
            check_crypto_permitted()
            if not ASCON_AVAILABLE:
                ...
            return _lib

    Every public Ascon entry point opens with ``lib = _require_native()`` and
    then calls ``lib.ama_ascon_*`` in its own body — so ``_calls_native``, which
    is receiver-agnostic, sees the native call, while ``_calls_guard`` did not
    see the guard.  The module was therefore left out of ``MODULES`` with a
    comment saying "a body-level scan cannot see the reach", which was true of
    ``hybrid_combiner`` and not of ``ascon``: the reach was visible, the GUARD
    was not.

    "First executable statement" is the whole rule, deliberately.  A helper
    that guards inside an ``if`` or after other work guards only sometimes, and
    a gate that accepted that would be asserting something weaker than it says.
    """
    helpers: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = list(node.body)
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
            body = body[1:]  # docstring
        if not body:
            continue
        first = body[0]
        if not isinstance(first, ast.Expr) or not isinstance(first.value, ast.Call):
            continue
        fn = first.value.func
        name = (
            fn.id
            if isinstance(fn, ast.Name)
            else (fn.attr if isinstance(fn, ast.Attribute) else None)
        )
        if name in GUARDS:
            helpers.add(node.name)
    return helpers


def _guard_call_lines(node: ast.AST, delegating: Optional[set[str]] = None) -> list[int]:
    """Line numbers of every error-state guard call in the body.

    ``delegating`` names module-local helpers that open with a guard call; see
    :func:`guard_delegating_helpers`.  Calling one of those counts as calling
    the guard, because it is one — with the ordering intact, since the helper
    guards before it returns anything the caller can use.
    """
    lines: list[int] = []
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        fn = sub.func
        if isinstance(fn, ast.Name) and fn.id in GUARDS:
            lines.append(sub.lineno)
        elif isinstance(fn, ast.Attribute) and fn.attr in GUARDS:
            lines.append(sub.lineno)
        elif delegating and isinstance(fn, ast.Name) and fn.id in delegating:
            lines.append(sub.lineno)
    return lines


def _iter_public_functions(
    tree: ast.Module,
) -> Iterator[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]:
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


def _module_reaches_native(tree: ast.AST) -> bool:
    """Whether a module reaches the native library by any form that could let a
    public function emit cryptographic output.

    Matched on the AST so comments and lookalike names (``_find_native_library``
    contains the substring ``_native_lib``) are never false positives:

    * ``_native_lib`` as a Name or an Attribute — the direct handle;
    * ``getattr(x, "_native_lib", ...)`` — the dynamic-by-string re-read
      ``crypto_api`` and ``legacy_compat`` use so ``sys.modules`` patches take
      effect;
    * a call to a ``_cy_*`` Cython binding — the fast path that bypasses the
      ctypes wrappers.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == "_native_lib":
            return True
        if isinstance(node, ast.Attribute) and node.attr == "_native_lib":
            return True
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id.startswith(CYTHON_PREFIX):
                return True
            if (
                isinstance(fn, ast.Name)
                and fn.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value == "_native_lib"
            ):
                return True
    return False


def discover_native_reaching_modules(repo: Path) -> list[str]:
    """Every package module that reaches the native library, repo-relative.

    Scans ``ama_cryptography/**/*.py`` (skipping ``__pycache__``) so a module
    added later cannot reach the library while escaping this gate simply by not
    being listed — the silent omission the discovery exists to make impossible
    (audit M16).  Each result must appear in :data:`MODULES` (audited) or
    :data:`EXEMPT_MODULES` (exempted with a reason); :func:`main` enforces it.
    """
    pkg = repo / "ama_cryptography"
    found: list[str] = []
    for path in sorted(pkg.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:
            continue
        if _module_reaches_native(tree):
            found.append(str(path.relative_to(repo)))
    return found


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
    delegating = guard_delegating_helpers(tree)

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
        guard_lines = _guard_call_lines(node, delegating)
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


def entry_point_counts() -> tuple[int, int]:
    """(native entry points, Cython binding entry points) that this gate covers.

    Exposed so ``tools/check_documented_counts.py`` can compare the figures
    published in INVARIANTS.md and CHANGELOG.md against the tool those
    documents name as authoritative, instead of against a number someone typed.
    Both had drifted to 85 while this tool reported 86 — the count moved when a
    native symbol selected by a conditional expression started being tracked,
    and the two documents did not follow.

    Raises the same way ``main`` fails: a missing module is an error, not a
    smaller count.
    """
    native = 0
    for rel_mod in MODULES:
        mod_path = REPO_ROOT / rel_mod
        if not mod_path.is_file():
            raise FileNotFoundError(f"module {rel_mod} not found")
        _ungated, _stale, checked = audit(mod_path)
        native += checked
    cython = 0
    for rel_pyx in BINDING_PYX:
        pyx_path = REPO_ROOT / rel_pyx
        if not pyx_path.is_file():
            raise FileNotFoundError(f"binding {rel_pyx} not found")
        cython += _count_cy_funcs(pyx_path)
    return native, cython


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

    # Discovery (audit M16): every package module that reaches the native
    # library must be audited (MODULES) or exempted on purpose (EXEMPT_MODULES).
    # Before this, MODULES was hand-maintained and a new native-reaching module
    # was unaudited by default rather than by decision.
    discovered = discover_native_reaching_modules(REPO_ROOT)
    classified = set(MODULES) | set(EXEMPT_MODULES)
    unclassified = sorted(m for m in discovered if m not in classified)
    if unclassified:
        print(
            "ERROR: module(s) reach the native library but appear in neither "
            "MODULES (to be audited) nor EXEMPT_MODULES (exempted with a reason). "
            "A module reaching the library while unlisted is unaudited by "
            "omission — decide on purpose:",
            file=sys.stderr,
        )
        for name in unclassified:
            print(f"  - {name}", file=sys.stderr)
        return 1

    stale_modules = sorted(m for m in EXEMPT_MODULES if m not in discovered)
    if stale_modules:
        print(
            "ERROR: stale entries in EXEMPT_MODULES — these no longer reach the "
            "native library, so the exemption is dead weight that would silently "
            "cover a future module of the same path:",
            file=sys.stderr,
        )
        for name in stale_modules:
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
        f"are gated ({len(EXEMPT)} documented function exemption(s)). "
        f"Discovery: {len(discovered)} native-reaching module(s), all classified "
        f"({len(MODULES)} audited, {len(EXEMPT_MODULES)} exempted with a reason)."
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
