# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""INVARIANT-41: every bare RNG draw in the shipped package is accounted for.

Why this gate exists
--------------------
INVARIANT-41 routes key material, nonces, and every identifier a key
derivation consumes through ``secure_token_bytes`` — the wrapper that runs
the FIPS 140-3 §4.9.2 continuous stuck-DRBG check and refuses in the ERROR
state.  The invariant was enforced by hand-sweeping the package for bare
``secrets.token_bytes`` / ``os.urandom`` calls and fixing what the sweep
found.  That sweep missed exactly one site: the responder-side handshake
session ID in ``secure_channel.py``, which is signed into the transcript
and consumed by ``_derive_session`` — while the initiator side of the very
same protocol drew through the health-tested wrapper.  A hand sweep that
must be re-run perfectly after every change is not a control; this module
is the control.

What it enforces
----------------
Every call site of a bare OS-entropy draw in ``ama_cryptography/`` must be
on the allowlist below, and every allowlist entry must still exist.  The
allowlist names its reasons: an entry is either the health-tested wrapper's
own entropy source, the POST stage that tests the RNG, a build-time context
where POST is structurally unavailable, or a draw whose output is not
security-load-bearing.  Demo code under ``if __name__ == "__main__":`` is
exempt — it never runs on import and models caller code, not library code.

Both directions are pinned: the sweep must flag a bare draw added to a
shipped code path (``test_the_sweep_can_fail``), and must not flag the
``__main__`` demo form (``test_main_guard_is_exempt``).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from ama_cryptography.exceptions import CryptoModuleError

PACKAGE_DIR = Path(__file__).resolve().parent.parent / "ama_cryptography"

#: Call shapes that reach OS entropy without the continuous health test.
#: ``secrets.SystemRandom`` / ``random.SystemRandom`` are included so a
#: draw cannot be laundered through an instance the sweep never sees.
BARE_DRAW_CALLS = frozenset(
    {
        "secrets.token_bytes",
        "os.urandom",
        "random.randbytes",
        "secrets.SystemRandom",
        "random.SystemRandom",
    }
)

#: (module filename, dotted enclosing context) -> reason the bare draw is
#: legitimate THERE.  A new bare draw anywhere else fails the sweep; a
#: stale entry (code moved or was fixed) fails the allowlist-rot test.
ALLOWED_BARE_DRAWS: dict[tuple[str, str], str] = {
    ("_module_state.py", "secure_token_bytes"): (
        "the health-tested wrapper itself — this call IS the entropy source "
        "the continuous check wraps"
    ),
    ("_self_test.py", "_run_rng_stage"): (
        "POST's RNG stage draws bare on purpose: it is the test that decides "
        "whether the gated wrapper may be trusted at all"
    ),
    ("_build_sign.py", "_generate_keypair_and_sign"): (
        "build-time ephemeral signer; runs while the package may be mid-"
        "re-sign with POST structurally unavailable, and carries its own "
        "two-draw stuck-entropy check at the call site"
    ),
    ("key_management.py", "SecureKeyStorage.delete_key"): (
        "random overwrite passes for secure deletion; the bytes are never "
        "secret and predictability is not load-bearing (zeros would satisfy "
        "the same contract)"
    ),
}


def _bare_draw_sites(tree: ast.AST) -> list[tuple[int, str, str, bool]]:
    """Every bare-draw call in ``tree``.

    Returns ``(lineno, call_name, enclosing_context, under_main_guard)``
    tuples.  The enclosing context is the dotted class/function path, or
    ``<module>`` for module-level code.  ``under_main_guard`` is True for
    code inside an ``if __name__ == "__main__":`` block.
    """
    sites: list[tuple[int, str, str, bool]] = []

    def call_name(node: ast.Call) -> str | None:
        func = node.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            return f"{func.value.id}.{func.attr}"
        return None

    def is_main_guard(node: ast.stmt) -> bool:
        if not isinstance(node, ast.If):
            return False
        test = node.test
        return (
            isinstance(test, ast.Compare)
            and isinstance(test.left, ast.Name)
            and test.left.id == "__name__"
        )

    def walk(node: ast.AST, stack: list[str], in_main: bool) -> None:
        for child in ast.iter_child_nodes(node):
            child_stack = stack
            child_main = in_main
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                child_stack = [*stack, child.name]
            if isinstance(child, ast.stmt) and is_main_guard(child):
                child_main = True
            if isinstance(child, ast.Call):
                name = call_name(child)
                if name in BARE_DRAW_CALLS:
                    sites.append(
                        (child.lineno, name, ".".join(child_stack) or "<module>", child_main)
                    )
            walk(child, child_stack, child_main)

    walk(tree, [], False)
    return sites


def _sweep_package() -> tuple[list[str], dict[tuple[str, str], int]]:
    """Sweep the shipped package.

    Returns ``(violations, seen_allowlisted)`` where each violation is a
    rendered ``file:line`` description and ``seen_allowlisted`` counts how
    often each allowlist entry was actually witnessed.
    """
    violations: list[str] = []
    seen: dict[tuple[str, str], int] = dict.fromkeys(ALLOWED_BARE_DRAWS, 0)

    for path in sorted(PACKAGE_DIR.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for lineno, name, context, under_main in _bare_draw_sites(tree):
            if under_main:
                continue
            key = (path.name, context)
            if key in seen:
                seen[key] += 1
                continue
            violations.append(
                f"{path.relative_to(PACKAGE_DIR.parent)}:{lineno}: {name}() in {context} — "
                f"a bare OS-entropy draw in shipped code bypasses the INVARIANT-41 "
                f"continuous stuck-DRBG check. Route it through secure_token_bytes, "
                f"or add an allowlist entry to {Path(__file__).name} with the reason "
                f"it is legitimately exempt."
            )
    return violations, seen


class TestInvariant41Sweep:
    def test_every_bare_draw_in_the_package_is_accounted_for(self) -> None:
        violations, _ = _sweep_package()
        assert not violations, "\n" + "\n".join(violations)

    def test_the_allowlist_carries_no_rot(self) -> None:
        """Every allowlist entry must still be witnessed by real code.

        A stale entry means the code it excused moved or was fixed; leaving
        it behind would silently pre-authorise a future bare draw at that
        (module, context) pair.
        """
        _, seen = _sweep_package()
        stale = [key for key, count in seen.items() if count == 0]
        assert not stale, f"allowlist entries no longer witnessed by any code: {stale}"

    def test_secure_channel_carries_no_bare_draw(self) -> None:
        """The regression this gate was built from, pinned directly.

        The responder handshake session ID was drawn with bare
        ``secrets.token_bytes`` while the initiator side used the gated
        draw.  ``secure_channel.py`` has no legitimate bare-draw context,
        so the file-level assertion is exact — this holds even if the
        allowlist above is edited.
        """
        tree = ast.parse((PACKAGE_DIR / "secure_channel.py").read_text(encoding="utf-8"))
        sites = [s for s in _bare_draw_sites(tree) if not s[3]]
        assert (
            sites == []
        ), f"secure_channel.py must route every draw through secure_token_bytes: {sites}"


class TestTheSweepItselfWorks:
    """The gate must be able to fail — pinned on synthetic sources."""

    def test_the_sweep_can_fail(self) -> None:
        tree = ast.parse(
            "import secrets\n"
            "def mint_session_id() -> bytes:\n"
            "    return secrets.token_bytes(32)\n"
        )
        sites = [s for s in _bare_draw_sites(tree) if not s[3]]
        assert [(s[1], s[2]) for s in sites] == [("secrets.token_bytes", "mint_session_id")]

    def test_main_guard_is_exempt(self) -> None:
        tree = ast.parse(
            "import secrets\n"
            'if __name__ == "__main__":\n'
            "    demo_key = secrets.token_bytes(32)\n"
        )
        flagged = [s for s in _bare_draw_sites(tree) if not s[3]]
        exempt = [s for s in _bare_draw_sites(tree) if s[3]]
        assert flagged == []
        assert [(s[1], s[2]) for s in exempt] == [("secrets.token_bytes", "<module>")]

    def test_an_aliased_import_cannot_slip_past_unnoticed(self) -> None:
        """``from secrets import token_bytes`` produces a bare ``Name`` call
        the dotted matcher cannot see.  The shipped package imports the
        module, never the function — this test enforces that import shape
        stays true, so the sweep's dotted matching remains sound."""
        for path in sorted(PACKAGE_DIR.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module in {"secrets", "os", "random"}:
                    names = {alias.name for alias in node.names}
                    entropy = names & {"token_bytes", "urandom", "randbytes", "SystemRandom"}
                    assert not entropy, (
                        f"{path.name}:{node.lineno} imports {sorted(entropy)} directly from "
                        f"{node.module}; use the module-qualified form so the INVARIANT-41 "
                        f"sweep can see every draw"
                    )


class TestHealthDigestKernelResolution:
    """Losing the injected kernel must not brick the module permanently.

    Injecting the SHA-256 kernel at ``pqc_backends`` import time removed an
    import cycle, but it also removed the self-healing the previous
    function-local import had: that form re-resolved from ``sys.modules`` on
    every call, so anything re-running this module's body (``importlib.reload``,
    IPython ``%autoreload``, a test popping the module, a second module
    identity on a vendored path) recovered on the next draw.  With a plain
    module global it did not, and ``reset_module()`` could not repair it —
    its POST re-import is a no-op against a cached ``pqc_backends``.

    The recovery path is a ``sys.modules`` lookup rather than an import
    statement, so it heals the state without putting the cycle back in the
    import graph.
    """

    def test_a_lost_kernel_is_re_resolved_rather_than_bricking(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ama_cryptography import _module_state as ms

        monkeypatch.setattr(ms, "_health_digest", None, raising=False)
        assert len(ms.secure_token_bytes(32)) == 32
        assert ms.module_error_reason() is None

    def test_an_unresolvable_kernel_refuses_without_latching_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Could-not-run is not ran-and-failed.

        No bytes may be issued, and hashlib must never stand in — its
        constructors are OpenSSL on a libcrypto build and the health sample is
        potential key material (INVARIANT-1).  But a missing kernel means the
        continuous test never executed, so it must not latch the permanent,
        process-wide ERROR state this module reserves for a test that ran and
        failed.
        """
        import sys as _sys

        from ama_cryptography import _module_state as ms

        monkeypatch.setattr(ms, "_health_digest", None, raising=False)
        monkeypatch.delitem(_sys.modules, "ama_cryptography.pqc_backends", raising=False)

        with pytest.raises(CryptoModuleError, match="no health-digest kernel"):
            ms.secure_token_bytes(32)

        assert ms.module_error_reason() is None
