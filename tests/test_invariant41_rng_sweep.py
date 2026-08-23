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
found.  That sweep missed ``secure_channel.py`` entirely: at ``origin/main``
the file contained no reference to ``secure_token_bytes`` at all, and both of
its draws were bare — the AEAD nonce and the responder-side handshake session
ID, the latter signed into the transcript and consumed by ``_derive_session``.

(This paragraph used to say the sweep "missed exactly one site … while the
initiator side of the very same protocol drew through the health-tested
wrapper".  Neither half was true: the initiator does not generate a session ID
at all — it receives one from the peer — and no draw in the file went through
the wrapper before this branch.  A false account of how a control came to be
needed is a bad reason to trust the control.)

A hand sweep that must be re-run perfectly after every change is not a
control; this module is the control.

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
#:
#: The list is the whole of the sweep's reach, so an omission is not a smaller
#: version of this check — it is no check at all for that shape.  Five names
#: were missing, and two shipped call sites drew through one of them:
#: ``rfc3161_timestamp.py`` and ``legacy_compat.py`` minted the RFC 3161 replay
#: nonce with ``secrets.randbits(64)`` — the value the code itself calls "the
#: client's only way to tell a fresh response from a replayed one" — outside
#: the health test, outside the allowlist, and structurally invisible to the
#: gate that promises to enumerate "every bare draw".  Both now draw through
#: ``secure_token_bytes``.
#:
#: ``secrets.randbits`` IS ``SystemRandom.getrandbits``; ``token_hex`` and
#: ``token_urlsafe`` are ``token_bytes`` with an encoding on top; ``choice``
#: and ``getrandbits`` are the same generator through a different accessor.
#: None of them is a weaker draw — they are the same draw, spelled differently,
#: which is precisely why a name-based sweep has to name them all.
#: The stdlib modules a bare draw can come from.  Used to resolve IMPORT
#: BINDINGS, so an alias cannot hide a draw — see `call_name`.
_DRAW_MODULES = frozenset({"os", "secrets", "random"})

BARE_DRAW_CALLS = frozenset(
    {
        "secrets.token_bytes",
        "secrets.token_hex",
        "secrets.token_urlsafe",
        "secrets.randbits",
        "secrets.randbelow",
        "secrets.choice",
        "os.urandom",
        "random.randbytes",
        "random.getrandbits",
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


def _resolve_draw_aliases(tree: ast.AST) -> dict[str, str]:
    """Map this module's local bindings back to the canonical draw names.

    `call_name` used to return the literal text `<Name>.<attr>` and compare it
    against BARE_DRAW_CALLS' dotted spellings.  That matches SPELLINGS, not
    BINDINGS: `import os as _os_mod` makes the call name `_os_mod.urandom`,
    which is not in the set, so the site was never recorded and the sweep
    reported the tree clean — while the module docstring claims "every call
    site of a bare OS-entropy draw in ama_cryptography/ must be on the
    allowlist" and "the list is the whole of the sweep's reach".  The shipped
    package contained exactly one such site: `_os_mod.urandom(32)` in
    rfc3161_timestamp.py, the HMAC key of MockTSA's integrity tag.

    Resolving bindings is what tools/check_stdlib_hash_boundary.py's
    _GuardedModuleVisitor already does for hashlib in this same tree.

    Two key shapes share the dict: a plain module binding maps
    ``"_os_mod" -> "os"``, and a from-import maps ``"os:_u" -> "os.urandom"``
    so a bare NAME call can be resolved without colliding with a module
    binding of the same text.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for entry in node.names:
                if entry.name in _DRAW_MODULES:
                    aliases[entry.asname or entry.name] = entry.name
        elif isinstance(node, ast.ImportFrom) and node.module in _DRAW_MODULES:
            # `from os import urandom as _u` — a bare NAME call, resolved below.
            for entry in node.names:
                aliases[f"{node.module}:{entry.asname or entry.name}"] = (
                    f"{node.module}.{entry.name}"
                )
    return aliases


def _call_name(node: ast.Call, aliases: dict[str, str]) -> str | None:
    """The canonical dotted name ``node`` calls, or None if it is not a draw."""
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        module = aliases.get(func.value.id, func.value.id)
        return f"{module}.{func.attr}"
    if isinstance(func, ast.Name):
        # `from secrets import token_bytes` / `... as _tb`.
        for key, dotted in aliases.items():
            if ":" in key and key.split(":", 1)[1] == func.id:
                return dotted
    return None


def _is_main_guard(node: ast.stmt) -> bool:
    """True for an ``if __name__ == "__main__":`` statement.

    This predicate EXEMPTS everything under it from the sweep, so it has to be
    exactly the script-entry idiom and nothing adjacent to it.  It used to test
    only that the left operand was the name ``__name__``, which also accepted
    ``if __name__ != "__main__":`` — a block that runs on every IMPORT, i.e.
    the opposite of the thing being exempted, and shipped-package code inside
    one would have been waved through.  The operator and the compared literal
    are now both checked.
    """
    if not isinstance(node, ast.If):
        return False
    test = node.test
    return (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id == "__name__"
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Eq)
        and len(test.comparators) == 1
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value == "__main__"
    )


def _bare_draw_sites(tree: ast.AST) -> list[tuple[int, str, str, bool]]:
    """Every bare-draw call in ``tree``.

    Returns ``(lineno, call_name, enclosing_context, under_main_guard)``
    tuples.  The enclosing context is the dotted class/function path, or
    ``<module>`` for module-level code.  ``under_main_guard`` is True for
    code inside an ``if __name__ == "__main__":`` block.
    """
    sites: list[tuple[int, str, str, bool]] = []
    aliases = _resolve_draw_aliases(tree)

    def walk(node: ast.AST, stack: list[str], in_main: bool) -> None:
        for child in ast.iter_child_nodes(node):
            child_stack = stack
            child_main = in_main
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                child_stack = [*stack, child.name]
            if isinstance(child, ast.stmt) and _is_main_guard(child):
                child_main = True
            if isinstance(child, ast.Call):
                name = _call_name(child, aliases)
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

        Both draws in ``secure_channel.py`` were bare at ``origin/main`` — the
        AEAD nonce and the responder handshake session ID — and the file
        referenced ``secure_token_bytes`` nowhere.  (This docstring used to say
        the responder drew bare "while the initiator side used the gated draw";
        there was no gated draw in the file, and the initiator does not
        generate a session ID at all.)  ``secure_channel.py`` has no legitimate
        bare-draw context, so the file-level assertion is exact — this holds
        even if the allowlist above is edited.
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


class TestTheSweepResolvesBindingsNotSpellings:
    """An aliased import must not hide a draw.

    `call_name` compared the literal text `<Name>.<attr>` against
    BARE_DRAW_CALLS' dotted spellings, so `import os as _os_mod` produced
    `_os_mod.urandom`, which is not in the set — the site was never recorded
    and the sweep reported the tree clean.  The shipped package contained
    exactly one: `_os_mod.urandom(32)` in `rfc3161_timestamp.py`, the HMAC key
    of MockTSA's integrity tag.  The module docstring meanwhile claims "every
    call site of a bare OS-entropy draw in ``ama_cryptography/`` must be on the
    allowlist below" and "the list is the whole of the sweep's reach".
    """

    @pytest.mark.parametrize(
        "source",
        [
            "import os as _os_mod\n\ndef f():\n    return _os_mod.urandom(32)\n",
            "import secrets as _s\n\ndef f():\n    return _s.token_bytes(32)\n",
            "import random as _r\n\ndef f():\n    return _r.randbytes(32)\n",
            "from os import urandom as _u\n\ndef f():\n    return _u(32)\n",
            "from secrets import token_bytes\n\ndef f():\n    return token_bytes(32)\n",
        ],
    )
    def test_an_aliased_draw_is_found(self, source: str) -> None:
        sites = _bare_draw_sites(ast.parse(source))
        assert sites, f"the sweep missed an aliased draw:\n{source}"

    def test_an_unaliased_draw_is_still_found(self) -> None:
        """The control: the ordinary spelling must keep working."""
        source = "import os\n\ndef f():\n    return os.urandom(32)\n"
        assert _bare_draw_sites(ast.parse(source))

    def test_an_unrelated_module_is_not_a_draw(self) -> None:
        """And a call that merely LOOKS like one must not be swept up."""
        source = "import mymod\n\ndef f():\n    return mymod.urandom(32)\n"
        assert _bare_draw_sites(ast.parse(source)) == []


class TestTheMainGuardExemptionIsTheScriptIdiomAndNothingElse:
    """Only ``if __name__ == "__main__":`` may exempt a draw.

    ``_bare_draw_sites`` reports an ``under_main_guard`` flag and
    ``_sweep_package`` skips every site carrying it, so this predicate decides
    what the sweep does NOT look at.  It used to test only that the left
    operand was the name ``__name__``, which accepted ``!=`` as readily as
    ``==`` — and ``if __name__ != "__main__":`` guards a block that runs on
    every IMPORT of a shipped module, which is exactly the code the sweep
    exists to cover.
    """

    DRAW = "import os\n\n{guard}\n    x = os.urandom(32)\n"

    def test_the_real_idiom_exempts(self) -> None:
        sites = _bare_draw_sites(ast.parse(self.DRAW.format(guard='if __name__ == "__main__":')))
        assert sites and all(under_main for *_, under_main in sites)

    @pytest.mark.parametrize(
        "guard",
        [
            'if __name__ != "__main__":',
            'if __name__ == "__mai__":',
            "if __name__ is None:",
            'if __name__ == "__main__" == "x":',
        ],
    )
    def test_a_near_miss_does_not_exempt(self, guard: str) -> None:
        sites = _bare_draw_sites(ast.parse(self.DRAW.format(guard=guard)))
        assert sites, f"the draw itself was lost under {guard!r}"
        assert not any(under_main for *_, under_main in sites), (
            f"{guard!r} exempted a draw from the INVARIANT-41 sweep; only "
            f'if __name__ == "__main__": may do that'
        )
