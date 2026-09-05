#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Negative controls for ``tools/check_keygen_pct.py`` (INVARIANT-41).

INVARIANTS.md claimed the wiring was already enforced::

    **Enforcement.** `tests/test_keygen_pct.py` pins the wiring (every keygen
    entry point invokes its helper — a new keygen path that forgets the test
    fails the coverage assertion)

It does not.  That test monkeypatches the three ``pairwise_test_*`` helpers
into recorders, calls a HAND-WRITTEN list of eleven entry points, builds its
``expected`` list alongside, and asserts the two match — so a twelfth keygen
that omits its pairwise test is never called by it, ``recorded`` and
``expected`` are both unchanged, and it passes.

Measured: appending an unwired ``native_widget_keypair()`` to
``pqc_backends.py`` left ``tests/test_keygen_pct.py`` at 17 passed / exit 0
while ``tools/check_keygen_pct.py`` named the violation and exited 1.

The gate discovers its scope from the module's AST — 19 entry points today
against the test's eleven — which is the property that makes it enforcement
rather than a snapshot.  This file drives it in both directions, and pins the
conditional-arm rule that a negative control showed the first version lacked.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "tools" / "check_keygen_pct.py"


@pytest.fixture(scope="module")
def gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_keygen_pct", GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _module(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "ama_cryptography" / "pqc_backends.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return tmp_path


class TestTheRule:
    WIRED = """
def native_alpha_keypair():
    pk, sk = _lib.gen()
    pairwise_test_signature(_sign, _verify, sk, pk, "Alpha")
    return pk, sk
"""

    UNWIRED = """
def native_alpha_keypair():
    pk, sk = _lib.gen()
    return pk, sk
"""

    DELEGATED = """
def _keypair_pairwise_test(pk, sk):
    pairwise_test_kem(_encaps, _decaps, pk, sk, "Alpha")


def native_alpha_keypair():
    pk, sk = _lib.gen()
    _keypair_pairwise_test(pk, sk)
    return pk, sk
"""

    def test_a_wired_entry_point_passes(self, gate: ModuleType) -> None:
        tree = ast.parse(self.WIRED)
        assert [n for n, _l, _x in gate.keygen_entry_points(tree)] == ["native_alpha_keypair"]

    def test_an_unwired_entry_point_is_reported(self, gate: ModuleType, tmp_path: Path) -> None:
        root = _module(tmp_path, self.UNWIRED)
        unwired, examined = gate.audit(root / gate.BACKEND)
        assert examined == 1
        assert [name for name, _line in unwired] == ["native_alpha_keypair"]

    def test_one_level_of_delegation_is_followed(self, gate: ModuleType, tmp_path: Path) -> None:
        root = _module(tmp_path, self.DELEGATED)
        unwired, examined = gate.audit(root / gate.BACKEND)
        assert examined == 1
        assert unwired == []

    def test_a_direct_call_is_accepted(self, gate: ModuleType, tmp_path: Path) -> None:
        root = _module(tmp_path, self.WIRED)
        unwired, _examined = gate.audit(root / gate.BACKEND)
        assert unwired == []

    def test_two_levels_of_delegation_are_not_followed(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        """Stated as a limit rather than discovered as a surprise.

        A gate that traces arbitrarily far stops being checkable by reading it,
        and nothing in the module needs more than one hop.  If a second hop
        ever appears, this test fails and the choice gets made deliberately.
        """
        source = """
def _inner(pk, sk):
    pairwise_test_kem(_encaps, _decaps, pk, sk, "Alpha")


def _outer(pk, sk):
    _inner(pk, sk)


def native_alpha_keypair():
    pk, sk = _lib.gen()
    _outer(pk, sk)
    return pk, sk
"""
        root = _module(tmp_path, source)
        unwired, _examined = gate.audit(root / gate.BACKEND)
        assert [name for name, _line in unwired] == ["native_alpha_keypair"]


class TestConditionalArms:
    """A family dispatch releases a keypair from every arm.

    Found by planting the defect and re-running the gate: with the signature
    arm of ``AmaContext._keypair_pairwise_test`` replaced by a no-op, the
    gate still exited 0, because the helper still
    called ``pairwise_test_kem`` in its other arm and so still counted as
    "reaching a helper".  ``keypair_generate`` would have released untested
    ML-DSA, SLH-DSA and hybrid keypairs with the gate green.
    """

    DELEGATED_HELPER_WITH_A_DARK_ARM = """
def _keypair_pairwise_test(self, pk, sk):
    if self._algorithm == self.ALG_KYBER_1024:
        pairwise_test_kem(_encaps, _decaps, pk, sk, "KEM")
    else:
        (lambda *a, **k: None)(_sign, _verify, sk, pk, "SIG")


def native_alpha_keypair():
    pk, sk = _lib.gen()
    _keypair_pairwise_test(pk, sk)
    return pk, sk
"""

    ENTRY_POINT_WITH_A_DARK_ARM = """
def native_alpha_keypair(kind):
    pk, sk = _lib.gen()
    if kind == "kem":
        pairwise_test_kem(_encaps, _decaps, pk, sk, "KEM")
    else:
        pass
    return pk, sk
"""

    RAISING_ARM = """
def native_alpha_keypair(kind):
    pk, sk = _lib.gen()
    if kind == "kem":
        pairwise_test_kem(_encaps, _decaps, pk, sk, "KEM")
    elif kind == "sig":
        pairwise_test_signature(_sign, _verify, sk, pk, "SIG")
    else:
        raise ValueError(kind)
    return pk, sk
"""

    MATCH_WITH_A_DARK_CASE = """
def native_alpha_keypair(kind):
    pk, sk = _lib.gen()
    match kind:
        case "kem":
            pairwise_test_kem(_encaps, _decaps, pk, sk, "KEM")
        case _:
            return pk, sk
    return pk, sk
"""

    FALL_THROUGH = """
def native_alpha_keypair(kind):
    pk, sk = _lib.gen()
    if kind == "kem":
        pairwise_test_kem(_encaps, _decaps, pk, sk, "KEM")
        return pk, sk
    pairwise_test_signature(_sign, _verify, sk, pk, "SIG")
    return pk, sk
"""

    def test_a_delegated_helper_with_a_dark_arm_is_not_a_helper(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        """The exact shape NC-17 injected: both the caller and the arm are named."""
        root = _module(tmp_path, self.DELEGATED_HELPER_WITH_A_DARK_ARM)
        unwired, examined = gate.audit(root / gate.BACKEND)
        assert examined == 1
        assert unwired == [
            ("_keypair_pairwise_test [conditional arm]", 6),
            ("native_alpha_keypair", 9),
        ]

    def test_an_entry_point_with_a_dark_arm_is_reported_at_the_arm(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        root = _module(tmp_path, self.ENTRY_POINT_WITH_A_DARK_ARM)
        unwired, _examined = gate.audit(root / gate.BACKEND)
        assert unwired == [("native_alpha_keypair [conditional arm]", 7)]

    def test_an_arm_that_raises_releases_nothing(self, gate: ModuleType, tmp_path: Path) -> None:
        root = _module(tmp_path, self.RAISING_ARM)
        unwired, _examined = gate.audit(root / gate.BACKEND)
        assert unwired == []

    def test_match_cases_are_arms_too(self, gate: ModuleType, tmp_path: Path) -> None:
        root = _module(tmp_path, self.MATCH_WITH_A_DARK_CASE)
        unwired, _examined = gate.audit(root / gate.BACKEND)
        assert unwired == [("native_alpha_keypair [conditional arm]", 8)]

    EARLIER_CONDITIONALS = """
def native_alpha_keypair(kind):
    pk, sk = _lib.gen()
    if pk is None:
        raise RuntimeError("keygen failed")
    if kind == "fast":
        _lib.tune(1)
    else:
        _lib.tune(0)
    if kind == "kem":
        pairwise_test_kem(_encaps, _decaps, pk, sk, "KEM")
    else:
        pass
    return pk, sk
"""

    def test_earlier_conditionals_do_not_end_the_scan(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        """Found by mutation: `continue` -> `break` in the arm scan survived.

        An `if` with no `else`, then an `if`/`else` with no pairwise test in
        either arm, both ahead of the dispatch whose arm is dark.  The scan
        must skip past them, not stop at them.
        """
        root = _module(tmp_path, self.EARLIER_CONDITIONALS)
        unwired, _examined = gate.audit(root / gate.BACKEND)
        assert unwired == [("native_alpha_keypair [conditional arm]", 13)]

    def test_an_if_without_else_opens_no_comparison(self, gate: ModuleType, tmp_path: Path) -> None:
        """Stated as a limit: the fall-through path runs its test later."""
        root = _module(tmp_path, self.FALL_THROUGH)
        unwired, _examined = gate.audit(root / gate.BACKEND)
        assert unwired == []

    def test_the_cli_names_the_arm(
        self,
        gate: ModuleType,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        root = _module(tmp_path, self.DELEGATED_HELPER_WITH_A_DARK_ARM)
        monkeypatch.setattr(gate, "MIN_ENTRY_POINTS", 1)
        assert gate.main(["--root", str(root)]) == 1
        err = capsys.readouterr().err
        assert "_keypair_pairwise_test [conditional arm]()" in err
        assert "give it the family's test, or make it raise" in err


class TestTheRealTree:
    def test_the_shipped_backend_is_fully_wired(self, gate: ModuleType) -> None:
        unwired, examined = gate.audit(REPO_ROOT / gate.BACKEND)
        assert unwired == [], unwired
        assert examined >= gate.MIN_ENTRY_POINTS, examined

    def test_discovery_finds_more_than_the_hand_written_test_drives(self, gate: ModuleType) -> None:
        """The point of the change, stated as a number.

        ``tests/test_keygen_pct.py`` drives eleven entry points from a literal
        list.  If discovery ever found no more than that, the gate would have
        stopped adding anything over the test it replaced.
        """
        _unwired, examined = gate.audit(REPO_ROOT / gate.BACKEND)
        assert examined > 11, examined

    def test_every_exemption_carries_a_reason_and_still_exists(self, gate: ModuleType) -> None:
        """An exemption for a function that is gone is an exemption that rots."""
        source = (REPO_ROOT / gate.BACKEND).read_text(encoding="utf-8")
        tree = ast.parse(source)
        defined = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for name, reason in gate.EXEMPT.items():
            assert name in defined, f"EXEMPT names {name!r}, which no longer exists"
            assert len(reason) > 40, f"{name}: exemption needs a stated reason"

    def test_the_cli_reports_success(
        self, gate: ModuleType, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert gate.main(["--root", str(REPO_ROOT)]) == 0
        assert "every one reaches a pairwise consistency test" in capsys.readouterr().out

    def test_a_collapsed_scope_fails_closed(self, gate: ModuleType, tmp_path: Path) -> None:
        root = _module(tmp_path, "def native_alpha_keypair():\n    return None\n")
        assert gate.main(["--root", str(root)]) == 1

    def test_a_missing_backend_fails_closed(
        self, gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Found by mutation: `return 1` -> `return None` on the missing-file path survived.

        A gate whose input vanished must not exit 0; nothing pinned that.
        """
        assert gate.main(["--root", str(tmp_path)]) == 1
        assert "missing" in capsys.readouterr().err
