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
import re
import subprocess
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


class TestEveryPath:
    """An ``if`` with no ``else`` used to open no comparison at all.

    Measured before the fix: wrapping the pairwise call in
    ``if os.environ.get("AMA_SKIP_PCT") is None:`` left the gate at exit 0
    while the function released an untested keypair whenever the variable was
    set.  A missing ``else`` is now an empty arm that falls through to the
    statements after the ``if``, and that path must reach a test too.
    """

    ENV_GUARDED = """
import os


def native_alpha_keypair():
    pk, sk = _lib.gen()
    if os.environ.get("AMA_SKIP_PCT") is None:
        pairwise_test_signature(_sign, _verify, sk, pk, "Alpha")
    return pk, sk
"""

    RC_GUARDED = """
def native_alpha_keypair():
    rc = _lib.gen(pk, sk)
    if rc == 0:
        pairwise_test_signature(_sign, _verify, sk, pk, "Alpha")
    return rc
"""

    FAILURE_EXIT_FIRST = """
def native_alpha_keypair(n):
    if n < 32:
        return -1
    rc = _lib.gen(pk, sk)
    if rc != 0:
        return rc
    pairwise_test_signature(_sign, _verify, sk, pk, "Alpha")
    return rc
"""

    MATCH_WITHOUT_A_DEFAULT = """
def native_alpha_keypair(kind):
    pk, sk = _lib.gen()
    match kind:
        case "kem":
            pairwise_test_kem(_encaps, _decaps, pk, sk, "KEM")
    return pk, sk
"""

    EARLY_RETURN_IN_AN_UNTESTED_CONSTRUCT = """
def native_alpha_keypair(fast):
    pk, sk = _lib.gen()
    if fast:
        return pk, sk
    pairwise_test_signature(_sign, _verify, sk, pk, "Alpha")
    return pk, sk
"""

    TEST_ONLY_IN_A_LOOP = """
def native_alpha_keypair(rounds):
    pk, sk = _lib.gen()
    for _ in range(rounds):
        pairwise_test_signature(_sign, _verify, sk, pk, "Alpha")
    return pk, sk
"""

    TEST_ONLY_IN_A_LAMBDA = """
def native_alpha_keypair():
    pk, sk = _lib.gen()
    later = lambda: pairwise_test_signature(_sign, _verify, sk, pk, "Alpha")
    return pk, sk
"""

    TEST_IN_WITH_AND_TRY = """
def native_alpha_keypair():
    with _lock:
        pk, sk = _lib.gen()
        try:
            pairwise_test_signature(_sign, _verify, sk, pk, "Alpha")
        except RuntimeError:
            raise
        return pk, sk
"""

    SWALLOWED_TEST_FAILURE = """
def native_alpha_keypair():
    pk, sk = _lib.gen()
    try:
        pairwise_test_signature(_sign, _verify, sk, pk, "Alpha")
    except RuntimeError:
        pass
    return pk, sk
"""

    DELEGATE_WITH_A_GUARDED_TEST = """
import os


def _pct(pk, sk):
    if not os.environ.get("AMA_SKIP_PCT"):
        pairwise_test_kem(_encaps, _decaps, pk, sk, "Alpha")


def native_alpha_keypair():
    pk, sk = _lib.gen()
    _pct(pk, sk)
    return pk, sk
"""

    @staticmethod
    def _audit(gate: ModuleType, tmp_path: Path, source: str) -> list[tuple[str, int]]:
        root = _module(tmp_path, source)
        unwired, examined = gate.audit(root / gate.BACKEND)
        assert examined == 1
        return list(unwired)

    def test_the_reported_env_var_bypass_is_caught(self, gate: ModuleType, tmp_path: Path) -> None:
        assert self._audit(gate, tmp_path, self.ENV_GUARDED) == [
            ("native_alpha_keypair [path skips the test]", 9)
        ]

    def test_a_return_code_guard_is_just_as_conditional(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        """The shape AmaContext.keypair_generate has; conditions are not evaluated."""
        assert self._audit(gate, tmp_path, self.RC_GUARDED) == [
            ("native_alpha_keypair [path skips the test]", 6)
        ]

    def test_leaving_on_failure_then_testing_unconditionally_passes(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        """The remedy the diagnostic recommends must satisfy it."""
        assert self._audit(gate, tmp_path, self.FAILURE_EXIT_FIRST) == []

    def test_a_match_with_no_default_may_match_nothing(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        """The arm rule compares only the cases that exist; the path rule does not."""
        assert self._audit(gate, tmp_path, self.MATCH_WITHOUT_A_DEFAULT) == [
            ("native_alpha_keypair [path skips the test]", 7)
        ]

    def test_an_early_return_in_an_untested_construct_is_not_judged(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        """Stated as a limit, not discovered as a surprise.

        A construct with no pairwise test in it is not judged, because its
        exits are indistinguishable from the input-validation returns
        (``return -1``) that precede key generation.  If this ever starts
        failing, the limit was closed deliberately: update the docstring.
        """
        assert self._audit(gate, tmp_path, self.EARLY_RETURN_IN_AN_UNTESTED_CONSTRUCT) == []

    def test_a_loop_body_may_run_zero_times(self, gate: ModuleType, tmp_path: Path) -> None:
        assert self._audit(gate, tmp_path, self.TEST_ONLY_IN_A_LOOP) == [
            ("native_alpha_keypair [path skips the test]", 6)
        ]

    def test_a_test_inside_a_lambda_is_not_run(self, gate: ModuleType, tmp_path: Path) -> None:
        assert self._audit(gate, tmp_path, self.TEST_ONLY_IN_A_LAMBDA) == [
            ("native_alpha_keypair [path skips the test]", 5)
        ]

    def test_a_handler_that_swallows_a_failed_test_is_a_path(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        """A PCT failure caught and ignored releases the keypair it condemned."""
        assert self._audit(gate, tmp_path, self.SWALLOWED_TEST_FAILURE) == [
            ("native_alpha_keypair [path skips the test]", 8)
        ]

    def test_with_and_try_bodies_run_in_line(self, gate: ModuleType, tmp_path: Path) -> None:
        assert self._audit(gate, tmp_path, self.TEST_IN_WITH_AND_TRY) == []

    def test_a_delegate_with_a_guarded_test_is_not_a_helper(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        assert self._audit(gate, tmp_path, self.DELEGATE_WITH_A_GUARDED_TEST) == [
            ("native_alpha_keypair", 10)
        ]


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

    @pytest.mark.parametrize(
        "body",
        [TestTheRule.WIRED, "", "def unrelated():\n    return None\n"],
        ids=["one-wired-keygen", "empty-module", "no-keygen"],
    )
    def test_a_collapsed_scope_fails_closed(
        self,
        gate: ModuleType,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        body: str,
    ) -> None:
        """Only the MIN_ENTRY_POINTS floor can fail these: every keygen present
        is wired, so the unwired branch has nothing to report.

        The control this replaces used an UNWIRED keygen, which exits 1 from
        the unwired branch whether or not the floor exists; with the floor
        deleted, a backend whose keygens stopped matching the markers read
        "OK: 0 keygen entry point(s)" and exited 0.
        """
        root = _module(tmp_path, body)
        assert gate.main(["--root", str(root)]) == 1
        # Named by file: the .pyx scan has a floor with the same wording, and
        # this tree has no .pyx at all, so an unqualified match would be
        # satisfied by the wrong floor.
        assert f"keygen entry point(s) in {gate.BACKEND} " in capsys.readouterr().err

    def test_a_collapsed_binding_scope_fails_closed(
        self, gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The .pyx floor, reached with the Python scope satisfied."""
        wired = "".join(
            TestTheRule.WIRED.replace("native_alpha_keypair", f"native_k{i}_keypair")
            for i in range(gate.MIN_ENTRY_POINTS)
        )
        root = _module(tmp_path, wired)
        assert gate.main(["--root", str(root)]) == 1
        err = capsys.readouterr().err
        assert f"keygen entry point(s) in {gate.PYX_GLOB} " in err, err
        assert f"in {gate.BACKEND} " not in err, err

    def test_a_missing_backend_fails_closed(
        self, gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Found by mutation: `return 1` -> `return None` on the missing-file path survived.

        A gate whose input vanished must not exit 0; nothing pinned that.
        """
        assert gate.main(["--root", str(tmp_path)]) == 1
        assert "missing" in capsys.readouterr().err


class TestCythonBindingKeygens:
    """The ``.pyx`` keygens are read by indentation (Cython is not Python)."""

    _OK = (
        "def cy_x_keygen():\n"
        "    check_crypto_permitted()\n"
        "    try:\n"
        "        pk, sk = make()\n"
        "    finally:\n"
        "        wipe()\n"
        "    pairwise_test_signature(sign, verify, sk, pk, 'x')\n"
        "    return (pk, sk)\n"
    )

    def test_an_unconditional_test_before_the_return_passes(self, gate: ModuleType) -> None:
        assert gate.pyx_keygens_without_pct(self._OK) == ([], 1)

    def test_a_keygen_without_the_test_is_reported(self, gate: ModuleType) -> None:
        text = "def cy_x_keypair(bytes seed):\n    pk, sk = make(seed)\n    return (pk, sk)\n"
        problems, examined = gate.pyx_keygens_without_pct(text)
        assert examined == 1
        assert problems == [("cy_x_keypair", 1, "no unconditional pairwise test")]

    def test_a_return_before_the_test_is_reported(self, gate: ModuleType) -> None:
        text = self._OK.replace("        pk, sk = make()\n", "        return make()\n")
        problems, _ = gate.pyx_keygens_without_pct(text)
        assert [why for _, _, why in problems] == ["returns before the pairwise test"]

    def test_a_test_inside_a_conditional_is_not_unconditional(self, gate: ModuleType) -> None:
        text = self._OK.replace(
            "    pairwise_test_signature(", "    if fips:\n        pairwise_test_signature("
        )
        problems, _ = gate.pyx_keygens_without_pct(text)
        assert [why for _, _, why in problems] == ["no unconditional pairwise test"]

    def test_non_keygen_functions_are_not_examined(self, gate: ModuleType) -> None:
        assert gate.pyx_keygens_without_pct("def cy_sign(m):\n    return m\n") == ([], 0)

    def test_the_shipped_bindings_are_wired(self, gate: ModuleType) -> None:
        root = Path(__file__).resolve().parent.parent
        examined = 0
        for pyx in sorted(root.glob(gate.PYX_GLOB)):
            problems, count = gate.pyx_keygens_without_pct(pyx.read_text(encoding="utf-8"))
            assert problems == [], pyx.name
            examined += count
        assert examined >= gate.MIN_PYX_ENTRY_POINTS

    def test_the_cli_fails_on_an_unwired_binding(self, gate: ModuleType, tmp_path: Path) -> None:
        root = Path(__file__).resolve().parent.parent
        (tmp_path / "ama_cryptography").mkdir()
        (tmp_path / gate.BACKEND).write_text(
            (root / gate.BACKEND).read_text(encoding="utf-8"), encoding="utf-8"
        )
        (tmp_path / "src" / "cython").mkdir(parents=True)
        for pyx in root.glob(gate.PYX_GLOB):
            (tmp_path / "src" / "cython" / pyx.name).write_text(
                pyx.read_text(encoding="utf-8"), encoding="utf-8"
            )
        assert gate.main(["--root", str(tmp_path)]) == 0
        target = tmp_path / "src" / "cython" / "ed25519_binding.pyx"
        text = target.read_text(encoding="utf-8")
        target.write_text(
            text.replace("    pairwise_test_signature(", "    _no_test(", 1), encoding="utf-8"
        )
        assert gate.main(["--root", str(tmp_path)]) == 1


#: Wording that describes the pairwise test as something application code
#: runs.  Each alternative is a phrase the documentation shipped.
_CALLER_INVOKED = re.compile(
    r"responsible for invoking|not\*{0,2} automatically intercept|called explicitly"
    r"|\b(?:must|can|should|may) be (?:called|invoked)\b",
    re.IGNORECASE,
)


def _caller_invoked_paragraphs(text: str) -> list[str]:
    return [
        " ".join(paragraph.split())[:200]
        for paragraph in re.split(r"\n\s*\n", text)
        if re.search(r"pairwise", paragraph, re.IGNORECASE) and _CALLER_INVOKED.search(paragraph)
    ]


class TestNoDocumentDescribesThePairwiseTestAsCallerInvoked:
    """The gate proves the wiring; the documents must not deny it.

    ``docs/compliance/CSRC_ALIGN_REPORT.md`` §4.4 — the document that states
    the FIPS 140-3 control inventory — said callers "are responsible for
    invoking these helpers", that they "do **not** automatically intercept every
    key generation" and "must be called explicitly", and listed three
    algorithms.  ``IMPLEMENTATION_GUIDE.md`` said the helpers "can be called
    after any key generation".  Both were accurate before INVARIANT-41 wired
    the test into every keygen and false after it, while the invariant, README
    and SECURITY.md said the opposite: a compliance reviewer reading the report
    records the §4.9.2 conditional self-test as absent and caller-dependent.

    This reads every tracked Markdown document except the historical record,
    and fails on a paragraph that names the pairwise test and describes it as
    caller-invoked — so the claim cannot move to another page either.
    """

    @staticmethod
    def _documents() -> list[Path]:
        from tools._repo import is_historical_record

        listed = subprocess.run(
            ["git", "ls-files", "*.md"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split()
        return [REPO_ROOT / name for name in listed if not is_historical_record(Path(name))]

    def test_the_shipped_wording_is_recognised(self) -> None:
        """Non-vacuity: the two paragraphs that shipped must both be caught."""
        csrc = (
            "The library provides helper functions (`pairwise_test_signature()`,\n"
            "`pairwise_test_kem()`) that perform a sign-verify or encaps-decaps\n"
            "roundtrip on a fixed test message. Callers (e.g. key-generation wrappers)\n"
            "are responsible for invoking these helpers after generating a keypair.\n"
        )
        guide = (
            "**Pairwise Consistency Tests:** Functions `pairwise_test_signature()` and\n"
            "`pairwise_test_kem()` in `ama_cryptography._self_test` can be called after\n"
            "any key generation to verify the keypair is consistent.\n"
        )
        assert _caller_invoked_paragraphs(csrc)
        assert _caller_invoked_paragraphs(guide)

    def test_the_corrected_wording_passes(self) -> None:
        corrected = (
            "Every asymmetric key generation in the package runs its pairwise\n"
            "consistency test itself, before the keypair is returned. There is nothing\n"
            "for application code to call and no way to switch it off.\n"
        )
        assert _caller_invoked_paragraphs(corrected) == []

    def test_no_tracked_document_says_it(self) -> None:
        documents = self._documents()
        assert len(documents) > 40, "git ls-files returned too few documents to be the tree"
        offenders = [
            f"{path.relative_to(REPO_ROOT)}: {paragraph}"
            for path in documents
            for paragraph in _caller_invoked_paragraphs(
                path.read_text(encoding="utf-8", errors="replace")
            )
        ]
        assert not offenders, (
            "these paragraphs describe the INVARIANT-41 pairwise test as something "
            "the caller runs; tools/check_keygen_pct.py proves every keygen runs it "
            "itself:\n" + "\n".join(offenders)
        )
