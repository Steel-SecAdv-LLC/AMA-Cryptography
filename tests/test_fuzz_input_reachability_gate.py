# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for ``tools/check_fuzz_input_reachability.py``.

The gate exists because a fuzz target can be registered in every lane, run on
every trigger, report green, and never enter the branch it was written for.
libFuzzer never generates a unit longer than ``-max_len`` and — measured on
this tree — truncates corpus units to it as well: a 60,001-byte seed loaded
under ``-max_len=4096`` enters the in-memory corpus at 4,096 bytes.  So a
guard above the ceiling is unreachable by construction, not merely unlikely.

Two harnesses were in exactly that state against the hard-coded
``-max_len=4096``: ``fuzz_dilithium`` case 1 (5,262 bytes) and
``fuzz_sphincs`` cases 1 and 2 (49,921 and 49,857).

Every case below is a mutation: the gate must reject a guard above the
ceiling, an unresolved guard that is not declared, and a ``-max_len`` written
into the workflow by hand — and must accept the tree as it stands.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "tools" / "check_fuzz_input_reachability.py"


def _load_gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_fuzz_input_reachability", GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def gate() -> ModuleType:
    return _load_gate()


# --------------------------------------------------------------------------
# The tree itself
# --------------------------------------------------------------------------


def test_the_tree_passes(gate: ModuleType) -> None:
    """Every harness branch is reachable under the ceiling its lane uses."""
    assert gate.main([]) == 0


def test_the_two_known_deep_targets_are_above_the_floor(gate: ModuleType) -> None:
    """The regression this gate was written for, stated as numbers.

    If either of these drops back to the floor, either the harness lost the
    fully-fuzzed case or the arithmetic stopped being read.
    """
    assert gate.max_len_for("fuzz_dilithium") > gate.DEFAULT_MAX_LEN
    assert gate.max_len_for("fuzz_sphincs") > gate.DEFAULT_MAX_LEN
    # 3,309 signature + 1,952 public key + 1 selector byte, past a `<` guard.
    assert gate.max_len_for("fuzz_dilithium") == 3309 + 1952 + 1 + 1
    # 49,856 signature + 64 public key + 1 selector byte, past a `<` guard.
    assert gate.max_len_for("fuzz_sphincs") == 49856 + 64 + 1 + 1


def test_a_shallow_target_keeps_the_floor(gate: ModuleType) -> None:
    """Raising one ceiling must not lower another."""
    assert gate.max_len_for("fuzz_sha3") == gate.DEFAULT_MAX_LEN


def test_every_harness_is_examined(gate: ModuleType) -> None:
    """A gate with no subjects would pass vacuously."""
    harnesses = gate._harnesses()
    assert len(harnesses) >= 10
    assert all(p.is_file() for p in harnesses)


# --------------------------------------------------------------------------
# Mutations the gate must reject
# --------------------------------------------------------------------------


def _write_harness(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "fuzz_synthetic.c"
    path.write_text(body, encoding="utf-8")
    return path


def test_a_resolvable_guard_is_measured(gate: ModuleType, tmp_path: Path) -> None:
    harness = _write_harness(
        tmp_path,
        """
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    size_t payload_len = size - 1;
    if (payload_len < 9000) return 0;
    return 0;
}
""",
    )
    required, unresolved = gate.required_max_len(harness)
    assert not unresolved
    # 9,000 to pass a `<` guard is 9,001, plus the 1-byte payload offset.
    assert required == 9002


def test_a_macro_sum_resolves_against_the_public_header(gate: ModuleType, tmp_path: Path) -> None:
    """The real guards are sums of header macros, not literals."""
    harness = _write_harness(
        tmp_path,
        """
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    size_t payload_len = size - 1;
    if (payload_len < AMA_ML_DSA_65_SIGNATURE_BYTES + AMA_ML_DSA_65_PUBLIC_KEY_BYTES)
        return 0;
    return 0;
}
""",
    )
    required, unresolved = gate.required_max_len(harness)
    assert not unresolved
    assert required == 3309 + 1952 + 1 + 1


def test_an_equality_guard_needs_exactly_the_bound(gate: ModuleType, tmp_path: Path) -> None:
    """`payload_len == N` is reachable at N, not N+1 — fuzz_kyber's shape."""
    harness = _write_harness(
        tmp_path,
        """
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    size_t payload_len = size - 1;
    if (payload_len == 3168) return 0;
    return 0;
}
""",
    )
    required, _ = gate.required_max_len(harness)
    assert required == 3169


def test_an_unresolved_guard_is_a_failure_not_a_skip(
    gate: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A guard the gate cannot evaluate is the branch that goes dark.

    Skipping it silently is how the defect this gate exists for would return,
    so it must be declared in MANUAL_BOUNDS or fail.
    """
    harness = _write_harness(
        tmp_path,
        """
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    size_t payload_len = size - 1;
    size_t needed = compute_it(data);
    if (payload_len < needed) return 0;
    return 0;
}
""",
    )
    _required, unresolved = gate.required_max_len(harness)
    assert unresolved, "an unevaluable bound must be reported, not dropped"

    monkeypatch.setattr(gate, "FUZZ_DIR", tmp_path)
    assert gate.main([]) == 1
    assert "does not resolve to a constant" in capsys.readouterr().err


def test_a_declared_bound_clears_the_unresolved_guard(
    gate: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_harness(
        tmp_path,
        """
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    size_t payload_len = size - 1;
    if (payload_len < needed) return 0;
    return 0;
}
""",
    )
    monkeypatch.setattr(gate, "FUZZ_DIR", tmp_path)
    # The reason must NAME the guard expression it accounts for.  It used to be
    # free prose ("worked out by hand") and the entry cleared the whole
    # unresolved list regardless, so one manual bound stopped the harness being
    # checked at all — including for guards added later.  Naming the expression
    # is what scopes the exemption to the guard it explains.
    monkeypatch.setitem(
        gate.MANUAL_BOUNDS,
        "fuzz_synthetic",
        (777, "`needed` is a runtime value bounded by construction; worked out by hand"),
    )
    assert gate.main([]) == 0
    assert gate.max_len_for("fuzz_synthetic") == gate.DEFAULT_MAX_LEN


def test_frost_is_declared_because_its_bound_is_a_runtime_value(gate: ModuleType) -> None:
    """The one real harness whose guard this gate cannot evaluate.

    Its entry must carry the reasoning, not just a number, or the next reader
    cannot check it.
    """
    bound, reason = gate.MANUAL_BOUNDS["fuzz_frost"]
    assert bound == 780
    assert "FROST_FUZZ_MAX_N" in reason


def test_a_hardcoded_max_len_in_the_workflow_fails(
    gate: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The number must be asked for, not restated.

    A correct table beside a stale literal is the exact failure this gate
    exists to prevent, so the gate reads the workflow too.
    """
    workflow = tmp_path / "fuzzing.yml"
    workflow.write_text("run: ./fuzz -max_len=4096 corpus/\n", encoding="utf-8")
    monkeypatch.setattr(gate, "WORKFLOW", workflow)
    assert gate.main([]) == 1
    assert "written into the workflow" in capsys.readouterr().err


def test_a_workflow_with_no_max_len_at_all_fails(
    gate: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deleting the flag would make the gate's subject vanish."""
    workflow = tmp_path / "fuzzing.yml"
    workflow.write_text("run: ./fuzz corpus/\n", encoding="utf-8")
    monkeypatch.setattr(gate, "WORKFLOW", workflow)
    assert gate.main([]) == 1


def test_missing_inputs_fail_closed(
    gate: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gate, "WORKFLOW", tmp_path / "absent.yml")
    assert gate.main([]) == 2


def test_no_harnesses_is_fail_closed_not_a_clean_pass(
    gate: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gate, "FUZZ_DIR", tmp_path)
    assert gate.main([]) == 2


class TestEveryComparisonOperatorIsSeen:
    """`<=`, `>=` and `>` were invisible, not merely unhandled.

    `_GUARD_RE`'s operator alternation was `(?P<op><|==)`.  For `size <= 65536)`
    it matches the `<`, then requires the expression to start with
    `[A-Za-z_0-9]` — and the `=` blocks that, so the pattern failed to match
    anywhere on the guard.  A guard that never MATCHES contributes neither a
    bound nor an entry in `unresolved`, and the gate's fail-closed path only
    fires for guards that match and will not resolve.  So the guard produced no
    signal at all, under an error message reading "a guard this gate skips is a
    branch that can go unreachable unnoticed".
    """

    @pytest.mark.parametrize(
        ("operator", "expected"),
        [
            ("<", 9002),
            ("<=", 9002),
            ("==", 9001),
            (">", 9002),
            (">=", 9001),
        ],
    )
    def test_each_operator_produces_a_bound(
        self, gate: ModuleType, tmp_path: Path, operator: str, expected: int
    ) -> None:
        source = (
            "\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
            "    if (size < 2) return 0;\n"
            "    size_t payload_len = size - 1;\n"
            f"    if (payload_len {operator} 9000) return 0;\n"
            "    return 0;\n"
            "}\n"
        )
        harness = _write_harness(tmp_path, source)
        required, unresolved = gate.required_max_len(harness)
        assert not unresolved, unresolved
        assert required == expected, (operator, required)

    def test_an_unresolvable_two_character_guard_is_reported(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        """Fail-closed, which is what a never-matching guard could not be."""
        harness = _write_harness(
            tmp_path,
            """
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size <= SOME_UNKNOWN_MACRO) return 0;
    return 0;
}
""",
        )
        _required, unresolved = gate.required_max_len(harness)
        assert unresolved, "an unresolvable `<=` guard produced no signal at all"


class TestAManualBoundClearsOnlyItsOwnGuard:
    """A MANUAL_BOUNDS entry used to clear the WHOLE unresolved list.

    Its reason string explains one guard — the one this tool's arithmetic
    cannot evaluate — but the assignment discarded every other unresolved guard
    in the same harness, including ones added afterwards.  A harness that needed
    one manual bound stopped being checked at all.
    """

    def test_an_unrelated_unresolved_guard_survives(
        self, gate: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        harness = _write_harness(
            tmp_path,
            """
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < DECLARED_IN_THE_REASON) return 0;
    if (size < A_SECOND_UNKNOWN_MACRO) return 0;
    return 0;
}
""",
        )
        monkeypatch.setitem(
            gate.MANUAL_BOUNDS,
            "fuzz_synthetic",
            (1234, "the guard on DECLARED_IN_THE_REASON is bounded by construction"),
        )
        _required, unresolved = gate._bound_for(harness)
        assert unresolved, "the manual bound silenced a guard its reason never mentions"
        assert any("A_SECOND_UNKNOWN_MACRO" in guard for guard in unresolved), unresolved
        assert not any("DECLARED_IN_THE_REASON" in guard for guard in unresolved), unresolved
