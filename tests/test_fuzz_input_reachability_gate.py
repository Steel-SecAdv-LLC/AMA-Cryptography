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

    # The GUARD-derived part, which is what this test was written for.
    # 3,309 signature + 1,952 public key + 1 selector byte: a `<` guard is
    # false AT its bound, so the bound itself is enough (the docstring's
    # 5,262 — this used to assert 5,263, one byte more than needed).
    required_dilithium, _ = gate._bound_for(gate.FUZZ_DIR / "fuzz_dilithium.c")
    assert required_dilithium == 3309 + 1952 + 1
    # 49,856 signature + 64 public key + 1 selector byte, past a `<` guard.
    required_sphincs, _ = gate._bound_for(gate.FUZZ_DIR / "fuzz_sphincs.c")
    assert required_sphincs == 49856 + 64 + 1

    # And the CEILING is the larger of that and the committed corpus, because
    # libFuzzer applies -max_len to corpus files as well as to mutations.  The
    # PQC verify seeds are `1 + bound + MESSAGE_BYTES`, 16 bytes past the
    # guard-derived ceiling, so every one of them used to be truncated on load
    # — landing just short of the branch it was built to reach.
    assert gate.max_len_for("fuzz_dilithium") == required_dilithium + 16
    assert gate.max_len_for("fuzz_sphincs") == required_sphincs + 16


def test_a_shallow_target_keeps_the_floor(gate: ModuleType) -> None:
    """Raising one ceiling must not lower another.

    `fuzz_sha3` is the shallow-guard case (its deepest guard is 3 bytes), and
    it does NOT sit at the floor: its committed corpus holds a 4,491-byte seed,
    395 bytes past DEFAULT_MAX_LEN, so that seed was being truncated too.  The
    seed rule found a third instance of the same defect the PQC corpus has.
    """
    required, _ = gate._bound_for(gate.FUZZ_DIR / "fuzz_sha3.c")
    assert required < gate.DEFAULT_MAX_LEN, required
    assert gate.max_len_for("fuzz_sha3") == gate.largest_seed("fuzz_sha3")
    assert gate.max_len_for("fuzz_sha3") > gate.DEFAULT_MAX_LEN

    # A target with a shallow guard AND no oversized seed does sit at the floor.
    assert gate.max_len_for("fuzz_consttime") == gate.DEFAULT_MAX_LEN


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
    # `payload_len < 9000` is false AT 9,000, plus the 1-byte payload offset.
    assert required == 9001


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
    assert required == 3309 + 1952 + 1


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


def test_a_guard_on_a_derived_length_variable_is_modeled(gate: ModuleType, tmp_path: Path) -> None:
    """`tail_len = size - K;` then `if (tail_len < N)` used to be invisible.

    The guard alternation was the literal `payload_len|size`, so a harness
    that derived any other length name and gated on it produced no bound AND
    no `unresolved` entry — the exact no-signal failure mode the gate's own
    comments document for `<=` guards, one level up.  fuzz_agent_binding
    already derives `tail_len = size - FUZZ_HEADER_BYTES`; only the guard was
    hypothetical.
    """
    harness = _write_harness(
        tmp_path,
        """
#define SYN_HEADER_BYTES 8
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 9) return 0;
    size_t tail_len = size - SYN_HEADER_BYTES;
    if (tail_len < 9000) return 0;
    return 0;
}
""",
    )
    required, unresolved = gate.required_max_len(harness)
    assert not unresolved
    # `tail_len < 9000` is false AT 9,000, plus the 8-byte offset.
    assert required == 9008


def test_a_data_dependent_length_is_reported_not_modeled(gate: ModuleType, tmp_path: Path) -> None:
    """`pt_len = payload_len - aad_len` can be small at ANY input size.

    Its guards are not input-length floors, so they contribute no bound —
    but they must be visible (unmodeled_guards feeds main()'s notes), not
    silently dropped.  A clamp assignment (`pt_len = 4096;`-style) must not
    fool the tracker into treating the variable as a clean offset either.
    """
    harness = _write_harness(
        tmp_path,
        """
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) return 0;
    size_t payload_len = size - 1;
    size_t aad_len = data[1];
    size_t pt_len = payload_len - aad_len;
    if (pt_len > 9000) pt_len = 9000;
    return 0;
}
""",
    )
    required, unresolved = gate.required_max_len(harness)
    assert not unresolved
    assert required < 9000, "a data-dependent clamp must not become a floor"
    assert "pt_len > 9000" in " ".join(gate.unmodeled_guards(harness))


def test_a_parenthesised_sum_resolves_and_a_product_fails_closed(
    gate: ModuleType, tmp_path: Path
) -> None:
    """`size < (N + 1)` resolves; `size < 2 * N` lands in unresolved.

    Both spellings used to fall outside the expression class entirely and
    produced no signal at all; now the sum is evaluated (parentheses cannot
    change a sum) and the product is a MANUAL_BOUNDS decision rather than a
    silently wrong bound.
    """
    harness = _write_harness(
        tmp_path,
        """
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < (9000 + 1)) return 0;
    return 0;
}
""",
    )
    required, unresolved = gate.required_max_len(harness)
    assert not unresolved
    assert required == 9001

    harness = _write_harness(
        tmp_path,
        """
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 * 4500) return 0;
    return 0;
}
""",
    )
    _required, unresolved = gate.required_max_len(harness)
    assert unresolved, "a multiplicative bound must fail closed, not vanish"


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
        gate.ManualBound(
            777,
            ("payload_len < needed",),
            "`needed` is a runtime value bounded by construction; worked out by hand",
        ),
    )
    assert gate.main([]) == 0
    assert gate.max_len_for("fuzz_synthetic") == gate.DEFAULT_MAX_LEN


def test_frost_is_declared_because_its_bound_is_a_runtime_value(gate: ModuleType) -> None:
    """The one real harness whose guard this gate cannot evaluate.

    Its entry must carry the reasoning, not just a number, or the next reader
    cannot check it.
    """
    entry = gate.MANUAL_BOUNDS["fuzz_frost"]
    assert entry.bound == 780
    assert entry.guards == ("payload_len < needed",)
    assert "FROST_FUZZ_MAX_N" in entry.reason


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
            ("<", 9001),
            ("<=", 9002),
            ("==", 9001),
            ("!=", 9001),
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
            gate.ManualBound(
                1234,
                ("size < DECLARED_IN_THE_REASON",),
                "the guard on DECLARED_IN_THE_REASON is bounded by construction",
            ),
        )
        _required, unresolved = gate._bound_for(harness)
        assert unresolved, "the manual bound silenced a guard its reason never mentions"
        assert any("A_SECOND_UNKNOWN_MACRO" in guard for guard in unresolved), unresolved
        assert not any("DECLARED_IN_THE_REASON" in guard for guard in unresolved), unresolved


class TestTheCeilingCoversTheCommittedSeeds:
    """libFuzzer applies -max_len to CORPUS FILES, not only to mutations.

    The ceiling was derived from the deepest guard alone.  The PQC verify
    seeds are built as `1 + bound + MESSAGE_BYTES` — 5,278 and 49,937 bytes —
    against the ceilings then derived, 5,263 and 49,922 (one byte above the
    true minimum through the `<` off-by-one since corrected), so EVERY seed the corpus
    builder writes for those two targets was truncated on load, by 15 bytes,
    landing just short of the branch it was constructed to reach.  Same defect
    the derivation was introduced to fix, from the other side.
    """

    @pytest.mark.parametrize("target", ["fuzz_dilithium", "fuzz_sphincs"])
    def test_no_committed_seed_is_truncated(self, gate: ModuleType, target: str) -> None:
        largest = gate.largest_seed(target)
        assert largest > 0, f"{target} has no committed seed corpus; this case has no subject"
        assert gate.max_len_for(target) >= largest, (
            f"{target}'s -max_len is below its largest seed, so libFuzzer " f"truncates it on load"
        )

    def test_every_target_with_a_corpus_covers_it(self, gate: ModuleType) -> None:
        checked = 0
        for harness in gate._harnesses():
            target = harness.stem
            largest = gate.largest_seed(target)
            if largest == 0:
                continue
            checked += 1
            assert gate.max_len_for(target) >= largest, target
        assert checked >= 2, "the seed-corpus sweep found nothing to check"

    def test_a_target_without_a_corpus_is_unaffected(self, gate: ModuleType) -> None:
        """The control: the seed rule must not raise a ceiling on its own."""
        assert gate.largest_seed("fuzz_no_such_target") == 0


def _body(*guards: str) -> str:
    lines = "\n".join(f"    {guard}" for guard in guards)
    return (
        "\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
        "    if (size < 2) return 0;\n"
        "    size_t payload_len = size - 1;\n"
        f"{lines}\n"
        "    return 0;\n"
        "}\n"
    )


class TestALengthOnEitherSideOfTheOperatorIsSeen:
    """The variable had to sit IMMEDIATELY LEFT of the operator.

    ``9000 > payload_len``, ``payload_len - 1 < 9000`` and ``(payload_len) <
    9000`` matched nowhere, so each contributed neither a bound nor an
    unresolved entry.  Measured against the previous revision: every guard in
    the first parametrisation below except the cast returned ``(3, [])`` — the
    3 of ``size < 2`` (then with the ``<`` off-by-one) and nothing else — and
    so did ``payload_len != 9000``.  ``(size_t)payload_len < 9000`` was already
    modeled and stays as the control.  ``payload_len + payload_len > 9000``
    was worse than invisible: it read as ``payload_len > 9000``.
    """

    @pytest.mark.parametrize(
        ("guard", "expected"),
        [
            ("if (9000 > payload_len) return 0;", 9001),
            ("if (9000 >= payload_len) return 0;", 9002),
            ("if (9000 <= payload_len) { data = 0; }", 9001),
            ("if (9000 + 1 > payload_len) return 0;", 9002),
            ("if (AMA_ML_DSA_65_SIGNATURE_BYTES > payload_len) return 0;", 3309 + 1),
            ("if ((payload_len) < 9000) return 0;", 9001),
            ("if ((size_t)payload_len < 9000) return 0;", 9001),
        ],
    )
    def test_a_reversed_or_wrapped_guard_is_modeled(
        self, gate: ModuleType, tmp_path: Path, guard: str, expected: int
    ) -> None:
        required, unresolved = gate.required_max_len(_write_harness(tmp_path, _body(guard)))
        assert not unresolved, unresolved
        assert required == expected

    @pytest.mark.parametrize(
        "guard",
        [
            "if (payload_len - 1 < 9000) return 0;",
            "if (9000 < payload_len * 2) return 0;",
            "if (payload_len + payload_len > 9000) return 0;",
        ],
    )
    def test_arithmetic_on_the_length_side_fails_closed(
        self, gate: ModuleType, tmp_path: Path, guard: str
    ) -> None:
        """Not modeled — this tool adds, it does not solve — so declared or failed."""
        _required, unresolved = gate.required_max_len(_write_harness(tmp_path, _body(guard)))
        assert unresolved, f"{guard!r} produced no signal at all"

    def test_a_length_passed_to_a_call_is_not_a_comparison_of_it(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        """Non-detection: ``f(payload, payload_len) != 0`` compares f's result."""
        source = _body(
            "if (consume(data, payload_len) != 0) return 0;",
            "if (data[payload_len - 1] == 0) return 0;",
        )
        required, unresolved = gate.required_max_len(_write_harness(tmp_path, source))
        assert (required, unresolved) == (2, [])

    def test_a_length_in_an_or_condition_fails_closed(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        """``A || B`` is reachable with ``A`` false: the policy is unchanged."""
        source = _body("if (payload_len != 9000 || data[0] == 1) return 0;")
        _required, unresolved = gate.required_max_len(_write_harness(tmp_path, source))
        assert unresolved == ["payload_len != 9000 (in a || condition)"]


class TestAManualBoundMatchesItsGuardsExactly:
    """An entry used to clear any guard whose expression occurred in its prose.

    ``_guard_expression(guard) not in reason`` is a SUBSTRING test: a new
    ``payload_len < n`` was cleared by any reason containing the letter n.
    """

    def test_a_guard_named_only_in_the_prose_is_not_cleared(
        self, gate: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        harness = _write_harness(
            tmp_path, _body("if (payload_len < needed) return 0;", "if (payload_len < n) return 0;")
        )
        monkeypatch.setitem(
            gate.MANUAL_BOUNDS,
            "fuzz_synthetic",
            gate.ManualBound(
                777,
                ("payload_len < needed",),
                "`needed` is bounded by construction; n is any count at all",
            ),
        )
        _required, unresolved = gate._bound_for(harness)
        assert unresolved == ["payload_len < n"]

    def test_a_declaration_with_no_subject_fails_the_gate(
        self,
        gate: ModuleType,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A stale entry would clear the next guard that renders the same."""
        _write_harness(tmp_path, _body("if (payload_len < 9000) return 0;"))
        monkeypatch.setattr(gate, "FUZZ_DIR", tmp_path)
        monkeypatch.setitem(
            gate.MANUAL_BOUNDS,
            "fuzz_synthetic",
            gate.ManualBound(777, ("payload_len < needed",), "the guard was deleted"),
        )
        assert gate.main([]) == 1
        assert "not an unresolved guard" in capsys.readouterr().err

    def test_every_real_declaration_has_a_subject(self, gate: ModuleType) -> None:
        for name in gate.MANUAL_BOUNDS:
            harness = gate.FUZZ_DIR / f"{name}.c"
            assert harness.is_file(), name
            assert gate.stale_declarations(harness) == [], name


def test_a_less_than_guard_needs_exactly_its_bound(gate: ModuleType) -> None:
    """The ``<`` row of the table: ``var < N`` is false AT N.

    Measured with clang 18's libFuzzer rather than argued: a harness that traps
    past ``if (payload_len < 100) return 0;`` (1-byte selector) traps under
    ``-max_len=101`` from a 101-byte seed and cannot under ``-max_len=100``.
    The rule added one here, contradicting the comment that stated it, so every
    ``<``-derived ceiling was a byte above the smallest one that works.
    """
    assert gate._needed("<", 100) + 1 == 101
    assert [gate._needed(op, 100) for op in ("<", "<=", "==", "!=", ">", ">=")] == [
        100,
        101,
        100,
        100,
        101,
        100,
    ]
