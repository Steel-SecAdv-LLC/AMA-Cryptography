# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for ``tools/check_dudect_class_staging.py``.

The gate exists because a dudect lane whose class reaches the timer through a
branch or an address selection confounds the class with the harness's own
machine state, and that bias is fixed for a given binary on a given host — so
it reproduces every round with the same sign and is indistinguishable from a
leak by any threshold or round count.

Measured on this tree with byte-identical input in both classes (true effect
exactly zero), 500,000 measurements per run, 8 runs, threshold 5.0: the
ternary-select form the first version of this gate sanctioned trips in 4 of 8
runs; the masked-merge form ``dudect_stage_select`` trips in 0 of 8.  Placing
one class's key across two cache lines drives the same statistic to
|t| = 13.5..30.9 in 10 of 10 runs.

A gate is only worth its runtime if it fails on the thing it claims to catch,
so every case below is a mutation: the gate must reject a ternary on the class
before the timer (in both spellings the tree has used), an ``if`` on the class,
a ``[class_idx]`` address selection, an unaligned staging buffer, a class draw
with no timer after it, and a missing input file — and must accept the
masked-merge staging, the reused-probe form, and branchless class arithmetic.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "tools" / "check_dudect_class_staging.py"


def _load_gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_dudect_class_staging", GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


# --------------------------------------------------------------------------
# The tree itself
# --------------------------------------------------------------------------


def test_gate_passes_on_the_tree() -> None:
    """Every dudect lane in the repository stages its class input."""
    assert gate.main(["--root", str(REPO_ROOT)]) == 0


def test_every_governed_file_exists() -> None:
    """A gate whose input vanished must not pass; the list must be real."""
    assert gate.HARNESS_FILES, "an empty file list would pass vacuously"
    for rel in gate.HARNESS_FILES:
        assert (REPO_ROOT / rel).is_file(), rel


def test_missing_file_fails_closed(tmp_path: Path) -> None:
    """A missing harness is exit 2, not a clean report."""
    assert gate.main(["--root", str(tmp_path)]) == 2


# --------------------------------------------------------------------------
# Mutations the gate must reject
# --------------------------------------------------------------------------

UNSTAGED = """
static double test_lane(int iterations) {
    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        const uint8_t *key = class_idx ? key1 : key0;
        uint64_t start = get_time_ns();
        crypt(key);
        uint64_t end = get_time_ns();
    }
}
"""

UNSTAGED_LEGACY_SPELLING = """
static double test_lane(int iterations) {
    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        const uint8_t *key = (class_idx == 0) ? key0 : key1;
        uint64_t start = get_time_ns();
        crypt(key);
        uint64_t end = get_time_ns();
    }
}
"""

# The form the first version of this gate sanctioned: the destination is
# staged, but the SELECTION — a branch perfectly correlated with the class,
# and two distinct source addresses — is still in front of the timer.
STAGED_BUT_TERNARY_SELECTED = """
static double test_lane(int iterations) {
    _Alignas(64) uint8_t key_stage[16];
    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        const uint8_t *key =
            dudect_stage(key_stage, class_idx ? key1 : key0, sizeof key_stage);
        uint64_t start = get_time_ns();
        crypt(key);
        uint64_t end = get_time_ns();
    }
}
"""

# An `if` on the class before the timer is the same defect spelled out.
BRANCH_ON_CLASS = """
static double test_lane(int iterations) {
    _Alignas(64) uint8_t key_stage[16];
    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        if (class_idx) { memcpy(key_stage, key1, 16); }
        uint64_t start = get_time_ns();
        crypt(key_stage);
        uint64_t end = get_time_ns();
    }
}
"""

# An index by the class selects an address even without a branch.
INDEXED_BY_CLASS = """
static double test_lane(int iterations) {
    _Alignas(64) uint8_t key_stage[16];
    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        memcpy(key_stage, keys[class_idx], sizeof key_stage);
        uint64_t start = get_time_ns();
        crypt(key_stage);
        uint64_t end = get_time_ns();
    }
}
"""

STAGED = """
static double test_lane(int iterations) {
    _Alignas(64) uint8_t key_stage[16];
    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        const uint8_t *key =
            dudect_stage_select(key_stage, key0, key1, sizeof key_stage, class_idx);
        uint64_t start = get_time_ns();
        crypt(key);
        uint64_t end = get_time_ns();
    }
}
"""

STAGED_UNALIGNED = """
static double test_lane(int iterations) {
    uint8_t key_stage[16];
    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        const uint8_t *key =
            dudect_stage_select(key_stage, key0, key1, sizeof key_stage, class_idx);
        uint64_t start = get_time_ns();
        crypt(key);
        uint64_t end = get_time_ns();
    }
}
"""

REUSED_PROBE = """
static double test_tag_compare(int iterations) {
    _Alignas(64) uint8_t probe[16];
    memcpy(probe, tag, sizeof tag);
    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        probe[0]  = (uint8_t)(tag[0]  ^ (class_idx == 0));
        probe[15] = (uint8_t)(tag[15] ^ (class_idx == 1));
        uint64_t start = get_time_ns();
        verify(probe);
        uint64_t end = get_time_ns();
    }
}
"""

# Branchless arithmetic that builds the class input is the sanctioned way to
# construct a class without a branch, and must not be flagged.
BRANCHLESS_CLASS_ARITHMETIC = """
static double test_lane(int iterations) {
    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        memset(buf, (int)(0xFFu * (unsigned)class_idx), BUFFER_SIZE);
        uint64_t start = get_time_ns();
        ama_secure_memzero(buf, BUFFER_SIZE);
        uint64_t end = get_time_ns();
    }
}
"""

STAGED_STRUCT = """
static double test_binding(int iterations) {
    _Alignas(64) ama_agent_binding_t b_stage;
    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        const ama_agent_binding_t *b =
            dudect_stage_select(&b_stage, &good, &bad, sizeof b_stage, class_idx);
        uint64_t start = get_time_ns();
        check(b);
        uint64_t end = get_time_ns();
    }
}
"""

# A class draw the gate cannot pair with a timer must fail closed: without a
# window end the gate has no idea what it is judging.
DRAW_WITHOUT_TIMER = """
static double test_lane(int iterations) {
    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        crypt(keys[0], class_idx);
    }
}
"""

# The Yoda spelling of the same branch: `(0 == class_idx) ? a : b`.  The
# enforced pattern used to require `class_idx (==|!=) [01]` in that operand
# order, so flipping the operands passed the gate while executing the exact
# construction the module's measurement table shows tripping the lane.
YODA_TERNARY = """
static double test_lane(int iterations) {
    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        const uint8_t *sk = (0 == class_idx) ? sk_a : sk_b;
        uint64_t start = get_time_ns();
        crypt(sk);
        uint64_t end = get_time_ns();
    }
}
"""

# A relational comparison feeding the ternary: `class_idx > 0 ? a : b`.
RELATIONAL_TERNARY = """
static double test_lane(int iterations) {
    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        const uint8_t *sk = class_idx > 0 ? sk_a : sk_b;
        uint64_t start = get_time_ns();
        crypt(sk);
        uint64_t end = get_time_ns();
    }
}
"""

# A branch table is still a branch.
SWITCH_ON_CLASS = """
static double test_lane(int iterations) {
    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        const uint8_t *sk = sk_a;
        switch (class_idx) {
        case 1: sk = sk_b; break;
        default: break;
        }
        uint64_t start = get_time_ns();
        crypt(sk);
        uint64_t end = get_time_ns();
    }
}
"""

# The subscript's bias spelled as pointer arithmetic: the class selects an
# ADDRESS even though no comparison and no `[]` appears.
POINTER_ARITH_SELECT = """
static double test_lane(int iterations) {
    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        const uint8_t *sk = sk_base + (size_t)class_idx * SK_BYTES;
        uint64_t start = get_time_ns();
        crypt(sk);
        uint64_t end = get_time_ns();
    }
}
"""

# The same arithmetic computing a classed input VALUE is the sanctioned
# branchless form both harness families use for the lookup lane (measured:
# branchy mean t = -8.68, 9/10 over threshold; this form -0.85, 0/10).
VALUE_INDEX_ARITHMETIC = """
static double test_lane(int iterations) {
    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        size_t index =
            (size_t)class_idx * (TABLE_SIZE / 2) + (size_t)(rand() % (TABLE_SIZE / 2));
        uint64_t start = get_time_ns();
        ama_consttime_lookup(table, TABLE_SIZE, ELEM_SIZE, index, output);
        uint64_t end = get_time_ns();
    }
}
"""


@pytest.mark.parametrize(
    "source,expect_violation,label",
    [
        (UNSTAGED, True, "unstaged class-selected pointer"),
        (UNSTAGED_LEGACY_SPELLING, True, "legacy (class_idx == 0) spelling"),
        (STAGED_BUT_TERNARY_SELECTED, True, "destination staged, selection still branchy"),
        (BRANCH_ON_CLASS, True, "if on the class before the timer"),
        (INDEXED_BY_CLASS, True, "address indexed by the class"),
        (STAGED_UNALIGNED, True, "staging buffer not cache-line aligned"),
        (DRAW_WITHOUT_TIMER, True, "class draw with no timer to close the window"),
        (YODA_TERNARY, True, "Yoda comparison (0 == class_idx) feeding a ternary"),
        (RELATIONAL_TERNARY, True, "relational class_idx > 0 feeding a ternary"),
        (SWITCH_ON_CLASS, True, "switch on the class"),
        (POINTER_ARITH_SELECT, True, "address selected by pointer arithmetic"),
        (VALUE_INDEX_ARITHMETIC, False, "sanctioned classed-input value arithmetic"),
        (STAGED, False, "masked-merge staging, aligned"),
        (REUSED_PROBE, False, "reused probe, no class-selected address"),
        (BRANCHLESS_CLASS_ARITHMETIC, False, "branchless class arithmetic"),
        (STAGED_STRUCT, False, "staged struct by address"),
    ],
)
def test_gate_verdicts(source: str, expect_violation: bool, label: str) -> None:
    violations = gate.check_text(source, "synthetic.c")
    if expect_violation:
        assert violations, f"gate accepted {label}, which it must reject"
    else:
        assert not violations, f"gate rejected {label}: {violations}"


def test_multiline_binding_is_not_a_false_positive() -> None:
    """The staged form wraps across lines; a line-at-a-time scan mis-reads it.

    This is the specific way this gate would have become noise and then been
    switched off: the sanctioned form is too long for one line, so a naive
    scanner sees ``const uint8_t *key =`` alone, finds no ``dudect_stage`` on
    that line, and reports every correctly-staged lane as a violation.
    """
    assert not gate.check_text(STAGED, "synthetic.c")


def test_comments_do_not_trigger_the_gate() -> None:
    """A block comment describing the forbidden form is documentation.

    The harnesses explain the defect they were fixed for, and the explanation
    necessarily quotes the unstaged idiom.  A gate that fires on its own
    rationale is a gate that gets deleted.
    """
    commented = """
/* An earlier form wrote:
 *     const uint8_t *key = class_idx ? key1 : key0;
 * which confounds the class with the buffer address. */
""" + STAGED
    assert not gate.check_text(commented, "synthetic.c")


def test_violation_message_names_the_binding_and_the_fix() -> None:
    """The diagnostic has to be actionable, not just red."""
    violations = gate.check_text(UNSTAGED, "synthetic.c")
    assert len(violations) == 1
    message = violations[0]
    assert "class_idx ?" in message
    assert "dudect_stage_select(" in message
    assert "synthetic.c:" in message


# ---------------------------------------------------------------------------
# The alignment rule, derived from the calls rather than from a name suffix
# ---------------------------------------------------------------------------
class TestAlignmentIsCheckedOnEveryStagingDestination:
    """The rule was stated without qualification and enforced on a naming convention.

    The module docstring says "every staging buffer" must be ``_Alignas(64)``,
    because an unaligned one can straddle a cache line and reintroduce exactly
    the asymmetry the staging removes.  The implementation matched declarations
    whose identifier ends in ``_stage``.  ``tests/c/test_dudect.c`` uses that
    convention (``tag_use_stage``, ``sk_use_stage``, ``k_stage``…) so it was
    covered by coincidence; ``tools/constant_time/dudect_crypto.c`` — one of
    the three files in ``HARNESS_FILES`` — names its destinations ``sk``,
    ``key``, ``probe_tag``, ``ikm``, ``input``, and the alignment rule applied
    to **zero** declarations in it.

    Measured against the gate as it stood: removing ``_Alignas(64)`` from
    ``probe_tag`` in that file left the gate at exit 0.
    """

    ALIGNED = """
static void probe(int class_idx) {
    _Alignas(64) uint8_t dest[32];
    uint8_t a[32], b[32];
    dudect_stage_select(dest, a, b, sizeof dest, class_idx);
    uint64_t t0 = get_time_ns();
    consume(dest);
    uint64_t t1 = get_time_ns();
    ttest_update(&ctx, class_idx, (double)(t1 - t0));
}
"""

    UNALIGNED = ALIGNED.replace("_Alignas(64) uint8_t dest[32];", "uint8_t dest[32];")

    def test_an_unaligned_destination_is_reported(self) -> None:
        gate = _load_gate()
        violations = gate.check_text(self.UNALIGNED, "synthetic.c")
        assert violations, "an unaligned staging destination was accepted"
        assert "dest" in violations[0] and "_Alignas(64)" in violations[0]

    def test_an_aligned_destination_is_accepted(self) -> None:
        gate = _load_gate()
        assert gate.check_text(self.ALIGNED, "synthetic.c") == []

    def test_the_rule_does_not_depend_on_the_name(self) -> None:
        """The whole point: no ``_stage`` suffix anywhere."""
        gate = _load_gate()
        assert "_stage" not in self.UNALIGNED.replace("dudect_stage_select", "")
        assert gate.check_text(self.UNALIGNED, "synthetic.c")

    def test_a_destination_with_no_local_declaration_is_reported(self) -> None:
        """Staging into a caller's buffer cannot be verified here, so it fails.

        Fail-closed: "I cannot tell" is not "it is fine".
        """
        gate = _load_gate()
        source = """
static void probe(uint8_t *dest, int class_idx) {
    uint8_t a[32], b[32];
    dudect_stage_select(dest, a, b, 32, class_idx);
    uint64_t t0 = get_time_ns();
    consume(dest);
    uint64_t t1 = get_time_ns();
    ttest_update(&ctx, class_idx, (double)(t1 - t0));
}
"""
        violations = gate.check_text(source, "synthetic.c")
        assert violations and "no declaration" in violations[0], violations

    def test_the_real_crypto_harness_destinations_are_covered(self) -> None:
        """Non-vacuity on the file the suffix rule could not see.

        Being "in HARNESS_FILES" is not coverage; the destinations must
        actually be found and checked.
        """
        gate = _load_gate()
        text = (REPO_ROOT / "tools" / "constant_time" / "dudect_crypto.c").read_text(
            encoding="utf-8"
        )
        destinations = {m.group("dest") for m in gate._STAGE_CALL_DEST.finditer(text)}
        assert len(destinations) >= 5, destinations
        assert not any(name.endswith("_stage") for name in destinations), (
            "this file is the control precisely because none of its staging "
            f"destinations carries the _stage suffix: {sorted(destinations)}"
        )
        assert gate.check_text(text, "tools/constant_time/dudect_crypto.c") == []


class TestTheGateCannotPassOnWhatItCannotRead:
    """Two ways this gate reported clean over something it had not examined."""

    def test_an_ampersand_destination_is_examined(self) -> None:
        """`dudect_stage_select(&dest, ...)` never matched Rule 1's pattern.

        `_STAGE_CALL_DEST` required a bare identifier as the first argument.
        tests/c/test_dudect.c stages a STRUCT — `dudect_stage_select(&b_stage,
        &good, &bad, sizeof b_stage, class_idx)` — so the regex found nothing
        and Rule 1 examined zero destinations for that call.  Rule 1 exists to
        stop the alignment check depending on the `*_stage` naming convention;
        a spelling it cannot parse puts it back where it started.
        """
        source = (
            "static unsigned char misaligned_buf[64];\n"
            "void lane(void) {\n"
            "    int class_idx = draw();\n"
            "    dudect_stage_select(&misaligned_buf, &a, &b, 64, class_idx);\n"
            "    uint64_t start = get_time_ns();\n"
            "}\n"
        )
        violations = gate.check_text(source, "synthetic.c")
        assert any("misaligned_buf" in v for v in violations), violations

    def test_a_parenthesised_ampersand_destination_is_examined(self) -> None:
        source = (
            "static unsigned char misaligned_buf[64];\n"
            "void lane(void) {\n"
            "    int class_idx = draw();\n"
            "    dudect_stage_select( (&misaligned_buf), &a, &b, 64, class_idx);\n"
            "    uint64_t start = get_time_ns();\n"
            "}\n"
        )
        assert any("misaligned_buf" in v for v in gate.check_text(source, "synthetic.c"))

    def test_an_aligned_ampersand_destination_still_passes(self) -> None:
        """The control: the fix must not report a correctly aligned buffer."""
        source = (
            "static _Alignas(64) unsigned char ok_buf[64];\n"
            "void lane(void) {\n"
            "    int class_idx = draw();\n"
            "    dudect_stage_select(&ok_buf, &a, &b, 64, class_idx);\n"
            "    uint64_t start = get_time_ns();\n"
            "}\n"
        )
        assert gate.check_text(source, "synthetic.c") == [], source

    def test_a_file_with_no_recognised_class_draw_is_fatal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The gate's whole state machine is keyed to the name `class_idx`.

        `_CLASS_DRAW`, `_CLASS_USE`, `_CLASS_BRANCH` and `_STAGE_SELECT` all
        hard-code it, and `main` counted FILES examined, never lanes.  A
        harness that named its class variable anything else opened no window,
        produced no violations, and was printed as "every lane reaches its
        timer with no class-dependent branch or address selection in front of
        it" — over a file the gate had not read a single lane of.

        Driven through `main`, because that is where the coverage CLAIM is
        made; `check_text` stays a statement-level checker whose synthetic
        inputs legitimately have no class draw.
        """
        harness = tmp_path / "fake_harness.c"
        harness.write_text(
            "void lane(void) {\n    int which = draw();\n    uint64_t start = get_time_ns();\n}\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(gate, "HARNESS_FILES", ("fake_harness.c",))
        assert gate.main(["--root", str(tmp_path)]) == 2

    def test_a_harness_with_a_class_draw_is_examined(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The control: the coverage floor must not reject a real harness."""
        harness = tmp_path / "fake_harness.c"
        harness.write_text(
            "void lane(void) {\n"
            "    int class_idx = draw();\n"
            "    uint64_t start = get_time_ns();\n"
            "}\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(gate, "HARNESS_FILES", ("fake_harness.c",))
        assert gate.main(["--root", str(tmp_path)]) == 0

    def test_the_real_harnesses_all_yield_windows(self) -> None:
        for rel in gate.HARNESS_FILES:
            text = (REPO_ROOT / rel).read_text(encoding="utf-8")
            assert gate.class_draw_count(text) > 0, rel

    def test_every_governed_harness_is_clean(self) -> None:
        """Non-vacuity on the real files, not only on synthetic ones."""
        for rel in gate.HARNESS_FILES:
            text = (REPO_ROOT / rel).read_text(encoding="utf-8")
            assert gate.check_text(text, rel) == [], rel
