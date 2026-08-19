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
