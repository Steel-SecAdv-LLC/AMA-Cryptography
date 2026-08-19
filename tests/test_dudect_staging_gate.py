# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for ``tools/check_dudect_class_staging.py``.

The gate exists because a dudect lane that hands the timed call one of two
per-class buffers confounds the class with the input's ADDRESS, and that bias
is fixed for a given binary on a given host — so it reproduces every round
with the same sign and is indistinguishable from a leak by any threshold or
round count.  Measured on this tree, with identical key data in both classes,
placing one class's key across two cache lines drives the cropped statistic to
|t| = 13.5..30.9 in 10 of 10 runs.

A gate is only worth its runtime if it fails on the thing it claims to catch,
so every case below is a mutation: the gate must reject the unstaged form, the
legacy ``(class_idx == 0) ?`` spelling, an unaligned staging buffer, and a
missing input file, and must accept the staged form and the reused-probe form.
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
        crypt(key);
    }
}
"""

STAGED = """
static double test_lane(int iterations) {
    _Alignas(64) uint8_t key_stage[16];
    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        const uint8_t *key =
            dudect_stage(key_stage, class_idx ? key1 : key0, sizeof key_stage);
        crypt(key);
    }
}
"""

STAGED_UNALIGNED = """
static double test_lane(int iterations) {
    uint8_t key_stage[16];
    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        const uint8_t *key =
            dudect_stage(key_stage, class_idx ? key1 : key0, sizeof key_stage);
        crypt(key);
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
        verify(probe);
    }
}
"""

STAGED_STRUCT = """
static double test_binding(int iterations) {
    _Alignas(64) ama_agent_binding_t b_stage;
    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        const ama_agent_binding_t *b =
            dudect_stage(&b_stage, class_idx ? &bad : &good, sizeof b_stage);
        check(b);
    }
}
"""


@pytest.mark.parametrize(
    "source,expect_violation,label",
    [
        (UNSTAGED, True, "unstaged class-selected pointer"),
        (UNSTAGED_LEGACY_SPELLING, True, "legacy (class_idx == 0) spelling"),
        (STAGED_UNALIGNED, True, "staging buffer not cache-line aligned"),
        (STAGED, False, "staged, aligned"),
        (REUSED_PROBE, False, "reused probe, no class-selected pointer"),
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
    assert "key" in message
    assert "dudect_stage(" in message
    assert "synthetic.c:" in message
