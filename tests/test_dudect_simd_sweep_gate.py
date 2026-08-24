# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Regression guard for the dudect SIMD-sweep slot escalation (audit M26).

The sweep's "Confirm dispatch slot resolves on this host" step used to exit 0
on CTest exit code 77 (the dispatcher could not honour the requested slot) for
EVERY slot, downstream-skipping the measurement and leaving only a ``::warning::``.
A SIMD kernel could therefore go permanently unmeasured behind a green gate —
the same "a gate slot that cannot fail" shape as the AVX-512 KAT lane (H2).

The fix splits the slots: AVX2 is baseline on every GitHub-hosted x86-64 runner
and NEON is mandated by the AArch64 base ISA, so a 77 on those is a
dispatch-wiring regression and must FAIL; only AVX-512 and SVE2 depend on the
specific runner's silicon and may legitimately skip.  These tests pin that
split against the real workflow so it cannot silently regress to a blanket skip
or misclassify a mandatory slot as optional.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = Path(__file__).resolve().parent.parent
DUDECT_YML = REPO_ROOT / ".github" / "workflows" / "dudect.yml"

#: The only slots whose CPU feature is genuinely runner-silicon-dependent.
EXPECTED_OPTIONAL = {"sha3-avx512x4", "kyber-sve2", "sha3-sve2"}


def _sweep_job() -> dict[str, Any]:
    doc = yaml.safe_load(DUDECT_YML.read_text(encoding="utf-8"))
    job = doc["jobs"]["dudect-simd-sweep"]
    assert isinstance(job, dict), "dudect-simd-sweep job is missing or malformed"
    return job


def _confirm_step_run() -> str:
    for step in _sweep_job()["steps"]:
        if str(step.get("name", "")).startswith("Confirm dispatch slot"):
            return str(step["run"])
    raise AssertionError("the 'Confirm dispatch slot resolves' step is gone")


def _declared_optional_slots() -> set[str]:
    run = _confirm_step_run()
    match = re.search(r'OPTIONAL_SLOTS="([^"]*)"', run)
    assert match is not None, "OPTIONAL_SLOTS is not declared in the confirm step"
    return set(match.group(1).split())


def _matrix_slots() -> set[str]:
    return set(_sweep_job()["strategy"]["matrix"]["slot"])


def test_optional_slots_are_exactly_avx512_and_sve2() -> None:
    assert _declared_optional_slots() == EXPECTED_OPTIONAL


def test_optional_slots_are_all_real_matrix_slots() -> None:
    """A typo in OPTIONAL_SLOTS would silently make a mandatory slot's 77 fail
    (harmless) or list a slot that does not exist (dead) — pin the subset."""
    assert _declared_optional_slots() <= _matrix_slots()


def test_the_mandatory_set_is_non_empty_and_covers_avx2_and_neon() -> None:
    mandatory = _matrix_slots() - _declared_optional_slots()
    assert mandatory, "every slot is optional — nothing would fail on a 77"
    assert any(s.endswith("-avx2") or "avx2" in s for s in mandatory), mandatory
    assert any(s.endswith("-neon") for s in mandatory), mandatory


def test_the_rc77_handler_is_not_a_blanket_skip() -> None:
    """The mandatory fail path must be reachable on 77: the handler both skips
    (exit 0) AND fails (exit 1) depending on the slot, rather than the old
    unconditional exit 0."""
    run = _confirm_step_run()
    # Isolate the rc==77 handling from the elif that follows it.
    m = re.search(r'rc"?\s*-eq\s*77.*?(?=elif|\Z)', run, re.DOTALL)
    assert m is not None, "the rc==77 branch is gone"
    branch = m.group(0)
    assert "exit 1" in branch, "the rc==77 branch has no mandatory-fail path (M26 regressed)"
    assert "::error::" in branch, "a mandatory 77 must surface as a GitHub error annotation"


@pytest.mark.parametrize("slot", sorted(_matrix_slots()))
def test_each_slot_is_classified_by_the_real_declared_list(slot: str) -> None:
    """Run the exact membership rule the step uses, against the REAL declared
    OPTIONAL_SLOTS, and assert each slot's 77-classification: optional slots
    skip (exit 0), mandatory slots fail (exit 1)."""
    optional = " ".join(sorted(_declared_optional_slots()))
    script = (
        f'OPTIONAL_SLOTS="{optional}"; '
        'case " ${OPTIONAL_SLOTS} " in '
        '*" ${SLOT} "*) exit 0 ;; '
        "*) exit 1 ;; "
        "esac"
    )
    result = subprocess.run(
        ["bash", "-c", script], env={"SLOT": slot, "PATH": "/usr/bin:/bin"}, check=False
    )
    expected = 0 if slot in EXPECTED_OPTIONAL else 1
    assert result.returncode == expected, (
        f"slot {slot!r} classified {'optional' if result.returncode == 0 else 'mandatory'}, "
        f"expected {'optional' if expected == 0 else 'mandatory'}"
    )
