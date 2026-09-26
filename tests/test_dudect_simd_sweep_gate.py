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
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = Path(__file__).resolve().parent.parent
DUDECT_YML = REPO_ROOT / ".github" / "workflows" / "dudect.yml"

#: The only slots whose CPU feature is genuinely runner-silicon-dependent:
#: AVX-512 and VAES are on some hosted x86-64 SKUs only, SVE2 on some AArch64.
EXPECTED_OPTIONAL = {
    "sha3-avx512x4",
    "aes-gcm-vaes",
    "kyber-sve2",
    "sha3-sve2",
    "dilithium-ntt-sve2",
}

# The membership-rule test below runs the step's own POSIX `case` through bash
# with a POSIX PATH, so it reproduces the workflow byte-for-byte on the runners
# that actually execute the dudect SIMD sweep — ubuntu x86-64 and AArch64.  It
# is skipped only on Windows: Git Bash there resolves the invocation against a
# non-POSIX environment, the `case " ${SLOT} "` never matches, and the sweep
# job has no Windows lane for it to guard.  Linux AND macOS keep running it, so
# both production runner families stay covered — this is not a coverage hole,
# it is the same POSIX-shell scoping the apt/choco gate tests already use.  The
# platform-independent assertions above (the declared list, the matrix subset,
# the rc==77 handler shape) keep running everywhere.
_POSIX_SHELL_ONLY = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("bash") is None,
    reason="runs the step's POSIX `case` through bash; the dudect SIMD sweep has no Windows lane",
)


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


#: The membership idiom and BOTH of its arms: padded, quoted substring match
#: of the slot inside the space-joined optional list, whose member arm skips
#: (``exit 0``) and whose catch-all arm fails (``exit 1``).  This used to pin
#: the head of the ``case`` only, so swapping the two arms — every optional
#: slot failing, every mandatory slot skipping — still matched it, and the
#: classification test below, which then ran its own copy of the rule, stayed
#: green over a workflow that did the opposite.  ``[^;]`` keeps each arm's
#: body inside that arm: shell arms end at ``;;``.
_MEMBERSHIP_IDIOM_RE = re.compile(
    r'case\s+" \$\{OPTIONAL_SLOTS\} "\s+in\s+'
    r'\*" \$\{AMA_DISPATCH_ONLY\} "\*\)(?P<member>[^;]*);;\s*'
    r"\*\)(?P<other>[^;]*);;\s*esac",
)


@_POSIX_SHELL_ONLY
def test_the_workflow_still_uses_the_modeled_membership_idiom() -> None:
    """The padded-quoted idiom, and which arm exits which way, in dudect.yml.

    If the pattern were edited — the quotes dropped (``*${AMA_DISPATCH_ONLY}*``,
    which turns substring slots into false members), the padding removed — or
    the arms' exits swapped, this fails and names the change.  The behaviour
    itself is pinned by executing the step in the test below.
    """
    run = _confirm_step_run()
    match = _MEMBERSHIP_IDIOM_RE.search(run)
    assert match is not None, (
        "dudect.yml's confirm step no longer uses the padded-quoted "
        'membership idiom (`case " ${OPTIONAL_SLOTS} " in *" ${AMA_DISPATCH_ONLY} "*) '
        "... ;; *) ... ;; esac`)"
    )
    member, other = match.group("member"), match.group("other")
    assert re.search(r"\bexit 0\b", member) and not re.search(
        r"\bexit [1-9]", member
    ), "the OPTIONAL-slot arm must skip (exit 0) — it no longer does"
    assert re.search(r"\bexit 1\b", other) and not re.search(
        r"\bexit 0\b", other
    ), "the catch-all (mandatory-slot) arm must fail (exit 1) — it no longer does"
    assert "::error::" in other and "::error::" not in member


def _run_confirm_step(tmp_path: Path, slot: str, dispatch_rc: int) -> tuple[int, str]:
    """Execute dudect.yml's own confirm step for ``slot``.

    The step body is taken verbatim from the workflow, with the one GitHub
    expression it contains (``${{ matrix.slot }}``) substituted as the runner
    would, and run the way the runner runs an unspecified-shell step on Linux
    (``bash -e``).  The dispatch binary is a stub exiting ``dispatch_rc``, so
    the step's own rc==77 branch — not a copy of it — decides the outcome.
    """
    body = _confirm_step_run().replace("${{ matrix.slot }}", slot)
    assert "${{" not in body, "the confirm step gained a GitHub expression this test cannot resolve"
    stub = tmp_path / "build" / "bin" / "test_dispatch_only_env"
    stub.parent.mkdir(parents=True, exist_ok=True)
    stub.write_text(f"#!/bin/sh\nexit {dispatch_rc}\n", encoding="utf-8", newline="")
    stub.chmod(0o755)
    script = tmp_path / "confirm.sh"
    script.write_text(body, encoding="utf-8", newline="")
    output = tmp_path / "github_output"
    output.write_text("", encoding="utf-8")
    result = subprocess.run(
        ["bash", "-e", str(script)],
        cwd=tmp_path,
        env={
            "AMA_DISPATCH_ONLY": slot,
            "GITHUB_OUTPUT": str(output),
            "PATH": "/usr/bin:/bin",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode, output.read_text(encoding="utf-8")


def test_the_step_takes_its_slot_from_the_matrix() -> None:
    """The executed step reads AMA_DISPATCH_ONLY; the workflow must set it to the slot."""
    (step,) = [
        step
        for step in _sweep_job()["steps"]
        if str(step.get("name", "")).startswith("Confirm dispatch slot")
    ]
    assert step["env"]["AMA_DISPATCH_ONLY"] == "${{ matrix.slot }}"


@_POSIX_SHELL_ONLY
@pytest.mark.parametrize("slot", sorted(_matrix_slots()))
def test_each_slot_is_classified_by_the_real_declared_list(slot: str, tmp_path: Path) -> None:
    """Run the workflow's own confirm step with the dispatcher answering 77,
    and assert each slot's classification: optional slots skip (exit 0),
    mandatory slots fail (exit 1), and both record ``supported=false``.

    This used to run a hand-written copy of the step's ``case`` rule, which a
    change to the workflow's arms could not reach; it now runs the step.
    """
    returncode, output = _run_confirm_step(tmp_path, slot, 77)
    expected = 0 if slot in EXPECTED_OPTIONAL else 1
    assert returncode == expected, (
        f"slot {slot!r} classified {'optional' if returncode == 0 else 'mandatory'}, "
        f"expected {'optional' if expected == 0 else 'mandatory'}"
    )
    assert "supported=false" in output, output


@_POSIX_SHELL_ONLY
@pytest.mark.parametrize(
    "dispatch_rc,expected_rc,expected_output", [(0, 0, "supported=true"), (3, 3, "supported=false")]
)
def test_the_step_passes_through_a_supported_slot_and_a_real_failure(
    tmp_path: Path, dispatch_rc: int, expected_rc: int, expected_output: str
) -> None:
    """Controls for the executed step: without a 77 the classification is not
    consulted — a supported slot proceeds, any other failure is propagated."""
    mandatory = sorted(_matrix_slots() - EXPECTED_OPTIONAL)[0]
    returncode, output = _run_confirm_step(tmp_path, mandatory, dispatch_rc)
    assert returncode == expected_rc
    assert expected_output in output, output
