# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Benchmark baselines must not silently outlive their own validity window
=======================================================================

Both `benchmarks/baseline.json` and `benchmarks/arm-baseline.json` declare
`metadata.applies_through_release` — the last release the floors in that file
were calibrated for. Nothing read that field: a repo-wide search for it
returned matches only inside the two JSON files and the prose that describes
them, never in a gate, a workflow, or the runner.

That is the failure mode this pins. The floors were measured against v2.1.2
and declared valid through v3.0.0, while the library shipped 3.4.0 — four
minor releases past the window — and the regression job kept reporting PASS.
It could hardly do otherwise: measured throughput had moved so far above the
stale floors that `benchmark-report.md` recorded deltas of -642% and -1806%
and still called them passes. A gate whose thresholds no longer bear any
relation to the code cannot fail, and a gate that cannot fail is worse than no
gate, because it manufactures assurance a reviewer will rely on.

So the window is now enforced rather than merely documented: when the
package's minor version moves past `applies_through_release`, this test fails
and names the remedy — re-measure on a canonical runner and update the floors
with the justification `benchmarks/check_baseline_justification.py` already
requires for any baseline edit.

Patch releases are deliberately tolerated. A z-bump carries no performance
intent, so requiring recalibration for one would be noise; the check compares
`(major, minor)` only.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINES = (
    REPO_ROOT / "benchmarks" / "baseline.json",
    REPO_ROOT / "benchmarks" / "arm-baseline.json",
)


def _package_version() -> tuple[int, int, int]:
    """Read the canonical version from ama_cryptography/__init__.py.

    Parsed rather than imported so the check still runs in an environment
    where the native extension is absent — the same reason
    tools/check_version_consistency.py parses it.
    """
    init = (REPO_ROOT / "ama_cryptography" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'^__version__\s*=\s*["\'](\d+)\.(\d+)\.(\d+)["\']', init, re.M)
    assert m is not None, "could not parse __version__ from ama_cryptography/__init__.py"
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _parse_release(value: str) -> tuple[int, int, int]:
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", value.strip())
    assert m is not None, f"malformed release string: {value!r}"
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


@pytest.mark.parametrize("path", BASELINES, ids=lambda p: p.name)
def test_baseline_declares_its_validity_window(path: Path) -> None:
    """The metadata fields this gate depends on must exist and be well-formed."""
    meta = json.loads(path.read_text(encoding="utf-8"))["metadata"]
    for field in ("baseline_source_release", "applies_through_release"):
        assert field in meta, f"{path.name}: metadata.{field} is missing"
        _parse_release(meta[field])


@pytest.mark.parametrize("path", BASELINES, ids=lambda p: p.name)
def test_baseline_has_not_outlived_its_window(path: Path) -> None:
    """Fail once the package's minor version passes `applies_through_release`."""
    meta = json.loads(path.read_text(encoding="utf-8"))["metadata"]
    through = _parse_release(meta["applies_through_release"])
    current = _package_version()

    # Compare (major, minor): a patch bump carries no performance intent.
    if current[:2] > through[:2]:
        pytest.fail(
            f"{path.name} floors are stale.\n"
            f"  measured against release : {meta['baseline_source_release']}\n"
            f"  declared valid through   : {meta['applies_through_release']}\n"
            f"  package version is now   : {current[0]}.{current[1]}.{current[2]}\n"
            "\n"
            "The regression gate is comparing today's code against floors that no "
            "longer describe it, so it cannot fail and its PASS means nothing.\n"
            "\n"
            "Remedy: re-measure on a canonical runner "
            "(`./build/bin/benchmark_c_raw`, or the benchmark-regression CI job), "
            "update the floors in this file, bump `applies_through_release`, and "
            "record the measurement in `metadata.baseline_change_log`. "
            "`benchmarks/check_baseline_justification.py` requires a per-primitive "
            "justification, a measured number, and a runner identifier in the "
            "commit message or PR body for any baseline edit."
        )
