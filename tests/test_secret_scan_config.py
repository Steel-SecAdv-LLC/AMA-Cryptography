# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The TruffleHog secret-scan step excludes exactly one detector, for cause.

TruffleHog's Lob detector matches any ``test_<word>`` token — Lob API keys are
``test_<hex>`` / ``live_<hex>`` — and its verifier lenient-accepts them, so
``--only-verified`` does not filter them. On this repository that means every
pytest function name is reported as a "verified Lob API key" (685 of them), and
the secret-scanning gate fails on the naming convention rather than on a secret.
This is a cryptography library with no Lob integration, so a real Lob key can
never legitimately appear.

The fix excludes the Lob detector. This test guards the two ways that fix could
rot into something worse than the problem:

* the exclusion silently disappears, and the gate goes back to red on every
  ``test_`` name until people learn to ignore it (the verification-theatre
  failure mode this whole line of work exists to close); or
* the exclusion silently widens to real detectors (Github, AWS, …), quietly
  blinding the gate to the secrets it exists to catch — a weakening dressed up
  as a false-positive fix.

So the rule pinned here is exact: the step runs, still verified-only, and
excludes Lob and nothing but Lob.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SECURITY_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "security.yml"

#: Detectors it is legitimate to turn off, with the reason each is off. Adding a
#: name here is a deliberate, reviewed act; the test fails on any exclusion not
#: in this map, so widening the exclusion set cannot pass unnoticed.
_JUSTIFIED_EXCLUSIONS = {
    "Lob": "matches every pytest test_<name>; no Lob integration exists in this repo",
}


def _trufflehog_step() -> dict[str, Any]:
    document = yaml.safe_load(SECURITY_WORKFLOW.read_text(encoding="utf-8"))
    for job in document["jobs"].values():
        for step in job.get("steps", []):
            uses = step.get("uses", "")
            if isinstance(uses, str) and uses.startswith("trufflesecurity/trufflehog@"):
                trufflehog_step: dict[str, Any] = step
                return trufflehog_step
    raise AssertionError("security.yml has no trufflesecurity/trufflehog step")


def _extra_args() -> str:
    step = _trufflehog_step()
    with_block = step.get("with", {})
    return str(with_block.get("extra_args", ""))


def _excluded_detectors(extra_args: str) -> list[str]:
    """Every detector named in an --exclude-detectors flag, `=`- or space-form."""
    names: list[str] = []
    for match in re.finditer(r"--exclude-detectors(?:=|\s+)([^\s]+)", extra_args):
        names.extend(part for part in match.group(1).split(",") if part)
    return names


def test_the_scan_step_exists() -> None:
    """A gate that is not wired up cannot catch anything."""
    assert _trufflehog_step()["with"]["path"] == "./"


def test_the_scan_stays_verified_only() -> None:
    """--only-verified is the noise floor; dropping it floods the gate with
    unverified candidates and it becomes a red light nobody reads."""
    assert "--only-verified" in _extra_args()


def test_lob_is_excluded() -> None:
    """The documented fix must actually be in place."""
    assert "Lob" in _excluded_detectors(_extra_args())


def test_only_justified_detectors_are_excluded() -> None:
    """Every excluded detector must be one this test signs off on, so an
    exclusion widened to a real detector (Github, AWS, …) fails here instead of
    silently blinding the scan."""
    excluded = _excluded_detectors(_extra_args())
    unjustified = [d for d in excluded if d not in _JUSTIFIED_EXCLUSIONS]
    assert not unjustified, (
        f"security.yml excludes detector(s) with no recorded justification: {unjustified}. "
        "Add the detector and its reason to _JUSTIFIED_EXCLUSIONS only if turning it off is "
        "genuinely correct for this repository."
    )
