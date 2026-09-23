# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""docs/constant-time-testing.md names every ``--taint`` driver the gate has.

The list is prose, so it drifted: it named twelve while
``tools/check_ghash_constant_time._TAINT_DRIVERS`` held fourteen, missing the
two Ed25519 drivers added in the same branch.  This pins the sentence to the
dictionary it describes.
"""

from __future__ import annotations

import re
from pathlib import Path

from tools import check_ghash_constant_time

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_the_documented_taint_drivers_are_the_gates() -> None:
    text = (REPO_ROOT / "docs" / "constant-time-testing.md").read_text(encoding="utf-8")
    start = text.index("`--taint` drivers exist for ") + len("`--taint` drivers exist for ")
    end = text.index(".", text.index(" and `", start))
    documented = set(re.findall(r"`([a-z0-9-]+)`", text[start:end]))
    assert documented == set(check_ghash_constant_time._TAINT_DRIVERS)
