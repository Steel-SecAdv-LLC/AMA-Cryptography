#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
README algorithm-table invariant citations must match invariant scope.

The NIST prime-curve row must cite INVARIANT-34 (the NIST curves emit RFC 6979's
``s`` verbatim and accept either representative by default; low-`s` is opt-in via
``AMA_NISTP_ECDSA_SIGN_LOW_S`` / ``AMA_NISTP_ECDSA_REQUIRE_LOW_S``), not
INVARIANT-28, which is scoped to secp256k1's strict-low-`s` sign/verify pair. The
behaviour is pinned by ``tests/test_nistp_curves.py``; this test pins the
matching README claim.

The expected citations are anchored to ``INVARIANTS.md`` rather than hard-coded,
so if a future edit broadens INVARIANT-28's scope or moves the NIST low-`s`
policy to a different invariant, this test surfaces the drift instead of
freezing today's numbering into CI.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"
INVARIANTS = REPO_ROOT / "INVARIANTS.md"


def _algorithm_row(name: str) -> str:
    """Return the capabilities-table row whose first cell is exactly ``name``.

    Rows are Markdown table lines: ``| <name> | Full | Full | <notes> |``. The
    ``Full`` second column pins the match to the algorithm *capabilities* table
    and not to a benchmark or FROST table that may also mention the name.
    """
    text = README.read_text(encoding="utf-8")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if len(cells) >= 3 and cells[0] == name and cells[1] == "Full":
            return stripped
    raise AssertionError(
        f"no README capabilities-table row (| {name} | Full | ...) found"
    )


def _invariant_section(number: int) -> str:
    """Return the text of the ``## INVARIANT-<n>`` section of INVARIANTS.md."""
    text = INVARIANTS.read_text(encoding="utf-8")
    # Section header, then everything up to the next "## INVARIANT-" header.
    pattern = re.compile(
        rf"^## INVARIANT-{number}\b.*?(?=^## INVARIANT-\d+\b|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    m = pattern.search(text)
    assert m, f"INVARIANTS.md has no ## INVARIANT-{number} section"
    return m.group(0)


# ---------------------------------------------------------------------------
# The source-of-truth anchors: verify the invariants still mean what the README
# citations assume, so the assertions below are semantic, not string-frozen.
# ---------------------------------------------------------------------------

def test_invariant_28_is_secp256k1_scoped() -> None:
    """INVARIANT-28's default low-s guarantee is about secp256k1, not the NIST curves.

    If someone broadens it to the prime curves, the README could legitimately
    cite it there — and this test should be the thing that makes that a
    deliberate, reviewed change rather than a silent one.
    """
    section = _invariant_section(28)
    assert "secp256k1" in section, "INVARIANT-28 no longer mentions secp256k1"
    # It must not have quietly become the NIST-curve low-s authority.
    assert "ama_secp256k1_ecdsa_sign" in section, (
        "INVARIANT-28 no longer names the secp256k1 signer as the subject of its "
        "low-s guarantee; the README NIST-curve citation assumptions may be stale"
    )


def test_invariant_34_is_the_nist_low_s_authority() -> None:
    """INVARIANT-34 is the paired sign/verify low-s control the NIST row must cite."""
    section = _invariant_section(34)
    lowered = section.lower()
    assert "low-`s`" in lowered or "low-s" in lowered, "INVARIANT-34 is not about low-s"
    # The env vars the README points callers at must be the ones this invariant defines.
    assert "AMA_NISTP_ECDSA_SIGN_LOW_S" in section
    assert "AMA_NISTP_ECDSA_REQUIRE_LOW_S" in section


# ---------------------------------------------------------------------------
# The README claim itself.
# ---------------------------------------------------------------------------

def test_nist_curve_row_does_not_misattribute_low_s() -> None:
    """The NIST prime-curve row must not claim default low-s, nor cite INVARIANT-28.

    Guards against regression of the exact defect: ``Low-s + strict DER
    (INVARIANT-28)`` on the P-256/P-384/P-521 row.
    """
    row = _algorithm_row("NIST P-256 / P-384 / P-521")

    assert "INVARIANT-28" not in row, (
        "NIST prime-curve README row cites INVARIANT-28, which is scoped to "
        "secp256k1; the NIST low-s policy is INVARIANT-34"
    )
    # The specific misstatement that was here: a bare "Low-s" default claim.
    assert "Low-s + strict DER" not in row, (
        "NIST prime-curve README row claims default low-s; INVARIANT-34 says the "
        "NIST signer emits RFC 6979 s verbatim and accepts either representative"
    )
    # It must cite the correct invariant and keep the (accurate) strict-DER claim.
    assert "INVARIANT-34" in row, "NIST prime-curve row must cite INVARIANT-34 for its low-s policy"
    assert "DER" in row, "NIST prime-curve row dropped its (accurate) strict-DER claim"


def test_secp256k1_low_s_claim_not_weakened() -> None:
    """Fixing the NIST row must not have collaterally weakened the secp256k1 story.

    secp256k1 genuinely is low-s by default (INVARIANT-28); its row must still
    reflect a deterministic-ECDSA / comb posture and not inherit the NIST
    'either representative' language.
    """
    row = _algorithm_row("secp256k1")
    assert "RFC 6979" in row, "secp256k1 row no longer documents deterministic ECDSA"
    assert "either representative" not in row, (
        "secp256k1 row wrongly picked up the NIST curves' permissive-verify wording"
    )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
