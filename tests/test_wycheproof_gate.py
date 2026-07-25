# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the vendored Wycheproof gate's own safety mechanisms.

The gate trusts each per-schema driver to actually call into the library. Two
mechanisms keep that trust honest, and both are pinned here:

  * the **hollow-driver tripwire** — a driver rigged to return a pass for every
    case would let invalid vectors through for any family whose behaviour the
    policy counts do not pin (everything except ECDSA's high-`s` divergence);
  * **reverse manifest coverage** — a vector file present on disk but absent
    from the manifest would be silently un-run.

Both are exercised for real, including the failure direction — a mechanism
that cannot fail is not a safety net.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import wycheproof_vectors.run_wycheproof as w  # noqa: E402 -- import follows the repo-root sys.path insert above; kept a real import (not importlib) so mypy --strict type-checks run_wycheproof.py (WYP-001)


@pytest.fixture(scope="module")
def corpora() -> dict[str, Any]:
    manifest = w.load_manifest()
    loaded, problems = w.verify_and_load(manifest)
    assert problems == [], f"corpus integrity problems before any test ran: {problems}"
    return loaded


def _hollow(_case: w.Case) -> tuple[bool, str]:
    """A driver that ignores its input and always reports a pass."""
    return True, "verify=True"


def test_real_drivers_pass_the_tripwire(corpora: dict[str, Any]) -> None:
    """Every shipped driver demonstrably consults the library."""
    assert w.driver_tripwires(corpora) == []


@pytest.mark.parametrize("schema", sorted(w.DRIVER_TRIPWIRE))
def test_hollow_driver_is_caught_for_each_family(
    corpora: dict[str, Any], monkeypatch: pytest.MonkeyPatch, schema: str
) -> None:
    """Rigging any one driver to always pass must be caught by the tripwire —
    for every family, not only ECDSA. This is the backstop the policy counts
    did not provide for HMAC/HKDF/AEAD/EdDSA/X25519."""
    monkeypatch.setitem(w.DRIVERS, schema, _hollow)
    problems = w.driver_tripwires(corpora)
    assert any(
        "hollow-driver tripwire" in p for p in problems
    ), f"a hollow {schema} driver slipped past the tripwire: {problems}"


def test_every_driven_schema_has_a_tripwire_field() -> None:
    """A new driver without a tripwire entry would silently regain the blind
    spot, so the two tables must stay in lockstep."""
    assert set(w.DRIVERS) == set(w.DRIVER_TRIPWIRE)


def test_reverse_coverage_flags_an_unlisted_vector_file() -> None:
    """A vector file on disk but absent from the manifest is a red gate, not a
    silently un-run file. Simulated by dropping one entry from the manifest so
    its on-disk file becomes unlisted."""
    manifest = w.load_manifest()
    dropped = sorted(manifest["files"])[0]
    trimmed = dict(manifest)
    trimmed["files"] = {k: v for k, v in manifest["files"].items() if k != dropped}
    _, problems = w.verify_and_load(trimmed)
    assert any(
        dropped in p and "absent from manifest" in p for p in problems
    ), f"unlisted file {dropped} was not flagged: {problems}"
