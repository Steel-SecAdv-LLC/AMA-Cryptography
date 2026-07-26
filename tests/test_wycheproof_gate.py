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


def test_ecdsa_tripwire_flips_inside_s_not_the_der_tag(corpora: dict[str, Any]) -> None:
    """The ECDSA tripwire must exercise *curve-math* rejection, not DER-parse
    rejection: it corrupts a byte inside the ``s`` integer while leaving the DER
    framing (SEQUENCE tag, lengths, ``r``) intact. Prove all four properties on
    a real corpus signature: (a) byte 0 stays 0x30 and ``r`` is untouched,
    (b) the flipped signature still parses as DER and its ``s`` changed,
    (c) exactly one byte — inside ``s`` — differs, and (d) a correct driver
    rejects it with ``verify=False`` (the R.x check), never a parse exception."""
    fname = "ecdsa_secp256k1_sha256_test.json"
    data = corpora[fname]
    schema = data["schema"]
    driver = w.DRIVERS[schema]

    probe: tuple[dict[str, Any], dict[str, Any]] | None = None
    for raw_group in data["testGroups"]:
        group = dict(raw_group, _schema=schema)
        for test in group["tests"]:
            if test.get("result") == "valid" and test.get("sig"):
                ok, _ = driver(w.Case(file=fname, group=group, test=test))
                if ok:
                    probe = (group, test)
                    break
        if probe is not None:
            break
    assert probe is not None, "no passing `valid` ECDSA vector found to probe the tripwire"
    group, test = probe

    orig = bytes.fromhex(str(test["sig"]))
    flipped = bytes.fromhex(w._flip_sig_body_byte(str(test["sig"])))

    # (a) DER framing intact: same length, SEQUENCE tag + all of r untouched.
    assert len(flipped) == len(orig)
    assert flipped[0] == 0x30 == orig[0], "the SEQUENCE tag must NOT be the byte that flips"
    r_len = orig[3]
    assert flipped[: 4 + r_len] == orig[: 4 + r_len], "r (tag/len/value) must be untouched"
    s_tag = 4 + r_len
    assert flipped[s_tag] == orig[s_tag] == 0x02, "s INTEGER tag must be untouched"
    assert flipped[s_tag + 1] == orig[s_tag + 1], "s length must be untouched"

    # (b) still valid DER, and s actually changed.
    s_orig = w._der_s_value(orig)
    s_flipped = w._der_s_value(flipped)
    assert (
        s_orig is not None and s_flipped is not None
    ), "flipped signature must remain parseable DER"
    assert s_flipped != s_orig, "the s value must actually change"

    # (c) exactly one byte differs, and it lies inside s's value.
    diffs = [i for i in range(len(orig)) if orig[i] != flipped[i]]
    assert len(diffs) == 1, f"exactly one byte should change, got {diffs}"
    s_start, s_end = s_tag + 2, s_tag + 2 + orig[s_tag + 1]
    assert s_start <= diffs[0] < s_end, "the changed byte must lie inside the s integer"

    # (d) a correct driver rejects it via the curve-math check, not a parse error.
    corrupted = dict(test, sig=flipped.hex())
    ok_bad, detail = driver(w.Case(file=fname, group=group, test=corrupted))
    assert ok_bad is False, f"the corrupted signature must fail verification: {detail}"
    assert (
        "rejected:" not in detail
    ), f"rejection must be curve-math (verify=False), not a DER-parse exception: {detail}"


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
