# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""NIST ACVP ML-KEM (FIPS 203) replay: keyGen, decapsulation and key-check groups.

Vectors: ``tests/kat/fips203/acvp/ml_kem_acvp_v1.1.0.42.json``, trimmed from
ACVP-Server v1.1.0.42 ``ML-KEM-keyGen-FIPS203`` and
``ML-KEM-encapDecap-FIPS203`` ``internalProjection.json`` (the upstream
digests are recorded in the file's ``source`` block).  The encapsulation AFT
group needs a derandomised encapsulation and replays in C
(``tests/c/test_ml_kem_acvp_encaps.c``).

What each group proves:

* ``keyGen`` (75): ``ML-KEM.KeyGen_internal(d, z)`` reproduces ``ek`` and
  ``dk`` byte for byte on all three parameter sets.
* ``decapsulation`` (30): 15 valid ciphertexts and 15 modified ones.  For a
  modified ciphertext the expected ``k`` is the implicit-rejection value
  ``J(z || c)`` — FIPS 203 Algorithm 18 line 9 — so a decapsulation that
  branched on the re-encryption check, or derived the rejection value
  differently, fails here.
* ``encapsulationKeyCheck`` (30): 15 well-formed keys and 15 flagged "noisy
  linear system values too large".  In v1.1.0.42 the flagged keys are emitted
  416 octets LONGER than the parameter set's ``ek`` (1216 / 1600 / 1984 octets
  for 512 / 768 / 1024), so what this group exercises is the FIPS 203 Sec 7.2
  **type check**; the wrapper raises ``ValueError`` for that (a caller error by
  its documented contract) and encapsulation refuses.  The Sec 7.2 **modulus
  check** on a correctly sized key with a coefficient at or above q is pinned
  separately by ``tests/test_key_formats.py`` (``native_ml_kem_pubkey_check``
  returning ``False``); no ACVP vector in this release exercises it.
* ``decapsulationKeyCheck`` (30): 15 well-formed keys and 15 with a modified
  ``H(ek)`` field.  FIPS 203 Sec 7.3 hash check: decapsulation must refuse the
  latter, which is the check ``kyber_decapsulate_internal`` gained in this
  pass.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ama_cryptography import pqc_backends as pb

VECTORS = (
    Path(__file__).resolve().parent / "kat" / "fips203" / "acvp" / "ml_kem_acvp_v1.1.0.42.json"
)

pytestmark = pytest.mark.skipif(
    not getattr(pb, "_ML_KEM_NATIVE_AVAILABLE", getattr(pb, "KYBER_AVAILABLE", True)),
    reason="native ML-KEM backend unavailable",
)


def _load() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(VECTORS.read_text(encoding="utf-8"))
    return loaded


def _ps(parameter_set: str) -> int:
    return int(parameter_set.rsplit("-", 1)[1])


_DATA = _load()


def _ids(group: str) -> list[str]:
    return [f"{t['parameterSet']}-tc{t['tcId']}" for t in _DATA[group]]


def test_vendored_file_records_its_upstream() -> None:
    src = _DATA["source"]
    assert src["ref"] == "v1.1.0.42"
    assert len(src["keyGen_internalProjection_sha256"]) == 64
    assert len(src["encapDecap_internalProjection_sha256"]) == 64
    assert len(_DATA["keyGen"]) == 75
    assert len(_DATA["decapsulation"]) == 30
    assert len(_DATA["encapsulationKeyCheck"]) == 30
    assert len(_DATA["decapsulationKeyCheck"]) == 30


@pytest.mark.parametrize("t", _DATA["keyGen"], ids=_ids("keyGen"))
def test_keygen_reproduces_ek_and_dk(t: dict[str, Any]) -> None:
    ek, dk = pb.native_ml_kem_keypair_from_seed(
        _ps(t["parameterSet"]), bytes.fromhex(t["d"]), bytes.fromhex(t["z"])
    )
    assert ek.hex() == t["ek"].lower()
    assert dk.hex() == t["dk"].lower()


@pytest.mark.parametrize("t", _DATA["decapsulation"], ids=_ids("decapsulation"))
def test_decapsulation_reproduces_k_including_implicit_rejection(t: dict[str, Any]) -> None:
    k = pb.native_ml_kem_decapsulate(
        _ps(t["parameterSet"]), bytes.fromhex(t["c"]), bytes.fromhex(t["dk"])
    )
    assert k.hex() == t["k"].lower(), t["reason"]


_EK_BYTES = {512: 800, 768: 1184, 1024: 1568}


@pytest.mark.parametrize("t", _DATA["encapsulationKeyCheck"], ids=_ids("encapsulationKeyCheck"))
def test_encapsulation_key_check_matches_acvp_verdict(t: dict[str, Any]) -> None:
    ps = _ps(t["parameterSet"])
    ek = bytes.fromhex(t["ek"])
    if t["testPassed"]:
        assert len(ek) == _EK_BYTES[ps]
        assert pb.native_ml_kem_pubkey_check(ps, ek) is True
        _, ss = pb.native_ml_kem_encapsulate(ps, ek)
        assert len(ss) == 32
    else:
        # v1.1.0.42 flags keys of the wrong length (see the module docstring):
        # the type check, not the modulus check.  Pin that fact so a future
        # vendoring that changes the shape of this group is noticed.
        assert len(ek) == _EK_BYTES[ps] + 416, t["reason"]
        with pytest.raises(ValueError):
            pb.native_ml_kem_pubkey_check(ps, ek)
        with pytest.raises(ValueError):
            pb.native_ml_kem_encapsulate(ps, ek)


@pytest.mark.parametrize("t", _DATA["decapsulationKeyCheck"], ids=_ids("decapsulationKeyCheck"))
def test_decapsulation_key_check_matches_acvp_verdict(t: dict[str, Any]) -> None:
    ps = _ps(t["parameterSet"])
    dk = bytes.fromhex(t["dk"])
    ek = bytes.fromhex(t["ek"])
    ct, _ = pb.native_ml_kem_encapsulate(ps, ek)
    if t["testPassed"]:
        assert len(pb.native_ml_kem_decapsulate(ps, ct, dk)) == 32
    else:
        with pytest.raises(ValueError, match=r"FIPS 203 Sec 7\.3"):
            pb.native_ml_kem_decapsulate(ps, ct, dk)
