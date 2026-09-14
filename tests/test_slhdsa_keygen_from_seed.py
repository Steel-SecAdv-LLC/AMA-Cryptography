# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""``generate_slhdsa_keypair_from_seed`` — the FIPS 205 §10.1 deterministic keygen.

The binding was announced in the CHANGELOG as delivered but was not exported,
not documented beside its siblings, and had no caller and no test.  These
tests pin the contract its docstring states:

* the secret key is ``SK.seed || SK.prf || PK.seed || PK.root`` and the public
  key is ``PK.seed || PK.root`` — i.e. ``pk == sk[-2n:]``;
* the derivation is deterministic;
* the pair signs and verifies through the shipped ``slhdsa_sign`` /
  ``slhdsa_verify`` bindings;
* a seed of the wrong length is refused with ``ValueError``.

The first two are pinned against NIST, not against ourselves: every ``sk`` in
the ACVP sigGen projections under ``tests/kat/fips205/`` carries its three
seeds in the clear, so re-deriving from ``sk[:3n]`` must reproduce NIST's
``sk`` byte for byte, for both parameter sets.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import ama_cryptography.pqc_backends as pb

pytestmark = pytest.mark.skipif(
    not pb.SPHINCS_AVAILABLE, reason="SPHINCS+/SLH-DSA native backend not available"
)

_KAT_DIR = Path(__file__).parent / "kat" / "fips205"

#: param_set -> (n, ACVP sigGen projection carrying NIST's secret keys)
_PARAM_SETS: dict[str, tuple[int, Path]] = {
    "SHAKE-128s": (16, _KAT_DIR / "SLH-DSA-SHAKE-128s-sigGen-FIPS205.json"),
    "SHA2-256f": (32, _KAT_DIR / "SLH-DSA-SHA2-256f-sigGen-FIPS205.json"),
}


def _nist_secret_keys(param_set: str) -> list[tuple[int, bytes]]:
    n, path = _PARAM_SETS[param_set]
    with path.open(encoding="utf-8") as handle:
        vectors: list[dict[str, Any]] = json.load(handle)["vectors"]
    keys = [(v["tcId"], bytes.fromhex(v["sk"])) for v in vectors]
    assert keys, f"{path.name} carries no vectors"
    assert all(len(sk) == 4 * n for _, sk in keys), "sk is not 4n bytes"
    return keys


def _seeds(sk: bytes, n: int) -> tuple[bytes, bytes, bytes]:
    return sk[:n], sk[n : 2 * n], sk[2 * n : 3 * n]


@pytest.fixture
def pct_recorder(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record, instead of run, the INVARIANT-41 pairwise consistency test.

    The real PCT signs, and SLH-DSA-SHAKE-128s signing costs ~1 s, so a sweep
    over every NIST key would take half a minute for no extra evidence: the
    PCT itself is exercised, for real, by ``test_the_pair_signs_and_verifies``.
    Recording it also lets the sweep assert that the seeded path RUNS one.
    """
    recorded: list[str] = []
    monkeypatch.setattr(
        pb, "pairwise_test_signature", lambda s, v, sk, pk, name: recorded.append(name)
    )
    return recorded


def test_the_binding_is_exported() -> None:
    assert "generate_slhdsa_keypair_from_seed" in pb.__all__
    assert callable(pb.generate_slhdsa_keypair_from_seed)


@pytest.mark.parametrize("param_set", sorted(_PARAM_SETS))
def test_nist_seeds_reproduce_nist_secret_keys_byte_for_byte(
    param_set: str, pct_recorder: list[str]
) -> None:
    """(i) determinism and (ii) layout, against every NIST ACVP key.

    ``sk[:3n]`` are the three §10.1 seeds; deriving from them must give back
    NIST's whole ``sk`` (so ``PK.root`` was computed correctly) and a public
    key equal to ``sk[-2n:]``.
    """
    n, _ = _PARAM_SETS[param_set]
    keys = _nist_secret_keys(param_set)
    for tc_id, sk in keys:
        first = pb.generate_slhdsa_keypair_from_seed(*_seeds(sk, n), param_set=param_set)
        again = pb.generate_slhdsa_keypair_from_seed(*_seeds(sk, n), param_set=param_set)
        assert bytes(first.secret_key) == sk, f"tc{tc_id}: sk differs from NIST"
        assert first.public_key == sk[-2 * n :], f"tc{tc_id}: pk is not PK.seed || PK.root"
        assert first.public_key == sk[2 * n : 4 * n]
        assert (
            bytes(again.secret_key) == sk and again.public_key == first.public_key
        ), f"tc{tc_id}: derivation is not deterministic"
        assert first.param_set == param_set
        assert isinstance(first.secret_key, bytearray), "INVARIANT-6: sk must be wipeable"
        assert isinstance(first.public_key, bytes)
    # INVARIANT-41: a seed-derived keypair is still a generated keypair, so
    # every derivation ran a pairwise consistency test — one per call.
    assert pct_recorder == [f"SLH-DSA-{param_set}"] * (2 * len(keys))


@pytest.mark.parametrize("param_set", sorted(_PARAM_SETS))
def test_the_pair_signs_and_verifies(param_set: str) -> None:
    """(iii) through the shipped bindings, with the real PCT left in place."""
    n, _ = _PARAM_SETS[param_set]
    _, sk = _nist_secret_keys(param_set)[0]
    pair = pb.generate_slhdsa_keypair_from_seed(*_seeds(sk, n), param_set=param_set)
    message, ctx = b"SLH-DSA seeded keypair round trip", b"seeded"
    signature = pb.slhdsa_sign(message, pair.secret_key, ctx, param_set=param_set)
    assert pb.slhdsa_verify(message, signature, pair.public_key, ctx, param_set=param_set)
    # The pk the binding returned is the one NIST's sk embeds, so a signature
    # under it also verifies against the key NIST published.
    assert pb.slhdsa_verify(message, signature, sk[-2 * n :], ctx, param_set=param_set)
    assert not pb.slhdsa_verify(
        b"other message", signature, pair.public_key, ctx, param_set=param_set
    )
    assert not pb.slhdsa_verify(message, signature, pair.public_key, b"", param_set=param_set)


@pytest.mark.parametrize("param_set", sorted(_PARAM_SETS))
@pytest.mark.parametrize("label", ["sk_seed", "sk_prf", "pk_seed"])
@pytest.mark.parametrize("delta", [-1, +1, -16])
def test_a_wrong_length_seed_is_refused(
    param_set: str, label: str, delta: int, pct_recorder: list[str]
) -> None:
    """(iv) each seed must be exactly n bytes; the error names the offender."""
    n, _ = _PARAM_SETS[param_set]
    seeds = {"sk_seed": b"\x11" * n, "sk_prf": b"\x22" * n, "pk_seed": b"\x33" * n}
    seeds[label] = b"\x44" * max(n + delta, 0)
    with pytest.raises(ValueError, match=rf"{label} must be {n} bytes"):
        pb.generate_slhdsa_keypair_from_seed(
            seeds["sk_seed"], seeds["sk_prf"], seeds["pk_seed"], param_set=param_set
        )
    assert pct_recorder == [], "a refused seed must not reach the native keygen"


def test_an_unsupported_parameter_set_is_refused(pct_recorder: list[str]) -> None:
    with pytest.raises(ValueError, match="Unsupported SLH-DSA parameter set"):
        pb.generate_slhdsa_keypair_from_seed(b"\x00" * 16, b"\x00" * 16, b"\x00" * 16, "SHAKE-256s")
    assert pct_recorder == []
