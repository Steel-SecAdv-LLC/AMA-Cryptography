# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The fuzz_nistp verifying seeds must verify under the harness's own layout.

``fuzz/fuzz_nistp.c`` asserts its verify properties only on inputs the
verifier ACCEPTS, and random bytes are never a valid ECDSA signature, so the
three ``*_verifying_triple`` seeds are what put case 3 on its property path at
all.  The builder that wrote them was deleted, which left nothing to notice a
seed that stopped verifying -- or a layout change in the harness that the
seeds were not regenerated for.

Case 3 reads ``curve (1) || selector (1) || digest (32) || public key ||
DER signature``.  Until 2026-09-24 it read the digest from the first 32 bytes
of the public key, so the two were never independent and every verifying seed
signed its own key's x coordinate; the seeds were regenerated with the layout.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import ama_cryptography.pqc_backends as pb

SEEDS = Path(__file__).resolve().parent.parent / "fuzz" / "seed_corpus" / "fuzz_nistp"
CURVES = ("P-256", "P-384", "P-521")

pytestmark = pytest.mark.skipif(
    not getattr(pb, "_NISTP_NATIVE_AVAILABLE", True),
    reason="native NIST P-curve backend not available",
)


def _split(curve: str) -> tuple[bytes, bytes, bytes, bytes]:
    """``(header, digest, public key, DER signature)`` exactly as case 3 reads them."""
    data = (SEEDS / f"{curve}_verifying_triple").read_bytes()
    pub_len = 2 * pb.nistp_field_bytes(curve)
    header, payload = data[:2], data[2:]
    return header, payload[:32], payload[32 : 32 + pub_len], payload[32 + pub_len :]


@pytest.mark.parametrize("index,curve", list(enumerate(CURVES)))
def test_the_seed_selects_case_3_on_its_curve(index: int, curve: str) -> None:
    header, _digest, _pub, _sig = _split(curve)
    assert header[0] % 3 == index, "pick_curve would read another curve"
    assert header[1] % 6 == 3, "the selector would not reach case 3"


@pytest.mark.parametrize("curve", CURVES)
def test_the_seed_verifies_with_an_independent_digest(curve: str) -> None:
    _header, digest, pub, sig = _split(curve)
    assert digest != pub[:32], "the digest is the key's own bytes again"
    assert pb.native_nistp_ecdsa_verify(curve, sig, digest, pub)
    # Property 2 on this seed: the raw form of an accepted DER signature verifies.
    raw = pb.native_nistp_sig_der_to_raw(curve, sig)
    assert pb.native_nistp_ecdsa_verify(curve, raw, digest, pub, raw=True)
