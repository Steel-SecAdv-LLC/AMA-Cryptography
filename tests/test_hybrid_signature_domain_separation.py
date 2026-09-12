# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Hybrid (Ed25519 + ML-DSA-65) signatures are domain-separated (format v2).

A component signature must not be transferable between the hybrid scheme and
the standalone schemes under key reuse: the Ed25519 half of a hybrid signature
is not a valid Ed25519 signature over the raw message, a standalone Ed25519 or
ML-DSA-65 signature over the raw message cannot be spliced into a hybrid
signature, and the domain string that makes this so is pinned as part of the
signature format.
"""

from __future__ import annotations

import pytest

from ama_cryptography import crypto_api
from ama_cryptography.crypto_api import (
    HYBRID_SIG_DOMAIN,
    HybridSignatureProvider,
    KeyPair,
    hybrid_classical_input,
)
from ama_cryptography.pqc_backends import (
    DILITHIUM_AVAILABLE,
    dilithium_sign,
    dilithium_verify,
    native_ed25519_keypair_from_seed,
    native_ed25519_sign,
    native_ed25519_verify,
)

pytestmark = pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="ML-DSA-65 backend unavailable")

MESSAGE = b"hybrid domain separation: the message every component sees"

ED_PK = HybridSignatureProvider.ED25519_PK_SIZE
ED_SIG = HybridSignatureProvider.ED25519_SIG_SIZE
ED_SK = HybridSignatureProvider.ED25519_SK_SIZE


@pytest.fixture(scope="module")
def provider() -> HybridSignatureProvider:
    return HybridSignatureProvider()


@pytest.fixture(scope="module")
def keys(provider: HybridSignatureProvider) -> KeyPair:
    return provider.generate_keypair()


def test_domain_string_and_wrapper_are_pinned() -> None:
    assert HYBRID_SIG_DOMAIN == b"AMA-Cryptography/hybrid-sig/v2/Ed25519+ML-DSA-65"
    assert len(HYBRID_SIG_DOMAIN) <= 255  # FIPS 204 ctx length bound
    assert hybrid_classical_input(b"m") == (
        b"\x00" + bytes([len(HYBRID_SIG_DOMAIN)]) + HYBRID_SIG_DOMAIN + b"m"
    )


def test_round_trip_parallel_and_sequential_agree(
    provider: HybridSignatureProvider, keys: KeyPair
) -> None:
    sig = provider.sign(MESSAGE, keys.secret_key)
    assert sig.metadata["domain"] == HYBRID_SIG_DOMAIN.decode("ascii")
    assert provider.verify(MESSAGE, sig.signature, keys.public_key, parallel=True)
    assert provider.verify(MESSAGE, sig.signature, keys.public_key, parallel=False)
    assert not provider.verify(MESSAGE + b"x", sig.signature, keys.public_key)


def test_hybrid_ed25519_half_is_not_a_standalone_signature(
    provider: HybridSignatureProvider, keys: KeyPair
) -> None:
    sig = provider.sign(MESSAGE, keys.secret_key).signature
    ed_half, ed_pk = sig[:ED_SIG], keys.public_key[:ED_PK]
    assert not native_ed25519_verify(ed_half, MESSAGE, ed_pk)
    # It is a valid Ed25519 signature over the domain-bound input only.
    assert native_ed25519_verify(ed_half, hybrid_classical_input(MESSAGE), ed_pk)


def test_standalone_ed25519_signature_cannot_be_spliced_in(
    provider: HybridSignatureProvider, keys: KeyPair
) -> None:
    sig = provider.sign(MESSAGE, keys.secret_key).signature
    _, full_sk = native_ed25519_keypair_from_seed(bytes(keys.secret_key[:ED_SK]))
    standalone = native_ed25519_sign(MESSAGE, full_sk)
    assert native_ed25519_verify(standalone, MESSAGE, keys.public_key[:ED_PK])
    spliced = standalone + sig[ED_SIG:]
    assert not provider.verify(MESSAGE, spliced, keys.public_key, parallel=False)


def test_hybrid_ml_dsa_half_is_not_a_standalone_signature(
    provider: HybridSignatureProvider, keys: KeyPair
) -> None:
    sig = provider.sign(MESSAGE, keys.secret_key).signature
    pqc_half, pqc_pk = sig[ED_SIG:], keys.public_key[ED_PK:]
    assert not dilithium_verify(MESSAGE, pqc_half, pqc_pk)


def test_standalone_ml_dsa_signature_cannot_be_spliced_in(
    provider: HybridSignatureProvider, keys: KeyPair
) -> None:
    sig = provider.sign(MESSAGE, keys.secret_key).signature
    pqc_sk = keys.secret_key[ED_SK:]
    standalone = dilithium_sign(MESSAGE, pqc_sk)
    assert dilithium_verify(MESSAGE, standalone, keys.public_key[ED_PK:])
    spliced = sig[:ED_SIG] + standalone
    assert not provider.verify(MESSAGE, spliced, keys.public_key, parallel=False)


def test_v1_format_signature_does_not_verify_under_v2(
    provider: HybridSignatureProvider, keys: KeyPair
) -> None:
    """A v1 hybrid signature was exactly the two standalone signatures over
    the raw message, concatenated."""
    _, full_sk = native_ed25519_keypair_from_seed(bytes(keys.secret_key[:ED_SK]))
    v1 = native_ed25519_sign(MESSAGE, full_sk) + dilithium_sign(MESSAGE, keys.secret_key[ED_SK:])
    assert not provider.verify(MESSAGE, v1, keys.public_key, parallel=False)


def test_public_api_exports_the_domain() -> None:
    assert crypto_api.HYBRID_SIG_DOMAIN is HYBRID_SIG_DOMAIN
