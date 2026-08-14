#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Pins for the per-config signing-keypair normalization in ``crypto_api``.

HYBRID_SIG and ED25519 secret keys embed the Ed25519 secret as its 32-byte
seed, and ``Ed25519Provider.sign`` expands a seed to the 64-byte native form
on every call.  That expansion is a key *generation*
(``native_ed25519_keypair_from_seed``), so each signature also re-ran the
INVARIANT-41 pairwise consistency test — ~0.2 ms per package on the agent
flow ``signing_keypair`` exists for, with no security payoff after the first
call.  ``_normalized_signing_secret`` now expands once per supplied keypair,
memoized on the config object the caller already owns.

The normalization also closed a validation gap these tests pin from both
directions: a ``signing_keypair`` whose Ed25519 public-key component does not
correspond to its seed used to produce packages whose signatures could never
verify (discovered only downstream, or never); it now raises ``ValueError``
at create time.
"""

from __future__ import annotations

import pytest

from ama_cryptography.crypto_api import (
    AlgorithmType,
    CryptoPackageConfig,
    HybridSignatureProvider,
    KeypairCache,
    create_crypto_package,
    verify_crypto_package,
)
from ama_cryptography.pqc_backends import DILITHIUM_AVAILABLE

pytestmark = pytest.mark.skipif(
    not DILITHIUM_AVAILABLE, reason="hybrid signatures require the native ML-DSA-65 backend"
)

CONTENT = b"normalization pin content"


@pytest.fixture(scope="module")
def hybrid_identity() -> tuple[bytes, bytes]:
    pk, sk = KeypairCache().get_or_generate()
    return pk, sk


class TestNormalizedSigning:
    def test_packages_verify_end_to_end(self, hybrid_identity: tuple[bytes, bytes]) -> None:
        pk, sk = hybrid_identity
        config = CryptoPackageConfig(signing_keypair=(pk, sk))
        package = create_crypto_package(CONTENT, config)
        result = verify_crypto_package(CONTENT, package, expected_public_key=pk)
        assert result["all_valid"], result

    def test_memo_written_once_and_reused(self, hybrid_identity: tuple[bytes, bytes]) -> None:
        pk, sk = hybrid_identity
        config = CryptoPackageConfig(signing_keypair=(pk, sk))
        assert config._normalized_signing_memo is None
        create_crypto_package(CONTENT, config)
        memo = config._normalized_signing_memo
        assert memo is not None
        assert memo[0] is config.signing_keypair
        # The normalized secret embeds the 64-byte expanded Ed25519 key.
        assert len(memo[1]) == (
            HybridSignatureProvider.ED25519_FULL_SK_SIZE + HybridSignatureProvider.DILITHIUM_SK_SIZE
        )
        create_crypto_package(CONTENT, config)
        assert config._normalized_signing_memo is memo, "second call must reuse the memo"

    def test_replacing_the_keypair_renormalizes(self, hybrid_identity: tuple[bytes, bytes]) -> None:
        pk, sk = hybrid_identity
        config = CryptoPackageConfig(signing_keypair=(pk, sk))
        create_crypto_package(CONTENT, config)
        first_memo = config._normalized_signing_memo

        pk2, sk2 = KeypairCache().get_or_generate()
        config.signing_keypair = (pk2, sk2)
        package = create_crypto_package(CONTENT, config)
        assert config._normalized_signing_memo is not first_memo
        assert verify_crypto_package(CONTENT, package, expected_public_key=pk2)["all_valid"]

    def test_result_keypair_keeps_the_callers_format(
        self, hybrid_identity: tuple[bytes, bytes]
    ) -> None:
        """The stored KeyPair must expose the key the caller supplied, not the
        normalized internal form — emitting a 4,096-byte secret where the
        caller supplied 4,064 bytes would be an observable format change."""
        pk, sk = hybrid_identity
        config = CryptoPackageConfig(signing_keypair=(pk, sk))
        package = create_crypto_package(CONTENT, config)
        stored = package.keypairs[AlgorithmType.HYBRID_SIG.name]
        assert stored.secret_key == sk
        assert stored.public_key == pk


class TestMismatchRejection:
    def test_mismatched_hybrid_public_key_raises(
        self, hybrid_identity: tuple[bytes, bytes]
    ) -> None:
        _, sk = hybrid_identity
        other_pk, _ = KeypairCache().get_or_generate()
        config = CryptoPackageConfig(signing_keypair=(other_pk, sk))
        with pytest.raises(ValueError, match="signing_keypair mismatch"):
            create_crypto_package(CONTENT, config)

    def test_mismatched_ed25519_public_key_raises(self) -> None:
        from ama_cryptography.pqc_backends import native_ed25519_keypair

        _pk_a, sk_a = native_ed25519_keypair()
        pk_b, _ = native_ed25519_keypair()
        config = CryptoPackageConfig(
            signature_algorithm=AlgorithmType.ED25519,
            signing_keypair=(pk_b, sk_a[:32]),
        )
        with pytest.raises(ValueError, match="signing_keypair mismatch"):
            create_crypto_package(CONTENT, config)


class TestHybridSplitDiscrimination:
    """4,064- and 4,096-byte hybrid secrets must both sign identically."""

    def test_seed_and_expanded_forms_agree(self, hybrid_identity: tuple[bytes, bytes]) -> None:
        from ama_cryptography.pqc_backends import native_ed25519_keypair_from_seed

        pk, sk = hybrid_identity
        seed_form = sk
        assert len(seed_form) == (
            HybridSignatureProvider.ED25519_SK_SIZE + HybridSignatureProvider.DILITHIUM_SK_SIZE
        )
        _, full_sk = native_ed25519_keypair_from_seed(
            seed_form[: HybridSignatureProvider.ED25519_SK_SIZE]
        )
        expanded_form = full_sk + seed_form[HybridSignatureProvider.ED25519_SK_SIZE :]

        provider = HybridSignatureProvider()
        message = b"split discrimination"
        sig_seed = provider.sign(message, seed_form)
        sig_expanded = provider.sign(message, expanded_form)
        # Ed25519 and deterministic ML-DSA-65 both sign deterministically, so
        # the two forms must produce byte-identical combined signatures.
        assert sig_seed.signature == sig_expanded.signature
        assert provider.verify(message, sig_expanded.signature, pk)
