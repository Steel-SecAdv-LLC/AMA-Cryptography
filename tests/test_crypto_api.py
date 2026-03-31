#!/usr/bin/env python3
"""
AMA Cryptography - Cryptographic API Tests

Comprehensive test suite for crypto_api.py providing coverage
of all cryptographic providers including Ed25519, ML-DSA-65,
Kyber-1024, SPHINCS+-256f, and hybrid signature schemes.

AI Co-Architects: Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛

Copyright 2025-2026 Steel Security Advisors LLC
Licensed under the Apache License, Version 2.0
"""

from unittest.mock import patch

import pytest

from ama_cryptography.crypto_api import (
    DILITHIUM_AVAILABLE,
    KYBER_AVAILABLE,
    SPHINCS_AVAILABLE,
    AlgorithmType,
    AmaCryptography,
    CryptoBackend,
    CryptoProvider,
    Ed25519Provider,
    EncapsulatedSecret,
    HybridSignatureProvider,
    KEMProvider,
    KeyPair,
    KyberProvider,
    KyberUnavailableError,
    MLDSAProvider,
    Signature,
    SphincsProvider,
    SphincsUnavailableError,
    get_pqc_capabilities,
    quick_hash,
    quick_kem,
    quick_sign,
    quick_verify,
)


class TestAlgorithmType:
    """Test AlgorithmType enum."""

    def test_ed25519_exists(self) -> None:
        """Verify ED25519 algorithm type exists."""
        assert hasattr(AlgorithmType, "ED25519")

    def test_ml_dsa_65_exists(self) -> None:
        """Verify ML_DSA_65 algorithm type exists."""
        assert hasattr(AlgorithmType, "ML_DSA_65")

    def test_kyber_1024_exists(self) -> None:
        """Verify KYBER_1024 algorithm type exists."""
        assert hasattr(AlgorithmType, "KYBER_1024")

    def test_sphincs_256f_exists(self) -> None:
        """Verify SPHINCS_256F algorithm type exists."""
        assert hasattr(AlgorithmType, "SPHINCS_256F")

    def test_hybrid_sig_exists(self) -> None:
        """Verify HYBRID_SIG algorithm type exists."""
        assert hasattr(AlgorithmType, "HYBRID_SIG")


class TestCryptoBackend:
    """Test CryptoBackend enum."""

    def test_pure_python_exists(self) -> None:
        """Verify PURE_PYTHON backend exists."""
        assert hasattr(CryptoBackend, "PURE_PYTHON")

    def test_c_library_exists(self) -> None:
        """Verify C_LIBRARY backend exists."""
        assert hasattr(CryptoBackend, "C_LIBRARY")


class TestKeyPairDataclass:
    """Test KeyPair dataclass."""

    def test_keypair_fields(self) -> None:
        """Verify KeyPair has required fields."""
        assert hasattr(KeyPair, "__dataclass_fields__")
        fields = KeyPair.__dataclass_fields__
        assert "public_key" in fields
        assert "secret_key" in fields
        assert "algorithm" in fields
        assert "metadata" in fields

    def test_keypair_creation(self) -> None:
        """Verify KeyPair can be created."""
        kp = KeyPair(
            public_key=b"test_public",
            secret_key=b"test_secret",
            algorithm=AlgorithmType.ED25519,
            metadata={},
        )
        assert kp.public_key == b"test_public"
        assert kp.secret_key == b"test_secret"
        assert kp.algorithm == AlgorithmType.ED25519


class TestSignatureDataclass:
    """Test Signature dataclass."""

    def test_signature_fields(self) -> None:
        """Verify Signature has required fields."""
        assert hasattr(Signature, "__dataclass_fields__")
        fields = Signature.__dataclass_fields__
        assert "signature" in fields
        assert "algorithm" in fields
        assert "message_hash" in fields
        assert "metadata" in fields

    def test_signature_creation(self) -> None:
        """Verify Signature can be created."""
        sig = Signature(
            signature=b"test_sig",
            algorithm=AlgorithmType.ED25519,
            message_hash=b"test_hash",
            metadata={},
        )
        assert sig.signature == b"test_sig"
        assert sig.algorithm == AlgorithmType.ED25519
        assert sig.message_hash == b"test_hash"


class TestEncapsulatedSecretDataclass:
    """Test EncapsulatedSecret dataclass."""

    def test_encapsulated_secret_fields(self) -> None:
        """Verify EncapsulatedSecret has required fields."""
        assert hasattr(EncapsulatedSecret, "__dataclass_fields__")
        fields = EncapsulatedSecret.__dataclass_fields__
        assert "ciphertext" in fields
        assert "shared_secret" in fields
        assert "algorithm" in fields
        assert "metadata" in fields

    def test_encapsulated_secret_creation(self) -> None:
        """Verify EncapsulatedSecret can be created."""
        es = EncapsulatedSecret(
            ciphertext=b"test_ct",
            shared_secret=b"test_ss",
            algorithm=AlgorithmType.KYBER_1024,
            metadata={},
        )
        assert es.ciphertext == b"test_ct"
        assert es.shared_secret == b"test_ss"
        assert es.algorithm == AlgorithmType.KYBER_1024


class TestEd25519Provider:
    """Test Ed25519Provider."""

    def test_provider_instantiation(self) -> None:
        """Verify Ed25519Provider can be instantiated."""
        provider = Ed25519Provider()
        assert provider is not None
        assert provider.algorithm == AlgorithmType.ED25519

    def test_generate_keypair(self) -> None:
        """Verify keypair generation works."""
        provider = Ed25519Provider()
        keypair = provider.generate_keypair()
        assert isinstance(keypair, KeyPair)
        assert len(keypair.public_key) == 32
        assert len(keypair.secret_key) == 32
        assert keypair.algorithm == AlgorithmType.ED25519

    def test_sign_and_verify(self) -> None:
        """Verify signing and verification works."""
        provider = Ed25519Provider()
        keypair = provider.generate_keypair()
        message = b"Test message for Ed25519"

        signature = provider.sign(message, keypair.secret_key)
        assert isinstance(signature, Signature)
        assert signature.algorithm == AlgorithmType.ED25519

        is_valid = provider.verify(message, signature.signature, keypair.public_key)
        assert is_valid is True

    def test_verify_rejects_tampered_message(self) -> None:
        """Verify tampered messages are rejected."""
        provider = Ed25519Provider()
        keypair = provider.generate_keypair()
        message = b"Original message"

        signature = provider.sign(message, keypair.secret_key)
        tampered = b"Tampered message"

        is_valid = provider.verify(tampered, signature.signature, keypair.public_key)
        assert is_valid is False

    def test_keypairs_are_unique(self) -> None:
        """Verify each keypair generation produces unique keys."""
        provider = Ed25519Provider()
        kp1 = provider.generate_keypair()
        kp2 = provider.generate_keypair()
        assert kp1.public_key != kp2.public_key
        assert kp1.secret_key != kp2.secret_key


@pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium backend not available")
class TestMLDSAProvider:
    """Test MLDSAProvider (ML-DSA-65/Dilithium)."""

    def test_provider_instantiation(self) -> None:
        """Verify MLDSAProvider can be instantiated."""
        provider = MLDSAProvider()
        assert provider is not None
        assert provider.algorithm == AlgorithmType.ML_DSA_65

    def test_generate_keypair(self) -> None:
        """Verify keypair generation works."""
        provider = MLDSAProvider()
        keypair = provider.generate_keypair()
        assert isinstance(keypair, KeyPair)
        assert len(keypair.public_key) == 1952
        assert len(keypair.secret_key) == 4032
        assert keypair.algorithm == AlgorithmType.ML_DSA_65

    def test_sign_and_verify(self) -> None:
        """Verify signing and verification works."""
        provider = MLDSAProvider()
        keypair = provider.generate_keypair()
        message = b"Test message for ML-DSA-65"

        signature = provider.sign(message, keypair.secret_key)
        assert isinstance(signature, Signature)
        assert signature.algorithm == AlgorithmType.ML_DSA_65

        is_valid = provider.verify(message, signature.signature, keypair.public_key)
        assert is_valid is True

    def test_verify_rejects_tampered_message(self) -> None:
        """Verify tampered messages are rejected."""
        provider = MLDSAProvider()
        keypair = provider.generate_keypair()
        message = b"Original message"

        signature = provider.sign(message, keypair.secret_key)
        tampered = b"Tampered message"

        is_valid = provider.verify(tampered, signature.signature, keypair.public_key)
        assert is_valid is False


@pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber backend not available")
class TestKyberProvider:
    """Test KyberProvider (Kyber-1024/ML-KEM)."""

    def test_provider_instantiation(self) -> None:
        """Verify KyberProvider can be instantiated."""
        provider = KyberProvider()
        assert provider is not None
        assert provider.algorithm == AlgorithmType.KYBER_1024

    def test_generate_keypair(self) -> None:
        """Verify keypair generation works."""
        provider = KyberProvider()
        keypair = provider.generate_keypair()
        assert isinstance(keypair, KeyPair)
        assert len(keypair.public_key) == 1568
        assert len(keypair.secret_key) == 3168
        assert keypair.algorithm == AlgorithmType.KYBER_1024

    def test_encapsulate_and_decapsulate(self) -> None:
        """Verify encapsulation and decapsulation works."""
        provider = KyberProvider()
        keypair = provider.generate_keypair()

        encapsulated = provider.encapsulate(keypair.public_key)
        assert isinstance(encapsulated, EncapsulatedSecret)
        assert len(encapsulated.ciphertext) == 1568
        assert len(encapsulated.shared_secret) == 32

        decapsulated = provider.decapsulate(encapsulated.ciphertext, keypair.secret_key)
        assert decapsulated == encapsulated.shared_secret

    def test_different_encapsulations_produce_different_secrets(self) -> None:
        """Verify each encapsulation produces unique shared secrets."""
        provider = KyberProvider()
        keypair = provider.generate_keypair()

        encap1 = provider.encapsulate(keypair.public_key)
        encap2 = provider.encapsulate(keypair.public_key)

        assert encap1.shared_secret != encap2.shared_secret
        assert encap1.ciphertext != encap2.ciphertext


@pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber backend not available")
def test_kyber_provider_not_placeholder() -> None:
    """Verify KyberProvider is not a placeholder."""
    provider = KyberProvider()
    # KyberProvider should be functional, not a stub
    keypair = provider.generate_keypair()
    assert keypair is not None


@pytest.mark.skipif(not SPHINCS_AVAILABLE, reason="SPHINCS+ backend not available")
class TestSphincsProvider:
    """Test SphincsProvider (SPHINCS+-SHA2-256f-simple)."""

    def test_provider_instantiation(self) -> None:
        """Verify SphincsProvider can be instantiated."""
        provider = SphincsProvider()
        assert provider is not None
        assert provider.algorithm == AlgorithmType.SPHINCS_256F

    def test_generate_keypair(self) -> None:
        """Verify keypair generation works."""
        provider = SphincsProvider()
        keypair = provider.generate_keypair()
        assert isinstance(keypair, KeyPair)
        assert len(keypair.public_key) == 64
        assert len(keypair.secret_key) == 128
        assert keypair.algorithm == AlgorithmType.SPHINCS_256F

    def test_sign_and_verify(self) -> None:
        """Verify signing and verification works."""
        provider = SphincsProvider()
        keypair = provider.generate_keypair()
        message = b"Test message for SPHINCS+"

        signature = provider.sign(message, keypair.secret_key)
        assert isinstance(signature, Signature)
        assert signature.algorithm == AlgorithmType.SPHINCS_256F
        assert len(signature.signature) == 49856

        is_valid = provider.verify(message, signature.signature, keypair.public_key)
        assert is_valid is True

    def test_verify_rejects_tampered_message(self) -> None:
        """Verify tampered messages are rejected."""
        provider = SphincsProvider()
        keypair = provider.generate_keypair()
        message = b"Original message"

        signature = provider.sign(message, keypair.secret_key)
        tampered = b"Tampered message"

        is_valid = provider.verify(tampered, signature.signature, keypair.public_key)
        assert is_valid is False


@pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium backend not available")
class TestHybridSignatureProvider:
    """Test HybridSignatureProvider (Ed25519 + ML-DSA-65)."""

    def test_provider_instantiation(self) -> None:
        """Verify HybridSignatureProvider can be instantiated."""
        provider = HybridSignatureProvider()
        assert provider is not None
        assert provider.algorithm == AlgorithmType.HYBRID_SIG

    def test_generate_keypair(self) -> None:
        """Verify hybrid keypair generation works."""
        provider = HybridSignatureProvider()
        keypair = provider.generate_keypair()
        assert isinstance(keypair, KeyPair)
        assert keypair.algorithm == AlgorithmType.HYBRID_SIG

    def test_sign_and_verify(self) -> None:
        """Verify hybrid signing and verification works."""
        provider = HybridSignatureProvider()
        keypair = provider.generate_keypair()
        message = b"Test message for hybrid signature"

        signature = provider.sign(message, keypair.secret_key)
        assert isinstance(signature, Signature)
        assert signature.algorithm == AlgorithmType.HYBRID_SIG

        is_valid = provider.verify(message, signature.signature, keypair.public_key)
        assert is_valid is True

    def test_verify_rejects_tampered_message(self) -> None:
        """Verify tampered messages are rejected."""
        provider = HybridSignatureProvider()
        keypair = provider.generate_keypair()
        message = b"Original message"

        signature = provider.sign(message, keypair.secret_key)
        tampered = b"Tampered message"

        is_valid = provider.verify(tampered, signature.signature, keypair.public_key)
        assert is_valid is False


class TestAmaCryptography:
    """Test AmaCryptography main interface."""

    def test_instantiation(self) -> None:
        """Verify AmaCryptography can be instantiated."""
        crypto = AmaCryptography()
        assert crypto is not None

    def test_ed25519_sign_and_verify(self) -> None:
        """Verify Ed25519 signing and verification via AmaCryptography."""
        crypto = AmaCryptography(algorithm=AlgorithmType.ED25519)
        keypair = crypto.generate_keypair()
        message = b"Test message"
        signature = crypto.sign(message, keypair.secret_key)
        is_valid = crypto.verify(message, signature.signature, keypair.public_key)
        assert is_valid is True

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium not available")
    def test_ml_dsa_sign_and_verify(self) -> None:
        """Verify ML-DSA-65 signing and verification via AmaCryptography."""
        crypto = AmaCryptography(algorithm=AlgorithmType.ML_DSA_65)
        keypair = crypto.generate_keypair()
        message = b"Test message"
        signature = crypto.sign(message, keypair.secret_key)
        is_valid = crypto.verify(message, signature.signature, keypair.public_key)
        assert is_valid is True

    @pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber not available")
    def test_kyber_encapsulate_and_decapsulate(self) -> None:
        """Verify Kyber-1024 KEM via AmaCryptography."""
        crypto = AmaCryptography(algorithm=AlgorithmType.KYBER_1024)
        keypair = crypto.generate_keypair()
        encapsulated = crypto.encapsulate(keypair.public_key)
        shared_secret = crypto.decapsulate(encapsulated.ciphertext, keypair.secret_key)
        assert shared_secret == encapsulated.shared_secret

    @pytest.mark.skipif(not SPHINCS_AVAILABLE, reason="SPHINCS+ not available")
    def test_sphincs_sign_and_verify(self) -> None:
        """Verify SPHINCS+-256f signing and verification via AmaCryptography."""
        crypto = AmaCryptography(algorithm=AlgorithmType.SPHINCS_256F)
        keypair = crypto.generate_keypair()
        message = b"Test message"
        signature = crypto.sign(message, keypair.secret_key)
        is_valid = crypto.verify(message, signature.signature, keypair.public_key)
        assert is_valid is True


class TestQuickHash:
    """Test quick_hash convenience function including FIPS 140-3 gate."""

    def test_sha3_256_default(self) -> None:
        """Verify quick_hash defaults to SHA3-256 and returns 32 bytes."""
        import hashlib

        message = b"Hello from AI agent"
        result = quick_hash(message)
        expected = hashlib.sha3_256(message).digest()
        assert result == expected
        assert len(result) == 32

    def test_sha3_512(self) -> None:
        """Verify quick_hash supports SHA3-512 (64-byte digest)."""
        import hashlib

        message = b"SHA3-512 test"
        result = quick_hash(message, algorithm="sha3-512")
        expected = hashlib.sha3_512(message).digest()
        assert result == expected
        assert len(result) == 64

    def test_shake256(self) -> None:
        """Verify quick_hash supports SHAKE256 (32-byte digest)."""
        import hashlib

        message = b"SHAKE256 test"
        result = quick_hash(message, algorithm="shake256")
        expected = hashlib.shake_256(message).digest(32)
        assert result == expected
        assert len(result) == 32

    def test_unsupported_algorithm_raises(self) -> None:
        """Verify quick_hash raises ValueError for unsupported algorithm."""
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            quick_hash(b"test", algorithm="md5")

    def test_empty_message(self) -> None:
        """Verify quick_hash handles empty input."""
        import hashlib

        result = quick_hash(b"")
        expected = hashlib.sha3_256(b"").digest()
        assert result == expected

    def test_fips_gate_blocks_in_error_state(self) -> None:
        """Verify quick_hash raises CryptoModuleError in ERROR state.

        This proves the _check_operational() gate is enforced,
        consistent with quick_sign / quick_verify / quick_kem.
        """
        from ama_cryptography._self_test import (
            _set_error,
            _set_operational,
        )
        from ama_cryptography.exceptions import CryptoModuleError

        try:
            _set_error("FIPS gate test")
            with pytest.raises(CryptoModuleError, match="FIPS gate test"):
                quick_hash(b"should not hash")
        finally:
            _set_operational()

    def test_fips_gate_allows_in_operational_state(self) -> None:
        """Verify quick_hash succeeds when module is OPERATIONAL."""
        from ama_cryptography._self_test import module_status

        assert module_status() == "OPERATIONAL"
        result = quick_hash(b"operational test")
        assert len(result) == 32


class TestQuickFunctions:
    """Test quick_sign, quick_verify, and quick_kem convenience functions."""

    def test_quick_sign_ed25519(self) -> None:
        """Verify quick_sign works with Ed25519."""
        message = b"Quick sign test"
        keypair, signature = quick_sign(message, algorithm=AlgorithmType.ED25519)
        assert isinstance(keypair, KeyPair)
        assert isinstance(signature, Signature)

    def test_quick_verify_ed25519(self) -> None:
        """Verify quick_verify works with Ed25519."""
        message = b"Quick verify test"
        keypair, signature = quick_sign(message, algorithm=AlgorithmType.ED25519)
        is_valid = quick_verify(
            message, signature.signature, keypair.public_key, AlgorithmType.ED25519
        )
        assert is_valid is True

    @pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber not available")
    def test_quick_kem(self) -> None:
        """Verify quick_kem works with Kyber-1024."""
        keypair, encapsulated = quick_kem(algorithm=AlgorithmType.KYBER_1024)
        assert isinstance(keypair, KeyPair)
        assert isinstance(encapsulated, EncapsulatedSecret)
        assert len(encapsulated.shared_secret) == 32


class TestGetPqcCapabilities:
    """Test get_pqc_capabilities function."""

    def test_returns_dict(self) -> None:
        """Verify get_pqc_capabilities returns a dictionary."""
        caps = get_pqc_capabilities()
        assert isinstance(caps, dict)

    def test_contains_dilithium_info(self) -> None:
        """Verify capabilities contains Dilithium information."""
        caps = get_pqc_capabilities()
        assert "dilithium_available" in caps or "ml_dsa_available" in caps

    def test_contains_kyber_info(self) -> None:
        """Verify capabilities contains Kyber information."""
        caps = get_pqc_capabilities()
        assert "kyber_available" in caps

    def test_contains_sphincs_info(self) -> None:
        """Verify capabilities contains SPHINCS+ information."""
        caps = get_pqc_capabilities()
        assert "sphincs_available" in caps


class TestUnavailableProviderErrors:
    """Test error handling when providers are unavailable."""

    def test_kyber_provider_raises_error(self) -> None:
        """Verify KyberProvider raises error when unavailable."""
        with patch("ama_cryptography.crypto_api.KYBER_AVAILABLE", False):
            with pytest.raises(KyberUnavailableError):
                KyberProvider()

    def test_sphincs_provider_raises_error(self) -> None:
        """Verify SphincsProvider raises error when unavailable."""
        with patch("ama_cryptography.crypto_api.SPHINCS_AVAILABLE", False):
            with pytest.raises(SphincsUnavailableError):
                SphincsProvider()


class TestProviderAbstractBase:
    """Test CryptoProvider abstract base class."""

    def test_crypto_provider_is_abstract(self) -> None:
        """Verify CryptoProvider cannot be instantiated directly."""
        with pytest.raises(TypeError):
            CryptoProvider()

    def test_kem_provider_is_abstract(self) -> None:
        """Verify KEMProvider cannot be instantiated directly."""
        with pytest.raises(TypeError):
            KEMProvider()


class TestEd25519NativeBackendConsistency:
    """
    Test Ed25519 native C backend consistency.

    Verifies that the native C backend produces deterministic, correct
    signatures and that multiple sign/verify cycles work consistently.
    """

    def test_sign_deterministic(self) -> None:
        """Verify signing is deterministic (same key + message = same signature)."""
        provider = Ed25519Provider()
        keypair = provider.generate_keypair()
        message = b"Test message for determinism check"

        sig1 = provider.sign(message, keypair.secret_key)
        sig2 = provider.sign(message, keypair.secret_key)

        # Ed25519 is deterministic - signatures must be identical
        assert sig1.signature == sig2.signature
        assert sig1.algorithm == sig2.algorithm

    def test_verify_valid_signature(self) -> None:
        """Verify valid signature returns True."""
        provider = Ed25519Provider()
        keypair = provider.generate_keypair()
        message = b"Test message for verification"

        signature = provider.sign(message, keypair.secret_key)
        valid = provider.verify(message, signature.signature, keypair.public_key)

        assert valid is True

    def test_verify_invalid_signature_rejected(self) -> None:
        """Verify invalid signatures are rejected."""
        provider = Ed25519Provider()
        keypair = provider.generate_keypair()
        message = b"Original message"
        tampered = b"Tampered message"

        signature = provider.sign(message, keypair.secret_key)
        is_valid = provider.verify(tampered, signature.signature, keypair.public_key)

        assert is_valid is False

    def test_sign_multiple_messages(self) -> None:
        """Verify signing multiple messages with same key works correctly."""
        provider = Ed25519Provider()
        keypair = provider.generate_keypair()

        messages = [
            b"Message 1",
            b"Message 2",
            b"Message 3",
            b"A longer message for testing",
            b"",  # Empty message
        ]

        for msg in messages:
            sig = provider.sign(msg, keypair.secret_key)
            is_valid = provider.verify(msg, sig.signature, keypair.public_key)
            assert is_valid is True, f"Failed for message: {msg!r}"


# ---------------------------------------------------------------------------
# Signature object coercion — verify() accepts both bytes and Signature
# ---------------------------------------------------------------------------


class TestSignatureCoercion:
    """verify() must accept a Signature object (from sign()) as well as raw bytes."""

    def test_ed25519_verify_accepts_signature_object(self) -> None:
        ed = Ed25519Provider()
        kp = ed.generate_keypair()
        sig = ed.sign(b"coercion test", kp.secret_key)
        assert isinstance(sig, Signature)
        assert ed.verify(b"coercion test", sig, kp.public_key) is True

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="ML-DSA-65 not available")
    def test_mldsa_verify_accepts_signature_object(self) -> None:
        mldsa = MLDSAProvider()
        kp = mldsa.generate_keypair()
        sig = mldsa.sign(b"coercion test", kp.secret_key)
        assert isinstance(sig, Signature)
        assert mldsa.verify(b"coercion test", sig, kp.public_key) is True

    @pytest.mark.skipif(not SPHINCS_AVAILABLE, reason="SPHINCS+ not available")
    def test_sphincs_verify_accepts_signature_object(self) -> None:
        sp = SphincsProvider()
        kp = sp.generate_keypair()
        sig = sp.sign(b"coercion test", kp.secret_key)
        assert isinstance(sig, Signature)
        assert sp.verify(b"coercion test", sig, kp.public_key) is True

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="ML-DSA-65 not available")
    def test_hybrid_verify_accepts_signature_object(self) -> None:
        hybrid = HybridSignatureProvider()
        kp = hybrid.generate_keypair()
        sig = hybrid.sign(b"coercion test", kp.secret_key)
        assert isinstance(sig, Signature)
        assert hybrid.verify(b"coercion test", sig, kp.public_key) is True
