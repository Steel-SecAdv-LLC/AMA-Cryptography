#!/usr/bin/env python3
"""
AMA Cryptography - Cryptographic API Tests

Comprehensive test suite for crypto_api.py providing coverage
of all cryptographic providers including Ed25519, ML-DSA-65,
Kyber-1024, SPHINCS+-256f, and hybrid signature schemes.

AI Co-Architects: Eris ⯰ | Eden | Veritas 💠 | X ⚛ | Caduceus ⚚ | Dev ⚕

Copyright 2025 Steel Security Advisors LLC
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
    quick_kem,
    quick_sign,
    quick_verify,
)


class TestAlgorithmType:
    """Test AlgorithmType enum."""

    def test_ed25519_exists(self):
        """Verify ED25519 algorithm type exists."""
        assert hasattr(AlgorithmType, "ED25519")

    def test_ml_dsa_65_exists(self):
        """Verify ML_DSA_65 algorithm type exists."""
        assert hasattr(AlgorithmType, "ML_DSA_65")

    def test_kyber_1024_exists(self):
        """Verify KYBER_1024 algorithm type exists."""
        assert hasattr(AlgorithmType, "KYBER_1024")

    def test_sphincs_256f_exists(self):
        """Verify SPHINCS_256F algorithm type exists."""
        assert hasattr(AlgorithmType, "SPHINCS_256F")

    def test_hybrid_sig_exists(self):
        """Verify HYBRID_SIG algorithm type exists."""
        assert hasattr(AlgorithmType, "HYBRID_SIG")


class TestCryptoBackend:
    """Test CryptoBackend enum."""

    def test_pure_python_exists(self):
        """Verify PURE_PYTHON backend exists."""
        assert hasattr(CryptoBackend, "PURE_PYTHON")

    def test_c_library_exists(self):
        """Verify C_LIBRARY backend exists."""
        assert hasattr(CryptoBackend, "C_LIBRARY")


class TestKeyPairDataclass:
    """Test KeyPair dataclass."""

    def test_keypair_fields(self):
        """Verify KeyPair has required fields."""
        assert hasattr(KeyPair, "__dataclass_fields__")
        fields = KeyPair.__dataclass_fields__
        assert "public_key" in fields
        assert "secret_key" in fields
        assert "algorithm" in fields
        assert "metadata" in fields

    def test_keypair_creation(self):
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

    def test_signature_fields(self):
        """Verify Signature has required fields."""
        assert hasattr(Signature, "__dataclass_fields__")
        fields = Signature.__dataclass_fields__
        assert "signature" in fields
        assert "algorithm" in fields
        assert "message_hash" in fields
        assert "metadata" in fields

    def test_signature_creation(self):
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

    def test_encapsulated_secret_fields(self):
        """Verify EncapsulatedSecret has required fields."""
        assert hasattr(EncapsulatedSecret, "__dataclass_fields__")
        fields = EncapsulatedSecret.__dataclass_fields__
        assert "ciphertext" in fields
        assert "shared_secret" in fields
        assert "algorithm" in fields
        assert "metadata" in fields

    def test_encapsulated_secret_creation(self):
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

    def test_provider_instantiation(self):
        """Verify Ed25519Provider can be instantiated."""
        provider = Ed25519Provider()
        assert provider is not None
        assert provider.algorithm == AlgorithmType.ED25519

    def test_generate_keypair(self):
        """Verify keypair generation works."""
        provider = Ed25519Provider()
        keypair = provider.generate_keypair()
        assert isinstance(keypair, KeyPair)
        assert len(keypair.public_key) == 32
        assert len(keypair.secret_key) == 32
        assert keypair.algorithm == AlgorithmType.ED25519

    def test_sign_and_verify(self):
        """Verify signing and verification works."""
        provider = Ed25519Provider()
        keypair = provider.generate_keypair()
        message = b"Test message for Ed25519"

        signature = provider.sign(message, keypair.secret_key)
        assert isinstance(signature, Signature)
        assert signature.algorithm == AlgorithmType.ED25519

        is_valid = provider.verify(message, signature.signature, keypair.public_key)
        assert is_valid is True

    def test_verify_rejects_tampered_message(self):
        """Verify tampered messages are rejected."""
        provider = Ed25519Provider()
        keypair = provider.generate_keypair()
        message = b"Original message"

        signature = provider.sign(message, keypair.secret_key)
        tampered = b"Tampered message"

        is_valid = provider.verify(tampered, signature.signature, keypair.public_key)
        assert is_valid is False

    def test_keypairs_are_unique(self):
        """Verify each keypair generation produces unique keys."""
        provider = Ed25519Provider()
        kp1 = provider.generate_keypair()
        kp2 = provider.generate_keypair()
        assert kp1.public_key != kp2.public_key
        assert kp1.secret_key != kp2.secret_key


@pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium backend not available")
class TestMLDSAProvider:
    """Test MLDSAProvider (ML-DSA-65/Dilithium)."""

    def test_provider_instantiation(self):
        """Verify MLDSAProvider can be instantiated."""
        provider = MLDSAProvider()
        assert provider is not None
        assert provider.algorithm == AlgorithmType.ML_DSA_65

    def test_generate_keypair(self):
        """Verify keypair generation works."""
        provider = MLDSAProvider()
        keypair = provider.generate_keypair()
        assert isinstance(keypair, KeyPair)
        assert len(keypair.public_key) == 1952
        assert len(keypair.secret_key) == 4032
        assert keypair.algorithm == AlgorithmType.ML_DSA_65

    def test_sign_and_verify(self):
        """Verify signing and verification works."""
        provider = MLDSAProvider()
        keypair = provider.generate_keypair()
        message = b"Test message for ML-DSA-65"

        signature = provider.sign(message, keypair.secret_key)
        assert isinstance(signature, Signature)
        assert signature.algorithm == AlgorithmType.ML_DSA_65

        is_valid = provider.verify(message, signature.signature, keypair.public_key)
        assert is_valid is True

    def test_verify_rejects_tampered_message(self):
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

    def test_provider_instantiation(self):
        """Verify KyberProvider can be instantiated."""
        provider = KyberProvider()
        assert provider is not None
        assert provider.algorithm == AlgorithmType.KYBER_1024

    def test_generate_keypair(self):
        """Verify keypair generation works."""
        provider = KyberProvider()
        keypair = provider.generate_keypair()
        assert isinstance(keypair, KeyPair)
        assert len(keypair.public_key) == 1568
        assert len(keypair.secret_key) == 3168
        assert keypair.algorithm == AlgorithmType.KYBER_1024

    def test_encapsulate_and_decapsulate(self):
        """Verify encapsulation and decapsulation works."""
        provider = KyberProvider()
        keypair = provider.generate_keypair()

        encapsulated = provider.encapsulate(keypair.public_key)
        assert isinstance(encapsulated, EncapsulatedSecret)
        assert len(encapsulated.ciphertext) == 1568
        assert len(encapsulated.shared_secret) == 32

        decapsulated = provider.decapsulate(encapsulated.ciphertext, keypair.secret_key)
        assert decapsulated == encapsulated.shared_secret

    def test_different_encapsulations_produce_different_secrets(self):
        """Verify each encapsulation produces unique shared secrets."""
        provider = KyberProvider()
        keypair = provider.generate_keypair()

        encap1 = provider.encapsulate(keypair.public_key)
        encap2 = provider.encapsulate(keypair.public_key)

        assert encap1.shared_secret != encap2.shared_secret
        assert encap1.ciphertext != encap2.ciphertext


@pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber backend not available")
def test_kyber_provider_not_placeholder():
    """Verify KyberProvider is not a placeholder."""
    provider = KyberProvider()
    # KyberProvider should be functional, not a stub
    keypair = provider.generate_keypair()
    assert keypair is not None


@pytest.mark.skipif(not SPHINCS_AVAILABLE, reason="SPHINCS+ backend not available")
class TestSphincsProvider:
    """Test SphincsProvider (SPHINCS+-SHA2-256f-simple)."""

    def test_provider_instantiation(self):
        """Verify SphincsProvider can be instantiated."""
        provider = SphincsProvider()
        assert provider is not None
        assert provider.algorithm == AlgorithmType.SPHINCS_256F

    def test_generate_keypair(self):
        """Verify keypair generation works."""
        provider = SphincsProvider()
        keypair = provider.generate_keypair()
        assert isinstance(keypair, KeyPair)
        assert len(keypair.public_key) == 64
        assert len(keypair.secret_key) == 128
        assert keypair.algorithm == AlgorithmType.SPHINCS_256F

    def test_sign_and_verify(self):
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

    def test_verify_rejects_tampered_message(self):
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

    def test_provider_instantiation(self):
        """Verify HybridSignatureProvider can be instantiated."""
        provider = HybridSignatureProvider()
        assert provider is not None
        assert provider.algorithm == AlgorithmType.HYBRID_SIG

    def test_generate_keypair(self):
        """Verify hybrid keypair generation works."""
        provider = HybridSignatureProvider()
        keypair = provider.generate_keypair()
        assert isinstance(keypair, KeyPair)
        assert keypair.algorithm == AlgorithmType.HYBRID_SIG

    def test_sign_and_verify(self):
        """Verify hybrid signing and verification works."""
        provider = HybridSignatureProvider()
        keypair = provider.generate_keypair()
        message = b"Test message for hybrid signature"

        signature = provider.sign(message, keypair.secret_key)
        assert isinstance(signature, Signature)
        assert signature.algorithm == AlgorithmType.HYBRID_SIG

        is_valid = provider.verify(message, signature.signature, keypair.public_key)
        assert is_valid is True

    def test_verify_rejects_tampered_message(self):
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

    def test_instantiation(self):
        """Verify AmaCryptography can be instantiated."""
        crypto = AmaCryptography()
        assert crypto is not None

    def test_ed25519_sign_and_verify(self):
        """Verify Ed25519 signing and verification via AmaCryptography."""
        crypto = AmaCryptography(algorithm=AlgorithmType.ED25519)
        keypair = crypto.generate_keypair()
        message = b"Test message"
        signature = crypto.sign(message, keypair.secret_key)
        is_valid = crypto.verify(message, signature.signature, keypair.public_key)
        assert is_valid is True

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium not available")
    def test_ml_dsa_sign_and_verify(self):
        """Verify ML-DSA-65 signing and verification via AmaCryptography."""
        crypto = AmaCryptography(algorithm=AlgorithmType.ML_DSA_65)
        keypair = crypto.generate_keypair()
        message = b"Test message"
        signature = crypto.sign(message, keypair.secret_key)
        is_valid = crypto.verify(message, signature.signature, keypair.public_key)
        assert is_valid is True

    @pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber not available")
    def test_kyber_encapsulate_and_decapsulate(self):
        """Verify Kyber-1024 KEM via AmaCryptography."""
        crypto = AmaCryptography(algorithm=AlgorithmType.KYBER_1024)
        keypair = crypto.generate_keypair()
        encapsulated = crypto.encapsulate(keypair.public_key)
        shared_secret = crypto.decapsulate(encapsulated.ciphertext, keypair.secret_key)
        assert shared_secret == encapsulated.shared_secret

    @pytest.mark.skipif(not SPHINCS_AVAILABLE, reason="SPHINCS+ not available")
    def test_sphincs_sign_and_verify(self):
        """Verify SPHINCS+-256f signing and verification via AmaCryptography."""
        crypto = AmaCryptography(algorithm=AlgorithmType.SPHINCS_256F)
        keypair = crypto.generate_keypair()
        message = b"Test message"
        signature = crypto.sign(message, keypair.secret_key)
        is_valid = crypto.verify(message, signature.signature, keypair.public_key)
        assert is_valid is True


class TestQuickFunctions:
    """Test quick_sign, quick_verify, and quick_kem convenience functions."""

    def test_quick_sign_ed25519(self):
        """Verify quick_sign works with Ed25519."""
        message = b"Quick sign test"
        keypair, signature = quick_sign(message, algorithm=AlgorithmType.ED25519)
        assert isinstance(keypair, KeyPair)
        assert isinstance(signature, Signature)

    def test_quick_verify_ed25519(self):
        """Verify quick_verify works with Ed25519."""
        message = b"Quick verify test"
        keypair, signature = quick_sign(message, algorithm=AlgorithmType.ED25519)
        is_valid = quick_verify(
            message, signature.signature, keypair.public_key, AlgorithmType.ED25519
        )
        assert is_valid is True

    @pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber not available")
    def test_quick_kem(self):
        """Verify quick_kem works with Kyber-1024."""
        keypair, encapsulated = quick_kem(algorithm=AlgorithmType.KYBER_1024)
        assert isinstance(keypair, KeyPair)
        assert isinstance(encapsulated, EncapsulatedSecret)
        assert len(encapsulated.shared_secret) == 32


class TestGetPqcCapabilities:
    """Test get_pqc_capabilities function."""

    def test_returns_dict(self):
        """Verify get_pqc_capabilities returns a dictionary."""
        caps = get_pqc_capabilities()
        assert isinstance(caps, dict)

    def test_contains_dilithium_info(self):
        """Verify capabilities contains Dilithium information."""
        caps = get_pqc_capabilities()
        assert "dilithium_available" in caps or "ml_dsa_available" in caps

    def test_contains_kyber_info(self):
        """Verify capabilities contains Kyber information."""
        caps = get_pqc_capabilities()
        assert "kyber_available" in caps

    def test_contains_sphincs_info(self):
        """Verify capabilities contains SPHINCS+ information."""
        caps = get_pqc_capabilities()
        assert "sphincs_available" in caps


class TestUnavailableProviderErrors:
    """Test error handling when providers are unavailable."""

    def test_kyber_provider_raises_error(self):
        """Verify KyberProvider raises error when unavailable."""
        with patch("ama_cryptography.crypto_api.KYBER_AVAILABLE", False):
            with pytest.raises(KyberUnavailableError):
                KyberProvider()

    def test_sphincs_provider_raises_error(self):
        """Verify SphincsProvider raises error when unavailable."""
        with patch("ama_cryptography.crypto_api.SPHINCS_AVAILABLE", False):
            with pytest.raises(SphincsUnavailableError):
                SphincsProvider()


class TestProviderAbstractBase:
    """Test CryptoProvider abstract base class."""

    def test_crypto_provider_is_abstract(self):
        """Verify CryptoProvider cannot be instantiated directly."""
        with pytest.raises(TypeError):
            CryptoProvider()

    def test_kem_provider_is_abstract(self):
        """Verify KEMProvider cannot be instantiated directly."""
        with pytest.raises(TypeError):
            KEMProvider()


class TestEd25519KeyObjectOptimization:
    """
    Test Ed25519 key object optimization.

    Verifies that passing Ed25519PrivateKey/PublicKey objects instead of bytes
    produces identical cryptographic results while enabling performance gains.
    """

    def test_sign_bytes_vs_key_object_identical(self):
        """Verify signing with bytes and key object produces identical signatures."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        provider = Ed25519Provider()
        keypair = provider.generate_keypair()
        message = b"Test message for key object optimization"

        # Sign with bytes (original approach)
        sig_bytes = provider.sign(message, keypair.secret_key)

        # Sign with key object (optimized approach)
        private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(keypair.secret_key)
        sig_obj = provider.sign(message, private_key_obj)

        # Ed25519 is deterministic - signatures must be identical
        assert sig_bytes.signature == sig_obj.signature
        assert sig_bytes.algorithm == sig_obj.algorithm
        assert sig_bytes.message_hash == sig_obj.message_hash

    def test_verify_bytes_vs_key_object_identical(self):
        """Verify verification with bytes and key object produces identical results."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        provider = Ed25519Provider()
        keypair = provider.generate_keypair()
        message = b"Test message for verification optimization"

        # Sign the message
        signature = provider.sign(message, keypair.secret_key)

        # Verify with bytes (original approach)
        valid_bytes = provider.verify(message, signature.signature, keypair.public_key)

        # Verify with key object (optimized approach)
        public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(keypair.public_key)
        valid_obj = provider.verify(message, signature.signature, public_key_obj)

        # Both must return True
        assert valid_bytes is True
        assert valid_obj is True

    def test_verify_invalid_signature_with_key_object(self):
        """Verify invalid signatures are rejected when using key objects."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        provider = Ed25519Provider()
        keypair = provider.generate_keypair()
        message = b"Original message"
        tampered = b"Tampered message"

        signature = provider.sign(message, keypair.secret_key)

        # Verify tampered message with key object
        public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(keypair.public_key)
        is_valid = provider.verify(tampered, signature.signature, public_key_obj)

        assert is_valid is False

    def test_sign_multiple_messages_with_cached_key_object(self):
        """Verify signing multiple messages with cached key object works correctly."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        provider = Ed25519Provider()
        keypair = provider.generate_keypair()

        # Cache the key object (simulating high-throughput scenario)
        private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(keypair.secret_key)
        public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(keypair.public_key)

        messages = [
            b"Message 1",
            b"Message 2",
            b"Message 3",
            b"A longer message for testing",
            b"",  # Empty message
        ]

        for msg in messages:
            # Sign with cached key object
            sig = provider.sign(msg, private_key_obj)

            # Verify with cached key object
            is_valid = provider.verify(msg, sig.signature, public_key_obj)
            assert is_valid is True, f"Failed for message: {msg!r}"

            # Cross-verify with bytes approach
            is_valid_bytes = provider.verify(msg, sig.signature, keypair.public_key)
            assert is_valid_bytes is True, f"Bytes verify failed for: {msg!r}"
