#!/usr/bin/env python3
"""
Ava Guardian ♱ (AG♱) - Post-Quantum Cryptography Backend Tests

Comprehensive test suite for pqc_backends.py providing 100% coverage
of all PQC backend functionality including ML-DSA-65 (Dilithium),
Kyber-1024 (ML-KEM), and SPHINCS+-256f.

AI Co-Architects: Eris ⯰ | Eden ♱ | Veritas 💠 | X ⚛ | Caduceus ⚚ | Dev ⚕

Copyright 2025 Steel Security Advisors LLC
Licensed under the Apache License, Version 2.0
"""

import pytest

from ava_guardian.pqc_backends import (
    DILITHIUM_AVAILABLE,
    DILITHIUM_BACKEND,
    DILITHIUM_PUBLIC_KEY_BYTES,
    DILITHIUM_SECRET_KEY_BYTES,
    DILITHIUM_SIGNATURE_BYTES,
    KYBER_AVAILABLE,
    KYBER_BACKEND,
    KYBER_CIPHERTEXT_BYTES,
    KYBER_PUBLIC_KEY_BYTES,
    KYBER_SECRET_KEY_BYTES,
    KYBER_SHARED_SECRET_BYTES,
    SPHINCS_AVAILABLE,
    SPHINCS_BACKEND,
    SPHINCS_PUBLIC_KEY_BYTES,
    SPHINCS_SECRET_KEY_BYTES,
    SPHINCS_SIGNATURE_BYTES,
    DilithiumKeyPair,
    KyberEncapsulation,
    KyberKeyPair,
    KyberUnavailableError,
    PQCUnavailableError,
    SphincsKeyPair,
    SphincsUnavailableError,
    generate_dilithium_keypair,
    generate_kyber_keypair,
    generate_sphincs_keypair,
    get_pqc_backend_info,
    kyber_decapsulate,
    kyber_encapsulate,
    sphincs_sign,
    sphincs_verify,
)


class TestDilithiumConstants:
    """Test ML-DSA-65 (Dilithium) constants per NIST FIPS."""

    def test_dilithium_public_key_size(self):
        """Verify ML-DSA-65 public key size matches NIST FIPS specification."""
        assert DILITHIUM_PUBLIC_KEY_BYTES == 1952

    def test_dilithium_secret_key_size(self):
        """Verify ML-DSA-65 secret key size matches NIST FIPS specification."""
        assert DILITHIUM_SECRET_KEY_BYTES == 4032

    def test_dilithium_signature_size(self):
        """Verify ML-DSA-65 signature size matches NIST FIPS specification."""
        assert DILITHIUM_SIGNATURE_BYTES == 3309


class TestKyberConstants:
    """Test Kyber-1024 (ML-KEM) constants per NIST FIPS."""

    def test_kyber_public_key_size(self):
        """Verify Kyber-1024 public key size matches NIST FIPS specification."""
        assert KYBER_PUBLIC_KEY_BYTES == 1568

    def test_kyber_secret_key_size(self):
        """Verify Kyber-1024 secret key size matches NIST FIPS specification."""
        assert KYBER_SECRET_KEY_BYTES == 3168

    def test_kyber_ciphertext_size(self):
        """Verify Kyber-1024 ciphertext size matches NIST FIPS specification."""
        assert KYBER_CIPHERTEXT_BYTES == 1568

    def test_kyber_shared_secret_size(self):
        """Verify Kyber-1024 shared secret size matches NIST FIPS specification."""
        assert KYBER_SHARED_SECRET_BYTES == 32


class TestSphincsConstants:
    """Test SPHINCS+-SHA2-256f-simple constants per NIST FIPS."""

    def test_sphincs_public_key_size(self):
        """Verify SPHINCS+-256f public key size matches NIST FIPS specification."""
        assert SPHINCS_PUBLIC_KEY_BYTES == 64

    def test_sphincs_secret_key_size(self):
        """Verify SPHINCS+-256f secret key size matches NIST FIPS specification."""
        assert SPHINCS_SECRET_KEY_BYTES == 128

    def test_sphincs_signature_size(self):
        """Verify SPHINCS+-256f signature size matches NIST FIPS specification."""
        assert SPHINCS_SIGNATURE_BYTES == 49856


class TestBackendAvailability:
    """Test backend availability detection."""

    def test_dilithium_backend_type(self):
        """Verify Dilithium backend is either native or None."""
        assert DILITHIUM_BACKEND in ("native", None)

    def test_dilithium_availability_consistency(self):
        """Verify DILITHIUM_AVAILABLE matches backend presence."""
        if DILITHIUM_BACKEND is not None:
            assert DILITHIUM_AVAILABLE is True
        else:
            assert DILITHIUM_AVAILABLE is False

    def test_kyber_backend_type(self):
        """Verify Kyber backend is either native or None."""
        assert KYBER_BACKEND in ("native", None)

    def test_kyber_availability_consistency(self):
        """Verify KYBER_AVAILABLE matches backend presence."""
        if KYBER_BACKEND is not None:
            assert KYBER_AVAILABLE is True
        else:
            assert KYBER_AVAILABLE is False

    def test_sphincs_backend_type(self):
        """Verify SPHINCS+ backend is either native or None."""
        assert SPHINCS_BACKEND in ("native", None)

    def test_sphincs_availability_consistency(self):
        """Verify SPHINCS_AVAILABLE matches backend presence."""
        if SPHINCS_BACKEND is not None:
            assert SPHINCS_AVAILABLE is True
        else:
            assert SPHINCS_AVAILABLE is False


class TestGetPqcBackendInfo:
    """Test get_pqc_backend_info() function."""

    def test_returns_dict(self):
        """Verify get_pqc_backend_info returns a dictionary."""
        info = get_pqc_backend_info()
        assert isinstance(info, dict)

    def test_contains_dilithium_info(self):
        """Verify info contains Dilithium backend information."""
        info = get_pqc_backend_info()
        assert "dilithium_backend" in info
        assert "dilithium_available" in info

    def test_contains_kyber_info(self):
        """Verify info contains Kyber backend information."""
        info = get_pqc_backend_info()
        assert "kyber_backend" in info
        assert "kyber_available" in info

    def test_contains_sphincs_info(self):
        """Verify info contains SPHINCS+ backend information."""
        info = get_pqc_backend_info()
        assert "sphincs_backend" in info
        assert "sphincs_available" in info

    def test_contains_key_sizes(self):
        """Verify info contains key size information in algorithms dict when available."""
        info = get_pqc_backend_info()
        assert "algorithms" in info
        algorithms = info["algorithms"]

        # Check ML-DSA-65 (Dilithium) key sizes - only if available
        assert "ML-DSA-65" in algorithms
        assert "key_sizes" in algorithms["ML-DSA-65"]
        if DILITHIUM_AVAILABLE:
            assert algorithms["ML-DSA-65"]["key_sizes"] is not None
            assert "public_key" in algorithms["ML-DSA-65"]["key_sizes"]
            assert "secret_key" in algorithms["ML-DSA-65"]["key_sizes"]
            assert "signature" in algorithms["ML-DSA-65"]["key_sizes"]
        else:
            assert algorithms["ML-DSA-65"]["key_sizes"] is None

        # Check Kyber-1024 key sizes - only if available
        assert "Kyber-1024" in algorithms
        assert "key_sizes" in algorithms["Kyber-1024"]
        if KYBER_AVAILABLE:
            assert algorithms["Kyber-1024"]["key_sizes"] is not None
            assert "public_key" in algorithms["Kyber-1024"]["key_sizes"]
            assert "secret_key" in algorithms["Kyber-1024"]["key_sizes"]
        else:
            assert algorithms["Kyber-1024"]["key_sizes"] is None

        # Check SPHINCS+-256f key sizes - only if available
        assert "SPHINCS+-256f" in algorithms
        assert "key_sizes" in algorithms["SPHINCS+-256f"]
        if SPHINCS_AVAILABLE:
            assert algorithms["SPHINCS+-256f"]["key_sizes"] is not None
            assert "public_key" in algorithms["SPHINCS+-256f"]["key_sizes"]
            assert "secret_key" in algorithms["SPHINCS+-256f"]["key_sizes"]
        else:
            assert algorithms["SPHINCS+-256f"]["key_sizes"] is None


@pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium backend not available")
class TestDilithiumKeyGeneration:
    """Test ML-DSA-65 (Dilithium) key generation."""

    def test_generate_keypair_returns_dataclass(self):
        """Verify generate_dilithium_keypair returns DilithiumKeyPair."""
        keypair = generate_dilithium_keypair()
        assert isinstance(keypair, DilithiumKeyPair)

    def test_public_key_size(self):
        """Verify generated public key has correct size."""
        keypair = generate_dilithium_keypair()
        assert len(keypair.public_key) == DILITHIUM_PUBLIC_KEY_BYTES

    def test_private_key_size(self):
        """Verify generated private key has correct size."""
        keypair = generate_dilithium_keypair()
        assert len(keypair.private_key) == DILITHIUM_SECRET_KEY_BYTES

    def test_keypairs_are_unique(self):
        """Verify each keypair generation produces unique keys."""
        keypair1 = generate_dilithium_keypair()
        keypair2 = generate_dilithium_keypair()
        assert keypair1.public_key != keypair2.public_key
        assert keypair1.private_key != keypair2.private_key


@pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber backend not available")
class TestKyberKeyGeneration:
    """Test Kyber-1024 (ML-KEM) key generation."""

    def test_generate_keypair_returns_dataclass(self):
        """Verify generate_kyber_keypair returns KyberKeyPair."""
        keypair = generate_kyber_keypair()
        assert isinstance(keypair, KyberKeyPair)

    def test_public_key_size(self):
        """Verify generated public key has correct size."""
        keypair = generate_kyber_keypair()
        assert len(keypair.public_key) == KYBER_PUBLIC_KEY_BYTES

    def test_secret_key_size(self):
        """Verify generated secret key has correct size."""
        keypair = generate_kyber_keypair()
        assert len(keypair.secret_key) == KYBER_SECRET_KEY_BYTES

    def test_keypairs_are_unique(self):
        """Verify each keypair generation produces unique keys."""
        keypair1 = generate_kyber_keypair()
        keypair2 = generate_kyber_keypair()
        assert keypair1.public_key != keypair2.public_key
        assert keypair1.secret_key != keypair2.secret_key


@pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber backend not available")
class TestKyberEncapsulation:
    """Test Kyber-1024 (ML-KEM) encapsulation/decapsulation."""

    def test_encapsulate_returns_dataclass(self):
        """Verify kyber_encapsulate returns KyberEncapsulation."""
        keypair = generate_kyber_keypair()
        result = kyber_encapsulate(keypair.public_key)
        assert isinstance(result, KyberEncapsulation)

    def test_ciphertext_size(self):
        """Verify encapsulation produces correct ciphertext size."""
        keypair = generate_kyber_keypair()
        result = kyber_encapsulate(keypair.public_key)
        assert len(result.ciphertext) == KYBER_CIPHERTEXT_BYTES

    def test_shared_secret_size(self):
        """Verify encapsulation produces correct shared secret size."""
        keypair = generate_kyber_keypair()
        result = kyber_encapsulate(keypair.public_key)
        assert len(result.shared_secret) == KYBER_SHARED_SECRET_BYTES

    def test_decapsulate_recovers_shared_secret(self):
        """Verify decapsulation recovers the same shared secret."""
        keypair = generate_kyber_keypair()
        encap = kyber_encapsulate(keypair.public_key)
        decap_secret = kyber_decapsulate(encap.ciphertext, keypair.secret_key)
        assert decap_secret == encap.shared_secret

    def test_different_encapsulations_produce_different_secrets(self):
        """Verify each encapsulation produces a unique shared secret."""
        keypair = generate_kyber_keypair()
        encap1 = kyber_encapsulate(keypair.public_key)
        encap2 = kyber_encapsulate(keypair.public_key)
        assert encap1.shared_secret != encap2.shared_secret
        assert encap1.ciphertext != encap2.ciphertext


@pytest.mark.skipif(not SPHINCS_AVAILABLE, reason="SPHINCS+ backend not available")
class TestSphincsKeyGeneration:
    """Test SPHINCS+-SHA2-256f-simple key generation."""

    def test_generate_keypair_returns_dataclass(self):
        """Verify generate_sphincs_keypair returns SphincsKeyPair."""
        keypair = generate_sphincs_keypair()
        assert isinstance(keypair, SphincsKeyPair)

    def test_public_key_size(self):
        """Verify generated public key has correct size."""
        keypair = generate_sphincs_keypair()
        assert len(keypair.public_key) == SPHINCS_PUBLIC_KEY_BYTES

    def test_secret_key_size(self):
        """Verify generated secret key has correct size."""
        keypair = generate_sphincs_keypair()
        assert len(keypair.secret_key) == SPHINCS_SECRET_KEY_BYTES

    def test_keypairs_are_unique(self):
        """Verify each keypair generation produces unique keys."""
        keypair1 = generate_sphincs_keypair()
        keypair2 = generate_sphincs_keypair()
        assert keypair1.public_key != keypair2.public_key
        assert keypair1.secret_key != keypair2.secret_key


@pytest.mark.skipif(not SPHINCS_AVAILABLE, reason="SPHINCS+ backend not available")
class TestSphincsSignatures:
    """Test SPHINCS+-SHA2-256f-simple signing and verification."""

    def test_sign_returns_bytes(self):
        """Verify sphincs_sign returns bytes."""
        keypair = generate_sphincs_keypair()
        message = b"Test message for SPHINCS+ signature"
        signature = sphincs_sign(message, keypair.secret_key)
        assert isinstance(signature, bytes)

    def test_signature_size(self):
        """Verify signature has correct size."""
        keypair = generate_sphincs_keypair()
        message = b"Test message for SPHINCS+ signature"
        signature = sphincs_sign(message, keypair.secret_key)
        assert len(signature) == SPHINCS_SIGNATURE_BYTES

    def test_verify_valid_signature(self):
        """Verify valid signatures are accepted."""
        keypair = generate_sphincs_keypair()
        message = b"Test message for SPHINCS+ signature"
        signature = sphincs_sign(message, keypair.secret_key)
        assert sphincs_verify(message, signature, keypair.public_key) is True

    def test_verify_rejects_tampered_message(self):
        """Verify tampered messages are rejected."""
        keypair = generate_sphincs_keypair()
        message = b"Original message"
        signature = sphincs_sign(message, keypair.secret_key)
        tampered = b"Tampered message"
        assert sphincs_verify(tampered, signature, keypair.public_key) is False

    def test_verify_rejects_wrong_public_key(self):
        """Verify signatures with wrong public key are rejected."""
        keypair1 = generate_sphincs_keypair()
        keypair2 = generate_sphincs_keypair()
        message = b"Test message"
        signature = sphincs_sign(message, keypair1.secret_key)
        assert sphincs_verify(message, signature, keypair2.public_key) is False

    def test_different_messages_produce_different_signatures(self):
        """Verify different messages produce different signatures."""
        keypair = generate_sphincs_keypair()
        message1 = b"First message"
        message2 = b"Second message"
        sig1 = sphincs_sign(message1, keypair.secret_key)
        sig2 = sphincs_sign(message2, keypair.secret_key)
        assert sig1 != sig2


class TestUnavailableBackendErrors:
    """Test error handling when backends are unavailable."""

    @pytest.mark.skipif(DILITHIUM_AVAILABLE, reason="Dilithium is available")
    def test_dilithium_unavailable_error(self):
        """Verify PQCUnavailableError is raised when backend missing."""
        with pytest.raises(PQCUnavailableError):
            generate_dilithium_keypair()

    @pytest.mark.skipif(KYBER_AVAILABLE, reason="Kyber is available")
    def test_kyber_unavailable_error_keygen(self):
        """Verify KyberUnavailableError is raised for keygen when backend missing."""
        with pytest.raises(KyberUnavailableError):
            generate_kyber_keypair()

    @pytest.mark.skipif(KYBER_AVAILABLE, reason="Kyber is available")
    def test_kyber_unavailable_error_encapsulate(self):
        """Verify KyberUnavailableError is raised for encapsulate when backend missing."""
        with pytest.raises(KyberUnavailableError):
            kyber_encapsulate(b"fake_public_key")

    @pytest.mark.skipif(KYBER_AVAILABLE, reason="Kyber is available")
    def test_kyber_unavailable_error_decapsulate(self):
        """Verify KyberUnavailableError is raised for decapsulate when backend missing."""
        with pytest.raises(KyberUnavailableError):
            kyber_decapsulate(b"fake_ciphertext", b"fake_secret_key")

    @pytest.mark.skipif(SPHINCS_AVAILABLE, reason="SPHINCS+ is available")
    def test_sphincs_unavailable_error_keygen(self):
        """Verify SphincsUnavailableError is raised for keygen when backend missing."""
        with pytest.raises(SphincsUnavailableError):
            generate_sphincs_keypair()

    @pytest.mark.skipif(SPHINCS_AVAILABLE, reason="SPHINCS+ is available")
    def test_sphincs_unavailable_error_sign(self):
        """Verify SphincsUnavailableError is raised for sign when backend missing."""
        with pytest.raises(SphincsUnavailableError):
            sphincs_sign(b"message", b"fake_secret_key")

    @pytest.mark.skipif(SPHINCS_AVAILABLE, reason="SPHINCS+ is available")
    def test_sphincs_unavailable_error_verify(self):
        """Verify SphincsUnavailableError is raised for verify when backend missing."""
        with pytest.raises(SphincsUnavailableError):
            sphincs_verify(b"message", b"signature", b"public_key")


class TestDataclassFields:
    """Test dataclass field definitions."""

    def test_dilithium_keypair_fields(self):
        """Verify DilithiumKeyPair has required fields."""
        assert hasattr(DilithiumKeyPair, "__dataclass_fields__")
        fields = DilithiumKeyPair.__dataclass_fields__
        assert "public_key" in fields
        assert "private_key" in fields

    def test_kyber_keypair_fields(self):
        """Verify KyberKeyPair has required fields."""
        assert hasattr(KyberKeyPair, "__dataclass_fields__")
        fields = KyberKeyPair.__dataclass_fields__
        assert "public_key" in fields
        assert "secret_key" in fields

    def test_kyber_encapsulation_fields(self):
        """Verify KyberEncapsulation has required fields."""
        assert hasattr(KyberEncapsulation, "__dataclass_fields__")
        fields = KyberEncapsulation.__dataclass_fields__
        assert "ciphertext" in fields
        assert "shared_secret" in fields

    def test_sphincs_keypair_fields(self):
        """Verify SphincsKeyPair has required fields."""
        assert hasattr(SphincsKeyPair, "__dataclass_fields__")
        fields = SphincsKeyPair.__dataclass_fields__
        assert "public_key" in fields
        assert "secret_key" in fields


class TestExceptionClasses:
    """Test exception class definitions."""

    def test_pqc_unavailable_error_is_exception(self):
        """Verify PQCUnavailableError is an Exception subclass."""
        assert issubclass(PQCUnavailableError, Exception)

    def test_kyber_unavailable_error_is_exception(self):
        """Verify KyberUnavailableError is an Exception subclass."""
        assert issubclass(KyberUnavailableError, Exception)

    def test_sphincs_unavailable_error_is_exception(self):
        """Verify SphincsUnavailableError is an Exception subclass."""
        assert issubclass(SphincsUnavailableError, Exception)

    def test_kyber_inherits_from_pqc_error(self):
        """Verify KyberUnavailableError inherits from PQCUnavailableError."""
        assert issubclass(KyberUnavailableError, PQCUnavailableError)

    def test_sphincs_inherits_from_pqc_error(self):
        """Verify SphincsUnavailableError inherits from PQCUnavailableError."""
        assert issubclass(SphincsUnavailableError, PQCUnavailableError)

    def test_exception_messages(self):
        """Verify exception messages are informative."""
        pqc_err = PQCUnavailableError("Test message")
        assert "Test message" in str(pqc_err)

        kyber_err = KyberUnavailableError("Kyber test")
        assert "Kyber test" in str(kyber_err)

        sphincs_err = SphincsUnavailableError("SPHINCS test")
        assert "SPHINCS test" in str(sphincs_err)
