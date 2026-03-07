#!/usr/bin/env python3
# Copyright 2025 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Comprehensive PQC Backends Tests
================================

Professional-grade test coverage for the pqc_backends module.
Tests all post-quantum cryptographic operations with proper error handling.

Test Categories:
- Backend detection and status
- ML-DSA-65 (Dilithium) signatures
- Kyber-1024 key encapsulation
- SPHINCS+-256f hash-based signatures
- Error handling and edge cases
"""

import pytest

from ama_cryptography.pqc_backends import (
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
    PQCStatus,
    PQCUnavailableError,
    SphincsKeyPair,
    SphincsUnavailableError,
    dilithium_sign,
    dilithium_verify,
    generate_dilithium_keypair,
    generate_kyber_keypair,
    generate_sphincs_keypair,
    get_pqc_backend_info,
    get_pqc_status,
    kyber_decapsulate,
    kyber_encapsulate,
    sphincs_sign,
    sphincs_verify,
)

# =============================================================================
# BACKEND STATUS TESTS
# =============================================================================


class TestPQCStatus:
    """Tests for PQC backend status detection."""

    def test_pqc_status_enum_values(self):
        """PQCStatus enum has expected values."""
        assert PQCStatus.AVAILABLE.value == "AVAILABLE"
        assert PQCStatus.UNAVAILABLE.value == "UNAVAILABLE"

    def test_get_pqc_status(self):
        """get_pqc_status returns valid status."""
        status = get_pqc_status()
        assert status in [PQCStatus.AVAILABLE, PQCStatus.UNAVAILABLE]

    def test_get_pqc_status_matches_availability(self):
        """Status matches algorithm availability."""
        status = get_pqc_status()
        if DILITHIUM_AVAILABLE or KYBER_AVAILABLE or SPHINCS_AVAILABLE:
            assert status == PQCStatus.AVAILABLE
        else:
            assert status == PQCStatus.UNAVAILABLE


class TestPQCBackendInfo:
    """Tests for get_pqc_backend_info function."""

    def test_backend_info_structure(self):
        """Backend info has expected structure."""
        info = get_pqc_backend_info()

        assert "status" in info
        assert "dilithium_available" in info
        assert "dilithium_backend" in info
        assert "kyber_available" in info
        assert "kyber_backend" in info
        assert "sphincs_available" in info
        assert "sphincs_backend" in info
        assert "algorithms" in info

    def test_backend_info_algorithms(self):
        """Backend info has algorithm details."""
        info = get_pqc_backend_info()

        assert "ML-DSA-65" in info["algorithms"]
        assert "Kyber-1024" in info["algorithms"]
        assert "SPHINCS+-256f" in info["algorithms"]

    def test_backend_info_dilithium(self):
        """Dilithium algorithm info is correct."""
        info = get_pqc_backend_info()
        dilithium = info["algorithms"]["ML-DSA-65"]

        assert dilithium["available"] == DILITHIUM_AVAILABLE
        assert dilithium["backend"] == DILITHIUM_BACKEND

        if DILITHIUM_AVAILABLE:
            assert dilithium["security_level"] == 3
            assert dilithium["key_sizes"]["public_key"] == DILITHIUM_PUBLIC_KEY_BYTES
            assert dilithium["key_sizes"]["secret_key"] == DILITHIUM_SECRET_KEY_BYTES
            assert dilithium["key_sizes"]["signature"] == DILITHIUM_SIGNATURE_BYTES

    def test_backend_info_kyber(self):
        """Kyber algorithm info is correct."""
        info = get_pqc_backend_info()
        kyber = info["algorithms"]["Kyber-1024"]

        assert kyber["available"] == KYBER_AVAILABLE
        assert kyber["backend"] == KYBER_BACKEND

        if KYBER_AVAILABLE:
            assert kyber["security_level"] == 5
            assert kyber["key_sizes"]["public_key"] == KYBER_PUBLIC_KEY_BYTES
            assert kyber["key_sizes"]["secret_key"] == KYBER_SECRET_KEY_BYTES

    def test_backend_info_sphincs(self):
        """SPHINCS+ algorithm info is correct."""
        info = get_pqc_backend_info()
        sphincs = info["algorithms"]["SPHINCS+-256f"]

        assert sphincs["available"] == SPHINCS_AVAILABLE
        assert sphincs["backend"] == SPHINCS_BACKEND

        if SPHINCS_AVAILABLE:
            assert sphincs["security_level"] == 5
            assert sphincs["key_sizes"]["public_key"] == SPHINCS_PUBLIC_KEY_BYTES
            assert sphincs["key_sizes"]["secret_key"] == SPHINCS_SECRET_KEY_BYTES

    def test_backend_info_legacy_fields(self):
        """Backend info includes legacy compatibility fields."""
        info = get_pqc_backend_info()

        assert "backend" in info  # Legacy field
        assert "algorithm" in info  # Legacy field
        assert "security_level" in info  # Legacy field


# =============================================================================
# KEY SIZE CONSTANTS TESTS
# =============================================================================


class TestKeySizeConstants:
    """Tests for key size constants."""

    def test_dilithium_key_sizes(self):
        """Dilithium key sizes match NIST specification."""
        assert DILITHIUM_PUBLIC_KEY_BYTES == 1952
        assert DILITHIUM_SECRET_KEY_BYTES == 4032
        assert DILITHIUM_SIGNATURE_BYTES == 3309

    def test_kyber_key_sizes(self):
        """Kyber-1024 key sizes match NIST specification."""
        assert KYBER_PUBLIC_KEY_BYTES == 1568
        assert KYBER_SECRET_KEY_BYTES == 3168
        assert KYBER_CIPHERTEXT_BYTES == 1568
        assert KYBER_SHARED_SECRET_BYTES == 32

    def test_sphincs_key_sizes(self):
        """SPHINCS+-256f key sizes match specification."""
        assert SPHINCS_PUBLIC_KEY_BYTES == 64
        assert SPHINCS_SECRET_KEY_BYTES == 128
        assert SPHINCS_SIGNATURE_BYTES == 49856


# =============================================================================
# DATACLASS TESTS
# =============================================================================


class TestDataclasses:
    """Tests for PQC dataclasses."""

    def test_dilithium_keypair(self):
        """DilithiumKeyPair stores keys correctly."""
        keypair = DilithiumKeyPair(
            secret_key=b"x" * 4032,
            public_key=b"y" * 1952,
        )
        assert len(keypair.secret_key) == 4032
        assert len(keypair.public_key) == 1952

    def test_kyber_keypair(self):
        """KyberKeyPair stores keys correctly."""
        keypair = KyberKeyPair(
            secret_key=b"x" * 3168,
            public_key=b"y" * 1568,
        )
        assert len(keypair.secret_key) == 3168
        assert len(keypair.public_key) == 1568

    def test_kyber_encapsulation(self):
        """KyberEncapsulation stores result correctly."""
        encap = KyberEncapsulation(
            ciphertext=b"c" * 1568,
            shared_secret=b"s" * 32,
        )
        assert len(encap.ciphertext) == 1568
        assert len(encap.shared_secret) == 32

    def test_sphincs_keypair(self):
        """SphincsKeyPair stores keys correctly."""
        keypair = SphincsKeyPair(
            secret_key=b"x" * 128,
            public_key=b"y" * 64,
        )
        assert len(keypair.secret_key) == 128
        assert len(keypair.public_key) == 64


# =============================================================================
# EXCEPTION TESTS
# =============================================================================


class TestExceptions:
    """Tests for PQC exception classes."""

    def test_pqc_unavailable_error(self):
        """PQCUnavailableError is RuntimeError subclass."""
        assert issubclass(PQCUnavailableError, RuntimeError)

        with pytest.raises(PQCUnavailableError):
            raise PQCUnavailableError("Test error")

    def test_kyber_unavailable_error(self):
        """KyberUnavailableError is PQCUnavailableError subclass."""
        assert issubclass(KyberUnavailableError, PQCUnavailableError)

        with pytest.raises(KyberUnavailableError):
            raise KyberUnavailableError("Kyber not available")

    def test_sphincs_unavailable_error(self):
        """SphincsUnavailableError is PQCUnavailableError subclass."""
        assert issubclass(SphincsUnavailableError, PQCUnavailableError)

        with pytest.raises(SphincsUnavailableError):
            raise SphincsUnavailableError("SPHINCS+ not available")


# =============================================================================
# ML-DSA-65 (DILITHIUM) TESTS
# =============================================================================


class TestDilithiumOperations:
    """Tests for Dilithium signature operations."""

    @pytest.fixture
    def dilithium_keypair(self):
        """Generate Dilithium keypair for tests."""
        if not DILITHIUM_AVAILABLE:
            pytest.skip("Dilithium not available")
        return generate_dilithium_keypair()

    def test_generate_keypair(self, dilithium_keypair):
        """Generate Dilithium keypair successfully."""
        assert len(dilithium_keypair.public_key) == DILITHIUM_PUBLIC_KEY_BYTES
        assert len(dilithium_keypair.secret_key) == DILITHIUM_SECRET_KEY_BYTES

    def test_sign_and_verify(self, dilithium_keypair):
        """Sign message and verify signature."""
        message = b"Test message for Dilithium signature"

        signature = dilithium_sign(message, dilithium_keypair.secret_key)
        assert len(signature) > 0

        is_valid = dilithium_verify(message, signature, dilithium_keypair.public_key)
        assert is_valid is True

    def test_verify_wrong_message(self, dilithium_keypair):
        """Verification fails with wrong message."""
        message = b"Original message"
        wrong_message = b"Tampered message"

        signature = dilithium_sign(message, dilithium_keypair.secret_key)
        is_valid = dilithium_verify(wrong_message, signature, dilithium_keypair.public_key)

        assert is_valid is False

    def test_verify_wrong_signature(self, dilithium_keypair):
        """Verification fails with wrong signature."""
        message = b"Test message"

        signature = dilithium_sign(message, dilithium_keypair.secret_key)
        wrong_signature = bytes([b ^ 0xFF for b in signature[:100]]) + signature[100:]

        is_valid = dilithium_verify(message, wrong_signature, dilithium_keypair.public_key)
        assert is_valid is False

    def test_verify_wrong_key(self, dilithium_keypair):
        """Verification fails with wrong public key."""
        message = b"Test message"
        other_keypair = generate_dilithium_keypair()

        signature = dilithium_sign(message, dilithium_keypair.secret_key)
        is_valid = dilithium_verify(message, signature, other_keypair.public_key)

        assert is_valid is False

    def test_sign_empty_message(self, dilithium_keypair):
        """Can sign empty message."""
        signature = dilithium_sign(b"", dilithium_keypair.secret_key)
        is_valid = dilithium_verify(b"", signature, dilithium_keypair.public_key)

        assert is_valid is True

    def test_sign_large_message(self, dilithium_keypair):
        """Can sign large message."""
        large_message = b"x" * (1024 * 1024)  # 1 MB

        signature = dilithium_sign(large_message, dilithium_keypair.secret_key)
        is_valid = dilithium_verify(large_message, signature, dilithium_keypair.public_key)

        assert is_valid is True

    def test_keypair_uniqueness(self):
        """Each keypair is unique."""
        if not DILITHIUM_AVAILABLE:
            pytest.skip("Dilithium not available")

        kp1 = generate_dilithium_keypair()
        kp2 = generate_dilithium_keypair()

        assert kp1.public_key != kp2.public_key
        assert kp1.secret_key != kp2.secret_key


class TestDilithiumUnavailable:
    """Tests for Dilithium when backend is unavailable."""

    @pytest.fixture
    def mock_unavailable(self, monkeypatch):
        """Mock Dilithium as unavailable."""
        monkeypatch.setattr("ama_cryptography.pqc_backends.DILITHIUM_AVAILABLE", False)

    def test_generate_raises_error(self, mock_unavailable):
        """generate_dilithium_keypair raises when unavailable."""
        with pytest.raises(PQCUnavailableError, match="PQC_UNAVAILABLE"):
            generate_dilithium_keypair()

    def test_sign_raises_error(self, mock_unavailable):
        """dilithium_sign raises when unavailable."""
        with pytest.raises(PQCUnavailableError, match="PQC_UNAVAILABLE"):
            dilithium_sign(b"message", b"key")

    def test_verify_raises_error(self, mock_unavailable):
        """dilithium_verify raises when unavailable."""
        with pytest.raises(PQCUnavailableError, match="PQC_UNAVAILABLE"):
            dilithium_verify(b"message", b"signature", b"key")


# =============================================================================
# KYBER-1024 (ML-KEM) TESTS
# =============================================================================


class TestKyberOperations:
    """Tests for Kyber KEM operations."""

    @pytest.fixture
    def kyber_keypair(self):
        """Generate Kyber keypair for tests."""
        if not KYBER_AVAILABLE:
            pytest.skip("Kyber not available")
        return generate_kyber_keypair()

    def test_generate_keypair(self, kyber_keypair):
        """Generate Kyber keypair successfully."""
        assert len(kyber_keypair.public_key) == KYBER_PUBLIC_KEY_BYTES
        assert len(kyber_keypair.secret_key) == KYBER_SECRET_KEY_BYTES

    def test_encapsulate(self, kyber_keypair):
        """Encapsulate shared secret."""
        encap = kyber_encapsulate(kyber_keypair.public_key)

        assert len(encap.ciphertext) == KYBER_CIPHERTEXT_BYTES
        assert len(encap.shared_secret) == KYBER_SHARED_SECRET_BYTES

    def test_decapsulate(self, kyber_keypair):
        """Decapsulate shared secret."""
        encap = kyber_encapsulate(kyber_keypair.public_key)
        shared_secret = kyber_decapsulate(encap.ciphertext, kyber_keypair.secret_key)

        assert shared_secret == encap.shared_secret

    def test_encap_decap_roundtrip(self, kyber_keypair):
        """Full encapsulation/decapsulation roundtrip."""
        # Alice generates keypair
        alice_keypair = kyber_keypair

        # Bob encapsulates to Alice's public key
        encap = kyber_encapsulate(alice_keypair.public_key)

        # Alice decapsulates
        alice_secret = kyber_decapsulate(encap.ciphertext, alice_keypair.secret_key)

        # Both should have same shared secret
        assert alice_secret == encap.shared_secret

    def test_encapsulate_invalid_key_length(self):
        """Encapsulate raises on invalid key length."""
        if not KYBER_AVAILABLE:
            pytest.skip("Kyber not available")

        with pytest.raises(ValueError, match="Invalid public key length"):
            kyber_encapsulate(b"short")

    def test_decapsulate_invalid_ciphertext_length(self, kyber_keypair):
        """Decapsulate raises on invalid ciphertext length."""
        with pytest.raises(ValueError, match="Invalid ciphertext length"):
            kyber_decapsulate(b"short", kyber_keypair.secret_key)

    def test_decapsulate_invalid_key_length(self):
        """Decapsulate raises on invalid key length."""
        if not KYBER_AVAILABLE:
            pytest.skip("Kyber not available")

        with pytest.raises(ValueError, match="Invalid secret key length"):
            kyber_decapsulate(b"c" * KYBER_CIPHERTEXT_BYTES, b"short")

    def test_keypair_uniqueness(self):
        """Each keypair is unique."""
        if not KYBER_AVAILABLE:
            pytest.skip("Kyber not available")

        kp1 = generate_kyber_keypair()
        kp2 = generate_kyber_keypair()

        assert kp1.public_key != kp2.public_key
        assert kp1.secret_key != kp2.secret_key

    def test_encapsulation_uniqueness(self, kyber_keypair):
        """Each encapsulation produces unique result."""
        encap1 = kyber_encapsulate(kyber_keypair.public_key)
        encap2 = kyber_encapsulate(kyber_keypair.public_key)

        assert encap1.ciphertext != encap2.ciphertext
        assert encap1.shared_secret != encap2.shared_secret


class TestKyberUnavailable:
    """Tests for Kyber when backend is unavailable."""

    @pytest.fixture
    def mock_unavailable(self, monkeypatch):
        """Mock Kyber as unavailable."""
        monkeypatch.setattr("ama_cryptography.pqc_backends.KYBER_AVAILABLE", False)

    def test_generate_raises_error(self, mock_unavailable):
        """generate_kyber_keypair raises when unavailable."""
        with pytest.raises(KyberUnavailableError, match="KYBER_UNAVAILABLE"):
            generate_kyber_keypair()

    def test_encapsulate_raises_error(self, mock_unavailable):
        """kyber_encapsulate raises when unavailable."""
        with pytest.raises(KyberUnavailableError, match="KYBER_UNAVAILABLE"):
            kyber_encapsulate(b"k" * KYBER_PUBLIC_KEY_BYTES)

    def test_decapsulate_raises_error(self, mock_unavailable):
        """kyber_decapsulate raises when unavailable."""
        with pytest.raises(KyberUnavailableError, match="KYBER_UNAVAILABLE"):
            kyber_decapsulate(
                b"c" * KYBER_CIPHERTEXT_BYTES,
                b"k" * KYBER_SECRET_KEY_BYTES,
            )


# =============================================================================
# SPHINCS+-256f TESTS
# =============================================================================


class TestSphincsOperations:
    """Tests for SPHINCS+ signature operations."""

    @pytest.fixture
    def sphincs_keypair(self):
        """Generate SPHINCS+ keypair for tests."""
        if not SPHINCS_AVAILABLE:
            pytest.skip("SPHINCS+ not available")
        return generate_sphincs_keypair()

    def test_generate_keypair(self, sphincs_keypair):
        """Generate SPHINCS+ keypair successfully."""
        assert len(sphincs_keypair.public_key) == SPHINCS_PUBLIC_KEY_BYTES
        assert len(sphincs_keypair.secret_key) == SPHINCS_SECRET_KEY_BYTES

    def test_sign_and_verify(self, sphincs_keypair):
        """Sign message and verify signature."""
        message = b"Test message for SPHINCS+ signature"

        signature = sphincs_sign(message, sphincs_keypair.secret_key)
        assert len(signature) == SPHINCS_SIGNATURE_BYTES

        is_valid = sphincs_verify(message, signature, sphincs_keypair.public_key)
        assert is_valid is True

    def test_verify_wrong_message(self, sphincs_keypair):
        """Verification fails with wrong message."""
        message = b"Original message"
        wrong_message = b"Tampered message"

        signature = sphincs_sign(message, sphincs_keypair.secret_key)
        is_valid = sphincs_verify(wrong_message, signature, sphincs_keypair.public_key)

        assert is_valid is False

    def test_sign_invalid_key_length(self):
        """Sign raises on invalid key length."""
        if not SPHINCS_AVAILABLE:
            pytest.skip("SPHINCS+ not available")

        with pytest.raises(ValueError, match="Invalid secret key length"):
            sphincs_sign(b"message", b"short")

    def test_verify_invalid_key_length(self):
        """Verify raises on invalid key length."""
        if not SPHINCS_AVAILABLE:
            pytest.skip("SPHINCS+ not available")

        with pytest.raises(ValueError, match="Invalid public key length"):
            sphincs_verify(b"message", b"sig", b"short")

    def test_keypair_uniqueness(self):
        """Each keypair is unique."""
        if not SPHINCS_AVAILABLE:
            pytest.skip("SPHINCS+ not available")

        kp1 = generate_sphincs_keypair()
        kp2 = generate_sphincs_keypair()

        assert kp1.public_key != kp2.public_key
        assert kp1.secret_key != kp2.secret_key


class TestSphincsUnavailable:
    """Tests for SPHINCS+ when backend is unavailable."""

    @pytest.fixture
    def mock_unavailable(self, monkeypatch):
        """Mock SPHINCS+ as unavailable."""
        monkeypatch.setattr("ama_cryptography.pqc_backends.SPHINCS_AVAILABLE", False)

    def test_generate_raises_error(self, mock_unavailable):
        """generate_sphincs_keypair raises when unavailable."""
        with pytest.raises(SphincsUnavailableError, match="SPHINCS_UNAVAILABLE"):
            generate_sphincs_keypair()

    def test_sign_raises_error(self, mock_unavailable):
        """sphincs_sign raises when unavailable."""
        with pytest.raises(SphincsUnavailableError, match="SPHINCS_UNAVAILABLE"):
            sphincs_sign(b"message", b"k" * SPHINCS_SECRET_KEY_BYTES)

    def test_verify_raises_error(self, mock_unavailable):
        """sphincs_verify raises when unavailable."""
        with pytest.raises(SphincsUnavailableError, match="SPHINCS_UNAVAILABLE"):
            sphincs_verify(b"message", b"sig", b"k" * SPHINCS_PUBLIC_KEY_BYTES)


# =============================================================================
# BACKEND AVAILABILITY CONSISTENCY TESTS
# =============================================================================


class TestBackendConsistency:
    """Tests to verify backend availability is consistent."""

    def test_dilithium_backend_matches_availability(self):
        """Dilithium backend is set iff available."""
        if DILITHIUM_AVAILABLE:
            assert DILITHIUM_BACKEND == "native"
        else:
            assert DILITHIUM_BACKEND is None

    def test_kyber_backend_matches_availability(self):
        """Kyber backend is set iff available."""
        if KYBER_AVAILABLE:
            assert KYBER_BACKEND == "native"
        else:
            assert KYBER_BACKEND is None

    def test_sphincs_backend_matches_availability(self):
        """SPHINCS+ backend is set iff available."""
        if SPHINCS_AVAILABLE:
            assert SPHINCS_BACKEND == "native"
        else:
            assert SPHINCS_BACKEND is None

    def test_availability_constants_are_bool(self):
        """Availability constants are boolean."""
        assert isinstance(DILITHIUM_AVAILABLE, bool)
        assert isinstance(KYBER_AVAILABLE, bool)
        assert isinstance(SPHINCS_AVAILABLE, bool)
