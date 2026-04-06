#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Crypto API Coverage Tests
===========================

Coverage closure for ama_cryptography/crypto_api.py (target: >= 80%).
Tests providers, hybrid operations, AES-GCM nonce management, and edge cases.

AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
"""

import secrets
from unittest.mock import patch

import pytest

from ama_cryptography.pqc_backends import (
    _ED25519_NATIVE_AVAILABLE,
    DILITHIUM_AVAILABLE,
    KYBER_AVAILABLE,
    SPHINCS_AVAILABLE,
    _native_lib,
)

NATIVE_AVAILABLE = _native_lib is not None

skip_no_native = pytest.mark.skipif(not NATIVE_AVAILABLE, reason="Native C library not available")
skip_no_dilithium = pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium not available")
skip_no_kyber = pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber not available")
skip_no_sphincs = pytest.mark.skipif(not SPHINCS_AVAILABLE, reason="SPHINCS+ not available")
skip_no_ed25519 = pytest.mark.skipif(not _ED25519_NATIVE_AVAILABLE, reason="Ed25519 not available")


# ===========================================================================
# AlgorithmType and CryptoBackend Enum Tests
# ===========================================================================


class TestEnums:
    """Test crypto_api enums."""

    def test_algorithm_type_values(self) -> None:
        """AlgorithmType enum has expected members."""
        from ama_cryptography.crypto_api import AlgorithmType

        assert hasattr(AlgorithmType, "ML_DSA_65")
        assert hasattr(AlgorithmType, "ED25519")

    def test_crypto_backend_values(self) -> None:
        """CryptoBackend enum has expected members."""
        from ama_cryptography.crypto_api import CryptoBackend

        assert hasattr(CryptoBackend, "C_LIBRARY")
        assert hasattr(CryptoBackend, "CYTHON")
        assert hasattr(CryptoBackend, "PURE_PYTHON")


# ===========================================================================
# Container Dataclass Tests
# ===========================================================================


class TestContainers:
    """Test KeyPair, Signature, EncapsulatedSecret containers."""

    def test_keypair_container(self) -> None:
        """KeyPair stores public and secret keys."""
        from ama_cryptography.crypto_api import AlgorithmType, KeyPair

        kp = KeyPair(
            public_key=b"pk",
            secret_key=b"sk",
            algorithm=AlgorithmType.ED25519,
            metadata={},
        )
        assert kp.public_key == b"pk"
        assert kp.secret_key == b"sk"
        assert kp.algorithm == AlgorithmType.ED25519

    def test_signature_container(self) -> None:
        """Signature stores signature bytes and algorithm."""
        from ama_cryptography.crypto_api import AlgorithmType, Signature

        sig = Signature(
            signature=b"sig",
            algorithm=AlgorithmType.ML_DSA_65,
            message_hash=b"hash",
            metadata={},
        )
        assert sig.signature == b"sig"
        assert sig.algorithm == AlgorithmType.ML_DSA_65

    def test_encapsulated_secret_container(self) -> None:
        """EncapsulatedSecret stores ciphertext and shared_secret."""
        from ama_cryptography.crypto_api import AlgorithmType, EncapsulatedSecret

        enc = EncapsulatedSecret(
            ciphertext=b"ct",
            shared_secret=b"ss",
            algorithm=AlgorithmType.KYBER_1024,
            metadata={},
        )
        assert enc.ciphertext == b"ct"
        assert enc.shared_secret == b"ss"


# ===========================================================================
# MLDSAProvider Tests
# ===========================================================================


@skip_no_dilithium
class TestMLDSAProvider:
    """Test ML-DSA-65 provider."""

    def test_keygen(self) -> None:
        """MLDSAProvider generates valid keypairs."""
        from ama_cryptography.crypto_api import MLDSAProvider

        prov = MLDSAProvider()
        kp = prov.generate_keypair()
        assert len(kp.public_key) > 0
        assert len(kp.secret_key) > 0

    def test_sign_verify_roundtrip(self) -> None:
        """MLDSAProvider sign/verify roundtrip works."""
        from ama_cryptography.crypto_api import MLDSAProvider

        prov = MLDSAProvider()
        kp = prov.generate_keypair()
        sig = prov.sign(b"test message", kp.secret_key)
        assert prov.verify(b"test message", sig.signature, kp.public_key)

    def test_verify_wrong_message(self) -> None:
        """MLDSAProvider verify rejects wrong message."""
        from ama_cryptography.crypto_api import MLDSAProvider

        prov = MLDSAProvider()
        kp = prov.generate_keypair()
        sig = prov.sign(b"original", kp.secret_key)
        assert not prov.verify(b"tampered", sig.signature, kp.public_key)


# ===========================================================================
# Ed25519Provider Tests
# ===========================================================================


@skip_no_ed25519
class TestEd25519Provider:
    """Test Ed25519 provider."""

    def test_keygen(self) -> None:
        """Ed25519Provider generates valid keypairs."""
        from ama_cryptography.crypto_api import Ed25519Provider

        prov = Ed25519Provider()
        kp = prov.generate_keypair()
        assert len(kp.public_key) == 32
        assert len(kp.secret_key) == 32

    def test_sign_verify(self) -> None:
        """Ed25519Provider sign/verify roundtrip."""
        from ama_cryptography.crypto_api import Ed25519Provider

        prov = Ed25519Provider()
        kp = prov.generate_keypair()
        sig = prov.sign(b"message", kp.secret_key)
        assert prov.verify(b"message", sig.signature, kp.public_key)

    def test_keygen_deterministic(self) -> None:
        """Ed25519Provider keygen produces valid key sizes."""
        from ama_cryptography.crypto_api import Ed25519Provider

        prov = Ed25519Provider()
        kp = prov.generate_keypair()
        assert len(kp.public_key) == 32
        assert len(kp.secret_key) == 32
        assert kp.public_key != kp.secret_key


# ===========================================================================
# KyberProvider Tests
# ===========================================================================


@skip_no_kyber
class TestKyberProvider:
    """Test Kyber-1024 KEM provider."""

    def test_keygen(self) -> None:
        """KyberProvider generates valid keypairs."""
        from ama_cryptography.crypto_api import KyberProvider

        prov = KyberProvider()
        kp = prov.generate_keypair()
        assert len(kp.public_key) > 0
        assert len(kp.secret_key) > 0

    def test_encaps_decaps_roundtrip(self) -> None:
        """KyberProvider encaps/decaps roundtrip works."""
        from ama_cryptography.crypto_api import KyberProvider

        prov = KyberProvider()
        kp = prov.generate_keypair()
        enc = prov.encapsulate(kp.public_key)
        ss = prov.decapsulate(enc.ciphertext, kp.secret_key)
        assert ss == enc.shared_secret


# ===========================================================================
# SphincsProvider Tests
# ===========================================================================


@skip_no_sphincs
class TestSphincsProvider:
    """Test SPHINCS+ provider."""

    def test_keygen(self) -> None:
        """SphincsProvider generates valid keypairs."""
        from ama_cryptography.crypto_api import SphincsProvider

        prov = SphincsProvider()
        kp = prov.generate_keypair()
        assert len(kp.public_key) == 64
        assert len(kp.secret_key) == 128

    def test_sign_verify_roundtrip(self) -> None:
        """SphincsProvider sign/verify roundtrip."""
        from ama_cryptography.crypto_api import SphincsProvider

        prov = SphincsProvider()
        kp = prov.generate_keypair()
        sig = prov.sign(b"sphincs test", kp.secret_key)
        assert prov.verify(b"sphincs test", sig.signature, kp.public_key)


# ===========================================================================
# AESGCMProvider Tests
# ===========================================================================


@skip_no_native
class TestAESGCMProvider:
    """Test AES-256-GCM provider."""

    def test_encrypt_decrypt_roundtrip(self) -> None:
        """AESGCMProvider encrypt/decrypt roundtrip."""
        from ama_cryptography.crypto_api import AESGCMProvider

        prov = AESGCMProvider()
        key = secrets.token_bytes(32)
        pt = b"plaintext for AES-GCM"
        aad = b"associated data"

        result = prov.encrypt(pt, key, aad=aad)
        decrypted = prov.decrypt(result["ciphertext"], key, result["nonce"], result["tag"], aad=aad)
        assert decrypted == pt

    def test_empty_plaintext(self) -> None:
        """AESGCMProvider handles empty plaintext."""
        from ama_cryptography.crypto_api import AESGCMProvider

        prov = AESGCMProvider()
        key = secrets.token_bytes(32)

        result = prov.encrypt(b"", key)
        decrypted = prov.decrypt(result["ciphertext"], key, result["nonce"], result["tag"])
        assert decrypted == b""

    def test_tampered_ciphertext_fails(self) -> None:
        """AESGCMProvider detects tampered ciphertext."""
        from ama_cryptography.crypto_api import AESGCMProvider

        prov = AESGCMProvider()
        key = secrets.token_bytes(32)

        result = prov.encrypt(b"secret", key)
        bad_ct = bytearray(result["ciphertext"])
        if len(bad_ct) > 0:
            bad_ct[0] ^= 0xFF
        with pytest.raises((ValueError, RuntimeError)):
            prov.decrypt(bytes(bad_ct), key, result["nonce"], result["tag"])


# ===========================================================================
# HybridKEMProvider Tests
# ===========================================================================


@skip_no_native
class TestHybridKEMProvider:
    """Test HybridKEMProvider combining classical and PQC."""

    def test_keygen(self) -> None:
        """HybridKEMProvider generates keypairs."""
        from ama_cryptography.crypto_api import HybridKEMProvider

        prov = HybridKEMProvider()
        kp = prov.generate_keypair()
        assert len(kp.public_key) > 0
        assert len(kp.secret_key) > 0

    def test_encaps_decaps_roundtrip(self) -> None:
        """HybridKEMProvider encaps/decaps roundtrip."""
        from ama_cryptography.crypto_api import HybridKEMProvider

        prov = HybridKEMProvider()
        kp = prov.generate_keypair()
        enc = prov.encapsulate(kp.public_key)
        ss = prov.decapsulate(enc.ciphertext, kp.secret_key)
        assert ss == enc.shared_secret
        assert len(ss) == 32


# ===========================================================================
# HybridSignatureProvider Tests
# ===========================================================================


@skip_no_native
class TestHybridSignatureProvider:
    """Test HybridSignatureProvider combining classical and PQC."""

    def test_keygen(self) -> None:
        """HybridSignatureProvider generates keypairs."""
        from ama_cryptography.crypto_api import HybridSignatureProvider

        prov = HybridSignatureProvider()
        kp = prov.generate_keypair()
        assert len(kp.public_key) > 0
        assert len(kp.secret_key) > 0

    def test_sign_verify_roundtrip(self) -> None:
        """HybridSignatureProvider sign/verify roundtrip."""
        from ama_cryptography.crypto_api import HybridSignatureProvider

        prov = HybridSignatureProvider()
        kp = prov.generate_keypair()
        sig = prov.sign(b"hybrid sig test", kp.secret_key)
        assert prov.verify(b"hybrid sig test", sig.signature, kp.public_key)

    def test_verify_tampered_message(self) -> None:
        """HybridSignatureProvider rejects tampered message."""
        from ama_cryptography.crypto_api import HybridSignatureProvider

        prov = HybridSignatureProvider()
        kp = prov.generate_keypair()
        sig = prov.sign(b"original", kp.secret_key)
        assert not prov.verify(b"tampered", sig.signature, kp.public_key)


# ===========================================================================
# AmaCryptography Unified API Tests
# ===========================================================================


@skip_no_native
class TestAmaCryptography:
    """Test the unified AmaCryptography API class."""

    def test_create_instance(self) -> None:
        """AmaCryptography can be instantiated."""
        from ama_cryptography.crypto_api import AmaCryptography

        api = AmaCryptography()
        assert api is not None
        assert api.backend is not None
        assert api.algorithm is not None

    def test_sign_verify_roundtrip(self) -> None:
        """AmaCryptography sign/verify roundtrip."""
        from ama_cryptography.crypto_api import AmaCryptography

        api = AmaCryptography()
        kp = api.generate_keypair()
        sig = api.sign(b"test payload", kp.secret_key)
        assert api.verify(b"test payload", sig.signature, kp.public_key)

    def test_backend_is_c_library(self) -> None:
        """AmaCryptography reports C_LIBRARY backend."""
        from ama_cryptography.crypto_api import AmaCryptography, CryptoBackend

        api = AmaCryptography()
        assert api.backend == CryptoBackend.C_LIBRARY


# ===========================================================================
# _enforce_invariant7 Tests
# ===========================================================================


class TestEnforceInvariant7:
    """Test _enforce_invariant7 call-time enforcement."""

    def test_invariant7_when_native_none(self) -> None:
        """_enforce_invariant7 raises when _native_lib is None."""
        from ama_cryptography.crypto_api import _enforce_invariant7

        with patch("ama_cryptography.pqc_backends._native_lib", None):
            with pytest.raises(RuntimeError, match="INVARIANT"):
                _enforce_invariant7()
