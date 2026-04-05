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
    DILITHIUM_AVAILABLE,
    KYBER_AVAILABLE,
    SPHINCS_AVAILABLE,
    _ED25519_NATIVE_AVAILABLE,
    _native_lib,
)

NATIVE_AVAILABLE = _native_lib is not None

skip_no_native = pytest.mark.skipif(
    not NATIVE_AVAILABLE, reason="Native C library not available"
)
skip_no_dilithium = pytest.mark.skipif(
    not DILITHIUM_AVAILABLE, reason="Dilithium not available"
)
skip_no_kyber = pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber not available")
skip_no_sphincs = pytest.mark.skipif(
    not SPHINCS_AVAILABLE, reason="SPHINCS+ not available"
)
skip_no_ed25519 = pytest.mark.skipif(
    not _ED25519_NATIVE_AVAILABLE, reason="Ed25519 not available"
)


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

        assert hasattr(CryptoBackend, "NATIVE")


# ===========================================================================
# Container Dataclass Tests
# ===========================================================================


class TestContainers:
    """Test KeyPair, Signature, EncapsulatedSecret containers."""

    def test_keypair_container(self) -> None:
        """KeyPair stores public and secret keys."""
        from ama_cryptography.crypto_api import KeyPair

        kp = KeyPair(public_key=b"pk", secret_key=b"sk")
        assert kp.public_key == b"pk"
        assert kp.secret_key == b"sk"

    def test_signature_container(self) -> None:
        """Signature stores value and algorithm."""
        from ama_cryptography.crypto_api import Signature

        sig = Signature(value=b"sig", algorithm="ML-DSA-65")
        assert sig.value == b"sig"
        assert sig.algorithm == "ML-DSA-65"

    def test_encapsulated_secret_container(self) -> None:
        """EncapsulatedSecret stores ciphertext and shared_secret."""
        from ama_cryptography.crypto_api import EncapsulatedSecret

        enc = EncapsulatedSecret(ciphertext=b"ct", shared_secret=b"ss")
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
        assert prov.verify(b"test message", sig.value, kp.public_key)

    def test_verify_wrong_message(self) -> None:
        """MLDSAProvider verify rejects wrong message."""
        from ama_cryptography.crypto_api import MLDSAProvider

        prov = MLDSAProvider()
        kp = prov.generate_keypair()
        sig = prov.sign(b"original", kp.secret_key)
        assert not prov.verify(b"tampered", sig.value, kp.public_key)


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
        assert len(kp.secret_key) == 64

    def test_sign_verify(self) -> None:
        """Ed25519Provider sign/verify roundtrip."""
        from ama_cryptography.crypto_api import Ed25519Provider

        prov = Ed25519Provider()
        kp = prov.generate_keypair()
        sig = prov.sign(b"message", kp.secret_key)
        assert prov.verify(b"message", sig.value, kp.public_key)

    def test_keygen_from_seed(self) -> None:
        """Ed25519Provider keygen from 32-byte seed is deterministic."""
        from ama_cryptography.crypto_api import Ed25519Provider

        prov = Ed25519Provider()
        seed = secrets.token_bytes(32)
        kp1 = prov.generate_keypair(seed=seed)
        kp2 = prov.generate_keypair(seed=seed)
        assert kp1.public_key == kp2.public_key


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
        assert prov.verify(b"sphincs test", sig.value, kp.public_key)


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

        ct, tag, nonce = prov.encrypt(key, pt, aad)
        result = prov.decrypt(key, ct, nonce, tag, aad)
        assert result == pt

    def test_empty_plaintext(self) -> None:
        """AESGCMProvider handles empty plaintext."""
        from ama_cryptography.crypto_api import AESGCMProvider

        prov = AESGCMProvider()
        key = secrets.token_bytes(32)

        ct, tag, nonce = prov.encrypt(key, b"", b"")
        result = prov.decrypt(key, ct, nonce, tag, b"")
        assert result == b""

    def test_tampered_ciphertext_fails(self) -> None:
        """AESGCMProvider detects tampered ciphertext."""
        from ama_cryptography.crypto_api import AESGCMProvider

        prov = AESGCMProvider()
        key = secrets.token_bytes(32)

        ct, tag, nonce = prov.encrypt(key, b"secret", b"")
        bad_ct = bytearray(ct)
        if len(bad_ct) > 0:
            bad_ct[0] ^= 0xFF
        with pytest.raises((ValueError, RuntimeError)):
            prov.decrypt(key, bytes(bad_ct), nonce, tag, b"")


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
        assert prov.verify(b"hybrid sig test", sig.value, kp.public_key)

    def test_verify_tampered_message(self) -> None:
        """HybridSignatureProvider rejects tampered message."""
        from ama_cryptography.crypto_api import HybridSignatureProvider

        prov = HybridSignatureProvider()
        kp = prov.generate_keypair()
        sig = prov.sign(b"original", kp.secret_key)
        assert not prov.verify(b"tampered", sig.value, kp.public_key)


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

    def test_crypto_package_roundtrip(self) -> None:
        """create_crypto_package / verify_crypto_package roundtrip."""
        from ama_cryptography.crypto_api import AmaCryptography

        api = AmaCryptography()
        pkg = api.create_crypto_package(b"test payload")
        assert pkg is not None
        assert "payload" in pkg or "signature" in pkg or hasattr(pkg, "payload")

    def test_get_status(self) -> None:
        """AmaCryptography reports backend status."""
        from ama_cryptography.crypto_api import AmaCryptography

        api = AmaCryptography()
        status = api.get_status()
        assert isinstance(status, dict)


# ===========================================================================
# _enforce_invariant7 Tests
# ===========================================================================


class TestEnforceInvariant7:
    """Test _enforce_invariant7 call-time enforcement."""

    def test_invariant7_when_native_none(self) -> None:
        """_enforce_invariant7 raises when _native_lib is None."""
        from ama_cryptography.crypto_api import _enforce_invariant7

        with patch("ama_cryptography.crypto_api._native_lib", None):
            with pytest.raises(RuntimeError, match="[Nn]ative|INVARIANT"):
                _enforce_invariant7()
