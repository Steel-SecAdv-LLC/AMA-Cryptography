#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
PQC Backends Coverage Tests
=============================

Coverage closure for ama_cryptography/pqc_backends.py (target: >= 85%).
Tests platform detection, library loading, error paths, key sizes, and
all public cryptographic functions.

AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ama_cryptography.pqc_backends import (
    DILITHIUM_AVAILABLE,
    DILITHIUM_PUBLIC_KEY_BYTES,
    DILITHIUM_SECRET_KEY_BYTES,
    DILITHIUM_SIGNATURE_BYTES,
    KYBER_AVAILABLE,
    KYBER_CIPHERTEXT_BYTES,
    KYBER_PUBLIC_KEY_BYTES,
    KYBER_SECRET_KEY_BYTES,
    KYBER_SHARED_SECRET_BYTES,
    SPHINCS_AVAILABLE,
    SPHINCS_PUBLIC_KEY_BYTES,
    SPHINCS_SECRET_KEY_BYTES,
    SPHINCS_SIGNATURE_BYTES,
    DilithiumKeyPair,
    KyberEncapsulation,
    KyberKeyPair,
    PQCStatus,
    SphincsKeyPair,
    _get_lib_names,
    _get_search_dirs,
    _native_lib,
    _secure_memzero,
    _setup_native_ctypes,
    _try_load_library,
    get_pqc_backend_info,
    get_pqc_status,
)

NATIVE_AVAILABLE = _native_lib is not None

skip_no_native = pytest.mark.skipif(not NATIVE_AVAILABLE, reason="Native C library not available")
skip_no_dilithium = pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium not available")
skip_no_kyber = pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber not available")
skip_no_sphincs = pytest.mark.skipif(not SPHINCS_AVAILABLE, reason="SPHINCS+ not available")


# ===========================================================================
# Platform Detection Tests
# ===========================================================================


class TestPlatformDetection:
    """Test _get_lib_names and _get_search_dirs on different platforms."""

    def test_get_lib_names_linux(self) -> None:
        """Linux returns .so library names."""
        with patch("ama_cryptography.pqc_backends.platform.system", return_value="Linux"):
            names = _get_lib_names()
            assert "libama_cryptography.so" in names

    def test_get_lib_names_darwin(self) -> None:
        """macOS returns .dylib and .so library names."""
        with patch("ama_cryptography.pqc_backends.platform.system", return_value="Darwin"):
            names = _get_lib_names()
            assert "libama_cryptography.dylib" in names
            assert "libama_cryptography.so" in names

    def test_get_lib_names_windows(self) -> None:
        """Windows returns .dll library names."""
        with patch("ama_cryptography.pqc_backends.platform.system", return_value="Windows"):
            names = _get_lib_names()
            assert any(".dll" in n for n in names)

    def test_get_search_dirs_includes_build(self) -> None:
        """Search dirs include build directories."""
        dirs = _get_search_dirs()
        assert len(dirs) > 0
        dir_strs = [str(d) for d in dirs]
        assert any("build" in s for s in dir_strs)

    @pytest.mark.skipif(sys.platform == "win32", reason="LD_LIBRARY_PATH is Unix-only")
    def test_get_search_dirs_with_ld_library_path(self) -> None:
        """LD_LIBRARY_PATH entries are included in search dirs."""
        with patch.dict("os.environ", {"LD_LIBRARY_PATH": "/custom/lib:/another/lib"}):
            dirs = _get_search_dirs()
            dir_strs = [str(d) for d in dirs]
            assert any("/custom/lib" in s for s in dir_strs)

    @pytest.mark.skipif(sys.platform == "win32", reason="DYLD_LIBRARY_PATH is Unix-only")
    def test_get_search_dirs_with_dyld_library_path(self) -> None:
        """DYLD_LIBRARY_PATH entries are included in search dirs."""
        with patch.dict("os.environ", {"DYLD_LIBRARY_PATH": "/dyld/path"}):
            dirs = _get_search_dirs()
            dir_strs = [str(d) for d in dirs]
            assert any("/dyld/path" in s for s in dir_strs)


# ===========================================================================
# Library Loading Tests
# ===========================================================================


class TestLibraryLoading:
    """Test _try_load_library and _find_native_library paths."""

    def test_try_load_library_failure(self) -> None:
        """_try_load_library returns None for nonexistent file."""
        result = _try_load_library(Path("/nonexistent/libfake.so"))
        assert result is None

    def test_try_load_library_oserror(self) -> None:
        """_try_load_library returns None when CDLL raises OSError."""
        with patch("ama_cryptography.pqc_backends.ctypes.CDLL", side_effect=OSError("test")):
            result = _try_load_library(Path("/some/lib.so"))
            assert result is None

    def test_setup_native_ctypes_missing_attribute(self) -> None:
        """_setup_native_ctypes returns False if lib lacks symbols."""
        mock_lib = MagicMock(spec=[])  # Empty spec — no attributes
        # Accessing ama_dilithium_keypair will raise AttributeError
        del mock_lib.ama_dilithium_keypair
        result = _setup_native_ctypes(mock_lib)
        assert result is False

    def test_find_native_library_with_env_override_file(self) -> None:
        """AMA_CRYPTO_LIB_PATH pointing to a file is tried first."""
        from ama_cryptography.pqc_backends import _find_native_library

        with patch.dict("os.environ", {"AMA_CRYPTO_LIB_PATH": "/fake/path/lib.so"}):
            with patch("ama_cryptography.pqc_backends.Path.is_file", return_value=True):
                with patch("ama_cryptography.pqc_backends._try_load_library", return_value=None):
                    # Should not crash even if loading fails
                    _find_native_library()

    def test_find_native_library_with_env_override_dir(self) -> None:
        """AMA_CRYPTO_LIB_PATH pointing to a directory is searched."""
        from ama_cryptography.pqc_backends import _find_native_library

        with patch.dict("os.environ", {"AMA_CRYPTO_LIB_PATH": "/fake/dir"}):
            with patch("ama_cryptography.pqc_backends.Path.is_file", return_value=False):
                with patch("ama_cryptography.pqc_backends.Path.is_dir", return_value=True):
                    _find_native_library()
                    # Returns None because no real library at /fake/dir
                    # but shouldn't crash


# ===========================================================================
# _secure_memzero Tests
# ===========================================================================


class TestSecureMemzero:
    """Test the standalone _secure_memzero in pqc_backends."""

    def test_zeroes_bytearray(self) -> None:
        """_secure_memzero fills bytearray with zeros."""
        buf = bytearray(b"\xaa\xbb\xcc\xdd")
        _secure_memzero(buf)
        assert all(b == 0 for b in buf)

    def test_empty_bytearray(self) -> None:
        """_secure_memzero handles empty bytearray."""
        buf = bytearray()
        _secure_memzero(buf)
        assert len(buf) == 0


# ===========================================================================
# KeyPair Tests
# ===========================================================================


class TestKeyPairLifecycle:
    """Test KeyPair dataclasses: creation, wipe, __del__."""

    def test_dilithium_keypair_bytes_to_bytearray(self) -> None:
        """DilithiumKeyPair converts bytes secret_key to bytearray."""
        sk = b"\x01" * DILITHIUM_SECRET_KEY_BYTES
        pk = b"\x02" * DILITHIUM_PUBLIC_KEY_BYTES
        kp = DilithiumKeyPair(secret_key=sk, public_key=pk)
        assert isinstance(kp.secret_key, bytearray)

    def test_kyber_keypair_bytes_to_bytearray(self) -> None:
        """KyberKeyPair converts bytes secret_key to bytearray."""
        sk = b"\x01" * KYBER_SECRET_KEY_BYTES
        pk = b"\x02" * KYBER_PUBLIC_KEY_BYTES
        kp = KyberKeyPair(secret_key=sk, public_key=pk)
        assert isinstance(kp.secret_key, bytearray)

    def test_sphincs_keypair_bytes_to_bytearray(self) -> None:
        """SphincsKeyPair converts bytes secret_key to bytearray."""
        sk = b"\x01" * SPHINCS_SECRET_KEY_BYTES
        pk = b"\x02" * SPHINCS_PUBLIC_KEY_BYTES
        kp = SphincsKeyPair(secret_key=sk, public_key=pk)
        assert isinstance(kp.secret_key, bytearray)

    def test_dilithium_keypair_wipe(self) -> None:
        """DilithiumKeyPair.wipe() zeroes the secret key."""
        kp = DilithiumKeyPair(
            secret_key=bytearray(b"\xaa" * DILITHIUM_SECRET_KEY_BYTES),
            public_key=b"\x00" * DILITHIUM_PUBLIC_KEY_BYTES,
        )
        kp.wipe()
        assert all(b == 0 for b in kp.secret_key)

    def test_kyber_keypair_wipe(self) -> None:
        """KyberKeyPair.wipe() zeroes the secret key."""
        kp = KyberKeyPair(
            secret_key=bytearray(b"\xaa" * KYBER_SECRET_KEY_BYTES),
            public_key=b"\x00" * KYBER_PUBLIC_KEY_BYTES,
        )
        kp.wipe()
        assert all(b == 0 for b in kp.secret_key)

    def test_sphincs_keypair_wipe(self) -> None:
        """SphincsKeyPair.wipe() zeroes the secret key."""
        kp = SphincsKeyPair(
            secret_key=bytearray(b"\xaa" * SPHINCS_SECRET_KEY_BYTES),
            public_key=b"\x00" * SPHINCS_PUBLIC_KEY_BYTES,
        )
        kp.wipe()
        assert all(b == 0 for b in kp.secret_key)

    def test_wipe_already_wiped(self) -> None:
        """Wiping an already-wiped keypair does not crash."""
        kp = DilithiumKeyPair(
            secret_key=bytearray(DILITHIUM_SECRET_KEY_BYTES),
            public_key=b"\x00" * DILITHIUM_PUBLIC_KEY_BYTES,
        )
        kp.wipe()
        kp.wipe()  # Second wipe should be a no-op (all zeros)

    def test_wipe_empty_bytearray(self) -> None:
        """Wiping a keypair with empty secret_key does not crash."""
        kp = DilithiumKeyPair(
            secret_key=bytearray(),
            public_key=b"\x00" * DILITHIUM_PUBLIC_KEY_BYTES,
        )
        kp.wipe()  # len == 0, should be no-op

    def test_keypair_del_calls_wipe(self) -> None:
        """__del__ calls wipe without raising.

        Uses ``del`` to trigger the finalizer code path that calls wipe().
        This verifies the finalizer does not raise when the GC invokes
        it. (PBC-001)
        """
        kp = DilithiumKeyPair(
            secret_key=bytearray(b"\xaa" * DILITHIUM_SECRET_KEY_BYTES),
            public_key=b"\x00" * DILITHIUM_PUBLIC_KEY_BYTES,
        )
        del kp  # Trigger GC finalizer path (PBC-001)

    def test_kyber_encapsulation_dataclass(self) -> None:
        """KyberEncapsulation stores ciphertext and shared_secret."""
        enc = KyberEncapsulation(ciphertext=b"\x01" * 1568, shared_secret=b"\x02" * 32)
        assert len(enc.ciphertext) == 1568
        assert len(enc.shared_secret) == 32


# ===========================================================================
# PQC Status and Backend Info Tests
# ===========================================================================


class TestPQCStatusAndInfo:
    """Test get_pqc_status and get_pqc_backend_info."""

    @skip_no_native
    def test_pqc_status_available(self) -> None:
        """PQC status is AVAILABLE when backends are loaded."""
        assert get_pqc_status() == PQCStatus.AVAILABLE

    @skip_no_native
    def test_backend_info_structure(self) -> None:
        """get_pqc_backend_info returns expected dict structure."""
        info = get_pqc_backend_info()
        assert "status" in info
        assert "dilithium_available" in info
        assert "kyber_available" in info
        assert "sphincs_available" in info
        assert "algorithms" in info
        assert "ML-DSA-65" in info["algorithms"]
        assert "Kyber-1024" in info["algorithms"]
        assert "SPHINCS+-256f" in info["algorithms"]

    @skip_no_native
    def test_backend_info_key_sizes(self) -> None:
        """Backend info includes correct key sizes."""
        info = get_pqc_backend_info()
        dil = info["algorithms"]["ML-DSA-65"]
        if dil["available"]:
            assert dil["key_sizes"]["public_key"] == DILITHIUM_PUBLIC_KEY_BYTES
            assert dil["key_sizes"]["secret_key"] == DILITHIUM_SECRET_KEY_BYTES
            assert dil["key_sizes"]["signature"] == DILITHIUM_SIGNATURE_BYTES

    def test_pqc_status_unavailable(self) -> None:
        """PQC status is UNAVAILABLE when no backends are loaded."""
        with patch("ama_cryptography.pqc_backends.DILITHIUM_AVAILABLE", False):
            with patch("ama_cryptography.pqc_backends.KYBER_AVAILABLE", False):
                with patch("ama_cryptography.pqc_backends.SPHINCS_AVAILABLE", False):
                    assert get_pqc_status() == PQCStatus.UNAVAILABLE


# ===========================================================================
# Crypto Function Tests — Dilithium
# ===========================================================================


@skip_no_dilithium
class TestDilithiumFunctions:
    """Test Dilithium keygen, sign, verify with valid and invalid inputs."""

    def test_keygen(self) -> None:
        """generate_dilithium_keypair produces correctly-sized keys."""
        from ama_cryptography.pqc_backends import generate_dilithium_keypair

        kp = generate_dilithium_keypair()
        assert len(kp.public_key) == DILITHIUM_PUBLIC_KEY_BYTES
        assert len(kp.secret_key) == DILITHIUM_SECRET_KEY_BYTES

    def test_sign_verify_roundtrip(self) -> None:
        """Sign then verify succeeds."""
        from ama_cryptography.pqc_backends import (
            dilithium_sign,
            dilithium_verify,
            generate_dilithium_keypair,
        )

        kp = generate_dilithium_keypair()
        sig = dilithium_sign(b"test message", kp.secret_key)
        assert len(sig) == DILITHIUM_SIGNATURE_BYTES
        assert dilithium_verify(b"test message", sig, kp.public_key)

    def test_verify_wrong_message(self) -> None:
        """Verify with wrong message fails."""
        from ama_cryptography.pqc_backends import (
            dilithium_sign,
            dilithium_verify,
            generate_dilithium_keypair,
        )

        kp = generate_dilithium_keypair()
        sig = dilithium_sign(b"original", kp.secret_key)
        assert not dilithium_verify(b"tampered", sig, kp.public_key)

    def test_sign_wrong_key_size(self) -> None:
        """Sign with wrong-size key raises ValueError."""
        from ama_cryptography.pqc_backends import dilithium_sign

        with pytest.raises(ValueError, match=r"[Ss]ecret.key"):
            dilithium_sign(b"msg", b"\x00" * 10)

    def test_verify_wrong_key_size(self) -> None:
        """Verify with wrong-size public key raises ValueError."""
        from ama_cryptography.pqc_backends import dilithium_verify

        with pytest.raises(ValueError, match=r"[Pp]ublic.key"):
            dilithium_verify(b"msg", b"\x00" * DILITHIUM_SIGNATURE_BYTES, b"\x00" * 10)


# ===========================================================================
# Crypto Function Tests — Kyber
# ===========================================================================


@skip_no_kyber
class TestKyberFunctions:
    """Test Kyber keygen, encaps, decaps with valid and invalid inputs."""

    def test_keygen(self) -> None:
        """generate_kyber_keypair produces correctly-sized keys."""
        from ama_cryptography.pqc_backends import generate_kyber_keypair

        kp = generate_kyber_keypair()
        assert len(kp.public_key) == KYBER_PUBLIC_KEY_BYTES
        assert len(kp.secret_key) == KYBER_SECRET_KEY_BYTES

    def test_encaps_decaps_roundtrip(self) -> None:
        """Encapsulate then decapsulate recovers shared secret."""
        from ama_cryptography.pqc_backends import (
            generate_kyber_keypair,
            kyber_decapsulate,
            kyber_encapsulate,
        )

        kp = generate_kyber_keypair()
        enc = kyber_encapsulate(kp.public_key)
        assert len(enc.ciphertext) == KYBER_CIPHERTEXT_BYTES
        assert len(enc.shared_secret) == KYBER_SHARED_SECRET_BYTES

        ss = kyber_decapsulate(enc.ciphertext, kp.secret_key)
        assert ss == enc.shared_secret

    def test_encapsulate_wrong_pk_size(self) -> None:
        """Encapsulate with wrong-size public key raises ValueError."""
        from ama_cryptography.pqc_backends import kyber_encapsulate

        with pytest.raises(ValueError, match=r"[Pp]ublic.key"):
            kyber_encapsulate(b"\x00" * 10)

    def test_decapsulate_wrong_sk_size(self) -> None:
        """Decapsulate with wrong-size secret key raises ValueError."""
        from ama_cryptography.pqc_backends import kyber_decapsulate

        with pytest.raises(ValueError, match=r"[Ss]ecret.key"):
            kyber_decapsulate(b"\x00" * KYBER_CIPHERTEXT_BYTES, b"\x00" * 10)

    def test_decapsulate_wrong_ct_size(self) -> None:
        """Decapsulate with wrong-size ciphertext raises ValueError."""
        from ama_cryptography.pqc_backends import kyber_decapsulate

        with pytest.raises(ValueError, match=r"[Cc]iphertext"):
            kyber_decapsulate(b"\x00" * 10, b"\x00" * KYBER_SECRET_KEY_BYTES)


# ===========================================================================
# Crypto Function Tests — SPHINCS+
# ===========================================================================


@skip_no_sphincs
class TestSphincsFunctions:
    """Test SPHINCS+ keygen, sign, verify with valid and invalid inputs."""

    def test_keygen(self) -> None:
        """generate_sphincs_keypair produces correctly-sized keys."""
        from ama_cryptography.pqc_backends import generate_sphincs_keypair

        kp = generate_sphincs_keypair()
        assert len(kp.public_key) == SPHINCS_PUBLIC_KEY_BYTES
        assert len(kp.secret_key) == SPHINCS_SECRET_KEY_BYTES

    def test_sign_verify_roundtrip(self) -> None:
        """Sign then verify succeeds."""
        from ama_cryptography.pqc_backends import (
            generate_sphincs_keypair,
            sphincs_sign,
            sphincs_verify,
        )

        kp = generate_sphincs_keypair()
        sig = sphincs_sign(b"test message", kp.secret_key)
        assert len(sig) == SPHINCS_SIGNATURE_BYTES
        assert sphincs_verify(b"test message", sig, kp.public_key)

    def test_sign_wrong_key_size(self) -> None:
        """Sign with wrong-size key raises ValueError."""
        from ama_cryptography.pqc_backends import sphincs_sign

        with pytest.raises(ValueError, match=r"[Ss]ecret.key"):
            sphincs_sign(b"msg", b"\x00" * 10)

    def test_verify_wrong_key_size(self) -> None:
        """Verify with wrong-size public key raises ValueError."""
        from ama_cryptography.pqc_backends import sphincs_verify

        with pytest.raises(ValueError, match=r"[Pp]ublic.key"):
            sphincs_verify(b"msg", b"\x00" * SPHINCS_SIGNATURE_BYTES, b"\x00" * 10)


# ===========================================================================
# Ed25519 Function Tests
# ===========================================================================


@skip_no_native
class TestEd25519Functions:
    """Test Ed25519 native functions."""

    def test_keypair(self) -> None:
        """Ed25519 keypair generation works."""
        from ama_cryptography.pqc_backends import native_ed25519_keypair

        pk, sk = native_ed25519_keypair()
        assert len(pk) == 32
        assert len(sk) == 64

    def test_sign_verify(self) -> None:
        """Ed25519 sign/verify roundtrip."""
        from ama_cryptography.pqc_backends import (
            native_ed25519_keypair,
            native_ed25519_sign,
            native_ed25519_verify,
        )

        pk, sk = native_ed25519_keypair()
        sig = native_ed25519_sign(b"hello", sk)
        assert len(sig) == 64
        assert native_ed25519_verify(sig, b"hello", pk)

    def test_verify_tampered(self) -> None:
        """Ed25519 verify rejects tampered signatures."""
        from ama_cryptography.pqc_backends import (
            native_ed25519_keypair,
            native_ed25519_sign,
            native_ed25519_verify,
        )

        pk, sk = native_ed25519_keypair()
        sig = native_ed25519_sign(b"hello", sk)
        bad_sig = bytearray(sig)
        bad_sig[0] ^= 0xFF
        assert not native_ed25519_verify(bytes(bad_sig), b"hello", pk)


# ===========================================================================
# AES-256-GCM Function Tests
# ===========================================================================


@skip_no_native
class TestAESGCMFunctions:
    """Test AES-256-GCM native functions."""

    def test_encrypt_decrypt_roundtrip(self) -> None:
        """AES-256-GCM encrypt then decrypt recovers plaintext."""
        import secrets

        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"secret data for AES-GCM"
        aad = b"associated data"

        ct, tag = native_aes256_gcm_encrypt(key, nonce, plaintext, aad)
        pt = native_aes256_gcm_decrypt(key, nonce, ct, tag, aad)
        assert pt == plaintext

    def test_decrypt_tampered_tag(self) -> None:
        """Tampered tag causes decryption failure."""
        import secrets

        from ama_cryptography.pqc_backends import (
            native_aes256_gcm_decrypt,
            native_aes256_gcm_encrypt,
        )

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        ct, tag = native_aes256_gcm_encrypt(key, nonce, b"data", b"")

        bad_tag = bytearray(tag)
        bad_tag[0] ^= 0xFF
        with pytest.raises((ValueError, RuntimeError)):
            native_aes256_gcm_decrypt(key, nonce, ct, bytes(bad_tag), b"")


# ===========================================================================
# HKDF Function Tests
# ===========================================================================


@skip_no_native
class TestHKDFFunctions:
    """Test HKDF native function."""

    def test_hkdf_basic(self) -> None:
        """HKDF produces output of requested length."""
        from ama_cryptography.pqc_backends import native_hkdf

        out = native_hkdf(b"\x01" * 32, 64, salt=b"salt", info=b"info")
        assert len(out) == 64

    def test_hkdf_deterministic(self) -> None:
        """HKDF is deterministic."""
        from ama_cryptography.pqc_backends import native_hkdf

        out1 = native_hkdf(b"ikm", 32, salt=b"salt", info=b"info")
        out2 = native_hkdf(b"ikm", 32, salt=b"salt", info=b"info")
        assert out1 == out2


# ===========================================================================
# Unavailable Backend Tests
# ===========================================================================


class TestUnavailableBackends:
    """Test error paths when backends are not available."""

    def test_dilithium_unavailable(self) -> None:
        """generate_dilithium_keypair raises when unavailable."""
        from ama_cryptography.pqc_backends import generate_dilithium_keypair

        with patch("ama_cryptography.pqc_backends.DILITHIUM_AVAILABLE", False):
            with pytest.raises(Exception, match=r"[Uu]navailable|PQC"):
                generate_dilithium_keypair()

    def test_kyber_unavailable(self) -> None:
        """generate_kyber_keypair raises when unavailable."""
        from ama_cryptography.pqc_backends import generate_kyber_keypair

        with patch("ama_cryptography.pqc_backends.KYBER_AVAILABLE", False):
            with pytest.raises(Exception, match=r"[Uu]navailable|KYBER"):
                generate_kyber_keypair()

    def test_sphincs_unavailable(self) -> None:
        """generate_sphincs_keypair raises when unavailable."""
        from ama_cryptography.pqc_backends import generate_sphincs_keypair

        with patch("ama_cryptography.pqc_backends.SPHINCS_AVAILABLE", False):
            with pytest.raises(Exception, match=r"[Uu]navailable|SPHINCS"):
                generate_sphincs_keypair()


# ===========================================================================
# HMAC Function Tests
# ===========================================================================


@skip_no_native
class TestHMACFunctions:
    """Test HMAC-SHA3-256 and HMAC-SHA-512 functions."""

    def test_hmac_sha3_256(self) -> None:
        """hmac_sha3_256 produces 32-byte output."""
        from ama_cryptography.pqc_backends import hmac_sha3_256

        result = hmac_sha3_256(b"key", b"message")
        assert len(result) == 32

    def test_hmac_sha3_256_deterministic(self) -> None:
        """hmac_sha3_256 is deterministic."""
        from ama_cryptography.pqc_backends import hmac_sha3_256

        r1 = hmac_sha3_256(b"key", b"msg")
        r2 = hmac_sha3_256(b"key", b"msg")
        assert r1 == r2

    def test_native_hmac_sha3_256(self) -> None:
        """native_hmac_sha3_256 produces 32-byte output."""
        from ama_cryptography.pqc_backends import native_hmac_sha3_256

        result = native_hmac_sha3_256(b"key", b"message")
        assert len(result) == 32

    def test_native_hmac_sha512(self) -> None:
        """native_hmac_sha512 produces 64-byte output."""
        from ama_cryptography.pqc_backends import native_hmac_sha512

        result = native_hmac_sha512(b"key", b"message")
        assert len(result) == 64


# ===========================================================================
# SHA3-256 Function Tests
# ===========================================================================


@skip_no_native
class TestSHA3Functions:
    """Test native SHA3-256 function."""

    def test_sha3_256(self) -> None:
        """native_sha3_256 produces 32-byte output."""
        from ama_cryptography.pqc_backends import native_sha3_256

        result = native_sha3_256(b"test data")
        assert len(result) == 32

    def test_sha3_256_deterministic(self) -> None:
        """native_sha3_256 is deterministic."""
        from ama_cryptography.pqc_backends import native_sha3_256

        r1 = native_sha3_256(b"data")
        r2 = native_sha3_256(b"data")
        assert r1 == r2

    def test_sha3_256_empty(self) -> None:
        """native_sha3_256 handles empty input."""
        from ama_cryptography.pqc_backends import native_sha3_256

        result = native_sha3_256(b"")
        assert len(result) == 32


# ===========================================================================
# Additional Native Functions
# ===========================================================================


@skip_no_native
class TestAdditionalNativeFunctions:
    """Test X25519, secp256k1, Argon2, ChaCha20-Poly1305."""

    def test_x25519_keypair_and_exchange(self) -> None:
        """X25519 keypair + key exchange roundtrip."""
        from ama_cryptography.pqc_backends import (
            _X25519_NATIVE_AVAILABLE,
            native_x25519_key_exchange,
            native_x25519_keypair,
        )

        if not _X25519_NATIVE_AVAILABLE:
            pytest.skip("X25519 not available")

        pk1, sk1 = native_x25519_keypair()
        pk2, sk2 = native_x25519_keypair()
        ss1 = native_x25519_key_exchange(sk1, pk2)
        ss2 = native_x25519_key_exchange(sk2, pk1)
        assert ss1 == ss2

    def test_argon2id(self) -> None:
        """Argon2id produces output of requested length."""
        from ama_cryptography.pqc_backends import (
            _ARGON2_NATIVE_AVAILABLE,
            native_argon2id,
        )

        if not _ARGON2_NATIVE_AVAILABLE:
            pytest.skip("Argon2 not available")

        result = native_argon2id(
            password=b"password",
            salt=b"saltsalt12345678",
            t_cost=1,
            m_cost=1024,
            parallelism=1,
            out_len=32,
        )
        assert len(result) == 32

    def test_chacha20poly1305_roundtrip(self) -> None:
        """ChaCha20-Poly1305 encrypt/decrypt roundtrip."""
        import secrets

        from ama_cryptography.pqc_backends import (
            _CHACHA20_POLY1305_NATIVE_AVAILABLE,
            native_chacha20poly1305_decrypt,
            native_chacha20poly1305_encrypt,
        )

        if not _CHACHA20_POLY1305_NATIVE_AVAILABLE:
            pytest.skip("ChaCha20-Poly1305 not available")

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        pt = b"chacha20 test data"
        aad = b"additional"

        ct, tag = native_chacha20poly1305_encrypt(key, nonce, pt, aad)
        result = native_chacha20poly1305_decrypt(key, nonce, ct, tag, aad)
        assert result == pt

    def test_ed25519_keypair_from_seed(self) -> None:
        """Ed25519 keypair from seed produces deterministic output."""
        from ama_cryptography.pqc_backends import native_ed25519_keypair_from_seed

        seed = b"\x42" * 32
        pk1, sk1 = native_ed25519_keypair_from_seed(seed)
        pk2, sk2 = native_ed25519_keypair_from_seed(seed)
        assert pk1 == pk2
        assert sk1 == sk2
