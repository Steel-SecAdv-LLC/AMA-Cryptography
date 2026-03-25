"""Tests for 4-Layer Defense-in-Depth crypto package creation and verification."""

import hashlib

import pytest


def _skip_if_no_backends() -> None:
    """Skip test if native backends are not available."""
    try:
        from ama_cryptography.crypto_api import create_crypto_package

        create_crypto_package(b"test")
    except (RuntimeError, Exception) as e:
        if "native" in str(e).lower() or "unavailable" in str(e).lower():
            pytest.skip(f"Native backend required: {e}")
        raise


class TestCreateCryptoPackage:
    def test_basic_creation(self) -> None:
        _skip_if_no_backends()
        from ama_cryptography.crypto_api import create_crypto_package

        result = create_crypto_package(b"Hello, World!")
        assert result.content_hash == hashlib.sha3_256(b"Hello, World!").hexdigest()
        assert len(result.hmac_key) == 32
        assert len(result.hmac_tag) == 32
        assert result.primary_signature is not None
        assert len(result.derived_keys) == 3
        assert len(result.hkdf_salt) == 32

    def test_metadata_has_4_layers(self) -> None:
        _skip_if_no_backends()
        from ama_cryptography.crypto_api import create_crypto_package

        result = create_crypto_package(b"test")
        assert result.metadata["defense_layers"] == 4

    def test_rejects_empty_content(self) -> None:
        from ama_cryptography.crypto_api import create_crypto_package

        with pytest.raises(ValueError, match="empty"):
            create_crypto_package(b"")

    def test_rejects_non_bytes(self) -> None:
        from ama_cryptography.crypto_api import create_crypto_package

        with pytest.raises(TypeError, match="bytes"):
            create_crypto_package("string")  # type: ignore[arg-type]

    def test_hmac_key_preserved(self) -> None:
        _skip_if_no_backends()
        from ama_cryptography.crypto_api import create_crypto_package

        result = create_crypto_package(b"test")
        assert isinstance(result.hmac_key, bytes)
        assert len(result.hmac_key) == 32

    def test_hkdf_master_secret_preserved(self) -> None:
        _skip_if_no_backends()
        from ama_cryptography.crypto_api import create_crypto_package

        result = create_crypto_package(b"test")
        assert isinstance(result.hkdf_master_secret, bytes)
        assert len(result.hkdf_master_secret) == 32


class TestVerifyCryptoPackage:
    def test_verify_all_layers_pass(self) -> None:
        _skip_if_no_backends()
        from ama_cryptography.crypto_api import create_crypto_package, verify_crypto_package

        result = create_crypto_package(b"Hello")
        v = verify_crypto_package(b"Hello", result)
        assert v["content_hash"] is True
        assert v["hmac"] is True
        assert v["primary_signature"] is True
        assert v["hkdf_keys"] is True
        assert v["all_valid"] is True

    def test_tampered_content_fails_hash(self) -> None:
        _skip_if_no_backends()
        from ama_cryptography.crypto_api import create_crypto_package, verify_crypto_package

        result = create_crypto_package(b"original")
        v = verify_crypto_package(b"tampered", result)
        assert v["content_hash"] is False
        assert v["all_valid"] is False

    def test_tampered_content_fails_hmac(self) -> None:
        _skip_if_no_backends()
        from ama_cryptography.crypto_api import create_crypto_package, verify_crypto_package

        result = create_crypto_package(b"original")
        v = verify_crypto_package(b"tampered", result)
        assert v["hmac"] is False

    def test_tampered_content_fails_signature(self) -> None:
        _skip_if_no_backends()
        from ama_cryptography.crypto_api import create_crypto_package, verify_crypto_package

        result = create_crypto_package(b"original")
        v = verify_crypto_package(b"tampered", result)
        assert v["primary_signature"] is False

    def test_tampered_hmac_key_fails(self) -> None:
        _skip_if_no_backends()
        import os

        from ama_cryptography.crypto_api import create_crypto_package, verify_crypto_package

        content = b"test data"
        result = create_crypto_package(content)
        # Tamper with HMAC key
        from dataclasses import replace

        tampered = replace(result, hmac_key=os.urandom(32))
        v = verify_crypto_package(content, tampered)
        assert v["hmac"] is False
        assert v["all_valid"] is False

    def test_verify_returns_all_valid_key(self) -> None:
        _skip_if_no_backends()
        from ama_cryptography.crypto_api import create_crypto_package, verify_crypto_package

        result = create_crypto_package(b"test")
        v = verify_crypto_package(b"test", result)
        assert "all_valid" in v
