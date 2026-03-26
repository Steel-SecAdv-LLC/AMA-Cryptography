#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Security fix regression tests (S1–S6).

Each test class covers exactly one security issue and proves the fix.
"""

import hashlib
import os
from unittest.mock import patch

import pytest

from ama_cryptography.rfc3161_timestamp import (
    MockTSA,
    get_timestamp,
    verify_timestamp,
)

# ---------------------------------------------------------------------------
# S1 — HKDF Layer 4 trivial bypass on empty derived_keys
# ---------------------------------------------------------------------------


class TestS1_HKDFEmptyDerivedKeys:
    """S1: verify_crypto_package must fail when derived_keys is empty."""

    def test_empty_derived_keys_fails_hkdf_layer(self) -> None:
        """An empty derived_keys list must cause hkdf_keys to be False."""
        import secrets

        from ama_cryptography.crypto_api import (
            CryptoPackageResult,
            Ed25519Provider,
            _hmac_sha3_256,
            verify_crypto_package,
        )

        # Build a minimal valid-looking CryptoPackageResult by hand
        # so we don't depend on _check_operational / FIPS self-test.
        content = b"test content for S1"
        content_hash = hashlib.sha3_256(content).hexdigest()
        hmac_key = secrets.token_bytes(32)
        hmac_tag = _hmac_sha3_256(hmac_key, content)
        master_secret = secrets.token_bytes(32)
        hkdf_salt = secrets.token_bytes(32)
        hkdf_info = b"ama_cryptography_crypto_package_v1"

        # Generate a real Ed25519 signature (provider bypasses _check_operational)
        ed_provider = Ed25519Provider()
        kp = ed_provider.generate_keypair()
        sig_obj = ed_provider.sign(content, kp.secret_key)

        package = CryptoPackageResult(
            content_hash=content_hash,
            hmac_key=hmac_key,
            hmac_tag=hmac_tag,
            primary_signature=sig_obj,
            sphincs_signature=None,
            derived_keys=[],  # Empty — should fail Layer 4
            hkdf_salt=hkdf_salt,
            hkdf_master_secret=master_secret,
            hkdf_info=hkdf_info,
            timestamp=None,
            kem_ciphertext=None,
            kem_shared_secret=None,
            keypairs={"ED25519": kp},
            metadata={"signature_algorithm": "ED25519", "defense_layers": 4},
        )

        # Bypass FIPS self-test check for unit test isolation
        with patch("ama_cryptography.crypto_api._check_operational"):
            verification = verify_crypto_package(content, package)
        assert (
            verification["hkdf_keys"] is False
        ), "S1 REGRESSION: empty derived_keys must fail Layer 4 (HKDF)"
        assert verification["all_valid"] is False


# ---------------------------------------------------------------------------
# S2 — verify_timestamp() disabled-mode skips data integrity check
# ---------------------------------------------------------------------------


class TestS2_DisabledTimestampIntegrity:
    """S2: disabled-mode timestamps must still verify data integrity."""

    def test_disabled_timestamp_wrong_data_fails(self) -> None:
        """A disabled TimestampResult from payload A must not validate payload B."""
        payload_a = b"payload A for S2 test"
        payload_b = b"payload B for S2 test"

        ts_result = get_timestamp(payload_a, tsa_mode="disabled")
        assert ts_result is not None

        # Verify with the WRONG data — must return False
        assert (
            verify_timestamp(payload_b, ts_result) is False
        ), "S2 REGRESSION: disabled timestamp validated wrong payload"

    def test_disabled_timestamp_correct_data_passes(self) -> None:
        """A disabled TimestampResult should still pass with correct data."""
        data = b"correct data for S2"
        ts_result = get_timestamp(data, tsa_mode="disabled")
        assert ts_result is not None
        assert verify_timestamp(data, ts_result) is True


# ---------------------------------------------------------------------------
# S3 — MockTSA uses length-extension-vulnerable hash construction
# ---------------------------------------------------------------------------


class TestS3_MockTSAHMACAndGuard:
    """S3: MockTSA must use HMAC and must be guarded against production use."""

    def test_mock_tsa_uses_hmac(self) -> None:
        """MockTSA.timestamp() must produce tokens verifiable with HMAC."""
        import hmac as hmac_mod

        import ama_cryptography.rfc3161_timestamp as ts_mod

        # Enable MockTSA for this test
        ts_mod._MOCK_TSA_ALLOWED = True
        try:
            data_hash = hashlib.sha256(b"test data").digest()
            token = MockTSA.timestamp(data_hash, "sha256")

            # Extract nonce and payload from token
            nonce = token[-32:]
            mac = token[-(32 + 32) : -32]
            payload = token[: -(32 + 32)]

            # Verify it's an HMAC, not raw SHA-256(nonce || payload)
            expected_hmac = hmac_mod.new(nonce, payload, hashlib.sha256).digest()
            assert mac == expected_hmac, "MockTSA must use HMAC, not raw hash"

            # Verify the old vulnerable construction does NOT match
            old_vulnerable = hashlib.sha256(nonce + payload).digest()
            # They should differ (HMAC != raw hash concatenation)
            # Note: they COULD theoretically match by coincidence, but practically won't
            assert mac != old_vulnerable or mac == expected_hmac

            # Verify roundtrip works
            assert MockTSA.verify(token, data_hash) is True
        finally:
            ts_mod._MOCK_TSA_ALLOWED = False

    def test_mock_tsa_blocked_outside_testing(self) -> None:
        """MockTSA.timestamp() must raise RuntimeError when _MOCK_TSA_ALLOWED is False."""
        import ama_cryptography.rfc3161_timestamp as ts_mod

        ts_mod._MOCK_TSA_ALLOWED = False
        with pytest.raises(RuntimeError, match="testing context"):
            MockTSA.timestamp(b"\x00" * 32, "sha256")

    def test_get_timestamp_mock_mode_still_works(self) -> None:
        """get_timestamp(tsa_mode='mock') must work (it enables the guard internally)."""
        import ama_cryptography.rfc3161_timestamp as ts_mod

        ts_mod._MOCK_TSA_ALLOWED = False  # Ensure it's off
        result = get_timestamp(b"data", tsa_mode="mock")
        assert result is not None
        assert result.tsa_url == "mock"
        # Flag should be restored to False after the call
        assert ts_mod._MOCK_TSA_ALLOWED is False


# ---------------------------------------------------------------------------
# S4 — Mock timestamp exceptions silently swallowed
# ---------------------------------------------------------------------------


class TestS4_MockTimestampExceptionNotSwallowed:
    """S4: _acquire_timestamp must not silently swallow mock-mode exceptions."""

    def test_mock_mode_exception_propagates(self) -> None:
        """When get_timestamp raises in mock mode, _acquire_timestamp must re-raise."""
        from ama_cryptography.crypto_api import CryptoPackageConfig, _acquire_timestamp

        config = CryptoPackageConfig(
            include_timestamp=True,
            tsa_mode="mock",
        )

        with patch(
            "ama_cryptography.crypto_api.get_timestamp",
            side_effect=RuntimeError("mock TSA exploded"),
        ):
            with pytest.raises(RuntimeError, match="mock TSA exploded"):
                _acquire_timestamp(b"content", config)


# ---------------------------------------------------------------------------
# S5 — _acquire_timestamp() None-guard silent failure
# ---------------------------------------------------------------------------


class TestS5_AcquireTimestampNoneGuard:
    """S5: _acquire_timestamp must raise when get_timestamp returns empty token."""

    def test_empty_token_raises_in_mock_mode(self) -> None:
        """If get_timestamp() returns empty token in mock mode, raise RuntimeError."""
        from ama_cryptography.crypto_api import CryptoPackageConfig, _acquire_timestamp
        from ama_cryptography.rfc3161_timestamp import TimestampResult

        config = CryptoPackageConfig(
            include_timestamp=True,
            tsa_mode="mock",
        )

        empty_result = TimestampResult(
            token=b"", tsa_url="mock", hash_algorithm="sha3-256", data_hash=b""
        )
        with patch(
            "ama_cryptography.crypto_api.get_timestamp",
            return_value=empty_result,
        ):
            with pytest.raises(RuntimeError, match=r"empty token"):
                _acquire_timestamp(b"content", config)

    def test_empty_token_raises_in_online_mode(self) -> None:
        """If get_timestamp() returns empty token in online mode, raise RuntimeError."""
        from ama_cryptography.crypto_api import CryptoPackageConfig, _acquire_timestamp
        from ama_cryptography.rfc3161_timestamp import TimestampResult

        config = CryptoPackageConfig(
            include_timestamp=True,
            tsa_mode="online",
        )

        empty_result = TimestampResult(
            token=b"", tsa_url="online", hash_algorithm="sha3-256", data_hash=b""
        )
        with patch(
            "ama_cryptography.crypto_api.RFC3161_AVAILABLE",
            True,
        ):
            with patch(
                "ama_cryptography.crypto_api.get_timestamp",
                return_value=empty_result,
            ):
                with pytest.raises(RuntimeError, match=r"empty token"):
                    _acquire_timestamp(b"content", config)

    def test_disabled_mode_returns_none_silently(self) -> None:
        """Disabled mode should still return None (no timestamp requested)."""
        from ama_cryptography.crypto_api import CryptoPackageConfig, _acquire_timestamp

        config = CryptoPackageConfig(
            include_timestamp=True,
            tsa_mode="disabled",
        )
        result = _acquire_timestamp(b"content", config)
        assert result is None


# ---------------------------------------------------------------------------
# S6 — AESGCMProvider._ephemeral set after constructor in test
# ---------------------------------------------------------------------------


class TestS6_AESGCMEphemeralMode:
    """S6: AESGCMProvider must support ephemeral mode before construction."""

    def test_configure_ephemeral_before_init(self) -> None:
        """configure_ephemeral(True) must prevent disk I/O."""
        try:
            from ama_cryptography.crypto_api import AESGCMProvider
        except RuntimeError:
            pytest.skip("AES-GCM native backend not available")

        # Reset to clean state first (clears any counters from prior tests)
        AESGCMProvider._encrypt_counters = {}
        AESGCMProvider.configure_ephemeral(True)
        try:
            provider = AESGCMProvider()
            key = os.urandom(32)

            # Encrypt something
            result = provider.encrypt(b"ephemeral test data", key)
            assert result["ciphertext"] is not None

            # In ephemeral mode, _persist_counters should be a no-op,
            # so even if the file exists from prior runs, the provider
            # should not have loaded or written to it during this test.
            assert AESGCMProvider._ephemeral is True
        finally:
            AESGCMProvider.configure_ephemeral(False)

    def test_ephemeral_param_in_constructor(self) -> None:
        """Passing ephemeral=True to __init__ must enable ephemeral mode."""
        try:
            from ama_cryptography.crypto_api import AESGCMProvider
        except RuntimeError:
            pytest.skip("AES-GCM native backend not available")

        # Reset state
        AESGCMProvider.configure_ephemeral(False)
        provider = AESGCMProvider(ephemeral=True)
        assert AESGCMProvider._ephemeral is True

        key = os.urandom(32)
        result = provider.encrypt(b"constructor ephemeral test", key)
        assert result["ciphertext"] is not None

        # Cleanup
        AESGCMProvider.configure_ephemeral(False)

    def test_configure_ephemeral_resets_state(self) -> None:
        """configure_ephemeral must reset counters and flags."""
        try:
            from ama_cryptography.crypto_api import AESGCMProvider
        except RuntimeError:
            pytest.skip("AES-GCM native backend not available")

        AESGCMProvider.configure_ephemeral(True)
        assert AESGCMProvider._ephemeral is True
        assert AESGCMProvider._counters_loaded is False
        assert AESGCMProvider._atexit_registered is False
        assert AESGCMProvider._encrypt_counters == {}

        AESGCMProvider.configure_ephemeral(False)
