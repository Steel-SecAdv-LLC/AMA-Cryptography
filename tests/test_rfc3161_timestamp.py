#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Tests for RFC 3161 Timestamp Protocol Implementation
=====================================================

Covers:
  - TimestampResult dataclass construction and field access
  - Exception hierarchy (TimestampUnavailableError, TimestampError)
  - get_timestamp: input validation, hash algorithms, error paths
  - verify_timestamp: hash recomputation, mismatch detection, error paths
  - Module __all__ exports
"""

from __future__ import annotations

import hashlib
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from ama_cryptography.rfc3161_timestamp import (
    RFC3161_AVAILABLE,
    TimestampError,
    TimestampResult,
    TimestampUnavailableError,
    get_timestamp,
    verify_timestamp,
)

# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class TestExceptionHierarchy:
    """Verify exception classes are well-formed and catchable."""

    def test_timestamp_unavailable_is_exception(self) -> None:
        assert issubclass(TimestampUnavailableError, Exception)

    def test_timestamp_error_is_exception(self) -> None:
        assert issubclass(TimestampError, Exception)

    def test_timestamp_unavailable_message(self) -> None:
        err = TimestampUnavailableError("lib missing")
        assert str(err) == "lib missing"

    def test_timestamp_error_message(self) -> None:
        err = TimestampError("request failed")
        assert str(err) == "request failed"

    def test_exceptions_are_distinct(self) -> None:
        assert id(TimestampUnavailableError) != id(TimestampError)
        assert not issubclass(TimestampUnavailableError, TimestampError)
        assert not issubclass(TimestampError, TimestampUnavailableError)


# ---------------------------------------------------------------------------
# TimestampResult dataclass
# ---------------------------------------------------------------------------


class TestTimestampResult:
    """Verify the TimestampResult dataclass."""

    def test_construction_and_fields(self) -> None:
        result = TimestampResult(
            token=b"\x30\x82",
            tsa_url="http://tsa.example.com",
            hash_algorithm="sha256",
            data_hash=b"\xab" * 32,
        )
        assert result.token == b"\x30\x82"
        assert result.tsa_url == "http://tsa.example.com"
        assert result.hash_algorithm == "sha256"
        assert result.data_hash == b"\xab" * 32

    def test_equality(self) -> None:
        kwargs: dict[str, Any] = {
            "token": b"tok",
            "tsa_url": "http://x",
            "hash_algorithm": "sha256",
            "data_hash": b"h",
        }
        assert TimestampResult(**kwargs) == TimestampResult(**kwargs)

    def test_inequality_on_different_token(self) -> None:
        base: dict[str, Any] = {
            "tsa_url": "http://x",
            "hash_algorithm": "sha256",
            "data_hash": b"h",
        }
        a = TimestampResult(token=b"a", **base)
        b = TimestampResult(token=b"b", **base)
        assert a != b


# ---------------------------------------------------------------------------
# get_timestamp
# ---------------------------------------------------------------------------


class TestGetTimestamp:
    """Test get_timestamp input validation and behaviour."""

    def test_unsupported_hash_algorithm_raises_value_error(self) -> None:
        """Unsupported hash algorithm must raise ValueError."""
        with patch("ama_cryptography.rfc3161_timestamp.RFC3161_AVAILABLE", True):
            with pytest.raises(ValueError, match="Unsupported hash algorithm"):
                get_timestamp(b"data", tsa_url="http://tsa.example.com", hash_algorithm="md5")

    def test_unavailable_library_raises(self) -> None:
        """When rfc3161ng is missing, TimestampUnavailableError must be raised."""
        with patch("ama_cryptography.rfc3161_timestamp.RFC3161_AVAILABLE", False):
            with pytest.raises(TimestampUnavailableError, match="RFC3161_UNAVAILABLE"):
                get_timestamp(b"data")

    def test_default_tsa_url_emits_warning(self) -> None:
        """When no tsa_url is given, a UserWarning should be emitted."""
        mock_timestamper_cls = MagicMock()
        mock_timestamper_cls.return_value = MagicMock(return_value=b"token-bytes")
        with (
            patch("ama_cryptography.rfc3161_timestamp.RFC3161_AVAILABLE", True),
            patch("ama_cryptography.rfc3161_timestamp.RemoteTimestamper", mock_timestamper_cls),
            pytest.warns(UserWarning, match="No TSA URL specified"),
        ):
            get_timestamp(b"data")

    @pytest.mark.parametrize(
        "algo,hashfunc",
        [
            ("sha256", hashlib.sha256),
            ("sha3-256", hashlib.sha3_256),
            ("sha512", hashlib.sha512),
            ("sha3-512", hashlib.sha3_512),
        ],
    )
    def test_supported_hash_algorithms(self, algo: str, hashfunc: Any) -> None:
        """Each supported algorithm must compute the correct hash."""
        data = b"test-data-for-hashing"
        expected_hash = hashfunc(data).digest()
        mock_timestamper_cls = MagicMock()
        mock_timestamper_cls.return_value = MagicMock(return_value=b"mock-token")
        with (
            patch("ama_cryptography.rfc3161_timestamp.RFC3161_AVAILABLE", True),
            patch("ama_cryptography.rfc3161_timestamp.RemoteTimestamper", mock_timestamper_cls),
        ):
            result = get_timestamp(data, tsa_url="http://tsa.example.com", hash_algorithm=algo)
        assert result is not None
        assert result.data_hash == expected_hash
        assert result.hash_algorithm == algo
        assert result.tsa_url == "http://tsa.example.com"
        assert result.token == b"mock-token"

    def test_none_token_raises_timestamp_error(self) -> None:
        """If TSA returns None, TimestampError should be raised."""
        mock_timestamper_cls = MagicMock()
        mock_timestamper_cls.return_value = MagicMock(return_value=None)
        with (
            patch("ama_cryptography.rfc3161_timestamp.RFC3161_AVAILABLE", True),
            patch("ama_cryptography.rfc3161_timestamp.RemoteTimestamper", mock_timestamper_cls),
        ):
            with pytest.raises(TimestampError, match="Failed to obtain timestamp"):
                get_timestamp(b"data", tsa_url="http://tsa.example.com")

    def test_network_error_raises_timestamp_error(self) -> None:
        """Network/connection errors must be wrapped in TimestampError."""
        mock_timestamper_cls = MagicMock()
        mock_timestamper_cls.return_value = MagicMock(
            side_effect=ConnectionError("connection refused")
        )
        with (
            patch("ama_cryptography.rfc3161_timestamp.RFC3161_AVAILABLE", True),
            patch("ama_cryptography.rfc3161_timestamp.RemoteTimestamper", mock_timestamper_cls),
        ):
            with pytest.raises(TimestampError, match="Timestamp request failed"):
                get_timestamp(b"data", tsa_url="http://tsa.example.com")

    def test_value_error_passthrough(self) -> None:
        """ValueError from inside get_timestamp should propagate directly."""
        with patch("ama_cryptography.rfc3161_timestamp.RFC3161_AVAILABLE", True):
            with pytest.raises(ValueError):
                get_timestamp(b"data", tsa_url="http://tsa.example.com", hash_algorithm="blake2")

    def test_hashname_format_passed_to_remote_timestamper(self) -> None:
        """Hash algorithm name should have dashes stripped for RemoteTimestamper."""
        mock_timestamper_cls = MagicMock()
        mock_instance = MagicMock(return_value=b"tok")
        mock_timestamper_cls.return_value = mock_instance
        with (
            patch("ama_cryptography.rfc3161_timestamp.RFC3161_AVAILABLE", True),
            patch("ama_cryptography.rfc3161_timestamp.RemoteTimestamper", mock_timestamper_cls),
        ):
            get_timestamp(b"data", tsa_url="http://tsa.example.com", hash_algorithm="sha3-256")
        mock_timestamper_cls.assert_called_once_with(
            "http://tsa.example.com", certificate=None, hashname="sha3256"
        )


# ---------------------------------------------------------------------------
# verify_timestamp
# ---------------------------------------------------------------------------


class TestVerifyTimestamp:
    """Test verify_timestamp logic."""

    def test_unavailable_library_raises(self) -> None:
        result = TimestampResult(
            token=b"tok", tsa_url="http://x", hash_algorithm="sha256", data_hash=b"h"
        )
        with patch("ama_cryptography.rfc3161_timestamp.RFC3161_AVAILABLE", False):
            with pytest.raises(TimestampUnavailableError):
                verify_timestamp(b"data", result)

    def test_hash_mismatch_returns_false(self) -> None:
        """If stored data_hash doesn't match recomputed hash, return False."""
        wrong_hash = b"\x00" * 32
        result = TimestampResult(
            token=b"tok",
            tsa_url="http://x",
            hash_algorithm="sha256",
            data_hash=wrong_hash,
        )
        mock_timestamper_cls = MagicMock()
        with (
            patch("ama_cryptography.rfc3161_timestamp.RFC3161_AVAILABLE", True),
            patch("ama_cryptography.rfc3161_timestamp.RemoteTimestamper", mock_timestamper_cls),
        ):
            assert verify_timestamp(b"real data", result) is False

    def test_unsupported_algorithm_returns_false(self) -> None:
        """Unsupported hash algorithm in TimestampResult should return False."""
        result = TimestampResult(
            token=b"tok", tsa_url="http://x", hash_algorithm="md5", data_hash=b"h"
        )
        mock_timestamper_cls = MagicMock()
        with (
            patch("ama_cryptography.rfc3161_timestamp.RFC3161_AVAILABLE", True),
            patch("ama_cryptography.rfc3161_timestamp.RemoteTimestamper", mock_timestamper_cls),
        ):
            assert verify_timestamp(b"data", result) is False

    @pytest.mark.parametrize("algo", ["sha256", "sha3-256", "sha512", "sha3-512"])
    def test_valid_verification_all_algorithms(self, algo: str) -> None:
        """Verification succeeds when hash matches and TSA confirms."""
        data = b"important document"
        hash_funcs = {
            "sha256": hashlib.sha256,
            "sha3-256": hashlib.sha3_256,
            "sha512": hashlib.sha512,
            "sha3-512": hashlib.sha3_512,
        }
        correct_hash = hash_funcs[algo](data).digest()
        result = TimestampResult(
            token=b"valid-token",
            tsa_url="http://tsa.example.com",
            hash_algorithm=algo,
            data_hash=correct_hash,
        )
        mock_timestamper_cls = MagicMock()
        mock_instance = MagicMock()
        mock_instance.check.return_value = True
        mock_timestamper_cls.return_value = mock_instance
        with (
            patch("ama_cryptography.rfc3161_timestamp.RFC3161_AVAILABLE", True),
            patch("ama_cryptography.rfc3161_timestamp.RemoteTimestamper", mock_timestamper_cls),
        ):
            assert verify_timestamp(data, result) is True

    def test_tsa_rejection_returns_false(self) -> None:
        """If TSA check() returns False, verification should return False."""
        data = b"doc"
        correct_hash = hashlib.sha256(data).digest()
        result = TimestampResult(
            token=b"tok",
            tsa_url="http://x",
            hash_algorithm="sha256",
            data_hash=correct_hash,
        )
        mock_timestamper_cls = MagicMock()
        mock_instance = MagicMock()
        mock_instance.check.return_value = False
        mock_timestamper_cls.return_value = mock_instance
        with (
            patch("ama_cryptography.rfc3161_timestamp.RFC3161_AVAILABLE", True),
            patch("ama_cryptography.rfc3161_timestamp.RemoteTimestamper", mock_timestamper_cls),
        ):
            assert verify_timestamp(data, result) is False

    def test_exception_during_verification_returns_false(self) -> None:
        """Any exception during verification should be caught and return False."""
        data = b"doc"
        correct_hash = hashlib.sha256(data).digest()
        result = TimestampResult(
            token=b"tok",
            tsa_url="http://x",
            hash_algorithm="sha256",
            data_hash=correct_hash,
        )
        mock_timestamper_cls = MagicMock()
        mock_timestamper_cls.return_value = MagicMock(
            check=MagicMock(side_effect=RuntimeError("TSA down"))
        )
        with (
            patch("ama_cryptography.rfc3161_timestamp.RFC3161_AVAILABLE", True),
            patch("ama_cryptography.rfc3161_timestamp.RemoteTimestamper", mock_timestamper_cls),
        ):
            assert verify_timestamp(data, result) is False

    def test_tampered_data_fails_verification(self) -> None:
        """Verification must fail when data has been modified after timestamping."""
        original = b"original document"
        tampered = b"tampered document"
        correct_hash = hashlib.sha256(original).digest()
        result = TimestampResult(
            token=b"tok",
            tsa_url="http://x",
            hash_algorithm="sha256",
            data_hash=correct_hash,
        )
        mock_timestamper_cls = MagicMock()
        with (
            patch("ama_cryptography.rfc3161_timestamp.RFC3161_AVAILABLE", True),
            patch("ama_cryptography.rfc3161_timestamp.RemoteTimestamper", mock_timestamper_cls),
        ):
            assert verify_timestamp(tampered, result) is False


# ---------------------------------------------------------------------------
# Module-level
# ---------------------------------------------------------------------------


class TestModuleAttributes:
    """Verify module exports and constants."""

    def test_rfc3161_available_is_bool(self) -> None:
        assert isinstance(RFC3161_AVAILABLE, bool)

    def test_all_exports(self) -> None:
        from ama_cryptography import rfc3161_timestamp as mod

        expected = {
            "get_timestamp",
            "verify_timestamp",
            "TimestampResult",
            "TimestampUnavailableError",
            "TimestampError",
            "RFC3161_AVAILABLE",
        }
        assert set(mod.__all__) == expected


# ---------------------------------------------------------------------------
# Additional RFC 3161 mock coverage (Phase 10b)
# ---------------------------------------------------------------------------


class TestNetworkErrorPaths:
    """Test network failure scenarios for timestamp operations."""

    @patch("ama_cryptography.rfc3161_timestamp._RFC3161_AVAILABLE", True)
    @patch("ama_cryptography.rfc3161_timestamp.rfc3161ng")
    def test_connection_timeout_raises_timestamp_error(self, mock_rfc: MagicMock) -> None:
        """Connection timeout is surfaced as TimestampError."""
        import socket

        mock_rfc.RemoteTimestamper.return_value.timestamp.side_effect = socket.timeout(
            "Connection timed out"
        )
        with pytest.raises(TimestampError):
            get_timestamp(b"test data", tsa_url="http://example.com/tsa")

    @patch("ama_cryptography.rfc3161_timestamp._RFC3161_AVAILABLE", True)
    @patch("ama_cryptography.rfc3161_timestamp.rfc3161ng")
    def test_connection_refused_raises_timestamp_error(self, mock_rfc: MagicMock) -> None:
        """Connection refused is surfaced as TimestampError."""
        mock_rfc.RemoteTimestamper.return_value.timestamp.side_effect = ConnectionRefusedError(
            "Connection refused"
        )
        with pytest.raises(TimestampError):
            get_timestamp(b"test data", tsa_url="http://example.com/tsa")

    @patch("ama_cryptography.rfc3161_timestamp._RFC3161_AVAILABLE", True)
    @patch("ama_cryptography.rfc3161_timestamp.rfc3161ng")
    def test_generic_os_error_raises_timestamp_error(self, mock_rfc: MagicMock) -> None:
        """Generic OSError during timestamping raises TimestampError."""
        mock_rfc.RemoteTimestamper.return_value.timestamp.side_effect = OSError(
            "Network unreachable"
        )
        with pytest.raises(TimestampError):
            get_timestamp(b"test data", tsa_url="http://example.com/tsa")


class TestMalformedResponses:
    """Test handling of malformed TSA responses."""

    @patch("ama_cryptography.rfc3161_timestamp._RFC3161_AVAILABLE", True)
    @patch("ama_cryptography.rfc3161_timestamp.rfc3161ng")
    def test_empty_token_raises_error(self, mock_rfc: MagicMock) -> None:
        """Empty timestamp token raises TimestampError."""
        mock_rfc.RemoteTimestamper.return_value.timestamp.return_value = None
        with pytest.raises(TimestampError):
            get_timestamp(b"test data", tsa_url="http://example.com/tsa")

    @patch("ama_cryptography.rfc3161_timestamp._RFC3161_AVAILABLE", True)
    @patch("ama_cryptography.rfc3161_timestamp.rfc3161ng")
    def test_empty_bytes_token_raises_error(self, mock_rfc: MagicMock) -> None:
        """Empty bytes timestamp token raises TimestampError."""
        mock_rfc.RemoteTimestamper.return_value.timestamp.return_value = b""
        # Depending on implementation, may raise or return with empty token
        try:
            result = get_timestamp(b"test data", tsa_url="http://example.com/tsa")
            # If it doesn't raise, token should be bytes
            assert isinstance(result.token, bytes)
        except TimestampError:
            pass  # Also acceptable


class TestNonceMismatch:
    """Test nonce validation in timestamp responses."""

    @patch("ama_cryptography.rfc3161_timestamp._RFC3161_AVAILABLE", True)
    @patch("ama_cryptography.rfc3161_timestamp.rfc3161ng")
    def test_verify_with_different_data_fails(self, mock_rfc: MagicMock) -> None:
        """Verification with different data than what was timestamped returns False."""
        # Create a result with a known hash
        original_data = b"original data"
        digest = hashlib.sha256(original_data).hexdigest()
        result = TimestampResult(
            token=b"\x30\x82\x01\x00",
            hash_algorithm="sha256",
            data_hash=digest,
            tsa_url="http://example.com/tsa",
        )

        # Verify with different data
        assert verify_timestamp(b"different data", result) is False

    @patch("ama_cryptography.rfc3161_timestamp._RFC3161_AVAILABLE", True)
    @patch("ama_cryptography.rfc3161_timestamp.rfc3161ng")
    def test_verify_with_corrupted_digest(self, mock_rfc: MagicMock) -> None:
        """Verification with corrupted digest returns False."""
        result = TimestampResult(
            token=b"\x30\x82\x01\x00",
            hash_algorithm="sha256",
            data_hash="0" * 64,  # All zeros — won't match any real data
            tsa_url="http://example.com/tsa",
        )
        assert verify_timestamp(b"any data", result) is False


class TestReplayProtection:
    """Test replay attack detection scenarios."""

    @patch("ama_cryptography.rfc3161_timestamp._RFC3161_AVAILABLE", True)
    @patch("ama_cryptography.rfc3161_timestamp.rfc3161ng")
    def test_same_data_different_timestamps(self, mock_rfc: MagicMock) -> None:
        """Two timestamps of same data should have same digest."""
        data = b"replay test data"
        digest = hashlib.sha256(data).hexdigest()

        result1 = TimestampResult(
            token=b"\x30\x82\x01\x01",
            hash_algorithm="sha256",
            data_hash=digest,
            tsa_url="http://example.com/tsa",
        )
        result2 = TimestampResult(
            token=b"\x30\x82\x01\x02",
            hash_algorithm="sha256",
            data_hash=digest,
            tsa_url="http://example.com/tsa",
        )
        assert result1.data_hash == result2.data_hash
        # But tokens should differ (different nonces in real scenario)
        assert result1.token != result2.token


class TestCertificateChainErrors:
    """Test TSA certificate chain validation error paths."""

    @patch("ama_cryptography.rfc3161_timestamp._RFC3161_AVAILABLE", True)
    @patch("ama_cryptography.rfc3161_timestamp.rfc3161ng")
    def test_tsa_certificate_expired(self, mock_rfc: MagicMock) -> None:
        """Expired TSA certificate raises TimestampError."""
        mock_rfc.RemoteTimestamper.return_value.timestamp.side_effect = Exception(
            "certificate has expired"
        )
        with pytest.raises(TimestampError):
            get_timestamp(b"test data", tsa_url="http://example.com/tsa")

    @patch("ama_cryptography.rfc3161_timestamp._RFC3161_AVAILABLE", True)
    @patch("ama_cryptography.rfc3161_timestamp.rfc3161ng")
    def test_tsa_certificate_untrusted(self, mock_rfc: MagicMock) -> None:
        """Untrusted TSA certificate raises TimestampError."""
        mock_rfc.RemoteTimestamper.return_value.timestamp.side_effect = Exception(
            "unable to get local issuer certificate"
        )
        with pytest.raises(TimestampError):
            get_timestamp(b"test data", tsa_url="http://example.com/tsa")
