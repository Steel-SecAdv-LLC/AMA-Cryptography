#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Offline tests for the RFC 3161 timestamp module.

Covers TimestampResult fields, hash algorithm validation, mock mode,
disabled mode, TimestampUnavailableError, verify_timestamp with
matching and mismatched data, and default TSA URL.

All tests run without network access or the rfc3161ng library.
"""

import hashlib

import pytest

from ama_cryptography.rfc3161_timestamp import (
    RFC3161_AVAILABLE,
    MockTSA,
    TimestampError,
    TimestampResult,
    TimestampUnavailableError,
    get_timestamp,
    verify_timestamp,
)


# ---- tests ------------------------------------------------------------------


class TestTimestampResultDataclass:
    """Tests for TimestampResult field access."""

    def test_fields_are_accessible(self) -> None:
        """All four fields of TimestampResult must be readable."""
        tr = TimestampResult(
            token=b"\x00",
            tsa_url="https://example.com",
            hash_algorithm="sha256",
            data_hash=b"\x01" * 32,
        )
        assert tr.token == b"\x00"
        assert tr.tsa_url == "https://example.com"
        assert tr.hash_algorithm == "sha256"
        assert tr.data_hash == b"\x01" * 32

    def test_equality(self) -> None:
        """Two TimestampResult instances with identical fields should be equal."""
        kwargs = dict(
            token=b"tok",
            tsa_url="url",
            hash_algorithm="sha256",
            data_hash=b"h",
        )
        assert TimestampResult(**kwargs) == TimestampResult(**kwargs)


class TestHashAlgorithmValidation:
    """Tests for hash algorithm validation in get_timestamp()."""

    def test_unsupported_hash_raises_value_error(self) -> None:
        """An unsupported hash algorithm must raise ValueError."""
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            get_timestamp(b"data", hash_algorithm="md5", tsa_mode="mock")

    def test_supported_algorithms_accepted(self) -> None:
        """All documented hash algorithms must be accepted in mock mode."""
        for algo in ("sha256", "sha3-256", "sha512", "sha3-512"):
            result = get_timestamp(b"data", hash_algorithm=algo, tsa_mode="mock")
            assert result is not None
            assert result.hash_algorithm == algo


class TestMockMode:
    """Tests for tsa_mode='mock'."""

    def test_mock_returns_timestamp_result(self) -> None:
        """Mock mode must return a TimestampResult with a non-empty token."""
        result = get_timestamp(b"hello world", tsa_mode="mock")
        assert isinstance(result, TimestampResult)
        assert len(result.token) > 0

    def test_mock_tsa_url_is_mock(self) -> None:
        """Mock mode must set tsa_url to 'mock'."""
        result = get_timestamp(b"data", tsa_mode="mock")
        assert result.tsa_url == "mock"

    def test_mock_data_hash_matches(self) -> None:
        """The data_hash in the result must match the expected hash."""
        data = b"test document"
        result = get_timestamp(data, hash_algorithm="sha3-256", tsa_mode="mock")
        expected = hashlib.sha3_256(data).digest()
        assert result.data_hash == expected


class TestDisabledMode:
    """Tests for tsa_mode='disabled'."""

    def test_disabled_returns_empty_token(self) -> None:
        """Disabled mode must return a TimestampResult with an empty token."""
        result = get_timestamp(b"data", tsa_mode="disabled")
        assert isinstance(result, TimestampResult)
        assert result.token == b""

    def test_disabled_tsa_url(self) -> None:
        """Disabled mode must set tsa_url to 'disabled'."""
        result = get_timestamp(b"data", tsa_mode="disabled")
        assert result.tsa_url == "disabled"


class TestTimestampUnavailable:
    """Tests for TimestampUnavailableError."""

    @pytest.mark.skipif(RFC3161_AVAILABLE, reason="rfc3161ng is installed")
    def test_online_mode_raises_when_rfc3161ng_missing(self) -> None:
        """Online mode must raise TimestampUnavailableError when rfc3161ng
        is not installed."""
        with pytest.raises(TimestampUnavailableError):
            get_timestamp(b"data", tsa_mode="online")

    def test_invalid_tsa_mode_raises(self) -> None:
        """An invalid tsa_mode must raise ValueError."""
        with pytest.raises(ValueError, match="Unsupported tsa_mode"):
            get_timestamp(b"data", tsa_mode="bogus")


class TestVerifyTimestamp:
    """Tests for verify_timestamp()."""

    def test_verify_matching_data(self) -> None:
        """verify_timestamp must return True for matching data."""
        data = b"important document"
        result = get_timestamp(data, tsa_mode="mock", hash_algorithm="sha3-256")
        assert verify_timestamp(data, result) is True

    def test_verify_mismatched_data(self) -> None:
        """verify_timestamp must return False when data does not match."""
        data = b"important document"
        result = get_timestamp(data, tsa_mode="mock", hash_algorithm="sha3-256")
        # Tamper with the stored data_hash so the recompute check fails
        tampered = TimestampResult(
            token=result.token,
            tsa_url=result.tsa_url,
            hash_algorithm=result.hash_algorithm,
            data_hash=b"\x00" * 32,
        )
        assert verify_timestamp(data, tampered) is False

    def test_verify_disabled_token_always_valid(self) -> None:
        """Disabled tokens should always verify as True."""
        result = get_timestamp(b"data", tsa_mode="disabled")
        assert verify_timestamp(b"data", result) is True


class TestDefaultTSAUrl:
    """Tests for the default TSA URL."""

    def test_default_tsa_url_is_https(self) -> None:
        """The default TSA URL hard-coded in the source module must use HTTPS.

        We inspect the source code directly because when rfc3161ng is not
        installed the function raises TimestampUnavailableError before
        the warning that contains the URL is emitted.
        """
        import inspect
        import ama_cryptography.rfc3161_timestamp as mod

        source = inspect.getsource(mod.get_timestamp)
        # The default URL assigned when tsa_url is None should be HTTPS
        assert "https://" in source, (
            "Expected the default TSA URL in get_timestamp() to use HTTPS"
        )
