#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Offline tests for the RFC 3161 timestamp module.

Covers TimestampResult fields, hash algorithm validation, mock mode,
disabled mode, RFC 3161 availability, verify_timestamp with
matching and mismatched data, and default TSA URL.

All tests run without network access. RFC 3161 is implemented in-tree on
AMA's own DER codec; the third-party ``rfc3161ng`` client was removed under
INVARIANT-1 and there is no configuration in which it is present.
"""

import hashlib

import pytest

from ama_cryptography.rfc3161_timestamp import (
    RFC3161_AVAILABLE,
    TimestampResult,
    allow_mock_tsa,
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
        a = TimestampResult(
            token=b"tok",
            tsa_url="url",
            hash_algorithm="sha256",
            data_hash=b"h",
        )
        b = TimestampResult(
            token=b"tok",
            tsa_url="url",
            hash_algorithm="sha256",
            data_hash=b"h",
        )
        assert a == b


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
        assert result is not None
        assert result.tsa_url == "mock"

    def test_mock_data_hash_matches(self) -> None:
        """The data_hash in the result must match the expected hash."""
        data = b"test document"
        result = get_timestamp(data, hash_algorithm="sha3-256", tsa_mode="mock")
        expected = hashlib.sha3_256(data).digest()
        assert result is not None
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
        assert result is not None
        assert result.tsa_url == "disabled"


class TestRfc3161Availability:
    """RFC 3161 has no optional dependency and no availability gate."""

    def test_rfc3161_is_unconditionally_available(self) -> None:
        """RFC 3161 has no optional dependency, so the gate is always open.

        This class used to hold ``test_online_mode_raises_when_rfc3161ng_missing``,
        skipped under ``skipif(RFC3161_AVAILABLE)``. Once ``rfc3161ng`` was
        removed and ``RFC3161_AVAILABLE`` became unconditionally ``True``, that
        condition was permanently satisfied: the test could never run and never
        fail, so the class contributed no evidence while still reporting as
        covered. A test that cannot fail is not a test — it is replaced with the
        assertion that actually holds now.
        """
        assert RFC3161_AVAILABLE is True

    def test_invalid_tsa_mode_raises(self) -> None:
        """An invalid tsa_mode must raise ValueError."""
        with pytest.raises(ValueError, match="Unsupported tsa_mode"):
            get_timestamp(b"data", tsa_mode="bogus")


class TestVerifyTimestamp:
    """Tests for verify_timestamp()."""

    def test_verify_matching_data(self) -> None:
        """verify_timestamp must return True for matching data.

        A mock token is only a trust path inside a testing context, so the
        verify runs under ``allow_mock_tsa`` — outside it, a mock-format token
        is refused (see ``test_mock_token_refused_outside_testing_context``).
        """
        data = b"important document"
        result = get_timestamp(data, tsa_mode="mock", hash_algorithm="sha3-256")
        assert result is not None
        with allow_mock_tsa():
            assert verify_timestamp(data, result) is True

    def test_verify_mismatched_data(self) -> None:
        """verify_timestamp must return False when data does not match."""
        data = b"important document"
        result = get_timestamp(data, tsa_mode="mock", hash_algorithm="sha3-256")
        assert result is not None
        # Tamper with the stored data_hash so the recompute check fails
        tampered = TimestampResult(
            token=result.token,
            tsa_url=result.tsa_url,
            hash_algorithm=result.hash_algorithm,
            data_hash=b"\x00" * 32,
        )
        with allow_mock_tsa():
            assert verify_timestamp(data, tampered) is False

    def test_mock_token_refused_outside_testing_context(self) -> None:
        """A MockTSA-format token must not verify on the production path.

        Mock tokens are self-authenticating (the HMAC key ships inside the
        token), so honouring one outside a testing context would let anyone
        forge a "valid" timestamp for any data by supplying the whole
        ``TimestampResult``. The forged token below carries a correct HMAC and
        an attacker-chosen ``genTime`` of epoch 0, and its stored ``data_hash``
        matches the data — the exact shape a real mock round trip has — yet with
        mock mode disabled ``verify_timestamp`` refuses it.
        """
        import struct

        from ama_cryptography import rfc3161_timestamp as ts_mod

        data = b"attacker-chosen document"
        digest = hashlib.sha3_256(data).digest()
        algo = b"sha3-256"
        payload = (
            ts_mod._MOCK_MAGIC
            + struct.pack(">I", len(algo))
            + algo
            + struct.pack(">d", 0.0)
            + digest
        )
        nonce = b"\x00" * 32
        forged = payload + ts_mod._hmac_sha256(nonce, payload) + nonce
        result = TimestampResult(
            token=forged,
            tsa_url="https://freetsa.org/tsr",
            hash_algorithm="sha3-256",
            data_hash=digest,
        )

        assert ts_mod._MOCK_TSA_ALLOWED is False
        assert verify_timestamp(data, result) is False
        # The same forged token is honoured only when a testing context opts in.
        with allow_mock_tsa():
            assert verify_timestamp(data, result) is True

    def test_verify_disabled_token_valid_with_matching_data(self) -> None:
        """Disabled tokens should verify as True when data matches."""
        result = get_timestamp(b"data", tsa_mode="disabled")
        assert result is not None
        assert verify_timestamp(b"data", result) is True


class TestDefaultTSAUrl:
    """Tests for the default TSA URL."""

    def test_default_tsa_url_is_https(self) -> None:
        """The default TSA URL hard-coded in the source module must use HTTPS.

        The source is inspected rather than the warning observed, because
        reaching the warning would mean contacting a TSA and these tests are
        offline by construction. (The original reason given here — that
        ``rfc3161ng`` might be missing and the function would raise
        ``TimestampUnavailableError`` first — stopped being true when that
        dependency was removed.)
        """
        import inspect

        source = inspect.getsource(get_timestamp)
        # The default URL assigned when tsa_url is None should be HTTPS
        assert "https://" in source, "Expected the default TSA URL in get_timestamp() to use HTTPS"
