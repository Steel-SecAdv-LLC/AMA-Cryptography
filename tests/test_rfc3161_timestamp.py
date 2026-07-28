#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
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

from ama_cryptography._asn1 import (
    DerReader,
    der_integer,
    der_null,
    der_octet_string,
    der_sequence,
    der_tagged,
    oid_from_string,
)
from ama_cryptography.rfc3161_timestamp import (
    RFC3161_AVAILABLE,
    TimestampError,
    TimestampResult,
    TimestampUnavailableError,
    get_timestamp,
    verify_timestamp,
    verify_token_binding,
)

#: Every transport test posts here; the socket is mocked, nothing leaves.
TSA = "https://tsa.example.com"

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
# A TSA, mocked at the socket rather than at a third-party client
#
# These tests used to drive `rfc3161ng.RemoteTimestamper`. That library is gone
# — INVARIANT-1 forbids the core package calling a third-party cryptographic
# implementation, and it was never declared as an optional extra, so the
# carve-out never covered it — and the protocol is now AMA's own. Mocking
# `http.client.HTTPSConnection` instead means these tests exercise the request
# encoder, the response decoder, the nonce echo and the imprint binding, none of
# which the old mock could reach.
# ---------------------------------------------------------------------------


def _der_set(*elements: bytes) -> bytes:
    body = b"".join(elements)
    if len(body) < 0x80:
        return bytes([0x31, len(body)]) + body
    return bytes([0x31, 0x81, len(body)]) + body


def make_token(digest: bytes, hash_oid: str, nonce: int | None) -> bytes:
    """A structurally complete RFC 3161 token binding ``digest``."""
    fields = [
        der_integer(1),
        oid_from_string("1.2.3.4.5"),
        der_sequence(
            der_sequence(oid_from_string(hash_oid), der_null()),
            der_octet_string(digest),
        ),
        der_integer(42),
        b"\x18\x0f20260101000000Z",
    ]
    if nonce is not None:
        fields.append(der_integer(nonce))
    tst_info = der_sequence(*fields)
    signer_info = der_sequence(
        der_integer(1),
        der_sequence(der_sequence(), der_integer(1)),
        der_sequence(oid_from_string(hash_oid), der_null()),
        der_sequence(oid_from_string("1.2.840.113549.1.1.1"), der_null()),
        der_octet_string(b"\x00" * 32),
    )
    signed_data = der_sequence(
        der_integer(3),
        _der_set(der_sequence(oid_from_string(hash_oid), der_null())),
        der_sequence(
            oid_from_string("1.2.840.113549.1.9.16.1.4"),
            der_tagged(0, der_octet_string(tst_info)),
        ),
        _der_set(signer_info),
    )
    return der_sequence(oid_from_string("1.2.840.113549.1.7.2"), der_tagged(0, signed_data))


class _MockTSA:
    """Answers a posted TimeStampReq the way a conformant TSA would."""

    def __init__(
        self,
        *,
        status: int = 0,
        include_token: bool = True,
        echo_nonce: bool = True,
        override_digest: bytes | None = None,
        http_status: int = 200,
        content_length: str | None = None,
        body_override: bytes | None = None,
    ) -> None:
        self.status = status
        self.include_token = include_token
        self.echo_nonce = echo_nonce
        self.override_digest = override_digest
        self.http_status = http_status
        self.content_length = content_length
        self.body_override = body_override
        self.request_body: bytes = b""

    def install(self, mock_conn_cls: Any) -> None:
        response = MagicMock(status=self.http_status)
        response.getheader.return_value = self.content_length
        conn = mock_conn_cls.return_value
        conn.getresponse.return_value = response

        def _request(method: str, path: str, body: bytes = b"", headers: Any = None) -> None:
            self.request_body = body
            response.read.return_value = self._answer(body)

        conn.request.side_effect = _request

    def _answer(self, body: bytes) -> bytes:
        if self.body_override is not None:
            return self.body_override
        req = DerReader(body).read_sequence()
        req.read_integer()  # version
        imprint = req.read_sequence()
        algorithm = imprint.read_sequence()
        hash_oid = algorithm.read_oid()
        algorithm.read_null()
        digest = imprint.read_octet_string()
        nonce = req.read_integer() if req.peek_tag() == 0x02 else None
        if self.override_digest is not None:
            digest = self.override_digest
        elements = [der_sequence(der_integer(self.status))]
        if self.include_token:
            elements.append(make_token(digest, hash_oid, nonce if self.echo_nonce else None))
        return der_sequence(*elements)


# ---------------------------------------------------------------------------
# get_timestamp
# ---------------------------------------------------------------------------


class TestGetTimestamp:
    """Test get_timestamp input validation and behaviour."""

    def test_unsupported_hash_algorithm_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            get_timestamp(b"data", tsa_url=TSA, hash_algorithm="md5")

    def test_http_url_is_refused(self) -> None:
        """The transport is https-only, checked before any socket is opened."""
        with pytest.raises(ValueError, match="must be https"):
            get_timestamp(b"data", tsa_url="http://tsa.example.com")

    def test_certificate_file_is_refused_rather_than_ignored(self) -> None:
        """``certificate_file`` asked for the TSA signature to be verified.

        AMA implements neither CMS SignerInfo processing nor X.509 path
        validation. Accepting the argument and performing only the binding
        check would answer a weaker question while looking like it answered
        this one.
        """
        with pytest.raises(TimestampError, match="certificate_file"):
            get_timestamp(b"data", tsa_url=TSA, certificate_file="tsa-signing-cert.pem")

    def test_default_tsa_url_emits_warning(self) -> None:
        tsa = _MockTSA()
        with patch("http.client.HTTPSConnection") as conn_cls:
            tsa.install(conn_cls)
            with pytest.warns(UserWarning, match="No TSA URL specified"):
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
        data = b"test-data-for-hashing"
        tsa = _MockTSA()
        with patch("http.client.HTTPSConnection") as conn_cls:
            tsa.install(conn_cls)
            result = get_timestamp(data, tsa_url=TSA, hash_algorithm=algo)
        assert result.data_hash == hashfunc(data).digest()
        assert result.hash_algorithm == algo
        assert result.tsa_url == TSA
        # The token returned is the one that binds this data.
        assert verify_token_binding(data, result.token)

    def test_a_nonce_is_sent_and_its_echo_is_required(self) -> None:
        """RFC 3161 §2.4.2's nonce echo is the client's only replay defence.

        Before this, no nonce was sent and none was checked: a captured token
        for the same imprint was indistinguishable from a fresh one, and
        ``build_timestamp_request(nonce=...)`` documented an anti-replay
        property no API could reach.
        """
        tsa = _MockTSA()
        with patch("http.client.HTTPSConnection") as conn_cls:
            tsa.install(conn_cls)
            get_timestamp(b"data", tsa_url=TSA)
        req = DerReader(tsa.request_body).read_sequence()
        req.read_integer()
        req.read_sequence()
        assert req.peek_tag() == 0x02, "no nonce was sent"
        assert req.read_integer() != 0

        replaying = _MockTSA(echo_nonce=False)
        with patch("http.client.HTTPSConnection") as conn_cls:
            replaying.install(conn_cls)
            with pytest.raises(TimestampError, match="does not echo"):
                get_timestamp(b"data", tsa_url=TSA)

    def test_cert_req_is_asked_for(self) -> None:
        """A token archived without the TSA's certificate can never have its
        signature verified later, because by then the certificate may have
        rotated and no longer be published."""
        tsa = _MockTSA()
        with patch("http.client.HTTPSConnection") as conn_cls:
            tsa.install(conn_cls)
            get_timestamp(b"data", tsa_url=TSA)
        req = DerReader(tsa.request_body).read_sequence()
        req.read_integer()
        req.read_sequence()
        req.read_integer()  # nonce
        assert req.peek_tag() == 0x01, "certReq BOOLEAN must be present"

    def test_a_token_that_binds_other_data_is_refused(self) -> None:
        """RFC 3161 §2.4.2 requires the imprint cross-check, and skipping it
        means an attestation about unrelated data is stored as though it were
        about yours — discovered only at some later verification, after the
        artefact is on disk and the TSA interaction is unrepeatable."""
        tsa = _MockTSA(override_digest=hashlib.sha256(b"something else").digest())
        with patch("http.client.HTTPSConnection") as conn_cls:
            tsa.install(conn_cls)
            with pytest.raises(TimestampError, match="attests to something else"):
                get_timestamp(b"data", tsa_url=TSA)

    @pytest.mark.parametrize("status", [2, 3, 4, 5])
    def test_a_rejection_is_not_returned_as_a_timestamp(self, status: int) -> None:
        tsa = _MockTSA(status=status, include_token=False)
        with patch("http.client.HTTPSConnection") as conn_cls:
            tsa.install(conn_cls)
            with pytest.raises(TimestampError, match="did not grant"):
                get_timestamp(b"data", tsa_url=TSA)

    def test_a_granted_status_with_no_token_is_refused(self) -> None:
        tsa = _MockTSA(include_token=False)
        with patch("http.client.HTTPSConnection") as conn_cls:
            tsa.install(conn_cls)
            with pytest.raises(TimestampError, match="sent no"):
                get_timestamp(b"data", tsa_url=TSA)

    def test_an_over_long_response_is_refused_before_it_is_parsed(self) -> None:
        """An unbounded ``response.read()`` let one TSA reply allocate arbitrary
        memory before any validity check ran."""
        tsa = _MockTSA(content_length="4294967296")
        with patch("http.client.HTTPSConnection") as conn_cls:
            tsa.install(conn_cls)
            with pytest.raises(TimestampError, match="limit"):
                get_timestamp(b"data", tsa_url=TSA)

        # …and a peer that lies about Content-Length is caught by the read cap.
        tsa = _MockTSA(body_override=b"\x30" * (300 * 1024))
        with patch("http.client.HTTPSConnection") as conn_cls:
            tsa.install(conn_cls)
            conn_cls.return_value.getresponse.return_value.read.side_effect = (
                lambda n=None: b"\x30" * (n if n else 300 * 1024)
            )
            with pytest.raises(TimestampError, match="exceeds"):
                get_timestamp(b"data", tsa_url=TSA)

    def test_non_2xx_is_refused(self) -> None:
        tsa = _MockTSA(http_status=503)
        with patch("http.client.HTTPSConnection") as conn_cls:
            tsa.install(conn_cls)
            with pytest.raises(TimestampError, match="HTTP status 503"):
                get_timestamp(b"data", tsa_url=TSA)

    def test_network_error_raises_timestamp_error(self) -> None:
        with patch("http.client.HTTPSConnection") as conn_cls:
            conn_cls.return_value.request.side_effect = ConnectionError("connection refused")
            with pytest.raises(TimestampError, match="failed"):
                get_timestamp(b"data", tsa_url=TSA)

    def test_value_error_passthrough(self) -> None:
        with pytest.raises(ValueError):
            get_timestamp(b"data", tsa_url=TSA, hash_algorithm="blake2")


# ---------------------------------------------------------------------------
# verify_timestamp
# ---------------------------------------------------------------------------


class TestVerifyTimestamp:
    """Test verify_timestamp logic."""

    @staticmethod
    def _result(data: bytes, algo: str = "sha256") -> TimestampResult:
        hash_funcs = {
            "sha256": hashlib.sha256,
            "sha3-256": hashlib.sha3_256,
            "sha512": hashlib.sha512,
            "sha3-512": hashlib.sha3_512,
        }
        digest = hash_funcs[algo](data).digest()
        oid = {
            "sha256": "2.16.840.1.101.3.4.2.1",
            "sha3-256": "2.16.840.1.101.3.4.2.8",
            "sha512": "2.16.840.1.101.3.4.2.3",
            "sha3-512": "2.16.840.1.101.3.4.2.10",
        }[algo]
        return TimestampResult(
            token=make_token(digest, oid, 1234),
            tsa_url=TSA,
            hash_algorithm=algo,
            data_hash=digest,
        )

    def test_certificate_file_is_refused_rather_than_ignored(self) -> None:
        with pytest.raises(TimestampError, match="certificate_file"):
            verify_timestamp(b"doc", self._result(b"doc"), certificate_file="tsa-signing-cert.pem")

    def test_hash_mismatch_returns_false(self) -> None:
        result = TimestampResult(
            token=make_token(b"\x00" * 32, "2.16.840.1.101.3.4.2.1", None),
            tsa_url=TSA,
            hash_algorithm="sha256",
            data_hash=b"\x00" * 32,
        )
        assert verify_timestamp(b"real data", result) is False

    def test_unsupported_algorithm_returns_false(self) -> None:
        result = TimestampResult(token=b"tok", tsa_url=TSA, hash_algorithm="md5", data_hash=b"h")
        assert verify_timestamp(b"data", result) is False

    @pytest.mark.parametrize("algo", ["sha256", "sha3-256", "sha512", "sha3-512"])
    def test_valid_verification_all_algorithms(self, algo: str) -> None:
        data = b"important document"
        assert verify_timestamp(data, self._result(data, algo)) is True

    def test_tampered_data_fails_verification(self) -> None:
        result = self._result(b"original document")
        assert verify_timestamp(b"tampered document", result) is False

    def test_a_malformed_token_returns_false_rather_than_raising(self) -> None:
        data = b"doc"
        result = TimestampResult(
            token=b"\x30\x03\x02\x01\x00",
            tsa_url=TSA,
            hash_algorithm="sha256",
            data_hash=hashlib.sha256(data).digest(),
        )
        assert verify_timestamp(data, result) is False

    def test_an_unsigned_token_is_refused(self) -> None:
        """A SignedData with an empty signerInfos set is a container anybody
        can build offline; it must not reach the binding check at all."""
        data = b"doc"
        digest = hashlib.sha256(data).digest()
        tst_info = der_sequence(
            der_integer(1),
            oid_from_string("1.2.3.4.5"),
            der_sequence(
                der_sequence(oid_from_string("2.16.840.1.101.3.4.2.1"), der_null()),
                der_octet_string(digest),
            ),
            der_integer(42),
        )
        signed_data = der_sequence(
            der_integer(3),
            b"\x31\x00",
            der_sequence(
                oid_from_string("1.2.840.113549.1.9.16.1.4"),
                der_tagged(0, der_octet_string(tst_info)),
            ),
            b"\x31\x00",
        )
        forged = der_sequence(oid_from_string("1.2.840.113549.1.7.2"), der_tagged(0, signed_data))
        result = TimestampResult(
            token=forged, tsa_url=TSA, hash_algorithm="sha256", data_hash=digest
        )
        assert verify_timestamp(data, result) is False


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
            # The binding check under a name that matches it, plus the
            # deprecated alias it replaces (INVARIANT-37).
            "verify_timestamp_binding",
            "verify_timestamp",
            # The same verdict as a record that names what was *not* checked.
            "describe_token_verification",
            "TokenVerification",
            # The single source of truth for which checks AMA performs. The
            # INVARIANT-37 gate, TokenVerification and the honesty tests all
            # read this table rather than restating its facts.
            "RFC3161_CAPABILITIES",
            "TimestampResult",
            "TimestampUnavailableError",
            "TimestampError",
            "RFC3161_AVAILABLE",
            # Exported because the documented mock-mode example needs it:
            # creating and honouring a mock token are both gated to a testing
            # context, so a caller following the README must be able to open it.
            "allow_mock_tsa",
            # The codec is now exported too: it was reachable only from the
            # deprecated legacy surface, which is how the module came to keep a
            # third-party client for a protocol it already implements.
            "TSA_HASH_OIDS",
            "build_timestamp_request",
            "parse_timestamp_response",
            "request_timestamp_token",
            "request_timestamp_exchange",
            "extract_tst_info",
            "tst_info_nonce",
            "verify_token_binding",
        }
        assert set(mod.__all__) == expected
