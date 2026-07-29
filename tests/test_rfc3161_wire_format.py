# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""AMA's own RFC 3161 encoder and decoder.

``legacy_compat`` used to shell out to ``openssl ts`` to build a TimeStampReq
and to check a token. INVARIANT-1 says the core package "must not import or
call" a third-party cryptographic implementation at runtime, so that was a
violation sitting in the shipped tree — and a hard dependency on an ``openssl``
binary being installed, which nothing declared.

RFC 3161 specifies the request completely, so AMA encodes it with its own DER
codec. These tests assert against the RFC's ASN.1, field by field, rather than
against any implementation's output.

They also cover a defect the subprocess shape hid: the response was returned
verbatim without ever reading ``PKIStatusInfo``, so a TSA *rejection* was handed
back in the same shape as a granted token.
"""

from __future__ import annotations

import hashlib
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ama_cryptography._asn1 import (  # noqa: E402 -- follows the sys.path insert (TSP-001)
    DerReader,
    der_integer,
    der_null,
    der_octet_string,
    der_sequence,
    der_tagged,
    oid_from_string,
)
from ama_cryptography.rfc3161_timestamp import (  # noqa: E402 -- same (TSP-001)
    TSA_HASH_OIDS,
    TimestampError,
    build_timestamp_request,
    extract_tst_info,
    parse_timestamp_response,
    verify_token_binding,
)

DATA = b"the quick brown fox"

#: RFC 5652 §5.1 / RFC 3161 §2.4.2.
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_CT_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
SHA256_OID = "2.16.840.1.101.3.4.2.1"


def make_tst_info(digest: bytes, hash_oid: str, policy: str = "1.2.3.4.5") -> bytes:
    """A TSTInfo carrying ``digest`` (RFC 3161 §2.4.2)."""
    return der_sequence(
        der_integer(1),
        oid_from_string(policy),
        der_sequence(
            der_sequence(oid_from_string(hash_oid), der_null()),
            der_octet_string(digest),
        ),
        der_integer(42),
    )


#: A structurally complete but cryptographically meaningless SignerInfo.
#:
#: These tests are about the *binding*, and `verify_token_binding` documents
#: that it does not verify a signature — so the signature value here is
#: nonsense on purpose. What it must not be is *absent*: `extract_tst_info`
#: refuses a SignedData whose `digestAlgorithms` or `signerInfos` set is empty,
#: because such a structure is one anybody can build offline, and the earlier
#: fixture built exactly that. A fixture that a real verifier would reject is
#: not a fixture, it is a false negative waiting to be discovered.
def _signer_info() -> bytes:
    return der_sequence(
        der_integer(1),  # CMSVersion
        der_sequence(  # SignerIdentifier: issuerAndSerialNumber
            der_sequence(),  # issuer Name (empty RDNSequence)
            der_integer(1),  # serialNumber
        ),
        der_sequence(oid_from_string(SHA256_OID), der_null()),  # digestAlgorithm
        der_sequence(oid_from_string(OID_RSA_ENCRYPTION), der_null()),  # signatureAlgorithm
        der_octet_string(b"\x00" * 32),  # signature — not checked, see above
    )


def _der_set(*elements: bytes) -> bytes:
    body = b"".join(elements)
    if len(body) < 0x80:
        return bytes([0x31, len(body)]) + body
    length = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([0x31, 0x80 | len(length)]) + length + body


def make_token(tst_info: bytes) -> bytes:
    """Wrap a TSTInfo as a CMS ContentInfo/SignedData, per RFC 5652 §5.1."""
    signed_data = der_sequence(
        der_integer(3),
        _der_set(der_sequence(oid_from_string(SHA256_OID), der_null())),  # digestAlgorithms
        der_sequence(oid_from_string(OID_CT_TSTINFO), der_tagged(0, der_octet_string(tst_info))),
        _der_set(_signer_info()),  # signerInfos
    )
    return der_sequence(oid_from_string(OID_SIGNED_DATA), der_tagged(0, signed_data))


def make_response(token: bytes, status: int = 0) -> bytes:
    elements = [der_sequence(der_integer(status))]
    if token:
        elements.append(token)
    return der_sequence(*elements)


# ---------------------------------------------------------------------------
# TimeStampReq — RFC 3161 §2.4.1
# ---------------------------------------------------------------------------
def test_request_matches_the_rfc_field_by_field() -> None:
    """Decode what we encoded and check every field the RFC fixes."""
    digest = hashlib.sha256(DATA).digest()
    request = build_timestamp_request(digest, "sha256")

    outer = DerReader(request)
    req = outer.read_sequence()
    outer.finish()

    assert req.read_integer() == 1, "version must be v1"
    imprint = req.read_sequence()
    algorithm = imprint.read_sequence()
    assert algorithm.read_oid() == "2.16.840.1.101.3.4.2.1"
    algorithm.read_null()
    algorithm.finish()
    assert imprint.read_octet_string() == digest
    imprint.finish()
    # reqPolicy, nonce and extensions are absent; certReq is DEFAULT FALSE and
    # X.690 §11.5 forbids encoding a DEFAULT in DER.
    assert req.peek_tag() is None
    req.finish()


@pytest.mark.parametrize("algorithm", sorted(TSA_HASH_OIDS))
def test_every_supported_algorithm_encodes_and_reads_back(algorithm: str) -> None:
    size = {"sha256": 32, "sha384": 48, "sha512": 64, "sha3-256": 32, "sha3-384": 48}.get(
        algorithm, 64
    )
    request = build_timestamp_request(b"\xa5" * size, algorithm)
    req = DerReader(request).read_sequence()
    req.read_integer()
    imprint = req.read_sequence()
    assert imprint.read_sequence().read_oid() == TSA_HASH_OIDS[algorithm]


def test_a_nonce_is_encoded_when_asked_and_omitted_otherwise() -> None:
    """A nonce is how a caller detects a replayed TSA response, so it has to be
    reachable — and absent by default, since a TSA may refuse one."""
    digest = hashlib.sha256(DATA).digest()
    with_nonce = DerReader(build_timestamp_request(digest, "sha256", nonce=0x1234)).read_sequence()
    with_nonce.read_integer()
    with_nonce.read_sequence()
    assert with_nonce.read_integer() == 0x1234

    without = DerReader(build_timestamp_request(digest, "sha256")).read_sequence()
    without.read_integer()
    without.read_sequence()
    assert without.peek_tag() is None


def test_cert_req_is_encoded_only_when_true() -> None:
    digest = hashlib.sha256(DATA).digest()
    assert build_timestamp_request(digest, "sha256", cert_req=False) == build_timestamp_request(
        digest, "sha256"
    ), "certReq FALSE is the DEFAULT and must not be encoded (X.690 §11.5)"
    with_cert = build_timestamp_request(digest, "sha256", cert_req=True)
    assert with_cert.endswith(b"\x01\x01\xff") and len(with_cert) > len(
        build_timestamp_request(digest, "sha256")
    )


@pytest.mark.parametrize(
    ("digest", "algorithm"),
    [(b"\x00" * 31, "sha256"), (b"\x00" * 33, "sha256"), (b"\x00" * 32, "sha512")],
)
def test_a_digest_of_the_wrong_length_is_refused(digest: bytes, algorithm: str) -> None:
    """Encoding it anyway would surface as an opaque TSA rejection much later."""
    with pytest.raises(ValueError, match="digest must be"):
        build_timestamp_request(digest, algorithm)


def test_an_unsupported_algorithm_is_refused() -> None:
    with pytest.raises(ValueError, match="Unsupported hash algorithm"):
        build_timestamp_request(b"\x00" * 16, "md5")


# ---------------------------------------------------------------------------
# TimeStampResp — RFC 3161 §2.4.2
# ---------------------------------------------------------------------------
def test_a_granted_response_yields_its_token() -> None:
    token = make_token(make_tst_info(hashlib.sha256(DATA).digest(), TSA_HASH_OIDS["sha256"]))
    assert parse_timestamp_response(make_response(token)) == token


@pytest.mark.parametrize(
    ("status", "name"),
    [(2, "rejection"), (3, "waiting"), (4, "revocationWarning"), (5, "revocationNotification")],
)
def test_a_non_granted_status_is_never_returned_as_a_token(status: int, name: str) -> None:
    """The defect the subprocess shape hid.

    Nothing read ``PKIStatusInfo``, so the TSA's refusal was returned to the
    caller in the same shape as a timestamp and stored as though it were one.
    """
    token = make_token(make_tst_info(hashlib.sha256(DATA).digest(), TSA_HASH_OIDS["sha256"]))
    with pytest.raises(TimestampError, match=name):
        parse_timestamp_response(make_response(token, status=status))


def test_granted_with_mods_is_accepted() -> None:
    """PKIStatus 1 carries a token; refusing it would break real TSAs."""
    token = make_token(make_tst_info(hashlib.sha256(DATA).digest(), TSA_HASH_OIDS["sha256"]))
    assert parse_timestamp_response(make_response(token, status=1)) == token


def test_granted_with_no_token_is_a_failure() -> None:
    with pytest.raises(TimestampError, match="no timeStampToken"):
        parse_timestamp_response(make_response(b"", status=0))


@pytest.mark.parametrize(
    "payload", [b"", b"TSR_RESPONSE", b"\x30\x03\x02\x01", b"\x04\x01\x00", bytes(range(64))]
)
def test_a_malformed_response_raises_rather_than_returning_something(payload: bytes) -> None:
    with pytest.raises(TimestampError):
        parse_timestamp_response(payload)


# ---------------------------------------------------------------------------
# Token binding — the half of verification AMA implements
# ---------------------------------------------------------------------------
def test_binding_holds_for_the_data_that_was_timestamped() -> None:
    token = make_token(make_tst_info(hashlib.sha256(DATA).digest(), TSA_HASH_OIDS["sha256"]))
    assert verify_token_binding(DATA, token) is True
    assert verify_token_binding(DATA, make_response(token)) is True, "response form too"


def test_binding_fails_for_different_data() -> None:
    """A mismatch is a verification *failure*, reported as False — not an error.
    Anything that stops the check running raises instead."""
    token = make_token(make_tst_info(hashlib.sha256(DATA).digest(), TSA_HASH_OIDS["sha256"]))
    assert verify_token_binding(b"different data", token) is False


@pytest.mark.parametrize("algorithm", ["sha256", "sha384", "sha512", "sha3-256", "sha3-512"])
def test_binding_uses_the_algorithm_the_token_names(algorithm: str) -> None:
    """Not a hardcoded SHA-256: the token says which digest it used."""
    digest = {
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
        "sha3-256": hashlib.sha3_256,
        "sha3-512": hashlib.sha3_512,
    }[algorithm](DATA).digest()
    token = make_token(make_tst_info(digest, TSA_HASH_OIDS[algorithm]))
    assert verify_token_binding(DATA, token) is True
    assert verify_token_binding(DATA + b"!", token) is False


def test_a_token_naming_an_unknown_hash_raises_rather_than_passing() -> None:
    """Fail closed: an algorithm AMA cannot compute means the binding was not
    checked, which must not be reported as a check that passed."""
    token = make_token(make_tst_info(b"\x00" * 16, "1.2.840.113549.2.5"))  # md5
    with pytest.raises(TimestampError, match="does not implement"):
        verify_token_binding(DATA, token)


def test_a_token_that_is_not_signed_data_is_refused() -> None:
    not_cms = der_sequence(oid_from_string("1.2.3.4"), der_tagged(0, der_integer(1)))
    with pytest.raises(TimestampError, match="not a CMS SignedData"):
        extract_tst_info(not_cms)


def test_a_token_encapsulating_something_other_than_tstinfo_is_refused() -> None:
    signed_data = der_sequence(
        der_integer(3),
        _der_set(der_sequence(oid_from_string(SHA256_OID), der_null())),
        der_sequence(
            oid_from_string("1.2.840.113549.1.7.1"), der_tagged(0, der_octet_string(b"x"))
        ),
        _der_set(_signer_info()),
    )
    token = der_sequence(oid_from_string(OID_SIGNED_DATA), der_tagged(0, signed_data))
    with pytest.raises(TimestampError, match="does not encapsulate a TSTInfo"):
        extract_tst_info(token)


def test_a_token_with_no_econtent_attests_to_nothing() -> None:
    signed_data = der_sequence(
        der_integer(3),
        _der_set(der_sequence(oid_from_string(SHA256_OID), der_null())),
        der_sequence(oid_from_string(OID_CT_TSTINFO)),
        _der_set(_signer_info()),
    )
    token = der_sequence(oid_from_string(OID_SIGNED_DATA), der_tagged(0, signed_data))
    with pytest.raises(TimestampError, match="attests to nothing"):
        extract_tst_info(token)


def test_a_response_that_nests_timestampresp_is_bounded_not_recursed() -> None:
    """A TimeStampResp nested inside a TimeStampResp ... must hit a depth bound.

    ``extract_tst_info`` recognises a status envelope by its first inner element
    being a SEQUENCE (PKIStatusInfo) rather than a ContentInfo's contentType
    OID, and unwraps it. A structure that keeps that shape at every level used
    to recurse once per layer, so a few dozen levels drove ``RecursionError``
    straight past the ``TimestampError`` boundary the module otherwise
    guarantees — the DoS class it bounds for CBOR and OIDs. It is now refused by
    ``_MAX_TSR_UNWRAP`` instead.
    """
    granted_status = der_sequence(der_integer(0))
    # The innermost value keeps the "looks like a response" shape, so the unwrap
    # never terminates on a ContentInfo and must terminate on the depth bound.
    nested = der_sequence(granted_status, granted_status)
    for _ in range(64):
        nested = der_sequence(granted_status, nested)
    with pytest.raises(TimestampError, match="nests more than"):
        extract_tst_info(nested)


# ---------------------------------------------------------------------------
# The legacy API's contract, and what it now refuses to pretend
# ---------------------------------------------------------------------------
def test_chain_validation_is_refused_rather_than_silently_downgraded() -> None:
    """``tsa_cert_path`` asks for X.509 path validation of the TSA certificate.

    AMA implements neither CMS SignerInfo processing nor X.509 path validation.
    Answering with the binding check would answer a different, weaker question
    while looking like it answered this one, so the call raises instead.
    """
    from ama_cryptography.legacy_compat import verify_rfc3161_timestamp

    token = make_token(make_tst_info(hashlib.sha256(DATA).digest(), TSA_HASH_OIDS["sha256"]))
    with pytest.raises(RuntimeError, match=r"X\.509"):
        verify_rfc3161_timestamp(DATA, token, tsa_cert_path="/etc/ssl/certs/tsa.pem")


def test_the_legacy_verifier_agrees_with_the_binding_check() -> None:
    from ama_cryptography.legacy_compat import verify_rfc3161_timestamp

    token = make_token(make_tst_info(hashlib.sha256(DATA).digest(), TSA_HASH_OIDS["sha256"]))
    assert verify_rfc3161_timestamp(DATA, token) is True
    assert verify_rfc3161_timestamp(b"other", token) is False


# ---------------------------------------------------------------------------
# Transport: the response body is bounded in size *and* in time
# ---------------------------------------------------------------------------
class _DripResponse:
    """An HTTP response that never finishes, one octet at a time.

    Models the peer a socket timeout cannot catch: every ``read`` returns data,
    so the per-operation timer is rearmed forever and the transfer itself is
    what never terminates.  ``time.monotonic`` is not slept through — the clock
    is advanced by the harness — so the test costs nothing to run.
    """

    def __init__(self, clock: list[float], per_read_seconds: float = 1.0) -> None:
        self._clock = clock
        self._per_read = per_read_seconds
        self.reads = 0

    def read(self, amount: int) -> bytes:
        self.reads += 1
        self._clock[0] += self._per_read
        return b"\x00"


class _FiniteResponse:
    """A well-behaved peer that delivers ``body`` across several reads."""

    def __init__(self, body: bytes, chunk: int) -> None:
        self._body = body
        self._chunk = chunk
        self._pos = 0

    def read(self, amount: int) -> bytes:
        take = min(self._chunk, amount, len(self._body) - self._pos)
        out = self._body[self._pos : self._pos + take]
        self._pos += take
        return out


def test_a_drip_feeding_tsa_hits_the_total_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    """A socket timeout bounds one recv; it does not bound the transfer.

    Without a deadline of its own, a peer sending one octet per nine seconds
    never trips a ten-second socket timeout, and the 256 KiB ceiling puts the
    worst case at roughly three weeks with the signing process parked on the
    socket the whole time.
    """
    from ama_cryptography import rfc3161_timestamp as ts

    clock = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    response = _DripResponse(clock, per_read_seconds=1.0)
    deadline = clock[0] + ts._TSA_TOTAL_DEADLINE

    with pytest.raises(TimestampError, match="did not complete within"):
        ts._read_bounded(response, ts._MAX_TSR_BYTES, deadline)

    # It gave up on the deadline, not after draining 256 KiB one octet at a time.
    assert response.reads <= int(ts._TSA_TOTAL_DEADLINE) + 1


def test_a_prompt_response_is_returned_whole(monkeypatch: pytest.MonkeyPatch) -> None:
    """The deadline must not truncate a healthy multi-chunk transfer."""
    from ama_cryptography import rfc3161_timestamp as ts

    monkeypatch.setattr(time, "monotonic", lambda: 0.0)
    body = bytes(range(256)) * 40  # 10 240 octets
    response = _FiniteResponse(body, chunk=1024)
    assert ts._read_bounded(response, ts._MAX_TSR_BYTES, 30.0) == body


def test_an_over_long_body_is_detected_not_truncated(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reading one octet past the cap is what distinguishes the two."""
    from ama_cryptography import rfc3161_timestamp as ts

    monkeypatch.setattr(time, "monotonic", lambda: 0.0)
    limit = 4096
    response = _FiniteResponse(b"A" * (limit + 500), chunk=512)
    raw = ts._read_bounded(response, limit, 30.0)
    assert len(raw) == limit + 1, "an over-long body must be observable, not silently cut to size"


def test_the_deadline_is_monotonic_not_wall_clock() -> None:
    """A clock step must not abort a healthy transfer or extend a stalled one."""
    import inspect

    from ama_cryptography import rfc3161_timestamp as ts

    source = inspect.getsource(ts._read_bounded) + inspect.getsource(ts.request_timestamp_exchange)
    assert "time.monotonic()" in source
    assert "time.time()" not in source
