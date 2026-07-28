#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
RFC 3161 Timestamp Protocol Implementation
===========================================

Provides Time-Stamp Protocol (TSP) client for obtaining cryptographic timestamps
from RFC 3161 compliant Time-Stamp Authorities (TSAs).

Standard: RFC 3161 - Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)
Reference: https://www.rfc-editor.org/rfc/rfc3161

Security Properties:
--------------------
1. Non-repudiation: Proves data existed at a specific time
2. Third-party attestation: Independent verification by TSA
3. Cryptographic binding: Timestamp is cryptographically bound to data hash
4. Long-term validity: Uses long-term signature algorithms (e.g., SPHINCS+)

Use Cases:
----------
- Legal documents requiring proof of existence
- Code signing with verifiable creation time
- Audit logs with tamper-evident timestamps
- Long-term archival with time attestation
"""

import hashlib
import http.client
import logging
import os as _os_mod
import secrets
import struct
import threading
import time
import warnings
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Dict, Generator, Optional
from urllib.parse import urlparse

_logger = logging.getLogger(__name__)

# RFC 3161 is implemented in this module, on AMA's own DER codec — see the wire
# format section below. `rfc3161ng` used to be imported here and to perform the
# whole online protocol, which INVARIANT-1 forbids for the core package: it is a
# third-party cryptographic implementation, and it was not declared as an
# optional extra in pyproject.toml, so the invariant's carve-out never covered
# it. The practical effect was an incoherent module — the *documented* public
# online path raised `TimestampUnavailableError` in a default install, while a
# complete, tested RFC 3161 client sat unused a few hundred lines below it.
#
# `RFC3161_AVAILABLE` is kept and is now unconditionally True: the capability no
# longer depends on anything being installed. Existing `if RFC3161_AVAILABLE:`
# call sites keep working and simply stop being a gate.
RFC3161_AVAILABLE = True


from ama_cryptography._asn1 import (
    DerReader,
    der_integer,
    der_null,
    der_octet_string,
    der_sequence,
    oid_from_string,
)
from ama_cryptography.exceptions import AmaCryptographyError

# ---------------------------------------------------------------------------
# RFC 3161 wire format, encoded and decoded by AMA
# ---------------------------------------------------------------------------
# INVARIANT-1 is explicit that the core package "must not import or call"
# third-party cryptographic packages at runtime. `legacy_compat` nonetheless
# shelled out to the `openssl` binary to build its TimeStampReq — a competing
# implementation performing a cryptographic-protocol operation inside AMA's own
# shipped tree, and a hard dependency on that binary being installed. The
# request is a page of ASN.1 that RFC 3161 fully specifies, so AMA encodes it
# with its own DER codec instead.
#
# RFC 3161 §2.4.1:
#
#     TimeStampReq ::= SEQUENCE  {
#        version                  INTEGER  { v1(1) },
#        messageImprint           MessageImprint,
#        reqPolicy                TSAPolicyId              OPTIONAL,
#        nonce                    INTEGER                  OPTIONAL,
#        certReq                  BOOLEAN                  DEFAULT FALSE,
#        extensions               [0] IMPLICIT Extensions  OPTIONAL  }
#
#     MessageImprint ::= SEQUENCE  {
#          hashAlgorithm                AlgorithmIdentifier,
#          hashedMessage                OCTET STRING  }
#
# `certReq` is omitted rather than encoded FALSE: X.690 §11.5 forbids encoding a
# DEFAULT value in DER, and this module emits DER.

#: NIST hash OIDs, from the CSOR arc these algorithms are registered under
#: (2.16.840.1.101.3.4.2). The SHA-3 entries are the ones AMA prefers; a TSA
#: that does not support them rejects the request with a PKIStatus this module
#: now reads, rather than the caller receiving a rejection shaped like a token.
TSA_HASH_OIDS: Dict[str, str] = {
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha384": "2.16.840.1.101.3.4.2.2",
    "sha512": "2.16.840.1.101.3.4.2.3",
    "sha3-256": "2.16.840.1.101.3.4.2.8",
    "sha3-384": "2.16.840.1.101.3.4.2.9",
    "sha3-512": "2.16.840.1.101.3.4.2.10",
}

#: Digest length each algorithm must produce, so a mismatched hash cannot be
#: encoded into a request that then fails opaquely at the TSA.
_TSA_HASH_BYTES: Dict[str, int] = {
    "sha256": 32,
    "sha384": 48,
    "sha512": 64,
    "sha3-256": 32,
    "sha3-384": 48,
    "sha3-512": 64,
}

#: RFC 3161 §2.4.2 PKIStatus values. 0 and 1 are the two that carry a token.
PKI_STATUS_GRANTED = 0
PKI_STATUS_GRANTED_WITH_MODS = 1
_PKI_STATUS_NAMES = {
    0: "granted",
    1: "grantedWithMods",
    2: "rejection",
    3: "waiting",
    4: "revocationWarning",
    5: "revocationNotification",
}


def build_timestamp_request(
    data_hash: bytes,
    hash_algorithm: str = "sha256",
    *,
    nonce: Optional[int] = None,
    cert_req: bool = False,
) -> bytes:
    """DER-encode an RFC 3161 §2.4.1 ``TimeStampReq`` for ``data_hash``.

    Args:
        data_hash: The digest of the data being timestamped — *not* the data.
        hash_algorithm: Which digest produced it; must be a key of
            :data:`TSA_HASH_OIDS`, and its length must match.
        nonce: Optional RFC 3161 nonce. A TSA echoes it back, which lets a
            caller detect a replayed response. Omitted when ``None``.
        cert_req: Ask the TSA to include its signing certificate in the token.

    Raises:
        ValueError: unknown algorithm, or a digest whose length does not match
            the algorithm named. Both mean the caller has already made a
            mistake, and encoding the request anyway would surface it as an
            opaque TSA rejection much later.
    """
    oid = TSA_HASH_OIDS.get(hash_algorithm)
    if oid is None:
        raise ValueError(
            f"Unsupported hash algorithm for RFC 3161: {hash_algorithm!r}. "
            f"Supported: {sorted(TSA_HASH_OIDS)}"
        )
    expected = _TSA_HASH_BYTES[hash_algorithm]
    if len(data_hash) != expected:
        raise ValueError(f"{hash_algorithm} digest must be {expected} bytes, got {len(data_hash)}")
    if nonce is not None and nonce < 0:
        raise ValueError("RFC 3161 nonce must be a non-negative integer")

    message_imprint = der_sequence(
        der_sequence(oid_from_string(oid), der_null()),
        der_octet_string(data_hash),
    )
    elements = [der_integer(1), message_imprint]
    if nonce is not None:
        elements.append(der_integer(nonce))
    if cert_req:
        # BOOLEAN TRUE. Encoded only when TRUE — see the DEFAULT note above.
        elements.append(b"\x01\x01\xff")
    return der_sequence(*elements)


def parse_timestamp_response(response: bytes, *, expected_nonce: Optional[int] = None) -> bytes:
    """Return the ``timeStampToken`` from an RFC 3161 §2.4.2 ``TimeStampResp``.

    The previous implementation returned the TSA's response verbatim without
    ever looking at it, so a *rejection* was handed back to the caller in the
    same shape as a granted token and stored as though it were one. RFC 3161
    §2.4.2 puts the verdict in ``PKIStatusInfo``, ahead of the optional token::

        TimeStampResp ::= SEQUENCE  {
           status                  PKIStatusInfo,
           timeStampToken          TimeStampToken     OPTIONAL  }

        PKIStatusInfo ::= SEQUENCE {
            status        PKIStatus,
            statusString  PKIFreeText     OPTIONAL,
            failInfo      PKIFailureInfo  OPTIONAL }

    Args:
        response: The DER ``TimeStampResp`` as received.
        expected_nonce: If given, the nonce that was sent in the
            ``TimeStampReq``. RFC 3161 §2.4.2 requires the TSA to echo it into
            the ``TSTInfo``, and checking the echo is the only way a client can
            tell a fresh response from a replayed one — a caching proxy, a
            rolled-back TSA or a hostile operator can otherwise answer today's
            request with last year's token for the same imprint, and nothing
            downstream can see it.

    Raises:
        TimestampError: the response is not a well-formed ``TimeStampResp``,
            the TSA did not grant the request, it granted one and sent no
            token, or ``expected_nonce`` was given and the token does not echo
            it. Every one of those is "you do not have a timestamp", and
            none of them may be returned as if it were one.
    """
    try:
        outer = DerReader(response)
        body = outer.read_sequence()
        outer.finish()
        status_info = body.read_sequence()
        status = status_info.read_integer()

        # RFC 3161 §2.4.2 makes PKIStatus an enumeration of 0..5, so anything
        # else is malformed and is rejected *before* it is formatted into a
        # message. Formatting first was itself an escape: since CPython 3.11
        # `str(int)` refuses a value whose decimal form exceeds
        # `sys.int_max_str_digits`, so a ~2 kB PKIStatus INTEGER made the error
        # path raise `ValueError` past this function's documented
        # `TimestampError` boundary — from data supplied by a network peer.
        # Same defect, same fix, as `_asn1.oid_to_string`'s arc bound.
        if status not in _PKI_STATUS_NAMES:
            raise TimestampError(
                "TSA response carries a PKIStatus outside RFC 3161 §2.4.2's " "0..5 enumeration"
            )

        if status not in (PKI_STATUS_GRANTED, PKI_STATUS_GRANTED_WITH_MODS):
            name = _PKI_STATUS_NAMES[status]
            raise TimestampError(
                f"TSA did not grant the timestamp: PKIStatus {status} ({name}). "
                "No token was issued."
            )

        # PKIStatusInfo's remaining fields are optional and not needed here; the
        # token is the next element of the outer SEQUENCE.
        if body.peek_tag() is None:
            raise TimestampError(
                f"TSA reported PKIStatus {status} ({_PKI_STATUS_NAMES[status]}) but sent no "
                "timeStampToken"
            )
        token = body.read_any_raw()
        # RFC 3161 §2.4.2 defines TimeStampResp as exactly two fields. Anything
        # after the token is a second encoding of the same response — the
        # legacy API stores the whole response, so without this an unbounded
        # family of byte-distinct packages carry one timestamp. `outer.finish()`
        # above rejects trailing data *after* the SEQUENCE; this rejects it
        # inside.
        body.finish()
    except TimestampError:
        raise
    except Exception as exc:
        raise TimestampError(f"TSA response is not a well-formed TimeStampResp: {exc}") from None

    if expected_nonce is not None:
        echoed = tst_info_nonce(extract_tst_info(token))
        if echoed != expected_nonce:
            raise TimestampError(
                "TSA response does not echo the request's nonce "
                f"(sent {expected_nonce}, token carries "
                f"{'none' if echoed is None else echoed}). RFC 3161 §2.4.2 makes the "
                "echo the client's only way to tell a fresh response from a replayed one."
            )
    return token


#: RFC 5652 §5.1 / RFC 3161 §2.4.2 content-type OIDs.
_OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
_OID_CT_TSTINFO = "1.2.840.113549.1.9.16.1.4"

#: Reverse of :data:`TSA_HASH_OIDS`, for reading a token's messageImprint.
_HASH_BY_OID = {oid: name for name, oid in TSA_HASH_OIDS.items()}

_HASH_FUNCS: Dict[str, Callable[[bytes], "hashlib._Hash"]] = {
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha3-256": hashlib.sha3_256,
    "sha3-384": hashlib.sha3_384,
    "sha3-512": hashlib.sha3_512,
}


def extract_tst_info(token: bytes) -> bytes:
    """The DER ``TSTInfo`` inside an RFC 3161 token, or inside a whole response.

    A ``TimeStampToken`` is a CMS ``ContentInfo`` wrapping ``SignedData``
    (RFC 5652 §5.1), whose ``encapContentInfo`` carries the ``TSTInfo`` as an
    OCTET STRING::

        ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
        SignedData  ::= SEQUENCE { version, digestAlgorithms SET,
                                   encapContentInfo, [0] certificates OPTIONAL,
                                   [1] crls OPTIONAL, signerInfos SET }
        EncapsulatedContentInfo ::= SEQUENCE {
            eContentType OID, eContent [0] EXPLICIT OCTET STRING OPTIONAL }

    Accepts either a bare token or a full ``TimeStampResp``, because the legacy
    API stores the response and callers have both shapes on disk.

    Raises:
        TimestampError: the input is not a well-formed RFC 3161 token.
    """
    try:
        # A TimeStampResp opens with PKIStatusInfo (a SEQUENCE); a ContentInfo
        # opens with the contentType OID. Unwrap any response envelope first,
        # under a hard bound: recursing on each layer let a token that nests
        # TimeStampResp structures drive RecursionError straight past this
        # function's TimestampError boundary — the DoS class this module bounds
        # elsewhere (_CBOR_MAX_DEPTH, _OID_MAX_BODY). A real token needs at most
        # one unwrap.
        for _ in range(_MAX_TSR_UNWRAP):
            outer = DerReader(token).read_sequence()
            if outer.peek_tag() != 0x30:
                break
            token = parse_timestamp_response(token)
        else:
            raise TimestampError(
                f"timestamp response nests more than {_MAX_TSR_UNWRAP - 1} level(s), "
                "which no RFC 3161 token does"
            )
        content_type = outer.read_oid()
        if content_type != _OID_SIGNED_DATA:
            raise TimestampError(
                f"not a CMS SignedData: contentType is {content_type}, expected "
                f"{_OID_SIGNED_DATA}"
            )
        signed_data = outer.read_tagged(0).read_sequence()
        signed_data.read_integer()  # CMSVersion
        digest_algorithms = signed_data.read_set()
        # RFC 5652 §5.1: `digestAlgorithms` is the set of digests the signers
        # used, so an empty one means nothing signed this. A token whose
        # `signerInfos` is likewise empty is not a TSA token at all — it is a
        # container anybody can build offline. AMA does not verify the TSA's
        # signature (see `verify_token_binding`), which makes it all the more
        # important that a structure carrying *no* signature is refused
        # outright rather than passed on to a binding check that would answer
        # "yes, this token is about your data" about a token nobody issued.
        if digest_algorithms.peek_tag() is None:
            raise TimestampError(
                "token's SignedData carries an empty digestAlgorithms set, so nothing "
                "signed it (RFC 5652 §5.1)"
            )
        encap = signed_data.read_sequence()
        econtent_type = encap.read_oid()
        if econtent_type != _OID_CT_TSTINFO:
            raise TimestampError(
                f"token does not encapsulate a TSTInfo: eContentType is {econtent_type}"
            )
        if encap.peek_tag() is None:
            raise TimestampError("token carries no eContent, so it attests to nothing")
        tst_info = encap.read_tagged(0).read_octet_string()

        # `certificates [0]` and `crls [1]` are OPTIONAL and skipped; what
        # follows them is the mandatory `signerInfos SET`.
        while signed_data.peek_tag() in (0xA0, 0xA1):
            signed_data.skip_any()
        if signed_data.peek_tag() is None:
            raise TimestampError("token's SignedData has no signerInfos field (RFC 5652 §5.1)")
        signer_infos = signed_data.read_set()
        if signer_infos.peek_tag() is None:
            raise TimestampError(
                "token's SignedData carries an empty signerInfos set: no TSA signed it. "
                "RFC 3161 §2.4.2 requires exactly one signer"
            )
        return tst_info
    except TimestampError:
        raise
    except Exception as exc:
        raise TimestampError(f"malformed RFC 3161 token: {exc}") from None


#: Largest TimeStampResp this client will read from a TSA.
#:
#: A TimeStampResp is a few kilobytes. `response.read()` with no argument reads
#: whatever Content-Length the peer declares, and the peer is a network peer —
#: the default is a public TSA — so one reply could make the signing process
#: allocate arbitrary memory *before* a single validity check ran. 256 KiB is
#: two orders of magnitude above any real token and still bounded.
_MAX_TSR_BYTES = 256 * 1024

#: Maximum number of TimeStampResp envelopes ``extract_tst_info`` will unwrap
#: before it reaches a ContentInfo. A real token is either bare (0 unwraps) or a
#: single response wrapping one token (1 unwrap); anything deeper is a crafted
#: structure whose only purpose is to drive unbounded recursion, so it is
#: refused rather than followed. Two allows the single legitimate unwrap and its
#: terminating ContentInfo check.
_MAX_TSR_UNWRAP = 2

#: How long to wait on the TSA, in seconds.
_TSA_TIMEOUT = 10


def request_timestamp_token(
    digest: bytes,
    hash_name: str,
    tsa_url: str,
    *,
    nonce: Optional[int] = None,
    cert_req: bool = True,
) -> bytes:
    """Obtain an RFC 3161 timestamp token for ``digest`` from ``tsa_url``.

    The whole protocol on AMA's own codec: encode the ``TimeStampReq``, POST it
    over HTTPS, decode the ``TimeStampResp``, check the TSA granted it, check
    the nonce echo, and check that the token it returned actually binds the
    digest that was asked about.

    That last check is the one most clients omit. RFC 3161 §2.4.2 requires it —
    especially for ``grantedWithMods``, which this accepts — and without it a
    token attesting to *unrelated* data is accepted, stored, and only found to
    be wrong at some later verification, by which point the artefact is on disk
    and the TSA interaction is unrepeatable.

    ``cert_req`` defaults to True so the TSA embeds its signing certificate and
    the token is self-contained. AMA does not verify the TSA signature today
    (see :func:`verify_token_binding`); a token archived *without* the
    certificate can never have it verified later either, because by then the
    TSA's certificate may have rotated and no longer be published — which
    defeats the long-term-archival use case the timestamp exists for.

    Args:
        digest: The message digest to be timestamped.
        hash_name: The algorithm that produced it, from :data:`TSA_HASH_OIDS`.
        tsa_url: An ``https://`` TSA endpoint.
        nonce: Optional 64-bit nonce; the response must echo it.
        cert_req: Ask the TSA to include its signing certificate.

    Returns:
        The DER ``timeStampToken`` (not the whole response). Callers that need
        the response verbatim — the legacy ``CryptoPackage`` stores it — use
        :func:`request_timestamp_exchange`, which returns both.

    Raises:
        TimestampError: on any transport, protocol or binding failure.
        ValueError: if ``tsa_url`` is not an ``https://`` URL.
    """
    return request_timestamp_exchange(digest, hash_name, tsa_url, nonce=nonce, cert_req=cert_req)[1]


def request_timestamp_exchange(
    digest: bytes,
    hash_name: str,
    tsa_url: str,
    *,
    nonce: Optional[int] = None,
    cert_req: bool = True,
) -> "tuple[bytes, bytes]":
    """As :func:`request_timestamp_token`, returning ``(response, token)``.

    The verbatim ``TimeStampResp`` is what the legacy ``CryptoPackage`` format
    stores, so it is kept available rather than reconstructed; every check
    :func:`request_timestamp_token` performs has already run by the time this
    returns.
    """
    parsed = urlparse(tsa_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError(f"TSA URL must be https with a host, got {tsa_url!r}")

    request = build_timestamp_request(digest, hash_name, nonce=nonce, cert_req=cert_req)

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    conn = http.client.HTTPSConnection(parsed.hostname, parsed.port, timeout=_TSA_TIMEOUT)
    try:
        conn.request(
            "POST", path, body=request, headers={"Content-Type": "application/timestamp-query"}
        )
        response = conn.getresponse()
        if response.status < 200 or response.status >= 300:
            raise TimestampError(f"TSA returned HTTP status {response.status}")
        declared = response.getheader("Content-Length")
        if declared is not None:
            try:
                if int(declared) > _MAX_TSR_BYTES:
                    raise TimestampError(
                        f"TSA declared a {declared}-byte response; the limit is "
                        f"{_MAX_TSR_BYTES}"
                    )
            except ValueError:
                raise TimestampError("TSA sent a malformed Content-Length") from None
        # Read one octet past the cap so an over-long body is detected rather
        # than silently truncated into something that might still parse.
        raw = response.read(_MAX_TSR_BYTES + 1)
        if len(raw) > _MAX_TSR_BYTES:
            raise TimestampError(f"TSA response exceeds the {_MAX_TSR_BYTES}-byte limit")
    except TimestampError:
        raise
    except OSError as exc:
        raise TimestampError(f"TSA request to {tsa_url} failed: {exc}") from None
    finally:
        conn.close()

    token = parse_timestamp_response(raw, expected_nonce=nonce)

    # RFC 3161 §2.4.2: the token must attest to the imprint that was sent.
    tst_info = extract_tst_info(token)
    if _tst_info_imprint(tst_info) != (TSA_HASH_OIDS[hash_name], digest):
        raise TimestampError(
            "TSA returned a token whose messageImprint is not the digest that was "
            "submitted; it attests to something else"
        )
    return raw, token


def _tst_info_imprint(tst_info: bytes) -> "tuple[str, bytes]":
    """The ``(hashAlgorithm OID, hashedMessage)`` pair a ``TSTInfo`` carries."""
    try:
        info = DerReader(tst_info).read_sequence()
        info.read_integer()  # version
        info.read_oid()  # policy
        imprint = info.read_sequence()
        algorithm = imprint.read_sequence()
        digest_oid = algorithm.read_oid()
        hashed = imprint.read_octet_string()
    except Exception as exc:
        raise TimestampError(f"malformed TSTInfo in RFC 3161 token: {exc}") from None
    return digest_oid, hashed


def tst_info_nonce(tst_info: bytes) -> Optional[int]:
    """The ``nonce`` an RFC 3161 ``TSTInfo`` echoes back, or ``None``.

    RFC 3161 §2.4.2::

        TSTInfo ::= SEQUENCE  {
           version        INTEGER { v1(1) },
           policy         TSAPolicyId,
           messageImprint MessageImprint,
           serialNumber   INTEGER,
           genTime        GeneralizedTime,
           accuracy       Accuracy                 OPTIONAL,
           ordering       BOOLEAN                  DEFAULT FALSE,
           nonce          INTEGER                  OPTIONAL,
           tsa            [0] GeneralName          OPTIONAL,
           extensions     [1] IMPLICIT Extensions  OPTIONAL  }

    The nonce is the client's only means of binding a response to the request
    it answers; without it a captured token for the same imprint is
    indistinguishable from a fresh one. It is optional in the grammar and the
    optional fields before it are of several types, so this walks positionally
    to ``genTime`` and then takes the first INTEGER that follows — ``accuracy``
    is a SEQUENCE and ``ordering`` a BOOLEAN, so neither can be mistaken for it.

    Raises:
        TimestampError: the input is not a well-formed ``TSTInfo``.
    """
    try:
        info = DerReader(tst_info).read_sequence()
        info.read_integer()  # version
        info.read_oid()  # policy
        info.skip_any()  # messageImprint
        info.read_integer()  # serialNumber
        info.skip_any()  # genTime
        if info.peek_tag() == 0x30:  # accuracy
            info.skip_any()
        if info.peek_tag() == 0x01:  # ordering BOOLEAN
            info.skip_any()
        if info.peek_tag() == 0x02:  # nonce
            return int(info.read_integer())
        return None
    except Exception as exc:
        raise TimestampError(f"malformed TSTInfo in RFC 3161 token: {exc}") from None


def verify_token_binding(data: bytes, token: bytes) -> bool:
    """Whether ``token``'s ``messageImprint`` is the digest of ``data``.

    .. warning::
        This is the *binding* half of RFC 3161 verification, not the whole of
        it. It answers "is this token about this data", by recomputing the
        digest under the algorithm the token names and comparing it in constant
        time to ``TSTInfo.messageImprint.hashedMessage`` (RFC 3161 §2.4.2).

        It does **not** verify the TSA's signature over the ``TSTInfo``, and it
        does not validate a certificate chain. Both need CMS ``SignerInfo``
        processing and X.509 path validation, which AMA does not implement.
        A caller who needs third-party attestation — the actual point of a
        timestamp — must not treat a ``True`` here as that attestation.

    Returning ``False`` rather than raising for a *mismatch* is deliberate: a
    token that is well-formed but describes different data is a verification
    failure, not an error. Anything that stops the check from running raises,
    so "verification failed" is never confused with "verification never ran".
    """
    tst_info = extract_tst_info(token)
    try:
        info = DerReader(tst_info).read_sequence()
        info.read_integer()  # version
        info.read_oid()  # policy
        imprint = info.read_sequence()  # messageImprint
        algorithm = imprint.read_sequence()
        digest_oid = algorithm.read_oid()
        hashed = imprint.read_octet_string()
    except Exception as exc:
        raise TimestampError(f"malformed TSTInfo in RFC 3161 token: {exc}") from None

    name = _HASH_BY_OID.get(digest_oid)
    if name is None:
        raise TimestampError(
            f"token's messageImprint uses hash OID {digest_oid}, which AMA does not "
            "implement; the binding cannot be checked"
        )
    computed = _HASH_FUNCS[name](data).digest()
    if len(computed) != len(hashed):
        return False
    # Constant-time: the comparison operand is attacker-supplied, and a length
    # or early-exit signal on a digest comparison is a habit worth not having.
    diff = 0
    for a, b in zip(computed, hashed):
        diff |= a ^ b
    return diff == 0


class TimestampUnavailableError(AmaCryptographyError):
    """Raised when RFC 3161 timestamping is requested but not available."""

    pass


class TimestampError(AmaCryptographyError):
    """Raised when timestamp request fails."""

    pass


@dataclass
class TimestampResult:
    """
    Result from get_timestamp() containing the timestamp token.

    Attributes:
        token: RFC 3161 timestamp token (ASN.1 DER encoded, or mock token bytes)
        tsa_url: URL of the Time-Stamp Authority used (or "mock" / "disabled")
        hash_algorithm: Hash algorithm used (e.g., 'sha256', 'sha3-256')
        data_hash: Hash of the timestamped data
    """

    token: bytes
    tsa_url: str
    hash_algorithm: str
    data_hash: bytes


# ---------------------------------------------------------------------------
# Mock TSA for offline / testing use
# ---------------------------------------------------------------------------

# 16-byte magic header that identifies a mock timestamp token.
_MOCK_MAGIC = b"AMA_MOCK_TSA\x00\x01\x00\x00"


# S3 fix: Guard flag — MockTSA is only available in testing contexts.
# Set this to True in test fixtures / conftest.py before using MockTSA.
# Thread-local storage so concurrent threads don't leak the allowed state.
_MOCK_TSA_ALLOWED: bool = False
_MOCK_TSA_LOCK = threading.Lock()
_mock_tsa_local = threading.local()


@contextmanager
def allow_mock_tsa() -> Generator[None, None, None]:
    """Context manager that enables MockTSA for the calling thread.

    SECURITY FIX (audit finding C8): Replaces bare try/finally flag
    manipulation with a context manager that guarantees atomic
    enable/disable semantics.  The thread-local flag is set on entry
    and unconditionally cleared on exit, eliminating the TOCTOU race
    where a concurrent finalizer or signal handler could observe the
    flag in an inconsistent state.

    Usage::

        with allow_mock_tsa():
            token = MockTSA.timestamp(data_hash, "sha256")
            assert MockTSA.verify(token, data_hash)
    """
    previous = getattr(_mock_tsa_local, "allowed", False)
    _mock_tsa_local.allowed = True
    try:
        yield
    finally:
        _mock_tsa_local.allowed = previous


def _hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """RFC 2104 HMAC-SHA-256 via the native ama_hmac_sha256 kernel.

    INVARIANT-1 (AMA's own HMAC, never a stdlib-hashlib construction) and
    INVARIANT-7 (no cryptographic fallback, ever) — there is deliberately no
    pure-Python fallback.  When the native backend is unavailable,
    ``native_hmac_sha256`` raises ``RuntimeError`` and MockTSA fails closed;
    tests skip accordingly rather than silently exercising a non-native HMAC.
    """
    from ama_cryptography.pqc_backends import native_hmac_sha256

    return native_hmac_sha256(key, msg)


class MockTSA:
    """
    Self-signed mock Time-Stamp Authority for testing purposes.

    .. warning:: **Testing only.**  MockTSA will raise ``RuntimeError`` if
       ``_MOCK_TSA_ALLOWED`` is not set to ``True``.  Set it in your test
       fixtures or via the ``allow_mock_tsa`` context manager.

    The token format (all big-endian) is:
        16 bytes  - magic header (_MOCK_MAGIC)
         4 bytes  - hash algorithm name length (N)
         N bytes  - hash algorithm name (utf-8)
         8 bytes  - Unix timestamp (double, seconds since epoch)
        32 bytes  - HMAC-SHA256(key=nonce, msg=payload)  [S3: uses HMAC,
                    not raw SHA-256 concatenation, to avoid length-extension]
        32 bytes  - the random nonce used for the HMAC

    The HMAC lets ``verify_timestamp`` confirm that the token has not been
    tampered with, even though the key is embedded in the token (the security
    goal is integrity, not authenticity -- this is a *mock*).
    """

    @staticmethod
    def _check_allowed() -> None:
        """Raise if MockTSA is used outside a testing context.

        Checks thread-local flag first (set by get_timestamp mock-mode),
        then falls back to the module-level global (set by test fixtures).
        The global read is guarded by ``_MOCK_TSA_LOCK`` so that a
        concurrent ``_MOCK_TSA_ALLOWED = True`` assignment in another
        thread is observed atomically.
        """
        if getattr(_mock_tsa_local, "allowed", False):
            return
        with _MOCK_TSA_LOCK:
            allowed = _MOCK_TSA_ALLOWED
        if not allowed:
            raise RuntimeError(
                "MockTSA is only available in testing contexts. "
                "Set ama_cryptography.rfc3161_timestamp._MOCK_TSA_ALLOWED = True "
                "in your test fixture before using MockTSA."
            )

    @staticmethod
    def timestamp(data_hash: bytes, hash_algorithm: str) -> bytes:
        """Create a mock timestamp token from *data_hash*."""
        MockTSA._check_allowed()

        algo_bytes = hash_algorithm.encode("utf-8")
        algo_len = struct.pack(">I", len(algo_bytes))
        ts = struct.pack(">d", time.time())
        nonce = _os_mod.urandom(32)

        payload = _MOCK_MAGIC + algo_len + algo_bytes + ts + data_hash
        # S3 fix: Use HMAC instead of raw SHA-256(nonce || payload) to
        # prevent length-extension attacks on the integrity tag.
        mac = _hmac_sha256(nonce, payload)

        return payload + mac + nonce

    @staticmethod
    def verify(token: bytes, data_hash: bytes) -> bool:
        """Verify a mock timestamp token against *data_hash*.

        Gated on the same testing-context flag as :meth:`timestamp`. A mock
        token is self-authenticating -- its HMAC key (the embedded nonce) ships
        inside the token -- so this cannot tell a token the process produced
        from one an attacker fabricated. Verification is therefore only
        meaningful, and only permitted, inside a testing context; gating
        creation but not verification would let a forged mock token be honoured
        wherever verification runs.
        """
        MockTSA._check_allowed()
        try:
            if not token.startswith(_MOCK_MAGIC):
                return False

            offset = len(_MOCK_MAGIC)
            algo_len = struct.unpack_from(">I", token, offset)[0]
            offset += 4
            # skip algo bytes
            offset += algo_len
            # skip timestamp (8 bytes)
            offset += 8

            # The remaining bytes up to this point form the payload.
            payload_end = offset
            # payload = _MOCK_MAGIC + algo_len(4) + algo(N) + ts(8) + data_hash
            # mac(32) + nonce(32) at the tail.
            mac = token[-(32 + 32) : -32]
            nonce = token[-32:]
            payload = token[: -(32 + 32)]

            # S3 fix: Verify HMAC (not raw hash concatenation).
            # Use constant-time comparison to be consistent with the
            # project's security posture (CONTRIBUTING.md / INVARIANT-1).
            from ama_cryptography.secure_memory import constant_time_compare

            expected_mac = _hmac_sha256(nonce, payload)
            if not constant_time_compare(mac, expected_mac):
                return False

            # Extract embedded data_hash from the payload and compare.
            # SECURITY FIX: Use constant-time comparison to prevent
            # timing oracle attacks on hash values (audit finding S3b).
            embedded_hash = payload[payload_end:]
            return constant_time_compare(embedded_hash, data_hash)
        except Exception as exc:
            _logger.error("MockTSA.verify failed: %s", exc)
            return False


def _is_mock_token(token: bytes) -> bool:
    """Return True if *token* was produced by :class:`MockTSA`."""
    return token[:16] == _MOCK_MAGIC


def _mock_tsa_enabled() -> bool:
    """Non-raising counterpart to :meth:`MockTSA._check_allowed`.

    ``verify_timestamp`` uses this to decide whether the mock path may run at
    all, rather than letting ``_is_mock_token``'s format check alone route an
    attacker-supplied token into the self-authenticating mock verifier. Returns
    ``True`` only inside a testing context: the thread-local flag set by
    :func:`allow_mock_tsa` / ``get_timestamp(tsa_mode="mock")``, or the
    module-level ``_MOCK_TSA_ALLOWED`` a test fixture set. The global read is
    taken under ``_MOCK_TSA_LOCK`` to match ``_check_allowed``'s visibility
    guarantee.
    """
    if getattr(_mock_tsa_local, "allowed", False):
        return True
    with _MOCK_TSA_LOCK:
        return _MOCK_TSA_ALLOWED


def get_timestamp(
    data: bytes,
    tsa_url: Optional[str] = None,
    hash_algorithm: str = "sha3-256",
    certificate_file: Optional[str] = None,
    tsa_mode: str = "online",
) -> TimestampResult:
    """
    Obtain RFC 3161 timestamp for data from a Time-Stamp Authority.

    **Process**

    1. Compute hash of data using specified algorithm
    2. Create RFC 3161 TimeStampReq with hash
    3. Send request to TSA server via HTTP POST
    4. Receive and validate TimeStampResp
    5. Extract timestamp token from response

    Args:
        data: Data to timestamp (will be hashed).
        tsa_url: URL of RFC 3161 Time-Stamp Authority.
            Default: FreeTSA.org public service.
        hash_algorithm: Hash algorithm to use (``'sha256'``, ``'sha3-256'``,
            ``'sha512'``). Default: ``'sha3-256'`` (consistent with AMA
            Cryptography).
        certificate_file: Optional path to TSA certificate for verification.
        tsa_mode: Operating mode for timestamping. One of:

            - ``"online"`` (default): contact a real TSA server.
            - ``"mock"``: use MockTSA for offline / testing purposes.
            - ``"disabled"``: skip timestamping; returns a TimestampResult
              with ``tsa_url='disabled'`` and an empty token.

    Returns:
        TimestampResult with timestamp token and metadata.  When ``tsa_mode``
        is ``"disabled"``, returns a TimestampResult with ``tsa_url='disabled'``
        and ``token=b""``.  Never returns ``None``.

    Raises:
        TimestampUnavailableError: If rfc3161ng library not installed (online mode).
        TimestampError: If timestamp request fails.
        ValueError: If ``hash_algorithm`` or ``tsa_mode`` is not supported.

    Example:
        >>> result = get_timestamp(b"Important document")
        >>> print(f"Timestamp token: {len(result.token)} bytes")
        >>> # Save token for later verification
        >>> with open("document.tsr", "wb") as f:
        ...     f.write(result.token)

    **Public TSA Services**

    - FreeTSA: https://freetsa.org/tsr (free, no registration)
    - DigiCert: http://timestamp.digicert.com (free, no registration)
    - GlobalSign: http://timestamp.globalsign.com/tsa/tsa (free)

    Note:
        For production use, consider running your own TSA server or using a
        commercial service with SLA guarantees.
    """
    if tsa_mode not in ("online", "mock", "disabled"):
        raise ValueError(
            f"Unsupported tsa_mode: {tsa_mode!r}. Supported: 'online', 'mock', 'disabled'"
        )

    # ---- Compute data hash (needed for all modes) ----
    if hash_algorithm == "sha256":
        data_hash = hashlib.sha256(data).digest()
    elif hash_algorithm == "sha3-256":
        data_hash = hashlib.sha3_256(data).digest()
    elif hash_algorithm == "sha512":
        data_hash = hashlib.sha512(data).digest()
    elif hash_algorithm == "sha3-512":
        data_hash = hashlib.sha3_512(data).digest()
    else:
        raise ValueError(
            f"Unsupported hash algorithm: {hash_algorithm}. "
            "Supported: sha256, sha3-256, sha512, sha3-512"
        )

    # ---- Disabled mode: return immediately with empty token ----
    if tsa_mode == "disabled":
        return TimestampResult(
            token=b"",
            tsa_url="disabled",
            hash_algorithm=hash_algorithm,
            data_hash=data_hash,
        )

    # ---- Mock mode: generate a self-signed mock token ----
    if tsa_mode == "mock":
        # SECURITY FIX (audit finding C8): Use the allow_mock_tsa()
        # context manager instead of bare flag manipulation to guarantee
        # atomic enable/disable semantics.
        with allow_mock_tsa():
            token = MockTSA.timestamp(data_hash, hash_algorithm)
        return TimestampResult(
            token=token,
            tsa_url="mock",
            hash_algorithm=hash_algorithm,
            data_hash=data_hash,
        )

    # ---- Online mode ----
    # `certificate_file` asked for the TSA's signing certificate to be pinned
    # and its signature verified. AMA implements neither CMS SignerInfo
    # processing nor X.509 path validation, so it refuses rather than accepting
    # the argument and quietly doing something weaker — the same posture, and
    # the same reasoning, as `legacy_compat.verify_rfc3161_timestamp`'s
    # `tsa_cert_path`.
    if certificate_file is not None:
        raise TimestampError(
            "certificate_file requests verification of the TSA's signing certificate. "
            "AMA implements neither CMS SignerInfo verification nor X.509 path "
            "validation and will not report a weaker check as though it were this one. "
            "Call without certificate_file for the RFC 3161 §2.4.2 message-imprint "
            "binding, and see verify_token_binding for exactly what that establishes."
        )

    # Use FreeTSA as default public TSA
    if tsa_url is None:
        tsa_url = "https://freetsa.org/tsr"
        warnings.warn(
            f"No TSA URL specified, using public service: {tsa_url}. "
            "For production use, specify a reliable TSA server.",
            category=UserWarning,
        )

    # A fresh 64-bit nonce per request, echoed back by the TSA into the TSTInfo.
    # RFC 3161 §2.4.2 makes the echo the client's only way to tell a fresh
    # response from a replayed one; `request_timestamp_token` checks it.
    nonce = secrets.randbits(64)
    token = request_timestamp_token(data_hash, hash_algorithm, tsa_url, nonce=nonce, cert_req=True)
    return TimestampResult(
        token=token,
        tsa_url=tsa_url,
        hash_algorithm=hash_algorithm,
        data_hash=data_hash,
    )


def _compute_data_hash(data: bytes, algorithm: str) -> Optional[bytes]:
    """Compute a hash of *data* using the named *algorithm*.

    Returns the digest bytes, or ``None`` if the algorithm is not supported.

    Backed by the module-level ``_HASH_FUNCS`` so this covers exactly the six
    algorithms ``TSA_HASH_OIDS`` / ``verify_token_binding`` accept. A local
    subset here previously rejected an otherwise-valid ``sha384`` / ``sha3-384``
    token before the binding check ran.
    """
    func = _HASH_FUNCS.get(algorithm)
    if func is None:
        return None
    return func(data).digest()


def verify_timestamp(
    data: bytes,
    timestamp_result: TimestampResult,
    certificate_file: Optional[str] = None,
) -> bool:
    """
    Verify RFC 3161 timestamp token against data.

    Verification Process:
    ---------------------
    1. Recompute hash of data using specified algorithm
    2. Parse timestamp token (ASN.1 DER) -- or verify mock / disabled token
    3. Verify timestamp signature
    4. Check hash in token matches computed hash
    5. Validate TSA certificate chain (if certificate_file provided)

    Args:
        data: Original data that was timestamped
        timestamp_result: TimestampResult from get_timestamp()
        certificate_file: Optional path to TSA certificate for chain validation

    Returns:
        True if timestamp is valid, False otherwise

    Example:
        >>> # Load timestamp from file
        >>> with open("document.tsr", "rb") as f:
        ...     token = f.read()
        >>> result = TimestampResult(
        ...     token=token,
        ...     tsa_url="https://freetsa.org/tsr",
        ...     hash_algorithm='sha3-256',
        ...     data_hash=b'...'
        ... )
        >>> is_valid = verify_timestamp(b"Important document", result)
        >>> print(f"Timestamp valid: {is_valid}")
    """
    # ---- Disabled tokens: still verify data integrity (S2 fix) ----
    # Even when timestamping is disabled, the data_hash stored in the
    # TimestampResult must match the actual data. Without this check,
    # a TimestampResult from payload A would validate payload B.
    if timestamp_result.tsa_url == "disabled" and timestamp_result.token == b"":
        computed_hash = _compute_data_hash(data, timestamp_result.hash_algorithm)
        if computed_hash is None:
            return False
        return computed_hash == timestamp_result.data_hash

    # ---- Mock token path (test contexts only) ----
    #
    # A MockTSA token is self-authenticating: its HMAC key (the nonce) ships
    # inside the token, so MockTSA.verify cannot distinguish a token this
    # process produced from one an attacker fabricated. Honouring a mock-format
    # token on the production verification path would therefore let anyone forge
    # a "valid" timestamp -- with any genTime -- for any data, since the caller
    # supplies the whole TimestampResult. Mock *creation* is already gated to a
    # testing context; verification is gated the same way here, or the gate on
    # creation prevents nothing. Outside a testing context a mock-format token
    # is refused, never verified.
    if _is_mock_token(timestamp_result.token):
        if not _mock_tsa_enabled():
            _logger.warning(
                "Refusing a MockTSA-format timestamp token outside a testing "
                "context: mock verification is not a production trust path."
            )
            return False
        try:
            computed_hash = _compute_data_hash(data, timestamp_result.hash_algorithm)
            if computed_hash is None or computed_hash != timestamp_result.data_hash:
                return False
            return MockTSA.verify(timestamp_result.token, computed_hash)
        except Exception as exc:
            _logger.error("Mock timestamp verification failed: %s", exc)
            return False

    # ---- Online (real RFC 3161) verification ----
    #
    # This performs the RFC 3161 §2.4.2 *message-imprint binding* check, and
    # says so. It does not verify the TSA's signature over the TSTInfo and does
    # not validate a certificate chain; `verify_token_binding`'s docstring
    # states precisely what that does and does not establish, and
    # `certificate_file` is refused rather than silently ignored so a caller
    # who asked for the stronger check is not told they got it.
    if certificate_file is not None:
        raise TimestampError(
            "certificate_file requests verification of the TSA's signing certificate. "
            "AMA implements neither CMS SignerInfo verification nor X.509 path "
            "validation and will not report a weaker check as though it were this one."
        )

    try:
        computed_hash = _compute_data_hash(data, timestamp_result.hash_algorithm)
        if computed_hash is None or computed_hash != timestamp_result.data_hash:
            return False
        return verify_token_binding(data, timestamp_result.token)
    except Exception as exc:
        _logger.error("RFC 3161 timestamp verification failed: %s", exc)
        return False


# Public API
__all__ = [
    "get_timestamp",
    "verify_timestamp",
    "TimestampResult",
    "TimestampUnavailableError",
    "TimestampError",
    "RFC3161_AVAILABLE",
    # The RFC 3161 codec itself. It was reachable only from the deprecated
    # `legacy_compat` surface and exported from nowhere, which is how the
    # module came to keep a third-party client for the protocol it already
    # implements.
    "TSA_HASH_OIDS",
    "build_timestamp_request",
    "parse_timestamp_response",
    "request_timestamp_token",
    "request_timestamp_exchange",
    "extract_tst_info",
    "tst_info_nonce",
    "verify_token_binding",
]
