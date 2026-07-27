#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
A reference key encoder, derived from the specifications and nothing else.
=========================================================================

Why this exists
---------------
A round trip through AMA's own encoder proves only that AMA agrees with itself.
An encoder with a wrong OID, an absent-versus-NULL ``parameters`` mistake or a
misidentified ``CHOICE`` arm round-trips perfectly and interoperates with
nothing. Some of that is closed by the vendored answer keys under
``tests/kat/keyformats/`` — RFC 9881, RFC 8410 §10, RFC 8037, RFC 8152 and
RFC 9500 §2.3 all publish worked examples. What those cover is a handful of
specific keys; what they do not cover is *every algorithm, every option, every
width*, including the ones no document happens to have printed.

This module closes that gap without introducing another cryptographic product
into the tree. It is a second encoder for the same structures, written by
transcribing the ASN.1 modules out of the RFCs, and it is AMA's own work.

The rule this module is built to obey
-------------------------------------
PR #378 found the hard version of this lesson in its RFC 6979 work: the
"independent" reference normalised ``s`` because the C code did, so the two
agreed by construction and neither was checked. **Two implementations that
share an assumption do not check each other.** So:

* Every structure below is transcribed from the RFC's own ASN.1, quoted inline
  above the code that builds it. The document is the authority, not
  ``ama_cryptography/_asn1.py`` — which this module deliberately does not
  import, and must never import.
* The construction is *declarative*: the encodings are data (nested tuples of
  ``(tag, content)``) fed to one generic serialiser, where the production
  encoder is a set of per-type writer functions called from per-algorithm
  branches. A shared control-flow mistake has nowhere to hide when the two
  shapes have no control flow in common.
* Lengths, OID arcs and the BIT STRING unused-bits octet are computed here from
  X.690's rules, not copied from the production code.

What it is not
--------------
Not a parser, not a key generator, and not shipped. It encodes: given key
material AMA produced, it says what the DER should be, and the test suite
compares. Nothing here performs cryptography.
"""

from __future__ import annotations

from typing import Union

# ---------------------------------------------------------------------------
# X.690 primitives
# ---------------------------------------------------------------------------
# ITU-T X.690 (DER), transcribed:
#
#   §8.1.3.3  "the definite form ... the length octets shall consist of 1 to
#              127 octets ... the first octet shall have bit 8 set to one, and
#              bits 7 to 1 shall encode the number of subsequent octets"
#   §8.1.3.4  short form: a single octet, bit 8 zero, value 0..127
#   §10.1     "the definite form of length encoding shall be used ... the
#              minimum number of octets" — so the short form is mandatory
#              wherever it fits, which is what makes DER canonical.
Node = tuple[int, Union[bytes, list["Node"]]]


def _length(count: int) -> bytes:
    if count < 0x80:
        return bytes([count])
    body = count.to_bytes((count.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def encode(node: Node) -> bytes:
    """Serialise one ``(tag, content)`` node. Content is bytes or child nodes."""
    tag, content = node
    body = content if isinstance(content, bytes) else b"".join(encode(c) for c in content)
    return bytes([tag]) + _length(len(body)) + body


# Universal tag numbers, X.690 §8.4 / X.680 Table 1.
INTEGER = 0x02
BIT_STRING = 0x03
OCTET_STRING = 0x04
OID = 0x06
SEQUENCE = 0x30


def integer(value: int) -> Node:
    """X.690 §8.3: two's complement, minimum number of octets.

    Only non-negative values occur in these structures (versions 0, 1 and the
    RFC 5915 ``ecPrivkeyVer1``), so the sign handling is the leading-zero rule:
    prepend 0x00 when the top bit of the first octet would otherwise read as a
    sign bit.
    """
    if value < 0:
        raise ValueError("no negative INTEGER occurs in these structures")
    if value == 0:
        return (INTEGER, b"\x00")
    body = value.to_bytes((value.bit_length() + 8) // 8, "big")
    return (INTEGER, body.lstrip(b"\x00") if body[0] == 0 and body[1] < 0x80 else body)


def octet_string(data: bytes) -> Node:
    return (OCTET_STRING, data)


def bit_string(data: bytes) -> Node:
    """X.690 §8.6.2.2: the initial octet counts unused trailing bits.

    Every BIT STRING in these structures carries whole octets, so it is zero —
    stated rather than implied, because omitting the octet entirely is a
    classic encoder bug that shortens the field by one and still parses.
    """
    return (BIT_STRING, b"\x00" + data)


def object_identifier(dotted: str) -> Node:
    """X.690 §8.19, transcribed.

    §8.19.4: "the first subidentifier ... shall be (X*40) + Y where X is the
    value of the first object identifier component and Y the second".
    §8.19.2: each subidentifier is base-128, most significant group first, with
    bit 8 set on every octet except the last.
    """
    parts = [int(p) for p in dotted.split(".")]
    if len(parts) < 2:
        raise ValueError(f"an OID needs at least two arcs: {dotted!r}")
    arcs = [parts[0] * 40 + parts[1], *parts[2:]]
    body = bytearray()
    for arc in arcs:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append((arc & 0x7F) | 0x80)
            arc >>= 7
        body.extend(reversed(chunk))
    return (OID, bytes(body))


def context(number: int, content: Union[bytes, list[Node]], *, constructed: bool) -> Node:
    """X.690 §8.14: context-specific class (bits 8-7 = 10), tag number in 5-1.

    ``constructed`` selects bit 6. It is a parameter rather than inferred,
    because the distinction is exactly what IMPLICIT tagging turns on: an
    IMPLICIT ``[0] OCTET STRING`` is primitive (``0x80``) and its content is the
    octets themselves, while an EXPLICIT ``[0]`` is constructed (``0xA0``) and
    wraps a complete TLV.
    """
    return (0x80 | (0x20 if constructed else 0x00) | number, content)


# ---------------------------------------------------------------------------
# Algorithm identifiers
# ---------------------------------------------------------------------------
# OIDs transcribed from the documents that assign them, one citation each:
#
#   id-ecPublicKey        RFC 5480 §2.1.1   1.2.840.10045.2.1
#   secp256r1 (P-256)     RFC 5480 §2.1.1.1 1.2.840.10045.3.1.7
#   secp384r1 (P-384)     RFC 5480 §2.1.1.1 1.3.132.0.34
#   secp521r1 (P-521)     RFC 5480 §2.1.1.1 1.3.132.0.35
#   secp256k1             SEC 2 v2 §2.4.1   1.3.132.0.10
#   id-Ed25519            RFC 8410 §3       1.3.101.112
#   id-X25519             RFC 8410 §3       1.3.101.110
#   id-ml-dsa-44/65/87    RFC 9881 §3       2.16.840.1.101.3.4.3.17/18/19
#   id-alg-ml-kem-512/768/1024
#                         draft-ietf-lamps-kyber-certificates §3
#                                           2.16.840.1.101.3.4.4.1/2/3
CURVE_OID = {
    "P-256": "1.2.840.10045.3.1.7",
    "P-384": "1.3.132.0.34",
    "P-521": "1.3.132.0.35",
    "secp256k1": "1.3.132.0.10",
}
ID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
ALGORITHM_OID = {
    "Ed25519": "1.3.101.112",
    "X25519": "1.3.101.110",
    "ML-DSA-44": "2.16.840.1.101.3.4.3.17",
    "ML-DSA-65": "2.16.840.1.101.3.4.3.18",
    "ML-DSA-87": "2.16.840.1.101.3.4.3.19",
    "ML-KEM-512": "2.16.840.1.101.3.4.4.1",
    "ML-KEM-768": "2.16.840.1.101.3.4.4.2",
    "ML-KEM-1024": "2.16.840.1.101.3.4.4.3",
}

#: Field width in octets, from each curve's own parameter document. Used to
#: split ``X || Y`` and to left-pad; derived here rather than imported so a
#: wrong width in the production registry cannot hide behind agreement.
FIELD_BYTES = {"P-256": 32, "P-384": 48, "P-521": 66, "secp256k1": 32}


def algorithm_identifier(algorithm: str) -> Node:
    """RFC 5280 §4.1.1.2, with each family's ``parameters`` rule.

        AlgorithmIdentifier ::= SEQUENCE {
            algorithm   OBJECT IDENTIFIER,
            parameters  ANY DEFINED BY algorithm OPTIONAL }

    * EC: RFC 5480 §2.1.1 — ``parameters`` is ``ECParameters``, and for a named
      curve that is the curve's OBJECT IDENTIFIER.
    * Ed25519/X25519: RFC 8410 §3 — "the parameters field MUST be absent".
      Absent, not NULL. Emitting a NULL here is quietly non-conformant and is a
      common enough mistake that the distinction is worth encoding twice.
    * ML-DSA / ML-KEM: RFC 9881 §3 and draft-ietf-lamps-kyber-certificates §3
      say the same — absent.
    """
    if algorithm in CURVE_OID:
        return (SEQUENCE, [object_identifier(ID_EC_PUBLIC_KEY),
                           object_identifier(CURVE_OID[algorithm])])
    return (SEQUENCE, [object_identifier(ALGORITHM_OID[algorithm])])


# ---------------------------------------------------------------------------
# SubjectPublicKeyInfo — RFC 5280 §4.1.2.7
# ---------------------------------------------------------------------------
def spki(algorithm: str, public_key: bytes) -> bytes:
    """
        SubjectPublicKeyInfo ::= SEQUENCE {
            algorithm         AlgorithmIdentifier,
            subjectPublicKey  BIT STRING }

    For the EC curves the BIT STRING carries an ``ECPoint`` in the SEC 1
    uncompressed form (RFC 5480 §2.2): ``0x04 || X || Y``, each coordinate
    padded to the field width. For Ed25519/X25519 it is the 32 raw octets
    (RFC 8410 §4), and for ML-DSA/ML-KEM the raw FIPS 204/203 public key.
    """
    payload = b"\x04" + public_key if algorithm in CURVE_OID else public_key
    return encode((SEQUENCE, [algorithm_identifier(algorithm), bit_string(payload)]))


# ---------------------------------------------------------------------------
# PKCS#8 / OneAsymmetricKey — RFC 5958 §2
# ---------------------------------------------------------------------------
#     OneAsymmetricKey ::= SEQUENCE {
#         version                   Version,
#         privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
#         privateKey                PrivateKey,
#         attributes            [0] Attributes OPTIONAL,
#         ...,
#         [[2: publicKey        [1] PublicKey OPTIONAL ]],
#         ... }
#     Version    ::= INTEGER { v1(0), v2(1) }
#     PrivateKey ::= OCTET STRING
#     PublicKey  ::= BIT STRING
#
# §2 also fixes the relationship this reference encodes literally: "If publicKey
# is present, then version is set to v2 else version is set to v1."
V1 = 0
V2 = 1


def ec_private_key(
    algorithm: str,
    scalar: bytes,
    public_key: bytes | None,
    *,
    include_parameters: bool = False,
) -> Node:
    """RFC 5915 §3:

        ECPrivateKey ::= SEQUENCE {
            version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
            privateKey     OCTET STRING,
            parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
            publicKey  [1] BIT STRING OPTIONAL }

    ``privateKey`` is fixed width: RFC 5915 §3 says it is "an unsigned integer
    ... the length ... in octets ... is the length of the base point order",
    i.e. ceil(log2(n)/8), left-padded. That is the whole reason a scalar with a
    leading zero octet is an interesting test case — the natural way to get it
    wrong is a big-integer round trip that emits a shorter field, which is
    still valid DER and still parses, as a different key. This encoder pads and
    refuses a short input rather than accommodating it.

    ``parameters`` is governed by where the structure sits. RFC 5915 §3: "when
    ... used in a context where the curve is already known, such as within a
    PrivateKeyInfo, the parameters field SHOULD be omitted" — the enclosing
    ``privateKeyAlgorithm`` already names the curve, and repeating it creates a
    file that can name two different curves. A *standalone* ``EC PRIVATE KEY``,
    which is what RFC 9500 §2.3 publishes, has no enclosing identifier and so
    carries it. ``include_parameters`` selects between the two, so this encoder
    can reproduce the RFC's own bytes as well as the wrapped form.
    """
    width = FIELD_BYTES[algorithm]
    if len(scalar) > width:
        raise ValueError(f"{algorithm} scalar is {len(scalar)} octets, wider than {width}")
    children: list[Node] = [integer(1), octet_string(scalar.rjust(width, b"\x00"))]
    if include_parameters:
        children.append(context(0, [object_identifier(CURVE_OID[algorithm])],
                                constructed=True))
    if public_key is not None:
        children.append(context(1, [bit_string(b"\x04" + public_key)], constructed=True))
    return (SEQUENCE, children)


def pq_private_key(seed: bytes | None, expanded: bytes | None, arm: str) -> Node:
    """RFC 9881 §6 (and the ML-KEM I-D §6, which is word-for-word the same shape):

        ML-DSA-PrivateKey ::= CHOICE {
            seed [0] IMPLICIT OCTET STRING (SIZE (32)),
            expandedKey OCTET STRING (SIZE (2560 | 4032 | 4896)),
            both SEQUENCE {
                seed OCTET STRING (SIZE (32)),
                expandedKey OCTET STRING (SIZE (2560 | 4032 | 4896)) } }

    RFC 9881 §6 is explicit that the arm is selected by the ASN.1 tag — 0x80,
    0x04, 0x30 — "rather than any other heuristic like length of the enclosing
    OCTET STRING". The ``[0]`` is IMPLICIT, so it is *primitive*: the tag
    replaces the OCTET STRING's own and the seed octets follow the header
    directly. An encoder that emits 0xA0 here has produced a different CHOICE.
    """
    if arm == "seed":
        if seed is None:
            raise ValueError("the seed arm needs a seed")
        return context(0, seed, constructed=False)
    if arm == "expandedKey":
        if expanded is None:
            raise ValueError("the expandedKey arm needs an expanded key")
        return octet_string(expanded)
    if arm == "both":
        if seed is None or expanded is None:
            raise ValueError("the both arm needs a seed and an expanded key")
        return (SEQUENCE, [octet_string(seed), octet_string(expanded)])
    raise ValueError(f"unknown private-key CHOICE arm {arm!r}")


def pkcs8(
    algorithm: str,
    private_key: bytes,
    *,
    public_key: bytes | None = None,
    include_public_key: bool = False,
    seed: bytes | None = None,
    pq_arm: str = "expandedKey",
) -> bytes:
    """Build a ``OneAsymmetricKey`` for any of the twelve algorithms.

    ``include_public_key`` places the public half where the algorithm's own
    document puts it, which is *not* the same field in every family:

    * EC — inside RFC 5915 ``ECPrivateKey``'s ``[1] publicKey``, which RFC 5958
      never sees, so the outer version stays v1.
    * Ed25519/X25519 and ML-DSA/ML-KEM — RFC 5958's own ``[1] publicKey`` on the
      outer SEQUENCE, which raises the version to v2.

    Conflating the two is the mistake this reference is positioned to catch: an
    encoder that puts an EC public key in the outer field produces a file that
    parses, carries the right key, and is not what any EC tooling writes.
    """
    extra: list[Node] = []
    version = V1

    if algorithm in CURVE_OID:
        embedded = public_key if include_public_key else None
        if include_public_key and embedded is None:
            raise ValueError("include_public_key=True needs the public key")
        inner = encode(ec_private_key(algorithm, private_key, embedded))
    elif algorithm in ("Ed25519", "X25519"):
        # RFC 8410 §7: CurvePrivateKey ::= OCTET STRING, wrapped again by
        # OneAsymmetricKey's own privateKey OCTET STRING.
        inner = encode(octet_string(private_key))
    else:
        inner = encode(pq_private_key(seed, private_key, pq_arm))

    if include_public_key and algorithm not in CURVE_OID:
        if public_key is None:
            raise ValueError("include_public_key=True needs the public key")
        # [1] PublicKey is an IMPLICIT BIT STRING: the context tag replaces the
        # BIT STRING's, so the unused-bits octet is written directly.
        extra = [context(1, b"\x00" + public_key, constructed=False)]
        version = V2

    return encode((SEQUENCE, [
        integer(version),
        algorithm_identifier(algorithm),
        octet_string(inner),
        *extra,
    ]))


# ---------------------------------------------------------------------------
# PEM — RFC 7468
# ---------------------------------------------------------------------------
def pem(der: bytes, label: str) -> str:
    """RFC 7468 §2: 64 base64 characters per line, ``-----BEGIN <label>-----``.

    Implemented with the stdlib base64 codec only; the line folding is the part
    worth having a second opinion on, because a 76-column default (the MIME
    width, which several stdlib helpers use) produces a file most parsers
    accept and RFC 7468 does not describe.
    """
    import base64

    body = base64.b64encode(der).decode("ascii")
    lines = [body[i : i + 64] for i in range(0, len(body), 64)] or [""]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"
