#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Key interoperability formats — conformance and negative space.
==============================================================

``ama_cryptography.key_formats`` exists so an AMA key can leave the library and
come back. A round trip through AMA's own encoder proves none of that: an
encoder with a wrong OID, an absent-vs-NULL parameters mistake, or a
misidentified private-key CHOICE arm round-trips perfectly against itself and
interoperates with nothing.

So the positive half of this module is driven almost entirely by **the
specifications' own answer keys**, vendored under ``tests/kat/keyformats/``:

============================================  ===============================
Corpus                                        What it pins
============================================  ===============================
RFC 9881 Appendix C                           ML-DSA-44/65/87 PKCS#8 in all
                                              three CHOICE arms, SPKI, and
                                              three inconsistent keys
draft-ietf-lamps-kyber-certificates-11 App C  the same for ML-KEM-512/768/1024,
                                              with four inconsistent keys
RFC 8410 §10                                  Ed25519 SPKI and both PKCS#8
                                              forms, including one carrying a
                                              PKCS#8 attribute and a primitive
                                              ``[1] publicKey``
RFC 8037 Appendix A                           Ed25519 JWK, and the RFC 7638
                                              thumbprint of it
RFC 8152 Appendix C.7.1                       P-256 and P-521 ``COSE_Key``
RFC 9500 §2.3                                 the IETF's own P-256/P-384/P-521
                                              ``ECPrivateKey`` — the structure
                                              RFC 5915 defines without an
                                              example
============================================  ===============================

Every one of those is checked **both ways**: the vendored bytes must parse to
the right key, and re-encoding that key must reproduce the vendored bytes
exactly. One direction alone would miss a decoder and encoder that are wrong in
the same way.

What the documents do not print — every algorithm, every option, every width —
is covered against ``tests/ref_keyformat.py``, a second encoder transcribed from
the RFCs' own ASN.1. It is AMA's work, it imports nothing from
``ama_cryptography``, and it is itself anchored against RFC 9500 §2.3 and
RFC 8410 §10.1 before it is trusted anywhere else. No other cryptographic
product's output appears in this suite.

The negative half is the larger one. A key parser is a parser fed hostile input
by definition — anyone who can hand you a key file reaches it — so malformed,
truncated, mismatched, non-canonical and type-confused inputs are exercised
here as first-class cases, not as an afterthought.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, cast

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import ama_cryptography.key_formats as kf  # noqa: E402 -- import follows the repo-root sys.path insert above (KF-003)
import ama_cryptography.pqc_backends as pb  # noqa: E402 -- same (KF-003)
import tests.ref_keyformat as ref  # noqa: E402 -- same (KF-003)
from ama_cryptography._asn1 import (  # noqa: E402 -- same (KF-003)
    cbor_decode_canonical,
    cbor_encode_canonical,
    der_bit_string,
    der_integer,
    der_octet_string,
    der_sequence,
    der_tagged,
    oid_from_string,
    oid_to_string,
)
from ama_cryptography.exceptions import (  # noqa: E402 -- same (KF-003)
    KeyFormatError,
    UnsupportedKeyFormatError,
)

CORPUS = REPO_ROOT / "tests" / "kat" / "keyformats"

pytestmark = pytest.mark.skipif(pb._native_lib is None, reason="native library not built")


# ---------------------------------------------------------------------------
# Corpus loading — a missing corpus fails, it does not skip
# ---------------------------------------------------------------------------
def _load(name: str) -> dict[str, Any]:
    path = CORPUS / name
    assert path.is_file(), (
        f"{path} is missing. This corpus is the only evidence that AMA's key "
        "encodings match the specifications rather than merely themselves; a "
        "missing file must fail rather than silently skip. Regenerate with "
        "tools/build_keyformat_corpus.py --specs"
    )
    loaded: dict[str, Any] = json.loads(path.read_text())
    return loaded


def _pem(record: dict[str, Any]) -> str:
    return kf.encode_pem(base64.b64decode(record["pem_b64"]), record["label"])


def _der(record: dict[str, Any]) -> bytes:
    return base64.b64decode(record["pem_b64"])


def _pq_records(name: str, kind: str, label: str) -> list[dict[str, Any]]:
    return [r for r in _load(name)["records"] if r["kind"] == kind and r["label"] == label]


def _ids(records: list[dict[str, Any]]) -> list[str]:
    return [r["section"].split("  ")[0].rstrip(".") or str(i) for i, r in enumerate(records)]


ML_DSA_VALID_PRIV = _pq_records("rfc9881_ml_dsa.json", "valid", "PRIVATE KEY")
ML_DSA_VALID_PUB = _pq_records("rfc9881_ml_dsa.json", "valid", "PUBLIC KEY")
ML_DSA_BAD = _pq_records("rfc9881_ml_dsa.json", "inconsistent", "PRIVATE KEY")
ML_KEM_VALID_PRIV = _pq_records("lamps_ml_kem.json", "valid", "PRIVATE KEY")
ML_KEM_VALID_PUB = _pq_records("lamps_ml_kem.json", "valid", "PUBLIC KEY")
ML_KEM_BAD = _pq_records("lamps_ml_kem.json", "inconsistent", "PRIVATE KEY")

ALL_ALGORITHMS = sorted(kf.ALGORITHMS)
CLASSICAL = [n for n in ALL_ALGORITHMS if kf.ALGORITHMS[n].kind != "pq"]
EC_ALGORITHMS = [n for n in ALL_ALGORITHMS if kf.ALGORITHMS[n].kind == "ec"]
PQ_ALGORITHMS = [n for n in ALL_ALGORITHMS if kf.ALGORITHMS[n].kind == "pq"]


# One dataclass describes three kinds of algorithm, so every kind-specific
# field on `_Alg` is Optional and `mypy --strict` rejects passing one straight
# to a backend entry point that wants a concrete type. These state the
# invariant *once*, where it can be read, instead of scattering two dozen
# inline narrowings through the tests — and if the registry ever grows an
# entry that violates it, the assertion names the algorithm.
def _param_set(alg: kf._Alg) -> int:
    assert alg.pq_param_set is not None, f"{alg.name} is not a PQ algorithm"
    return alg.pq_param_set


def _curve(alg: kf._Alg) -> str:
    assert alg.curve is not None, f"{alg.name} is not an EC algorithm"
    return alg.curve


def _curve_oid(alg: kf._Alg) -> str:
    assert alg.curve_oid is not None, f"{alg.name} has no curve OID"
    return alg.curve_oid


def _reencode(key: kf.PublicKey | kf.PrivateKey, which: str) -> bytes:
    """Re-encode a parsed key in the form it was parsed from.

    ``which`` decides the type, but only ``isinstance`` narrows it, and a
    mismatch between the two would mean the parser returned the wrong kind of
    key — worth asserting rather than casting away.
    """
    if which == "spki":
        assert isinstance(key, kf.PublicKey), which
        return key.to_spki()
    assert isinstance(key, kf.PrivateKey), which
    return key.to_pkcs8()


def make_key(name: str) -> tuple[kf.PublicKey, kf.PrivateKey]:
    """A freshly generated key pair in AMA's native representation."""
    alg = kf.ALGORITHMS[name]
    if name == "Ed25519":
        public, secret = pb.native_ed25519_keypair()
        secret = secret[:32]
    elif name == "X25519":
        public, secret = pb.native_x25519_keypair()
    elif name == "secp256k1":
        import os

        secret = os.urandom(32)
        public = pb.native_secp256k1_pubkey_decompress(
            pb.native_secp256k1_pubkey_from_privkey(secret)
        )
    elif alg.kind == "ec":
        public, secret = pb.native_nistp_keypair(_curve(alg))
    elif alg.pq_family == "ml-dsa":
        public, secret = pb.native_ml_dsa_keypair(_param_set(alg))
    else:
        public, secret = pb.native_ml_kem_keypair(_param_set(alg))
    return kf.PublicKey(name, public), kf.PrivateKey(name, secret, public)


def _public_from_scalar(name: str, scalar: bytes) -> bytes:
    """The public key for a chosen EC scalar, via the native backend.

    Only used to build the constructed edge cases below; the *encoding* they
    check is still compared against the specification-derived reference.
    """
    if name == "secp256k1":
        return pb.native_secp256k1_pubkey_decompress(
            pb.native_secp256k1_pubkey_from_privkey(scalar)
        )
    return pb.native_nistp_pubkey_from_privkey(_curve(kf.ALGORITHMS[name]), scalar)


def make_seeded_pq_key(name: str, filler: int = 0x5A) -> kf.PrivateKey:
    """A PQ key that *carries its seed*, which ``make_key`` deliberately does not.

    ``make_key`` goes through the randomised keygen entry points, so the seed is
    consumed inside the C library and never surfaces — the same situation as a
    key imported from an ``expandedKey``-only file. Anything exercising the
    ``seed`` or ``both`` arms needs a key whose seed is known, so it is built
    from a fixed one here. Deterministic, so a failure reproduces.
    """
    alg = kf.ALGORITHMS[name]
    assert alg.kind == "pq", name
    seed = bytes((filler + i) & 0xFF for i in range(alg.pq_seed_bytes))
    if alg.pq_family == "ml-dsa":
        public, secret = pb.native_ml_dsa_keypair_from_seed(_param_set(alg), seed)
    else:
        public, secret = pb.native_ml_kem_keypair_from_seed(_param_set(alg), seed[:32], seed[32:])
    return kf.PrivateKey(name, secret, public, seed)


# ===========================================================================
# 1. The specifications' answer keys — ML-DSA and ML-KEM
# ===========================================================================
@pytest.mark.parametrize(
    "record", ML_DSA_VALID_PRIV + ML_KEM_VALID_PRIV, ids=_ids(ML_DSA_VALID_PRIV + ML_KEM_VALID_PRIV)
)
def test_pq_private_key_vectors_parse(record: dict[str, Any]) -> None:
    """Every published private key parses, in every CHOICE arm.

    Parsing a ``seed`` arm runs it through deterministic keygen, so this is
    simultaneously a FIPS 203/204 key-generation KAT: if AMA's ML-KEM-512 or
    ML-DSA-44 expansion were wrong by a single sampled coefficient, the seed
    would not reproduce the RFC's expanded key and the ``both`` records would
    fail outright.
    """
    key = kf.load_pkcs8(_pem(record))
    alg = kf.ALGORITHMS[key.algorithm]
    assert len(key.key) == alg.private_bytes
    # Every arm yields a usable public key: read from the file, expanded from
    # the seed, or recomputed from the expanded key.
    assert key.public_key is not None
    assert len(key.public_key) == alg.public_bytes
    assert (key.seed is not None) == (record["arm"] in ("seed", "both"))


@pytest.mark.parametrize(
    "record", ML_DSA_VALID_PRIV + ML_KEM_VALID_PRIV, ids=_ids(ML_DSA_VALID_PRIV + ML_KEM_VALID_PRIV)
)
def test_pq_private_key_vectors_reencode_exactly(record: dict[str, Any]) -> None:
    """Re-encoding a published key reproduces its bytes.

    This is the direction that catches an encoder which is wrong in the same
    way as the decoder — the failure a self-round-trip cannot see.
    """
    key = kf.load_pkcs8(_pem(record))
    assert key.to_pkcs8(pq_format=record["arm"]) == _der(record)


@pytest.mark.parametrize(
    "record", ML_DSA_VALID_PRIV + ML_KEM_VALID_PRIV, ids=_ids(ML_DSA_VALID_PRIV + ML_KEM_VALID_PRIV)
)
def test_pq_seed_survives_a_round_trip(record: dict[str, Any]) -> None:
    """A seed-carrying key must not degrade to the expanded form.

    RFC 9881 §8.1: expanding a seed is one-way, so a layer that drops the seed
    on import turns a 54-octet key file into a multi-kilobyte one on the next
    write and the compact form can never be recovered. ``pq_format="auto"``
    therefore has to re-emit what arrived.
    """
    key = kf.load_pkcs8(_pem(record))
    if record["arm"] == "seed":
        assert key.seed is not None
        assert key.to_pkcs8() == _der(record), "seed form silently expanded"
    elif record["arm"] == "expandedKey":
        assert key.seed is None
        assert key.to_pkcs8() == _der(record)


@pytest.mark.parametrize(
    "record",
    ML_DSA_VALID_PUB + ML_KEM_VALID_PUB,
    ids=[r["section"][:20] + str(i) for i, r in enumerate(ML_DSA_VALID_PUB + ML_KEM_VALID_PUB)],
)
def test_pq_public_key_vectors_round_trip(record: dict[str, Any]) -> None:
    """Published SPKI parses and re-encodes byte-for-byte."""
    key = kf.load_spki(_pem(record))
    assert len(key.key) == kf.ALGORITHMS[key.algorithm].public_bytes
    assert key.to_spki() == _der(record)


def test_pq_seed_and_expanded_forms_describe_the_same_key() -> None:
    """The three arms of one published key must agree with each other.

    RFC 9881 Appendix C derives all of its examples from the same seed
    ``000102...1e1f``, so the seed, expanded and both records at a given
    parameter set are three encodings of one key. If AMA's expansion drifted,
    they would decode to different keys while each still parsing cleanly.
    """
    for corpus in ("rfc9881_ml_dsa.json", "lamps_ml_kem.json"):
        by_algorithm: dict[str, list[tuple[str, kf.PrivateKey]]] = {}
        for record in _pq_records(corpus, "valid", "PRIVATE KEY"):
            key = kf.load_pkcs8(_pem(record))
            by_algorithm.setdefault(key.algorithm, []).append((record["arm"], key))
        for algorithm, entries in by_algorithm.items():
            assert len(entries) == 3, f"{algorithm}: expected all three arms"
            keys = {arm: key.key for arm, key in entries}
            assert len(set(keys.values())) == 1, (
                f"{algorithm}: the seed, expandedKey and both arms of the same "
                f"published key decoded to different secret keys: "
                f"{ {arm: len(v) for arm, v in keys.items()} }"
            )


@pytest.mark.parametrize(
    "record", ML_DSA_BAD + ML_KEM_BAD, ids=[f"bad{i}" for i in range(len(ML_DSA_BAD + ML_KEM_BAD))]
)
def test_pq_inconsistent_private_keys_are_rejected(record: dict[str, Any]) -> None:
    """The specifications' deliberately-bad keys must not import.

    RFC 9881 §8.2 and draft-ietf-lamps-kyber-certificates §C.4.1 publish these
    for exactly this purpose. They cover three distinct failures, and each
    needs a different check:

    * a ``both`` key whose seed does not expand to its ``expandedKey``;
    * an ``expandedKey``-only ML-DSA key whose ``tr`` or ``t0`` disagrees with
      the key its ``s1``/``s2`` imply;
    * an ``expandedKey``-only ML-KEM key with a mutated ``dk_PKE`` or a mutated
      ``H(ek)``.

    RFC 9881 notes that implementations which "neglect to check consistency of
    tr and t_0" detect none of the second kind. Accepting any of these produces
    a key whose signatures verify under no public key, or which derives a
    shared secret the sender never computed — and because ML-KEM's implicit
    rejection is designed to fail silently, that second one surfaces nowhere.
    """
    with pytest.raises(KeyFormatError):
        kf.load_pkcs8(_pem(record))


def test_the_bad_key_corpus_is_not_empty() -> None:
    """A negative corpus that silently emptied would make the gate above vacuous."""
    assert len(ML_DSA_BAD) == 3, f"expected RFC 9881's three bad keys, got {len(ML_DSA_BAD)}"
    assert len(ML_KEM_BAD) == 4, f"expected the I-D's four bad keys, got {len(ML_KEM_BAD)}"


# ===========================================================================
# 2. RFC 8410 §10 — Ed25519, including the awkward form
# ===========================================================================
RFC8410 = _load("rfc8410_okp.json")["records"]
RFC8410_PRIVATE = [r for r in RFC8410 if r["label"] == "PRIVATE KEY"]


def test_rfc8410_public_key_vector() -> None:
    record = next(r for r in RFC8410 if r["label"] == "PUBLIC KEY")
    key = kf.load_spki(_pem(record))
    assert key.algorithm == "Ed25519"
    assert key.to_spki() == _der(record)


def test_rfc8410_private_key_without_public_key() -> None:
    """§10.3's first example: v1, bare CurvePrivateKey, no public key."""
    record = RFC8410_PRIVATE[0]
    key = kf.load_pkcs8(_pem(record))
    assert key.algorithm == "Ed25519"
    assert key.key.hex() == (
        "d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842"
    ), "RFC 8410 §10.3 prints this seed in the running text"
    assert key.to_pkcs8() == _der(record), "the conventional default must match the RFC"


def test_rfc8410_private_key_with_attribute_and_public_key() -> None:
    """§10.3's second example, which is the one that finds parser bugs.

    It is version 1, it carries a PKCS#8 *attribute* (a "Curdle Chairs"
    friendly name) that AMA does not consume, and its ``[1] publicKey`` uses
    the primitive ``0x81`` tag rather than the constructed ``0xA1``. A parser
    that rejects unknown attributes, or that assumes the constructed form,
    fails here — and third-party key files do carry both.
    """
    record = RFC8410_PRIVATE[1]
    key = kf.load_pkcs8(_pem(record))
    assert key.algorithm == "Ed25519"
    assert key.public_key is not None
    # Same key as the first example, and its public half is §10.1's.
    first = kf.load_pkcs8(_pem(RFC8410_PRIVATE[0]))
    assert key.key == first.key
    public_record = next(r for r in RFC8410 if r["label"] == "PUBLIC KEY")
    assert key.public_key == kf.load_spki(_pem(public_record)).key


def test_rfc8410_attributes_are_not_reemitted() -> None:
    """Attributes are accepted for interop but nothing pretends to preserve them.

    Re-encoding drops them, which is the documented behaviour; asserting it
    keeps the docstring honest.
    """
    record = RFC8410_PRIVATE[1]
    key = kf.load_pkcs8(_pem(record))
    assert key.to_pkcs8(include_public_key=True) != _der(record)
    assert kf.load_pkcs8(key.to_pkcs8(include_public_key=True)).key == key.key


# ===========================================================================
# 3. RFC 9500 §2.3 — the IETF's own EC keys, and a reference encoder
# ===========================================================================
# RFC 5915 defines ECPrivateKey and publishes no example of it; RFC 5480 does
# the same for the SPKI side. That gap is why this section used to hold key
# files produced by another cryptographic product. It no longer does, and it
# does not need to:
#
#   * RFC 9500 ("Standard Public Key Cryptography (PKCS) Test Keys", December
#     2023) §2.3 publishes P-256, P-384 and P-521 keys as `EC PRIVATE KEY` PEM,
#     which *is* an RFC 5915 ECPrivateKey — the exact structure AMA places
#     inside the PKCS#8 privateKey OCTET STRING. A standards-body answer key,
#     like every other corpus here.
#   * `tests/ref_keyformat.py` is a second encoder for these structures,
#     transcribed from the RFCs' own ASN.1 with the text quoted inline. It is
#     AMA's work, it imports nothing from `ama_cryptography`, and it is built
#     declaratively so it shares no control flow with the production encoder.
#
# The second point carries the lesson PR #378 learned the hard way on RFC 6979:
# two implementations that share an assumption do not check each other. A
# reference derived from the specification, in a different shape, is the
# defence; a reference derived from the implementation is theatre.
RFC9500 = _load("rfc9500_ec.json")["records"]
RFC9500_ALGORITHMS = sorted(r["algorithm"] for r in RFC9500)


def _rfc9500(name: str) -> dict[str, Any]:
    return next(r for r in RFC9500 if r["algorithm"] == name)


def test_rfc9500_covers_the_nist_curves() -> None:
    """A curve silently missing from the corpus would go unchecked."""
    assert RFC9500_ALGORITHMS == ["P-256", "P-384", "P-521"], RFC9500_ALGORITHMS


def _rfc9500_wrapped(name: str) -> bytes:
    """RFC 9500's standalone ECPrivateKey inside a PKCS#8 OneAsymmetricKey.

    The RFC prints the bare SEC 1 form, so the RFC 5958 §2 wrapper is built
    around it here — with the OID and version RFC 5480 and RFC 5958 specify —
    to reach AMA's PKCS#8 entry point.
    """
    alg = kf.ALGORITHMS[name]
    return der_sequence(
        der_integer(0),
        der_sequence(oid_from_string(alg.oid), oid_from_string(_curve_oid(alg))),
        der_octet_string(_der(_rfc9500(name))),
    )


@pytest.mark.parametrize("name", RFC9500_ALGORITHMS)
def test_the_reference_encoder_reproduces_rfc9500_exactly(name: str) -> None:
    """The reference is checked against the document before anything is checked
    against the reference.

    Two encoders that agree could both be wrong. RFC 9500 §2.3's DER is an
    answer key neither AMA nor this reference wrote, so reproducing it octet for
    octet — including the ``[0] parameters`` a standalone ECPrivateKey carries
    and the constructed ``[1] publicKey`` — is what earns the reference the
    right to be an authority in the tests that follow.
    """
    published = _der(_rfc9500(name))
    private = kf.load_pkcs8(_rfc9500_wrapped(name))
    assert private.public_key is not None
    rebuilt = ref.encode(
        ref.ec_private_key(name, private.key, private.public_key, include_parameters=True)
    )
    assert rebuilt == published, (
        "the specification-derived reference does not reproduce RFC 9500's own "
        "bytes; it cannot be used as an authority until it does"
    )


@pytest.mark.parametrize("name", RFC9500_ALGORITHMS)
def test_rfc9500_ec_private_keys_parse_and_reencode(name: str) -> None:
    """The RFC's own key material, imported and re-emitted.

    Two directions, and they check different things:

    * The RFC's ``[0] parameters`` must be *accepted* — a standalone
      ECPrivateKey carries the curve OID, and third-party files do too.
    * AMA's own output must then omit it, because RFC 5915 §3 says the field
      SHOULD be omitted "in a context where the curve is already known, such as
      within a PrivateKeyInfo". Re-emitting it would produce a file naming the
      curve twice — the shape that lets two parsers disagree about which one
      wins, and which ``test_ec_key_naming_two_different_curves_is_refused``
      exists for.

    So the re-encoding is compared against the reference's *wrapped* form, not
    against the RFC's standalone bytes: byte equality with the wrong structure
    would be the wrong thing to assert.
    """
    alg = kf.ALGORITHMS[name]
    private = kf.load_pkcs8(_rfc9500_wrapped(name))
    assert private.algorithm == name
    assert len(private.key) == alg.field_bytes
    assert private.public_key is not None

    # The public key the RFC prints must be the one the RFC's own scalar
    # derives to — the document checking itself, and AMA against both.
    assert private.derive_public_key().key == private.public_key

    assert private.to_pkcs8() == ref.pkcs8(
        name, private.key, public_key=private.public_key, include_public_key=True
    )
    assert kf.load_pkcs8(private.to_pkcs8()).key == private.key


@pytest.mark.parametrize("name", RFC9500_ALGORITHMS)
def test_rfc9500_scalar_widths_are_the_curves_own(name: str) -> None:
    """RFC 9500's P-521 scalar begins 0x01 in a 66-octet field, so it is also a
    width vector: an encoder that dropped leading octets would shorten it."""
    alg = kf.ALGORITHMS[name]
    published = _der(_rfc9500(name))
    private = kf.load_pkcs8(_rfc9500_wrapped(name))
    assert len(private.key) == alg.field_bytes
    assert private.key in published, "the scalar was not carried through verbatim"


@pytest.mark.parametrize("name", RFC9500_ALGORITHMS)
def test_rfc9500_public_keys_round_trip_through_spki(name: str) -> None:
    private = kf.load_pkcs8(
        der_sequence(
            der_integer(0),
            der_sequence(
                oid_from_string(kf.ALGORITHMS[name].oid),
                oid_from_string(_curve_oid(kf.ALGORITHMS[name])),
            ),
            der_octet_string(_der(_rfc9500(name))),
        )
    )
    public = private.public()
    assert kf.load_spki(public.to_spki()) == public
    assert kf.load_spki(public.to_pem()) == public


# --- The reference encoder, over every algorithm and every option ------------
@pytest.mark.parametrize("name", ALL_ALGORITHMS)
def test_spki_matches_the_reference_encoder(name: str) -> None:
    """AMA's SPKI is what the RFCs' ASN.1 says it should be.

    Covers what the vendored vectors cannot: every algorithm, not the handful
    any document happened to print.
    """
    public, _ = make_key(name)
    assert public.to_spki() == ref.spki(name, public.key)
    assert public.to_pem() == ref.pem(ref.spki(name, public.key), "PUBLIC KEY")


@pytest.mark.parametrize("name", ALL_ALGORITHMS)
@pytest.mark.parametrize("include_public_key", [False, True])
def test_pkcs8_matches_the_reference_encoder(name: str, include_public_key: bool) -> None:
    """Both settings of ``include_public_key``, against the specification.

    The two families put the public half in *different fields* — RFC 5915's
    ``[1]`` inside ECPrivateKey for EC, RFC 5958's ``[1]`` on the outer
    SEQUENCE for everything else — and only the second raises the version to
    v2. An encoder that conflates them produces a file that parses, carries the
    right key, and is not what the document describes.
    """
    public, private = make_key(name)
    expected = ref.pkcs8(
        name,
        private.key,
        public_key=public.key,
        include_public_key=include_public_key,
        pq_arm="expandedKey",
    )
    assert private.to_pkcs8(include_public_key=include_public_key) == expected


@pytest.mark.parametrize("name", PQ_ALGORITHMS)
@pytest.mark.parametrize("arm", ["seed", "expandedKey", "both"])
def test_the_pq_choice_arms_match_the_reference_encoder(name: str, arm: str) -> None:
    """RFC 9881 §6's three arms, each encoded independently from the ASN.1.

    The ``seed`` arm is the one worth a second opinion: ``[0]`` is IMPLICIT and
    therefore *primitive* (0x80), so the seed octets follow the header with no
    inner OCTET STRING. An encoder that emits the constructed 0xA0 has produced
    a different CHOICE that some parsers still accept.
    """
    private = make_seeded_pq_key(name)
    assert private.seed is not None
    expected = ref.pkcs8(
        name,
        private.key,
        seed=private.seed,
        pq_arm=arm,
        public_key=private.public_key,
    )
    assert private.to_pkcs8(pq_format=arm) == expected
    assert kf.load_pkcs8(expected).key == private.key


def test_the_reference_encoder_is_independent_of_the_production_one() -> None:
    """The property that makes the comparison worth anything.

    A reference that imports the encoder it checks agrees with it by
    construction. Asserted rather than trusted, because the import that breaks
    this is one line and would be invisible in review.
    """
    import ast

    # Explicit encoding: ref_keyformat.py contains non-ASCII, and ci.yml's
    # Windows lanes deliberately do not set PYTHONUTF8 (see the note in that
    # workflow), so a bare read_text() decodes UTF-8 source through cp1252.
    # That does not raise — cp1252 maps every byte — it silently yields
    # mojibake, so this import scan would parse subtly wrong text and still
    # report success.  Same root cause as the UnicodeDecodeError this commit
    # fixes in test_conftest_backend_skip_scoping.py, one failure mode quieter.
    source = (REPO_ROOT / "tests" / "ref_keyformat.py").read_text(encoding="utf-8")
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "ama_cryptography" not in imported, (
        f"tests/ref_keyformat.py imports ama_cryptography ({sorted(imported)}); it "
        "must stand on the RFC text alone"
    )
    assert imported <= {"__future__", "typing", "base64"}, sorted(imported)
    assert ref.CURVE_OID["P-256"] == "1.2.840.10045.3.1.7"
    # Both encoders must agree on the OIDs *and* have derived them separately:
    # the reference builds arcs from the dotted string per X.690 §8.19.
    for algorithm, dotted in ref.ALGORITHM_OID.items():
        assert kf.ALGORITHMS[algorithm].oid == dotted
    for curve, dotted in ref.CURVE_OID.items():
        assert kf.ALGORITHMS[curve].curve_oid == dotted


def test_the_reference_encoder_reproduces_a_published_spki() -> None:
    """A second document anchoring the reference, on the SPKI side this time.

    RFC 9500 anchors ECPrivateKey; RFC 8410 §10.1's SPKI anchors the
    SubjectPublicKeyInfo wrapper and the absent-not-NULL parameters rule.
    """
    record = next(r for r in RFC8410 if r["label"] == "PUBLIC KEY")
    published = _der(record)
    parsed = kf.load_spki(published)
    assert ref.spki("Ed25519", parsed.key) == published


# --- Edge cases: fixed-width fields holding short numbers --------------------
# The encodings that break implementations are the ones where a fixed-width
# field holds a number with leading zero octets, because the natural way to get
# it wrong — route the value through a big integer and back — produces a
# *shorter* field that is still well-formed DER and still parses, as a
# different key.
#
# These are *constructed* rather than sampled. Waiting for a random key to have
# the property means about 1 P-521 key in 512 for the scalar case, and a corpus
# built by generating keys until one turns up is neither deterministic nor able
# to reach the awkward combinations at all. Constructing the scalar and
# deriving the point with AMA's own primitives gives an exact, reproducible
# case, and the reference encoder — which pads from the RFC 5915 rule rather
# than from AMA's code — is what says whether the encoding is right.
_LEADING_ZERO_SCALARS = {
    # A scalar whose big-endian encoding needs one leading zero octet at the
    # curve's fixed width, and one that needs many. Both are valid private keys
    # (any value in [1, n-1] is), and both are far below the field width.
    "one_zero_octet": lambda width: (1 << (8 * width - 9)) | 1,
    "many_zero_octets": lambda width: 0x1234,
}


@pytest.mark.parametrize("name", EC_ALGORITHMS)
@pytest.mark.parametrize("shape", sorted(_LEADING_ZERO_SCALARS))
def test_a_scalar_with_leading_zero_octets_keeps_its_width(name: str, shape: str) -> None:
    """RFC 5915 §3 fixes ``privateKey`` at the base-point-order width.

    A big-integer round trip emits a shorter OCTET STRING, which is valid DER,
    parses cleanly, and is a different key.
    """
    alg = kf.ALGORITHMS[name]
    width = alg.field_bytes
    scalar = _LEADING_ZERO_SCALARS[shape](width).to_bytes(width, "big")
    assert scalar[0] == 0x00, "the constructed scalar has no leading zero octet"

    public = kf.PublicKey(name, _public_from_scalar(name, scalar))
    private = kf.PrivateKey(name, scalar, public.key)

    encoded = private.to_pkcs8()
    assert encoded == ref.pkcs8(name, scalar, public_key=public.key, include_public_key=True)
    reparsed = kf.load_pkcs8(encoded)
    assert reparsed.key == scalar, "the scalar did not survive the round trip"
    assert len(reparsed.key) == width, (
        f"{name}: the scalar came back {len(reparsed.key)} octets wide, not {width} — "
        "a leading zero was dropped somewhere"
    )
    # The JWK 'd' member is fixed width too (RFC 7518 §6.2.2.1).
    d = private.to_jwk()["d"]
    assert len(base64.urlsafe_b64decode(d + "=" * (-len(d) % 4))) == width


@pytest.mark.parametrize("name", EC_ALGORITHMS)
def test_a_coordinate_with_a_leading_zero_octet_keeps_its_width(name: str) -> None:
    """The same hazard on the public half — SEC 1, JWK and COSE all fix the width.

    RFC 8152 Appendix C.7.1's P-521 key is vendored precisely because its ``x``
    begins with a zero octet; this extends that coverage to every curve and to
    both coordinates, by searching AMA's own keygen for one rather than waiting
    for it to appear.
    """
    alg = kf.ALGORITHMS[name]
    half = alg.field_bytes
    found = None
    for _ in range(4000):
        public, private = make_key(name)
        if public.key[0] == 0x00 or public.key[half] == 0x00:
            found = (public, private)
            break
    if found is None:  # pragma: no cover - about 1 in 128 per attempt
        pytest.skip(f"no {name} key with a zero coordinate octet in 4000 tries")
    # `pytest.skip` is `NoReturn`, so this narrowing is redundant at runtime —
    # but only a type-checker that can *see* pytest knows that. `pytest.*` is
    # under `ignore_missing_imports`, so in a lint environment without pytest
    # installed it degrades to `Any`, the guard above stops narrowing, and the
    # unpack below becomes "None object is not iterable". Spelled out so the
    # file type-checks the same either way.
    assert found is not None
    public, private = found

    assert public.to_spki() == ref.spki(name, public.key)
    assert kf.load_spki(public.to_spki()) == public

    jwk = public.to_jwk()
    for member in ("x", "y"):
        raw = base64.urlsafe_b64decode(jwk[member] + "=" * (-len(jwk[member]) % 4))
        assert (
            len(raw) == half
        ), f"{name}: JWK '{member}' is {len(raw)} octets, not the mandatory {half}"
    assert kf.jwk_to_public_key(jwk) == public

    decoded = cbor_decode_canonical(public.to_cose())
    assert len(decoded[-2]) == half and len(decoded[-3]) == half
    assert kf.cose_to_public_key(public.to_cose()) == public


@pytest.mark.parametrize("name", EC_ALGORITHMS)
def test_a_shortened_coordinate_is_refused(name: str) -> None:
    """The failure the width rules exist to prevent, produced deliberately."""
    alg = kf.ALGORITHMS[name]
    half = alg.field_bytes
    public, _ = make_key(name)
    jwk = dict(public.to_jwk())
    for member in ("x", "y"):
        raw = base64.urlsafe_b64decode(jwk[member] + "=" * (-len(jwk[member]) % 4))
        short = dict(jwk)
        short[member] = base64.urlsafe_b64encode(raw[1:]).rstrip(b"=").decode()
        with pytest.raises(KeyFormatError, match="bytes"):
            kf.jwk_to_public_key(short)
    point = b"\x04" + public.key
    for cut in (1, 1 + half):
        with pytest.raises(KeyFormatError):
            kf.load_spki(
                der_sequence(
                    der_sequence(oid_from_string(alg.oid), oid_from_string(_curve_oid(alg))),
                    der_bit_string(point[:cut] + point[cut + 1 :]),
                )
            )


# ===========================================================================
# 4. RFC 8037 / RFC 8152 — JWK and COSE_Key
# ===========================================================================
JOSE_COSE = _load("jose_cose.json")["records"]


def test_rfc8037_private_jwk_vector() -> None:
    record = next(r for r in JOSE_COSE if r["format"] == "jwk" and r["kind"] == "private")
    key = kf.jwk_to_private_key(record["jwk"])
    assert key.algorithm == "Ed25519"
    assert key.key.hex() == record["d_hex"]
    assert key.public().key.hex() == record["x_hex"], (
        "the JWK's 'x' is not what its 'd' derives to — either the base64url "
        "decode or the Ed25519 public-key derivation is wrong"
    )
    assert key.to_jwk() == record["jwk"]


def test_rfc8037_public_jwk_vector() -> None:
    record = next(r for r in JOSE_COSE if r["format"] == "jwk" and r["kind"] == "public")
    private = next(r for r in JOSE_COSE if r["format"] == "jwk" and r["kind"] == "private")
    key = kf.jwk_to_public_key(record["jwk"])
    # RFC 8037 A.2 is "the public part of the previous private key", so it must
    # be exactly the public half A.1 prints.
    assert key.key.hex() == private["x_hex"]
    assert key.to_jwk() == record["jwk"]


def test_rfc7638_thumbprint_vector() -> None:
    """RFC 8037 A.3, including the exact canonical input it prints.

    A thumbprint is only useful if two implementations agree on it, and the
    thing they have to agree on is the canonicalisation: required members only,
    lexicographic order, no whitespace. Checking the digest alone would let a
    wrong canonical form pass if it happened to hash the same, so the input
    string is asserted too.
    """
    record = next(r for r in JOSE_COSE if r["format"] == "jwk" and r["kind"] == "private")
    expected = bytes.fromhex(record["thumbprint_sha256_hex"])
    assert hashlib.sha256(record["thumbprint_input"].encode()).digest() == expected, (
        "the RFC's own canonical input does not hash to the RFC's own digest — "
        "the vendored vector is corrupt"
    )
    assert kf.jwk_thumbprint(record["jwk"]) == expected
    assert base64.urlsafe_b64encode(expected).rstrip(b"=").decode() == record["thumbprint_b64u"]


def test_thumbprint_ignores_the_private_member() -> None:
    """A key and its public half must have the same thumbprint — that is the point."""
    private = next(r for r in JOSE_COSE if r["format"] == "jwk" and r["kind"] == "private")
    public = next(r for r in JOSE_COSE if r["format"] == "jwk" and r["kind"] == "public")
    assert kf.jwk_thumbprint(private["jwk"]) == kf.jwk_thumbprint(public["jwk"])


@pytest.mark.parametrize(
    "record",
    [r for r in JOSE_COSE if r["format"] == "cose"],
    ids=[r["algorithm"] for r in JOSE_COSE if r["format"] == "cose"],
)
def test_rfc8152_cose_key_vectors(record: dict[str, Any]) -> None:
    """Published COSE_Key maps parse to the right point.

    The P-521 record is the one that matters most: its ``x`` begins with a zero
    octet, and any implementation that routes a coordinate through a big
    integer instead of fixed-width octets silently drops it and produces a
    65-byte value that is a different key.
    """
    labels = {int(k): v for k, v in record["cose_labels"].items()}
    labels[-2] = bytes.fromhex(record["x_hex"])
    labels[-3] = bytes.fromhex(record["y_hex"])
    key = kf.cose_to_public_key(cbor_encode_canonical(labels))
    assert key.algorithm == record["algorithm"]
    assert key.key == labels[-2] + labels[-3]
    assert len(labels[-2]) == kf.ALGORITHMS[record["algorithm"]].field_bytes


def test_cose_key_tolerates_labels_it_does_not_consume() -> None:
    """A COSE_Key is an open map; a ``kid`` must not make it unparseable.

    Real COSE keys carry ``kid`` (2) and ``alg`` (3) — a WebAuthn credential
    public key always carries ``alg``. Rejecting them would refuse most of the
    keys this format exists to read.
    """
    public, _ = make_key("P-256")
    decoded = cbor_decode_canonical(public.to_cose())
    decoded[2] = b"key-identifier"
    decoded[3] = -7  # ES256
    assert kf.cose_to_public_key(cbor_encode_canonical(decoded)) == public


# ===========================================================================
# 5. Self-consistency across every algorithm
# ===========================================================================
@pytest.mark.parametrize("name", ALL_ALGORITHMS)
def test_spki_round_trip(name: str) -> None:
    public, _ = make_key(name)
    assert kf.load_spki(public.to_spki()) == public
    assert kf.load_spki(public.to_pem()) == public


@pytest.mark.parametrize("name", ALL_ALGORITHMS)
@pytest.mark.parametrize("include_public_key", [None, True, False])
def test_pkcs8_round_trip(name: str, include_public_key: bool | None) -> None:
    """Both settings of ``include_public_key`` must work, in both directions.

    A flag whose non-default value is never exercised is a flag that quietly
    stops working.
    """
    _, private = make_key(name)
    encoded = private.to_pkcs8(include_public_key=include_public_key)
    decoded = kf.load_pkcs8(encoded)
    assert decoded.algorithm == name
    assert decoded.key == private.key
    if include_public_key or (include_public_key is None and kf.ALGORITHMS[name].kind == "ec"):
        assert decoded.public_key == private.public_key
    assert kf.load_pkcs8(kf.encode_pem(encoded, "PRIVATE KEY")).key == private.key


@pytest.mark.parametrize("name", CLASSICAL)
def test_jwk_and_cose_round_trip(name: str) -> None:
    public, private = make_key(name)
    assert kf.jwk_to_public_key(public.to_jwk()) == public
    assert kf.jwk_to_public_key(json.dumps(public.to_jwk())) == public
    assert kf.jwk_to_private_key(private.to_jwk()).key == private.key
    assert kf.cose_to_public_key(public.to_cose()) == public
    assert kf.cose_to_private_key(private.to_cose()).key == private.key


@pytest.mark.parametrize("name", CLASSICAL)
def test_cose_encoding_is_deterministic(name: str) -> None:
    """RFC 8949 §4.2.1 ordering, so one key has exactly one encoding.

    Two byte strings that decode to the same key is the same defect class as
    signature malleability, and it breaks anything that identifies a key by the
    hash of its encoding.
    """
    public, _ = make_key(name)
    encoded = public.to_cose()
    assert cbor_encode_canonical(cbor_decode_canonical(encoded)) == encoded
    assert public.to_cose() == encoded


@pytest.mark.parametrize("name", ALL_ALGORITHMS)
def test_derived_public_key_matches_the_generated_one(name: str) -> None:
    """Derivation is real for every algorithm, including the PQ ones.

    An expandedKey-only PQ import has no public key to read, so this path is
    what makes such a file usable at all.
    """
    public, private = make_key(name)
    assert private.derive_public_key() == public
    assert kf.PrivateKey(name, private.key).public() == public


@pytest.mark.parametrize("name", PQ_ALGORITHMS)
def test_pq_seed_form_is_functional_end_to_end(name: str) -> None:
    """A seed-form key must sign or decapsulate, not merely parse.

    The seed arm is the RECOMMENDED storage form, so it has to expand into a
    key that actually works — not into a blob that round-trips.
    """
    alg = kf.ALGORITHMS[name]
    seed = bytes(range(32)) if alg.pq_seed_bytes == 32 else bytes(range(64))
    if alg.pq_family == "ml-dsa":
        public, secret = pb.native_ml_dsa_keypair_from_seed(_param_set(alg), seed)
    else:
        public, secret = pb.native_ml_kem_keypair_from_seed(_param_set(alg), seed[:32], seed[32:])
    private = kf.PrivateKey(name, secret, public, seed)
    encoded = private.to_pkcs8()  # auto -> seed form
    assert len(encoded) < 200, "the seed form should be compact, not expanded"

    reloaded = kf.load_pkcs8(encoded)
    assert reloaded.key == secret
    if alg.pq_family == "ml-dsa":
        signature = pb.native_ml_dsa_sign(_param_set(alg), b"m", reloaded.key)
        assert pb.native_ml_dsa_verify(_param_set(alg), b"m", signature, reloaded.public().key)
    else:
        ciphertext, shared = pb.native_ml_kem_encapsulate(_param_set(alg), reloaded.public().key)
        assert pb.native_ml_kem_decapsulate(_param_set(alg), ciphertext, reloaded.key) == shared


# ===========================================================================
# 6. Public and private material must not share a code path
# ===========================================================================
def test_public_and_private_keys_are_distinct_types() -> None:
    """There is no encoder that decides which kind of key it received.

    The failure that design permits — a private key serialised into the slot
    the caller is about to publish — is silent and unrecoverable, so the type
    system has to prevent it rather than a runtime check.
    """
    assert not issubclass(kf.PrivateKey, kf.PublicKey)
    assert not issubclass(kf.PublicKey, kf.PrivateKey)
    public, private = make_key("Ed25519")
    assert not hasattr(public, "to_pkcs8")
    assert not hasattr(private, "to_spki")
    # Widened deliberately: mypy can prove these two types never compare equal,
    # and that proof is exactly the property under test. The runtime check stays
    # because `__eq__` is dataclass-generated and a future shared base would
    # silently make them comparable again.
    assert public != cast(object, private)


@pytest.mark.parametrize("name", ["Ed25519", "X25519", "P-256"])
def test_a_private_key_cannot_be_encoded_as_a_public_one(name: str) -> None:
    """Separate types are not by themselves a boundary.

    Both classes carry ``.algorithm`` and ``.key``, so a ``PrivateKey``
    duck-types through a public encoder — and for Ed25519 and X25519, where the
    two halves are the same width, it comes out as a well-formed public
    encoding of the *secret seed*. Nothing about the result looks wrong, which
    is exactly why this needs an explicit runtime refusal and a test for it.
    """
    _, private = make_key(name)
    for encode in (kf.public_key_to_jwk, kf.public_key_to_cose, kf._encode_spki):
        with pytest.raises(KeyFormatError, match="expected a PublicKey"):
            encode(private)  # type: ignore[arg-type]  # asserting the runtime guard (KF-004)


def test_a_public_jwk_is_refused_by_the_private_parser_and_vice_versa() -> None:
    public, private = make_key("P-256")
    with pytest.raises(KeyFormatError, match="no private key member"):
        kf.jwk_to_private_key(public.to_jwk())
    with pytest.raises(KeyFormatError, match="private key member"):
        kf.jwk_to_public_key(private.to_jwk())


def test_a_public_cose_key_is_refused_by_the_private_parser_and_vice_versa() -> None:
    public, private = make_key("P-256")
    with pytest.raises(KeyFormatError, match="no private key member"):
        kf.cose_to_private_key(public.to_cose())
    with pytest.raises(KeyFormatError, match="private key member"):
        kf.cose_to_public_key(private.to_cose())


def _public_encodings(public: kf.PublicKey) -> list[tuple[str, bytes]]:
    """Every public form this module can emit for ``public``.

    Built by asking the algorithm what it supports rather than by listing the
    classical ones, so a format gaining PQ support is covered the day it does.
    """
    forms: list[tuple[str, bytes]] = [
        ("spki", public.to_spki()),
        ("pem", public.to_pem().encode()),
    ]
    try:
        forms.append(("jwk", json.dumps(public.to_jwk()).encode()))
        forms.append(("cose", public.to_cose()))
    except UnsupportedKeyFormatError:
        pass  # ML-DSA/ML-KEM have no standardised JWK or COSE encoding
    return forms


@pytest.mark.parametrize("name", ALL_ALGORITHMS)
def test_a_private_key_never_leaks_into_a_public_encoding(name: str) -> None:
    """Belt and braces: no secret octets in any public form, for any algorithm.

    Extended from the classical algorithms to all twelve. The PQ ones are the
    interesting case now that a private key may carry a ``seed``: the seed is a
    *second* piece of secret material with its own field, and it is the one that
    matters most — RFC 9881 §8.1 makes expansion one-way, so 32 leaked octets
    reconstruct the entire 4896-octet ML-DSA-87 key, while the expanded key
    yields nothing about the seed. A leak check that looked only at ``.key``
    would have watched the less valuable of the two.
    """
    _public, private = make_key(name)
    seeded = make_seeded_pq_key(name) if kf.ALGORITHMS[name].kind == "pq" else None

    for key in (private, seeded):
        if key is None:
            continue
        secrets: list[tuple[str, bytes]] = [("key", key.key)]
        if key.seed is not None:
            secrets.append(("seed", key.seed))
        for form, encoded in _public_encodings(key.public()):
            for label, secret in secrets:
                assert secret not in encoded, (
                    f"{name}: private.{label} appears verbatim in the {form} "
                    "encoding of its own public key"
                )


@pytest.mark.parametrize("name", PQ_ALGORITHMS)
def test_a_pq_seed_never_leaks_into_a_public_encoding(name: str) -> None:
    """The seed, specifically, and against a key that definitely has one.

    ``make_key`` goes through randomised keygen, so ``seed`` is ``None`` and the
    check above would pass vacuously for the field that matters. This builds a
    key from a known seed so there is something to look for, and asserts the
    setup rather than assuming it.
    """
    private = make_seeded_pq_key(name)
    assert private.seed is not None and len(private.seed) == kf.ALGORITHMS[name].pq_seed_bytes
    public = private.public()
    for form, encoded in _public_encodings(public):
        assert private.seed not in encoded, f"{name}: the seed leaked into {form}"
    # And it is not merely absent from the public encoding — it is absent from
    # the public *key material*, which is what a caller might copy elsewhere.
    assert private.seed not in public.key


@pytest.mark.parametrize("name", PQ_ALGORITHMS)
def test_the_expanded_private_key_form_does_not_carry_the_seed(name: str) -> None:
    """``pq_format='expandedKey'`` must not smuggle the seed into the output.

    The two arms exist so a caller can choose which secret to write down. A
    caller who asks for the expanded form has decided not to persist the seed —
    RFC 9881 §8.1's one-way property is the whole point — and an encoder that
    included it anyway would silently defeat that choice.
    """
    private = make_seeded_pq_key(name)
    assert private.seed is not None
    expanded = private.to_pkcs8(pq_format="expandedKey")
    assert private.seed not in expanded, f"{name}: the seed leaked into the expanded form"
    reparsed = kf.load_pkcs8(expanded)
    assert reparsed.seed is None, f"{name}: an expandedKey-only file produced a seed"
    assert reparsed.key == private.key


# ===========================================================================
# 7. Negative space — malformed, truncated, mismatched, unsupported
# ===========================================================================
def test_unknown_algorithm_name_is_refused() -> None:
    """INVARIANT-35: a selector must never resolve to a neighbour."""
    for name in ("P256", "p-256", "ed25519", "ML-DSA-45", "", "P-224", "RSA"):
        with pytest.raises(KeyFormatError, match="unknown algorithm"):
            kf.PublicKey(name, b"\x00" * 32)


@pytest.mark.parametrize("name", ALL_ALGORITHMS)
def test_wrong_length_key_material_is_refused(name: str) -> None:
    alg = kf.ALGORITHMS[name]
    for delta in (-1, +1):
        with pytest.raises(KeyFormatError, match="bytes"):
            kf.PublicKey(name, b"\x00" * (alg.public_bytes + delta))
        with pytest.raises(KeyFormatError, match="bytes"):
            kf.PrivateKey(name, b"\x00" * (alg.private_bytes + delta))
    with pytest.raises(KeyFormatError, match="bytes"):
        kf.PublicKey(name, b"")


@pytest.mark.parametrize("name", ALL_ALGORITHMS)
def test_truncated_spki_is_refused(name: str) -> None:
    """Every prefix of a valid encoding must be refused, not partially believed."""
    public, _ = make_key(name)
    der = public.to_spki()
    for cut in (1, 2, 5, len(der) // 2, len(der) - 1):
        with pytest.raises(KeyFormatError):
            kf.load_spki(der[:cut])


@pytest.mark.parametrize("name", ALL_ALGORITHMS)
def test_trailing_data_after_a_key_is_refused(name: str) -> None:
    """A key file with unexplained bytes after it is not a key file.

    Accepting the prefix is how one byte string comes to represent two
    different things to two different parsers.
    """
    public, private = make_key(name)
    with pytest.raises(KeyFormatError):
        kf.load_spki(public.to_spki() + b"\x00")
    with pytest.raises(KeyFormatError):
        kf.load_pkcs8(private.to_pkcs8() + b"\x00")


def test_spki_with_an_unimplemented_algorithm_oid_says_so() -> None:
    """An unimplemented algorithm is distinguishable from a malformed file."""
    # rsaEncryption, 1.2.840.113549.1.1.1 — well-formed, just not implemented.
    der = der_sequence(
        der_sequence(oid_from_string("1.2.840.113549.1.1.1")),
        der_bit_string(b"\x00" * 32),
    )
    with pytest.raises(UnsupportedKeyFormatError, match=r"1\.2\.840\.113549\.1\.1\.1"):
        kf.load_spki(der)


def test_spki_with_an_unimplemented_curve_oid_says_so() -> None:
    # secp224r1, 1.3.132.0.33 — deliberately not implemented.
    der = der_sequence(
        der_sequence(oid_from_string("1.2.840.10045.2.1"), oid_from_string("1.3.132.0.33")),
        der_bit_string(b"\x04" + b"\x00" * 56),
    )
    with pytest.raises(UnsupportedKeyFormatError, match=r"1\.3\.132\.0\.33"):
        kf.load_spki(der)


def test_ec_spki_without_a_named_curve_is_refused() -> None:
    """``id-ecPublicKey`` with absent parameters names no curve at all.

    Guessing one would make the same bytes mean different keys to different
    parsers — and the guess would be P-256, the first entry in the table.
    """
    der = der_sequence(
        der_sequence(oid_from_string("1.2.840.10045.2.1")),
        der_bit_string(b"\x04" + b"\x00" * 64),
    )
    with pytest.raises(KeyFormatError, match="named-curve"):
        kf.load_spki(der)


def test_okp_spki_with_present_parameters_is_refused() -> None:
    """RFC 8410 §3: the parameters field MUST be absent, not NULL.

    Emitting NULL here is a common and quietly non-conformant bug, so the
    parser has to be able to tell the two apart.
    """
    der = der_sequence(
        der_sequence(oid_from_string("1.3.101.112"), b"\x05\x00"),
        der_bit_string(b"\x00" * 32),
    )
    with pytest.raises(KeyFormatError, match="absent parameters"):
        kf.load_spki(der)


@pytest.mark.parametrize("name", EC_ALGORITHMS)
def test_ec_point_not_on_the_curve_is_refused(name: str) -> None:
    """A point that satisfies no curve equation is not a public key.

    Accepting one is the invalid-curve attack: an ECDH peer who supplies a
    point on a weaker curve recovers the private scalar from the results.
    """
    alg = kf.ALGORITHMS[name]
    der = der_sequence(
        der_sequence(oid_from_string(alg.oid), oid_from_string(_curve_oid(alg))),
        der_bit_string(b"\x04" + b"\x01" * (2 * alg.field_bytes)),
    )
    with pytest.raises(KeyFormatError):
        kf.load_spki(der)


@pytest.mark.parametrize("name", EC_ALGORITHMS)
def test_ec_point_at_infinity_is_refused(name: str) -> None:
    """SEC 1 encodes the identity as a single ``0x00``; it is not a public key."""
    alg = kf.ALGORITHMS[name]
    der = der_sequence(
        der_sequence(oid_from_string(alg.oid), oid_from_string(_curve_oid(alg))),
        der_bit_string(b"\x00"),
    )
    with pytest.raises(KeyFormatError):
        kf.load_spki(der)


@pytest.mark.parametrize("name", EC_ALGORITHMS)
def test_ec_coordinate_at_or_above_the_field_prime_is_refused(name: str) -> None:
    """INVARIANT-29: a coordinate must be a canonical field element.

    ``0xFF...FF`` exceeds every one of these primes. Reducing it into range
    instead of refusing would make two encodings name one key.
    """
    alg = kf.ALGORITHMS[name]
    der = der_sequence(
        der_sequence(oid_from_string(alg.oid), oid_from_string(_curve_oid(alg))),
        der_bit_string(b"\x04" + b"\xff" * (2 * alg.field_bytes)),
    )
    with pytest.raises(KeyFormatError):
        kf.load_spki(der)


@pytest.mark.parametrize("name", EC_ALGORITHMS)
def test_ec_key_file_whose_halves_disagree_is_refused(name: str) -> None:
    """A file carrying a private key and a public key for a *different* key.

    Never benign: either corruption, or a file assembled from two keys.
    Importing it produces signatures nobody can verify, and the mismatch is
    invisible until then.
    """
    _, private = make_key(name)
    _, other = make_key(name)
    alg = kf.ALGORITHMS[name]
    inner = der_sequence(
        der_integer(1),
        der_octet_string(private.key),
        der_tagged(1, der_bit_string(b"\x04" + other.public().key)),
    )
    der = der_sequence(
        der_integer(0),
        der_sequence(oid_from_string(alg.oid), oid_from_string(_curve_oid(alg))),
        der_octet_string(inner),
    )
    with pytest.raises(KeyFormatError, match="inconsistent"):
        kf.load_pkcs8(der)


def test_ec_key_naming_two_different_curves_is_refused() -> None:
    """RFC 5915 [0] parameters that disagree with the AlgorithmIdentifier.

    Whichever one a parser believes, the other parser believes the other.
    """
    _, private = make_key("P-256")
    inner = der_sequence(
        der_integer(1),
        der_octet_string(private.key),
        der_tagged(0, oid_from_string("1.3.132.0.34")),  # P-384, not P-256
    )
    der = der_sequence(
        der_integer(0),
        der_sequence(oid_from_string("1.2.840.10045.2.1"), oid_from_string("1.2.840.10045.3.1.7")),
        der_octet_string(inner),
    )
    with pytest.raises(KeyFormatError, match="two different curves"):
        kf.load_pkcs8(der)


def test_ec_private_key_with_the_wrong_version_is_refused() -> None:
    _, private = make_key("P-256")
    inner = der_sequence(der_integer(2), der_octet_string(private.key))
    der = der_sequence(
        der_integer(0),
        der_sequence(oid_from_string("1.2.840.10045.2.1"), oid_from_string("1.2.840.10045.3.1.7")),
        der_octet_string(inner),
    )
    with pytest.raises(KeyFormatError, match="version must be 1"):
        kf.load_pkcs8(der)


def _with_pkcs8_version(der: bytes, value: int) -> bytes:
    """Rewrite the ``version`` INTEGER of a PKCS#8 blob, leaving all else alone.

    ``version`` is the first element of the outer SEQUENCE, always encoded as
    ``02 01 vv``, so the only thing to compute is how long the outer length
    field is.
    """
    length_octet = der[1]
    header = 2 if length_octet < 0x80 else 2 + (length_octet & 0x7F)
    assert der[header : header + 2] == b"\x02\x01", "unexpected PKCS#8 layout"
    out = bytearray(der)
    out[header + 2] = value
    return bytes(out)


@pytest.mark.parametrize("name", ALL_ALGORITHMS)
def test_the_pkcs8_version_must_agree_with_the_publickey_field(name: str) -> None:
    """RFC 5958 §2: v2 if and only if ``publicKey`` is present.

    Found by ``test_every_structural_octet_is_refused_when_corrupted``: flipping
    the version octet from 0 to 1 on a key with no ``[1] publicKey`` was
    accepted, so one key had two valid encodings. That is the malleability
    defect class — the same reason this module refuses non-minimal lengths and
    non-canonical CBOR — reachable by anyone who can hand you a key file.

    Both directions are checked. The EC case is the one worth stating: its
    public half lives inside RFC 5915 ``ECPrivateKey``, which RFC 5958 does not
    see, so the conventional EC encoding correctly stays at v1 *while carrying a
    public key*. A rule written as "carries a public key at all ⇒ v2" would
    reject RFC 9500 §2.3's own keys.
    """
    _, private = make_key(name)
    conventional = private.to_pkcs8()
    assert kf.load_pkcs8(conventional).key == private.key

    # v2 with no outer publicKey — the case that used to be accepted.
    with pytest.raises(KeyFormatError, match=r"no \[1\] publicKey"):
        kf.load_pkcs8(_with_pkcs8_version(conventional, 1))

    if kf.ALGORITHMS[name].kind == "ec":
        # EC has no *outer* publicKey form to build the converse from: RFC 5915
        # puts it inside ECPrivateKey, and `include_public_key=True` is already
        # the conventional setting.
        return
    # The converse: an outer publicKey with the version left at v1.
    with_public = private.to_pkcs8(include_public_key=True)
    assert kf.load_pkcs8(with_public).public_key == private.public().key
    with pytest.raises(KeyFormatError, match="requires v2"):
        kf.load_pkcs8(_with_pkcs8_version(with_public, 0))


def test_pkcs8_with_an_unsupported_version_is_refused() -> None:
    _, private = make_key("Ed25519")
    der = der_sequence(
        der_integer(7),
        der_sequence(oid_from_string("1.3.101.112")),
        der_octet_string(der_octet_string(private.key)),
    )
    with pytest.raises(KeyFormatError, match="version"):
        kf.load_pkcs8(der)


@pytest.mark.parametrize("name", PQ_ALGORITHMS)
def test_pq_private_key_with_an_unrecognised_choice_tag_is_refused(name: str) -> None:
    """RFC 9881 §6 selects the arm by tag; an unknown tag has no arm."""
    alg = kf.ALGORITHMS[name]
    der = der_sequence(
        der_integer(0),
        der_sequence(oid_from_string(alg.oid)),
        der_octet_string(der_integer(1)),  # INTEGER: not seed, expandedKey or both
    )
    with pytest.raises(KeyFormatError, match="CHOICE tag"):
        kf.load_pkcs8(der)


@pytest.mark.parametrize("name", PQ_ALGORITHMS)
def test_pq_seed_of_the_wrong_length_is_refused(name: str) -> None:
    """ML-DSA seeds are 32 octets and ML-KEM's are 64; the other is not a seed."""
    alg = kf.ALGORITHMS[name]
    der = der_sequence(
        der_integer(0),
        der_sequence(oid_from_string(alg.oid)),
        der_octet_string(der_tagged(0, b"\x00" * (alg.pq_seed_bytes // 2), constructed=False)),
    )
    with pytest.raises(KeyFormatError, match="seed must be"):
        kf.load_pkcs8(der)


@pytest.mark.parametrize("name", PQ_ALGORITHMS)
def test_pq_seed_form_cannot_be_emitted_without_a_seed(name: str) -> None:
    """Asking for a form the key cannot produce fails loudly.

    Silently emitting the expanded form instead would be a lie about the format
    the caller asked for, and the caller cannot tell without re-parsing.
    """
    _, private = make_key(name)
    assert private.seed is None
    for arm in ("seed", "both"):
        with pytest.raises(KeyFormatError, match="no seed"):
            private.to_pkcs8(pq_format=arm)
    private.to_pkcs8(pq_format="expandedKey")  # the arm it can produce


def test_unknown_pq_format_is_refused() -> None:
    _, private = make_key("ML-DSA-65")
    with pytest.raises(KeyFormatError, match="unknown pq_format"):
        private.to_pkcs8(pq_format="raw")


def test_a_seed_on_a_non_pq_key_is_refused() -> None:
    """Only ML-DSA and ML-KEM have a seed form; the field is not a free slot."""
    _, private = make_key("Ed25519")
    with pytest.raises(KeyFormatError, match="no seed form"):
        kf.PrivateKey("Ed25519", private.key, private.public_key, b"\x00" * 32)


@pytest.mark.parametrize("name", PQ_ALGORITHMS)
def test_pq_jwk_and_cose_are_refused_with_a_reason(name: str) -> None:
    """No standardised encoding means no invented one.

    A guessed encoding produces keys that interoperate with nothing and that a
    future revision has to break. The refusal names the reason so a caller can
    tell "not yet standardised" from "you passed the wrong thing".
    """
    public, private = make_key(name)
    for call in (
        lambda: kf.public_key_to_jwk(public),
        lambda: kf.private_key_to_jwk(private),
        lambda: kf.public_key_to_cose(public),
        lambda: kf.private_key_to_cose(private),
    ):
        with pytest.raises(UnsupportedKeyFormatError, match="no standardised"):
            call()


# --- JWK negative space -----------------------------------------------------
def test_jwk_with_an_unimplemented_key_type_is_refused() -> None:
    for kty in ("RSA", "oct"):
        with pytest.raises(UnsupportedKeyFormatError, match=kty):
            kf.jwk_to_public_key({"kty": kty, "n": "AQAB", "e": "AQAB"})


def test_jwk_with_a_missing_or_unknown_kty_is_refused() -> None:
    with pytest.raises(KeyFormatError, match="kty"):
        kf.jwk_to_public_key({"crv": "P-256", "x": "AA", "y": "AA"})
    with pytest.raises(KeyFormatError, match="kty"):
        kf.jwk_to_public_key({"kty": "EC2", "crv": "P-256", "x": "AA", "y": "AA"})


def test_jwk_with_an_unimplemented_curve_is_refused() -> None:
    with pytest.raises(UnsupportedKeyFormatError, match="P-224"):
        kf.jwk_to_public_key({"kty": "EC", "crv": "P-224", "x": "AA", "y": "AA"})
    with pytest.raises(UnsupportedKeyFormatError, match="Ed448"):
        kf.jwk_to_public_key({"kty": "OKP", "crv": "Ed448", "x": "AA"})


def test_jwk_missing_a_required_member_is_refused() -> None:
    public, _ = make_key("P-256")
    for member in ("x", "y"):
        jwk = public.to_jwk()
        del jwk[member]
        with pytest.raises(KeyFormatError, match=f"missing required member '{member}'"):
            kf.jwk_to_public_key(jwk)


def test_jwk_coordinate_of_the_wrong_width_is_refused() -> None:
    """RFC 7518 §6.2.1.2: coordinates are fixed-width and zero-padded.

    A short value is a *different*, invalid key — not the same one with the
    leading zero elided. Accepting it makes two JWKs name one key and breaks
    every thumbprint that identifies it.
    """
    public, _ = make_key("P-256")
    jwk = public.to_jwk()
    raw = base64.urlsafe_b64decode(jwk["x"] + "==")
    jwk["x"] = base64.urlsafe_b64encode(raw[1:]).rstrip(b"=").decode()
    with pytest.raises(KeyFormatError, match="must be 32 bytes"):
        kf.jwk_to_public_key(jwk)


def test_jwk_with_padded_or_standard_base64_is_refused() -> None:
    """RFC 7515 §2 is base64url without padding, and only that."""
    public, _ = make_key("P-256")
    for mutate in (lambda v: v + "=", lambda v: v.replace("-", "+").replace("_", "/") + "="):
        jwk = public.to_jwk()
        jwk["x"] = mutate(jwk["x"])
        with pytest.raises(KeyFormatError, match="base64url"):
            kf.jwk_to_public_key(jwk)


def test_jwk_with_a_non_string_member_is_refused() -> None:
    public, _ = make_key("P-256")
    jwk = public.to_jwk()
    jwk["x"] = 12345
    with pytest.raises(KeyFormatError, match="must be a string"):
        kf.jwk_to_public_key(jwk)


def test_jwk_with_an_over_long_integer_literal_is_refused() -> None:
    """A giant integer literal must not escape the KeyFormatError boundary.

    CPython caps integer<->string conversion at ``sys.get_int_max_str_digits()``
    (default 4300) and raises a *bare* ``ValueError`` -- not a
    ``json.JSONDecodeError`` -- while parsing a longer literal, even one in a
    member the JWK never uses. That ValueError is a sibling of, not a subclass
    of, ``KeyFormatError``, so a caller catching the module's documented
    boundary would not have caught it. Both string and bytes entry points must
    convert it to ``KeyFormatError``.
    """
    # The literal lands in json.loads, which every JWK entry point reaches
    # through _load_jwk (a bytes input is UTF-8 decoded to the same string
    # first), so the string form covers all three.
    over_long = "9" * (sys.get_int_max_str_digits() + 1)
    jwk_str = '{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA","spurious":' + over_long + "}"
    with pytest.raises(KeyFormatError):
        kf.jwk_to_public_key(jwk_str)
    with pytest.raises(KeyFormatError):
        kf.jwk_to_private_key(jwk_str)
    with pytest.raises(KeyFormatError):
        kf.jwk_thumbprint(jwk_str)


def test_jwk_that_is_not_an_object_is_refused() -> None:
    for value in ("[]", '"a string"', "42", "null"):
        with pytest.raises(KeyFormatError, match="must be a JSON object"):
            kf.jwk_to_public_key(value)
    with pytest.raises(KeyFormatError, match="invalid JWK JSON"):
        kf.jwk_to_public_key("{not json")


def test_jwk_private_key_whose_halves_disagree_is_refused() -> None:
    _, private = make_key("P-256")
    _, other = make_key("P-256")
    jwk = private.to_jwk()
    jwk["d"] = base64.urlsafe_b64encode(other.key).rstrip(b"=").decode()
    with pytest.raises(KeyFormatError, match="inconsistent"):
        kf.jwk_to_private_key(jwk)


def test_jwk_private_key_of_the_wrong_width_is_refused() -> None:
    _, private = make_key("P-256")
    jwk = private.to_jwk()
    jwk["d"] = base64.urlsafe_b64encode(private.key[:-1]).rstrip(b"=").decode()
    with pytest.raises(KeyFormatError, match="'d' must be 32 bytes"):
        kf.jwk_to_private_key(jwk)


def test_jwk_thumbprint_with_an_unknown_hash_is_refused() -> None:
    public, _ = make_key("P-256")
    with pytest.raises(KeyFormatError, match="unknown hash"):
        kf.jwk_thumbprint(public.to_jwk(), hash_name="not-a-hash")


# --- COSE negative space ----------------------------------------------------
def test_cose_key_that_is_not_a_map_is_refused() -> None:
    for value in ([1, 2, 3], b"bytes", 42):
        with pytest.raises(KeyFormatError, match="must be a CBOR map"):
            kf.cose_to_public_key(cbor_encode_canonical(value))


def test_cose_key_with_an_unimplemented_curve_is_refused() -> None:
    with pytest.raises(UnsupportedKeyFormatError, match="EC2 curve"):
        kf.cose_to_public_key(
            cbor_encode_canonical({1: 2, -1: 99, -2: b"\x00" * 32, -3: b"\x00" * 32})
        )
    with pytest.raises(UnsupportedKeyFormatError, match="OKP curve"):
        kf.cose_to_public_key(cbor_encode_canonical({1: 1, -1: 99, -2: b"\x00" * 32}))


def test_cose_key_with_a_missing_or_unknown_kty_is_refused() -> None:
    with pytest.raises(KeyFormatError, match="kty"):
        kf.cose_to_public_key(cbor_encode_canonical({-1: 1, -2: b"\x00" * 32}))
    with pytest.raises(KeyFormatError, match="kty"):
        kf.cose_to_public_key(cbor_encode_canonical({1: 99, -1: 1, -2: b"\x00" * 32}))


def test_cose_key_with_a_non_bytes_member_is_refused() -> None:
    """A text string where a byte string belongs is a type confusion, not a value."""
    public, _ = make_key("P-256")
    decoded = cbor_decode_canonical(public.to_cose())
    decoded[-2] = "not bytes"
    with pytest.raises(KeyFormatError, match="must be a byte string"):
        kf.cose_to_public_key(cbor_encode_canonical(decoded))


def test_cose_key_missing_a_required_member_is_refused() -> None:
    public, _ = make_key("P-256")
    for label in (-2, -3):
        decoded = cbor_decode_canonical(public.to_cose())
        del decoded[label]
        with pytest.raises(KeyFormatError, match="missing required member"):
            kf.cose_to_public_key(cbor_encode_canonical(decoded))


def test_cose_key_with_a_wrong_width_member_is_refused() -> None:
    public, _ = make_key("P-256")
    decoded = cbor_decode_canonical(public.to_cose())
    decoded[-2] = decoded[-2][:-1]
    with pytest.raises(KeyFormatError, match="must be 32 bytes"):
        kf.cose_to_public_key(cbor_encode_canonical(decoded))


def test_cose_private_key_whose_halves_disagree_is_refused() -> None:
    _, private = make_key("P-256")
    _, other = make_key("P-256")
    decoded = cbor_decode_canonical(private.to_cose())
    decoded[-4] = other.key
    with pytest.raises(KeyFormatError, match="inconsistent"):
        kf.cose_to_private_key(cbor_encode_canonical(decoded))


def test_cose_key_with_a_non_deterministic_encoding_is_refused() -> None:
    """Unsorted map keys are not deterministic CBOR (RFC 8949 §4.2.1).

    Accepting them would mean one key has many encodings, which breaks
    identifying a key by the hash of its COSE form.
    """
    # {-1: 1, 1: 2, ...} written with the map keys out of canonical order.
    unsorted_map = bytes([0xA3, 0x20, 0x01, 0x01, 0x02, 0x21, 0x58, 0x20]) + b"\x00" * 32
    with pytest.raises(Exception) as excinfo:
        kf.cose_to_public_key(unsorted_map)
    assert "order" in str(excinfo.value).lower() or "sort" in str(excinfo.value).lower()


# --- PEM negative space -----------------------------------------------------
def test_pem_with_a_mismatched_label_is_refused() -> None:
    public, _ = make_key("Ed25519")
    with pytest.raises(KeyFormatError, match="expected PEM label"):
        kf.load_pkcs8(kf.encode_pem(public.to_spki(), "PUBLIC KEY"))


def test_pem_with_leading_explanatory_text_is_refused() -> None:
    """RFC 7468 §3 lets a parser accept this; a key loader should not.

    A key file with unexplained bytes around it is one a caller should look at,
    not one this layer should quietly salvage — the salvaged part may not be
    the part they meant.
    """
    public, _ = make_key("Ed25519")
    pem = public.to_pem()
    with pytest.raises(KeyFormatError, match="strict RFC 7468"):
        kf.decode_pem("Subject: someone\n" + pem)
    with pytest.raises(KeyFormatError, match="strict RFC 7468"):
        kf.decode_pem(pem + "-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n")


def test_pem_with_mismatched_begin_and_end_labels_is_refused() -> None:
    public, _ = make_key("Ed25519")
    pem = public.to_pem().replace("END PUBLIC KEY", "END PRIVATE KEY")
    with pytest.raises(KeyFormatError, match="strict RFC 7468"):
        kf.decode_pem(pem)


def test_pem_with_invalid_base64_is_refused() -> None:
    with pytest.raises(KeyFormatError):
        kf.decode_pem("-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----\n")


def test_empty_pem_body_is_refused() -> None:
    with pytest.raises(KeyFormatError, match="empty PEM body"):
        kf.decode_pem("-----BEGIN PUBLIC KEY-----\n\n-----END PUBLIC KEY-----\n")


def test_pem_accepts_crlf_line_endings() -> None:
    """Key files cross platforms; CRLF is not corruption."""
    public, _ = make_key("Ed25519")
    assert kf.load_spki(public.to_pem().replace("\n", "\r\n")) == public


def test_pem_lines_are_64_characters() -> None:
    """RFC 7468 §2 generators MUST wrap at 64; some parsers depend on it."""
    public, _ = make_key("ML-DSA-87")
    body = public.to_pem().split("\n")[1:-2]
    assert all(len(line) == 64 for line in body[:-1]), "PEM body is not wrapped at 64"
    assert 0 < len(body[-1]) <= 64


def test_a_non_bytes_non_string_input_is_refused() -> None:
    for value in (None, 42, ["not", "a", "key"], {"also": "not"}):
        with pytest.raises(KeyFormatError, match="expected bytes or a PEM string"):
            kf.load_spki(value)  # type: ignore[arg-type]  # asserting the runtime guard (KF-004)


def test_bytes_holding_pem_text_are_accepted() -> None:
    """A file read in binary mode is the common case and must work."""
    public, _ = make_key("P-256")
    assert kf.load_spki(public.to_pem().encode("ascii")) == public


# ===========================================================================
# 8. Registry consistency
# ===========================================================================
def test_every_registered_algorithm_has_a_distinct_identifier() -> None:
    """A collision would make two algorithms decode to one.

    EC algorithms share ``id-ecPublicKey`` and are told apart by the curve OID,
    so the two namespaces are checked separately.
    """
    curve_oids = [a.curve_oid for a in kf.ALGORITHMS.values() if a.kind == "ec"]
    assert len(curve_oids) == len(set(curve_oids))
    other_oids = [a.oid for a in kf.ALGORITHMS.values() if a.kind != "ec"]
    assert len(other_oids) == len(set(other_oids))
    for attribute, kinds in (("jwk_crv", {"ec"}), ("okp_crv", {"okp"})):
        values = [getattr(a, attribute) for a in kf.ALGORITHMS.values() if a.kind in kinds]
        assert len(values) == len(set(values))
    for kind in ("ec", "okp"):
        crvs = [a.cose_crv for a in kf.ALGORITHMS.values() if a.kind == kind]
        assert len(crvs) == len(set(crvs))


def test_registry_sizes_agree_with_the_native_backend() -> None:
    """The table is not allowed to drift from the implementation it describes."""
    for name, alg in kf.ALGORITHMS.items():
        if alg.pq_family == "ml-dsa":
            sizes = pb.ML_DSA_SIZES[alg.pq_param_set]
        elif alg.pq_family == "ml-kem":
            sizes = pb.ML_KEM_SIZES[alg.pq_param_set]
        else:
            continue
        assert alg.public_bytes == sizes["public_key"], name
        assert alg.private_bytes == sizes["secret_key"], name


def test_every_exported_name_exists() -> None:
    """``__all__`` must not advertise something that is not there.

    It has been wrong once already — an encoder was listed under a name that
    was never defined.
    """
    missing = [name for name in kf.__all__ if not hasattr(kf, name)]
    assert not missing, f"key_formats.__all__ names non-existent attributes: {missing}"


# ===========================================================================
# 8b. `include_public_key=None` — one parameter, several defaults, stated
# ===========================================================================
# `None` means "the conventional encoding for this algorithm", which is what
# keeps AMA's output byte-identical to the reference encoders. That is worth
# having, but it makes one parameter mean different things depending on
# algorithm, so the resolved answer is a published table rather than something
# a maintainer has to infer from a `kind` lookup three functions away. These
# tests are what stop the table and the encoder from drifting apart.
def test_the_conventional_table_covers_every_algorithm() -> None:
    assert set(kf.CONVENTIONAL_PUBLIC_KEY) == set(kf.ALGORITHMS)


@pytest.mark.parametrize(
    "name,expected",
    [
        # Inside RFC 5915 ECPrivateKey — the form RFC 9500 §2.3's keys use.
        ("P-256", True),
        ("P-384", True),
        ("P-521", True),
        ("secp256k1", True),
        # RFC 8410 §10.3's first example.
        ("Ed25519", False),
        ("X25519", False),
        # RFC 9881 Appendix C.
        ("ML-DSA-44", False),
        ("ML-DSA-65", False),
        ("ML-DSA-87", False),
        # draft-ietf-lamps-kyber-certificates Appendix C.
        ("ML-KEM-512", False),
        ("ML-KEM-768", False),
        ("ML-KEM-1024", False),
    ],
)
def test_the_conventional_answer_is_what_the_documents_say(name: str, expected: bool) -> None:
    """Transcribed from the documents, not from the implementation.

    Written out per algorithm on purpose. Deriving the expectation from
    ``ALGORITHMS[name].kind`` would restate the implementation and pass however
    the implementation changed.
    """
    assert kf.conventional_include_public_key(name) is expected
    assert kf.CONVENTIONAL_PUBLIC_KEY[name] is expected


@pytest.mark.parametrize("name", ALL_ALGORITHMS)
def test_none_encodes_exactly_as_the_conventional_explicit_value(name: str) -> None:
    """``None`` is not a fourth behaviour: it is one of ``True``/``False``.

    Byte equality, not "produces a parseable key" — the whole point of the
    per-algorithm default is that the output matches a reference encoder's.
    """
    _, private = make_key(name)
    conventional = kf.conventional_include_public_key(name)
    assert private.to_pkcs8() == private.to_pkcs8(include_public_key=conventional)
    assert private.to_pkcs8() != private.to_pkcs8(
        include_public_key=not conventional
    ), f"{name}: the two settings produce identical bytes, so the flag does nothing"


@pytest.mark.parametrize("name", ALL_ALGORITHMS)
def test_the_conventional_answer_matches_what_the_encoder_emitted(name: str) -> None:
    """Close the loop: the table has to describe the DER, not just claim to.

    Read the encoded key back and ask whether a public half is present, rather
    than trusting the flag that produced it.
    """
    _, private = make_key(name)
    reparsed = kf.load_pkcs8(private.to_pkcs8())
    carries_public = _pkcs8_carries_a_public_key(private.to_pkcs8(), kf.ALGORITHMS[name])
    assert carries_public is kf.conventional_include_public_key(name)
    assert reparsed.key == private.key


def _pkcs8_carries_a_public_key(der: bytes, alg: Any) -> bool:
    """Whether this PKCS#8 blob actually carries a public key, read from the DER.

    Two places it can live, and they are not interchangeable: RFC 5958's
    ``[1] publicKey`` on the outer SEQUENCE (which raises the version to v2),
    and RFC 5915's ``[1]`` inside ``ECPrivateKey`` (which does not).
    """
    from ama_cryptography._asn1 import DerReader

    outer = DerReader(der)
    seq = outer.read_sequence()
    outer.finish()
    version = seq.read_integer()
    seq.read_sequence()  # AlgorithmIdentifier
    inner = seq.read_octet_string()
    outer_public = False
    while (tag := seq.peek_tag()) is not None:
        if tag in (0xA1, 0x81):
            outer_public = True
        seq.read_tagged(1 if tag in (0xA1, 0x81) else 0, constructed=bool(tag & 0x20))
    seq.finish()
    if outer_public:
        assert version == 1, "an outer [1] publicKey must raise the version to v2"
        return True
    if alg.kind != "ec":
        assert version == 0, "no public key, so the version must stay v1"
        return False
    ec = DerReader(inner).read_sequence()
    ec.read_integer()
    ec.read_octet_string()
    while (tag := ec.peek_tag()) is not None:
        if tag == 0xA1:
            return True
        ec.read_tagged(0)
    return False


def test_an_unknown_algorithm_has_no_conventional_answer() -> None:
    """INVARIANT-35 again: never resolve an unrecognised selector."""
    for name in ("P-224", "ed25519", "", "ML-DSA-45"):
        with pytest.raises(KeyFormatError, match="unknown algorithm"):
            kf.conventional_include_public_key(name)


# ===========================================================================
# 8c. PQ import-consistency policy
# ===========================================================================
# The checks are correct and default to on. They are also *expensive* and sit
# on a parser path, so there is a documented way to turn them off — and every
# claim made about what stays true with them off is tested here, because an
# undocumented or untested escape hatch is worse than none.
def test_the_policy_defaults_to_enabled() -> None:
    assert kf.get_pq_import_consistency() is True


def test_the_policy_context_manager_restores_the_previous_value() -> None:
    assert kf.get_pq_import_consistency() is True
    with kf.pq_import_consistency(False):
        assert kf.get_pq_import_consistency() is False
    assert kf.get_pq_import_consistency() is True
    # …including when the body raises, which is the case a bare setter loses.
    # try/except rather than pytest.raises so the post-exception restoration
    # check is on a control-flow path static analysis can see is reachable —
    # pytest.raises swallows the exception, which CodeQL does not model, and it
    # flagged this assertion (the whole point of the case) as dead code.
    raised = False
    try:
        with kf.pq_import_consistency(False):
            raise RuntimeError("boom")
    except RuntimeError:
        raised = True
    assert raised, "the RuntimeError must propagate out of the context manager"
    assert kf.get_pq_import_consistency() is True


def test_the_environment_variable_is_parsed_strictly(monkeypatch: Any) -> None:
    """A misspelled flag must not silently pick a policy in either direction."""
    for value in ("1", "on", "TRUE", "Yes"):
        monkeypatch.setenv(kf.PQ_CONSISTENCY_ENV, value)
        assert kf._initial_pq_consistency() is True, value
    for value in ("0", "off", "FALSE", "no"):
        monkeypatch.setenv(kf.PQ_CONSISTENCY_ENV, value)
        assert kf._initial_pq_consistency() is False, value
    monkeypatch.delenv(kf.PQ_CONSISTENCY_ENV, raising=False)
    assert kf._initial_pq_consistency() is True
    for value in ("", "maybe", "2", "disabled"):
        monkeypatch.setenv(kf.PQ_CONSISTENCY_ENV, value)
        with pytest.raises(KeyFormatError, match="not a recognised boolean"):
            kf._initial_pq_consistency()


@pytest.mark.parametrize("record", ML_DSA_BAD + ML_KEM_BAD, ids=_ids(ML_DSA_BAD + ML_KEM_BAD))
def test_the_specifications_bad_keys_are_rejected_under_the_default_policy(
    record: dict[str, Any],
) -> None:
    """Restates the corpus gate with the policy named, so that if the default
    ever flips the failure says which decision caused it."""
    assert kf.get_pq_import_consistency() is True
    with pytest.raises(KeyFormatError):
        kf.load_pkcs8(_pem(record))


@pytest.mark.parametrize("name", PQ_ALGORITHMS)
def test_disabling_the_checks_still_imports_a_usable_key(name: str) -> None:
    """The private key must be identical either way — the policy governs
    checking, never decoding."""
    private = make_seeded_pq_key(name)
    for pq_format in ("expandedKey", "both", "seed"):
        encoded = private.to_pkcs8(pq_format=pq_format)
        strict = kf.load_pkcs8(encoded, verify_pq_consistency=True)
        relaxed = kf.load_pkcs8(encoded, verify_pq_consistency=False)
        assert relaxed.key == strict.key == private.key
        assert relaxed.seed == strict.seed
        # And the public key is still recoverable, whether it was carried at
        # import (ML-KEM, from the FIPS 203 §7.1 layout) or derived on first
        # use (ML-DSA).
        assert relaxed.public().key == private.public().key


@pytest.mark.parametrize("name", [n for n in PQ_ALGORITHMS if n.startswith("ML-KEM")])
def test_ml_kem_recovers_its_public_key_without_the_expensive_check(name: str) -> None:
    """FIPS 203 §7.1 embeds ``ek`` verbatim in ``dk``, so the cheap path is not
    a degradation for ML-KEM — the public key is exact, not approximate."""
    _, private = make_key(name)
    encoded = private.to_pkcs8(pq_format="expandedKey")
    relaxed = kf.load_pkcs8(encoded, verify_pq_consistency=False)
    assert relaxed.public_key == private.public_key


@pytest.mark.parametrize("name", [n for n in PQ_ALGORITHMS if n.startswith("ML-DSA")])
def test_ml_dsa_defers_rather_than_skipping_when_the_checks_are_off(name: str) -> None:
    """ML-DSA has no embedded public key, so the cost moves to first use rather
    than disappearing — and the check still runs there."""
    _, private = make_key(name)
    encoded = private.to_pkcs8(pq_format="expandedKey")
    relaxed = kf.load_pkcs8(encoded, verify_pq_consistency=False)
    assert relaxed.public_key is None
    assert relaxed.public().key == private.public().key


def test_a_carried_public_key_is_still_cross_checked_with_the_policy_off() -> None:
    """The free half of the check does not go away.

    A file assembled from two different ML-KEM keys is caught by comparing the
    carried public key with the one embedded in ``dk`` — no expansion, no
    encapsulation, just bytes.
    """
    _, private = make_key("ML-KEM-768")
    _, other = make_key("ML-KEM-768")
    alg = kf.ALGORITHMS["ML-KEM-768"]
    der = der_sequence(
        der_integer(1),
        der_sequence(oid_from_string(alg.oid)),
        der_octet_string(der_octet_string(private.key)),
        der_tagged(1, b"\x00" + other.public().key, constructed=False),
    )
    for policy in (True, False):
        with pytest.raises(KeyFormatError, match="inconsistent"):
            kf.load_pkcs8(der, verify_pq_consistency=policy)


def test_structural_checks_are_unaffected_by_the_policy() -> None:
    """The policy governs cryptographic consistency only. Lengths, the CHOICE
    arm and the DER around them are still refused with it off."""
    alg = kf.ALGORITHMS["ML-DSA-44"]
    too_short = der_sequence(
        der_integer(0),
        der_sequence(oid_from_string(alg.oid)),
        der_octet_string(der_octet_string(b"\x00" * (alg.private_bytes - 1))),
    )
    bad_seed = der_sequence(
        der_integer(0),
        der_sequence(oid_from_string(alg.oid)),
        der_octet_string(der_tagged(0, b"\x00" * 31, constructed=False)),
    )
    bad_arm = der_sequence(
        der_integer(0),
        der_sequence(oid_from_string(alg.oid)),
        der_octet_string(der_tagged(3, b"\x00" * 32, constructed=False)),
    )
    for der in (too_short, bad_seed, bad_arm):
        with pytest.raises(KeyFormatError):
            kf.load_pkcs8(der, verify_pq_consistency=False)


def test_a_both_arm_key_with_a_mismatched_seed_is_caught_only_when_checking() -> None:
    """Names the trade explicitly, in both directions.

    RFC 9881 §8.2 requires this key to be rejected as malformed, so turning the
    policy off is a conformance decision. The test states which behaviour goes
    with which setting rather than only asserting the safe one.
    """
    private = make_seeded_pq_key("ML-DSA-44", 0x10)
    other = make_seeded_pq_key("ML-DSA-44", 0x90)
    assert private.seed is not None and other.seed is not None
    alg = kf.ALGORITHMS["ML-DSA-44"]
    der = der_sequence(
        der_integer(0),
        der_sequence(oid_from_string(alg.oid)),
        der_octet_string(der_sequence(der_octet_string(other.seed), der_octet_string(private.key))),
    )
    with pytest.raises(KeyFormatError, match="does not expand"):
        kf.load_pkcs8(der, verify_pq_consistency=True)
    relaxed = kf.load_pkcs8(der, verify_pq_consistency=False)
    assert relaxed.key == private.key


def test_the_process_wide_policy_is_honoured_by_load_pkcs8() -> None:
    """The per-call argument defaults to the process-wide setting, not to True.

    A deployment that sets the policy once must not find every call site
    quietly overriding it.
    """
    private = make_seeded_pq_key("ML-DSA-44", 0x10)
    other = make_seeded_pq_key("ML-DSA-44", 0x90)
    assert other.seed is not None
    alg = kf.ALGORITHMS["ML-DSA-44"]
    der = der_sequence(
        der_integer(0),
        der_sequence(oid_from_string(alg.oid)),
        der_octet_string(der_sequence(der_octet_string(other.seed), der_octet_string(private.key))),
    )
    with pytest.raises(KeyFormatError):
        kf.load_pkcs8(der)
    with kf.pq_import_consistency(False):
        assert kf.load_pkcs8(der).key == private.key
    with pytest.raises(KeyFormatError):
        kf.load_pkcs8(der)


# ===========================================================================
# 8d. Defects found by fuzz/python/fuzz_key_formats.py
# ===========================================================================
# Each of these was a live parser defect on this branch, found by the harness
# and pinned here so pytest catches a regression without waiting for a fuzz
# campaign to rediscover it. All four are the same shape: an input reaches a
# layer that was not written for it, and the failure escapes as something the
# caller cannot catch, or as a second encoding of one key.
def test_pem_bytes_with_a_non_ascii_octet_raise_keyformaterror() -> None:
    """``_as_der`` decoded PEM-as-bytes with ``"ascii"``/``strict``.

    ``UnicodeDecodeError`` is a ``ValueError``, not a ``KeyFormatError``, so a
    file beginning with a PEM header and containing one non-ASCII octet escaped
    the format layer entirely. ``except KeyFormatError`` at the boundary is
    supposed to be sufficient; here it was not.
    """
    public, _ = make_key("Ed25519")
    good = public.to_pem().encode()
    assert kf.load_spki(good) == public
    for position in (10, len(good) // 2, len(good) - 2):
        corrupted = bytearray(good)
        corrupted[position] = 0xDB
        with pytest.raises(KeyFormatError):
            kf.load_spki(bytes(corrupted))
        with pytest.raises(KeyFormatError):
            kf.load_pkcs8(bytes(corrupted))


def test_a_cose_curve_label_that_is_not_an_integer_is_refused() -> None:
    """``_cose_algorithm`` looked ``crv`` up in a dict without checking its type.

    A COSE_Key is decoded CBOR, so ``crv`` can be a nested map or array — both
    unhashable in Python, so the lookup raised ``TypeError: unhashable type``.
    The JSON side already carried this fix; the CBOR side did not.
    """
    public, _ = make_key("P-256")
    for crv in ({1: 2}, [1, 2], b"P-256", "P-256", True, None):
        decoded = cbor_decode_canonical(public.to_cose())
        decoded[-1] = crv
        with pytest.raises((KeyFormatError, UnsupportedKeyFormatError)):
            kf.cose_to_public_key(cbor_encode_canonical(decoded))


@pytest.mark.parametrize("trailing", ["\x1f", "\x1c", "\x0b", "\x0c", "\x85", "\xa0"])
def test_pem_with_a_unicode_whitespace_suffix_is_refused(trailing: str) -> None:
    """``str.strip()`` is Unicode-aware and RFC 7468 is not.

    Python counts U+001C..U+001F, U+000B, U+000C, U+0085, U+00A0 and several
    Unicode spaces as whitespace. None of them is whitespace in RFC 7468, which
    is defined over printable ASCII plus CR and LF — so a key file with an
    unexplained trailing octet was silently salvaged by a parser whose stated
    position is that it does not salvage such files.
    """
    public, _ = make_key("Ed25519")
    pem = public.to_pem()
    assert kf.load_spki(pem) == public
    with pytest.raises(KeyFormatError, match="RFC 7468"):
        kf.load_spki(pem + trailing)
    with pytest.raises(KeyFormatError, match="RFC 7468"):
        kf.decode_pem(trailing + pem)
    # The characters RFC 7468 *does* allow around a block still work.
    for allowed in (" ", "\t", "\r\n", "\n"):
        assert kf.load_spki(allowed + pem + allowed) == public


@pytest.mark.parametrize("name", EC_ALGORITHMS)
def test_an_out_of_range_ec_scalar_in_a_key_file_raises_keyformaterror(name: str) -> None:
    """A private scalar of zero, or at or above the group order.

    Both are constructible key files, and both made the native derivation
    refuse — correctly — with a ``RuntimeError`` that escaped the format layer.
    ``except KeyFormatError`` around a key import has to be sufficient; here it
    was not. Found by the fuzz harness after 17.8 million executions.
    """
    alg = kf.ALGORITHMS[name]
    width = alg.field_bytes
    for scalar in (b"\x00" * width, b"\xff" * width):
        inner = der_sequence(der_integer(1), der_octet_string(scalar))
        der = der_sequence(
            der_integer(0),
            der_sequence(oid_from_string(alg.oid), oid_from_string(_curve_oid(alg))),
            der_octet_string(inner),
        )
        # No public key carried, so nothing forces a derivation at import…
        imported = kf.load_pkcs8(der)
        assert imported.key == scalar
        # …but asking for one must fail cleanly rather than escaping the layer.
        with pytest.raises(KeyFormatError, match="not usable"):
            imported.public()
        with pytest.raises(KeyFormatError, match="not usable"):
            imported.derive_public_key()

    # And with a public key carried, the cross-check must refuse it at import.
    public, _ = make_key(name)
    inner = der_sequence(
        der_integer(1),
        der_octet_string(b"\x00" * width),
        der_tagged(1, der_bit_string(b"\x04" + public.key)),
    )
    der = der_sequence(
        der_integer(0),
        der_sequence(oid_from_string(alg.oid), oid_from_string(_curve_oid(alg))),
        der_octet_string(inner),
    )
    with pytest.raises(KeyFormatError):
        kf.load_pkcs8(der)


@pytest.mark.parametrize(
    "mangle",
    [
        pytest.param(lambda b: ["", *b], id="blank-line-after-header"),
        pytest.param(lambda b: [*b[:1], "", *b[1:]], id="blank-line-in-the-middle"),
        pytest.param(lambda b: [b[0][:32], b[0][32:], *b[1:]], id="short-first-line"),
        pytest.param(lambda b: ["".join(b)], id="one-long-line"),
    ],
)
def test_pem_lines_must_be_exactly_64_characters(mangle: Any) -> None:
    """RFC 7468 §2: "exactly 64 characters except for the final line".

    Only the *maximum* was checked, so a short line — including an empty one —
    was accepted, and joining the lines discarded it. A blank line after the
    BEGIN header therefore gave one key a second valid encoding: the same
    malleability class as the padding-bit hole, reached a different way. Found
    by the fuzz harness after 18.1 million executions.
    """
    public, _ = make_key("ML-DSA-44")  # long enough to have many body lines
    pem = public.to_pem()
    assert kf.load_spki(pem) == public
    body = [ln for ln in pem.splitlines() if not ln.startswith("-----")]
    assert len(body) > 4 and all(len(ln) == 64 for ln in body[:-1])

    rebuilt = (
        "-----BEGIN PUBLIC KEY-----\n" + "\n".join(mangle(body)) + "\n-----END PUBLIC KEY-----\n"
    )
    with pytest.raises(KeyFormatError, match="RFC 7468"):
        kf.load_spki(rebuilt)


def test_pem_footer_must_start_its_own_line() -> None:
    """RFC 7468 §3: every base64 line, the last one included, ends in an ``eol``.

    The body pattern was ``[A-Za-z0-9+/=\\n]*``, which does not require that
    final newline, so a file whose last base64 line ran straight into the
    footer parsed to a perfectly good key::

        ...DpTAgqnXmlf37FN6D9YW04BLgpdFo7GS-----END PUBLIC KEY-----

    It then re-encoded to different bytes. One key, two textual encodings —
    the malleability class this module refuses in DER lengths, in INTEGERs and
    in CBOR. Found by the fuzz harness.
    """
    public, _ = make_key("P-384")
    pem = public.to_pem()
    assert kf.load_spki(pem) == public

    glued = pem.replace("\n-----END PUBLIC KEY-----", "-----END PUBLIC KEY-----")
    assert glued != pem and "GS" not in glued[:30]  # the mangling landed
    with pytest.raises(KeyFormatError, match="RFC 7468"):
        kf.load_spki(glued)

    # The same hole on a private key, and via the PKCS#8 parser.
    _, private = make_key("P-384")
    priv_pem = private.to_pem()
    glued_priv = priv_pem.replace("\n-----END PRIVATE KEY-----", "-----END PRIVATE KEY-----")
    with pytest.raises(KeyFormatError, match="RFC 7468"):
        kf.load_pkcs8(glued_priv)

    # Non-vacuity: the well-formed form the mangling was derived from still
    # parses, so the test is not merely rejecting a broken fixture.
    assert kf.load_pkcs8(priv_pem).key == private.key


def test_pem_with_non_zero_base64_padding_bits_is_refused() -> None:
    """RFC 4648 §3.5: "the pad bits MUST be set to zero".

    Python's ``b64decode(validate=True)`` checks the alphabet and ignores the
    padding bits, so ``...Of3N=`` and ``...Of3M=`` decoded to the same octets —
    one key with many encodings, the defect this module refuses everywhere
    else. Found by the fuzz harness after 7.5 million executions.
    """
    public, _ = make_key("Ed25519")
    pem = public.to_pem()
    assert kf.load_spki(pem) == public

    body = "".join(line for line in pem.splitlines() if not line.startswith("-----"))
    assert body.endswith("=")
    # The character before the pad carries the significant bits; the rest of its
    # six are padding and must be zero. Flip one of those.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    index = len(body) - 2
    flipped = alphabet[alphabet.index(body[index]) ^ 0b000001]
    mangled = body[:index] + flipped + body[index + 1 :]
    assert base64.b64decode(mangled) == base64.b64decode(
        body
    ), "the two bodies must decode to the same octets, or this tests nothing"
    assert mangled != body

    lines = [mangled[i : i + 64] for i in range(0, len(mangled), 64)]
    rebuilt = "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"
    with pytest.raises(KeyFormatError, match="non-canonical base64"):
        kf.load_spki(rebuilt)
    with pytest.raises(KeyFormatError, match="non-canonical base64"):
        kf.decode_pem(rebuilt)


def test_an_okp_cose_key_carrying_the_ec2_y_member_is_refused() -> None:
    """A COSE_Key is an open map, but ``y`` (-3) is not an unknown label.

    RFC 9053 §7 assigns ``y`` to the EC2 key type only. An OKP key carrying one
    does not have "a label we do not use", it contradicts its own ``kty`` — and
    accepting it gave one X25519 key two encodings, while inviting a reader that
    keys off ``-3`` to see an EC2 key where AMA sees an OKP one.
    """
    public, _ = make_key("X25519")
    decoded = cbor_decode_canonical(public.to_cose())
    assert -3 not in decoded
    decoded[-3] = b"\x00" * 32
    with pytest.raises(KeyFormatError, match="contradicts its own"):
        kf.cose_to_public_key(cbor_encode_canonical(decoded))
    # Labels that really are unknown must still be tolerated — a WebAuthn
    # credential public key always carries `alg`.
    tolerated = cbor_decode_canonical(public.to_cose())
    tolerated[2] = b"key-identifier"
    tolerated[3] = -8
    assert kf.cose_to_public_key(cbor_encode_canonical(tolerated)) == public


# ===========================================================================
# 9. Mutation robustness
# ===========================================================================
# A key parser is fed hostile input by definition — anyone who can hand you a
# key file reaches it. The hand-written negative cases above cover the failures
# that were thought of; this covers the ones that were not.
#
# The contract asserted is narrow and total: for *any* input, the parser either
# returns a key that survives its own validation, or raises KeyFormatError. It
# must never leak a backend exception through the format layer, never raise
# something a caller cannot reasonably catch, and never return a key whose
# re-encoding disagrees with itself. Leaking a raw ValueError from the native
# point decoder was a real defect found exactly this way.
#
# Deterministic by construction: a fixed seed, so a failure reproduces from the
# test name alone rather than only on the run that found it.
_MUTATION_SEED = 0x9881_C4


def _mutations(data: bytes, count: int) -> list[bytes]:
    """Deterministic single-edit mutations: flip, truncate, extend, splice."""
    import random

    # The suppression below must sit on the offending line, and black reflows
    # a wrapped call out from under a trailing comment. Keep this one line.
    seed = _MUTATION_SEED ^ len(data)
    rng = random.Random(seed)  # noqa: S311 -- deterministic test input, not key material (KF-006)
    out = []
    for _ in range(count):
        buf = bytearray(data)
        choice = rng.randrange(4)
        if choice == 0:
            buf[rng.randrange(len(buf))] ^= 1 << rng.randrange(8)
        elif choice == 1:
            del buf[rng.randrange(len(buf)) :]
        elif choice == 2:
            buf.extend(bytes([rng.randrange(256) for _ in range(rng.randrange(1, 8))]))
        else:
            i = rng.randrange(len(buf))
            buf[i] = rng.randrange(256)
        out.append(bytes(buf))
    return out


def _key_material_window(
    name: str, which: str, public: kf.PublicKey, private: kf.PrivateKey, encoded: bytes
) -> range:
    """The byte range of ``encoded`` that holds key material rather than structure.

    Everything outside it is tag, length, version, OID or the SEC 1 prefix — the
    *structure* the parser is supposed to be strict about. Located by searching
    for the material rather than by a hand-written offset table, so it stays
    correct as encodings change.
    """
    alg = kf.ALGORITHMS[name]
    if which == "spki":
        material = (b"\x04" + public.key) if alg.kind == "ec" else public.key
    else:
        material = private.key
    offset = encoded.find(material)
    assert offset >= 0, f"{name}/{which}: could not locate the key material"
    return range(offset, offset + len(material))


# Algorithms whose *every* mutation must be refused, and why it is structural
# rather than a lucky observation: an EC public key is validated for curve
# membership on import (INVARIANT-29), and a random perturbation of a valid
# point is on the curve with probability about 2**-|field|. Any mutation either
# breaks the DER or moves the point off the curve, so the count is exactly zero
# and is asserted as exactly zero — a weaker bound would not notice the
# invalid-curve gate being removed.
_MUTATION_TOTAL_REFUSAL = set(EC_ALGORITHMS)


@pytest.mark.parametrize("name", ALL_ALGORITHMS)
@pytest.mark.parametrize("which", ["spki", "pkcs8"])
def test_mutated_der_is_refused_cleanly(name: str, which: str) -> None:
    """A mutated key file yields a valid key or a KeyFormatError — never anything
    else — and what "valid" is allowed to mean is pinned four ways.

    The original form of this test ended at ``assert accepted < 120``, which
    only fails if the parser accepts *almost everything*. A parser that accepted
    every mutation but one would have passed it. What follows are the properties
    that actually characterise a strict parser, each one falsifiable:

    1. **No length-changing input is ever accepted.** Truncation must fail the
       DER length, and extension must fail the no-trailing-data rule. This is
       what makes "the encoding ends where it says it ends" a tested property
       rather than a claim in a docstring.
    2. **Canonicality.** Every accepted input must re-encode to *itself*, byte
       for byte. This is the property the module docstring is about: "a
       permissive parser means two byte strings decode to the same key, which is
       the same defect class as signature malleability". Two encodings of one
       key is precisely a violation of this, and nothing else in the suite would
       catch it.
    3. **Localisation.** An accepted mutation must differ from the original only
       inside the key-material window — every tag, length, version and OID octet
       must be byte-identical — *unless* it parsed as a different algorithm,
       which is the one legitimate way a structural edit can succeed (see
       ``test_an_oid_edit_that_names_another_algorithm_is_accepted_as_that_one``).
    4. **Exact counts where they are structural.** For the EC curves the answer
       is zero, and zero is asserted.
    """
    public, private = make_key(name)
    original = public.to_spki() if which == "spki" else private.to_pkcs8()
    load = kf.load_spki if which == "spki" else kf.load_pkcs8
    window = _key_material_window(name, which, public, private, original)

    accepted = 0
    for mutated in _mutations(original, 120):
        if mutated == original:
            continue
        try:
            key = load(mutated)
        except KeyFormatError:
            continue
        except Exception as exc:
            pytest.fail(
                f"{name}/{which}: a mutated key file raised "
                f"{type(exc).__name__} instead of KeyFormatError: {exc}"
            )
        accepted += 1
        reencoded = _reencode(key, which)

        # (1) length
        assert len(mutated) == len(original), (
            f"{name}/{which}: a {'truncated' if len(mutated) < len(original) else 'extended'} "
            "encoding was accepted — the DER length or the no-trailing-data rule is not enforced"
        )
        # (2) canonicality — the accepted bytes are the only encoding of this key
        assert reencoded == mutated, (
            f"{name}/{which}: an accepted encoding does not re-encode to itself, so "
            "two distinct byte strings decode to one key — the malleability defect class"
        )
        assert load(reencoded) == key
        # (3) localisation
        outside = [i for i in range(len(original)) if mutated[i] != original[i] and i not in window]
        if outside:
            assert key.algorithm != name, (
                f"{name}/{which}: structural octets {outside} were changed and the "
                f"result still parsed as {name} — tag, length, version and OID "
                "corruption must be refused"
            )

    # (4) exact count where it is structurally determined
    if name in _MUTATION_TOTAL_REFUSAL:
        assert accepted == 0, (
            f"{name}/{which}: {accepted} mutation(s) were accepted. Every EC public "
            "key is checked for curve membership on import, and a perturbed point is "
            "on the curve with negligible probability — a non-zero count here means "
            "that validation is no longer running"
        )
    else:
        # For the OKP and PQ algorithms, acceptance is expected: every 32-octet
        # string is a valid Ed25519/X25519 public key, every ML-DSA public key
        # is a valid packing, and the ML-DSA `K` and ML-KEM `z` fields are
        # semantically free. So the interesting bound is the other one — the
        # parser must reject *something*, and specifically it must reject every
        # length change, which is at least half of what `_mutations` produces.
        assert accepted < 120, f"{name}/{which}: every mutation was accepted"


@pytest.mark.parametrize("name", ALL_ALGORITHMS)
@pytest.mark.parametrize("which", ["spki", "pkcs8"])
def test_every_structural_octet_is_refused_when_corrupted(name: str, which: str) -> None:
    """The converse of the sweep, done exhaustively rather than by sampling.

    Every byte outside the key-material window is structure: an ASN.1 tag, a
    length, the PKCS#8 version, an algorithm or curve OID, the SEC 1 prefix, the
    BIT STRING unused-bits octet. Each one is corrupted with four different
    values and the result must be refused — or, in the single legitimate case,
    must announce that it is now a *different algorithm*.

    Sampling 120 random mutations does not establish this: with a 1500-octet
    ML-DSA key file, the ~20 structural octets are hit a handful of times at
    most, so a whole class of corruption could go unexercised for years.
    """
    public, private = make_key(name)
    original = public.to_spki() if which == "spki" else private.to_pkcs8()
    load = kf.load_spki if which == "spki" else kf.load_pkcs8
    window = _key_material_window(name, which, public, private, original)

    structural = [i for i in range(len(original)) if i not in window]
    assert structural, f"{name}/{which}: no structural octets — the window is wrong"

    reclassified: set[str] = set()
    for index in structural:
        for replacement in (0x00, 0xFF, original[index] ^ 0x01, original[index] ^ 0x80):
            if replacement == original[index]:
                continue
            corrupted = bytearray(original)
            corrupted[index] = replacement
            try:
                key = load(bytes(corrupted))
            except KeyFormatError:
                continue
            except Exception as exc:
                pytest.fail(
                    f"{name}/{which}: corrupting structural octet {index} to "
                    f"0x{replacement:02X} raised {type(exc).__name__} instead of "
                    f"KeyFormatError: {exc}"
                )
            # Accepted. The only defensible reason is that the octet was part of
            # an algorithm OID and now names a different algorithm this library
            # also implements — the encoding says what it is, and the parser
            # believed it. Anything else is structural corruption slipping past.
            assert key.algorithm != name, (
                f"{name}/{which}: structural octet {index} changed to "
                f"0x{replacement:02X} and the file still parsed as {name}"
            )
            assert _reencode(key, which) == bytes(
                corrupted
            ), f"{name}/{which}: reclassified key does not re-encode to its own bytes"
            reclassified.add(key.algorithm)

    # Ed25519 and X25519 differ in a single OID octet and share a key width, so
    # that pair is the only substitution that can legitimately turn one valid
    # file into another. (These four probe values do not happen to produce it —
    # 0x70 and 0x6E differ in two bits —
    # ``test_an_oid_edit_that_names_another_algorithm_is_accepted_as_that_one``
    # exercises it directly. The bound is written as a permitted *set* rather
    # than a count so it stays honest either way.)
    twin = {"Ed25519": {"X25519"}, "X25519": {"Ed25519"}}.get(name, set())
    assert reclassified <= twin, (
        f"{name}/{which}: a structural edit produced a valid {sorted(reclassified - twin)} "
        "key. Only the Ed25519/X25519 OID pair should be reachable that way"
    )


def test_an_oid_edit_that_names_another_algorithm_is_accepted_as_that_one() -> None:
    """The one structural edit that legitimately survives, made explicit.

    ``id-Ed25519`` is ``1.3.101.112`` and ``id-X25519`` is ``1.3.101.110``: one
    octet apart, and both keys are 32 octets. So flipping that octet in an
    Ed25519 SPKI produces a *well-formed X25519 SPKI*, and refusing it would be
    wrong — the encoding names the algorithm, and this one names X25519.

    Written out rather than left as a hole in the sweep above, because "the
    parser accepted a file with a corrupted OID" is exactly the sentence that
    should require a stated reason.
    """
    public, _ = make_key("Ed25519")
    ed_spki = public.to_spki()
    x_spki = kf.PublicKey("X25519", public.key).to_spki()

    assert len(ed_spki) == len(x_spki), "the two SPKIs should be the same length"
    differing = [i for i in range(len(ed_spki)) if ed_spki[i] != x_spki[i]]
    # Both encodings open with the fixed DER prefix 30 2A 30 05 06 03 2B 65 xx,
    # so the final OID arc (112 vs 110) sits at index 8.
    assert differing == [8], (
        "the Ed25519 and X25519 SPKI encodings should differ in exactly the final "
        f"OID octet at index 8; they differ at {differing}"
    )
    assert (ed_spki[8], x_spki[8]) == (0x70, 0x6E)
    assert kf.load_spki(x_spki).algorithm == "X25519"
    assert kf.load_spki(ed_spki).algorithm == "Ed25519"
    assert kf.load_spki(x_spki).key == public.key


@pytest.mark.parametrize("name", PQ_ALGORITHMS)
def test_pq_choice_arm_tags_are_the_only_ones_accepted(name: str) -> None:
    """RFC 9881 §6 selects the private-key arm by tag — ``0x80``, ``0x04``,
    ``0x30`` — "rather than any other heuristic like length". Every other tag
    must be refused, including the ones that are valid ASN.1 in their own right.
    """
    alg = kf.ALGORITHMS[name]
    private = make_seeded_pq_key(name)
    assert private.seed is not None
    bodies = {
        0x80: der_tagged(0, private.seed, constructed=False),
        0x04: der_octet_string(private.key),
        0x30: der_sequence(der_octet_string(private.seed), der_octet_string(private.key)),
    }
    for tag, body in bodies.items():
        der = der_sequence(
            der_integer(0), der_sequence(oid_from_string(alg.oid)), der_octet_string(body)
        )
        assert kf.load_pkcs8(der).key == private.key, f"{name}: arm 0x{tag:02X} rejected"
        # The same body under a different tag must not be salvaged by length.
        for other in (0x81, 0x82, 0x05, 0x0C, 0x31, 0xA0):
            mangled = bytearray(body)
            mangled[0] = other
            bad = der_sequence(
                der_integer(0),
                der_sequence(oid_from_string(alg.oid)),
                der_octet_string(bytes(mangled)),
            )
            with pytest.raises(KeyFormatError):
                kf.load_pkcs8(bad)


@pytest.mark.parametrize("name", ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
def test_an_out_of_range_encapsulation_key_coefficient_is_refused(name: str) -> None:
    """FIPS 203 §7.2's modulus check, at the import boundary.

    ``ek = ByteEncode_12(t_hat) || rho``; §7.2 requires every 12-bit coefficient
    to be below ``q = 3329``. 767 of every 4096 encodable values are not, so a
    single flipped bit in a real key has roughly a one-in-five chance of
    producing one. A conformant peer refuses such a key, so encapsulating to it
    derives a shared secret nobody else derives — and because ML-KEM's implicit
    rejection is designed to fail silently, nothing anywhere reports it. Import
    is the only place it is visible.

    This is the check the mutation sweep above found missing.
    """
    public, _ = make_key(name)
    # 0xFFF is the largest 12-bit value and is far above q. The first coefficient
    # occupies the low 12 bits of octets 0..1.
    body = bytearray(public.key)
    body[0] = 0xFF
    body[1] |= 0x0F
    assert not pb.native_ml_kem_pubkey_check(_param_set(kf.ALGORITHMS[name]), bytes(body))

    alg = kf.ALGORITHMS[name]
    spki = der_sequence(der_sequence(oid_from_string(alg.oid)), der_bit_string(bytes(body)))
    with pytest.raises(KeyFormatError, match="modulus check"):
        kf.load_spki(spki)
    # …and the honest key still passes, so the check is not simply refusing
    # everything.
    assert pb.native_ml_kem_pubkey_check(_param_set(alg), public.key)
    assert kf.load_spki(public.to_spki()) == public


@pytest.mark.parametrize("name", ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
def test_encapsulation_refuses_an_out_of_range_key(name: str) -> None:
    """§7.2 places the modulus check *before* encapsulation, not on the caller.

    A library that validates on import but not in ``Encaps`` protects only the
    callers who went through its own parser.
    """
    public, _ = make_key(name)
    ps = _param_set(kf.ALGORITHMS[name])
    body = bytearray(public.key)
    body[0] = 0xFF
    body[1] |= 0x0F
    with pytest.raises(RuntimeError):
        pb.native_ml_kem_encapsulate(ps, bytes(body))
    # The unmodified key encapsulates and decapsulates as usual.
    ciphertext, shared = pb.native_ml_kem_encapsulate(ps, public.key)
    assert len(shared) == 32 and len(ciphertext) > 0


@pytest.mark.parametrize("which", ["jwk", "cose"])
def test_mutated_jwk_and_cose_are_refused_cleanly(which: str) -> None:
    """The same total contract for the JSON and CBOR paths.

    CBOR decoding is where a parser is most likely to raise something
    structural — an IndexError off the end of a truncated buffer, a
    UnicodeDecodeError on a mangled text string — rather than a domain error.
    """
    public, _ = make_key("P-256")
    if which == "cose":
        original = public.to_cose()
        inputs = _mutations(original, 200)
        load: Any = kf.cose_to_public_key
    else:
        original = json.dumps(public.to_jwk()).encode()
        inputs = _mutations(original, 200)

        def load(raw: bytes) -> kf.PublicKey:
            return kf.jwk_to_public_key(raw.decode("utf-8", "replace"))

    for mutated in inputs:
        if mutated == original:
            continue
        try:
            load(mutated)
        except (KeyFormatError, UnsupportedKeyFormatError):
            continue
        except Exception as exc:
            pytest.fail(
                f"{which}: mutated input raised {type(exc).__name__} instead of "
                f"KeyFormatError: {exc!r}"
            )


# ---------------------------------------------------------------------------
# OID codec symmetry
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "dotted",
    [
        "0.0",
        "1.2",
        "1.2.840.113549.1.1.1",
        "2.16.840.1.101.3.4.2.1",
        "2.48",  # the first value whose subidentifier needs two octets
        "2.175",
        "2.999.1",  # the experimental arc
        "1.3.6.1.4.1.4294967295",  # a 32-bit arc
    ],
)
def test_the_oid_codec_round_trips(dotted: str) -> None:
    """``oid_from_string`` must be able to re-encode everything
    ``oid_to_string`` decodes.

    It could not: the first *subidentifier* (``40*arc1 + arc2``) was written as
    a single octet, so every OID with ``arc1 == 2`` and ``arc2 >= 176`` — the
    whole ``2.999.*`` experimental arc — raised a bare
    ``ValueError: byte must be in range(0, 256)``, outside the module's stated
    ``KeyFormatError`` contract, from a function in ``__all__``.
    """
    encoded = oid_from_string(dotted)
    assert encoded[0] == 0x06
    assert oid_to_string(encoded[2:]) == dotted


@pytest.mark.parametrize(
    "dotted",
    ["", "1", "3.0", "0.40", "1.40", "1.-2", "1.2.x", "2." + "9" * 400],
)
def test_a_malformed_oid_string_raises_key_format_error(dotted: str) -> None:
    """Every rejection surfaces as KeyFormatError — including the oversized
    one, which the encoder now bounds the same way the decoder does."""
    with pytest.raises(KeyFormatError):
        oid_from_string(dotted)


@pytest.mark.parametrize(
    ("dotted", "why"),
    [
        ("1.02.840.113549", "leading zero"),
        ("1.2.840.0113549", "leading zero, deeper arc"),
        (" 1.2.840.113549", "leading whitespace"),
        ("1.2.840.113549 ", "trailing whitespace"),
        ("1.2.840.113549\n", "trailing newline"),
        ("1.\t2.840.113549", "interior whitespace"),
        ("+1.2.840.113549", "explicit plus sign"),
        ("1.+2.840.113549", "explicit plus sign, deeper arc"),
        ("1.2.840.113_549", "PEP 515 underscore separator"),
        ("1.٢.840.113549", "non-ASCII decimal digit"),
        ("1..2", "empty arc"),
        (".1.2", "empty leading arc"),
        ("1.2.", "empty trailing arc"),
    ],
)
def test_a_non_canonical_oid_spelling_is_refused(dotted: str, why: str) -> None:
    """One OID, one dotted string. ``int()`` did not agree.

    Every spelling here encoded to *the same* OBJECT IDENTIFIER as
    ``"1.2.840.113549"``, because ``int()`` is a lenient parser: it accepts
    surrounding whitespace, a leading ``+``, redundant leading zeros, any
    Unicode decimal digit, and — since PEP 515 — underscore separators. That is
    exactly the many-spellings-of-one-value defect this module refuses on the
    octet side (non-minimal DER lengths, non-minimal INTEGERs, non-deterministic
    CBOR), reached through the text side instead.

    The shape it invites is a policy bypass rather than a cosmetic one: an
    allowlist keyed on the dotted string reads ``"1.2.840.113_549"`` as a
    different entry from ``"1.2.840.113549"`` while the encoder maps both onto
    the same octets — so the comparison and the encoding disagree, and the
    encoding is what ends up signed.
    """
    with pytest.raises(KeyFormatError, match="non-canonical arc"):
        oid_from_string(dotted)


def test_the_oid_codec_is_a_bijection_over_the_reachable_space() -> None:
    """Decode-then-encode and encode-then-decode are both the identity.

    Asserted over the boundaries rather than a handful of literals: the three
    legal values of ``arc1``, the ``arc2`` values either side of every encoding
    step (39/40, 47/48, 175/176), and tails that cross the base-128 boundaries.
    """
    checked = 0
    for arc1 in (0, 1, 2):
        for arc2 in (0, 1, 39, 40, 47, 48, 175, 176, 999, 4000):
            if arc1 < 2 and arc2 >= 40:
                continue  # not a legal OID; refused by the leading-arc check
            for tail in ([], [0], [1], [127], [128], [16383], [16384], [1, 0, 113549]):
                dotted = ".".join(str(a) for a in [arc1, arc2, *tail])
                encoded = oid_from_string(dotted)
                assert oid_to_string(encoded[2:]) == dotted, dotted
                assert oid_from_string(oid_to_string(encoded[2:])) == encoded, dotted
                checked += 1
    assert checked > 100, "the sweep stopped covering the boundary cases"


# ---------------------------------------------------------------------------
# CBOR nesting
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("array chain", b"\x81" * 10000 + b"\x00"),
        ("map chain", b"\xa1\x01" * 5000 + b"\x00"),
        ("array then map", b"\x81" * 500 + b"\xa1\x01" * 500 + b"\x00"),
    ],
    # Explicit ids. pytest derives an id from the parameter value otherwise, and
    # these values are 10 kB of repeated escapes — which lands in the node id,
    # which lands in `PYTEST_CURRENT_TEST`, which Windows refuses above 32,767
    # characters. The tests passed; the *teardown* raised.
    ids=["array-chain", "map-chain", "array-then-map"],
)
def test_deeply_nested_cbor_raises_key_format_error(label: str, payload: bytes) -> None:
    """``RecursionError`` is not in this module's contract.

    ``0x81`` (array of one) buys an attacker a stack frame per input octet, so
    a few hundred octets of COSE_Key drove the interpreter off its recursion
    limit — past the ``KeyFormatError`` boundary ``cose_to_public_key`` and
    ``cose_to_private_key`` promise, and on a small thread stack past the
    interpreter entirely.

    The repository's splice-based fuzzer cannot reach this shape: it mutates a
    seed corpus of *key encodings*, and no key encoding contains a thousand
    nested arrays. So it gets an explicit test rather than being left to a
    generator that structurally cannot generate it.
    """
    with pytest.raises(KeyFormatError):
        cbor_decode_canonical(payload)
    with pytest.raises(KeyFormatError):
        kf.cose_to_public_key(payload)


def test_a_flat_cose_key_still_decodes() -> None:
    """Non-vacuity: the depth limit must not reject the shape it exists for."""
    _pub, priv = pb.native_nistp_keypair("P-256")
    key = kf.PublicKey("P-256", pb.native_nistp_pubkey_from_privkey("P-256", priv))
    assert kf.cose_to_public_key(key.to_cose()).key == key.key
