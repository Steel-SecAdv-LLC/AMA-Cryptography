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
``tests/kat/keyformats/openssl/``             EC and OKP PKCS#8/SPKI produced
                                              by a second implementation, for
                                              which no RFC publishes examples
============================================  ===============================

Every one of those is checked **both ways**: the vendored bytes must parse to
the right key, and re-encoding that key must reproduce the vendored bytes
exactly. One direction alone would miss a decoder and encoder that are wrong in
the same way.

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
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import ama_cryptography.key_formats as kf  # noqa: E402 -- import follows the repo-root sys.path insert above (KF-003)
import ama_cryptography.pqc_backends as pb  # noqa: E402 -- same (KF-003)
from ama_cryptography._asn1 import (  # noqa: E402 -- same (KF-003)
    cbor_decode_canonical,
    cbor_encode_canonical,
    der_bit_string,
    der_integer,
    der_octet_string,
    der_sequence,
    der_tagged,
    oid_from_string,
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
    return json.loads(path.read_text())


def _pem(record: dict[str, Any]) -> str:
    return kf.encode_pem(base64.b64decode(record["pem_b64"]), record["label"])


def _der(record: dict[str, Any]) -> bytes:
    return base64.b64decode(record["pem_b64"])


def _pq_records(name: str, kind: str, label: str) -> list[dict[str, Any]]:
    return [
        r for r in _load(name)["records"]
        if r["kind"] == kind and r["label"] == label
    ]


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
        public, secret = pb.native_nistp_keypair(alg.curve)
    elif alg.pq_family == "ml-dsa":
        public, secret = pb.native_ml_dsa_keypair(alg.pq_param_set)
    else:
        public, secret = pb.native_ml_kem_keypair(alg.pq_param_set)
    return kf.PublicKey(name, public), kf.PrivateKey(name, secret, public)


# ===========================================================================
# 1. The specifications' answer keys — ML-DSA and ML-KEM
# ===========================================================================
@pytest.mark.parametrize("record", ML_DSA_VALID_PRIV + ML_KEM_VALID_PRIV,
                         ids=_ids(ML_DSA_VALID_PRIV + ML_KEM_VALID_PRIV))
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


@pytest.mark.parametrize("record", ML_DSA_VALID_PRIV + ML_KEM_VALID_PRIV,
                         ids=_ids(ML_DSA_VALID_PRIV + ML_KEM_VALID_PRIV))
def test_pq_private_key_vectors_reencode_exactly(record: dict[str, Any]) -> None:
    """Re-encoding a published key reproduces its bytes.

    This is the direction that catches an encoder which is wrong in the same
    way as the decoder — the failure a self-round-trip cannot see.
    """
    key = kf.load_pkcs8(_pem(record))
    assert key.to_pkcs8(pq_format=record["arm"]) == _der(record)


@pytest.mark.parametrize("record", ML_DSA_VALID_PRIV + ML_KEM_VALID_PRIV,
                         ids=_ids(ML_DSA_VALID_PRIV + ML_KEM_VALID_PRIV))
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


@pytest.mark.parametrize("record", ML_DSA_VALID_PUB + ML_KEM_VALID_PUB,
                         ids=[r["section"][:20] + str(i)
                              for i, r in enumerate(ML_DSA_VALID_PUB + ML_KEM_VALID_PUB)])
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


@pytest.mark.parametrize("record", ML_DSA_BAD + ML_KEM_BAD,
                         ids=[f"bad{i}" for i in range(len(ML_DSA_BAD + ML_KEM_BAD))])
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
# 3. A second implementation — EC and OKP, where no RFC publishes examples
# ===========================================================================
OPENSSL_DIR = CORPUS / "openssl"
OPENSSL_ALGORITHMS = sorted(p.name[: -len(".key.pem")] for p in OPENSSL_DIR.glob("*.key.pem"))


def test_openssl_corpus_covers_every_classical_algorithm() -> None:
    """A curve silently missing from the corpus would go unchecked."""
    assert OPENSSL_ALGORITHMS == CLASSICAL, (
        f"the independent-implementation corpus covers {OPENSSL_ALGORITHMS}, "
        f"but this library implements {CLASSICAL}"
    )


@pytest.mark.parametrize("name", OPENSSL_ALGORITHMS)
def test_independent_implementation_keys_parse_and_reencode(name: str) -> None:
    """Bytes from another implementation parse, and AMA reproduces them exactly.

    RFC 5915 and RFC 5480 publish no worked examples, so for the EC curves this
    is the only evidence that AMA's DER is what the ecosystem actually emits —
    the right OID, the named-curve parameter present, the ``ECPrivateKey``
    version, the SEC 1 prefix, and the ``[1] publicKey`` where OpenSSL puts it.
    """
    private_pem = (OPENSSL_DIR / f"{name}.key.pem").read_text()
    public_pem = (OPENSSL_DIR / f"{name}.pub.pem").read_text()

    private = kf.load_pkcs8(private_pem)
    public = kf.load_spki(public_pem)
    assert private.algorithm == name
    assert public.algorithm == name
    assert private.public().key == public.key, (
        "the public key derived from the imported secret disagrees with the "
        "one the same implementation published for it"
    )
    assert private.to_pem().strip() == private_pem.strip()
    assert public.to_pem().strip() == public_pem.strip()


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
    "record", [r for r in JOSE_COSE if r["format"] == "cose"],
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
    if include_public_key or (include_public_key is None
                              and kf.ALGORITHMS[name].kind == "ec"):
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
        public, secret = pb.native_ml_dsa_keypair_from_seed(alg.pq_param_set, seed)
    else:
        public, secret = pb.native_ml_kem_keypair_from_seed(
            alg.pq_param_set, seed[:32], seed[32:]
        )
    private = kf.PrivateKey(name, secret, public, seed)
    encoded = private.to_pkcs8()  # auto -> seed form
    assert len(encoded) < 200, "the seed form should be compact, not expanded"

    reloaded = kf.load_pkcs8(encoded)
    assert reloaded.key == secret
    if alg.pq_family == "ml-dsa":
        signature = pb.native_ml_dsa_sign(alg.pq_param_set, b"m", reloaded.key)
        assert pb.native_ml_dsa_verify(alg.pq_param_set, b"m", signature,
                                       reloaded.public().key)
    else:
        ciphertext, shared = pb.native_ml_kem_encapsulate(
            alg.pq_param_set, reloaded.public().key
        )
        assert pb.native_ml_kem_decapsulate(
            alg.pq_param_set, ciphertext, reloaded.key
        ) == shared


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
    assert public != private


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
            encode(private)  # type: ignore[arg-type] -- asserting the runtime guard (KF-004)


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


def test_a_private_key_never_leaks_into_a_public_encoding() -> None:
    """Belt and braces: the secret octets must not appear in any public form."""
    for name in CLASSICAL:
        public, private = make_key(name)
        for encoded in (public.to_spki(), public.to_cose(),
                        public.to_pem().encode(), json.dumps(public.to_jwk()).encode()):
            assert private.key not in encoded, f"{name}: secret found in a public encoding"


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
        der_sequence(oid_from_string(alg.oid), oid_from_string(alg.curve_oid)),
        der_bit_string(b"\x04" + b"\x01" * (2 * alg.field_bytes)),
    )
    with pytest.raises(KeyFormatError):
        kf.load_spki(der)


@pytest.mark.parametrize("name", EC_ALGORITHMS)
def test_ec_point_at_infinity_is_refused(name: str) -> None:
    """SEC 1 encodes the identity as a single ``0x00``; it is not a public key."""
    alg = kf.ALGORITHMS[name]
    der = der_sequence(
        der_sequence(oid_from_string(alg.oid), oid_from_string(alg.curve_oid)),
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
        der_sequence(oid_from_string(alg.oid), oid_from_string(alg.curve_oid)),
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
        der_tagged(1, der_bit_string(b"\x04" + other.public_key)),
    )
    der = der_sequence(
        der_integer(0),
        der_sequence(oid_from_string(alg.oid), oid_from_string(alg.curve_oid)),
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
        der_sequence(oid_from_string("1.2.840.10045.2.1"),
                     oid_from_string("1.2.840.10045.3.1.7")),
        der_octet_string(inner),
    )
    with pytest.raises(KeyFormatError, match="two different curves"):
        kf.load_pkcs8(der)


def test_ec_private_key_with_the_wrong_version_is_refused() -> None:
    _, private = make_key("P-256")
    inner = der_sequence(der_integer(2), der_octet_string(private.key))
    der = der_sequence(
        der_integer(0),
        der_sequence(oid_from_string("1.2.840.10045.2.1"),
                     oid_from_string("1.2.840.10045.3.1.7")),
        der_octet_string(inner),
    )
    with pytest.raises(KeyFormatError, match="version must be 1"):
        kf.load_pkcs8(der)


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
        der_octet_string(der_tagged(0, b"\x00" * (alg.pq_seed_bytes // 2),
                                    constructed=False)),
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
    for call in (lambda: kf.public_key_to_jwk(public),
                 lambda: kf.private_key_to_jwk(private),
                 lambda: kf.public_key_to_cose(public),
                 lambda: kf.private_key_to_cose(private)):
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
        kf.cose_to_public_key(cbor_encode_canonical({1: 2, -1: 99, -2: b"\x00" * 32,
                                                     -3: b"\x00" * 32}))
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
            kf.load_spki(value)  # type: ignore[arg-type] -- asserting the runtime guard (KF-004)


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

    rng = random.Random(_MUTATION_SEED ^ len(data))  # noqa: S311 -- deterministic test-input generation, not key material (KF-006)
    out = []
    for _ in range(count):
        buf = bytearray(data)
        choice = rng.randrange(4)
        if choice == 0:
            buf[rng.randrange(len(buf))] ^= 1 << rng.randrange(8)
        elif choice == 1:
            del buf[rng.randrange(len(buf)):]
        elif choice == 2:
            buf.extend(bytes([rng.randrange(256) for _ in range(rng.randrange(1, 8))]))
        else:
            i = rng.randrange(len(buf))
            buf[i] = rng.randrange(256)
        out.append(bytes(buf))
    return out


@pytest.mark.parametrize("name", ["Ed25519", "P-256", "P-521", "ML-DSA-44", "ML-KEM-512"])
@pytest.mark.parametrize("which", ["spki", "pkcs8"])
def test_mutated_der_is_refused_cleanly(name: str, which: str) -> None:
    """A mutated key file yields a valid key or a KeyFormatError — never anything else."""
    public, private = make_key(name)
    original = public.to_spki() if which == "spki" else private.to_pkcs8()
    load = kf.load_spki if which == "spki" else kf.load_pkcs8

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
        # If it was accepted, it must be a coherent key: re-encoding it and
        # parsing that back has to land in the same place.
        accepted += 1
        assert load(key.to_spki() if which == "spki" else key.to_pkcs8()) == key
    # A mutation that lands in a semantically free field (an ML-DSA K, an
    # ML-KEM z) legitimately parses, so acceptance is not itself a failure —
    # but a parser that accepted *everything* would pass the loop above
    # vacuously, and that is worth knowing.
    assert accepted < 120, f"{name}/{which}: every mutation was accepted"


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
