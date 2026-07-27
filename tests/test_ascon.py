#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Tests for the Ascon Python surface (``ama_cryptography.ascon``).

The C suite (``tests/c/test_ascon.c``) is the authority on algorithm
correctness: it sweeps the full vendored KAT corpus and checks the permutation
against the values SP 800-232 publishes.  These tests sweep the same corpus
through the Python boundary — a marshalling bug that truncated a buffer or
dropped the associated data would pass the C tests and fail here — and then
pin the surface's own contracts: fail-closed decryption, input validation, and
the round-trip and forgery properties under Hypothesis.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ama_cryptography.ascon import (
    AEAD128_KEY_BYTES,
    AEAD128_NONCE_BYTES,
    AEAD128_TAG_BYTES,
    ASCON_AVAILABLE,
    HASH256_DIGEST_BYTES,
    AsconVerificationError,
    aead128_decrypt,
    aead128_encrypt,
    generate_key,
    generate_nonce,
    hash256,
)

pytestmark = pytest.mark.skipif(
    not ASCON_AVAILABLE,
    reason="native Ascon implementation not built",
)

REPO_ROOT = Path(__file__).resolve().parent.parent
KAT_DIR = REPO_ROOT / "tests" / "kat" / "ascon"


def _parse_kat(path: Path) -> list[dict[str, str]]:
    """Parse the LWC KAT format into a list of records.

    Splitting on the first ``=`` and stripping keeps empty fields (``PT = ``)
    as empty strings rather than losing them, which is the parser bug that
    makes every empty-input vector silently reuse the previous record.
    """
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            if current:
                records.append(current)
                current = {}
            continue
        key, _, value = raw.partition("=")
        current[key.strip()] = value.strip()
    if current:
        records.append(current)
    return records


# --------------------------------------------------------------------------
# Known-answer vectors through the Python boundary
# --------------------------------------------------------------------------


def test_hash256_known_answer_vectors() -> None:
    records = _parse_kat(KAT_DIR / "ascon_hash256.kat")
    assert len(records) >= 1025, f"only {len(records)} hash vectors parsed"
    for record in records:
        message = bytes.fromhex(record["Msg"])
        expected = bytes.fromhex(record["MD"])
        assert hash256(message) == expected, f"vector {record['Count']}"


def test_aead128_known_answer_vectors() -> None:
    records = _parse_kat(KAT_DIR / "ascon_aead128.kat")
    assert len(records) >= 1089, f"only {len(records)} AEAD vectors parsed"
    for record in records:
        key = bytes.fromhex(record["Key"])
        nonce = bytes.fromhex(record["Nonce"])
        plaintext = bytes.fromhex(record["PT"])
        aad = bytes.fromhex(record["AD"])
        expected = bytes.fromhex(record["CT"])

        ciphertext, tag = aead128_encrypt(key, nonce, plaintext, aad)
        assert ciphertext + tag == expected, f"vector {record['Count']}"
        assert aead128_decrypt(key, nonce, ciphertext, tag, aad) == plaintext


# --------------------------------------------------------------------------
# Surface contracts
# --------------------------------------------------------------------------


def test_round_trip_across_lengths() -> None:
    key, nonce = generate_key(), generate_nonce()
    # Cover the rate boundaries in both directions: 0, sub-rate, exact rate,
    # rate+1, and multi-block.
    for length in (0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 64, 100):
        plaintext = os.urandom(length)
        aad = os.urandom((length * 3) % 40)
        ciphertext, tag = aead128_encrypt(key, nonce, plaintext, aad)
        assert len(ciphertext) == length
        assert len(tag) == AEAD128_TAG_BYTES
        assert aead128_decrypt(key, nonce, ciphertext, tag, aad) == plaintext


def test_every_tag_bit_flip_is_rejected() -> None:
    key, nonce = generate_key(), generate_nonce()
    plaintext, aad = b"authenticated payload", b"header"
    ciphertext, tag = aead128_encrypt(key, nonce, plaintext, aad)

    for byte in range(AEAD128_TAG_BYTES):
        for bit in range(8):
            forged = bytearray(tag)
            forged[byte] ^= 1 << bit
            with pytest.raises(AsconVerificationError):
                aead128_decrypt(key, nonce, ciphertext, bytes(forged), aad)


def test_ciphertext_and_aad_tampering_are_rejected() -> None:
    key, nonce = generate_key(), generate_nonce()
    plaintext, aad = b"authenticated payload", b"header"
    ciphertext, tag = aead128_encrypt(key, nonce, plaintext, aad)

    tampered_ct = bytearray(ciphertext)
    tampered_ct[0] ^= 0x01
    with pytest.raises(AsconVerificationError):
        aead128_decrypt(key, nonce, bytes(tampered_ct), tag, aad)

    with pytest.raises(AsconVerificationError):
        aead128_decrypt(key, nonce, ciphertext, tag, aad + b"x")

    # Dropping the AD entirely must also fail — this is the case controlled by
    # the |A| > 0 guard in the absorb phase.
    with pytest.raises(AsconVerificationError):
        aead128_decrypt(key, nonce, ciphertext, tag, b"")


def test_wrong_key_or_nonce_is_rejected() -> None:
    key, nonce = generate_key(), generate_nonce()
    ciphertext, tag = aead128_encrypt(key, nonce, b"payload")

    other_key = bytes(k ^ 0x80 for k in key)
    with pytest.raises(AsconVerificationError):
        aead128_decrypt(other_key, nonce, ciphertext, tag)

    other_nonce = bytes(n ^ 0x01 for n in nonce)
    with pytest.raises(AsconVerificationError):
        aead128_decrypt(key, other_nonce, ciphertext, tag)


def test_empty_message_vectors() -> None:
    """Vector 1 of each corpus, pinned inline as a smoke test."""
    key = bytes(range(16))
    nonce = bytes(range(0x10, 0x20))
    _, tag = aead128_encrypt(key, nonce, b"", b"")
    assert tag.hex().upper() == "4F9C278211BEC9316BF68F46EE8B2EC6"
    assert hash256(b"").hex().upper() == (
        "0B3BE5850F2F6B98CAF29F8FDEA89B64A1FA70AA249B8F839BD53BAA304D92B2"
    )


def test_digest_and_key_sizes() -> None:
    assert len(hash256(b"x")) == HASH256_DIGEST_BYTES
    assert len(generate_key()) == AEAD128_KEY_BYTES
    assert len(generate_nonce()) == AEAD128_NONCE_BYTES
    # Two calls must not return the same nonce; a generator that did would
    # violate the one discipline this AEAD depends on.
    assert generate_nonce() != generate_nonce()


@pytest.mark.parametrize(
    ("key_len", "nonce_len", "tag_len"),
    [(15, 16, 16), (17, 16, 16), (16, 15, 16), (16, 17, 16), (16, 16, 15)],
)
def test_wrong_sized_arguments_are_refused(key_len: int, nonce_len: int, tag_len: int) -> None:
    """A mis-sized key must raise, not be silently padded or truncated."""
    with pytest.raises(ValueError):
        aead128_decrypt(
            b"\x00" * key_len,
            b"\x00" * nonce_len,
            b"ciphertext",
            b"\x00" * tag_len,
        )


@pytest.mark.parametrize("bad", ["string", 42, None, ["list"]])
def test_non_bytes_arguments_are_refused(bad: object) -> None:
    with pytest.raises(TypeError):
        hash256(bad)  # type: ignore[arg-type]


def test_bytearray_and_memoryview_accepted() -> None:
    key, nonce = generate_key(), generate_nonce()
    payload = b"buffer protocol"
    reference, tag = aead128_encrypt(key, nonce, payload)
    for variant in (bytearray(payload), memoryview(payload)):
        ciphertext, variant_tag = aead128_encrypt(key, nonce, variant)
        assert ciphertext == reference
        assert variant_tag == tag


def test_hash_is_deterministic_and_sensitive() -> None:
    assert hash256(b"abc") == hash256(b"abc")
    assert hash256(b"abc") != hash256(b"abd")
    # Single-bit sensitivity.
    assert hash256(bytes([0x00])) != hash256(bytes([0x01]))


def test_nonce_reuse_leaks_the_first_rate_block() -> None:
    """Pin the documented weakness, and its exact extent.

    Ascon-AEAD128 has no nonce-misuse resistance, but the leak is not a
    stream cipher's.  Because the sponge absorbs the plaintext into the rate
    before permuting, only the **first 16-byte block** XORs to the plaintext
    XOR; from block two onward the two states have already diverged, so the
    keystreams differ.

    Both halves are asserted.  The first is the weakness callers must design
    around; the second is why "Ascon nonce reuse is the same as ChaCha20 nonce
    reuse" is wrong, and pinning it stops that shorthand from creeping into
    the documentation.
    """
    key, nonce = generate_key(), generate_nonce()
    p1 = bytes(range(32))
    p2 = bytes(255 - i for i in range(32))
    c1, _ = aead128_encrypt(key, nonce, p1)
    c2, _ = aead128_encrypt(key, nonce, p2)

    rate = 16
    assert bytes(a ^ b for a, b in zip(c1[:rate], c2[:rate])) == bytes(
        a ^ b for a, b in zip(p1[:rate], p2[:rate])
    ), "first rate block should leak the plaintext XOR"
    assert bytes(a ^ b for a, b in zip(c1[rate:], c2[rate:])) != bytes(
        a ^ b for a, b in zip(p1[rate:], p2[rate:])
    ), "blocks after the first must not leak the plaintext XOR"


# --------------------------------------------------------------------------
# Property-based
# --------------------------------------------------------------------------

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402


@given(
    plaintext=st.binary(max_size=200),
    aad=st.binary(max_size=200),
    key=st.binary(min_size=16, max_size=16),
    nonce=st.binary(min_size=16, max_size=16),
)
@settings(max_examples=200, deadline=None)
def test_property_round_trip(plaintext: bytes, aad: bytes, key: bytes, nonce: bytes) -> None:
    ciphertext, tag = aead128_encrypt(key, nonce, plaintext, aad)
    assert len(ciphertext) == len(plaintext)
    assert aead128_decrypt(key, nonce, ciphertext, tag, aad) == plaintext


@given(
    plaintext=st.binary(min_size=1, max_size=200),
    aad=st.binary(max_size=64),
    key=st.binary(min_size=16, max_size=16),
    nonce=st.binary(min_size=16, max_size=16),
    index=st.integers(min_value=0, max_value=199),
    mask=st.integers(min_value=1, max_value=255),
)
@settings(max_examples=200, deadline=None)
def test_property_ciphertext_tampering_always_rejected(
    plaintext: bytes,
    aad: bytes,
    key: bytes,
    nonce: bytes,
    index: int,
    mask: int,
) -> None:
    ciphertext, tag = aead128_encrypt(key, nonce, plaintext, aad)
    position = index % len(ciphertext)
    tampered = bytearray(ciphertext)
    tampered[position] ^= mask
    with pytest.raises(AsconVerificationError):
        aead128_decrypt(key, nonce, bytes(tampered), tag, aad)


@given(message=st.binary(max_size=400))
@settings(max_examples=200, deadline=None)
def test_property_hash_length_and_determinism(message: bytes) -> None:
    digest = hash256(message)
    assert len(digest) == HASH256_DIGEST_BYTES
    assert digest == hash256(message)


@given(a=st.binary(max_size=128), b=st.binary(max_size=128))
@settings(max_examples=200, deadline=None)
def test_property_hash_is_injective_on_samples(a: bytes, b: bytes) -> None:
    """Distinct inputs must give distinct digests.

    This is a collision search with a tiny budget, not a proof — but a
    padding or length-encoding bug produces collisions that a 200-example
    sweep finds immediately (for instance, if the rate-64 padding were
    dropped, b"" and b"\\x01" would collide).
    """
    if a != b:
        assert hash256(a) != hash256(b)
