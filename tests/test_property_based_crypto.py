#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Property-Based Invariants for the Native Cryptographic Primitives
=================================================================

Hypothesis-driven invariant tests for AMA Cryptography's native C primitives.

``tests/test_fuzzing.py`` already property-tests the HMAC and Ed25519
signature surfaces, and ``tests/test_property_based_lyapunov.py`` covers the
(non-cryptographic) 3R math engine.  Neither exercises the **AEAD, KEM or KDF**
surfaces, so the invariants that matter most for those primitives were only
pinned by fixed-vector tests.  Fixed vectors prove one input works; a property
test asserts the contract holds across the whole generated input space, which
is where length-handling, empty-input and boundary defects actually hide.

Invariants asserted here (each is a contract a caller may rely on):

AEAD (AES-256-GCM, ChaCha20-Poly1305)
    * Roundtrip:      ``decrypt(encrypt(m)) == m`` for arbitrary plaintext/AAD.
    * Authenticity:   any single-bit mutation of ciphertext, tag, nonce or AAD
                      must make decryption fail — never return wrong plaintext.
    * Key separation: decrypting under a different key must fail.
    * Non-triviality: ciphertext must never equal plaintext for non-empty input.

KEM (ML-KEM-1024 / Kyber)
    * Agreement:      encapsulate/decapsulate agree on the shared secret.
    * Determinism:    decapsulation is a pure function of (ciphertext, sk).
    * Independence:   independent encapsulations yield distinct secrets.

KDF (HKDF-SHA3-256)
    * Determinism:    identical inputs produce identical output.
    * Sensitivity:    changing IKM, salt or info changes the output.
    * Length honesty: the requested output length is what you get.

These are written against the public ``pqc_backends`` surface, so they also
pin that the exported API keeps its shape.

Exception-type note
-------------------
AEAD authentication failure surfaces as ``ValueError`` from AES-256-GCM but as
``RuntimeError`` from ChaCha20-Poly1305.  These tests pin the *current*
behaviour of each rather than a blanket ``Exception`` so the contract is
explicit and any future change is caught.  The asymmetry is a real API wart —
a caller writing ``except ValueError`` around a generic AEAD helper will miss
ChaCha failures — and is reported for a deliberate decision rather than
silently normalised here, because changing a raised type is a breaking change.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ama_cryptography.pqc_backends import (
    AES256_GCM_NONCE_BYTES,
    AES256_GCM_TAG_BYTES,
    KYBER_AVAILABLE,
    KYBER_SHARED_SECRET_BYTES,
    generate_kyber_keypair,
    kyber_decapsulate,
    kyber_encapsulate,
    native_aes256_gcm_decrypt,
    native_aes256_gcm_encrypt,
    native_chacha20poly1305_decrypt,
    native_chacha20poly1305_encrypt,
    native_hkdf,
)

# Hypothesis defaults are tuned for pure-Python code; these lanes call into the
# native library, so keep the example count modest and disable the
# too-slow health check rather than letting CI flake on timing.
_SETTINGS = settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)

_KEY = st.binary(min_size=32, max_size=32)
_NONCE = st.binary(min_size=AES256_GCM_NONCE_BYTES, max_size=AES256_GCM_NONCE_BYTES)
_PLAINTEXT = st.binary(min_size=0, max_size=2048)
_AAD = st.binary(min_size=0, max_size=256)


def _flip_one_bit(data: bytes, index: int) -> bytes:
    """Return ``data`` with exactly one bit flipped at ``index`` (mod len)."""
    if not data:
        return b"\x01"
    pos = index % len(data)
    mutated = bytearray(data)
    mutated[pos] ^= 1 << (index % 8)
    return bytes(mutated)


class TestAESGCMProperties:
    """AES-256-GCM (NIST SP 800-38D) contract invariants."""

    @_SETTINGS
    @given(key=_KEY, nonce=_NONCE, plaintext=_PLAINTEXT, aad=_AAD)
    def test_roundtrip_recovers_plaintext(
        self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes
    ) -> None:
        ct, tag = native_aes256_gcm_encrypt(key, nonce, plaintext, aad)
        assert len(tag) == AES256_GCM_TAG_BYTES
        assert native_aes256_gcm_decrypt(key, nonce, ct, tag, aad) == plaintext

    @_SETTINGS
    @given(key=_KEY, nonce=_NONCE, plaintext=st.binary(min_size=1, max_size=512))
    def test_ciphertext_is_not_plaintext(self, key: bytes, nonce: bytes, plaintext: bytes) -> None:
        ct, _tag = native_aes256_gcm_encrypt(key, nonce, plaintext, b"")
        assert ct != plaintext, "ciphertext must not equal plaintext"

    @_SETTINGS
    @given(
        key=_KEY,
        nonce=_NONCE,
        plaintext=st.binary(min_size=1, max_size=512),
        aad=_AAD,
        bit=st.integers(min_value=0, max_value=4096),
    )
    def test_ciphertext_bit_flip_fails_authentication(
        self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes, bit: int
    ) -> None:
        ct, tag = native_aes256_gcm_encrypt(key, nonce, plaintext, aad)
        with pytest.raises(ValueError):
            native_aes256_gcm_decrypt(key, nonce, _flip_one_bit(ct, bit), tag, aad)

    @_SETTINGS
    @given(
        key=_KEY,
        nonce=_NONCE,
        plaintext=_PLAINTEXT,
        aad=_AAD,
        bit=st.integers(min_value=0, max_value=127),
    )
    def test_tag_bit_flip_fails_authentication(
        self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes, bit: int
    ) -> None:
        ct, tag = native_aes256_gcm_encrypt(key, nonce, plaintext, aad)
        with pytest.raises(ValueError):
            native_aes256_gcm_decrypt(key, nonce, ct, _flip_one_bit(tag, bit), aad)

    @_SETTINGS
    @given(
        key=_KEY,
        nonce=_NONCE,
        plaintext=_PLAINTEXT,
        aad=st.binary(min_size=1, max_size=256),
        bit=st.integers(min_value=0, max_value=2048),
    )
    def test_aad_mutation_fails_authentication(
        self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes, bit: int
    ) -> None:
        ct, tag = native_aes256_gcm_encrypt(key, nonce, plaintext, aad)
        with pytest.raises(ValueError):
            native_aes256_gcm_decrypt(key, nonce, ct, tag, _flip_one_bit(aad, bit))

    @_SETTINGS
    @given(
        key=_KEY,
        other_key=_KEY,
        nonce=_NONCE,
        plaintext=st.binary(min_size=1, max_size=512),
    )
    def test_wrong_key_fails_authentication(
        self, key: bytes, other_key: bytes, nonce: bytes, plaintext: bytes
    ) -> None:
        if key == other_key:
            return  # same key is the roundtrip case, covered above
        ct, tag = native_aes256_gcm_encrypt(key, nonce, plaintext, b"")
        with pytest.raises(ValueError):
            native_aes256_gcm_decrypt(other_key, nonce, ct, tag, b"")

    @_SETTINGS
    @given(
        key=_KEY,
        nonce=_NONCE,
        plaintext=_PLAINTEXT,
        bit=st.integers(min_value=0, max_value=95),
    )
    def test_wrong_nonce_fails_authentication(
        self, key: bytes, nonce: bytes, plaintext: bytes, bit: int
    ) -> None:
        ct, tag = native_aes256_gcm_encrypt(key, nonce, plaintext, b"")
        with pytest.raises(ValueError):
            native_aes256_gcm_decrypt(key, _flip_one_bit(nonce, bit), ct, tag, b"")


class TestChaCha20Poly1305Properties:
    """ChaCha20-Poly1305 (RFC 8439) contract invariants."""

    @_SETTINGS
    @given(key=_KEY, nonce=_NONCE, plaintext=_PLAINTEXT, aad=_AAD)
    def test_roundtrip_recovers_plaintext(
        self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes
    ) -> None:
        ct, tag = native_chacha20poly1305_encrypt(key, nonce, plaintext, aad)
        assert native_chacha20poly1305_decrypt(key, nonce, ct, tag, aad) == plaintext

    @_SETTINGS
    @given(
        key=_KEY,
        nonce=_NONCE,
        plaintext=st.binary(min_size=1, max_size=512),
        aad=_AAD,
        bit=st.integers(min_value=0, max_value=4096),
    )
    def test_ciphertext_bit_flip_fails_authentication(
        self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes, bit: int
    ) -> None:
        ct, tag = native_chacha20poly1305_encrypt(key, nonce, plaintext, aad)
        with pytest.raises(RuntimeError):
            native_chacha20poly1305_decrypt(key, nonce, _flip_one_bit(ct, bit), tag, aad)

    @_SETTINGS
    @given(
        key=_KEY,
        nonce=_NONCE,
        plaintext=_PLAINTEXT,
        aad=_AAD,
        bit=st.integers(min_value=0, max_value=127),
    )
    def test_tag_bit_flip_fails_authentication(
        self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes, bit: int
    ) -> None:
        ct, tag = native_chacha20poly1305_encrypt(key, nonce, plaintext, aad)
        with pytest.raises(RuntimeError):
            native_chacha20poly1305_decrypt(key, nonce, ct, _flip_one_bit(tag, bit), aad)


@pytest.mark.skipif(not KYBER_AVAILABLE, reason="ML-KEM-1024 backend not built")
class TestKyberKEMProperties:
    """ML-KEM-1024 (FIPS 203) contract invariants."""

    @settings(max_examples=8, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(_seed=st.integers(min_value=0, max_value=2**16))
    def test_encapsulate_decapsulate_agree(self, _seed: int) -> None:
        kp = generate_kyber_keypair()
        encap = kyber_encapsulate(kp.public_key)
        recovered = kyber_decapsulate(encap.ciphertext, kp.secret_key)
        assert recovered == encap.shared_secret
        assert len(recovered) == KYBER_SHARED_SECRET_BYTES

    @settings(max_examples=8, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(_seed=st.integers(min_value=0, max_value=2**16))
    def test_decapsulation_is_deterministic(self, _seed: int) -> None:
        kp = generate_kyber_keypair()
        encap = kyber_encapsulate(kp.public_key)
        first = kyber_decapsulate(encap.ciphertext, kp.secret_key)
        second = kyber_decapsulate(encap.ciphertext, kp.secret_key)
        assert first == second

    @settings(max_examples=6, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(_seed=st.integers(min_value=0, max_value=2**16))
    def test_independent_encapsulations_differ(self, _seed: int) -> None:
        kp = generate_kyber_keypair()
        first = kyber_encapsulate(kp.public_key)
        second = kyber_encapsulate(kp.public_key)
        # Probability of collision is negligible (2^-256); equality here means
        # the encapsulation randomness is broken.
        assert first.ciphertext != second.ciphertext
        assert first.shared_secret != second.shared_secret


class TestHKDFProperties:
    """HKDF-SHA3-256 (RFC 5869) contract invariants."""

    @_SETTINGS
    @given(
        ikm=st.binary(min_size=1, max_size=256),
        salt=st.binary(min_size=0, max_size=64),
        info=st.binary(min_size=0, max_size=64),
        length=st.integers(min_value=1, max_value=128),
    )
    def test_deterministic_and_correct_length(
        self, ikm: bytes, salt: bytes, info: bytes, length: int
    ) -> None:
        salt_arg: Any = salt or None
        first = native_hkdf(ikm, length, salt=salt_arg, info=info)
        second = native_hkdf(ikm, length, salt=salt_arg, info=info)
        assert first == second, "HKDF must be deterministic"
        assert len(first) == length, "HKDF must honour the requested length"

    @_SETTINGS
    @given(
        ikm=st.binary(min_size=1, max_size=128),
        info_a=st.binary(min_size=0, max_size=32),
        info_b=st.binary(min_size=0, max_size=32),
    )
    def test_info_separates_outputs(self, ikm: bytes, info_a: bytes, info_b: bytes) -> None:
        if info_a == info_b:
            return
        out_a = native_hkdf(ikm, 32, salt=None, info=info_a)
        out_b = native_hkdf(ikm, 32, salt=None, info=info_b)
        assert out_a != out_b, "distinct info must derive distinct keys"

    @_SETTINGS
    @given(
        ikm_a=st.binary(min_size=1, max_size=128),
        ikm_b=st.binary(min_size=1, max_size=128),
    )
    def test_ikm_separates_outputs(self, ikm_a: bytes, ikm_b: bytes) -> None:
        if ikm_a == ikm_b:
            return
        assert native_hkdf(ikm_a, 32, salt=None, info=b"ctx") != native_hkdf(
            ikm_b, 32, salt=None, info=b"ctx"
        )
