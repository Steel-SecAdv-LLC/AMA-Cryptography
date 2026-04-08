#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Tests for Phase 2 cryptographic primitives:
- secp256k1 compressed pubkey derivation
- X25519 key exchange (RFC 7748)
- Argon2id KDF (RFC 9106)
- ChaCha20-Poly1305 AEAD (RFC 8439)
- Deterministic keygen (Kyber-1024, ML-DSA-65)
"""

from __future__ import annotations

from typing import Any

import pytest

from ama_cryptography.pqc_backends import (
    _ARGON2_NATIVE_AVAILABLE,
    _CHACHA20_POLY1305_NATIVE_AVAILABLE,
    _DETERMINISTIC_KEYGEN_AVAILABLE,
    _SECP256K1_NATIVE_AVAILABLE,
    _X25519_NATIVE_AVAILABLE,
)

# Skip entire module if native library is not built
pytestmark = pytest.mark.skipif(
    not _SECP256K1_NATIVE_AVAILABLE,
    reason="Native library not built with new primitives",
)


# =============================================================================
# SECP256K1 TESTS
# =============================================================================


class TestSecp256k1:
    """Tests for secp256k1 compressed public key derivation."""

    def test_pubkey_from_privkey_basic(self) -> None:
        """Derive a compressed public key from a valid private key."""
        from ama_cryptography.pqc_backends import native_secp256k1_pubkey_from_privkey

        # Use the well-known private key = 1 (the generator point G)
        privkey = b"\x00" * 31 + b"\x01"
        pubkey = native_secp256k1_pubkey_from_privkey(privkey)

        assert len(pubkey) == 33
        # Generator point G has even Y, so prefix should be 0x02
        assert pubkey[0] in (0x02, 0x03)

    def test_pubkey_from_privkey_known_vector(self) -> None:
        """Verify against a known secp256k1 test vector."""
        from ama_cryptography.pqc_backends import native_secp256k1_pubkey_from_privkey

        # Private key = 1 should produce the generator point G
        privkey = b"\x00" * 31 + b"\x01"
        pubkey = native_secp256k1_pubkey_from_privkey(privkey)

        # G.x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        expected_x = bytes.fromhex(
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        )
        assert pubkey[1:] == expected_x

    def test_pubkey_from_privkey_2g(self) -> None:
        """Private key = 2 should produce 2G."""
        from ama_cryptography.pqc_backends import native_secp256k1_pubkey_from_privkey

        privkey = b"\x00" * 31 + b"\x02"
        pubkey = native_secp256k1_pubkey_from_privkey(privkey)

        # 2G.x = 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
        expected_x = bytes.fromhex(
            "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5"
        )
        assert pubkey[1:] == expected_x

    def test_pubkey_deterministic(self) -> None:
        """Same private key always yields same public key."""
        from ama_cryptography.pqc_backends import native_secp256k1_pubkey_from_privkey

        privkey = bytes.fromhex("E8F32E723DECF4051AEFAC8E2C93C9C5B214313817CDB01A1494B917C8436B35")
        pubkey1 = native_secp256k1_pubkey_from_privkey(privkey)
        pubkey2 = native_secp256k1_pubkey_from_privkey(privkey)
        assert pubkey1 == pubkey2

    def test_pubkey_different_keys_differ(self) -> None:
        """Different private keys yield different public keys."""
        from ama_cryptography.pqc_backends import native_secp256k1_pubkey_from_privkey

        pk1 = native_secp256k1_pubkey_from_privkey(b"\x00" * 31 + b"\x01")
        pk2 = native_secp256k1_pubkey_from_privkey(b"\x00" * 31 + b"\x02")
        assert pk1 != pk2

    def test_pubkey_wrong_length_raises(self) -> None:
        """Wrong private key length raises ValueError."""
        from ama_cryptography.pqc_backends import native_secp256k1_pubkey_from_privkey

        with pytest.raises(ValueError):
            native_secp256k1_pubkey_from_privkey(b"\x01" * 16)


# =============================================================================
# X25519 TESTS
# =============================================================================


@pytest.mark.skipif(not _X25519_NATIVE_AVAILABLE, reason="X25519 not available")
class TestX25519:
    """Tests for X25519 key exchange (RFC 7748)."""

    def test_keypair_generation(self) -> None:
        """Generate a valid X25519 keypair."""
        from ama_cryptography.pqc_backends import native_x25519_keypair

        pk, sk = native_x25519_keypair()
        assert len(pk) == 32
        assert len(sk) == 32

    def test_keypair_uniqueness(self) -> None:
        """Different keypairs have different keys."""
        from ama_cryptography.pqc_backends import native_x25519_keypair

        pk1, sk1 = native_x25519_keypair()
        pk2, sk2 = native_x25519_keypair()
        assert pk1 != pk2
        assert sk1 != sk2

    def test_key_exchange_symmetric(self) -> None:
        """A and B compute the same shared secret."""
        from ama_cryptography.pqc_backends import native_x25519_key_exchange, native_x25519_keypair

        pk_a, sk_a = native_x25519_keypair()
        pk_b, sk_b = native_x25519_keypair()

        ss_a = native_x25519_key_exchange(sk_a, pk_b)
        ss_b = native_x25519_key_exchange(sk_b, pk_a)

        assert ss_a == ss_b
        assert len(ss_a) == 32

    def test_key_exchange_different_peers(self) -> None:
        """Different peers produce different shared secrets."""
        from ama_cryptography.pqc_backends import native_x25519_key_exchange, native_x25519_keypair

        _pk_a, sk_a = native_x25519_keypair()
        pk_b, _ = native_x25519_keypair()
        pk_c, _ = native_x25519_keypair()

        ss_ab = native_x25519_key_exchange(sk_a, pk_b)
        ss_ac = native_x25519_key_exchange(sk_a, pk_c)
        assert ss_ab != ss_ac

    def test_rfc7748_vector_1(self) -> None:
        """RFC 7748 Section 5.2 — Test Vector 1 (Alice's side)."""
        from ama_cryptography.pqc_backends import native_x25519_key_exchange

        # RFC 7748 Section 5.2 test vectors
        alice_sk = bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        )
        bob_pk = bytes.fromhex(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        )
        expected_shared = bytes.fromhex(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        )

        shared = native_x25519_key_exchange(alice_sk, bob_pk)
        assert shared == expected_shared

    def test_rfc7748_vector_2(self) -> None:
        """RFC 7748 Section 5.2 — Test Vector 2 (Bob's side)."""
        from ama_cryptography.pqc_backends import native_x25519_key_exchange

        bob_sk = bytes.fromhex(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
        )
        alice_pk = bytes.fromhex(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        )
        expected_shared = bytes.fromhex(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        )

        shared = native_x25519_key_exchange(bob_sk, alice_pk)
        assert shared == expected_shared

    def test_rfc7748_basepoint(self) -> None:
        """RFC 7748 Section 6.1 — scalar mult with known scalar and basepoint."""
        from ama_cryptography.pqc_backends import native_x25519_key_exchange

        # Scalar = 1 iteration: X25519(scalar, 9)
        scalar = bytes.fromhex(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
        )
        basepoint = bytes.fromhex(
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
        )
        expected = bytes.fromhex(
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        )

        result = native_x25519_key_exchange(scalar, basepoint)
        assert result == expected


# =============================================================================
# ARGON2ID TESTS
# =============================================================================


@pytest.mark.skipif(not _ARGON2_NATIVE_AVAILABLE, reason="Argon2id not available")
class TestArgon2id:
    """Tests for Argon2id KDF (RFC 9106)."""

    def test_basic_derivation(self) -> None:
        """Basic Argon2id derivation produces expected length output."""
        from ama_cryptography.pqc_backends import native_argon2id

        result = native_argon2id(
            password=b"password",
            salt=b"somesalt" * 2,  # 16 bytes
            t_cost=1,
            m_cost=64,  # 64 KiB (minimum for testing)
            parallelism=1,
            out_len=32,
        )
        assert len(result) == 32

    def test_deterministic(self) -> None:
        """Same inputs produce same output."""
        from ama_cryptography.pqc_backends import native_argon2id

        kwargs: dict[str, Any] = {
            "password": b"test_password",
            "salt": b"a" * 16,
            "t_cost": 1,
            "m_cost": 64,
            "parallelism": 1,
            "out_len": 32,
        }
        r1 = native_argon2id(**kwargs)
        r2 = native_argon2id(**kwargs)
        assert r1 == r2

    def test_different_passwords_differ(self) -> None:
        """Different passwords produce different outputs."""
        from ama_cryptography.pqc_backends import native_argon2id

        common: dict[str, Any] = {
            "salt": b"b" * 16,
            "t_cost": 1,
            "m_cost": 64,
            "parallelism": 1,
            "out_len": 32,
        }
        r1 = native_argon2id(password=b"password1", **common)
        r2 = native_argon2id(password=b"password2", **common)
        assert r1 != r2

    def test_different_salts_differ(self) -> None:
        """Different salts produce different outputs."""
        from ama_cryptography.pqc_backends import native_argon2id

        common: dict[str, Any] = {
            "password": b"password",
            "t_cost": 1,
            "m_cost": 64,
            "parallelism": 1,
            "out_len": 32,
        }
        r1 = native_argon2id(salt=b"c" * 16, **common)
        r2 = native_argon2id(salt=b"d" * 16, **common)
        assert r1 != r2

    def test_variable_output_length(self) -> None:
        """Different output lengths produce different-length results."""
        from ama_cryptography.pqc_backends import native_argon2id

        common: dict[str, Any] = {
            "password": b"password",
            "salt": b"e" * 16,
            "t_cost": 1,
            "m_cost": 64,
            "parallelism": 1,
        }
        r32 = native_argon2id(out_len=32, **common)
        r64 = native_argon2id(out_len=64, **common)
        assert len(r32) == 32
        assert len(r64) == 64

    def test_rfc9106_argon2id_deterministic_vector(self) -> None:
        """Argon2id deterministic regression vector (RFC 9106 parameters).

        Uses RFC 9106-style parameters (t_cost=3, m_cost=32 KiB, parallelism=4)
        with 32-byte password and 16-byte salt.  The expected output is a
        regression anchor — any change indicates an algorithm break.

        Note: RFC 9106 Section 5.4 test vector includes secret/associated-data
        parameters not exposed by our C API, so the output differs from the
        reference.  This test validates determinism and algorithm stability.
        """
        from ama_cryptography.pqc_backends import native_argon2id

        password = bytes([0x01] * 32)
        salt = bytes([0x02] * 16)

        result = native_argon2id(
            password=password,
            salt=salt,
            t_cost=3,
            m_cost=32,
            parallelism=4,
            out_len=32,
        )

        expected = bytes.fromhex(
            "107ef258c89eebc34d910bada639360cd98cac51079cdae54ea411d824af04c3"
        )
        assert result == expected, (
            f"Argon2id regression vector mismatch: got {result.hex()}, expected {expected.hex()}"
        )


# =============================================================================
# CHACHA20-POLY1305 TESTS
# =============================================================================


@pytest.mark.skipif(
    not _CHACHA20_POLY1305_NATIVE_AVAILABLE, reason="ChaCha20-Poly1305 not available"
)
class TestChaCha20Poly1305:
    """Tests for ChaCha20-Poly1305 AEAD (RFC 8439)."""

    def test_encrypt_decrypt_roundtrip(self) -> None:
        """Encrypt then decrypt recovers original plaintext."""
        from ama_cryptography.pqc_backends import (
            native_chacha20poly1305_decrypt,
            native_chacha20poly1305_encrypt,
        )

        key = b"\x01" * 32
        nonce = b"\x02" * 12
        plaintext = b"Hello, ChaCha20-Poly1305!"
        aad = b"additional data"

        ct, tag = native_chacha20poly1305_encrypt(key, nonce, plaintext, aad)
        assert len(ct) == len(plaintext)
        assert len(tag) == 16

        pt = native_chacha20poly1305_decrypt(key, nonce, ct, tag, aad)
        assert pt == plaintext

    def test_wrong_key_fails(self) -> None:
        """Decryption with wrong key fails."""
        from ama_cryptography.pqc_backends import (
            native_chacha20poly1305_decrypt,
            native_chacha20poly1305_encrypt,
        )

        key = b"\x01" * 32
        nonce = b"\x02" * 12
        ct, tag = native_chacha20poly1305_encrypt(key, nonce, b"secret", b"")

        with pytest.raises(RuntimeError):
            native_chacha20poly1305_decrypt(b"\xff" * 32, nonce, ct, tag, b"")

    def test_wrong_tag_fails(self) -> None:
        """Decryption with corrupted tag fails."""
        from ama_cryptography.pqc_backends import (
            native_chacha20poly1305_decrypt,
            native_chacha20poly1305_encrypt,
        )

        key = b"\x01" * 32
        nonce = b"\x02" * 12
        ct, tag = native_chacha20poly1305_encrypt(key, nonce, b"secret", b"")

        bad_tag = bytearray(tag)
        bad_tag[0] ^= 0xFF
        with pytest.raises(RuntimeError):
            native_chacha20poly1305_decrypt(key, nonce, ct, bytes(bad_tag), b"")

    def test_wrong_aad_fails(self) -> None:
        """Decryption with wrong AAD fails."""
        from ama_cryptography.pqc_backends import (
            native_chacha20poly1305_decrypt,
            native_chacha20poly1305_encrypt,
        )

        key = b"\x01" * 32
        nonce = b"\x02" * 12
        ct, tag = native_chacha20poly1305_encrypt(key, nonce, b"secret", b"correct")

        with pytest.raises(RuntimeError):
            native_chacha20poly1305_decrypt(key, nonce, ct, tag, b"wrong")

    def test_empty_plaintext(self) -> None:
        """Encrypt/decrypt with empty plaintext (AAD-only authentication)."""
        from ama_cryptography.pqc_backends import (
            native_chacha20poly1305_decrypt,
            native_chacha20poly1305_encrypt,
        )

        key = b"\x01" * 32
        nonce = b"\x02" * 12
        ct, tag = native_chacha20poly1305_encrypt(key, nonce, b"", b"just auth")
        assert len(ct) == 0
        assert len(tag) == 16

        pt = native_chacha20poly1305_decrypt(key, nonce, ct, tag, b"just auth")
        assert pt == b""

    def test_rfc8439_test_vector(self) -> None:
        """RFC 8439 Section 2.8.2 AEAD test vector."""
        from ama_cryptography.pqc_backends import (
            native_chacha20poly1305_decrypt,
            native_chacha20poly1305_encrypt,
        )

        key = bytes.fromhex("808182838485868788898a8b8c8d8e8f" "909192939495969798999a9b9c9d9e9f")
        nonce = bytes.fromhex("070000004041424344454647")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        plaintext = (
            b"Ladies and Gentlemen of the class of '99: "
            b"If I could offer you only one tip for the future, sunscreen would be it."
        )

        ct, tag = native_chacha20poly1305_encrypt(key, nonce, plaintext, aad)

        expected_tag = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")
        assert tag == expected_tag

        pt = native_chacha20poly1305_decrypt(key, nonce, ct, tag, aad)
        assert pt == plaintext


# =============================================================================
# DETERMINISTIC KEYGEN TESTS
# =============================================================================


@pytest.mark.skipif(
    not _DETERMINISTIC_KEYGEN_AVAILABLE, reason="Deterministic keygen not available"
)
class TestDeterministicKeygen:
    """Tests for deterministic key generation from seed."""

    def test_kyber_deterministic(self) -> None:
        """Same seeds produce same Kyber keypair."""
        from ama_cryptography.pqc_backends import native_kyber_keypair_from_seed

        d = b"\xaa" * 32
        z = b"\xbb" * 32

        pk1, sk1 = native_kyber_keypair_from_seed(d, z)
        pk2, sk2 = native_kyber_keypair_from_seed(d, z)

        assert pk1 == pk2
        assert sk1 == sk2
        assert len(pk1) == 1568
        assert len(sk1) == 3168

    def test_kyber_different_seeds_differ(self) -> None:
        """Different seeds produce different Kyber keypairs."""
        from ama_cryptography.pqc_backends import native_kyber_keypair_from_seed

        pk1, _ = native_kyber_keypair_from_seed(b"\x01" * 32, b"\x02" * 32)
        pk2, _ = native_kyber_keypair_from_seed(b"\x03" * 32, b"\x04" * 32)
        assert pk1 != pk2

    def test_dilithium_deterministic(self) -> None:
        """Same seed produces same Dilithium keypair."""
        from ama_cryptography.pqc_backends import native_dilithium_keypair_from_seed

        xi = b"\xcc" * 32

        pk1, sk1 = native_dilithium_keypair_from_seed(xi)
        pk2, sk2 = native_dilithium_keypair_from_seed(xi)

        assert pk1 == pk2
        assert sk1 == sk2
        assert len(pk1) == 1952
        assert len(sk1) == 4032

    def test_dilithium_different_seeds_differ(self) -> None:
        """Different seeds produce different Dilithium keypairs."""
        from ama_cryptography.pqc_backends import native_dilithium_keypair_from_seed

        pk1, _ = native_dilithium_keypair_from_seed(b"\x01" * 32)
        pk2, _ = native_dilithium_keypair_from_seed(b"\x02" * 32)
        assert pk1 != pk2

    def test_kyber_encaps_decaps_with_deterministic_keys(self) -> None:
        """Deterministically generated Kyber keys work for encaps/decaps."""
        from ama_cryptography.pqc_backends import (
            kyber_decapsulate,
            kyber_encapsulate,
            native_kyber_keypair_from_seed,
        )

        d = b"\xdd" * 32
        z = b"\xee" * 32
        pk, sk = native_kyber_keypair_from_seed(d, z)

        result = kyber_encapsulate(pk)
        ss2 = kyber_decapsulate(result.ciphertext, sk)
        assert result.shared_secret == ss2

    def test_dilithium_sign_verify_with_deterministic_keys(self) -> None:
        """Deterministically generated Dilithium keys work for sign/verify."""
        from ama_cryptography.pqc_backends import (
            dilithium_sign,
            dilithium_verify,
            native_dilithium_keypair_from_seed,
        )

        xi = b"\xff" * 32
        pk, sk = native_dilithium_keypair_from_seed(xi)

        message = b"Test message for deterministic Dilithium"
        sig = dilithium_sign(message, sk)
        assert dilithium_verify(message, sig, pk)


# =============================================================================
# BIP32 NON-HARDENED DERIVATION TESTS
# =============================================================================


class TestBIP32NonHardened:
    """Tests for BIP32 non-hardened derivation with native secp256k1."""

    def test_full_bip44_path(self) -> None:
        """Full BIP44 path m/44'/0'/0'/0/0 works."""
        from ama_cryptography.key_management import HDKeyDerivation

        hd = HDKeyDerivation(seed=b"A" * 64)
        key, chain = hd.derive_path("m/44'/0'/0'/0/0")
        assert len(key) == 32
        assert len(chain) == 32

    def test_non_hardened_deterministic(self) -> None:
        """Non-hardened derivation is deterministic."""
        from ama_cryptography.key_management import HDKeyDerivation

        seed = b"B" * 64
        hd1 = HDKeyDerivation(seed=seed)
        hd2 = HDKeyDerivation(seed=seed)

        key1, chain1 = hd1.derive_path("m/44'/0'/0'/0/0")
        key2, chain2 = hd2.derive_path("m/44'/0'/0'/0/0")
        assert key1 == key2
        assert chain1 == chain2

    def test_different_non_hardened_indices_differ(self) -> None:
        """Different non-hardened indices produce different keys."""
        from ama_cryptography.key_management import HDKeyDerivation

        hd = HDKeyDerivation(seed=b"C" * 64)
        key0, _ = hd.derive_path("m/44'/0'/0'/0/0")
        key1, _ = hd.derive_path("m/44'/0'/0'/0/1")
        assert key0 != key1

    def test_derive_key_convenience(self) -> None:
        """derive_key convenience method works with non-hardened segments."""
        from ama_cryptography.key_management import HDKeyDerivation

        hd = HDKeyDerivation(seed=b"D" * 64)
        key = hd.derive_key(purpose=44, account=0, change=0, index=0)
        assert len(key) == 32
