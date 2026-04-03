#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Adversarial Security Tests
==========================

Production-grade adversarial tests covering:
- Fault injection (bit flips in signatures, ciphertexts, public keys)
- Boundary values (zero-length, max-length, off-by-one)
- Oracle attack resistance (timing on invalid ciphertexts)
- Key misuse (wrong key type, reused nonces)
- Cross-algorithm confusion (Ed25519 sig verified with ML-DSA)

AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
"""

import ctypes
import secrets
import time

import pytest

from ama_cryptography.pqc_backends import (
    _AES_GCM_NATIVE_AVAILABLE,
    _ED25519_NATIVE_AVAILABLE,
    DILITHIUM_AVAILABLE,
    KYBER_AVAILABLE,
    SPHINCS_AVAILABLE,
    _native_lib,
)

NATIVE_AVAILABLE = _native_lib is not None

skip_no_native = pytest.mark.skipif(not NATIVE_AVAILABLE, reason="Native C library not available")
skip_no_dilithium = pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium not available")
skip_no_kyber = pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber not available")
skip_no_sphincs = pytest.mark.skipif(not SPHINCS_AVAILABLE, reason="SPHINCS+ not available")
skip_no_ed25519 = pytest.mark.skipif(not _ED25519_NATIVE_AVAILABLE, reason="Ed25519 not available")
skip_no_aes_gcm = pytest.mark.skipif(not _AES_GCM_NATIVE_AVAILABLE, reason="AES-GCM not available")

# Key/signature sizes
DIL_PK = 1952
DIL_SK = 4032
DIL_SIG = 3309
KYBER_PK = 1568
KYBER_SK = 3168
KYBER_CT = 1568
KYBER_SS = 32
ED25519_SIG = 64


# ---------------------------------------------------------------------------
# Helpers using the high-level pqc_backends API
# ---------------------------------------------------------------------------


def _dilithium_keygen() -> tuple[bytes, bytes]:
    from ama_cryptography.pqc_backends import generate_dilithium_keypair

    kp = generate_dilithium_keypair()
    return kp.public_key, bytes(kp.secret_key)


def _dilithium_sign(sk: bytes, msg: bytes) -> bytes:
    from ama_cryptography.pqc_backends import dilithium_sign

    return dilithium_sign(msg, sk)


def _dilithium_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    from ama_cryptography.pqc_backends import dilithium_verify

    return dilithium_verify(msg, sig, pk)


def _kyber_keygen() -> tuple[bytes, bytes]:
    from ama_cryptography.pqc_backends import generate_kyber_keypair

    kp = generate_kyber_keypair()
    return kp.public_key, bytes(kp.secret_key)


def _kyber_encap(pk: bytes) -> tuple[bytes, bytes]:
    from ama_cryptography.pqc_backends import kyber_encapsulate

    result = kyber_encapsulate(pk)
    return result.ciphertext, result.shared_secret


def _kyber_decap(ct: bytes, sk: bytes) -> bytes:
    from ama_cryptography.pqc_backends import kyber_decapsulate

    return kyber_decapsulate(ct, sk)


def _ed25519_keygen() -> tuple[bytes, bytes]:
    from ama_cryptography.pqc_backends import native_ed25519_keypair

    return native_ed25519_keypair()


def _ed25519_sign(sk: bytes, msg: bytes) -> bytes:
    from ama_cryptography.pqc_backends import native_ed25519_sign

    return native_ed25519_sign(msg, sk)


def _ed25519_verify(pk: bytes, msg: bytes, sig: bytes) -> int:
    """Returns 0 on success, nonzero on failure."""
    from ama_cryptography.pqc_backends import native_ed25519_verify

    return 0 if native_ed25519_verify(sig, msg, pk) else 1


def _aes_gcm_encrypt(key: bytes, nonce: bytes, pt: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    ct = ctypes.create_string_buffer(len(pt))
    tag = ctypes.create_string_buffer(16)
    rc = _native_lib.ama_aes256_gcm_encrypt(
        key, nonce, pt, ctypes.c_size_t(len(pt)), aad, ctypes.c_size_t(len(aad)), ct, tag
    )
    assert rc == 0
    return bytes(ct), bytes(tag)


def _aes_gcm_decrypt(
    key: bytes, nonce: bytes, ct: bytes, tag: bytes, aad: bytes = b""
) -> tuple[int, bytes]:
    pt = ctypes.create_string_buffer(len(ct))
    rc = _native_lib.ama_aes256_gcm_decrypt(
        key, nonce, ct, ctypes.c_size_t(len(ct)), aad, ctypes.c_size_t(len(aad)), tag, pt
    )
    return rc, bytes(pt)


def _flip_bit(data: bytes, byte_idx: int, bit_idx: int = 0) -> bytes:
    """Return a copy of data with one bit flipped."""
    ba = bytearray(data)
    ba[byte_idx] ^= 1 << bit_idx
    return bytes(ba)


# ===========================================================================
# 1. FAULT INJECTION
# ===========================================================================


@pytest.mark.security
class TestFaultInjection:
    """Verify that single-bit faults cause rejection."""

    @skip_no_dilithium
    def test_dilithium_sig_bit_flip(self) -> None:
        pk, sk = _dilithium_keygen()
        msg = b"test message for fault injection"
        sig = _dilithium_sign(sk, msg)

        for pos in [0, len(sig) // 2, len(sig) - 1]:
            bad_sig = _flip_bit(sig, pos)
            assert not _dilithium_verify(
                pk, msg, bad_sig
            ), f"Sig should be rejected after bit flip at byte {pos}"

    @skip_no_dilithium
    def test_dilithium_pk_bit_flip(self) -> None:
        pk, sk = _dilithium_keygen()
        msg = b"pk fault injection test"
        sig = _dilithium_sign(sk, msg)

        for pos in [0, DIL_PK // 2, DIL_PK - 1]:
            bad_pk = _flip_bit(pk, pos)
            assert not _dilithium_verify(
                bad_pk, msg, sig
            ), f"Should reject with corrupted pk at byte {pos}"

    @skip_no_dilithium
    def test_dilithium_msg_bit_flip(self) -> None:
        pk, sk = _dilithium_keygen()
        msg = b"message integrity test"
        sig = _dilithium_sign(sk, msg)
        bad_msg = _flip_bit(msg, 0)
        assert not _dilithium_verify(pk, bad_msg, sig)

    @skip_no_kyber
    def test_kyber_ct_bit_flip(self) -> None:
        pk, sk = _kyber_keygen()
        ct, ss_enc = _kyber_encap(pk)

        for pos in [0, KYBER_CT // 2, KYBER_CT - 1]:
            bad_ct = _flip_bit(ct, pos)
            ss_dec = _kyber_decap(bad_ct, sk)
            assert ss_dec != ss_enc, f"Shared secret should differ with corrupted ct at byte {pos}"

    @skip_no_ed25519
    def test_ed25519_sig_bit_flip(self) -> None:
        pk, sk = _ed25519_keygen()
        msg = b"ed25519 fault injection"
        sig = _ed25519_sign(sk, msg)

        for pos in [0, 16, 32, 48, ED25519_SIG - 1]:
            bad_sig = _flip_bit(sig, pos)
            rc = _ed25519_verify(pk, msg, bad_sig)
            assert rc != 0, f"Ed25519 should reject bit flip at byte {pos}"

    @skip_no_aes_gcm
    def test_aes_gcm_ct_bit_flip(self) -> None:
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        pt = b"plaintext for fault injection test"
        ct, tag = _aes_gcm_encrypt(key, nonce, pt)
        bad_ct = _flip_bit(ct, 0)
        rc, _ = _aes_gcm_decrypt(key, nonce, bad_ct, tag)
        assert rc != 0, "AES-GCM should reject corrupted ciphertext"

    @skip_no_aes_gcm
    def test_aes_gcm_tag_bit_flip(self) -> None:
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        pt = b"tag integrity test"
        ct, tag = _aes_gcm_encrypt(key, nonce, pt)

        for pos in range(16):
            bad_tag = _flip_bit(tag, pos)
            rc, _ = _aes_gcm_decrypt(key, nonce, ct, bad_tag)
            assert rc != 0, f"AES-GCM should reject corrupted tag at byte {pos}"


# ===========================================================================
# 2. BOUNDARY VALUES
# ===========================================================================


@pytest.mark.security
class TestBoundaryValues:

    @skip_no_dilithium
    def test_dilithium_empty_message(self) -> None:
        pk, sk = _dilithium_keygen()
        sig = _dilithium_sign(sk, b"")
        assert _dilithium_verify(pk, b"", sig)

    @skip_no_dilithium
    def test_dilithium_large_message(self) -> None:
        pk, sk = _dilithium_keygen()
        msg = secrets.token_bytes(1024 * 1024)
        sig = _dilithium_sign(sk, msg)
        assert _dilithium_verify(pk, msg, sig)

    @skip_no_dilithium
    def test_dilithium_single_byte_messages(self) -> None:
        pk, sk = _dilithium_keygen()
        for byte_val in [0x00, 0xFF, 0x42]:
            msg = bytes([byte_val])
            sig = _dilithium_sign(sk, msg)
            assert _dilithium_verify(pk, msg, sig)

    @skip_no_ed25519
    def test_ed25519_empty_message(self) -> None:
        pk, sk = _ed25519_keygen()
        sig = _ed25519_sign(sk, b"")
        assert _ed25519_verify(pk, b"", sig) == 0

    @skip_no_aes_gcm
    def test_aes_gcm_empty_plaintext(self) -> None:
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        ct, tag = _aes_gcm_encrypt(key, nonce, b"", aad=b"authenticate this")
        assert len(ct) == 0
        rc, _ = _aes_gcm_decrypt(key, nonce, ct, tag, aad=b"authenticate this")
        assert rc == 0

    @skip_no_aes_gcm
    def test_aes_gcm_block_boundaries(self) -> None:
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        for size in [1, 15, 16, 17, 31, 32, 33, 48]:
            pt = secrets.token_bytes(size)
            ct, tag = _aes_gcm_encrypt(key, nonce, pt)
            rc, dec = _aes_gcm_decrypt(key, nonce, ct, tag)
            assert rc == 0, f"Failed for size {size}"
            assert dec == pt

    @skip_no_kyber
    def test_kyber_roundtrip_stress(self) -> None:
        for _ in range(10):
            pk, sk = _kyber_keygen()
            ct, ss_enc = _kyber_encap(pk)
            ss_dec = _kyber_decap(ct, sk)
            assert ss_enc == ss_dec


# ===========================================================================
# 3. ORACLE RESISTANCE
# ===========================================================================


@pytest.mark.security
class TestOracleResistance:

    @skip_no_aes_gcm
    def test_aes_gcm_tag_mismatch_no_timing(self) -> None:
        """AES-GCM decryption timing: valid vs invalid tags should be comparable."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        pt = secrets.token_bytes(1024)
        ct, good_tag = _aes_gcm_encrypt(key, nonce, pt)
        bad_tag = secrets.token_bytes(16)

        # Step 5c: verify correctness of both paths before timing analysis
        valid_rc, valid_pt = _aes_gcm_decrypt(key, nonce, ct, good_tag)
        assert valid_rc == 0, "Valid tag must return success (rc=0)"
        assert valid_pt == pt, "Valid decryption must recover original plaintext"

        invalid_rc, _ = _aes_gcm_decrypt(key, nonce, ct, bad_tag)
        assert invalid_rc != 0, "Invalid tag must return failure (rc!=0)"

        # Warmup
        for _ in range(100):
            _aes_gcm_decrypt(key, nonce, ct, good_tag)
            _aes_gcm_decrypt(key, nonce, ct, bad_tag)

        n_trials = 1000
        valid_times = []
        invalid_times = []
        for _ in range(n_trials):
            t0 = time.perf_counter_ns()
            _aes_gcm_decrypt(key, nonce, ct, good_tag)
            valid_times.append(time.perf_counter_ns() - t0)

            t0 = time.perf_counter_ns()
            _aes_gcm_decrypt(key, nonce, ct, bad_tag)
            invalid_times.append(time.perf_counter_ns() - t0)

        valid_times.sort()
        invalid_times.sort()
        # Use median to reduce noise
        v_med = valid_times[len(valid_times) // 2]
        i_med = invalid_times[len(invalid_times) // 2]

        if v_med > 0 and i_med > 0:
            ratio = max(v_med, i_med) / min(v_med, i_med)
            # Valid decryption includes CTR decryption phase, invalid stops at
            # tag check.  The ratio will be large when plaintext is large since
            # valid does extra CTR work.  This test verifies we don't have an
            # extreme outlier (>50x) suggesting a completely different codepath.
            assert ratio < 50.0, (
                f"Timing ratio {ratio:.2f}x — potential oracle "
                f"(valid={v_med}ns, invalid={i_med}ns)"
            )

    @skip_no_kyber
    def test_kyber_implicit_rejection(self) -> None:
        pk, sk = _kyber_keygen()
        _ct, ss_enc = _kyber_encap(pk)
        random_ct = secrets.token_bytes(KYBER_CT)
        ss_rand = _kyber_decap(random_ct, sk)
        assert ss_rand != ss_enc

        zero_ct = b"\x00" * KYBER_CT
        ss_zero = _kyber_decap(zero_ct, sk)
        assert isinstance(ss_zero, bytes)


# ===========================================================================
# 4. KEY MISUSE
# ===========================================================================


@pytest.mark.security
class TestKeyMisuse:

    @skip_no_aes_gcm
    def test_aes_gcm_wrong_key(self) -> None:
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        ct, tag = _aes_gcm_encrypt(key1, nonce, b"secret message")
        rc, _ = _aes_gcm_decrypt(key2, nonce, ct, tag)
        assert rc != 0

    @skip_no_aes_gcm
    def test_aes_gcm_wrong_nonce(self) -> None:
        key = secrets.token_bytes(32)
        nonce1 = secrets.token_bytes(12)
        nonce2 = secrets.token_bytes(12)
        ct, tag = _aes_gcm_encrypt(key, nonce1, b"nonce misuse test")
        rc, _ = _aes_gcm_decrypt(key, nonce2, ct, tag)
        assert rc != 0

    @skip_no_aes_gcm
    def test_aes_gcm_wrong_aad(self) -> None:
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        ct, tag = _aes_gcm_encrypt(key, nonce, b"aad test", aad=b"correct")
        rc, _ = _aes_gcm_decrypt(key, nonce, ct, tag, aad=b"wrong")
        assert rc != 0

    @skip_no_aes_gcm
    def test_aes_gcm_nonce_reuse_xor(self) -> None:
        """Nonce reuse leaks XOR of plaintexts (verifying the danger is real)."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        pt1 = b"message one xxxxx"
        pt2 = b"message two xxxxx"
        ct1, _ = _aes_gcm_encrypt(key, nonce, pt1)
        ct2, _ = _aes_gcm_encrypt(key, nonce, pt2)
        xor_ct = bytes(a ^ b for a, b in zip(ct1, ct2))
        xor_pt = bytes(a ^ b for a, b in zip(pt1, pt2))
        assert xor_ct == xor_pt

    @skip_no_dilithium
    def test_dilithium_wrong_key_verify(self) -> None:
        _pk1, sk1 = _dilithium_keygen()
        pk2, _ = _dilithium_keygen()
        sig = _dilithium_sign(sk1, b"wrong key test")
        assert not _dilithium_verify(pk2, b"wrong key test", sig)

    @skip_no_kyber
    def test_kyber_wrong_sk_decap(self) -> None:
        pk1, _sk1 = _kyber_keygen()
        _, sk2 = _kyber_keygen()
        ct, ss_enc = _kyber_encap(pk1)
        ss_dec = _kyber_decap(ct, sk2)
        assert ss_dec != ss_enc


# ===========================================================================
# 5. CROSS-ALGORITHM CONFUSION
# ===========================================================================


@pytest.mark.security
class TestCrossAlgorithm:

    @skip_no_dilithium
    @skip_no_ed25519
    def test_ed25519_sig_as_dilithium(self) -> None:
        """Ed25519 signature verified as Dilithium must fail, not crash."""
        _, ed_sk = _ed25519_keygen()
        dil_pk, _ = _dilithium_keygen()
        msg = b"cross-algorithm test"
        ed_sig = _ed25519_sign(ed_sk, msg)
        padded_sig = ed_sig + b"\x00" * (DIL_SIG - len(ed_sig))
        assert not _dilithium_verify(dil_pk, msg, padded_sig)

    @skip_no_dilithium
    @skip_no_ed25519
    def test_dilithium_sig_as_ed25519(self) -> None:
        """Dilithium signature verified as Ed25519 must fail, not crash."""
        _, dil_sk = _dilithium_keygen()
        ed_pk, _ = _ed25519_keygen()
        msg = b"reverse cross-algorithm test"
        dil_sig = _dilithium_sign(dil_sk, msg)
        truncated_sig = dil_sig[:ED25519_SIG]
        rc = _ed25519_verify(ed_pk, msg, truncated_sig)
        assert rc != 0

    @skip_no_dilithium
    def test_random_bytes_as_dilithium_sig(self) -> None:
        pk, _ = _dilithium_keygen()
        random_sig = secrets.token_bytes(DIL_SIG)
        assert not _dilithium_verify(pk, b"random sig test", random_sig)

    @skip_no_ed25519
    def test_random_bytes_as_ed25519_sig(self) -> None:
        pk, _ = _ed25519_keygen()
        random_sig = secrets.token_bytes(ED25519_SIG)
        rc = _ed25519_verify(pk, b"random ed25519 sig", random_sig)
        assert rc != 0

    @skip_no_kyber
    @skip_no_dilithium
    def test_dilithium_pk_as_kyber(self) -> None:
        """Using Dilithium pk for Kyber encap should not crash."""
        dil_pk, _ = _dilithium_keygen()
        fake_pk = (dil_pk + b"\x00" * KYBER_PK)[:KYBER_PK]
        # Should not crash — may succeed with unusable keys
        try:
            from ama_cryptography.pqc_backends import kyber_encapsulate

            result = kyber_encapsulate(fake_pk)
            assert isinstance(result.ciphertext, bytes)
        except Exception:  # noqa: S110 -- intentional crash-safety test (ADV-001)
            pass  # Any exception is acceptable, crash is not


# ===========================================================================
# 6. ADDITIONAL SECURITY EDGE CASES
# ===========================================================================


@pytest.mark.security
class TestSecurityEdgeCases:

    @skip_no_aes_gcm
    def test_aes_gcm_all_zero_inputs(self) -> None:
        key = b"\x00" * 32
        nonce = b"\x00" * 12
        pt = b"\x00" * 32
        ct, tag = _aes_gcm_encrypt(key, nonce, pt)
        rc, dec = _aes_gcm_decrypt(key, nonce, ct, tag)
        assert rc == 0
        assert dec == pt
        assert ct != pt, "Encryption of zeros should not produce zeros"

    @skip_no_aes_gcm
    def test_aes_gcm_large_aad(self) -> None:
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        aad = secrets.token_bytes(65536)
        pt = b"small plaintext"
        ct, tag = _aes_gcm_encrypt(key, nonce, pt, aad=aad)
        rc, dec = _aes_gcm_decrypt(key, nonce, ct, tag, aad=aad)
        assert rc == 0 and dec == pt

    @skip_no_dilithium
    def test_dilithium_sig_both_verify(self) -> None:
        """Two signatures from same key/msg should both verify."""
        pk, sk = _dilithium_keygen()
        msg = b"determinism test"
        sig1 = _dilithium_sign(sk, msg)
        sig2 = _dilithium_sign(sk, msg)
        assert _dilithium_verify(pk, msg, sig1)
        assert _dilithium_verify(pk, msg, sig2)

    @skip_no_kyber
    def test_kyber_encap_different_each_time(self) -> None:
        pk, _ = _kyber_keygen()
        ct1, ss1 = _kyber_encap(pk)
        ct2, ss2 = _kyber_encap(pk)
        assert ct1 != ct2
        assert ss1 != ss2

    @skip_no_aes_gcm
    def test_aes_gcm_truncated_ciphertext(self) -> None:
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        pt = secrets.token_bytes(64)
        ct, tag = _aes_gcm_encrypt(key, nonce, pt)

        for trunc_len in [0, 1, len(ct) // 2, len(ct) - 1]:
            truncated = ct[:trunc_len]
            pt_buf = ctypes.create_string_buffer(trunc_len)
            rc = _native_lib.ama_aes256_gcm_decrypt(
                key,
                nonce,
                truncated,
                ctypes.c_size_t(trunc_len),
                b"",
                ctypes.c_size_t(0),
                tag,
                pt_buf,
            )
            assert rc != 0, f"Truncated CT (len={trunc_len}) must fail"

    @skip_no_ed25519
    def test_ed25519_various_msg_sizes(self) -> None:
        pk, sk = _ed25519_keygen()
        for size in [0, 1, 32, 64, 256, 1024]:
            msg = b"\x00" * size
            sig = _ed25519_sign(sk, msg)
            assert _ed25519_verify(pk, msg, sig) == 0, f"Failed for size {size}"

    @skip_no_kyber
    def test_kyber_all_zero_sk(self) -> None:
        """Kyber decapsulation with all-zero SK should not crash."""
        pk, _ = _kyber_keygen()
        ct, _ = _kyber_encap(pk)
        zero_sk = b"\x00" * KYBER_SK
        try:
            ss = _kyber_decap(ct, zero_sk)
            assert isinstance(ss, bytes)
        except Exception:  # noqa: S110 -- intentional crash-safety test (ADV-001)
            pass  # Exception is acceptable, crash is not
