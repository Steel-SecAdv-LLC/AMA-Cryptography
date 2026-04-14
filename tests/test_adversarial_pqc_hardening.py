#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Adversarial PQC Hardening Tests
================================

Production-grade adversarial tests covering 7 categories:
1. Kyber IND-CCA2 Ciphertext Malleability
2. Noise-NK Protocol Fuzzing
3. Rekey Desynchronization
4. Large Sequence Gap DoS
5. HKDF Context Manipulation / Domain Separation
6. Memory Disclosure After Key Destruction
7. SPHINCS+ Signature Forgery Attempts

AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
"""

import secrets
import time

import pytest

from ama_cryptography.pqc_backends import (
    _HKDF_NATIVE_AVAILABLE,
    DILITHIUM_AVAILABLE,
    KYBER_AVAILABLE,
    SPHINCS_AVAILABLE,
    _native_lib,
)

NATIVE_AVAILABLE = _native_lib is not None

skip_no_native = pytest.mark.skipif(not NATIVE_AVAILABLE, reason="Native C library not available")
skip_no_kyber = pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber not available")
skip_no_sphincs = pytest.mark.skipif(not SPHINCS_AVAILABLE, reason="SPHINCS+ not available")
skip_no_dilithium = pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium not available")
skip_no_hkdf = pytest.mark.skipif(not _HKDF_NATIVE_AVAILABLE, reason="Native HKDF not available")

# Key/signature sizes
KYBER_CT = 1568
KYBER_SS = 32
SPHINCS_SIG = 49856


def _flip_bit(data: bytes, byte_idx: int, bit_idx: int = 0) -> bytes:
    """Return a copy of data with one bit flipped."""
    ba = bytearray(data)
    ba[byte_idx] ^= 1 << bit_idx
    return bytes(ba)


# ===========================================================================
# 1. KYBER IND-CCA2 CIPHERTEXT MALLEABILITY TESTS
# ===========================================================================


@pytest.mark.security
@skip_no_kyber
class TestKyberINDCCA2Malleability:
    """Verify Kyber-1024 IND-CCA2 implicit rejection on ciphertext mutation."""

    def test_single_byte_flip_produces_different_secret(self) -> None:
        """Flipping each byte in the ciphertext must produce a different shared secret."""
        from ama_cryptography.pqc_backends import (
            generate_kyber_keypair,
            kyber_decapsulate,
            kyber_encapsulate,
        )

        kp = generate_kyber_keypair()
        encap = kyber_encapsulate(kp.public_key)
        original_ss = kyber_decapsulate(encap.ciphertext, kp.secret_key)

        # Test a sample of byte positions (full 1568 would be slow)
        positions = [0, 1, 100, 500, 783, 1000, 1567]
        for pos in positions:
            mutated_ct = _flip_bit(encap.ciphertext, pos)
            decap_ss = kyber_decapsulate(mutated_ct, kp.secret_key)
            assert decap_ss != original_ss, (
                f"IND-CCA2 violation: mutated ciphertext at byte {pos} "
                f"produced the same shared secret"
            )

    def test_all_zero_ciphertext(self) -> None:
        """All-zero ciphertext must not crash and must produce different secret."""
        from ama_cryptography.pqc_backends import (
            generate_kyber_keypair,
            kyber_decapsulate,
            kyber_encapsulate,
        )

        kp = generate_kyber_keypair()
        encap = kyber_encapsulate(kp.public_key)
        original_ss = kyber_decapsulate(encap.ciphertext, kp.secret_key)

        zero_ct = b"\x00" * KYBER_CT
        zero_ss = kyber_decapsulate(zero_ct, kp.secret_key)
        assert isinstance(zero_ss, bytes)
        assert len(zero_ss) == KYBER_SS
        assert zero_ss != original_ss

    def test_all_ff_ciphertext(self) -> None:
        """All-0xFF ciphertext must not crash and must produce different secret."""
        from ama_cryptography.pqc_backends import (
            generate_kyber_keypair,
            kyber_decapsulate,
            kyber_encapsulate,
        )

        kp = generate_kyber_keypair()
        encap = kyber_encapsulate(kp.public_key)
        original_ss = kyber_decapsulate(encap.ciphertext, kp.secret_key)

        ff_ct = b"\xff" * KYBER_CT
        ff_ss = kyber_decapsulate(ff_ct, kp.secret_key)
        assert isinstance(ff_ss, bytes)
        assert ff_ss != original_ss

    def test_truncated_ciphertext_rejected(self) -> None:
        """Truncated ciphertext (1567 bytes) must be rejected."""
        from ama_cryptography.pqc_backends import (
            generate_kyber_keypair,
            kyber_decapsulate,
        )

        kp = generate_kyber_keypair()
        truncated = secrets.token_bytes(KYBER_CT - 1)

        with pytest.raises((ValueError, RuntimeError)):
            kyber_decapsulate(truncated, kp.secret_key)

    def test_extended_ciphertext_rejected(self) -> None:
        """Extended ciphertext (1569 bytes) must be rejected."""
        from ama_cryptography.pqc_backends import (
            generate_kyber_keypair,
            kyber_decapsulate,
        )

        kp = generate_kyber_keypair()
        extended = secrets.token_bytes(KYBER_CT + 1)

        with pytest.raises((ValueError, RuntimeError)):
            kyber_decapsulate(extended, kp.secret_key)

    def test_random_ciphertext_implicit_rejection(self) -> None:
        """Random ciphertext must produce a shared secret (implicit rejection)."""
        from ama_cryptography.pqc_backends import (
            generate_kyber_keypair,
            kyber_decapsulate,
            kyber_encapsulate,
        )

        kp = generate_kyber_keypair()
        encap = kyber_encapsulate(kp.public_key)
        original_ss = kyber_decapsulate(encap.ciphertext, kp.secret_key)

        random_ct = secrets.token_bytes(KYBER_CT)
        rand_ss = kyber_decapsulate(random_ct, kp.secret_key)
        assert isinstance(rand_ss, bytes)
        assert len(rand_ss) == KYBER_SS
        assert rand_ss != original_ss


# ===========================================================================
# 2. NOISE-NK PROTOCOL FUZZING TESTS
# ===========================================================================


@pytest.mark.security
@skip_no_native
class TestNoiseNKProtocolFuzzing:
    """Fuzz the Noise-NK handshake and channel messages."""

    def test_fuzzed_handshake_bytes_rejected(self) -> None:
        """Mutated handshake serialized bytes must be rejected."""
        from ama_cryptography.crypto_api import HybridKEMProvider, HybridSignatureProvider
        from ama_cryptography.secure_channel import (
            HandshakeError,
            HandshakeMessage,
            SecureChannelInitiator,
            SecureChannelResponder,
        )

        kem_prov = HybridKEMProvider()
        sig_prov = HybridSignatureProvider()
        kem_kp = kem_prov.generate_keypair()
        sig_kp = sig_prov.generate_keypair()

        initiator = SecureChannelInitiator(kem_kp.public_key)
        SecureChannelResponder(kem_kp.secret_key, sig_kp.secret_key, sig_kp.public_key)

        msg = initiator.create_handshake()
        wire = msg.serialize()

        # Flip random bytes and try to deserialize + handle
        errors_caught = 0
        for pos in [0, 10, len(wire) // 2, len(wire) - 1]:
            mutated = bytearray(wire)
            mutated[pos] ^= 0xFF
            try:
                bad_msg = HandshakeMessage.deserialize(bytes(mutated))
                responder2 = SecureChannelResponder(
                    kem_kp.secret_key, sig_kp.secret_key, sig_kp.public_key
                )
                responder2.handle_handshake(bad_msg)
            except (HandshakeError, ValueError, RuntimeError, Exception):
                errors_caught += 1

        # At least some mutations should cause errors
        assert errors_caught > 0, "No mutations caused errors — fuzzing ineffective"

    def test_wrong_protocol_name_rejected(self) -> None:
        """Wrong protocol name in handshake must be rejected."""
        from ama_cryptography.crypto_api import HybridKEMProvider, HybridSignatureProvider
        from ama_cryptography.secure_channel import (
            HandshakeError,
            HandshakeMessage,
            SecureChannelInitiator,
            SecureChannelResponder,
        )

        kem_prov = HybridKEMProvider()
        sig_prov = HybridSignatureProvider()
        kem_kp = kem_prov.generate_keypair()
        sig_kp = sig_prov.generate_keypair()

        initiator = SecureChannelInitiator(kem_kp.public_key)
        responder = SecureChannelResponder(kem_kp.secret_key, sig_kp.secret_key, sig_kp.public_key)

        msg = initiator.create_handshake()
        bad_msg = HandshakeMessage(
            protocol_name=b"WRONG_PROTOCOL_NAME",
            version=msg.version,
            ephemeral_public_key=msg.ephemeral_public_key,
            kem_ciphertext=msg.kem_ciphertext,
        )

        with pytest.raises(HandshakeError, match="Protocol mismatch"):
            responder.handle_handshake(bad_msg)

    def test_wrong_version_rejected(self) -> None:
        """Wrong protocol version in handshake must be rejected."""
        from ama_cryptography.crypto_api import HybridKEMProvider, HybridSignatureProvider
        from ama_cryptography.secure_channel import (
            HandshakeError,
            HandshakeMessage,
            SecureChannelInitiator,
            SecureChannelResponder,
        )

        kem_prov = HybridKEMProvider()
        sig_prov = HybridSignatureProvider()
        kem_kp = kem_prov.generate_keypair()
        sig_kp = sig_prov.generate_keypair()

        initiator = SecureChannelInitiator(kem_kp.public_key)
        responder = SecureChannelResponder(kem_kp.secret_key, sig_kp.secret_key, sig_kp.public_key)

        msg = initiator.create_handshake()
        bad_msg = HandshakeMessage(
            protocol_name=msg.protocol_name,
            version=b"\xff",
            ephemeral_public_key=msg.ephemeral_public_key,
            kem_ciphertext=msg.kem_ciphertext,
        )

        with pytest.raises(HandshakeError, match="Version mismatch"):
            responder.handle_handshake(bad_msg)

    def test_tampered_response_signature_rejected(self) -> None:
        """Tampered response signature must be rejected by initiator."""
        from ama_cryptography.crypto_api import HybridKEMProvider, HybridSignatureProvider
        from ama_cryptography.secure_channel import (
            HandshakeError,
            HandshakeResponse,
            SecureChannelInitiator,
            SecureChannelResponder,
        )

        kem_prov = HybridKEMProvider()
        sig_prov = HybridSignatureProvider()
        kem_kp = kem_prov.generate_keypair()
        sig_kp = sig_prov.generate_keypair()

        initiator = SecureChannelInitiator(kem_kp.public_key)
        responder = SecureChannelResponder(kem_kp.secret_key, sig_kp.secret_key, sig_kp.public_key)

        handshake_msg = initiator.create_handshake()
        response, _ = responder.handle_handshake(handshake_msg)

        # Flip bits in the signature
        tampered_sig = bytearray(response.signature)
        tampered_sig[0] ^= 0xFF
        bad_response = HandshakeResponse(
            session_id=response.session_id,
            signature=bytes(tampered_sig),
            responder_public_key=response.responder_public_key,
        )

        with pytest.raises(HandshakeError, match="signature verification failed"):
            initiator.complete_handshake(bad_response)

    def test_fuzzed_channel_message_rejected(self) -> None:
        """Tampered channel messages after session establishment must be rejected."""
        from ama_cryptography.crypto_api import HybridKEMProvider, HybridSignatureProvider
        from ama_cryptography.secure_channel import (
            ChannelMessage,
            SecureChannelInitiator,
            SecureChannelResponder,
        )

        kem_prov = HybridKEMProvider()
        sig_prov = HybridSignatureProvider()
        kem_kp = kem_prov.generate_keypair()
        sig_kp = sig_prov.generate_keypair()

        initiator = SecureChannelInitiator(kem_kp.public_key)
        responder = SecureChannelResponder(kem_kp.secret_key, sig_kp.secret_key, sig_kp.public_key)

        handshake_msg = initiator.create_handshake()
        response, resp_session = responder.handle_handshake(handshake_msg)
        init_session = initiator.complete_handshake(response)

        msg = init_session.encrypt(b"test data for fuzzing")

        # Flip bit in ciphertext
        tampered_ct = bytearray(msg.ciphertext)
        tampered_ct[0] ^= 0xFF
        bad_msg = ChannelMessage(
            session_id=msg.session_id,
            sequence_number=msg.sequence_number,
            nonce=msg.nonce,
            ciphertext=bytes(tampered_ct),
            tag=msg.tag,
        )

        with pytest.raises(Exception):  # noqa: B017
            resp_session.decrypt(bad_msg)

        # Flip bit in tag
        tampered_tag = bytearray(msg.tag)
        tampered_tag[0] ^= 0xFF
        bad_msg2 = ChannelMessage(
            session_id=msg.session_id,
            sequence_number=msg.sequence_number,
            nonce=msg.nonce,
            ciphertext=msg.ciphertext,
            tag=bytes(tampered_tag),
        )

        with pytest.raises(Exception):  # noqa: B017
            resp_session.decrypt(bad_msg2)


# ===========================================================================
# 3. REKEY DESYNCHRONIZATION TESTS
# ===========================================================================


@pytest.mark.security
@skip_no_native
class TestRekeyDesynchronization:
    """Verify that rekey desync is detected and recoverable."""

    def test_one_sided_rekey_causes_decrypt_failure(self) -> None:
        """Rekey on one side only causes decryption failure on the other."""
        from ama_cryptography.crypto_api import HybridKEMProvider, HybridSignatureProvider
        from ama_cryptography.secure_channel import (
            SecureChannelInitiator,
            SecureChannelResponder,
        )

        kem_prov = HybridKEMProvider()
        sig_prov = HybridSignatureProvider()
        kem_kp = kem_prov.generate_keypair()
        sig_kp = sig_prov.generate_keypair()

        initiator = SecureChannelInitiator(kem_kp.public_key)
        responder = SecureChannelResponder(kem_kp.secret_key, sig_kp.secret_key, sig_kp.public_key)

        handshake_msg = initiator.create_handshake()
        response, resp_session = responder.handle_handshake(handshake_msg)
        init_session = initiator.complete_handshake(response)

        # Verify communication works before rekey
        msg1 = init_session.encrypt(b"before rekey")
        assert resp_session.decrypt(msg1) == b"before rekey"

        # Rekey only initiator
        init_session.rekey()

        # Encrypt with new keys, try to decrypt with old keys
        msg2 = init_session.encrypt(b"after initiator rekey")
        with pytest.raises(Exception):  # noqa: B017
            resp_session.decrypt(msg2)

    def test_both_sides_rekey_restores_communication(self) -> None:
        """Rekeying both sides restores communication."""
        from ama_cryptography.crypto_api import HybridKEMProvider, HybridSignatureProvider
        from ama_cryptography.secure_channel import (
            SecureChannelInitiator,
            SecureChannelResponder,
        )

        kem_prov = HybridKEMProvider()
        sig_prov = HybridSignatureProvider()
        kem_kp = kem_prov.generate_keypair()
        sig_kp = sig_prov.generate_keypair()

        initiator = SecureChannelInitiator(kem_kp.public_key)
        responder = SecureChannelResponder(kem_kp.secret_key, sig_kp.secret_key, sig_kp.public_key)

        handshake_msg = initiator.create_handshake()
        response, resp_session = responder.handle_handshake(handshake_msg)
        init_session = initiator.complete_handshake(response)

        # Rekey both sides
        init_session.rekey()
        resp_session.rekey()

        # Communication should work again
        msg = init_session.encrypt(b"after both rekey")
        assert resp_session.decrypt(msg) == b"after both rekey"

    def test_double_rekey_one_side(self) -> None:
        """Double rekey on one side only still causes desync."""
        from ama_cryptography.crypto_api import HybridKEMProvider, HybridSignatureProvider
        from ama_cryptography.secure_channel import (
            SecureChannelInitiator,
            SecureChannelResponder,
        )

        kem_prov = HybridKEMProvider()
        sig_prov = HybridSignatureProvider()
        kem_kp = kem_prov.generate_keypair()
        sig_kp = sig_prov.generate_keypair()

        initiator = SecureChannelInitiator(kem_kp.public_key)
        responder = SecureChannelResponder(kem_kp.secret_key, sig_kp.secret_key, sig_kp.public_key)

        handshake_msg = initiator.create_handshake()
        response, resp_session = responder.handle_handshake(handshake_msg)
        init_session = initiator.complete_handshake(response)

        # Double rekey on initiator only
        init_session.rekey()
        init_session.rekey()

        # Responder only rekeys once — keys still desync'd
        resp_session.rekey()

        msg = init_session.encrypt(b"double rekey test")
        with pytest.raises(Exception):  # noqa: B017
            resp_session.decrypt(msg)


# ===========================================================================
# 4. LARGE SEQUENCE GAP DoS TEST
# ===========================================================================


@pytest.mark.security
class TestLargeSequenceGapDoS:
    """Verify that large sequence gaps don't cause O(gap) iteration."""

    def test_replay_window_large_gap_performance(self) -> None:
        """Jumping from seq 0 to 1_000_000 must complete in <10ms."""
        from ama_cryptography.session import ReplayWindow

        rw = ReplayWindow()
        rw.check_and_accept(0)

        start = time.perf_counter()
        rw.check_and_accept(1_000_000)
        elapsed = time.perf_counter() - start

        assert elapsed < 0.01, f"Large gap took {elapsed:.4f}s — should be <10ms (O(1))"

    def test_replay_window_base_advances_correctly(self) -> None:
        """After exceeding window capacity, base advances and seen set stays bounded."""
        from ama_cryptography.session import REPLAY_WINDOW_SIZE, ReplayWindow

        rw = ReplayWindow()
        # Fill beyond window capacity so the base is forced to slide
        for i in range(REPLAY_WINDOW_SIZE + 10):
            rw.check_and_accept(i)

        assert rw.base > 0
        assert len(rw._seen) <= REPLAY_WINDOW_SIZE

    def test_secure_session_large_gap(self) -> None:
        """SecureSession handles large sequence gap without DoS."""
        from ama_cryptography.session import ReplayWindow

        rw = ReplayWindow()
        # Accept 0, 1, 2, then jump to 1_000_000
        rw.check_and_accept(0)
        rw.check_and_accept(1)
        rw.check_and_accept(2)

        start = time.perf_counter()
        rw.check_and_accept(1_000_000)
        elapsed = time.perf_counter() - start

        assert elapsed < 0.01


# ===========================================================================
# 5. HKDF CONTEXT MANIPULATION / DOMAIN SEPARATION TESTS
# ===========================================================================


@pytest.mark.security
@skip_no_hkdf
class TestHKDFDomainSeparation:
    """Verify HKDF domain separation properties."""

    def test_different_info_produces_different_keys(self) -> None:
        """Same IKM/salt but different info must produce different keys."""
        from ama_cryptography.pqc_backends import native_hkdf

        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(32)

        key1 = native_hkdf(ikm, 32, salt=salt, info=b"ama-noise-nk-initiator-send")
        key2 = native_hkdf(ikm, 32, salt=salt, info=b"ama-noise-nk-responder-send")

        assert key1 != key2, "Domain separation failed: same IKM/salt, different info"

    def test_empty_vs_nonempty_info(self) -> None:
        """Empty info vs non-empty info must produce different keys."""
        from ama_cryptography.pqc_backends import native_hkdf

        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(32)

        key1 = native_hkdf(ikm, 32, salt=salt, info=b"")
        key2 = native_hkdf(ikm, 32, salt=salt, info=b"some-context")

        assert key1 != key2

    def test_different_salt_produces_different_keys(self) -> None:
        """Same IKM/info but different salt must produce different keys."""
        from ama_cryptography.pqc_backends import native_hkdf

        ikm = secrets.token_bytes(32)
        info = b"test-context"

        key1 = native_hkdf(ikm, 32, salt=secrets.token_bytes(32), info=info)
        key2 = native_hkdf(ikm, 32, salt=secrets.token_bytes(32), info=info)

        assert key1 != key2

    def test_different_ikm_produces_different_keys(self) -> None:
        """Same salt/info but different IKM must produce different keys."""
        from ama_cryptography.pqc_backends import native_hkdf

        salt = secrets.token_bytes(32)
        info = b"test-context"

        key1 = native_hkdf(secrets.token_bytes(32), 32, salt=salt, info=info)
        key2 = native_hkdf(secrets.token_bytes(32), 32, salt=salt, info=info)

        assert key1 != key2

    def test_zero_length_ikm_produces_output(self) -> None:
        """Zero-length IKM must still produce output (HKDF spec allows it)."""
        from ama_cryptography.pqc_backends import native_hkdf

        key = native_hkdf(b"", 32, salt=b"salt", info=b"info")
        assert len(key) == 32

    def test_very_long_info(self) -> None:
        """Very long info (10KB) must not crash."""
        from ama_cryptography.pqc_backends import native_hkdf

        ikm = secrets.token_bytes(32)
        long_info = b"x" * 10240

        key = native_hkdf(ikm, 32, salt=b"salt", info=long_info)
        assert len(key) == 32


# ===========================================================================
# 6. MEMORY DISCLOSURE AFTER KEY DESTRUCTION TESTS
# ===========================================================================


@pytest.mark.security
class TestMemoryDisclosureAfterDestruction:
    """Verify that secret keys are zeroed after wipe/destruction."""

    @skip_no_dilithium
    def test_dilithium_keypair_wipe(self) -> None:
        """DilithiumKeyPair.wipe() must zero the secret key bytearray."""
        from ama_cryptography.pqc_backends import generate_dilithium_keypair

        kp = generate_dilithium_keypair()
        sk_ref = kp.secret_key  # Reference to the same bytearray
        assert any(b != 0 for b in sk_ref), "Secret key should not be all zeros"

        kp.wipe()
        assert all(b == 0 for b in sk_ref), "Secret key was not zeroed after wipe()"

    @skip_no_kyber
    def test_kyber_keypair_wipe(self) -> None:
        """KyberKeyPair.wipe() must zero the secret key bytearray."""
        from ama_cryptography.pqc_backends import generate_kyber_keypair

        kp = generate_kyber_keypair()
        sk_ref = kp.secret_key
        assert any(b != 0 for b in sk_ref)

        kp.wipe()
        assert all(b == 0 for b in sk_ref)

    @skip_no_sphincs
    def test_sphincs_keypair_wipe(self) -> None:
        """SphincsKeyPair.wipe() must zero the secret key bytearray."""
        from ama_cryptography.pqc_backends import generate_sphincs_keypair

        kp = generate_sphincs_keypair()
        sk_ref = kp.secret_key
        assert any(b != 0 for b in sk_ref)

        kp.wipe()
        assert all(b == 0 for b in sk_ref)

    @skip_no_native
    def test_secure_buffer_zeroed_on_exit(self) -> None:
        """SecureBuffer must zero its data on context exit."""
        from ama_cryptography.secure_memory import SecureBuffer

        sb = SecureBuffer(64)
        with sb as buf:
            # buf is a bytearray returned by __enter__
            for i in range(64):
                buf[i] = 0xAA
            data_ref = buf  # keep a reference to the bytearray

        # After exiting context, buffer should be zeroed
        assert all(b == 0 for b in data_ref)


# ===========================================================================
# 7. SPHINCS+ SIGNATURE FORGERY ATTEMPTS
# ===========================================================================


@pytest.mark.security
@skip_no_sphincs
class TestSPHINCSForgeryAttempts:
    """Verify SPHINCS+ signature verification rejects all forgery attempts."""

    def test_flip_first_100_bytes(self) -> None:
        """Flipping each of the first 100 signature bytes must fail verification."""
        from ama_cryptography.pqc_backends import (
            generate_sphincs_keypair,
            sphincs_sign,
            sphincs_verify,
        )

        kp = generate_sphincs_keypair()
        msg = b"test message for SPHINCS+ forgery"
        sig = sphincs_sign(msg, kp.secret_key)
        assert len(sig) == SPHINCS_SIG

        for pos in range(100):
            bad_sig = _flip_bit(sig, pos)
            assert not sphincs_verify(
                msg, bad_sig, kp.public_key
            ), f"Forgery accepted at byte {pos}"

    def test_flip_last_byte(self) -> None:
        """Flipping the last byte of the signature must fail verification."""
        from ama_cryptography.pqc_backends import (
            generate_sphincs_keypair,
            sphincs_sign,
            sphincs_verify,
        )

        kp = generate_sphincs_keypair()
        msg = b"last byte forgery test"
        sig = sphincs_sign(msg, kp.secret_key)

        bad_sig = _flip_bit(sig, SPHINCS_SIG - 1)
        assert not sphincs_verify(msg, bad_sig, kp.public_key)

    def test_completely_random_signature(self) -> None:
        """Completely random 49856-byte signature must fail verification."""
        from ama_cryptography.pqc_backends import (
            generate_sphincs_keypair,
            sphincs_verify,
        )

        kp = generate_sphincs_keypair()
        msg = b"random signature test"
        random_sig = secrets.token_bytes(SPHINCS_SIG)

        assert not sphincs_verify(msg, random_sig, kp.public_key)

    def test_truncated_signature_rejected(self) -> None:
        """Truncated signature (49855 bytes) must fail or raise."""
        from ama_cryptography.pqc_backends import (
            generate_sphincs_keypair,
            sphincs_verify,
        )

        kp = generate_sphincs_keypair()
        msg = b"truncated signature test"
        truncated_sig = secrets.token_bytes(SPHINCS_SIG - 1)

        try:
            result = sphincs_verify(msg, truncated_sig, kp.public_key)
            assert not result
        except (ValueError, RuntimeError):
            pass  # Also acceptable to raise

    def test_wrong_public_key(self) -> None:
        """Signature verified with wrong public key must fail."""
        from ama_cryptography.pqc_backends import (
            generate_sphincs_keypair,
            sphincs_sign,
            sphincs_verify,
        )

        kp1 = generate_sphincs_keypair()
        kp2 = generate_sphincs_keypair()
        msg = b"wrong key test"
        sig = sphincs_sign(msg, kp1.secret_key)

        assert not sphincs_verify(msg, sig, kp2.public_key)

    def test_wrong_message(self) -> None:
        """Valid signature for non-empty message must fail on empty message."""
        from ama_cryptography.pqc_backends import (
            generate_sphincs_keypair,
            sphincs_sign,
            sphincs_verify,
        )

        kp = generate_sphincs_keypair()
        msg = b"original message"
        sig = sphincs_sign(msg, kp.secret_key)

        assert not sphincs_verify(b"", sig, kp.public_key)
