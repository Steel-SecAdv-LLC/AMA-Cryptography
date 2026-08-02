#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Comprehensive Test Suite for secure_channel.py
================================================

Tests the Post-Quantum Noise-NK Secure Channel protocol including:
- Handshake roundtrip (Initiator <-> Responder)
- Message encryption/decryption after session establishment
- Message serialization and deserialization
- Replay detection (sliding window)
- Tampering detection (modified ciphertext, tag, AAD)
- Session TTL expiration
- Re-keying (forward secrecy)
- State machine enforcement
- Protocol version/name validation
- Edge cases (empty messages, max-size messages, etc.)

AI Co-Architects: Eris | Eden | Devin | Claude
"""

from __future__ import annotations

import secrets
import struct
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from ama_cryptography.secure_channel import SecureSession

# Check if native library is available
try:
    from ama_cryptography.pqc_backends import _native_lib

    NATIVE_AVAILABLE = _native_lib is not None
except ImportError:
    NATIVE_AVAILABLE = False

skip_no_native = pytest.mark.skipif(
    not NATIVE_AVAILABLE,
    reason="Native C library not available (build with cmake)",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def kem_keypair() -> tuple[bytes, bytes]:
    """Generate a hybrid KEM keypair for Responder."""
    from ama_cryptography.crypto_api import HybridKEMProvider

    provider = HybridKEMProvider()
    kp = provider.generate_keypair()
    return kp.public_key, kp.secret_key


@pytest.fixture()
def sig_keypair() -> tuple[bytes, bytes]:
    """Generate a hybrid signature keypair for Responder."""
    from ama_cryptography.crypto_api import HybridSignatureProvider

    provider = HybridSignatureProvider()
    kp = provider.generate_keypair()
    return kp.public_key, kp.secret_key


@pytest.fixture()
def established_session(
    kem_keypair: tuple[bytes, bytes],
    sig_keypair: tuple[bytes, bytes],
) -> tuple[SecureSession, SecureSession]:
    """Perform a full handshake and return (initiator_session, responder_session)."""
    from ama_cryptography.secure_channel import (
        SecureChannelInitiator,
        SecureChannelResponder,
    )

    kem_pk, kem_sk = kem_keypair
    sig_pk, sig_sk = sig_keypair

    initiator = SecureChannelInitiator(kem_pk)
    responder = SecureChannelResponder(kem_sk, sig_sk, sig_pk)

    handshake_msg = initiator.create_handshake()
    response, responder_session = responder.handle_handshake(handshake_msg)
    initiator_session = initiator.complete_handshake(response)

    return initiator_session, responder_session


# ---------------------------------------------------------------------------
# Handshake Tests
# ---------------------------------------------------------------------------


@skip_no_native
class TestNoiseNKHandshake:
    """Test the Noise-NK handshake protocol."""

    def test_full_handshake_roundtrip(
        self,
        kem_keypair: tuple[bytes, bytes],
        sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """Complete handshake produces valid sessions on both sides."""
        from ama_cryptography.secure_channel import (
            ChannelState,
            SecureChannelInitiator,
            SecureChannelResponder,
        )

        kem_pk, kem_sk = kem_keypair
        sig_pk, sig_sk = sig_keypair

        initiator = SecureChannelInitiator(kem_pk)
        responder = SecureChannelResponder(kem_sk, sig_sk, sig_pk)

        handshake_msg = initiator.create_handshake()
        response, resp_session = responder.handle_handshake(handshake_msg)
        init_session = initiator.complete_handshake(response)

        # Both sessions should be ESTABLISHED
        assert init_session._state == ChannelState.ESTABLISHED
        assert resp_session._state == ChannelState.ESTABLISHED

        # Session IDs must match
        assert init_session.session_id == resp_session.session_id

        # Keys must be cross-matched: initiator send == responder recv
        assert init_session.send_key == resp_session.recv_key
        assert init_session.recv_key == resp_session.send_key

    def test_handshake_message_serialization(self, kem_keypair: tuple[bytes, bytes]) -> None:
        """HandshakeMessage survives serialize/deserialize roundtrip."""
        from ama_cryptography.secure_channel import (
            HandshakeMessage,
            SecureChannelInitiator,
        )

        kem_pk, _ = kem_keypair
        initiator = SecureChannelInitiator(kem_pk)
        msg = initiator.create_handshake()

        wire = msg.serialize()
        restored = HandshakeMessage.deserialize(wire)

        assert restored.protocol_name == msg.protocol_name
        assert restored.version == msg.version
        assert restored.ephemeral_public_key == msg.ephemeral_public_key
        assert restored.kem_ciphertext == msg.kem_ciphertext

    def test_handshake_response_serialization(
        self,
        kem_keypair: tuple[bytes, bytes],
        sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """HandshakeResponse survives serialize/deserialize roundtrip."""
        from ama_cryptography.secure_channel import (
            HandshakeResponse,
            SecureChannelInitiator,
            SecureChannelResponder,
        )

        kem_pk, kem_sk = kem_keypair
        sig_pk, sig_sk = sig_keypair

        initiator = SecureChannelInitiator(kem_pk)
        responder = SecureChannelResponder(kem_sk, sig_sk, sig_pk)

        handshake_msg = initiator.create_handshake()
        response, _ = responder.handle_handshake(handshake_msg)

        wire = response.serialize()
        restored = HandshakeResponse.deserialize(wire)

        assert restored.session_id == response.session_id
        assert restored.signature == response.signature
        assert restored.responder_public_key == response.responder_public_key

    def test_protocol_name_mismatch_rejected(
        self,
        kem_keypair: tuple[bytes, bytes],
        sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """Responder rejects handshake with wrong protocol name."""
        from ama_cryptography.secure_channel import (
            HandshakeError,
            HandshakeMessage,
            SecureChannelInitiator,
            SecureChannelResponder,
        )

        kem_pk, kem_sk = kem_keypair
        sig_pk, sig_sk = sig_keypair

        initiator = SecureChannelInitiator(kem_pk)
        responder = SecureChannelResponder(kem_sk, sig_sk, sig_pk)

        msg = initiator.create_handshake()
        bad_msg = HandshakeMessage(
            protocol_name=b"WRONG_PROTOCOL",
            version=msg.version,
            ephemeral_public_key=msg.ephemeral_public_key,
            kem_ciphertext=msg.kem_ciphertext,
        )

        with pytest.raises(HandshakeError, match="Protocol mismatch"):
            responder.handle_handshake(bad_msg)

    def test_protocol_version_mismatch_rejected(
        self,
        kem_keypair: tuple[bytes, bytes],
        sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """Responder rejects handshake with wrong protocol version."""
        from ama_cryptography.secure_channel import (
            HandshakeError,
            HandshakeMessage,
            SecureChannelInitiator,
            SecureChannelResponder,
        )

        kem_pk, kem_sk = kem_keypair
        sig_pk, sig_sk = sig_keypair

        initiator = SecureChannelInitiator(kem_pk)
        responder = SecureChannelResponder(kem_sk, sig_sk, sig_pk)

        msg = initiator.create_handshake()
        bad_msg = HandshakeMessage(
            protocol_name=msg.protocol_name,
            version=b"\xff",
            ephemeral_public_key=msg.ephemeral_public_key,
            kem_ciphertext=msg.kem_ciphertext,
        )

        with pytest.raises(HandshakeError, match="Version mismatch"):
            responder.handle_handshake(bad_msg)

    def test_tampered_signature_rejected(
        self,
        kem_keypair: tuple[bytes, bytes],
        sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """Initiator rejects a response with a tampered signature."""
        from ama_cryptography.secure_channel import (
            HandshakeError,
            HandshakeResponse,
            SecureChannelInitiator,
            SecureChannelResponder,
        )

        kem_pk, kem_sk = kem_keypair
        sig_pk, sig_sk = sig_keypair

        initiator = SecureChannelInitiator(kem_pk)
        responder = SecureChannelResponder(kem_sk, sig_sk, sig_pk)

        handshake_msg = initiator.create_handshake()
        response, _ = responder.handle_handshake(handshake_msg)

        # Tamper with the signature
        tampered_sig = bytearray(response.signature)
        tampered_sig[0] ^= 0xFF
        bad_response = HandshakeResponse(
            session_id=response.session_id,
            signature=bytes(tampered_sig),
            responder_public_key=response.responder_public_key,
        )

        with pytest.raises(HandshakeError, match="signature verification failed"):
            initiator.complete_handshake(bad_response)

    def test_double_handshake_rejected(self, kem_keypair: tuple[bytes, bytes]) -> None:
        """Initiator rejects creating a second handshake."""
        from ama_cryptography.secure_channel import (
            ChannelError,
            SecureChannelInitiator,
        )

        kem_pk, _ = kem_keypair
        initiator = SecureChannelInitiator(kem_pk)
        initiator.create_handshake()

        with pytest.raises(ChannelError, match="Cannot create handshake"):
            initiator.create_handshake()


# ---------------------------------------------------------------------------
# Encrypt / Decrypt Tests
# ---------------------------------------------------------------------------


@skip_no_native
class TestSecureSessionEncryption:
    """Test SecureSession encrypt/decrypt operations."""

    def test_encrypt_decrypt_roundtrip(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Message encrypted by initiator can be decrypted by responder."""
        init_sess, resp_sess = established_session
        plaintext = b"Hello, Post-Quantum World!"

        msg = init_sess.encrypt(plaintext)
        decrypted = resp_sess.decrypt(msg)
        assert decrypted == plaintext

    def test_bidirectional_communication(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Both sides can send and receive messages."""
        init_sess, resp_sess = established_session

        # Initiator -> Responder
        msg1 = init_sess.encrypt(b"from initiator")
        assert resp_sess.decrypt(msg1) == b"from initiator"

        # Responder -> Initiator
        msg2 = resp_sess.encrypt(b"from responder")
        assert init_sess.decrypt(msg2) == b"from responder"

    def test_multiple_messages(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Multiple messages can be sent in sequence."""
        init_sess, resp_sess = established_session

        for i in range(10):
            plaintext = f"message {i}".encode()
            msg = init_sess.encrypt(plaintext)
            assert resp_sess.decrypt(msg) == plaintext

    def test_empty_plaintext(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Empty plaintext can be encrypted/decrypted (valid for AES-GCM)."""
        init_sess, resp_sess = established_session

        msg = init_sess.encrypt(b"")
        assert resp_sess.decrypt(msg) == b""

    def test_large_plaintext(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Large plaintext (up to MAX_MESSAGE_SIZE) works correctly."""
        init_sess, resp_sess = established_session
        plaintext = secrets.token_bytes(60000)

        msg = init_sess.encrypt(plaintext)
        assert resp_sess.decrypt(msg) == plaintext

    def test_max_message_size_exceeded(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Messages exceeding MAX_MESSAGE_SIZE are rejected."""
        init_sess, _ = established_session

        from ama_cryptography.secure_channel import MAX_MESSAGE_SIZE

        with pytest.raises(ValueError, match="Message too large"):
            init_sess.encrypt(b"\x00" * (MAX_MESSAGE_SIZE + 1))

    def test_sequence_numbers_increment(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Sequence numbers increment with each message."""
        init_sess, _ = established_session

        msg0 = init_sess.encrypt(b"a")
        msg1 = init_sess.encrypt(b"b")
        msg2 = init_sess.encrypt(b"c")

        assert msg0.sequence_number == 0
        assert msg1.sequence_number == 1
        assert msg2.sequence_number == 2


# ---------------------------------------------------------------------------
# Channel Message Serialization Tests
# ---------------------------------------------------------------------------


@skip_no_native
class TestChannelMessageSerialization:
    """Test ChannelMessage serialize/deserialize."""

    def test_roundtrip(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """ChannelMessage survives serialize/deserialize roundtrip."""
        from ama_cryptography.secure_channel import ChannelMessage

        init_sess, resp_sess = established_session
        msg = init_sess.encrypt(b"test data")

        wire = msg.serialize()
        restored = ChannelMessage.deserialize(wire)

        assert restored.session_id == msg.session_id
        assert restored.sequence_number == msg.sequence_number
        assert restored.nonce == msg.nonce
        assert restored.ciphertext == msg.ciphertext
        assert restored.tag == msg.tag

        # Deserialized message should still decrypt correctly
        assert resp_sess.decrypt(restored) == b"test data"

    def test_truncated_message_rejected(self) -> None:
        """Truncated wire data is rejected with ChannelError."""
        from ama_cryptography.secure_channel import ChannelError, ChannelMessage

        with pytest.raises(ChannelError, match="Truncated"):
            ChannelMessage.deserialize(b"\x00" * 10)

    def test_invalid_ct_len_rejected(self) -> None:
        """Message with ct_len exceeding available data is rejected."""
        from ama_cryptography.secure_channel import (
            NONCE_BYTES,
            SESSION_ID_BYTES,
            TAG_BYTES,
            ChannelError,
            ChannelMessage,
        )

        # Build a valid header but with ct_len pointing past the end
        data = (
            b"\x00" * SESSION_ID_BYTES  # session_id
            + struct.pack(">Q", 0)  # sequence
            + b"\x00" * NONCE_BYTES  # nonce
            + struct.pack(">I", 99999)  # ct_len (too large)
            + b"\x00" * TAG_BYTES  # tag (not enough ct data)
        )

        with pytest.raises(ChannelError, match="Truncated"):
            ChannelMessage.deserialize(data)


# ---------------------------------------------------------------------------
# Replay Detection Tests
# ---------------------------------------------------------------------------


@skip_no_native
class TestReplayDetection:
    """Test replay attack detection in SecureSession."""

    def test_replay_same_message_rejected(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Replaying the same ChannelMessage is rejected."""
        from ama_cryptography.secure_channel import ReplayError

        init_sess, resp_sess = established_session
        msg = init_sess.encrypt(b"original")

        # First decrypt succeeds
        resp_sess.decrypt(msg)

        # Replay: same message again
        with pytest.raises(ReplayError, match="already received"):
            resp_sess.decrypt(msg)

    def test_out_of_order_within_window_accepted(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Out-of-order messages within the replay window are accepted."""
        init_sess, resp_sess = established_session

        msg0 = init_sess.encrypt(b"msg0")
        msg1 = init_sess.encrypt(b"msg1")
        msg2 = init_sess.encrypt(b"msg2")

        # Receive out of order: 2, 0, 1
        assert resp_sess.decrypt(msg2) == b"msg2"
        assert resp_sess.decrypt(msg0) == b"msg0"
        assert resp_sess.decrypt(msg1) == b"msg1"

    def test_below_window_base_rejected(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Messages below the window base are rejected as too old."""
        from ama_cryptography.secure_channel import ReplayError

        init_sess, resp_sess = established_session

        # Send enough messages to push the window forward
        msgs = []
        for _ in range(300):
            msgs.append(init_sess.encrypt(b"x"))

        # Decrypt all to advance the window
        for m in msgs:
            resp_sess.decrypt(m)

        # Try to replay msgs[0] -- seq=0 is now below the window base
        with pytest.raises(ReplayError):
            resp_sess.decrypt(msgs[0])


# ---------------------------------------------------------------------------
# Tampering Detection Tests
# ---------------------------------------------------------------------------


@skip_no_native
class TestTamperingDetection:
    """Test that tampered messages are detected via AES-GCM authentication."""

    def test_tampered_ciphertext(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Flipping a bit in the ciphertext is detected."""
        from ama_cryptography.secure_channel import ChannelMessage

        init_sess, resp_sess = established_session
        msg = init_sess.encrypt(b"secret data")

        tampered_ct = bytearray(msg.ciphertext)
        tampered_ct[0] ^= 0xFF
        bad_msg = ChannelMessage(
            session_id=msg.session_id,
            sequence_number=msg.sequence_number,
            nonce=msg.nonce,
            ciphertext=bytes(tampered_ct),
            tag=msg.tag,
        )

        with pytest.raises(ValueError):
            resp_sess.decrypt(bad_msg)

    def test_tampered_tag(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Flipping a bit in the tag is detected."""
        from ama_cryptography.secure_channel import ChannelMessage

        init_sess, resp_sess = established_session
        msg = init_sess.encrypt(b"secret data")

        tampered_tag = bytearray(msg.tag)
        tampered_tag[0] ^= 0xFF
        bad_msg = ChannelMessage(
            session_id=msg.session_id,
            sequence_number=msg.sequence_number,
            nonce=msg.nonce,
            ciphertext=msg.ciphertext,
            tag=bytes(tampered_tag),
        )

        with pytest.raises(ValueError):
            resp_sess.decrypt(bad_msg)

    def test_wrong_session_id(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Message with wrong session_id is rejected."""
        from ama_cryptography.secure_channel import ChannelError, ChannelMessage

        init_sess, resp_sess = established_session
        msg = init_sess.encrypt(b"secret data")

        bad_msg = ChannelMessage(
            session_id=secrets.token_bytes(32),
            sequence_number=msg.sequence_number,
            nonce=msg.nonce,
            ciphertext=msg.ciphertext,
            tag=msg.tag,
        )

        with pytest.raises(ChannelError, match="Session ID mismatch"):
            resp_sess.decrypt(bad_msg)


# ---------------------------------------------------------------------------
# Session TTL / Expiration Tests
# ---------------------------------------------------------------------------


@skip_no_native
class TestSessionExpiration:
    """Test session time-to-live enforcement."""

    def test_expired_session_encrypt_rejected(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Encrypting on an expired session raises SessionExpiredError."""
        from ama_cryptography.secure_channel import SessionExpiredError

        init_sess, _ = established_session
        # Set TTL to 0 so it's immediately expired
        init_sess.ttl_seconds = 0.0

        with pytest.raises(SessionExpiredError, match="TTL expired"):
            init_sess.encrypt(b"too late")

    def test_expired_session_decrypt_rejected(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Decrypting on an expired session raises SessionExpiredError."""
        from ama_cryptography.secure_channel import SessionExpiredError

        init_sess, resp_sess = established_session
        msg = init_sess.encrypt(b"data")

        # Expire the responder session
        resp_sess.ttl_seconds = 0.0

        with pytest.raises(SessionExpiredError, match="TTL expired"):
            resp_sess.decrypt(msg)


# ---------------------------------------------------------------------------
# Re-keying Tests
# ---------------------------------------------------------------------------


@skip_no_native
class TestRekey:
    """Test session re-keying for forward secrecy."""

    def test_rekey_changes_keys(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """After rekey, session keys are different from before."""
        init_sess, resp_sess = established_session

        old_send = init_sess.send_key
        old_recv = init_sess.recv_key

        init_sess.rekey()
        resp_sess.rekey()

        assert init_sess.send_key != old_send
        assert init_sess.recv_key != old_recv

    def test_rekey_preserves_communication(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """After synchronized rekey, communication still works."""
        init_sess, resp_sess = established_session

        # Send a message before rekey
        msg1 = init_sess.encrypt(b"before rekey")
        assert resp_sess.decrypt(msg1) == b"before rekey"

        # Both sides rekey
        init_sess.rekey()
        resp_sess.rekey()

        # Send a message after rekey
        msg2 = init_sess.encrypt(b"after rekey")
        assert resp_sess.decrypt(msg2) == b"after rekey"

    def test_needs_rekey_threshold(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """needs_rekey returns True after REKEY_INTERVAL messages."""
        from ama_cryptography.secure_channel import REKEY_INTERVAL

        init_sess, _ = established_session
        init_sess.messages_since_rekey = REKEY_INTERVAL - 1
        assert not init_sess.needs_rekey()

        init_sess.messages_since_rekey = REKEY_INTERVAL
        assert init_sess.needs_rekey()

    def test_rekey_resets_counter(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Rekey resets the messages_since_rekey counter."""
        init_sess, _ = established_session
        init_sess.messages_since_rekey = 500
        init_sess.rekey()
        assert init_sess.messages_since_rekey == 0

    def test_rekey_resets_send_counter(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Rekey resets the per-epoch encryption budget."""
        init_sess, _ = established_session
        init_sess.sends_since_rekey = 500
        init_sess.rekey()
        assert init_sess.sends_since_rekey == 0

    def test_encrypt_refuses_past_epoch_budget(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """encrypt() fails closed once MAX_ENCRYPTIONS_PER_EPOCH is reached.

        Regression guard: encrypt() previously never consulted the rekey
        state at all, so a long-lived session kept drawing random 96-bit
        nonces under one key indefinitely and the collision probability grew
        without bound.
        """
        from ama_cryptography.secure_channel import (
            MAX_ENCRYPTIONS_PER_EPOCH,
            RekeyRequiredError,
        )

        init_sess, resp_sess = established_session

        # One under the cap: still allowed, and still decryptable.
        init_sess.sends_since_rekey = MAX_ENCRYPTIONS_PER_EPOCH - 1
        msg = init_sess.encrypt(b"last one")
        assert resp_sess.decrypt(msg) == b"last one"
        assert init_sess.sends_since_rekey == MAX_ENCRYPTIONS_PER_EPOCH

        # At the cap: refused.
        with pytest.raises(RekeyRequiredError, match="per-epoch encryption limit"):
            init_sess.encrypt(b"one too many")

        # The refusal must not consume a sequence number or leave the
        # session wedged — a rekey on both peers restores service.
        seq_before = init_sess.send_seq
        with pytest.raises(RekeyRequiredError):
            init_sess.encrypt(b"still refused")
        assert init_sess.send_seq == seq_before

        init_sess.rekey()
        resp_sess.rekey()
        recovered = init_sess.encrypt(b"after rekey")
        assert resp_sess.decrypt(recovered) == b"after rekey"

    def test_decrypt_is_not_capped(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """The budget binds the sender only.

        Nonces are drawn in encrypt(), so the collision bound is a property
        of the sending side. Rejecting on receive would break a peer running
        an older build without making this side any safer.
        """
        from ama_cryptography.secure_channel import MAX_ENCRYPTIONS_PER_EPOCH

        init_sess, resp_sess = established_session
        msg = init_sess.encrypt(b"payload")

        resp_sess.sends_since_rekey = MAX_ENCRYPTIONS_PER_EPOCH
        assert resp_sess.decrypt(msg) == b"payload"

    def test_soft_threshold_warns_once_per_epoch(
        self,
        established_session: tuple[SecureSession, SecureSession],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Crossing REKEY_INTERVAL logs exactly one advisory per epoch."""
        from ama_cryptography.secure_channel import REKEY_INTERVAL

        init_sess, resp_sess = established_session
        init_sess.messages_since_rekey = REKEY_INTERVAL - 1

        with caplog.at_level("WARNING", logger="ama_cryptography.secure_channel"):
            init_sess.encrypt(b"crosses the threshold")
            init_sess.encrypt(b"already warned")
            init_sess.encrypt(b"still warned")

        advisories = [r for r in caplog.records if "without a rekey" in r.getMessage()]
        assert len(advisories) == 1

        # A rekey re-arms the latch for the next epoch.
        caplog.clear()
        init_sess.rekey()
        resp_sess.rekey()
        init_sess.messages_since_rekey = REKEY_INTERVAL - 1
        with caplog.at_level("WARNING", logger="ama_cryptography.secure_channel"):
            init_sess.encrypt(b"next epoch")
        assert sum("without a rekey" in r.getMessage() for r in caplog.records) == 1

    def test_multiple_rekeys_preserve_communication(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Communication survives multiple consecutive rekeys."""
        init_sess, resp_sess = established_session

        for i in range(5):
            plaintext = f"round {i}".encode()
            msg = init_sess.encrypt(plaintext)
            assert resp_sess.decrypt(msg) == plaintext

            init_sess.rekey()
            resp_sess.rekey()

        # Final message after 5 rekeys
        final_msg = init_sess.encrypt(b"final")
        assert resp_sess.decrypt(final_msg) == b"final"


# ---------------------------------------------------------------------------
# Session Close Tests
# ---------------------------------------------------------------------------


@skip_no_native
class TestSessionClose:
    """Test session close behavior."""

    def test_close_zeroes_keys(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Closing a session zeroes the key material."""
        from ama_cryptography.secure_channel import KEY_BYTES, ChannelState

        init_sess, _ = established_session
        init_sess.close()

        assert init_sess._state == ChannelState.CLOSED
        assert init_sess.send_key == b"\x00" * KEY_BYTES
        assert init_sess.recv_key == b"\x00" * KEY_BYTES

    def test_encrypt_after_close_rejected(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Encrypting after close raises ChannelError."""
        from ama_cryptography.secure_channel import ChannelError

        init_sess, _ = established_session
        init_sess.close()

        with pytest.raises(ChannelError, match="Cannot encrypt"):
            init_sess.encrypt(b"too late")

    def test_decrypt_after_close_rejected(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Decrypting after close raises ChannelError."""
        from ama_cryptography.secure_channel import ChannelError

        init_sess, resp_sess = established_session
        msg = init_sess.encrypt(b"data")

        resp_sess.close()

        with pytest.raises(ChannelError, match="Cannot decrypt"):
            resp_sess.decrypt(msg)


# ---------------------------------------------------------------------------
# Phase 4A: Additional Adversarial Test Classes
# ---------------------------------------------------------------------------


@skip_no_native
class TestRekeyDesync:
    """Test rekey desynchronization and recovery."""

    def test_rekey_one_side_only_fails(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Rekeying only one side causes decryption failure."""
        init_sess, resp_sess = established_session

        # Rekey initiator only
        init_sess.rekey()

        # Encrypt with new keys
        msg = init_sess.encrypt(b"after one-sided rekey")

        # Decrypt with old keys should fail (tag mismatch)
        with pytest.raises((ValueError, RuntimeError)):
            resp_sess.decrypt(msg)

    def test_rekey_desync_recovery(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """After desync, rekeying both sides restores communication."""
        init_sess, resp_sess = established_session

        # Desync: rekey initiator only
        init_sess.rekey()

        # Now rekey responder to resync
        resp_sess.rekey()

        # Communication should work again
        msg = init_sess.encrypt(b"resynced")
        assert resp_sess.decrypt(msg) == b"resynced"

    def test_double_rekey_one_side(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Double-rekeying one side diverges further."""
        init_sess, resp_sess = established_session

        init_sess.rekey()
        init_sess.rekey()

        msg = init_sess.encrypt(b"double rekey")

        # Single rekey on responder should still fail
        resp_sess.rekey()
        with pytest.raises((ValueError, RuntimeError)):
            resp_sess.decrypt(msg)

        # Second rekey on responder to match
        resp_sess.rekey()
        msg2 = init_sess.encrypt(b"now synced")
        assert resp_sess.decrypt(msg2) == b"now synced"


@skip_no_native
class TestSessionTTLEdgeCases:
    """Test TTL edge cases."""

    def test_ttl_zero_immediately_expired(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """TTL=0 means session is immediately expired."""
        from ama_cryptography.secure_channel import SessionExpiredError

        init_sess, _ = established_session
        init_sess.ttl_seconds = 0.0

        with pytest.raises(SessionExpiredError):
            init_sess.encrypt(b"expired")

    def test_ttl_very_large_not_expired(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Very large TTL does not expire."""
        init_sess, resp_sess = established_session
        init_sess.ttl_seconds = 999999.0
        resp_sess.ttl_seconds = 999999.0

        msg = init_sess.encrypt(b"long lived")
        assert resp_sess.decrypt(msg) == b"long lived"


@skip_no_native
class TestMaxMessageSize:
    """Test message size limits."""

    def test_encrypt_max_size(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Encrypting exactly MAX_MESSAGE_SIZE bytes succeeds."""
        from ama_cryptography.secure_channel import MAX_MESSAGE_SIZE

        init_sess, resp_sess = established_session
        data = b"\xaa" * MAX_MESSAGE_SIZE
        msg = init_sess.encrypt(data)
        assert resp_sess.decrypt(msg) == data

    def test_encrypt_over_max_size_rejected(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Encrypting MAX_MESSAGE_SIZE + 1 bytes raises ValueError."""
        from ama_cryptography.secure_channel import MAX_MESSAGE_SIZE

        init_sess, _ = established_session
        data = b"\xaa" * (MAX_MESSAGE_SIZE + 1)
        with pytest.raises(ValueError, match=r"[Mm]essage too large"):
            init_sess.encrypt(data)


@skip_no_native
class TestReplayWindowExhaustion:
    """Test replay window behavior under heavy message load."""

    def test_window_exhaustion_rejects_old(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """After 257+ messages, old sequence numbers are rejected."""
        from ama_cryptography.secure_channel import ReplayError

        init_sess, resp_sess = established_session

        # Send 257 messages (window size is 256)
        msgs = []
        for _ in range(257):
            m = init_sess.encrypt(b"x")
            msgs.append(m)
            resp_sess.decrypt(m)

        # First message (seq=0) should now be below window base
        with pytest.raises(ReplayError):
            resp_sess.decrypt(msgs[0])

    def test_replay_within_window_detected(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Replaying a recent message within window is detected."""
        from ama_cryptography.secure_channel import ReplayError

        init_sess, resp_sess = established_session

        msg = init_sess.encrypt(b"once")
        resp_sess.decrypt(msg)

        with pytest.raises(ReplayError):
            resp_sess.decrypt(msg)


@skip_no_native
class TestConcurrentEncryptDecrypt:
    """Test concurrent encrypt/decrypt on a session."""

    def test_concurrent_encrypt(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """Multiple encrypts produce unique messages."""
        init_sess, resp_sess = established_session

        msgs = [init_sess.encrypt(f"msg-{i}".encode()) for i in range(10)]

        # Each message should have a unique sequence number
        seqs = [m.sequence_number for m in msgs]
        assert len(set(seqs)) == 10

        # All should decrypt successfully
        for i, m in enumerate(msgs):
            pt = resp_sess.decrypt(m)
            assert pt == f"msg-{i}".encode()


@skip_no_native
class TestSessionReprDoesNotLeakKeys:
    """The dataclass repr must not print the live AES-256 session keys.

    Regression: ``SecureSession`` declared ``send_key`` / ``recv_key`` as
    ordinary dataclass fields, so the generated ``__repr__`` rendered both in
    full. That reaches far more places than a deliberate print — a logger
    called with the session as an argument, a traceback showing locals, ``%r``
    in a debug line. ``crypto_api.KeyPair.secret_key`` already carried
    ``repr=False`` for the same reason.
    """

    def test_repr_omits_both_keys(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        init_sess, _ = established_session
        text = repr(init_sess)

        # Non-vacuity: the session really is holding key material, so its
        # absence from the repr is suppression rather than an empty session.
        assert len(init_sess.send_key) == 32
        assert len(init_sess.recv_key) == 32

        assert bytes(init_sess.send_key).hex() not in text
        assert bytes(init_sess.recv_key).hex() not in text
        assert "send_key" not in text
        assert "recv_key" not in text

        # Fields worth seeing in a log line are still there.
        assert "send_seq" in text
        assert "rekey_epoch" in text

    def test_keys_remain_usable_after_repr_suppression(
        self,
        established_session: tuple[SecureSession, SecureSession],
    ) -> None:
        """repr=False changes presentation only, never the field itself."""
        init_sess, resp_sess = established_session
        repr(init_sess)
        assert resp_sess.decrypt(init_sess.encrypt(b"still works")) == b"still works"
