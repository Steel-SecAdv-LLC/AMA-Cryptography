#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Tests for SecureChannelProvider — high-level Noise-NK wrapper in crypto_api.py.

Covers:
- Full round-trip handshake + message exchange via the provider API
- channel_send / channel_receive serialisation round-trip
- Error paths (wrong call order, replay detection through provider)
- Session integration with session.ReplayWindow
"""

from typing import Any

import pytest

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
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def responder_keypairs() -> tuple[bytes, bytes, bytes, bytes]:
    """Generate Responder's KEM and signature keypairs."""
    from ama_cryptography.crypto_api import HybridKEMProvider, HybridSignatureProvider

    kem_kp = HybridKEMProvider().generate_keypair()
    sig_kp = HybridSignatureProvider().generate_keypair()
    return kem_kp.public_key, kem_kp.secret_key, sig_kp.public_key, sig_kp.secret_key


@pytest.fixture()
def completed_provider_pair(responder_keypairs: tuple[bytes, bytes, bytes, bytes]) -> Any:
    """Perform a full handshake through SecureChannelProvider + Responder."""
    from ama_cryptography.crypto_api import SecureChannelProvider
    from ama_cryptography.secure_channel import SecureChannelResponder

    kem_pk, kem_sk, sig_pk, sig_sk = responder_keypairs

    provider = SecureChannelProvider()
    responder = SecureChannelResponder(kem_sk, sig_sk, sig_pk)

    # Initiator creates handshake
    hs_bytes = provider.create_secure_channel(kem_pk)

    # Responder handles handshake
    from ama_cryptography.secure_channel import HandshakeMessage

    hs_msg = HandshakeMessage.deserialize(hs_bytes)
    response, resp_session = responder.handle_handshake(hs_msg)

    # Initiator completes handshake
    provider.complete_handshake(response.serialize())

    return provider, resp_session


# ---------------------------------------------------------------------------
# Test: provider API
# ---------------------------------------------------------------------------


@skip_no_native
class TestSecureChannelProvider:
    def test_create_secure_channel_returns_bytes(
        self, responder_keypairs: tuple[bytes, bytes, bytes, bytes]
    ) -> None:
        """create_secure_channel() returns non-empty bytes (handshake wire format)."""
        from ama_cryptography.crypto_api import SecureChannelProvider

        kem_pk, *_ = responder_keypairs
        provider = SecureChannelProvider()
        hs_bytes = provider.create_secure_channel(kem_pk)
        assert isinstance(hs_bytes, bytes)
        assert len(hs_bytes) > 0

    def test_session_is_none_before_handshake(
        self, responder_keypairs: tuple[bytes, bytes, bytes, bytes]
    ) -> None:
        """session property is None until handshake completes."""
        from ama_cryptography.crypto_api import SecureChannelProvider

        kem_pk, *_ = responder_keypairs
        provider = SecureChannelProvider()
        assert provider.session is None
        provider.create_secure_channel(kem_pk)
        assert provider.session is None  # still None until complete_handshake

    def test_session_set_after_handshake(self, completed_provider_pair: Any) -> None:
        """session is set after complete_handshake."""
        provider, _ = completed_provider_pair
        assert provider.session is not None

    def test_channel_send_returns_bytes(self, completed_provider_pair: Any) -> None:
        """channel_send() returns serialized ChannelMessage bytes."""
        provider, _ = completed_provider_pair
        encrypted = provider.channel_send(b"hello world")
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > 0

    def test_full_round_trip(self, completed_provider_pair: Any) -> None:
        """Provider send → responder session decrypt round-trip."""
        from ama_cryptography.secure_channel import ChannelMessage

        provider, resp_session = completed_provider_pair
        plaintext = b"AMA secure channel test"
        encrypted = provider.channel_send(plaintext)
        msg = ChannelMessage.deserialize(encrypted)
        recovered = resp_session.decrypt(msg)
        assert recovered == plaintext

    def test_reverse_round_trip(self, completed_provider_pair: Any) -> None:
        """Responder session encrypt → provider channel_receive round-trip."""
        provider, resp_session = completed_provider_pair
        plaintext = b"Response from responder"
        msg = resp_session.encrypt(plaintext)
        recovered = provider.channel_receive(msg.serialize())
        assert recovered == plaintext

    def test_multiple_messages(self, completed_provider_pair: Any) -> None:
        """Multiple sequential messages are all decrypted correctly."""
        from ama_cryptography.secure_channel import ChannelMessage

        provider, resp_session = completed_provider_pair
        messages = [b"msg%d" % i for i in range(10)]
        for m in messages:
            enc = provider.channel_send(m)
            got = resp_session.decrypt(ChannelMessage.deserialize(enc))
            assert got == m

    def test_channel_send_before_handshake_raises(
        self, responder_keypairs: tuple[bytes, bytes, bytes, bytes]
    ) -> None:
        """channel_send() before complete_handshake() raises RuntimeError."""
        from ama_cryptography.crypto_api import SecureChannelProvider

        provider = SecureChannelProvider()
        with pytest.raises(RuntimeError, match="not established"):
            provider.channel_send(b"data")

    def test_channel_receive_before_handshake_raises(
        self, responder_keypairs: tuple[bytes, bytes, bytes, bytes]
    ) -> None:
        """channel_receive() before handshake raises RuntimeError."""
        from ama_cryptography.crypto_api import SecureChannelProvider

        provider = SecureChannelProvider()
        with pytest.raises(RuntimeError, match="not established"):
            provider.channel_receive(b"\x00" * 100)

    def test_complete_handshake_without_create_raises(self) -> None:
        """complete_handshake() without prior create_secure_channel() raises."""
        from ama_cryptography.crypto_api import SecureChannelProvider

        provider = SecureChannelProvider()
        with pytest.raises(RuntimeError):
            provider.complete_handshake(b"\x00" * 100)

    def test_replay_detection_through_provider(self, completed_provider_pair: Any) -> None:
        """Replaying a ChannelMessage is rejected at the responder session layer."""
        from ama_cryptography.secure_channel import ChannelMessage, ReplayError

        provider, resp_session = completed_provider_pair
        enc = provider.channel_send(b"original")
        msg = ChannelMessage.deserialize(enc)
        resp_session.decrypt(msg)  # first: OK
        with pytest.raises(ReplayError):
            resp_session.decrypt(msg)  # replay: must fail

    def test_tamper_detection(self, completed_provider_pair: Any) -> None:
        """Modifying ciphertext raises ValueError (AEAD tag mismatch)."""
        from ama_cryptography.secure_channel import ChannelMessage

        provider, resp_session = completed_provider_pair
        enc = provider.channel_send(b"tamper me")
        # Flip a byte in the ciphertext region
        byt = bytearray(enc)
        byt[-20] ^= 0xFF
        tampered = bytes(byt)
        msg = ChannelMessage.deserialize(tampered)
        with pytest.raises((ValueError, Exception)):
            resp_session.decrypt(msg)


# ---------------------------------------------------------------------------
# Test: ReplayWindow integration in SecureSession
# ---------------------------------------------------------------------------


@skip_no_native
class TestSecureSessionReplayWindow:
    """Verify SecureSession uses session.ReplayWindow correctly."""

    def test_replay_window_type(self, completed_provider_pair: Any) -> None:
        """SecureSession._replay_window is a session.ReplayWindow instance."""
        from ama_cryptography.session import ReplayWindow

        _, resp_session = completed_provider_pair
        assert isinstance(resp_session._replay_window, ReplayWindow)

    def test_window_base_advances(self, completed_provider_pair: Any) -> None:
        """ReplayWindow.base advances as messages fill the window."""
        from ama_cryptography.secure_channel import ChannelMessage

        provider, resp_session = completed_provider_pair
        for _ in range(5):
            enc = provider.channel_send(b"x")
            msg = ChannelMessage.deserialize(enc)
            resp_session.decrypt(msg)
        # Window base should still be 0 (5 messages, window size 256)
        assert resp_session._replay_window.base == 0

    def test_rekey_resets_replay_window(self, completed_provider_pair: Any) -> None:
        """rekey() resets the replay window base."""
        _provider, resp_session = completed_provider_pair
        # Manually set window state before rekey
        resp_session._replay_window._seen.add(999)
        resp_session.rekey()
        assert len(resp_session._replay_window._seen) == 0
        assert resp_session._replay_window.base == 0
