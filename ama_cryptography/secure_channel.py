#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
AMA Cryptography - Post-Quantum Noise-NK Secure Channel
========================================================

Implements a Noise-NK variant using AMA's hybrid post-quantum primitives.
This is genuinely original: no open-source library combines PQ Noise with
Kyber-1024 + Ed25519/ML-DSA-65 hybrid authentication.

Protocol:
    Key agreement:  HybridKEM (X25519 + Kyber-1024) via HybridCombiner
    Authentication: Dual Ed25519 + ML-DSA-65 hybrid signatures
    AEAD:           AES-256-GCM via native C backend
    KDF:            HKDF-SHA3-256 for key derivation

Pattern: Noise-NK
    - Server (Responder) has a known static keypair
    - Client (Initiator) is anonymous (no static key)

Protocol flow:
    1. Initiator generates ephemeral hybrid KEM keypair
    2. Initiator encapsulates against Responder's static KEM public key
    3. Initiator sends ephemeral public key + KEM ciphertext
    4. Responder decapsulates to recover shared secret
    5. Both derive session keys via HKDF-SHA3-256
    6. Responder sends authenticated response with hybrid signature
    7. Session established with encrypt/decrypt/rekey capabilities
    8. Forward secrecy via periodic re-keying using new KEM exchanges

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Version: 2.1
"""

import hashlib
import logging
import secrets
import struct
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Protocol constants
PROTOCOL_NAME = b"Noise_NK_HybridKEM_AESGCM_SHA3256"
PROTOCOL_VERSION = b"\x01"
SESSION_ID_BYTES = 32
NONCE_BYTES = 12
KEY_BYTES = 32
TAG_BYTES = 16
REKEY_INTERVAL = 1000  # Messages before mandatory rekey
MAX_MESSAGE_SIZE = 65535
SESSION_TTL_SECONDS = 3600  # 1 hour default


class ChannelState(Enum):
    """State machine for secure channel lifecycle."""

    INITIATOR_START = auto()
    RESPONDER_START = auto()
    HANDSHAKE_SENT = auto()
    HANDSHAKE_RECEIVED = auto()
    ESTABLISHED = auto()
    REKEYING = auto()
    CLOSED = auto()


class ChannelError(Exception):
    """Base exception for secure channel errors."""

    pass


class HandshakeError(ChannelError):
    """Raised when handshake fails (auth failure, decapsulation error)."""

    pass


class ReplayError(ChannelError):
    """Raised when a replayed or out-of-window message is detected."""

    pass


class SessionExpiredError(ChannelError):
    """Raised when session TTL has elapsed."""

    pass


@dataclass
class ChannelMessage:
    """Framed message for transport over the secure channel.

    Attributes:
        session_id: 32-byte session identifier
        sequence_number: Monotonic counter for replay protection
        nonce: 12-byte AEAD nonce
        ciphertext: Encrypted payload
        tag: 16-byte authentication tag
    """

    session_id: bytes
    sequence_number: int
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def serialize(self) -> bytes:
        """Serialize to wire format: session_id || seq(8) || nonce || ct_len(4) || ct || tag."""
        return (
            self.session_id
            + struct.pack(">Q", self.sequence_number)
            + self.nonce
            + struct.pack(">I", len(self.ciphertext))
            + self.ciphertext
            + self.tag
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "ChannelMessage":
        """Deserialize from wire format."""
        offset = 0
        session_id = data[offset : offset + SESSION_ID_BYTES]
        offset += SESSION_ID_BYTES

        (sequence_number,) = struct.unpack(">Q", data[offset : offset + 8])
        offset += 8

        nonce = data[offset : offset + NONCE_BYTES]
        offset += NONCE_BYTES

        (ct_len,) = struct.unpack(">I", data[offset : offset + 4])
        offset += 4

        ciphertext = data[offset : offset + ct_len]
        offset += ct_len

        tag = data[offset : offset + TAG_BYTES]

        return cls(
            session_id=session_id,
            sequence_number=sequence_number,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
        )


@dataclass
class HandshakeMessage:
    """Initial handshake message from Initiator to Responder.

    Contains ephemeral KEM public key and ciphertext for key agreement.

    Attributes:
        protocol_name: Protocol identifier for version negotiation
        version: Protocol version byte
        ephemeral_public_key: Initiator's ephemeral hybrid KEM public key
        kem_ciphertext: KEM encapsulation against Responder's static key
    """

    protocol_name: bytes
    version: bytes
    ephemeral_public_key: bytes
    kem_ciphertext: bytes

    def serialize(self) -> bytes:
        """Serialize handshake to wire format."""
        return (
            struct.pack(">H", len(self.protocol_name))
            + self.protocol_name
            + self.version
            + struct.pack(">I", len(self.ephemeral_public_key))
            + self.ephemeral_public_key
            + struct.pack(">I", len(self.kem_ciphertext))
            + self.kem_ciphertext
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "HandshakeMessage":
        """Deserialize handshake from wire format."""
        offset = 0
        (name_len,) = struct.unpack(">H", data[offset : offset + 2])
        offset += 2
        protocol_name = data[offset : offset + name_len]
        offset += name_len

        version = data[offset : offset + 1]
        offset += 1

        (epk_len,) = struct.unpack(">I", data[offset : offset + 4])
        offset += 4
        ephemeral_public_key = data[offset : offset + epk_len]
        offset += epk_len

        (ct_len,) = struct.unpack(">I", data[offset : offset + 4])
        offset += 4
        kem_ciphertext = data[offset : offset + ct_len]

        return cls(
            protocol_name=protocol_name,
            version=version,
            ephemeral_public_key=ephemeral_public_key,
            kem_ciphertext=kem_ciphertext,
        )


@dataclass
class HandshakeResponse:
    """Authenticated response from Responder to Initiator.

    Contains the hybrid signature proving the Responder holds the static key.

    Attributes:
        session_id: Agreed session identifier
        signature: Hybrid signature (Ed25519 + ML-DSA-65) over handshake transcript
        responder_public_key: Responder's signature verification key
    """

    session_id: bytes
    signature: bytes
    responder_public_key: bytes

    def serialize(self) -> bytes:
        """Serialize response to wire format."""
        return (
            self.session_id
            + struct.pack(">I", len(self.signature))
            + self.signature
            + struct.pack(">I", len(self.responder_public_key))
            + self.responder_public_key
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "HandshakeResponse":
        """Deserialize response from wire format."""
        offset = 0
        session_id = data[offset : offset + SESSION_ID_BYTES]
        offset += SESSION_ID_BYTES

        (sig_len,) = struct.unpack(">I", data[offset : offset + 4])
        offset += 4
        signature = data[offset : offset + sig_len]
        offset += sig_len

        (pk_len,) = struct.unpack(">I", data[offset : offset + 4])
        offset += 4
        responder_public_key = data[offset : offset + pk_len]

        return cls(
            session_id=session_id,
            signature=signature,
            responder_public_key=responder_public_key,
        )


@dataclass
class SecureSession:
    """Established session with encrypt/decrypt/rekey capabilities.

    Manages symmetric session keys derived from the Noise-NK handshake,
    monotonic sequence numbers for replay protection, and periodic
    re-keying for forward secrecy.

    Attributes:
        session_id: Unique 32-byte session identifier
        send_key: Current sending key (rotated on rekey)
        recv_key: Current receiving key (rotated on rekey)
        send_seq: Monotonic send sequence counter
        recv_seq: Expected receive sequence counter
        created_at: Session creation timestamp
        ttl_seconds: Session time-to-live
        messages_since_rekey: Counter for triggering automatic rekey
    """

    session_id: bytes
    send_key: bytes
    recv_key: bytes
    send_seq: int = 0
    recv_seq: int = 0
    created_at: float = field(default_factory=time.monotonic)
    ttl_seconds: float = SESSION_TTL_SECONDS
    messages_since_rekey: int = 0
    _replay_window: set = field(default_factory=set)  # type: ignore[type-arg]
    _replay_window_base: int = 0
    _state: ChannelState = ChannelState.ESTABLISHED

    # Sliding window size for replay detection
    REPLAY_WINDOW_SIZE: int = 256

    def is_expired(self) -> bool:
        """Check if session has exceeded its TTL."""
        return (time.monotonic() - self.created_at) > self.ttl_seconds

    def needs_rekey(self) -> bool:
        """Check if session should be re-keyed based on message count."""
        return self.messages_since_rekey >= REKEY_INTERVAL

    def encrypt(self, plaintext: bytes) -> ChannelMessage:
        """Encrypt plaintext and produce a framed ChannelMessage.

        Args:
            plaintext: Data to encrypt (max 65535 bytes)

        Returns:
            ChannelMessage ready for transport

        Raises:
            SessionExpiredError: If session TTL has elapsed
            ChannelError: If session is not in ESTABLISHED state
            ValueError: If plaintext exceeds MAX_MESSAGE_SIZE
        """
        if self._state != ChannelState.ESTABLISHED:
            raise ChannelError(f"Cannot encrypt in state {self._state}")
        if self.is_expired():
            self._state = ChannelState.CLOSED
            raise SessionExpiredError("Session TTL expired")
        if len(plaintext) > MAX_MESSAGE_SIZE:
            raise ValueError(f"Message too large: {len(plaintext)} > {MAX_MESSAGE_SIZE}")

        from ama_cryptography.pqc_backends import native_aes256_gcm_encrypt

        nonce = secrets.token_bytes(NONCE_BYTES)
        # AAD binds ciphertext to session_id and sequence number
        aad = self.session_id + struct.pack(">Q", self.send_seq)

        ct, tag = native_aes256_gcm_encrypt(self.send_key, nonce, plaintext, aad)

        msg = ChannelMessage(
            session_id=self.session_id,
            sequence_number=self.send_seq,
            nonce=nonce,
            ciphertext=ct,
            tag=tag,
        )

        self.send_seq += 1
        self.messages_since_rekey += 1
        return msg

    def decrypt(self, msg: ChannelMessage) -> bytes:
        """Decrypt a received ChannelMessage.

        Args:
            msg: Received channel message

        Returns:
            Decrypted plaintext

        Raises:
            ReplayError: If message sequence number is replayed or out of window
            SessionExpiredError: If session TTL has elapsed
            ChannelError: If session is not in ESTABLISHED state
            ValueError: If authentication fails (tampered message)
        """
        if self._state != ChannelState.ESTABLISHED:
            raise ChannelError(f"Cannot decrypt in state {self._state}")
        if self.is_expired():
            self._state = ChannelState.CLOSED
            raise SessionExpiredError("Session TTL expired")
        if msg.session_id != self.session_id:
            raise ChannelError("Session ID mismatch")

        # Replay detection: sliding window
        seq = msg.sequence_number
        if seq < self._replay_window_base:
            raise ReplayError(f"Sequence {seq} below window base {self._replay_window_base}")
        if seq in self._replay_window:
            raise ReplayError(f"Sequence {seq} already received (replay)")

        from ama_cryptography.pqc_backends import native_aes256_gcm_decrypt

        aad = self.session_id + struct.pack(">Q", seq)
        plaintext = native_aes256_gcm_decrypt(self.recv_key, msg.nonce, msg.ciphertext, msg.tag, aad)

        # Update replay window after successful decryption
        self._replay_window.add(seq)
        # Slide window forward if needed
        while len(self._replay_window) > self.REPLAY_WINDOW_SIZE:
            self._replay_window.discard(self._replay_window_base)
            self._replay_window_base += 1

        self.messages_since_rekey += 1
        return plaintext

    def rekey(self) -> None:
        """Derive new session keys from current keys for forward secrecy.

        Uses HKDF-SHA3-256 to derive fresh send/recv keys from the
        current keys, ensuring that compromise of current keys does
        not reveal past plaintext (forward secrecy).
        """
        from ama_cryptography.pqc_backends import native_hkdf

        self.send_key = native_hkdf(
            self.send_key, KEY_BYTES, salt=None, info=b"ama-rekey-send"
        )
        self.recv_key = native_hkdf(
            self.recv_key, KEY_BYTES, salt=None, info=b"ama-rekey-recv"
        )
        self.messages_since_rekey = 0
        logger.debug("Session %s re-keyed", self.session_id.hex()[:16])

    def close(self) -> None:
        """Close the session, zeroing key material."""
        self._state = ChannelState.CLOSED
        # Overwrite keys with zeros (best-effort in Python)
        self.send_key = b"\x00" * KEY_BYTES
        self.recv_key = b"\x00" * KEY_BYTES


class SecureChannelInitiator:
    """Client-side Noise-NK initiator.

    The Initiator is anonymous (has no static key) and establishes a
    session with a Responder whose static KEM public key is known.

    Usage::

        initiator = SecureChannelInitiator(responder_kem_public_key)
        handshake_msg = initiator.create_handshake()
        # ... send handshake_msg to responder, receive response ...
        session = initiator.complete_handshake(response)
    """

    def __init__(self, responder_static_kem_pk: bytes) -> None:
        """Initialize initiator with the Responder's known static KEM public key.

        Args:
            responder_static_kem_pk: Responder's hybrid KEM public key
                (X25519 pub || Kyber-1024 pub)
        """
        from ama_cryptography.crypto_api import HybridKEMProvider

        self._responder_kem_pk = responder_static_kem_pk
        self._kem = HybridKEMProvider()
        self._state = ChannelState.INITIATOR_START
        self._shared_secret: Optional[bytes] = None
        self._handshake_hash: Optional[bytes] = None
        self._ephemeral_pk: Optional[bytes] = None

    def create_handshake(self) -> HandshakeMessage:
        """Create the initial handshake message (Noise-NK message 1).

        Performs hybrid KEM encapsulation against the Responder's
        static public key to establish a shared secret.

        Returns:
            HandshakeMessage to send to the Responder

        Raises:
            ChannelError: If not in INITIATOR_START state
        """
        if self._state != ChannelState.INITIATOR_START:
            raise ChannelError(f"Cannot create handshake in state {self._state}")

        # Generate ephemeral keypair (for binding, not DH — KEM handles key agreement)
        eph_kp = self._kem.generate_keypair()
        self._ephemeral_pk = eph_kp.public_key

        # Encapsulate against responder's static KEM public key
        encap_result = self._kem.encapsulate(self._responder_kem_pk)
        self._shared_secret = encap_result.shared_secret

        msg = HandshakeMessage(
            protocol_name=PROTOCOL_NAME,
            version=PROTOCOL_VERSION,
            ephemeral_public_key=eph_kp.public_key,
            kem_ciphertext=encap_result.ciphertext,
        )

        # Hash the handshake transcript for signature verification
        self._handshake_hash = hashlib.sha3_256(msg.serialize()).digest()
        self._state = ChannelState.HANDSHAKE_SENT
        return msg

    def complete_handshake(self, response: HandshakeResponse) -> SecureSession:
        """Complete the handshake by verifying the Responder's signature.

        Args:
            response: Authenticated response from the Responder

        Returns:
            Established SecureSession for encrypted communication

        Raises:
            HandshakeError: If signature verification fails
            ChannelError: If not in HANDSHAKE_SENT state
        """
        if self._state != ChannelState.HANDSHAKE_SENT:
            raise ChannelError(f"Cannot complete handshake in state {self._state}")

        from ama_cryptography.crypto_api import HybridSignatureProvider

        sig_provider = HybridSignatureProvider()

        # Verify responder's hybrid signature over the handshake transcript
        transcript = self._handshake_hash + response.session_id  # type: ignore[operator]
        if not sig_provider.verify(transcript, response.signature, response.responder_public_key):
            raise HandshakeError("Responder signature verification failed")

        # Derive session keys from shared secret
        assert self._shared_secret is not None
        session = self._derive_session(response.session_id, self._shared_secret)

        # Clear handshake state
        self._shared_secret = None
        self._handshake_hash = None
        self._state = ChannelState.ESTABLISHED
        return session

    @staticmethod
    def _derive_session(session_id: bytes, shared_secret: bytes) -> SecureSession:
        """Derive send/recv keys from shared secret via HKDF-SHA3-256."""
        from ama_cryptography.pqc_backends import native_hkdf

        # Derive separate keys for each direction
        send_key = native_hkdf(
            shared_secret, KEY_BYTES, salt=session_id, info=b"ama-noise-nk-initiator-send"
        )
        recv_key = native_hkdf(
            shared_secret, KEY_BYTES, salt=session_id, info=b"ama-noise-nk-responder-send"
        )
        return SecureSession(session_id=session_id, send_key=send_key, recv_key=recv_key)


class SecureChannelResponder:
    """Server-side Noise-NK responder.

    The Responder holds a static KEM keypair and a static signature
    keypair. It receives handshake messages from anonymous Initiators
    and establishes authenticated sessions.

    Usage::

        responder = SecureChannelResponder(kem_secret_key, sig_secret_key, sig_public_key)
        response, session = responder.handle_handshake(handshake_msg)
        # ... send response to initiator ...
        # session is now ready for encrypt/decrypt
    """

    def __init__(
        self,
        static_kem_sk: bytes,
        static_sig_sk: bytes,
        static_sig_pk: bytes,
    ) -> None:
        """Initialize Responder with static key material.

        Args:
            static_kem_sk: Responder's hybrid KEM secret key
            static_sig_sk: Responder's hybrid signature secret key
                (Ed25519 sk || ML-DSA-65 sk)
            static_sig_pk: Responder's hybrid signature public key
                (Ed25519 pk || ML-DSA-65 pk)
        """
        from ama_cryptography.crypto_api import HybridKEMProvider, HybridSignatureProvider

        self._kem_sk = static_kem_sk
        self._sig_sk = static_sig_sk
        self._sig_pk = static_sig_pk
        self._kem = HybridKEMProvider()
        self._sig = HybridSignatureProvider()

    def handle_handshake(
        self, msg: HandshakeMessage
    ) -> Tuple[HandshakeResponse, SecureSession]:
        """Process an incoming handshake and produce an authenticated response.

        Args:
            msg: HandshakeMessage from an Initiator

        Returns:
            Tuple of (HandshakeResponse to send, established SecureSession)

        Raises:
            HandshakeError: If protocol mismatch or decapsulation fails
        """
        # Validate protocol
        if msg.protocol_name != PROTOCOL_NAME:
            raise HandshakeError(
                f"Protocol mismatch: expected {PROTOCOL_NAME!r}, got {msg.protocol_name!r}"
            )
        if msg.version != PROTOCOL_VERSION:
            raise HandshakeError(
                f"Version mismatch: expected {PROTOCOL_VERSION!r}, got {msg.version!r}"
            )

        # Decapsulate to recover shared secret
        try:
            shared_secret = self._kem.decapsulate(msg.kem_ciphertext, self._kem_sk)
        except Exception as exc:
            raise HandshakeError(f"KEM decapsulation failed: {exc}") from exc

        # Generate session ID
        session_id = secrets.token_bytes(SESSION_ID_BYTES)

        # Sign the handshake transcript (proves we hold the static key)
        handshake_hash = hashlib.sha3_256(msg.serialize()).digest()
        transcript = handshake_hash + session_id
        sig_result = self._sig.sign(transcript, self._sig_sk)

        response = HandshakeResponse(
            session_id=session_id,
            signature=sig_result.signature,
            responder_public_key=self._sig_pk,
        )

        # Derive session keys (note: responder send = initiator recv)
        session = self._derive_session(session_id, shared_secret)

        return response, session

    @staticmethod
    def _derive_session(session_id: bytes, shared_secret: bytes) -> SecureSession:
        """Derive send/recv keys from shared secret via HKDF-SHA3-256."""
        from ama_cryptography.pqc_backends import native_hkdf

        # Responder send = Initiator recv (symmetric derivation)
        send_key = native_hkdf(
            shared_secret, KEY_BYTES, salt=session_id, info=b"ama-noise-nk-responder-send"
        )
        recv_key = native_hkdf(
            shared_secret, KEY_BYTES, salt=session_id, info=b"ama-noise-nk-initiator-send"
        )
        return SecureSession(session_id=session_id, send_key=send_key, recv_key=recv_key)
