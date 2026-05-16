#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
AMA Cryptography - Post-Quantum Noise-NK Secure Channel
========================================================

Implements a Noise-NK variant using AMA's hybrid post-quantum primitives.

This protocol composes well-established building blocks from published
specifications into a PQ-hybrid Noise-NK channel.  The individual
primitives follow NIST/IETF standards; the protocol pattern follows
the Noise Protocol Framework.  The specific PQ-hybrid composition
(Kyber-1024 + Ed25519/ML-DSA-65) is novel and has not undergone
independent security review -- it should be treated as experimental
until a formal security analysis is published.

References:
    - Noise Protocol Framework, rev 34 (Perrin, 2018):
      https://noiseprotocol.org/noise.html
    - NIST FIPS 203 (ML-KEM / Kyber-1024): key encapsulation
    - NIST FIPS 204 (ML-DSA-65 / Dilithium): digital signatures
    - RFC 7748 (X25519): classical key agreement
    - RFC 8032 (Ed25519): classical digital signatures
    - RFC 5869 (HKDF): key derivation
    - NIST SP 800-38D (AES-GCM): authenticated encryption

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
Version: 3.0.0
"""

import hashlib
import logging
import secrets
import struct
import threading
import time
from _thread import LockType
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Tuple

from ama_cryptography.secure_memory import SecureMemoryError, secure_memzero

logger = logging.getLogger(__name__)

# Protocol constants
PROTOCOL_NAME = b"Noise_NK_HybridKEM_AESGCM_SHA3256"
PROTOCOL_VERSION = b"\x02"  # Bumped: AAD now includes rekey_epoch (v1 incompatible)
SESSION_ID_BYTES = 32
NONCE_BYTES = 12
KEY_BYTES = 32
TAG_BYTES = 16
REKEY_INTERVAL = 1000  # Messages before mandatory rekey
MAX_MESSAGE_SIZE = 65535
SESSION_TTL_SECONDS = 3600  # 1 hour default
# DoS resistance cap for deserialized field lengths (signature, public key).
# Hybrid signature (Ed25519 + ML-DSA-65) is ~2500 bytes; 64 KiB is generous
# but prevents multi-GB allocation from attacker input.
_MAX_FIELD_BYTES = 65536


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
        """Deserialize from wire format.

        Raises:
            ChannelError: If data is truncated or malformed
        """
        # Minimum: session_id(32) + seq(8) + nonce(12) + ct_len(4) + tag(16) = 72
        min_len = SESSION_ID_BYTES + 8 + NONCE_BYTES + 4 + TAG_BYTES
        if len(data) < min_len:
            raise ChannelError(f"Truncated ChannelMessage: {len(data)} bytes < minimum {min_len}")

        offset = 0
        session_id = data[offset : offset + SESSION_ID_BYTES]
        offset += SESSION_ID_BYTES

        (sequence_number,) = struct.unpack(">Q", data[offset : offset + 8])
        offset += 8

        nonce = data[offset : offset + NONCE_BYTES]
        offset += NONCE_BYTES

        (ct_len,) = struct.unpack(">I", data[offset : offset + 4])
        offset += 4

        if offset + ct_len + TAG_BYTES > len(data):
            raise ChannelError(
                f"Truncated ChannelMessage: declared ct_len={ct_len} "
                f"but only {len(data) - offset - TAG_BYTES} bytes available"
            )

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
        """Deserialize handshake from wire format.

        Hardened against attacker-controlled wire input:
          * Every length field is bounded by ``_MAX_FIELD_BYTES`` to
            prevent multi-GB allocation from a 32-bit attacker length.
          * Every slice is checked against the remaining buffer so a
            truncated message raises a deterministic ``ChannelError``
            instead of silently returning a short value.
          * Trailing bytes are rejected so an attacker cannot smuggle
            extra payload past the framing boundary.

        Raises:
            ChannelError: If data is truncated, contains an oversize
                length field, or has trailing bytes.
        """
        # Minimum: name_len(2) + version(1) + epk_len(4) + ct_len(4) = 11.
        # Protocol name and field bodies are length-prefixed and may be
        # zero-length on the wire (each adds nothing to the minimum);
        # bounds against actual payload are checked per-field below.
        min_len = 2 + 1 + 4 + 4
        if len(data) < min_len:
            raise ChannelError(f"Truncated HandshakeMessage: {len(data)} bytes < minimum {min_len}")

        offset = 0
        if offset + 2 > len(data):
            raise ChannelError("Truncated HandshakeMessage: missing protocol_name length")
        (name_len,) = struct.unpack(">H", data[offset : offset + 2])
        offset += 2
        if name_len > _MAX_FIELD_BYTES:
            raise ChannelError(
                f"HandshakeMessage: name_len={name_len} exceeds maximum {_MAX_FIELD_BYTES}"
            )
        if offset + name_len > len(data):
            raise ChannelError(
                f"Truncated HandshakeMessage: name_len={name_len} "
                f"but only {len(data) - offset} bytes remaining"
            )
        protocol_name = data[offset : offset + name_len]
        offset += name_len

        if offset + 1 > len(data):
            raise ChannelError("Truncated HandshakeMessage: missing version byte")
        version = data[offset : offset + 1]
        offset += 1

        if offset + 4 > len(data):
            raise ChannelError("Truncated HandshakeMessage: missing ephemeral_public_key length")
        (epk_len,) = struct.unpack(">I", data[offset : offset + 4])
        offset += 4
        if epk_len > _MAX_FIELD_BYTES:
            raise ChannelError(
                f"HandshakeMessage: epk_len={epk_len} exceeds maximum {_MAX_FIELD_BYTES}"
            )
        if offset + epk_len > len(data):
            raise ChannelError(
                f"Truncated HandshakeMessage: epk_len={epk_len} "
                f"but only {len(data) - offset} bytes remaining"
            )
        ephemeral_public_key = data[offset : offset + epk_len]
        offset += epk_len

        if offset + 4 > len(data):
            raise ChannelError("Truncated HandshakeMessage: missing kem_ciphertext length")
        (ct_len,) = struct.unpack(">I", data[offset : offset + 4])
        offset += 4
        if ct_len > _MAX_FIELD_BYTES:
            raise ChannelError(
                f"HandshakeMessage: ct_len={ct_len} exceeds maximum {_MAX_FIELD_BYTES}"
            )
        if offset + ct_len > len(data):
            raise ChannelError(
                f"Truncated HandshakeMessage: ct_len={ct_len} "
                f"but only {len(data) - offset} bytes remaining"
            )
        kem_ciphertext = data[offset : offset + ct_len]
        offset += ct_len

        if offset != len(data):
            raise ChannelError(f"Malformed HandshakeMessage: {len(data) - offset} trailing bytes")

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
        """Deserialize response from wire format.

        Raises:
            ChannelError: If data is truncated or malformed
        """
        # Minimum: session_id(32) + sig_len(4) + pk_len(4) = 40
        min_len = SESSION_ID_BYTES + 4 + 4
        if len(data) < min_len:
            raise ChannelError(
                f"Truncated HandshakeResponse: {len(data)} bytes < minimum {min_len}"
            )

        offset = 0
        session_id = data[offset : offset + SESSION_ID_BYTES]
        offset += SESSION_ID_BYTES

        if offset + 4 > len(data):
            raise ChannelError("Truncated HandshakeResponse: missing signature length")
        (sig_len,) = struct.unpack(">I", data[offset : offset + 4])
        offset += 4
        if sig_len > _MAX_FIELD_BYTES:
            raise ChannelError(
                f"HandshakeResponse: sig_len={sig_len} exceeds maximum {_MAX_FIELD_BYTES}"
            )

        if offset + sig_len > len(data):
            raise ChannelError(
                f"Truncated HandshakeResponse: sig_len={sig_len} "
                f"but only {len(data) - offset} bytes remaining"
            )
        signature = data[offset : offset + sig_len]
        offset += sig_len

        if offset + 4 > len(data):
            raise ChannelError("Truncated HandshakeResponse: missing public key length")
        (pk_len,) = struct.unpack(">I", data[offset : offset + 4])
        offset += 4
        if pk_len > _MAX_FIELD_BYTES:
            raise ChannelError(
                f"HandshakeResponse: pk_len={pk_len} exceeds maximum {_MAX_FIELD_BYTES}"
            )

        if offset + pk_len > len(data):
            raise ChannelError(
                f"Truncated HandshakeResponse: pk_len={pk_len} "
                f"but only {len(data) - offset} bytes remaining"
            )
        responder_public_key = data[offset : offset + pk_len]
        offset += pk_len

        if offset != len(data):
            raise ChannelError(f"Malformed HandshakeResponse: {len(data) - offset} trailing bytes")

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

    Thread safety:
        ``encrypt``, ``decrypt``, ``rekey``, and ``close`` are all
        serialised by an internal ``threading.Lock``.  This protects
        the mutable replay-window state (``_replay_window``,
        ``_replay_window_base``), the sequence counters, the key
        material, and the rekey epoch from race conditions when the
        session is shared across threads (e.g. an async I/O loop
        running encrypt in one task while decrypt runs in another).

    Memory hygiene:
        Session keys are stored as ``bytearray`` so they can be
        wiped in place via :func:`secure_memzero` on ``close()`` and
        on ``rekey()``.  Storing them as immutable ``bytes`` (as the
        previous implementation did) meant ``close()`` could only
        rebind the references, leaving the underlying key material
        live in the heap until the next GC pass.

    Attributes:
        session_id: Unique 32-byte session identifier
        send_key: Current sending key (rotated on rekey, wiped on close)
        recv_key: Current receiving key (rotated on rekey, wiped on close)
        send_seq: Monotonic send sequence counter
        recv_seq: Expected receive sequence counter
        created_at: Session creation timestamp
        ttl_seconds: Session time-to-live
        messages_since_rekey: Counter for triggering automatic rekey
        rekey_epoch: Monotonic counter incremented on every successful
            rekey; bound into the AEAD AAD so a silent rekey failure
            (same key, different epoch) cannot enable tag forgery.
    """

    session_id: bytes
    send_key: bytearray
    recv_key: bytearray
    send_seq: int = 0
    recv_seq: int = 0
    created_at: float = field(default_factory=time.monotonic)
    ttl_seconds: float = SESSION_TTL_SECONDS
    messages_since_rekey: int = 0
    # SECURITY FIX: Track key generation/epoch to bind AAD to the current
    # key material.  Without this, a silent rekey failure could leave the
    # same key active across two epochs with overlapping sequence numbers,
    # enabling tag forgery via multi-target attacks (audit finding H2).
    rekey_epoch: int = 0
    _replay_window: set[int] = field(default_factory=set)
    _replay_window_base: int = 0
    _state: ChannelState = ChannelState.ESTABLISHED

    # Sliding window size for replay detection
    REPLAY_WINDOW_SIZE: int = 256

    def __post_init__(self) -> None:
        """Initialise the per-session lock for thread-safe state mutation.

        Stored as an instance attribute (not a dataclass field) so it
        is excluded from equality, hashing, and repr — locks are not
        meaningful state to expose.
        """
        # NOTE: ``threading.Lock`` (not RLock).  encrypt/decrypt/rekey/
        # close do not recurse into one another while holding the lock,
        # so a plain Lock is sufficient and an attempted nested acquire
        # surfaces as a deadlock at the bad call site rather than being
        # silently allowed.
        self._lock: LockType = threading.Lock()
        # Defensive type coercion: callers from older API paths might pass
        # ``bytes`` for send/recv keys.  We canonicalise to bytearray so
        # ``close()`` can wipe the live memory rather than rebind names.
        if not isinstance(self.send_key, bytearray):
            self.send_key = bytearray(self.send_key)
        if not isinstance(self.recv_key, bytearray):
            self.recv_key = bytearray(self.recv_key)

    def is_expired(self) -> bool:
        """Check if session has exceeded its TTL."""
        return (time.monotonic() - self.created_at) >= self.ttl_seconds

    def needs_rekey(self) -> bool:
        """Check if session should be re-keyed based on message count."""
        return self.messages_since_rekey >= REKEY_INTERVAL

    def encrypt(self, plaintext: bytes) -> ChannelMessage:
        """Encrypt plaintext and produce a framed ChannelMessage.

        Serialised by the session lock — safe to call from multiple
        threads against the same session.

        Args:
            plaintext: Data to encrypt (max 65535 bytes)

        Returns:
            ChannelMessage ready for transport

        Raises:
            SessionExpiredError: If session TTL has elapsed
            ChannelError: If session is not in ESTABLISHED state
            ValueError: If plaintext exceeds MAX_MESSAGE_SIZE
        """
        if len(plaintext) > MAX_MESSAGE_SIZE:
            # Cheap bound check outside the lock — defends against the
            # adversarial caller that holds a giant plaintext for a long
            # time without ever needing the session state.
            raise ValueError(f"Message too large: {len(plaintext)} > {MAX_MESSAGE_SIZE}")

        from ama_cryptography.pqc_backends import native_aes256_gcm_encrypt

        with self._lock:
            if self._state != ChannelState.ESTABLISHED:
                raise ChannelError(f"Cannot encrypt in state {self._state}")
            if self.is_expired():
                self._state = ChannelState.CLOSED
                raise SessionExpiredError("Session TTL expired")

            nonce = secrets.token_bytes(NONCE_BYTES)
            # AAD binds ciphertext to session_id, rekey epoch, and sequence
            # number.  Including the epoch ensures that a silent rekey failure
            # (same key across two epochs) produces distinct AAD, preventing
            # multi-target tag forgery (audit finding H2).
            aad = (
                self.session_id
                + struct.pack(">I", self.rekey_epoch)
                + struct.pack(">Q", self.send_seq)
            )

            # The native wrapper borrows this bytearray via ctypes
            # ``from_buffer``; do NOT coerce to ``bytes`` here, because
            # immutable key copies cannot be scrubbed by ``close()``.
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

        Serialised by the session lock — safe to call from multiple
        threads against the same session.  The replay-window mutation
        (``_replay_window`` set / ``_replay_window_base`` slide) is
        protected by the same lock as the AEAD decryption so a
        concurrent caller cannot observe a half-updated window.

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
        from ama_cryptography.pqc_backends import native_aes256_gcm_decrypt

        with self._lock:
            if self._state != ChannelState.ESTABLISHED:
                raise ChannelError(f"Cannot decrypt in state {self._state}")
            if self.is_expired():
                self._state = ChannelState.CLOSED
                raise SessionExpiredError("Session TTL expired")
            if msg.session_id != self.session_id:
                raise ChannelError("Session ID mismatch")

            # Replay detection: sliding window — read AND mutated under
            # the same lock, so two concurrent decrypts cannot both
            # succeed on the same sequence number by racing the
            # membership check against the set-insert.
            seq = msg.sequence_number
            if seq < self._replay_window_base:
                raise ReplayError(f"Sequence {seq} below window base {self._replay_window_base}")
            if seq in self._replay_window:
                raise ReplayError(f"Sequence {seq} already received (replay)")

            aad = self.session_id + struct.pack(">I", self.rekey_epoch) + struct.pack(">Q", seq)
            plaintext = native_aes256_gcm_decrypt(
                self.recv_key, msg.nonce, msg.ciphertext, msg.tag, aad
            )

            # Update replay window after successful decryption.  If the
            # AEAD raised above, the set is unchanged — preserving the
            # invariant that a sequence only enters the window when its
            # tag has verified.
            self._replay_window.add(seq)
            while len(self._replay_window) > self.REPLAY_WINDOW_SIZE:
                # Jump past gaps to avoid O(gap) iteration when sequence
                # numbers are sparse (e.g. due to packet loss).
                if self._replay_window_base not in self._replay_window:
                    self._replay_window_base = min(self._replay_window)
                self._replay_window.discard(self._replay_window_base)
                self._replay_window_base += 1

            self.messages_since_rekey += 1
            return plaintext

    def rekey(self) -> None:
        """Derive new session keys from current keys for forward secrecy.

        Uses HKDF-SHA3-256 to derive fresh send/recv keys from the
        current keys, ensuring that compromise of current keys does
        not reveal past plaintext (forward secrecy).

        The info string is the same for both directions because the
        Initiator's send_key equals the Responder's recv_key (and
        vice versa).  Using a single info tag keeps the two sides
        in sync after rekey.

        The OLD key material is wiped via ``secure_memzero`` AFTER the
        new keys have been derived, so a failure inside HKDF cannot
        leave the session keyless while still in ESTABLISHED state.
        """
        from ama_cryptography.pqc_backends import native_hkdf

        with self._lock:
            # HKDF borrows the current bytearray keys through the native
            # buffer path, eliminating bytes(self.key) heap copies before
            # the old material is wiped below.
            new_send_bytes = native_hkdf(self.send_key, KEY_BYTES, salt=None, info=b"ama-rekey")
            new_recv_bytes = native_hkdf(self.recv_key, KEY_BYTES, salt=None, info=b"ama-rekey")
            new_send = bytearray(new_send_bytes)
            new_recv = bytearray(new_recv_bytes)
            # Wipe the source key material after native HKDF succeeds.
            self._wipe_keys()
            self.send_key = new_send
            self.recv_key = new_recv
            self.messages_since_rekey = 0
            self.rekey_epoch += 1
            logger.debug(
                "Session %s re-keyed (epoch %d)",
                self.session_id.hex()[:16],
                self.rekey_epoch,
            )

    def _wipe_keys(self) -> None:
        """Wipe send_key and recv_key bytearrays in place.

        Tolerant of a wipe-failure on either key — the second wipe is
        attempted even if the first raises, so a single backend hiccup
        cannot leave the second key live.  Any wipe error is re-raised
        after both attempts.
        """
        first_err: Optional[BaseException] = None
        for buf in (self.send_key, self.recv_key):
            try:
                secure_memzero(buf)
            except (SecureMemoryError, TypeError) as exc:
                # Capture but continue so the second buffer is wiped too.
                if first_err is None:
                    first_err = exc
        if first_err is not None:
            raise first_err

    def close(self) -> None:
        """Close the session and securely wipe key material.

        Unlike the previous implementation, this rewrites the underlying
        ``bytearray`` storage in place via ``secure_memzero`` — the
        key bytes are gone from the heap after this call rather than
        merely unreferenced and waiting on a future GC.

        Idempotent: a second ``close()`` returns immediately because the
        state is already ``CLOSED``.
        """
        with self._lock:
            if self._state == ChannelState.CLOSED:
                return
            self._state = ChannelState.CLOSED
            # ``_wipe_keys`` mutates the SAME bytearray objects we hold,
            # so any external reference (e.g. a test or audit log that
            # captured ``session.send_key`` earlier) now also sees the
            # zeroed memory.  This is the whole point of using a
            # bytearray rather than rebinding immutable ``bytes``.
            self._wipe_keys()


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

        # SECURITY FIX: Validate encapsulation result before using the
        # shared secret.  A corrupted or attacker-controlled encapsulation
        # result could compromise forward secrecy (audit finding C1).
        if encap_result.shared_secret is None or len(encap_result.shared_secret) != KEY_BYTES:
            raise HandshakeError(
                "KEM encapsulation returned invalid shared secret "
                f"(expected {KEY_BYTES} bytes, got "
                f"{len(encap_result.shared_secret) if encap_result.shared_secret else 0})"
            )
        if encap_result.ciphertext is None or len(encap_result.ciphertext) == 0:
            raise HandshakeError("KEM encapsulation returned empty ciphertext")

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
        if self._handshake_hash is None:
            raise HandshakeError("Handshake hash not established")
        transcript = self._handshake_hash + response.session_id
        if not sig_provider.verify(transcript, response.signature, response.responder_public_key):
            raise HandshakeError("Responder signature verification failed")

        # Derive session keys from shared secret
        if self._shared_secret is None:
            raise HandshakeError("Shared secret not established during handshake")
        session = self._derive_session(response.session_id, self._shared_secret)

        # Clear handshake state
        self._shared_secret = None
        self._handshake_hash = None
        self._state = ChannelState.ESTABLISHED
        return session

    @staticmethod
    def _derive_session(session_id: bytes, shared_secret: bytes) -> SecureSession:
        """Derive send/recv keys from shared secret via HKDF-SHA3-256.

        Keys are wrapped in ``bytearray`` so that
        :meth:`SecureSession.close` can wipe their backing memory in
        place via ``secure_memzero``.
        """
        from ama_cryptography.pqc_backends import native_hkdf

        # Derive separate keys for each direction
        send_key = bytearray(
            native_hkdf(
                shared_secret, KEY_BYTES, salt=session_id, info=b"ama-noise-nk-initiator-send"
            )
        )
        recv_key = bytearray(
            native_hkdf(
                shared_secret, KEY_BYTES, salt=session_id, info=b"ama-noise-nk-responder-send"
            )
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
        from ama_cryptography.crypto_api import (
            HybridKEMProvider,
            HybridSignatureProvider,
        )

        self._kem_sk = static_kem_sk
        self._sig_sk = static_sig_sk
        self._sig_pk = static_sig_pk
        self._kem = HybridKEMProvider()
        self._sig = HybridSignatureProvider()

    def handle_handshake(self, msg: HandshakeMessage) -> Tuple[HandshakeResponse, SecureSession]:
        """Process an incoming handshake and produce an authenticated response.

        Args:
            msg: HandshakeMessage from an Initiator

        Returns:
            Tuple of (HandshakeResponse to send, established SecureSession)

        Raises:
            HandshakeError: If protocol mismatch or decapsulation fails.
                The error message is *intentionally generic* and the
                cause chain is suppressed (``from None``) so that an
                online attacker cannot distinguish failure modes —
                short-ciphertext, wrong-length-secret-key, malformed
                lattice element, FO-decryption-mismatch, and other
                internal Kyber errors all surface as a single opaque
                "Handshake failed" error.  The detailed error is
                logged at WARNING for the operator.
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

        # Decapsulate to recover shared secret.
        #
        # SECURITY: KEM error indistinguishability.  Catching every
        # exception class and folding the cause chain ensures that no
        # information about *why* decapsulation failed leaks to the
        # remote peer.  Without this, error-message timing oracles
        # become attack surface (Bleichenbacher-style adaptive
        # ciphertext attacks against Kyber FO transforms).  The
        # internal failure detail is logged at WARNING so operators
        # retain forensic visibility, but the on-wire failure mode is
        # uniform.  ``from None`` is critical here — ``from exc``
        # would expose the original exception via ``__cause__`` and
        # defeat the masking on any caller that prints tracebacks.
        try:
            shared_secret = self._kem.decapsulate(msg.kem_ciphertext, self._kem_sk)
        except Exception as exc:
            logger.warning(
                "KEM decapsulation failed (internal detail withheld from peer): %s",
                exc,
                exc_info=True,
            )
            raise HandshakeError("Handshake failed") from None

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
        """Derive send/recv keys from shared secret via HKDF-SHA3-256.

        Keys are wrapped in ``bytearray`` for in-place secure wipe on
        ``close()`` (see :class:`SecureSession`).
        """
        from ama_cryptography.pqc_backends import native_hkdf

        # Responder send = Initiator recv (symmetric derivation)
        send_key = bytearray(
            native_hkdf(
                shared_secret, KEY_BYTES, salt=session_id, info=b"ama-noise-nk-responder-send"
            )
        )
        recv_key = bytearray(
            native_hkdf(
                shared_secret, KEY_BYTES, salt=session_id, info=b"ama-noise-nk-initiator-send"
            )
        )
        return SecureSession(session_id=session_id, send_key=send_key, recv_key=recv_key)
