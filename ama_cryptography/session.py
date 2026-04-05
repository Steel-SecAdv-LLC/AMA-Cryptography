#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
AMA Cryptography - Session Management & Replay Protection
==========================================================

Provides session lifecycle management for the Post-Quantum Noise-NK
secure channel protocol. This module handles:

- Session ID generation and validation (random 32-byte tokens)
- Monotonic sequence numbers per direction
- Sliding window replay detection (reject seen or old sequence numbers)
- Session expiration (configurable TTL)
- Graceful rekeying without dropping the session
- Session store for managing multiple concurrent sessions

This module complements secure_channel.py by providing the session
infrastructure that the channel protocol operates on.

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Version: 2.1
"""

import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Constants
SESSION_ID_BYTES = 32
DEFAULT_TTL_SECONDS = 3600.0  # 1 hour
DEFAULT_REKEY_INTERVAL = 1000  # messages
REPLAY_WINDOW_SIZE = 256
MAX_SESSIONS = 1024  # prevent unbounded memory growth


class SessionError(Exception):
    """Base exception for session management errors."""

    pass


class SessionNotFoundError(SessionError):
    """Raised when a session ID is not found in the store."""

    pass


class SessionExpiredError(SessionError):
    """Raised when an operation is attempted on an expired session."""

    pass


class ReplayDetectedError(SessionError):
    """Raised when a replayed sequence number is detected."""

    pass


class SessionLimitError(SessionError):
    """Raised when the maximum number of concurrent sessions is exceeded."""

    pass


@dataclass
class ReplayWindow:
    """Sliding window replay detection.

    Tracks received sequence numbers within a window to reject:
    - Sequence numbers already seen (replay)
    - Sequence numbers below the window base (too old)

    The window slides forward as new sequence numbers are accepted.
    Window size is configurable but defaults to 256.

    Attributes:
        window_size: Maximum number of recent sequence numbers tracked
        base: Lowest acceptable sequence number
    """

    window_size: int = REPLAY_WINDOW_SIZE
    base: int = 0
    _seen: set = field(default_factory=set)  # type: ignore[type-arg]  # generic set used for seq-number tracking; parameterising adds no safety (SS-001)

    def check_and_accept(self, seq: int) -> None:
        """Check a sequence number and accept it if valid.

        Args:
            seq: Sequence number to check

        Raises:
            ReplayDetectedError: If sequence is replayed or below window
        """
        if seq < self.base:
            raise ReplayDetectedError(f"Sequence {seq} below window base {self.base} (too old)")
        if seq in self._seen:
            raise ReplayDetectedError(f"Sequence {seq} already received (replay)")

        self._seen.add(seq)

        # Slide window forward when it exceeds capacity.
        # Jump past gaps to avoid O(gap) iteration when sequence
        # numbers are sparse (e.g. due to packet loss).
        while len(self._seen) > self.window_size:
            if self.base not in self._seen:
                self.base = min(self._seen)
            self._seen.discard(self.base)
            self.base += 1

    def reset(self) -> None:
        """Reset the replay window to initial state."""
        self._seen.clear()
        self.base = 0


@dataclass
class SessionState:
    """Tracks the lifecycle state of a single session.

    Attributes:
        session_id: Unique 32-byte identifier
        created_at: Monotonic timestamp of creation
        ttl_seconds: Time-to-live for the session
        send_seq: Next sequence number to send
        recv_window: Replay detection for received messages
        rekey_count: Number of rekeys performed
        messages_sent: Total messages sent
        messages_received: Total messages received
        last_activity: Monotonic timestamp of last activity
        metadata: Arbitrary metadata attached to the session
    """

    session_id: bytes
    created_at: float = field(default_factory=time.monotonic)
    ttl_seconds: float = DEFAULT_TTL_SECONDS
    send_seq: int = 0
    recv_window: ReplayWindow = field(default_factory=ReplayWindow)
    rekey_count: int = 0
    messages_sent: int = 0
    messages_received: int = 0
    last_activity: float = field(default_factory=time.monotonic)
    metadata: Dict[str, str] = field(default_factory=dict)
    _closed: bool = False

    @property
    def is_expired(self) -> bool:
        """Check if session has exceeded its TTL."""
        return (time.monotonic() - self.created_at) > self.ttl_seconds

    @property
    def is_closed(self) -> bool:
        """Check if session has been explicitly closed."""
        return self._closed

    @property
    def is_active(self) -> bool:
        """Check if session is still usable (not expired, not closed)."""
        return not self._closed and not self.is_expired

    @property
    def needs_rekey(self) -> bool:
        """Check if session should be re-keyed based on message count."""
        msgs_since_rekey = (self.messages_sent + self.messages_received) - (
            self.rekey_count * DEFAULT_REKEY_INTERVAL
        )
        return msgs_since_rekey >= DEFAULT_REKEY_INTERVAL

    def next_send_seq(self) -> int:
        """Get next send sequence number and increment counter."""
        seq = self.send_seq
        self.send_seq += 1
        self.messages_sent += 1
        self.last_activity = time.monotonic()
        return seq

    def accept_recv_seq(self, seq: int) -> None:
        """Validate and accept a received sequence number.

        Args:
            seq: Received sequence number

        Raises:
            SessionExpiredError: If session has expired
            ReplayDetectedError: If sequence is replayed
        """
        if self.is_expired:
            raise SessionExpiredError(f"Session {self.session_id.hex()[:16]} expired")
        if self._closed:
            raise SessionError("Session is closed")

        self.recv_window.check_and_accept(seq)
        self.messages_received += 1
        self.last_activity = time.monotonic()

    def record_rekey(self) -> None:
        """Record that a rekey has been performed."""
        self.rekey_count += 1
        self.last_activity = time.monotonic()

    def close(self) -> None:
        """Mark session as closed."""
        self._closed = True

    def summary(self) -> Dict[str, object]:
        """Return a summary dict of session state for diagnostics."""
        return {
            "session_id": self.session_id.hex()[:16] + "...",
            "active": self.is_active,
            "expired": self.is_expired,
            "closed": self.is_closed,
            "messages_sent": self.messages_sent,
            "messages_received": self.messages_received,
            "rekey_count": self.rekey_count,
            "age_seconds": round(time.monotonic() - self.created_at, 1),
            "needs_rekey": self.needs_rekey,
        }


class SessionStore:
    """Thread-safe store for managing multiple concurrent sessions.

    Provides CRUD operations for sessions with automatic expiration
    cleanup and a configurable maximum session limit.

    Usage::

        store = SessionStore(max_sessions=100, default_ttl=3600.0)
        session = store.create()
        # ... use session ...
        store.close(session.session_id)

    Attributes:
        max_sessions: Maximum concurrent sessions allowed
        default_ttl: Default time-to-live for new sessions
    """

    def __init__(
        self,
        max_sessions: int = MAX_SESSIONS,
        default_ttl: float = DEFAULT_TTL_SECONDS,
    ) -> None:
        self.max_sessions = max_sessions
        self.default_ttl = default_ttl
        self._sessions: Dict[bytes, SessionState] = {}
        self._lock = threading.Lock()

    def create(
        self,
        ttl_seconds: Optional[float] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> SessionState:
        """Create a new session with a random 32-byte ID.

        Args:
            ttl_seconds: Override default TTL for this session
            metadata: Optional metadata to attach to the session

        Returns:
            Newly created SessionState

        Raises:
            SessionLimitError: If max_sessions would be exceeded
        """
        with self._lock:
            # Cleanup expired sessions first
            self._cleanup_expired()

            if len(self._sessions) >= self.max_sessions:
                raise SessionLimitError(f"Maximum sessions ({self.max_sessions}) reached")

            session_id = secrets.token_bytes(SESSION_ID_BYTES)
            session = SessionState(
                session_id=session_id,
                ttl_seconds=ttl_seconds if ttl_seconds is not None else self.default_ttl,
                metadata=metadata or {},
            )
            self._sessions[session_id] = session
            logger.debug("Created session %s", session_id.hex()[:16])
            return session

    def get(self, session_id: bytes) -> SessionState:
        """Retrieve a session by ID.

        Args:
            session_id: 32-byte session identifier

        Returns:
            SessionState for the given ID

        Raises:
            SessionNotFoundError: If session ID is not in the store
            SessionExpiredError: If the session has expired
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise SessionNotFoundError(f"Session {session_id.hex()[:16]} not found")
            if session.is_expired:
                del self._sessions[session_id]
                raise SessionExpiredError(f"Session {session_id.hex()[:16]} expired")
            return session

    def close(self, session_id: bytes) -> None:
        """Close and remove a session.

        Args:
            session_id: 32-byte session identifier

        Raises:
            SessionNotFoundError: If session ID is not in the store
        """
        with self._lock:
            session = self._sessions.pop(session_id, None)
            if session is None:
                raise SessionNotFoundError(f"Session {session_id.hex()[:16]} not found")
            session.close()
            logger.debug("Closed session %s", session_id.hex()[:16])

    def close_all(self) -> int:
        """Close all sessions. Returns the number of sessions closed."""
        with self._lock:
            count = len(self._sessions)
            for session in self._sessions.values():
                session.close()
            self._sessions.clear()
            return count

    def list_active(self) -> List[Dict[str, object]]:
        """Return summaries of all active (non-expired) sessions."""
        with self._lock:
            self._cleanup_expired()
            return [s.summary() for s in self._sessions.values() if s.is_active]

    @property
    def active_count(self) -> int:
        """Number of active sessions."""
        with self._lock:
            self._cleanup_expired()
            return len(self._sessions)

    def _cleanup_expired(self) -> None:
        """Remove all expired sessions. Must be called with lock held."""
        expired = [sid for sid, s in self._sessions.items() if s.is_expired]
        for sid in expired:
            self._sessions[sid].close()
            del self._sessions[sid]
        if expired:
            logger.debug("Cleaned up %d expired sessions", len(expired))
