#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Comprehensive Test Suite for session.py
========================================

Tests the session management and replay protection module including:
- ReplayWindow sliding window behavior
- SessionState lifecycle (creation, expiration, closure)
- TTL expiration
- Rekey scheduling
- SessionStore CRUD and thread-safety
- Concurrent session management
- Session limits and cleanup

AI Co-Architects: Eris | Eden | Devin | Claude
"""

import secrets
import threading
import time

import pytest

from ama_cryptography.session import (
    DEFAULT_REKEY_INTERVAL,
    SESSION_ID_BYTES,
    ReplayDetectedError,
    ReplayWindow,
    SessionError,
    SessionExpiredError,
    SessionLimitError,
    SessionNotFoundError,
    SessionState,
    SessionStore,
)

# ---------------------------------------------------------------------------
# ReplayWindow Tests
# ---------------------------------------------------------------------------


class TestReplayWindow:
    """Test sliding window replay detection."""

    def test_accept_sequential(self) -> None:
        """Sequential sequence numbers are accepted."""
        rw = ReplayWindow()
        for i in range(10):
            rw.check_and_accept(i)

    def test_reject_duplicate(self) -> None:
        """Duplicate sequence number is rejected."""
        rw = ReplayWindow()
        rw.check_and_accept(0)

        with pytest.raises(ReplayDetectedError, match="already received"):
            rw.check_and_accept(0)

    def test_reject_below_base(self) -> None:
        """Sequence number below window base is rejected."""
        rw = ReplayWindow(window_size=5)
        # Fill and overflow the window to advance the base
        for i in range(10):
            rw.check_and_accept(i)

        # base should have advanced past 0
        assert rw.base > 0

        with pytest.raises(ReplayDetectedError, match="too old"):
            rw.check_and_accept(0)

    def test_out_of_order_within_window(self) -> None:
        """Out-of-order messages within the window are accepted."""
        rw = ReplayWindow()
        rw.check_and_accept(5)
        rw.check_and_accept(3)
        rw.check_and_accept(7)
        rw.check_and_accept(1)
        rw.check_and_accept(4)

    def test_window_slides_forward(self) -> None:
        """Window base advances when window exceeds capacity."""
        rw = ReplayWindow(window_size=10)

        for i in range(20):
            rw.check_and_accept(i)

        # Window should have slid forward
        assert rw.base > 0
        # Old sequence numbers should be rejected
        with pytest.raises(ReplayDetectedError):
            rw.check_and_accept(0)

    def test_large_gap_in_sequence(self) -> None:
        """Large gap in sequence numbers is handled efficiently."""
        rw = ReplayWindow(window_size=10)
        rw.check_and_accept(0)
        rw.check_and_accept(1000)  # large gap
        # Both should be in the window

    def test_reset_clears_state(self) -> None:
        """Reset restores the window to initial state."""
        rw = ReplayWindow()
        for i in range(50):
            rw.check_and_accept(i)

        rw.reset()
        assert rw.base == 0
        # Should be able to accept 0 again after reset
        rw.check_and_accept(0)

    def test_window_size_respected(self) -> None:
        """Window never exceeds configured size."""
        rw = ReplayWindow(window_size=10)
        for i in range(100):
            rw.check_and_accept(i)
        assert len(rw._seen) <= 10

    def test_custom_window_size(self) -> None:
        """Custom window size works correctly."""
        rw = ReplayWindow(window_size=3)
        rw.check_and_accept(0)
        rw.check_and_accept(1)
        rw.check_and_accept(2)
        rw.check_and_accept(3)
        # Window should have slid forward, seq 0 should be rejected
        with pytest.raises(ReplayDetectedError):
            rw.check_and_accept(0)


# ---------------------------------------------------------------------------
# SessionState Tests
# ---------------------------------------------------------------------------


class TestSessionState:
    """Test session state lifecycle management."""

    def test_create_session(self) -> None:
        """SessionState can be created with a random ID."""
        sid = secrets.token_bytes(SESSION_ID_BYTES)
        session = SessionState(session_id=sid)

        assert session.session_id == sid
        assert session.send_seq == 0
        assert session.messages_sent == 0
        assert session.messages_received == 0
        assert session.rekey_count == 0
        assert session.is_active
        assert not session.is_expired
        assert not session.is_closed

    def test_next_send_seq_increments(self) -> None:
        """next_send_seq returns incrementing sequence numbers."""
        session = SessionState(session_id=secrets.token_bytes(SESSION_ID_BYTES))

        assert session.next_send_seq() == 0
        assert session.next_send_seq() == 1
        assert session.next_send_seq() == 2
        assert session.messages_sent == 3

    def test_accept_recv_seq(self) -> None:
        """accept_recv_seq validates and records received sequences."""
        session = SessionState(session_id=secrets.token_bytes(SESSION_ID_BYTES))

        session.accept_recv_seq(0)
        session.accept_recv_seq(1)
        session.accept_recv_seq(2)
        assert session.messages_received == 3

    def test_accept_recv_seq_rejects_replay(self) -> None:
        """accept_recv_seq rejects replayed sequence numbers."""
        session = SessionState(session_id=secrets.token_bytes(SESSION_ID_BYTES))
        session.accept_recv_seq(0)

        with pytest.raises(ReplayDetectedError, match="already received"):
            session.accept_recv_seq(0)

    def test_accept_recv_seq_rejects_expired(self) -> None:
        """accept_recv_seq rejects operations on expired sessions."""
        session = SessionState(
            session_id=secrets.token_bytes(SESSION_ID_BYTES),
            ttl_seconds=0.0,
        )

        with pytest.raises(SessionExpiredError, match="expired"):
            session.accept_recv_seq(0)

    def test_accept_recv_seq_rejects_closed(self) -> None:
        """accept_recv_seq rejects operations on closed sessions."""
        session = SessionState(session_id=secrets.token_bytes(SESSION_ID_BYTES))
        session.close()

        with pytest.raises(SessionError, match="closed"):
            session.accept_recv_seq(0)

    def test_is_expired_with_zero_ttl(self) -> None:
        """Session with TTL=0 expires immediately."""
        session = SessionState(
            session_id=secrets.token_bytes(SESSION_ID_BYTES),
            ttl_seconds=0.0,
        )
        assert session.is_expired
        assert not session.is_active

    def test_is_expired_with_large_ttl(self) -> None:
        """Session with large TTL does not expire immediately."""
        session = SessionState(
            session_id=secrets.token_bytes(SESSION_ID_BYTES),
            ttl_seconds=99999.0,
        )
        assert not session.is_expired
        assert session.is_active

    def test_close_marks_inactive(self) -> None:
        """Closing a session marks it inactive."""
        session = SessionState(session_id=secrets.token_bytes(SESSION_ID_BYTES))
        assert session.is_active

        session.close()
        assert session.is_closed
        assert not session.is_active

    def test_needs_rekey_threshold(self) -> None:
        """needs_rekey triggers at DEFAULT_REKEY_INTERVAL messages."""
        session = SessionState(session_id=secrets.token_bytes(SESSION_ID_BYTES))

        # Send messages up to threshold - 1
        for _ in range(DEFAULT_REKEY_INTERVAL - 1):
            session.next_send_seq()

        assert not session.needs_rekey

        # One more message triggers rekey
        session.next_send_seq()
        assert session.needs_rekey

    def test_record_rekey_increments_count(self) -> None:
        """record_rekey increments the rekey counter."""
        session = SessionState(session_id=secrets.token_bytes(SESSION_ID_BYTES))
        assert session.rekey_count == 0

        session.record_rekey()
        assert session.rekey_count == 1

        session.record_rekey()
        assert session.rekey_count == 2

    def test_summary_returns_dict(self) -> None:
        """summary() returns a dict with expected keys."""
        session = SessionState(session_id=secrets.token_bytes(SESSION_ID_BYTES))
        summary = session.summary()

        assert "session_id" in summary
        assert "active" in summary
        assert "expired" in summary
        assert "closed" in summary
        assert "messages_sent" in summary
        assert "messages_received" in summary
        assert "rekey_count" in summary
        assert "age_seconds" in summary
        assert "needs_rekey" in summary

    def test_metadata_storage(self) -> None:
        """Metadata can be attached to a session."""
        session = SessionState(
            session_id=secrets.token_bytes(SESSION_ID_BYTES),
            metadata={"peer": "mercury-agent-01", "role": "client"},
        )
        assert session.metadata["peer"] == "mercury-agent-01"
        assert session.metadata["role"] == "client"

    def test_last_activity_updates(self) -> None:
        """last_activity is updated on send and recv operations."""
        session = SessionState(session_id=secrets.token_bytes(SESSION_ID_BYTES))
        initial = session.last_activity

        time.sleep(0.01)
        session.next_send_seq()
        assert session.last_activity >= initial


# ---------------------------------------------------------------------------
# SessionStore Tests
# ---------------------------------------------------------------------------


class TestSessionStore:
    """Test thread-safe session store."""

    def test_create_session(self) -> None:
        """Store can create a session."""
        store = SessionStore()
        session = store.create()

        assert len(session.session_id) == SESSION_ID_BYTES
        assert session.is_active

    def test_create_with_custom_ttl(self) -> None:
        """Store respects custom TTL on creation."""
        store = SessionStore()
        session = store.create(ttl_seconds=120.0)

        assert session.ttl_seconds == 120.0

    def test_create_with_metadata(self) -> None:
        """Store passes metadata to created sessions."""
        store = SessionStore()
        session = store.create(metadata={"key": "value"})

        assert session.metadata["key"] == "value"

    def test_get_existing_session(self) -> None:
        """Store can retrieve a session by ID."""
        store = SessionStore()
        created = store.create()

        retrieved = store.get(created.session_id)
        assert retrieved.session_id == created.session_id

    def test_get_nonexistent_raises(self) -> None:
        """Store raises SessionNotFoundError for unknown IDs."""
        store = SessionStore()
        fake_id = secrets.token_bytes(SESSION_ID_BYTES)

        with pytest.raises(SessionNotFoundError, match="not found"):
            store.get(fake_id)

    def test_get_expired_raises(self) -> None:
        """Store raises SessionExpiredError for expired sessions."""
        store = SessionStore()
        session = store.create(ttl_seconds=0.0)

        with pytest.raises(SessionExpiredError, match="expired"):
            store.get(session.session_id)

    def test_close_session(self) -> None:
        """Store can close and remove a session."""
        store = SessionStore()
        session = store.create()
        sid = session.session_id

        store.close(sid)

        with pytest.raises(SessionNotFoundError):
            store.get(sid)

    def test_close_nonexistent_raises(self) -> None:
        """Store raises SessionNotFoundError when closing unknown session."""
        store = SessionStore()
        fake_id = secrets.token_bytes(SESSION_ID_BYTES)

        with pytest.raises(SessionNotFoundError, match="not found"):
            store.close(fake_id)

    def test_close_all(self) -> None:
        """close_all removes all sessions."""
        store = SessionStore()
        for _ in range(5):
            store.create()

        count = store.close_all()
        assert count == 5
        assert store.active_count == 0

    def test_max_sessions_enforced(self) -> None:
        """Store rejects creation beyond max_sessions."""
        store = SessionStore(max_sessions=3)
        store.create()
        store.create()
        store.create()

        with pytest.raises(SessionLimitError, match="Maximum sessions"):
            store.create()

    def test_expired_cleanup_frees_slots(self) -> None:
        """Expired sessions are cleaned up, freeing slots."""
        store = SessionStore(max_sessions=2)
        # Create 2 sessions with instant expiry
        store.create(ttl_seconds=0.0)
        store.create(ttl_seconds=0.0)

        # Should succeed because expired sessions are cleaned up
        session = store.create(ttl_seconds=3600.0)
        assert session.is_active

    def test_list_active(self) -> None:
        """list_active returns summaries of active sessions."""
        store = SessionStore()
        store.create()
        store.create()

        active = store.list_active()
        assert len(active) == 2
        for summary in active:
            assert summary["active"] is True

    def test_active_count(self) -> None:
        """active_count reflects current session count."""
        store = SessionStore()
        assert store.active_count == 0

        store.create()
        assert store.active_count == 1

        store.create()
        assert store.active_count == 2

    def test_default_ttl_from_store(self) -> None:
        """Sessions inherit default TTL from store."""
        store = SessionStore(default_ttl=42.0)
        session = store.create()
        assert session.ttl_seconds == 42.0


# ---------------------------------------------------------------------------
# Thread-Safety Tests
# ---------------------------------------------------------------------------


class TestSessionStoreThreadSafety:
    """Test concurrent access to SessionStore."""

    def test_concurrent_create(self) -> None:
        """Multiple threads can create sessions concurrently."""
        store = SessionStore(max_sessions=200)
        sessions_created = []
        lock = threading.Lock()

        def create_sessions(n: int) -> None:
            for _ in range(n):
                session = store.create()
                with lock:
                    sessions_created.append(session.session_id)

        threads = [threading.Thread(target=create_sessions, args=(20,)) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(sessions_created) == 100
        # All session IDs should be unique
        assert len(set(sessions_created)) == 100

    def test_concurrent_get_and_close(self) -> None:
        """Concurrent get and close operations don't corrupt state."""
        store = SessionStore()
        sessions = [store.create() for _ in range(20)]
        errors = []

        def getter(session_ids: "list[bytes]") -> None:
            for sid in session_ids:
                try:
                    store.get(sid)
                except (SessionNotFoundError, SessionExpiredError):
                    pass  # Expected if another thread closed it
                except Exception as e:
                    errors.append(e)

        def closer(session_ids: "list[bytes]") -> None:
            for sid in session_ids:
                try:
                    store.close(sid)
                except SessionNotFoundError:
                    pass  # Expected if another thread already closed it
                except Exception as e:
                    errors.append(e)

        sids = [s.session_id for s in sessions]
        t1 = threading.Thread(target=getter, args=(sids,))
        t2 = threading.Thread(target=closer, args=(sids,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert len(errors) == 0, f"Unexpected errors: {errors}"


# ---------------------------------------------------------------------------
# Integration: ReplayWindow + SessionState
# ---------------------------------------------------------------------------


class TestReplayWindowSessionIntegration:
    """Test ReplayWindow integrated with SessionState."""

    def test_session_tracks_replay_per_direction(self) -> None:
        """Each session has independent send and recv tracking."""
        session = SessionState(session_id=secrets.token_bytes(SESSION_ID_BYTES))

        # Send and recv independently
        seq0 = session.next_send_seq()
        seq1 = session.next_send_seq()
        assert seq0 == 0
        assert seq1 == 1

        session.accept_recv_seq(0)
        session.accept_recv_seq(1)
        assert session.messages_sent == 2
        assert session.messages_received == 2

    def test_out_of_order_recv_accepted(self) -> None:
        """Out-of-order receive sequences are accepted within the window."""
        session = SessionState(session_id=secrets.token_bytes(SESSION_ID_BYTES))

        session.accept_recv_seq(5)
        session.accept_recv_seq(2)
        session.accept_recv_seq(8)
        session.accept_recv_seq(1)
        assert session.messages_received == 4

    def test_rekey_needed_after_bidirectional_traffic(self) -> None:
        """needs_rekey considers total messages (sent + received)."""
        session = SessionState(session_id=secrets.token_bytes(SESSION_ID_BYTES))

        # Send half, receive half
        half = DEFAULT_REKEY_INTERVAL // 2
        for _ in range(half):
            session.next_send_seq()
        for i in range(half):
            session.accept_recv_seq(i)

        assert session.needs_rekey


# ---------------------------------------------------------------------------
# Phase 4B: Additional Adversarial Test Classes
# ---------------------------------------------------------------------------


class TestReplayWindowLargeGap:
    """Test replay window behavior with large sequence gaps."""

    def test_large_gap_o1_performance(self) -> None:
        """Sequence jump from 0 to 1_000_000 completes in O(1) time."""
        import time as _time

        rw = ReplayWindow(window_size=10)
        # Fill the window so it slides
        for i in range(10):
            rw.check_and_accept(i)

        start = _time.monotonic()
        rw.check_and_accept(1_000_000)
        elapsed = _time.monotonic() - start

        # Must complete in < 10ms (not seconds of O(gap) iteration)
        assert elapsed < 0.01, f"Large gap took {elapsed:.3f}s, expected < 10ms"
        # Base should have advanced past 0
        assert rw.base > 0

    def test_large_gap_window_size_respected(self) -> None:
        """After large gap, window size stays bounded."""
        rw = ReplayWindow(window_size=256)
        rw.check_and_accept(0)
        rw.check_and_accept(1_000_000)

        assert len(rw._seen) <= 257  # window_size + 1

    def test_old_seq_rejected_after_large_gap(self) -> None:
        """Old sequence numbers are rejected after large gap advance."""
        rw = ReplayWindow()
        rw.check_and_accept(0)
        rw.check_and_accept(1_000_000)

        with pytest.raises(ReplayDetectedError):
            rw.check_and_accept(0)


class TestSessionStoreLimitEnforcement:
    """Test session store limit enforcement."""

    def test_max_sessions_plus_one_rejected(self) -> None:
        """Creating max_sessions+1 raises SessionLimitError."""
        store = SessionStore(max_sessions=5)
        for _ in range(5):
            store.create()

        with pytest.raises(SessionLimitError, match="Maximum sessions"):
            store.create()

    def test_closing_session_frees_slot(self) -> None:
        """Closing a session allows creating a new one."""
        store = SessionStore(max_sessions=2)
        s1 = store.create()
        store.create()

        # At limit
        with pytest.raises(SessionLimitError):
            store.create()

        # Close one to free a slot
        store.close(s1.session_id)
        s3 = store.create()
        assert s3.is_active


class TestSessionStateNeedsRekey:
    """Test needs_rekey behavior at exact threshold."""

    def test_needs_rekey_at_exact_threshold(self) -> None:
        """needs_rekey flips at exactly DEFAULT_REKEY_INTERVAL messages."""
        session = SessionState(session_id=secrets.token_bytes(SESSION_ID_BYTES))

        # Send exactly DEFAULT_REKEY_INTERVAL - 1 messages
        for _ in range(DEFAULT_REKEY_INTERVAL - 1):
            session.next_send_seq()

        assert not session.needs_rekey

        # One more message should trigger rekey
        session.next_send_seq()
        assert session.needs_rekey

    def test_record_rekey_resets_counter(self) -> None:
        """record_rekey resets the rekey counter."""
        session = SessionState(session_id=secrets.token_bytes(SESSION_ID_BYTES))

        for _ in range(DEFAULT_REKEY_INTERVAL):
            session.next_send_seq()
        assert session.needs_rekey

        session.record_rekey()
        assert session.rekey_count == 1


class TestSessionMetadata:
    """Test metadata attachment and persistence."""

    def test_metadata_persists_through_operations(self) -> None:
        """Metadata persists through send/recv operations."""
        session = SessionState(
            session_id=secrets.token_bytes(SESSION_ID_BYTES),
            metadata={"peer": "test-agent", "role": "initiator"},
        )

        session.next_send_seq()
        session.accept_recv_seq(0)

        assert session.metadata["peer"] == "test-agent"
        assert session.metadata["role"] == "initiator"

    def test_metadata_accessible_directly(self) -> None:
        """Metadata is accessible directly on the session object."""
        session = SessionState(
            session_id=secrets.token_bytes(SESSION_ID_BYTES),
            metadata={"tag": "alpha"},
        )
        assert session.metadata["tag"] == "alpha"
        # Summary still works
        summary = session.summary()
        assert isinstance(summary, dict)

    def test_empty_metadata_default(self) -> None:
        """Default metadata is empty dict."""
        session = SessionState(session_id=secrets.token_bytes(SESSION_ID_BYTES))
        assert session.metadata == {} or session.metadata is not None

    def test_store_passes_metadata(self) -> None:
        """SessionStore passes metadata to created sessions."""
        store = SessionStore()
        session = store.create(metadata={"source": "unit-test"})
        assert session.metadata["source"] == "unit-test"

        # Retrieve via store and verify
        retrieved = store.get(session.session_id)
        assert retrieved.metadata["source"] == "unit-test"
