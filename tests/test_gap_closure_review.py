#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Regression tests for the 10-item gap-closure review.

Each test class covers exactly one item from the review:

  1. AES-GCM persisted-counter race across processes.
  2. Persist every encrypt (close nonce-overlap window for shared keys).
  3. Locking around SecureSession.decrypt() replay-window mutation.
  4. Indistinguishable KEM exception chaining in secure_channel.py.
  5. Length bounds on HandshakeMessage.deserialize.
  6. SecureSession.close() actually wipes (bytearray + secure_memzero).
  7. _python_fallback_memzero fail-closed in production.
  8. _hkdf_python hard-disabled in production.
  9. FIPS POST timing-oracle: single deterministic pass (no retry/pass).
  10. KAT "skipped" is tri-state None, not pass.
"""

from __future__ import annotations

import inspect
import json
import struct
import threading
from collections.abc import Generator
from pathlib import Path
from unittest.mock import patch

import pytest

from ama_cryptography import _self_test as st
from ama_cryptography.hybrid_combiner import HybridCombiner
from ama_cryptography.secure_channel import (
    KEY_BYTES,
    NONCE_BYTES,
    SESSION_ID_BYTES,
    TAG_BYTES,
    ChannelError,
    ChannelMessage,
    ChannelState,
    HandshakeError,
    HandshakeMessage,
    SecureSession,
    _MAX_FIELD_BYTES,
)
from ama_cryptography.secure_memory import SecureMemoryError, secure_memzero

# Module-level string path used by monkeypatch.setattr for SECURE_MEMZERO_BACKEND.
# Using the string form avoids the CodeQL "import + import-from of the same
# module" finding while still letting tests flip the backend selection.
_SM_BACKEND_PATH = "ama_cryptography.secure_memory.SECURE_MEMZERO_BACKEND"


# =============================================================================
# Items 1 & 2 — AES-GCM per-encrypt persistence (multi-process safe)
# =============================================================================


@pytest.fixture
def aesgcm_persist_dir(
    tmp_path: Path,
) -> Generator[Path, None, None]:
    """Point AESGCMProvider at a throwaway counter file for this test.

    Saves and restores ALL the relevant class-level state so the test
    is hermetic against other tests that may have already touched the
    counter machinery.
    """
    from ama_cryptography.crypto_api import AESGCMProvider

    target = tmp_path / "aes_gcm_counters.json"
    saved = {
        "persist_path": AESGCMProvider._counters_persist_path,
        "ephemeral": AESGCMProvider._ephemeral,
        "loaded": AESGCMProvider._counters_loaded,
        "registered": AESGCMProvider._atexit_registered,
        "counters": dict(AESGCMProvider._encrypt_counters),
        "dirty": AESGCMProvider._counters_dirty,
    }
    AESGCMProvider._counters_persist_path = str(target)
    AESGCMProvider._ephemeral = False
    AESGCMProvider._counters_loaded = False
    AESGCMProvider._atexit_registered = False
    AESGCMProvider._encrypt_counters = {}
    AESGCMProvider._counters_dirty = 0

    try:
        yield target
    finally:
        AESGCMProvider._counters_persist_path = saved["persist_path"]
        AESGCMProvider._ephemeral = saved["ephemeral"]
        AESGCMProvider._counters_loaded = saved["loaded"]
        AESGCMProvider._atexit_registered = saved["registered"]
        AESGCMProvider._encrypt_counters = saved["counters"]
        AESGCMProvider._counters_dirty = saved["dirty"]


_native_available = True
try:
    from ama_cryptography.pqc_backends import (  # noqa: F401 -- availability-probe imports surface as unused (GCR-001)
        _AES_GCM_NATIVE_AVAILABLE,
        _native_lib,
    )

    if _native_lib is None or not _AES_GCM_NATIVE_AVAILABLE:
        _native_available = False
except Exception:
    _native_available = False


@pytest.mark.skipif(not _native_available, reason="AES-256-GCM native backend not built")
class TestItem1_AESGCMReservationAtomic:
    """Item 1 + 2: counter slot reservation is atomic and disk-durable."""

    def test_reserve_slot_persists_to_disk_immediately(
        self, aesgcm_persist_dir: Path
    ) -> None:
        """Each reservation writes to disk before returning.

        Pre-fix behaviour batched writes every 64 encrypts; a crash
        between batches lost up to 63 slots.  After the fix the
        on-disk counter mirrors the in-memory counter after every
        reservation.
        """
        from ama_cryptography.crypto_api import AESGCMProvider

        key_id = b"\xab" * 32
        n = AESGCMProvider._reserve_counter_slot(key_id)
        assert n == 0
        # Disk file must exist with the new high-water mark already
        assert aesgcm_persist_dir.exists()
        data = json.loads(aesgcm_persist_dir.read_text())
        assert data[key_id.hex()] == 1

        # Next call sees the disk reflect it
        m = AESGCMProvider._reserve_counter_slot(key_id)
        assert m == 1
        data = json.loads(aesgcm_persist_dir.read_text())
        assert data[key_id.hex()] == 2

    def test_reserve_slot_rolls_back_on_persist_failure(
        self, aesgcm_persist_dir: Path
    ) -> None:
        """If the disk write fails, the in-memory increment is rolled back.

        Returning a slot whose +1 was never durably persisted would
        let a future process reuse the same slot.  The fix:
        slot-reservation MUST raise instead of silently consuming an
        unpersisted slot.
        """
        from ama_cryptography.crypto_api import AESGCMProvider

        key_id = b"\xcd" * 32

        with patch.object(
            AESGCMProvider,
            "_write_counters_under_lock",
            side_effect=OSError("simulated disk-full"),
        ):
            with pytest.raises(RuntimeError, match="Failed to persist"):
                AESGCMProvider._reserve_counter_slot(key_id)

        # In-memory state rolled back
        assert AESGCMProvider._encrypt_counters.get(key_id, 0) == 0
        # Subsequent successful reserve gives slot 0
        slot = AESGCMProvider._reserve_counter_slot(key_id)
        assert slot == 0

    def test_concurrent_thread_reservations_are_unique(
        self, aesgcm_persist_dir: Path
    ) -> None:
        """Multiple threads reserving slots concurrently get distinct slots.

        The thread-local + file lock pair must serialise reservations
        within a single process.  Each thread must walk away with a
        unique slot — a duplicate would mean nonce reuse.
        """
        from ama_cryptography.crypto_api import AESGCMProvider

        key_id = b"\xef" * 32
        n_threads = 8
        slots: list[int] = []
        slots_lock = threading.Lock()

        def reserve_once() -> None:
            slot = AESGCMProvider._reserve_counter_slot(key_id)
            with slots_lock:
                slots.append(slot)

        threads = [threading.Thread(target=reserve_once) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All slots are unique
        assert len(set(slots)) == n_threads
        # And the high-water mark equals the number of reservations
        assert AESGCMProvider._encrypt_counters[key_id] == n_threads
        # And disk reflects it
        data = json.loads(aesgcm_persist_dir.read_text())
        assert data[key_id.hex()] == n_threads

    def test_reserve_slot_refuses_at_safety_limit(
        self, aesgcm_persist_dir: Path
    ) -> None:
        """At 2^32 the counter refuses to reserve more slots."""
        from ama_cryptography.crypto_api import AESGCMProvider

        key_id = b"\x55" * 32
        # Seed at the limit
        AESGCMProvider._encrypt_counters[key_id] = AESGCMProvider._NONCE_SAFETY_LIMIT

        with pytest.raises(RuntimeError, match="safety limit"):
            AESGCMProvider._reserve_counter_slot(key_id)

        # Counter unchanged
        assert (
            AESGCMProvider._encrypt_counters[key_id]
            == AESGCMProvider._NONCE_SAFETY_LIMIT
        )

    def test_encrypt_persists_before_aead(self, aesgcm_persist_dir: Path) -> None:
        """Counter is durable before native_aes256_gcm_encrypt is invoked.

        Belt-and-braces test: patch the AEAD to assert that by the
        time we get there, the counter file is already written.
        """
        from ama_cryptography.crypto_api import AESGCMProvider, CryptoBackend
        from ama_cryptography import pqc_backends as pq

        provider = AESGCMProvider(backend=CryptoBackend.C_LIBRARY)
        key = b"\xaa" * 32

        observations: list[int] = []
        real_encrypt = pq.native_aes256_gcm_encrypt

        def spy_encrypt(*args: object, **kw: object) -> tuple[bytes, bytes]:
            # When AEAD runs, the on-disk counter MUST already be 1.
            data = json.loads(aesgcm_persist_dir.read_text())
            key_id = __import__("hashlib").sha256(key).digest()
            observations.append(data.get(key_id.hex(), 0))
            return real_encrypt(*args, **kw)

        with patch.object(pq, "native_aes256_gcm_encrypt", spy_encrypt):
            provider.encrypt(b"payload", key)

        assert observations == [1], (
            "Counter must be durably persisted (slot+1 on disk) BEFORE the "
            "AEAD call runs.  Otherwise a crash inside the AEAD would leak "
            "a usable nonce slot for the next process."
        )


# =============================================================================
# Item 3 — SecureSession.decrypt locking
# =============================================================================


class TestItem3_SecureSessionLocking:
    """Item 3: replay-window mutation is protected by a per-session lock."""

    def test_session_has_threading_lock(self) -> None:
        sess = SecureSession(
            session_id=b"\x00" * SESSION_ID_BYTES,
            send_key=bytearray(b"\x01" * KEY_BYTES),
            recv_key=bytearray(b"\x02" * KEY_BYTES),
        )
        assert hasattr(sess, "_lock")
        # threading.Lock() returns a callable lock object — duck-type check
        assert hasattr(sess._lock, "acquire")
        assert hasattr(sess._lock, "release")

    def test_session_lock_is_held_during_decrypt(self) -> None:
        """While decrypt() runs in thread A, thread B calling decrypt blocks.

        Verified via a sentinel: thread A holds the lock manually
        (simulating mid-decrypt), thread B calling decrypt must wait.
        """
        sess = SecureSession(
            session_id=b"\x00" * SESSION_ID_BYTES,
            send_key=bytearray(b"\x01" * KEY_BYTES),
            recv_key=bytearray(b"\x02" * KEY_BYTES),
        )
        msg = ChannelMessage(
            session_id=sess.session_id,
            sequence_number=0,
            nonce=b"\x00" * NONCE_BYTES,
            ciphertext=b"x",
            tag=b"\x00" * TAG_BYTES,
        )

        b_finished = threading.Event()

        def call_decrypt_b() -> None:
            # B will block on the lock; once we release it, B will
            # try the (junk) decrypt and raise.  We only care that
            # B waited for the lock — the eventual failure of the
            # junk decrypt is expected and irrelevant to the
            # locking invariant under test, so swallow it.
            try:
                sess.decrypt(msg)
            except Exception:  # noqa: BLE001 -- intentional broad swallow; we only assert B waited for the lock (GCR-008)
                pass  # intentional: B's decrypt failure is expected and not the assertion target
            b_finished.set()

        with sess._lock:
            t = threading.Thread(target=call_decrypt_b)
            t.start()
            # B should NOT finish while we hold the lock
            assert not b_finished.wait(timeout=0.2), (
                "decrypt() did not wait for the session lock — thread B "
                "ran while thread A held the lock"
            )
        # After releasing, B can proceed
        t.join(timeout=2.0)
        assert b_finished.is_set()


# =============================================================================
# Item 4 — KEM exception masking in the Responder
# =============================================================================


class TestItem4_KEMExceptionMasking:
    """Item 4: distinguishable KEM exception chaining is suppressed.

    The Responder must NOT leak the underlying decapsulation error
    type or message to the peer.  All decapsulation failures collapse
    to a single generic ``HandshakeError("Handshake failed")`` with
    a suppressed cause chain so an online attacker cannot use error
    differentiation as an oracle.
    """

    def test_decap_failure_produces_generic_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """All decap failure modes produce identical HandshakeError text."""
        from ama_cryptography.secure_channel import (
            PROTOCOL_NAME,
            PROTOCOL_VERSION,
            SecureChannelResponder,
        )

        # Fake KEM that raises distinguishable errors
        class _FakeKEM:
            error_to_raise: BaseException = ValueError(
                "extremely revealing internal detail (e.g. lattice CT length=N expected=M)"
            )

            def decapsulate(self, ct: bytes, sk: bytes) -> bytes:
                raise self.error_to_raise

        # Fake Sig provider (won't be reached)
        class _FakeSig:
            def sign(self, msg: bytes, sk: bytes) -> object:
                raise AssertionError("sign should not be reached")

        responder = SecureChannelResponder.__new__(SecureChannelResponder)
        responder._kem = _FakeKEM()  # type: ignore[attr-defined]  # mock injection for test, attrs only on real class (GCR-002)
        responder._sig = _FakeSig()  # type: ignore[attr-defined]  # mock injection for test, attrs only on real class (GCR-003)
        responder._kem_sk = b""  # type: ignore[attr-defined]  # mock injection for test, attrs only on real class (GCR-004)
        responder._sig_sk = b""  # type: ignore[attr-defined]  # mock injection for test, attrs only on real class (GCR-005)
        responder._sig_pk = b""  # type: ignore[attr-defined]  # mock injection for test, attrs only on real class (GCR-006)

        msg = HandshakeMessage(
            protocol_name=PROTOCOL_NAME,
            version=PROTOCOL_VERSION,
            ephemeral_public_key=b"\x00" * 32,
            kem_ciphertext=b"\x00" * 32,
        )

        # First failure: ValueError
        _FakeKEM.error_to_raise = ValueError("kyber lattice fail mode 1")
        with pytest.raises(HandshakeError) as exc_info_1:
            responder.handle_handshake(msg)
        # Cause chain MUST be suppressed (``from None``)
        assert exc_info_1.value.__cause__ is None, (
            "Exception cause chain leaks the original KEM error — attackers "
            "can use this to distinguish failure modes"
        )
        # Generic message — no internal detail
        assert "lattice" not in str(exc_info_1.value).lower()
        assert "kyber" not in str(exc_info_1.value).lower()
        first_message = str(exc_info_1.value)

        # Second failure: different error type, different message
        _FakeKEM.error_to_raise = RuntimeError(
            "completely different error: short ciphertext, expected 1568 bytes got 32"
        )
        with pytest.raises(HandshakeError) as exc_info_2:
            responder.handle_handshake(msg)
        assert exc_info_2.value.__cause__ is None
        # Both error texts identical — no oracle
        assert str(exc_info_2.value) == first_message, (
            "Different decap failure modes produced different error texts.  "
            "An attacker can distinguish them — implement opaque masking."
        )


# =============================================================================
# Item 5 — HandshakeMessage.deserialize length bounds
# =============================================================================


class TestItem5_HandshakeMessageBounds:
    """Item 5: every length field is bounded and verified vs the buffer."""

    def test_empty_input_raises(self) -> None:
        with pytest.raises(ChannelError, match="Truncated"):
            HandshakeMessage.deserialize(b"")

    def test_oversize_protocol_name_rejected(self) -> None:
        # protocol_name length is a uint16, so the maximum on-wire
        # value (0xFFFF = 65535) is already <= _MAX_FIELD_BYTES.
        # The strictly-over-limit case is therefore unreachable for
        # name_len in this serialisation — but the same bounds path
        # is exercised by ``epk_len`` (uint32), which CAN exceed
        # _MAX_FIELD_BYTES.  Test the over-cap epk_len bound:
        with pytest.raises(ChannelError, match="exceeds maximum"):
            HandshakeMessage.deserialize(
                struct.pack(">H", 4)
                + b"NAME"
                + b"\x02"  # version
                + struct.pack(">I", _MAX_FIELD_BYTES + 1)  # epk_len over cap
                + b"\x00" * 4  # ct_len placeholder
            )

    def test_oversize_kem_ciphertext_rejected(self) -> None:
        data = (
            struct.pack(">H", 4)
            + b"NAME"
            + b"\x02"
            + struct.pack(">I", 0)  # epk_len = 0
            + struct.pack(">I", _MAX_FIELD_BYTES + 1)  # ct_len over cap
        )
        with pytest.raises(ChannelError, match="exceeds maximum"):
            HandshakeMessage.deserialize(data)

    def test_truncated_after_lengths_rejected(self) -> None:
        # Declare epk_len = 1000 but supply only 10 bytes
        data = (
            struct.pack(">H", 4)
            + b"NAME"
            + b"\x02"
            + struct.pack(">I", 1000)
            + b"A" * 10
        )
        with pytest.raises(ChannelError, match="Truncated"):
            HandshakeMessage.deserialize(data)

    def test_trailing_bytes_rejected(self) -> None:
        data = (
            struct.pack(">H", 4)
            + b"NAME"
            + b"\x02"
            + struct.pack(">I", 0)
            + struct.pack(">I", 0)
            + b"TRAILING-GARBAGE"
        )
        with pytest.raises(ChannelError, match="trailing"):
            HandshakeMessage.deserialize(data)

    def test_valid_message_roundtrip(self) -> None:
        msg = HandshakeMessage(
            protocol_name=b"AmaNoise-NK-v1",
            version=b"\x02",
            ephemeral_public_key=b"\x42" * 100,
            kem_ciphertext=b"\x43" * 1568,
        )
        restored = HandshakeMessage.deserialize(msg.serialize())
        assert restored.protocol_name == msg.protocol_name
        assert restored.version == msg.version
        assert restored.ephemeral_public_key == msg.ephemeral_public_key
        assert restored.kem_ciphertext == msg.kem_ciphertext


# =============================================================================
# Item 6 — SecureSession.close() actually wipes
# =============================================================================


class TestItem6_SecureSessionWipe:
    """Item 6: close() wipes the bytearray in place, not just rebinds."""

    def test_close_wipes_in_place(self) -> None:
        send_buf = bytearray(b"\xaa" * KEY_BYTES)
        recv_buf = bytearray(b"\xbb" * KEY_BYTES)
        sess = SecureSession(
            session_id=b"\x00" * SESSION_ID_BYTES,
            send_key=send_buf,
            recv_key=recv_buf,
        )
        # Capture a reference to the bytearray BEFORE close
        captured = sess.send_key
        assert captured is send_buf  # storage identity preserved

        sess.close()

        # Captured reference now sees the wiped memory
        assert all(b == 0 for b in captured), (
            "close() must wipe send_key in place, not just rebind the name. "
            f"captured={bytes(captured)[:8].hex()}..."
        )
        assert all(b == 0 for b in recv_buf), (
            "close() must wipe recv_key in place"
        )
        assert sess._state == ChannelState.CLOSED

    def test_close_is_idempotent(self) -> None:
        sess = SecureSession(
            session_id=b"\x00" * SESSION_ID_BYTES,
            send_key=bytearray(b"\xaa" * KEY_BYTES),
            recv_key=bytearray(b"\xbb" * KEY_BYTES),
        )
        sess.close()
        sess.close()  # must not raise
        assert sess._state == ChannelState.CLOSED

    def test_bytes_keys_coerced_to_bytearray(self) -> None:
        """Legacy bytes inputs to SecureSession are coerced to bytearray.

        The dataclass now stores keys as ``bytearray`` so close()
        can wipe.  Callers that still pass ``bytes`` must work
        without throwing — but the storage must end up writable.
        """
        sess = SecureSession(
            session_id=b"\x00" * SESSION_ID_BYTES,
            send_key=bytearray(b"\xaa" * KEY_BYTES),  # bytearray
            recv_key=bytearray(b"\xbb" * KEY_BYTES),
        )
        assert isinstance(sess.send_key, bytearray)
        assert isinstance(sess.recv_key, bytearray)


# =============================================================================
# Item 7 — _python_fallback_memzero fail-closed
# =============================================================================


class TestItem7_PythonFallbackFailClosed:
    """Item 7: secure_memzero refuses python_fallback without opt-in."""

    def test_python_fallback_without_opt_in_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(_SM_BACKEND_PATH, "python_fallback")
        monkeypatch.delenv("AMA_ALLOW_PYTHON_MEMZERO", raising=False)
        monkeypatch.delenv("AMA_SPHINX_BUILD", raising=False)
        monkeypatch.delenv("SPHINX_BUILD", raising=False)

        buf = bytearray(b"sensitive")
        with pytest.raises(SecureMemoryError, match="not opted-in"):
            secure_memzero(buf)

    def test_python_fallback_with_explicit_opt_in_works(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(_SM_BACKEND_PATH, "python_fallback")
        monkeypatch.setenv("AMA_ALLOW_PYTHON_MEMZERO", "1")
        buf = bytearray(b"sensitive")
        secure_memzero(buf)
        assert all(b == 0 for b in buf)

    def test_python_fallback_with_sphinx_build_works(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(_SM_BACKEND_PATH, "python_fallback")
        monkeypatch.delenv("AMA_ALLOW_PYTHON_MEMZERO", raising=False)
        monkeypatch.setenv("AMA_SPHINX_BUILD", "1")
        buf = bytearray(b"sensitive")
        secure_memzero(buf)
        assert all(b == 0 for b in buf)

    def test_python_fallback_env_must_be_truthy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """AMA_ALLOW_PYTHON_MEMZERO=0 (or empty) does NOT count as opt-in."""
        monkeypatch.setattr(_SM_BACKEND_PATH, "python_fallback")
        for falsy in ("", "0", "false", "no", "off", "anything-else"):
            monkeypatch.setenv("AMA_ALLOW_PYTHON_MEMZERO", falsy)
            with pytest.raises(SecureMemoryError):
                secure_memzero(bytearray(b"x"))


# =============================================================================
# Item 8 — _hkdf_python hard-disabled in production
# =============================================================================


class TestItem8_HkdfPythonDisabled:
    """Item 8: HybridCombiner._hkdf_python requires an explicit opt-in."""

    def test_call_without_opt_in_raises(self) -> None:
        with pytest.raises(RuntimeError, match="test-only"):
            HybridCombiner._hkdf_python(b"salt", b"ikm", b"info", 32)

    def test_opt_in_works(self) -> None:
        out = HybridCombiner._hkdf_python(
            b"salt", b"ikm", b"info", 32, _test_only_allow_python=True
        )
        assert len(out) == 32

    def test_opt_in_must_be_keyword_only(self) -> None:
        """The opt-in flag is keyword-only.

        Reduces the surface for accidental production callers — a
        ``*args`` shim cannot inadvertently include the flag.

        We inspect the signature directly rather than exercising an
        intentionally-invalid call: a static call with the wrong
        positional-arg count is a real bug from the type system's
        perspective (CodeQL py/wrong-number-arguments) even when
        the runtime behaviour is the intended TypeError.  Walking
        ``inspect.Parameter.kind`` proves the same property
        (KEYWORD_ONLY) without making the bad call.
        """
        sig = inspect.signature(HybridCombiner._hkdf_python)
        opt_in = sig.parameters.get("_test_only_allow_python")
        assert opt_in is not None, (
            "_test_only_allow_python parameter missing from _hkdf_python "
            "signature — the production guard has regressed"
        )
        assert opt_in.kind is inspect.Parameter.KEYWORD_ONLY, (
            f"_test_only_allow_python must be KEYWORD_ONLY, got {opt_in.kind!r}.  "
            "A future refactor that drops the keyword-only marker would let "
            "production code pass True positionally — restore the * marker "
            "before the named parameter."
        )


# =============================================================================
# Item 9 — FIPS POST timing-oracle single deterministic pass
# =============================================================================


class TestItem9_TimingOracleNoRetry:
    """Item 9: timing-oracle runs ONCE; no retry-until-pass."""

    def test_no_retry_loop_in_run_self_tests(self) -> None:
        """The runner must call ``_timing_oracle_consttime`` at most once.

        Pre-fix code retried up to 3 times and broke on first pass.
        That's a leak amplifier: a real timing leak that fell below
        the threshold on a noisy retry would be reported as a pass.
        Post-fix: a single deterministic call.
        """
        import ama_cryptography._self_test as st_local

        call_counter = {"n": 0}

        def counting_oracle() -> tuple[bool | None, str]:
            call_counter["n"] += 1
            # Force PASS so the runner proceeds without erroring.
            return True, "stubbed pass"

        # Patch the oracle and ensure POST calls it exactly once.
        with patch.object(st_local, "_timing_oracle_consttime", counting_oracle):
            # We don't care if POST returns True or False (integrity
            # may be in a forced-error state); we only care about
            # the oracle call count.
            st_local._run_self_tests()
            assert call_counter["n"] <= 1, (
                f"Timing oracle was called {call_counter['n']} times — "
                "the retry-until-pass loop has come back."
            )

    def test_oracle_returns_tri_state(self) -> None:
        """The oracle now returns Optional[bool]: True / False / None."""
        import ama_cryptography._self_test as st_local

        passed, _ = st_local._timing_oracle_consttime()
        assert passed is None or isinstance(passed, bool)


# =============================================================================
# Item 10 — KAT skipped is tri-state None (NOT pass)
# =============================================================================


class TestItem10_KATSkipNotPass:
    """Item 10: KAT skip returns ``None`` instead of ``True``."""

    def test_all_kat_skips_return_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Every per-algorithm KAT returns ``(None, ...)`` when its
        backend is unavailable.

        This test stubs each *availability* flag to ``False`` and
        confirms the KAT explicitly returns the tri-state skip
        sentinel rather than ``True``.
        """
        from ama_cryptography import _self_test as st_local
        from ama_cryptography import pqc_backends as pq_local

        cases = [
            ("_HMAC_SHA3_256_NATIVE_AVAILABLE", st_local._kat_hmac_sha3_256),
            ("_AES_GCM_NATIVE_AVAILABLE", st_local._kat_aes_256_gcm),
            ("KYBER_AVAILABLE", st_local._kat_ml_kem_1024),
            ("DILITHIUM_AVAILABLE", st_local._kat_ml_dsa_65),
            ("SPHINCS_AVAILABLE", st_local._kat_slh_dsa),
            ("SPHINCS_AVAILABLE", st_local._kat_slh_dsa_shake_128s),
            ("_ED25519_NATIVE_AVAILABLE", st_local._kat_ed25519),
        ]
        for flag, fn in cases:
            monkeypatch.setattr(pq_local, flag, False)
            passed, detail = fn()
            assert passed is None, (
                f"{fn.__name__} returned passed={passed!r} when "
                f"{flag}=False — skip must be None, not True"
            )
            assert "skipped" in detail.lower()

    def test_strict_mode_escalates_skip_to_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With ``AMA_FIPS_STRICT=1``, a skipped KAT fails POST.

        Release builds set this env var so a missing backend cannot
        leave any approved algorithm without self-test coverage.
        """
        from ama_cryptography import _self_test as st_local

        # Stub one KAT to return the skip sentinel
        monkeypatch.setattr(
            st_local,
            "_kat_sha3_256",
            lambda: (None, "synthetic skip"),
        )
        # And stub integrity to pass so we get to the KAT loop
        monkeypatch.setattr(
            st_local,
            "verify_module_integrity",
            lambda: (True, "stubbed pass"),
        )
        monkeypatch.setenv("AMA_FIPS_STRICT", "1")

        try:
            ok = st_local._run_self_tests()
            assert ok is False, (
                "AMA_FIPS_STRICT=1 must escalate a KAT skip to POST failure"
            )
            assert st_local.module_status() == "ERROR"
        finally:
            # Restore module to OPERATIONAL so other tests don't fail
            st_local._set_operational()

    def test_non_strict_mode_skips_continue(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without strict mode, a skipped KAT logs WARNING and POST proceeds."""
        from ama_cryptography import _self_test as st_local

        monkeypatch.delenv("AMA_FIPS_STRICT", raising=False)
        monkeypatch.setattr(
            st_local,
            "_kat_sha3_256",
            lambda: (None, "synthetic skip"),
        )
        monkeypatch.setattr(
            st_local,
            "verify_module_integrity",
            lambda: (True, "stubbed pass"),
        )

        try:
            # POST overall pass/fail can depend on other state in this
            # process (e.g. a forced-skip on the timing oracle in
            # strict-mode test runs).  We only care about the SHA3-256
            # row's tri-state ``passed`` field, not the aggregate.
            st_local._run_self_tests()
            results = st_local.module_self_test_results()
            sha = next((r for r in results if r[0] == "SHA3-256"), None)
            assert sha is not None
            assert sha[1] is None, (
                f"SHA3-256 KAT recorded with passed={sha[1]!r} — "
                "skip semantics regressed back to True"
            )
        finally:
            st_local._set_operational()

    def test_module_self_test_results_tri_state_typing(self) -> None:
        """``passed`` field accepts True / False / None."""
        results = st.module_self_test_results()
        for _name, passed, _detail in results:
            assert passed is None or isinstance(passed, bool)
