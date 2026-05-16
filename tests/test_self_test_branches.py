#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Branch-coverage additions for ``ama_cryptography._self_test``.

Focuses on KAT failure paths (both within individual KATs and inside
``_run_self_tests``), timing-oracle negative outcomes, and the RNG
health check — all of which are exceedingly hard to trigger "for real"
and are therefore covered via monkeypatching the algorithms the KATs
depend on.

Integrity hygiene
-----------------
These tests deliberately force ``_run_self_tests()`` into the ERROR
state. Earlier versions of this file called ``update_integrity_digest()``
in each ``finally`` block to restore ``OPERATIONAL`` for the next test,
which mutated the real ``_integrity_digest.txt`` on disk. We instead
redirect ``_INTEGRITY_DIGEST_FILE`` to a tmp-path in tests that request
the ``isolated_integrity_file`` fixture, so the runner is free to write
/ refresh the digest without touching the real package baseline.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Generator
from pathlib import Path
from typing import Callable, cast

import pytest

from ama_cryptography import _self_test as st


@pytest.fixture
def isolated_integrity_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Generator[Path, None, None]:
    """Redirect ``_INTEGRITY_DIGEST_FILE`` to a throwaway file for this test.

    The tmp file is seeded with the real package digest so
    ``verify_module_integrity()`` passes on entry. After the test
    finishes, pytest's monkeypatch fixture restores the original
    attribute automatically, so we only need to capture the baseline
    once. This keeps the real ``_integrity_digest.txt`` untouched even
    if the test re-runs ``update_integrity_digest()``.
    """
    fake = tmp_path / "_integrity_digest.txt"
    if st._INTEGRITY_DIGEST_FILE.exists():
        fake.write_text(st._INTEGRITY_DIGEST_FILE.read_text(encoding="utf-8"))
    monkeypatch.setattr(st, "_INTEGRITY_DIGEST_FILE", fake)
    yield fake


# ---------------------------------------------------------------------------
# Timing oracle negative branches
# ---------------------------------------------------------------------------


class TestTimingOracleBranches:
    def test_timing_oracle_detects_position_dependent_early_exit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """First-vs-last mismatch classes catch memcmp-style early exits."""

        ticks = {"now": 0}

        def fake_perf_counter_ns() -> int:
            ticks["now"] += 100
            return ticks["now"]

        def fake_memcmp(left: bytes, right: bytes, size: int) -> int:
            for i in range(size):
                if left[i] != right[i]:
                    ticks["now"] += i * 100
                    return 1
            ticks["now"] += size * 100
            return 0

        import ama_cryptography.secure_memory as sm

        monkeypatch.setattr(time, "perf_counter_ns", fake_perf_counter_ns)
        monkeypatch.setattr(
            sm,
            "_native_consttime_memcmp",
            cast(Callable[[bytes, bytes, int], int], fake_memcmp),
        )

        passed, detail = st._timing_oracle_consttime()
        assert passed is False
        # Accept either the legacy ("Timing leak detected") or the post-RA7BN
        # auditable form ("FIPS POST: timing-leak detected ... Operator
        # remediation:"); both are valid fail-closed outcomes.
        assert "timing-leak detected" in detail.lower() or "timing leak detected" in detail.lower()
        assert "remediation" in detail.lower() or "delta=" in detail

    def test_timing_oracle_min_effect_floor_suppresses_small_delta_false_positive(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """High-|t|, low-delta signals (host jitter) MUST NOT trip POST.

        This reproduces the Ubuntu 3.11 shared-runner failure: |t|=8.34 with
        delta=25 ns.  Under the post-RA7BN floor (50 ns), this pattern must
        be ABSORBED as scheduler noise rather than treated as a real leak —
        otherwise the module flips to ERROR and every subsequent crypto
        call is locked out for a non-cryptographic reason.

        Construction: simulate two classes that average exactly
        ``_TIMING_MIN_EFFECT_NS - epsilon`` apart but with extremely tight
        variance.  The tight variance forces |t| above 4.5; the small mean
        delta keeps the absolute effect below the floor.  The fail-closed
        contract for a *real* leak is preserved by the companion test
        ``test_timing_oracle_detects_position_dependent_early_exit`` (which
        injects deltas in the thousands-of-ns range — well above any floor
        we'd reasonably set).
        """

        # Target delta: just under the configured 50 ns floor.
        target_delta = st._TIMING_MIN_EFFECT_NS - 5.0
        assert target_delta > 0, "guard: floor must be > 5 ns for this test to be meaningful"

        # Interleaved measurement loop alternates which class gets the *first*
        # half of each pair (see ``_measure_timing_batch``).  Returning a
        # constant integer per call gives mean1 == mean2 (no |t|).  Instead,
        # we use a counter that returns a deterministic pair of values so
        # class A is exactly ``target_delta`` ns slower than class B every
        # iteration, with zero within-class variance.  Zero variance → SE → 0
        # → |t| → infinity, which is the worst-case false-positive shape.
        call_state = {"now": 0}

        def fake_perf_counter_ns() -> int:
            now = call_state["now"]
            call_state["now"] = now + 1  # arbitrary monotonic tick; deltas
            # computed below via memcmp side effect.
            return now

        # The driver under test pairs two start/end measurements per memcmp
        # call.  We make the memcmp function advance the clock by a known
        # amount: ``target_delta`` for "class A" inputs, 0 for "class B".
        def fake_memcmp(left: bytes, right: bytes, size: int) -> int:
            # Distinguish class A from B by which buffer the mismatch is in.
            # ``_timing_oracle_consttime`` builds class A as a first-byte
            # mismatch and class B as a last-byte mismatch.
            is_class_a = left[0] != right[0]
            call_state["now"] += int(target_delta) if is_class_a else 0
            return 1

        import ama_cryptography.secure_memory as sm

        monkeypatch.setattr(time, "perf_counter_ns", fake_perf_counter_ns)
        monkeypatch.setattr(
            sm,
            "_native_consttime_memcmp",
            cast(Callable[[bytes, bytes, int], int], fake_memcmp),
        )

        passed, detail = st._timing_oracle_consttime()
        # With delta < floor the oracle MUST return True (no false-positive),
        # regardless of how large |t| is — the absolute-effect floor is the
        # second gate that guards against jitter-only signals.
        assert passed is True, (
            f"min-effect floor failed to suppress sub-floor delta: "
            f"got passed={passed!r}, detail={detail!r}"
        )
        assert "OK" in detail or "constant" in detail.lower()


class TestPOSTLockoutLabelling:
    """Regression: downstream errors from POST lockout must be labelled.

    The change in this PR makes ``check_operational`` produce error messages
    that clearly identify the call as a *symptom* of a prior POST failure,
    not a fresh independent error.  This keeps CI logs readable: one root
    cause, N labelled downstream symptoms.
    """

    def test_check_operational_labels_downstream_failures(self) -> None:
        from ama_cryptography._self_test import (
            _set_error,
            _set_operational,
            check_operational,
        )
        from ama_cryptography.exceptions import CryptoModuleError

        try:
            _set_error("FIPS POST: timing-leak detected in ama_consttime_memcmp")
            with pytest.raises(CryptoModuleError) as exc_info:
                check_operational()
            msg = str(exc_info.value)
            # Symptom labelling
            assert "locked out by FIPS POST failure" in msg
            assert "downstream symptom" in msg
            # Root cause preserved verbatim
            assert "timing-leak detected" in msg
        finally:
            _set_operational()


# ---------------------------------------------------------------------------
# KAT failure branches
# ---------------------------------------------------------------------------


class TestKatFailureBranches:
    def test_kat_sha3_256_returns_false_on_wrong_digest(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If hashlib.sha3_256 yields the wrong digest, KAT reports failure."""

        class _FakeDigest:
            @staticmethod
            def hexdigest() -> str:
                return "00" * 32

        def _fake_sha3_256(_data: bytes) -> _FakeDigest:
            return _FakeDigest()

        monkeypatch.setattr(hashlib, "sha3_256", _fake_sha3_256)
        passed, detail = st._kat_sha3_256()
        assert passed is False
        assert "fail" in detail.lower() or "got" in detail.lower()

    def test_kat_hmac_sha3_256_wrong_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Wrong HMAC output triggers the mismatch branch."""
        from ama_cryptography import pqc_backends as pq

        if not pq._HMAC_SHA3_256_NATIVE_AVAILABLE:
            pytest.skip("HMAC-SHA3-256 native backend not built")

        monkeypatch.setattr(pq, "native_hmac_sha3_256", lambda key, data: b"\x00" * 32)
        passed, detail = st._kat_hmac_sha3_256()
        assert passed is False
        assert "KAT" in detail

    def test_kat_hmac_sha3_256_exception_branch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from ama_cryptography import pqc_backends as pq

        if not pq._HMAC_SHA3_256_NATIVE_AVAILABLE:
            pytest.skip("HMAC-SHA3-256 native backend not built")

        def _boom(_k: bytes, _d: bytes) -> bytes:
            raise RuntimeError("simulated native failure")

        monkeypatch.setattr(pq, "native_hmac_sha3_256", _boom)
        passed, detail = st._kat_hmac_sha3_256()
        assert passed is False
        assert "exception" in detail.lower()

    def test_kat_aes_256_gcm_ciphertext_mismatch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from ama_cryptography import pqc_backends as pq

        if not pq._AES_GCM_NATIVE_AVAILABLE:
            pytest.skip("AES-256-GCM native backend not built")

        def _fake_enc(*args: object, **kwargs: object) -> tuple[bytes, bytes]:
            return b"\x00" * 64, b"\x00" * 16  # wrong ct and tag

        monkeypatch.setattr(pq, "native_aes256_gcm_encrypt", _fake_enc)
        passed, detail = st._kat_aes_256_gcm()
        assert passed is False
        assert "ciphertext" in detail.lower() or "tag" in detail.lower()

    def test_kat_aes_256_gcm_exception_branch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from ama_cryptography import pqc_backends as pq

        if not pq._AES_GCM_NATIVE_AVAILABLE:
            pytest.skip("AES-256-GCM native backend not built")

        def _boom(*args: object, **kwargs: object) -> tuple[bytes, bytes]:
            raise RuntimeError("simulated encrypt failure")

        monkeypatch.setattr(pq, "native_aes256_gcm_encrypt", _boom)
        passed, detail = st._kat_aes_256_gcm()
        assert passed is False
        assert "exception" in detail.lower()

    def test_kat_ml_kem_1024_mismatch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from ama_cryptography import pqc_backends as pq

        if not pq.KYBER_AVAILABLE:
            pytest.skip("Kyber backend unavailable")

        monkeypatch.setattr(pq, "kyber_decapsulate", lambda ct, sk: b"\x00" * 32)
        passed, detail = st._kat_ml_kem_1024()
        assert passed is False
        assert "mismatch" in detail.lower()

    def test_kat_ml_dsa_65_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from ama_cryptography import pqc_backends as pq

        if not pq.DILITHIUM_AVAILABLE:
            pytest.skip("Dilithium backend unavailable")

        def _boom(*args: object, **kwargs: object) -> bytes:
            raise RuntimeError("simulated sign failure")

        monkeypatch.setattr(pq, "dilithium_sign", _boom)
        passed, detail = st._kat_ml_dsa_65()
        assert passed is False
        assert "exception" in detail.lower()


# ---------------------------------------------------------------------------
# Integrity branches
# ---------------------------------------------------------------------------


class TestIntegrityBranches:
    def test_update_integrity_then_verify_passes(self, isolated_integrity_file: Path) -> None:
        """``update_integrity_digest`` + ``verify_module_integrity`` round-trip.

        Runs against the redirected digest file so the real
        ``_integrity_digest.txt`` is never touched.
        """
        st.update_integrity_digest()
        assert isolated_integrity_file.exists()
        passed, _ = st.verify_module_integrity()
        assert passed is True


# ---------------------------------------------------------------------------
# _run_self_tests error branches
# ---------------------------------------------------------------------------


class TestRunSelfTestsFailures:
    """Tests that force ``_run_self_tests()`` into ERROR state.

    The ``isolated_integrity_file`` fixture redirects the digest file so
    the cleanup step (``update_integrity_digest()`` → ``_set_operational``)
    stays inside the tmp-path and does not mutate the real integrity
    baseline on disk.
    """

    def test_integrity_failure_short_circuits(
        self,
        monkeypatch: pytest.MonkeyPatch,
        isolated_integrity_file: Path,
    ) -> None:
        """A failing integrity check sets ERROR and aborts without running KATs."""
        from ama_cryptography._self_test import (
            _run_self_tests,
            _set_operational,
            module_status,
        )

        monkeypatch.setattr(
            "ama_cryptography._self_test.verify_module_integrity",
            lambda: (False, "synthetic integrity failure"),
        )
        try:
            assert _run_self_tests() is False
            assert module_status() == "ERROR"
        finally:
            # Redirected digest file: safe to regenerate in-place.
            st.update_integrity_digest()
            _set_operational()

    def test_integrity_exception_short_circuits(
        self,
        monkeypatch: pytest.MonkeyPatch,
        isolated_integrity_file: Path,
    ) -> None:
        from ama_cryptography._self_test import (
            _run_self_tests,
            _set_operational,
            module_status,
        )

        def _boom() -> tuple[bool, str]:
            raise RuntimeError("simulated integrity exception")

        monkeypatch.setattr("ama_cryptography._self_test.verify_module_integrity", _boom)
        try:
            assert _run_self_tests() is False
            assert module_status() == "ERROR"
        finally:
            st.update_integrity_digest()
            _set_operational()

    def test_kat_exception_sets_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
        isolated_integrity_file: Path,
    ) -> None:
        from ama_cryptography._self_test import (
            _run_self_tests,
            _set_operational,
            module_status,
        )

        # Force the first KAT to raise; the runner must treat this as failure.
        def _boom() -> tuple[bool, str]:
            raise RuntimeError("KAT exploded")

        monkeypatch.setattr("ama_cryptography._self_test._kat_sha3_256", _boom)
        try:
            assert _run_self_tests() is False
            assert module_status() == "ERROR"
        finally:
            st.update_integrity_digest()
            _set_operational()

    def test_kat_soft_failure_sets_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
        isolated_integrity_file: Path,
    ) -> None:
        from ama_cryptography._self_test import (
            _run_self_tests,
            _set_operational,
            module_status,
        )

        monkeypatch.setattr(
            "ama_cryptography._self_test._kat_sha3_256",
            lambda: (False, "synthetic soft failure"),
        )
        try:
            assert _run_self_tests() is False
            assert module_status() == "ERROR"
        finally:
            st.update_integrity_digest()
            _set_operational()

    def test_stage_false_none_fails_closed_without_assert(
        self,
        monkeypatch: pytest.MonkeyPatch,
        isolated_integrity_file: Path,
    ) -> None:
        from ama_cryptography._self_test import (
            _run_self_tests,
            _set_operational,
            module_error_reason,
            module_status,
        )

        monkeypatch.setattr(
            "ama_cryptography._self_test._run_integrity_stage",
            lambda: (False, None),
        )
        try:
            assert _run_self_tests() is False
            assert module_status() == "ERROR"
            assert module_error_reason() == (
                "FIPS POST internal error: stage returned (False, None)"
            )
        finally:
            st.update_integrity_digest()
            _set_operational()

    def test_rng_identical_outputs_fails(
        self,
        monkeypatch: pytest.MonkeyPatch,
        isolated_integrity_file: Path,
    ) -> None:
        """Two identical consecutive RNG draws must fail the runner."""
        from ama_cryptography._self_test import (
            _run_self_tests,
            _set_operational,
            module_status,
        )

        counter = {"n": 0}
        fixed = b"\xaa" * 32

        def _fake_token(n: int) -> bytes:
            counter["n"] += 1
            return fixed[:n]

        monkeypatch.setattr("ama_cryptography._self_test.secrets.token_bytes", _fake_token)
        try:
            assert _run_self_tests() is False
            assert module_status() == "ERROR"
        finally:
            st.update_integrity_digest()
            _set_operational()

    def test_rng_exception_fails(
        self,
        monkeypatch: pytest.MonkeyPatch,
        isolated_integrity_file: Path,
    ) -> None:
        from ama_cryptography._self_test import (
            _run_self_tests,
            _set_operational,
            module_status,
        )

        def _boom(_n: int) -> bytes:
            raise RuntimeError("simulated RNG failure")

        monkeypatch.setattr("ama_cryptography._self_test.secrets.token_bytes", _boom)
        try:
            assert _run_self_tests() is False
            assert module_status() == "ERROR"
        finally:
            st.update_integrity_digest()
            _set_operational()


# ---------------------------------------------------------------------------
# Accessors
# ---------------------------------------------------------------------------


class TestAccessors:
    def test_module_self_test_results_defensive_copy(self) -> None:
        first = st.module_self_test_results()
        first.append(("probe", True, "mutation should not affect module state"))
        second = st.module_self_test_results()
        assert ("probe", True, "mutation should not affect module state") not in second

    def test_post_duration_is_non_negative(self) -> None:
        assert st.post_duration_ms() >= 0.0
