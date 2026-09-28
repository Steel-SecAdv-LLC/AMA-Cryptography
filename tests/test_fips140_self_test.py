#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
FIPS 140-3 Self-Test and Module Integrity Tests
================================================

Tests for the FIPS 140-3 power-on self-test infrastructure:
- Error state machine transitions
- KAT execution and validation
- Module integrity verification
- Continuous RNG health check
- Pairwise consistency test helpers
- Integrity CLI (update/verify/show)

Run with:  pytest tests/test_fips140_self_test.py -v -m fips
"""

import sys
import threading
from unittest.mock import patch

import pytest

pytestmark = [pytest.mark.fips, pytest.mark.usefixtures("post_state_restored")]


# ============================================================================
# Module State Machine
# ============================================================================


class TestModuleStateMachine:
    """Test FIPS 140-3 error state machine transitions."""

    def test_module_is_operational_after_import(self) -> None:
        """Module should be OPERATIONAL after successful import."""
        from ama_cryptography._self_test import module_status

        assert module_status() == "OPERATIONAL"

    def test_module_error_reason_is_none_when_operational(self) -> None:
        from ama_cryptography._self_test import module_error_reason

        assert module_error_reason() is None

    def test_check_operational_does_not_raise_when_operational(self) -> None:
        # Smoke test: verifies no exception raised when OPERATIONAL
        from ama_cryptography._self_test import check_operational, module_status

        check_operational()
        assert module_status() == "OPERATIONAL"

    def test_set_error_transitions_to_error_state(self) -> None:
        from ama_cryptography._self_test import (
            _set_error,
            _set_operational,
            module_error_reason,
            module_status,
        )

        try:
            _set_error("test failure reason")
            assert module_status() == "ERROR"
            assert module_error_reason() == "test failure reason"
        finally:
            _set_operational()

    def test_check_operational_raises_in_error_state(self) -> None:
        from ama_cryptography._self_test import (
            _set_error,
            _set_operational,
            check_operational,
        )
        from ama_cryptography.exceptions import CryptoModuleError

        try:
            _set_error("forced error")
            with pytest.raises(CryptoModuleError, match="forced error"):
                check_operational()
        finally:
            _set_operational()

    def test_reset_module_recovers_from_error(self) -> None:
        from ama_cryptography._self_test import (
            _set_error,
            module_status,
            reset_module,
        )

        _set_error("transient failure")
        assert module_status() == "ERROR"
        result = reset_module()
        assert result is True
        assert module_status() == "OPERATIONAL"

    def test_module_status_exported_from_package(self) -> None:
        """Public API should be accessible from ama_cryptography."""
        from ama_cryptography import (
            CryptoModuleError,
            check_operational,
            module_error_reason,
            module_status,
            post_duration_ms,
            reset_module,
            secure_token_bytes,
        )

        assert callable(module_status)
        assert callable(module_error_reason)
        assert callable(reset_module)
        assert callable(check_operational)
        assert issubclass(CryptoModuleError, Exception)
        assert callable(secure_token_bytes)
        assert callable(post_duration_ms)


# ============================================================================
# Power-On Self-Tests
# ============================================================================


class TestPowerOnSelfTests:
    """Test KAT execution and POST behavior."""

    def test_post_completed_successfully(self) -> None:
        from ama_cryptography._self_test import module_status

        assert module_status() == "OPERATIONAL"

    def test_post_duration_is_under_budget(self) -> None:
        """POST's own cost stays under 2 s.

        Measured here, on five POST runs, against the median.  This used to
        read ``post_duration_ms()`` -- the duration of whichever POST some
        other test ran last.  On main's Windows / CPython 3.14.7 lane that was
        ``test_reset_module_recovers_from_error``'s POST, at 6,234 ms, while
        every other POST in the same process took about 1 s and the same lane
        on CPython 3.14.6 took 0.32 s: one stall of the host, charged to POST.

        The median, not the minimum: a stall adds time to one sample, and the
        median absorbs up to two; a regression that slows most runs --
        deterministic, or intermittent in three of five -- moves the median
        over the budget, where the minimum would let one fast run hide it.
        Every sample's per-stage breakdown is in the message.
        """
        from ama_cryptography._self_test import _run_self_tests, module_attestation

        # A run that fails leaves the module in ERROR; the module's
        # ``post_state_restored`` fixture puts it back for the tests after it.
        samples = []
        for run in range(1, 6):
            assert _run_self_tests() is True, f"POST run {run} of 5 failed"
            attestation = module_attestation()
            samples.append((attestation["duration_ms"], attestation["stage_durations_ms"]))
        median = sorted(duration for duration, _ in samples)[len(samples) // 2]
        report = "; ".join(
            f"{duration:.1f}ms " + ", ".join(f"{k}={v:.1f}" for k, v in stages.items())
            for duration, stages in samples
        )
        assert median > 0, "POST duration should be positive"
        assert median < 2000, (
            f"POST's median of 5 runs took {median:.1f}ms, exceeding the 2000ms "
            f"budget; runs: {report}"
        )

    def test_stage_durations_account_for_the_run(self) -> None:
        """Every stage is timed, in order, and the stages fit in the run."""
        from ama_cryptography._self_test import _run_self_tests, module_attestation

        assert _run_self_tests() is True
        attestation = module_attestation()
        stages = attestation["stage_durations_ms"]
        assert list(stages) == [
            "native-backend",
            "kat-pre-integrity",
            "integrity",
            "execution-integrity",
            "kat",
            "oracle",
            "rng",
        ]
        assert all(v >= 0 for v in stages.values())
        assert sum(stages.values()) <= attestation["duration_ms"] + 1.0

    # The tests below force POST to fail or to be interrupted.  Each leaves
    # the module however the forced run left it; the module's
    # ``post_state_restored`` fixture puts every piece of POST state back
    # afterwards.  (They used to re-run POST in a ``finally`` instead, where a
    # failing re-run replaced the test's own error and skipped the restore of
    # ``_LAST_FAILURE`` that followed it.)

    def test_stage_durations_stop_at_the_failing_stage(self) -> None:
        """A failed stage is timed; the stages POST never reached are absent."""
        from ama_cryptography._self_test import _run_self_tests, module_attestation

        with patch(
            "ama_cryptography._self_test._run_timing_oracle_stage",
            return_value=(False, "forced"),
        ):
            assert _run_self_tests() is False
        stages = module_attestation()["stage_durations_ms"]
        assert list(stages)[-1] == "oracle"
        assert "rng" not in stages

    def test_an_interrupt_before_the_first_stage_still_drops_the_allowance(self) -> None:
        """The self-test allowance is pinned to this thread the moment
        SELF_TEST is entered.  An interrupt that lands before the first stage
        runs -- here, while the strict-mode flag is read -- used to escape the
        ``try`` with the allowance still set, which kept
        ``check_crypto_permitted()`` permissive on this thread for the rest of
        the process (a window of microseconds, and a real one).  The pin
        itself is asserted: the guard now also requires the POST lock, so a
        refusal alone no longer shows that the ``finally`` ran."""
        from ama_cryptography import _module_state as ms
        from ama_cryptography._self_test import _run_self_tests, module_status
        from ama_cryptography.exceptions import CryptoModuleError

        assert _run_self_tests() is True
        with (
            patch(
                "ama_cryptography._self_test._env_flag_enabled",
                side_effect=KeyboardInterrupt,
            ),
            pytest.raises(KeyboardInterrupt),
        ):
            _run_self_tests()
        assert module_status() == "SELF_TEST"
        assert ms._SELF_TEST_THREAD is None
        with pytest.raises(CryptoModuleError):
            ms.check_crypto_permitted()

    def test_an_exception_before_the_first_stage_is_named_as_such(self) -> None:
        """A failure before any stage has run is attributed to no stage: the
        reason names ``<before the first stage>``, where it used to read as a
        stage called ``''``."""
        from ama_cryptography import _self_test as st

        with (
            patch.object(st, "_env_flag_enabled", side_effect=RuntimeError("flag unreadable")),
            pytest.raises(RuntimeError, match="flag unreadable"),
        ):
            st._run_self_tests()
        assert st.module_error_reason() == (
            "FIPS POST internal error: stage '<before the first stage>' raised "
            "RuntimeError: flag unreadable"
        )

    def test_an_interrupt_as_self_test_is_entered_drops_the_pin(self) -> None:
        """``_begin_self_test()`` runs inside the ``try`` whose ``finally``
        drops the pin.  An interrupt delivered the instant it returns must
        still leave no thread pinned; with the call moved back above the
        ``try``, it escaped with this thread's ident in ``_SELF_TEST_THREAD``."""
        from ama_cryptography import _module_state as ms
        from ama_cryptography import _self_test as st

        # The object _self_test binds; patched below on _self_test by name.
        real_begin = ms._begin_self_test

        def begin_then_interrupt() -> object:
            real_begin()
            raise KeyboardInterrupt

        with (
            patch.object(st, "_begin_self_test", begin_then_interrupt),
            pytest.raises(KeyboardInterrupt),
        ):
            st._run_self_tests()
        assert ms._MODULE_STATE == "SELF_TEST"
        assert ms._SELF_TEST_THREAD is None

    def test_a_failure_outside_post_is_recorded_with_its_reason_and_no_run(self) -> None:
        """A pairwise consistency test or the continuous RNG test puts the
        module in ERROR without a failed POST.  ``reset_module()`` records
        that reason, and no run: the live table and timings belong to the
        last POST, which passed, and attaching them (as it did until
        2026-09-27) reported a POST failure that never happened."""
        from ama_cryptography._module_state import _set_error
        from ama_cryptography._self_test import (
            _run_self_tests,
            last_failure,
            module_status,
            reset_module,
        )

        reason = "Pairwise consistency test failed for ed25519: synthetic"
        assert _run_self_tests() is True
        _set_error(reason)
        assert module_status() == "ERROR"
        assert reset_module() is True
        assert module_status() == "OPERATIONAL"
        record = last_failure()
        assert record["reason"] == reason
        assert record["results"] == []
        assert record["duration_ms"] == 0.0
        assert record["stage_durations_ms"] == {}

    def test_an_interrupt_during_post_is_not_recorded_as_a_failed_post(self) -> None:
        """Ctrl-C during POST is an interrupted self-test, not a failed one.

        The module still must not operate: SELF_TEST stands, the thread
        allowance is dropped and crypto is refused.  But no CRITICAL "POST
        FAILURE" is logged, no reason is set, last_failure() is untouched and
        the interrupt propagates; the stage timings are still published."""
        from ama_cryptography._module_state import check_crypto_permitted
        from ama_cryptography._self_test import (
            _run_self_tests,
            last_failure,
            module_attestation,
            module_error_reason,
            module_status,
        )
        from ama_cryptography.exceptions import CryptoModuleError

        assert _run_self_tests() is True
        untouched_record = last_failure()
        with (
            patch(
                "ama_cryptography._self_test._run_timing_oracle_stage",
                side_effect=KeyboardInterrupt,
            ),
            pytest.raises(KeyboardInterrupt),
        ):
            _run_self_tests()
        assert module_status() == "SELF_TEST"
        assert module_error_reason() is None
        assert last_failure() == untouched_record
        with pytest.raises(CryptoModuleError):
            check_crypto_permitted()
        stages = module_attestation()["stage_durations_ms"]
        assert list(stages)[-1] == "oracle"

    def test_stage_durations_name_a_stage_that_raises(self) -> None:
        """A stage that raises is a recorded POST failure: timed and published
        (not the previous run's map, and not a zero duration), the module in
        ERROR naming the stage, a failing row in the table, and the run in
        last_failure(); the exception still propagates."""
        from ama_cryptography._self_test import (
            _run_self_tests,
            last_failure,
            module_attestation,
            module_error_reason,
            module_self_test_results,
            module_status,
            post_duration_ms,
        )

        assert _run_self_tests() is True
        before = module_attestation()["stage_durations_ms"]
        assert "rng" in before
        with (
            patch(
                "ama_cryptography._self_test._run_timing_oracle_stage",
                side_effect=RuntimeError("stage escaped"),
            ),
            pytest.raises(RuntimeError, match="stage escaped"),
        ):
            _run_self_tests()
        stages = module_attestation()["stage_durations_ms"]
        assert list(stages)[-1] == "oracle"
        assert "rng" not in stages
        # The run's wall-clock is published on this exit too: it covers the
        # stages it timed, so it cannot be the zero POST starts from.
        assert post_duration_ms() >= sum(stages.values())
        assert module_status() == "ERROR"
        reason = module_error_reason() or ""
        assert "'oracle'" in reason and "RuntimeError" in reason
        assert module_self_test_results()[-1] == ("POST", False, reason)
        record = last_failure()
        assert record["reason"] == reason
        assert record["stage_durations_ms"] == stages
        assert record["duration_ms"] == post_duration_ms()
        assert record["results"] == module_self_test_results()

    def test_all_kats_passed(self) -> None:
        """Every recorded KAT either passed or was an explicit skip.

        Skip semantics: ``passed is None`` is a "backend unavailable"
        skip, which is NOT a pass but is also NOT a failure outside
        strict mode.  In CI (with ``AMA_CI_REQUIRE_BACKENDS=1``) the
        conftest fixture turns backend-related skips into hard
        failures, so this loop sees ``passed is True`` for every KAT.
        In a local checkout without the C library built, the loop
        tolerates skipped entries.
        """
        from ama_cryptography._self_test import module_self_test_results

        results = module_self_test_results()
        assert len(results) > 0, "No self-test results recorded"
        for name, passed, detail in results:
            if passed is None:
                # Skipped — backend not present.  Not a failure here.
                continue
            assert passed, f"KAT {name} failed: {detail}"

    def test_expected_kat_names_present(self) -> None:
        from ama_cryptography._self_test import module_self_test_results

        results = module_self_test_results()
        names = {name for name, _, _ in results}
        expected = {"integrity", "SHA3-256", "AES-256-GCM", "RNG"}
        # These are always expected; PQC tests may be skipped if unavailable
        for name in expected:
            assert name in names, f"Missing KAT: {name}"

    def test_run_self_tests_is_idempotent(self) -> None:
        from ama_cryptography._self_test import _run_self_tests, module_status

        result = _run_self_tests()
        assert result is True
        assert module_status() == "OPERATIONAL"

    def test_individual_kat_sha3_256(self) -> None:
        from ama_cryptography._self_test import _kat_sha3_256

        passed, detail = _kat_sha3_256()
        # SHA3-256 ships in CPython hashlib — never None (no skip path).
        assert passed, detail

    def test_individual_kat_hmac_sha3_256(self) -> None:
        from ama_cryptography._self_test import _kat_hmac_sha3_256

        passed, detail = _kat_hmac_sha3_256()
        if passed is None:
            pytest.skip(detail)
        assert passed, detail

    def test_individual_kat_aes_256_gcm(self) -> None:
        from ama_cryptography._self_test import _kat_aes_256_gcm

        passed, detail = _kat_aes_256_gcm()
        if passed is None:
            pytest.skip(detail)
        assert passed, detail

    def test_individual_kat_ml_kem_1024(self) -> None:
        from ama_cryptography._self_test import _kat_ml_kem_1024

        passed, detail = _kat_ml_kem_1024()
        if passed is None:
            pytest.skip(detail)
        assert passed, detail

    def test_individual_kat_ml_dsa_65(self) -> None:
        from ama_cryptography._self_test import _kat_ml_dsa_65

        passed, detail = _kat_ml_dsa_65()
        if passed is None:
            pytest.skip(detail)
        assert passed, detail

    def test_individual_kat_slh_dsa(self) -> None:
        from ama_cryptography._self_test import _kat_slh_dsa

        passed, detail = _kat_slh_dsa()
        if passed is None:
            pytest.skip(detail)
        assert passed, detail

    def test_individual_kat_ed25519(self) -> None:
        from ama_cryptography._self_test import _kat_ed25519

        passed, detail = _kat_ed25519()
        if passed is None:
            pytest.skip(detail)
        assert passed, detail


# ============================================================================
# POST State Transitions
# ============================================================================


class TestPostStateTransitions:
    """POST's transitions against each other, against other threads, and
    against the readers that report them.  Every test forces a failure or a
    race; the module's ``post_state_restored`` fixture undoes it."""

    def test_an_error_reported_during_post_is_not_overwritten(self) -> None:
        """Another thread's pairwise or continuous-RNG failure that lands while
        POST runs (its draw began before POST did) must survive POST.  The end
        of POST was an unconditional ``_set_operational()``, which erased it:
        the module reported OPERATIONAL, with no reason, after a failed
        conditional self-test."""
        from ama_cryptography import _self_test as st

        reason = "Pairwise consistency test failed for ML-DSA-65: synthetic, from another thread"
        real_rng = st._run_rng_stage

        def rng_then_another_thread_fails() -> tuple[bool, str | None]:
            outcome = real_rng()
            other = threading.Thread(target=st._set_error, args=(reason,))
            other.start()
            other.join(30)
            return outcome

        with patch.object(st, "_run_rng_stage", rng_then_another_thread_fails):
            assert st.reset_module() is False
        assert st.module_status() == "ERROR"
        assert st.module_error_reason() == reason
        # POST's own stages all passed; the record carries the reason and no run.
        assert all(ok is not False for _, ok, _ in st.module_self_test_results())
        assert st.last_failure() == {
            "reason": reason,
            "results": [],
            "duration_ms": 0.0,
            "stage_durations_ms": {},
        }

    def test_the_post_thread_is_refused_once_another_thread_enters_error(self) -> None:
        """The self-test allowance is for SELF_TEST only.  Once another thread
        has put the module in ERROR, the POST thread's next cryptographic call
        is refused like any other, and the run ends without OPERATIONAL."""
        from ama_cryptography import _module_state as ms
        from ama_cryptography import _self_test as st
        from ama_cryptography.exceptions import CryptoModuleError

        reason = "Pairwise consistency test failed for ML-KEM-1024: synthetic, from another thread"
        outcome: list[str] = []

        def another_thread_fails_mid_run() -> tuple[bool, str | None]:
            ms.check_crypto_permitted()  # this thread's allowance, before the failure
            other = threading.Thread(target=st._set_error, args=(reason,))
            other.start()
            other.join(30)
            try:
                ms.check_crypto_permitted()
                outcome.append("permitted")
            except CryptoModuleError:
                outcome.append("refused")
            return True, None

        with patch.object(st, "_run_rng_stage", another_thread_fails_mid_run):
            assert st._run_self_tests() is False
        assert outcome == ["refused"]
        assert st.module_status() == "ERROR"
        assert st.module_error_reason() == reason

    @staticmethod
    def _decide_while_a_transition_lands(
        pinned: bool, land: tuple[str, str | None]
    ) -> tuple[bool, Exception | None]:
        """Run ``check_crypto_permitted`` on a worker thread in SELF_TEST, and
        make ``land`` -- a ``(state, reason)`` transition -- happen after the
        worker's unlocked fast-path read and before its locked decision.

        The worker announces when it reaches ``_STATE_LOCK``; this thread holds
        the lock until then, applies the transition, and releases it.  Returns
        whether the worker reached the lock, and what the check raised."""
        from ama_cryptography import _module_state as ms

        inner = threading.RLock()
        reached = threading.Event()

        class _Announcing:
            def __enter__(self) -> bool:
                reached.set()
                return inner.__enter__()

            def __exit__(self, *exc: object) -> None:
                inner.release()

        raised: list[Exception | None] = []

        def worker() -> None:
            with ms._POST_LOCK:
                if pinned:
                    ms._SELF_TEST_THREAD = threading.get_ident()
                try:
                    ms.check_crypto_permitted()
                    raised.append(None)
                except Exception as exc:
                    raised.append(exc)

        with patch.object(ms, "_STATE_LOCK", _Announcing()):
            ms._MODULE_STATE = "SELF_TEST"
            ms._ERROR_REASON = None
            ms._SELF_TEST_THREAD = None
            with inner:
                thread = threading.Thread(target=worker)
                thread.start()
                did_reach = reached.wait(30)
                ms._MODULE_STATE, ms._ERROR_REASON = land
            thread.join(30)
        assert not thread.is_alive()
        return did_reach, raised[0]

    def test_an_error_entered_after_the_fast_path_read_is_honoured(self) -> None:
        """The permit is decided under ``_STATE_LOCK``, not on the state read
        before it: the POST thread, pinned and holding the POST lock, read
        SELF_TEST, and another thread's ERROR landed before the decision.  The
        call is refused and names that ERROR.  Decided on the earlier read, it
        was permitted after the failure."""
        from ama_cryptography.exceptions import CryptoModuleError

        reason = "Continuous RNG test failed: consecutive identical outputs (synthetic)"
        reached, raised = self._decide_while_a_transition_lands(True, ("ERROR", reason))
        assert reached
        assert isinstance(raised, CryptoModuleError)
        assert reason in str(raised)

    def test_operational_reached_after_the_fast_path_read_is_permitted(self) -> None:
        """A thread that read SELF_TEST while POST was finishing, and is not
        the POST thread, is permitted once POST has made the module
        OPERATIONAL.  The locked decision reads the state again; refused on
        the stale read, a caller racing a successful POST got an error."""
        reached, raised = self._decide_while_a_transition_lands(False, ("OPERATIONAL", None))
        assert reached
        assert raised is None

    def test_an_error_reported_as_post_begins_is_recorded(self) -> None:
        """An ERROR entered in the instant before POST enters SELF_TEST is
        replaced by the run, which is what a reset is for, but it is recorded
        first.  Erased unrecorded, it survived only as a log line."""
        from ama_cryptography import _module_state as ms
        from ama_cryptography import _self_test as st

        reason = "Continuous RNG test failed: consecutive identical outputs (synthetic)"
        # The object _self_test binds; patched below on _self_test by name.
        real_begin = ms._begin_self_test

        def another_thread_fails_then_begin() -> tuple[str, str | None, int]:
            other = threading.Thread(target=st._set_error, args=(reason,))
            other.start()
            other.join(30)
            return real_begin()

        assert st._run_self_tests() is True
        with patch.object(st, "_begin_self_test", another_thread_fails_then_begin):
            assert st.reset_module() is True
        assert st.module_status() == "OPERATIONAL"
        assert st.last_failure()["reason"] == reason
        assert st.last_failure()["results"] == []

    @pytest.mark.parametrize(
        "outcome",
        [(False, "stage failed and recorded no row"), (False, None)],
        ids=["reason-without-row", "contract-violation"],
    )
    def test_a_failed_stage_that_left_no_row_gets_one(
        self, outcome: tuple[bool, str | None]
    ) -> None:
        """With no failing row, ``module_attestation()["failed"]`` and the
        import gate's results listing named no failure while the module was
        in ERROR."""
        from ama_cryptography import _self_test as st

        with patch.object(st, "_run_timing_oracle_stage", return_value=outcome):
            assert st._run_self_tests() is False
        reason = st.module_error_reason()
        assert reason is not None
        assert st.module_self_test_results()[-1] == ("POST", False, reason)
        assert st.module_attestation()["failed"] == [("POST", reason)]

    def test_a_failed_stage_that_left_its_own_row_gets_no_second_one(self) -> None:
        from ama_cryptography import _self_test as st

        with patch.object(st, "_kat_sha3_256", return_value=(False, "synthetic KAT failure")):
            assert st._run_self_tests() is False
        failing = [name for name, ok, _ in st.module_self_test_results() if ok is False]
        assert failing == ["SHA3-256"]

    @pytest.mark.parametrize("reader", ["module_attestation", "last_failure"])
    def test_a_reader_waits_for_a_running_post(self, reader: str) -> None:
        """A reader called while POST runs describes the finished run.

        Unlocked, it paired whatever it read first with a table still being
        written: ``module_attestation()`` reported ``fully_verified: True``
        for a run that went on to skip a test, and ``last_failure()`` a new
        failure's reason beside an older one's evidence.  The reader is
        started inside a stage; it cannot return until POST has, which the
        stage observes for half a second (a reader that did not wait returns
        well within it, and one that does cannot return at all)."""
        from ama_cryptography import _self_test as st

        read = getattr(st, reader)
        started = threading.Event()
        returned = threading.Event()
        seen: list[dict[str, object]] = []
        returned_during_post: list[bool] = []

        def read_during_post() -> None:
            started.set()
            seen.append(read())
            returned.set()

        worker = threading.Thread(target=read_during_post)

        def stage_with_a_reader(strict_mode: bool) -> tuple[bool, str | None]:
            worker.start()
            started.wait(30)
            returned_during_post.append(returned.wait(0.5))
            st._SELF_TEST_RESULTS.append(("forced", False, "failed after the read began"))
            return False, "forced after the read began"

        with patch.object(st, "_run_timing_oracle_stage", stage_with_a_reader):
            assert st._run_self_tests() is False
        worker.join(30)
        assert returned_during_post == [False]
        if reader == "module_attestation":
            assert seen[0]["state"] == "ERROR"
            assert seen[0]["failed"] == [("forced", "failed after the read began")]
        else:
            assert seen[0]["reason"] == "forced after the read began"
            assert seen[0]["results"] == st.module_self_test_results()

    def test_last_failure_reports_an_outside_post_failure_before_recovery(self) -> None:
        """A failure outside POST is reported while the module is in ERROR,
        not only once ``reset_module()`` has been asked to recover; until then
        ``last_failure()`` described an older failure as the most recent."""
        from ama_cryptography import _self_test as st

        reason = "Pairwise consistency test failed for Ed25519: synthetic, unrecovered"
        assert st._run_self_tests() is True
        st._set_error(reason)
        assert st.last_failure() == {
            "reason": reason,
            "results": [],
            "duration_ms": 0.0,
            "stage_durations_ms": {},
        }

    def test_a_run_that_fails_before_integrity_reports_no_integrity_verdict(self) -> None:
        """The integrity verdict is the integrity stage's.  A run that fails
        before reaching it reported the previous run's ``integrity_strength``
        and ``anchored`` as its own, and kept its failure classification."""
        from ama_cryptography import _self_test as st

        assert st._run_self_tests() is True
        assert st.module_attestation()["integrity_strength"] is not None
        # As a previous run that failed on a stale binding would leave it.
        st._INTEGRITY_FAILURE_KIND = st._INTEGRITY_FAILURE_STALE_BINDING
        with patch.object(st, "_run_backend_stage", return_value=(False, "backend gone")):
            assert st._run_self_tests() is False
        attestation = st.module_attestation()
        assert attestation["integrity_strength"] is None
        assert attestation["anchored"] is None
        assert st.integrity_failure_was_stale_binding() is False

    def test_an_exception_whose_str_raises_is_still_recorded(self) -> None:
        """Formatting the reason used to call ``str(exc)`` inside the handler,
        so an exception whose ``__str__`` raises replaced itself with that
        second exception before ``_set_error`` ran: no ERROR, no reason, no
        record."""
        from ama_cryptography import _self_test as st

        class UnprintableError(Exception):
            def __str__(self) -> str:
                raise ValueError("__str__ failed")

        with (
            patch.object(st, "_run_timing_oracle_stage", side_effect=UnprintableError()),
            pytest.raises(UnprintableError),
        ):
            st._run_self_tests()
        assert st.module_status() == "ERROR"
        reason = st.module_error_reason()
        assert reason == (
            "FIPS POST internal error: stage 'oracle' raised UnprintableError: "
            "<str() of UnprintableError raised ValueError>"
        )
        assert st.last_failure()["reason"] == reason

    def test_the_timing_maps_handed_out_are_copies(self) -> None:
        """A caller editing a returned map cannot edit the module's record."""
        from ama_cryptography import _self_test as st

        with patch.object(st, "_run_timing_oracle_stage", return_value=(False, "forced")):
            assert st._run_self_tests() is False
        st.module_attestation()["stage_durations_ms"]["injected"] = 1.0
        assert "injected" not in st.module_attestation()["stage_durations_ms"]
        st.last_failure()["stage_durations_ms"]["injected"] = 1.0
        assert "injected" not in st.last_failure()["stage_durations_ms"]

    def test_a_pin_that_outlives_its_run_grants_nothing(self) -> None:
        """A second interrupt can land in the ``finally`` before the pin is
        dropped.  The pin then outlives the run, and it used to keep
        ``check_crypto_permitted()`` permissive on this thread after an
        unfinished POST.  The guard also requires the POST lock, which the
        ``with`` statement released."""
        from ama_cryptography import _module_state as ms
        from ama_cryptography import _self_test as st
        from ama_cryptography.exceptions import CryptoModuleError

        def second_interrupt() -> None:
            raise KeyboardInterrupt

        with (
            patch.object(st, "_run_timing_oracle_stage", side_effect=KeyboardInterrupt),
            patch.object(st, "_clear_self_test_thread", second_interrupt),
            pytest.raises(KeyboardInterrupt),
        ):
            st._run_self_tests()
        assert ms._MODULE_STATE == "SELF_TEST"
        assert ms._SELF_TEST_THREAD == threading.get_ident()
        with pytest.raises(CryptoModuleError, match="SELF_TEST"):
            ms.check_crypto_permitted()
        # The skipped ``finally`` also publishes the timing.  The run's map is
        # published live from its start, so what is reported is this run's
        # partial timing, and a wall-clock of 0 for a run that never finished,
        # never the previous run's figures.
        assert list(st.module_attestation()["stage_durations_ms"])[-1] == "oracle"
        assert st.post_duration_ms() == 0.0


# ============================================================================
# Continuous RNG Health Check
# ============================================================================


class TestContinuousRNG:
    """Test the continuous RNG health check wrapper."""

    def test_secure_token_bytes_returns_correct_length(self) -> None:
        from ama_cryptography._self_test import secure_token_bytes

        for n in (16, 32, 64):
            result = secure_token_bytes(n)
            assert len(result) == n

    def test_secure_token_bytes_returns_different_outputs(self) -> None:
        from ama_cryptography._self_test import secure_token_bytes

        a = secure_token_bytes(32)
        b = secure_token_bytes(32)
        assert a != b

    def test_secure_token_bytes_rejects_negative_size(self) -> None:
        """A negative ``n`` must raise, not silently truncate.

        ``buf[:n]`` with a negative ``n`` returns ``32 - |n|`` bytes — a
        caller that miscomputed a length would receive key material shorter
        than requested, with no error to notice.
        """
        from ama_cryptography._self_test import secure_token_bytes

        with pytest.raises(ValueError):
            secure_token_bytes(-1)

    def test_secure_token_bytes_raises_in_error_state(self) -> None:
        from ama_cryptography._self_test import (
            _set_error,
            _set_operational,
            secure_token_bytes,
        )
        from ama_cryptography.exceptions import CryptoModuleError

        try:
            _set_error("test error")
            with pytest.raises(CryptoModuleError):
                secure_token_bytes(32)
        finally:
            _set_operational()

    def test_identical_rng_output_triggers_error(self) -> None:
        """If secrets.token_bytes returns identical consecutive values, error state."""
        from ama_cryptography._self_test import (
            _set_operational,
            module_status,
            secure_token_bytes,
        )
        from ama_cryptography.exceptions import CryptoModuleError

        fixed = b"\xaa" * 32
        try:
            with patch("ama_cryptography._self_test.secrets.token_bytes", return_value=fixed):
                # First call sets _previous_rng_output
                secure_token_bytes(32)
                # Second call should detect duplicate
                with pytest.raises(CryptoModuleError, match="Continuous RNG"):
                    secure_token_bytes(32)
            assert module_status() == "ERROR"
        finally:
            _set_operational()


# ============================================================================
# Module Integrity Verification
# ============================================================================


class TestModuleIntegrity:
    """Test SHA3-256 module integrity verification."""

    def test_compute_digest_returns_hex_string(self) -> None:
        from ama_cryptography._self_test import _compute_module_digest

        digest = _compute_module_digest()
        assert len(digest) == 64  # SHA3-256 hex
        assert all(c in "0123456789abcdef" for c in digest)

    def test_compute_digest_is_deterministic(self) -> None:
        from ama_cryptography._self_test import _compute_module_digest

        assert _compute_module_digest() == _compute_module_digest()

    def test_verify_module_integrity_passes(self) -> None:
        from ama_cryptography._self_test import verify_module_integrity

        passed, detail = verify_module_integrity()
        assert passed is True
        # Detail string format depends on which path verified the module:
        #   - signed-integrity primary path (wheel built with AMA_BUILD_PIPELINE=1)
        #   - digest-only fallback (editable install / source checkout)
        # Both are valid OPERATIONAL outcomes; only the (False, ...) shape is
        # an error.  Pin a stable substring rather than the full message so
        # the test does not break when the detail wording is refined.
        assert "integrity verified" in detail.lower() or "module integrity" in detail.lower()

    def test_integrity_cli_verify(self) -> None:
        """Test `python -m ama_cryptography.integrity --verify` succeeds."""
        import subprocess

        result = subprocess.run(
            [sys.executable, "-m", "ama_cryptography.integrity", "--verify"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "OK" in result.stdout

    def test_integrity_cli_show(self) -> None:
        """Test `python -m ama_cryptography.integrity --show` outputs a hex digest."""
        import subprocess

        result = subprocess.run(
            [sys.executable, "-m", "ama_cryptography.integrity", "--show"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        digest = result.stdout.strip()
        assert len(digest) == 64


# ============================================================================
# Pairwise Consistency Tests
# ============================================================================


class TestPairwiseConsistency:
    """Test the pairwise consistency test helpers."""

    def test_pairwise_signature_passes_for_valid_keypair(self) -> None:
        from ama_cryptography._self_test import pairwise_test_signature
        from ama_cryptography.pqc_backends import (
            DILITHIUM_AVAILABLE,
            dilithium_sign,
            dilithium_verify,
            generate_dilithium_keypair,
        )

        if not DILITHIUM_AVAILABLE:
            pytest.skip("Dilithium not available")

        kp = generate_dilithium_keypair()
        # Should not raise
        pairwise_test_signature(
            dilithium_sign,
            dilithium_verify,
            kp.secret_key,
            kp.public_key,
            "ML-DSA-65",
        )

    def test_pairwise_kem_passes_for_valid_keypair(self) -> None:
        from ama_cryptography._self_test import pairwise_test_kem
        from ama_cryptography.pqc_backends import (
            KYBER_AVAILABLE,
            generate_kyber_keypair,
            kyber_decapsulate,
            kyber_encapsulate,
        )

        if not KYBER_AVAILABLE:
            pytest.skip("Kyber not available")

        kp = generate_kyber_keypair()
        # Should not raise
        pairwise_test_kem(
            kyber_encapsulate,
            kyber_decapsulate,
            kp.public_key,
            kp.secret_key,
            "ML-KEM-1024",
        )

    def test_pairwise_signature_fails_with_wrong_key(self) -> None:
        from ama_cryptography._self_test import (
            _set_operational,
            pairwise_test_signature,
        )
        from ama_cryptography.exceptions import CryptoModuleError
        from ama_cryptography.pqc_backends import (
            DILITHIUM_AVAILABLE,
            dilithium_sign,
            dilithium_verify,
            generate_dilithium_keypair,
        )

        if not DILITHIUM_AVAILABLE:
            pytest.skip("Dilithium not available")

        kp1 = generate_dilithium_keypair()
        kp2 = generate_dilithium_keypair()

        try:
            with pytest.raises(CryptoModuleError, match="Pairwise test failed"):
                pairwise_test_signature(
                    dilithium_sign,
                    dilithium_verify,
                    kp1.secret_key,
                    kp2.public_key,  # mismatched
                    "ML-DSA-65",
                )
        finally:
            _set_operational()

    @pytest.mark.parametrize("helper", ["signature", "kem", "agreement"])
    def test_a_failure_with_an_unprintable_exception_still_enters_error(self, helper: str) -> None:
        """The failure reason used to format ``str(exc)`` inside the handler;
        an exception whose ``__str__`` raises replaced itself with that second
        exception before ``_set_error`` ran, and the module stayed
        OPERATIONAL after a failed pairwise test."""
        from ama_cryptography import _module_state as ms
        from ama_cryptography.exceptions import CryptoModuleError

        class UnprintableError(Exception):
            def __str__(self) -> str:
                raise ValueError("__str__ failed")

        def fails(*_args: object) -> object:
            raise UnprintableError

        calls = {
            "signature": lambda: ms.pairwise_test_signature(fails, fails, b"sk", b"pk", "X"),
            "kem": lambda: ms.pairwise_test_kem(fails, fails, b"pk", b"sk", "X"),
            "agreement": lambda: ms.pairwise_test_agreement(fails, (b"p", b"s"), b"sk", b"pk", "X"),
        }
        with pytest.raises(CryptoModuleError, match="Pairwise test failed for X"):
            calls[helper]()
        assert ms.module_status() == "ERROR"
        assert ms.module_error_reason() == (
            "Pairwise consistency test failed for X: <str() of UnprintableError raised ValueError>"
        )


# ============================================================================
# CryptoModuleError Exception
# ============================================================================


class TestCryptoModuleError:
    """Test the CryptoModuleError exception class."""

    def test_is_runtime_error(self) -> None:
        from ama_cryptography.exceptions import CryptoModuleError

        assert issubclass(CryptoModuleError, RuntimeError)

    def test_can_be_raised_and_caught(self) -> None:
        from ama_cryptography.exceptions import CryptoModuleError

        with pytest.raises(CryptoModuleError, match="test message"):
            raise CryptoModuleError("test message")

    def test_importable_from_package(self) -> None:
        from ama_cryptography import CryptoModuleError

        assert CryptoModuleError is not None  # verify re-export exists
