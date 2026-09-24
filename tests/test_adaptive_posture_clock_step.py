#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""A backward wall-clock step must not permanently wedge the adaptive posture.

The cooldown, grace-period, retry-backoff and alert-scoring cursor all did
wall-clock duration arithmetic.
A backward step (NTP step, VM snapshot restore, container clock adjustment) made
``now - stored`` negative, which read as "still in cooldown" / "grace not
elapsed" forever and silently muted protective actions and blinded alert
scoring for the step's duration. The fix re-anchors a stored timestamp left in
the future by a regression, converting a permanent wedge into a bounded delay.

The alert-scoring cursor is the exception: re-anchoring a timestamp cursor does
not work there, because the monitor reports its FULL retained alert list and
the pre-step alert that set the cursor is still in it.  The evaluator therefore
selects the monitor's alerts by ARRIVAL index (``scorable_alerts_offset``), which
a clock step cannot reorder, and the timestamp re-baseline survives only for a
report without that offset.  The real-monitor tests below pin the first; the
hand-built one pins the second.
"""

from __future__ import annotations

import time as _real_time
from typing import Any

import pytest

from ama_cryptography import adaptive_posture, monitoring
from ama_cryptography.monitoring import AmaCryptographyMonitor, TimingAnomaly


class _SteppableClock:
    """A wall clock that can be stepped BACKWARD, unlike the monotonic fake the
    other posture tests use — this is exactly the condition under test."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def time(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def step_back(self, seconds: float) -> None:
        self.now -= seconds

    def __getattr__(self, name: str) -> Any:
        # Everything but time() is the real module, so a patched module that
        # also reads perf_counter/monotonic keeps working.
        return getattr(_real_time, name)


class _EmptyMonitor:
    """Minimal monitor stub: a quiet security report drives evaluate_and_respond
    through its cooldown guard without needing the real 3R monitor."""

    def get_security_report(self) -> dict[str, Any]:
        return {"recent_alerts": [], "total_alerts": 0, "timing_history": {}}


def test_cooldown_does_not_wedge_after_backward_step(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = _SteppableClock()
    monkeypatch.setattr(adaptive_posture, "time", clock)
    ctl = adaptive_posture.CryptoPostureController(monitor=_EmptyMonitor(), rotation_cooldown=300.0)

    # Arm the cooldown by stamping a rotation time at the current (high) clock.
    ctl._last_rotation_time = clock.time()
    # Step the wall clock back an hour (snapshot restore / NTP step).
    clock.step_back(3600.0)

    # Before the fix, now - _last_rotation_time = -3600 < 300 => cooldown_active
    # stays True forever. After the fix, one evaluation re-anchors the arm-time.
    ctl.evaluate_and_respond()
    assert (
        ctl._last_rotation_time <= clock.time()
    ), "arm-time left in the future after a backward step — cooldown would wedge"
    # After re-anchor, advancing past the cooldown must clear it.
    clock.advance(301.0)
    assert (clock.time() - ctl._last_rotation_time) >= ctl.rotation_cooldown


def test_grace_period_reanchors_after_backward_step(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = _SteppableClock()
    monkeypatch.setattr(adaptive_posture, "time", clock)
    ctl = adaptive_posture.CryptoPostureController(
        rotation_cooldown=1.0, grace_period=10.0, confirmation_mode=True
    )
    # Queue a pending action stamped at the current clock.
    from ama_cryptography.adaptive_posture import PendingAction, PostureAction

    pa = PendingAction(
        action_id="x",
        action=PostureAction.ROTATE_KEYS,
        reason="test",
        timestamp=clock.time(),
    )
    ctl._pending_actions.append(pa)
    # Step back: now < pa.timestamp -> grace never elapses without the guard.
    clock.step_back(3600.0)
    ctl._process_expired_pending_actions()
    assert (
        pa.timestamp <= clock.time()
    ), "pending-action timestamp left in the future — grace period would never elapse"


def test_alert_cursor_rebaselines_after_backward_step() -> None:
    """The TIMESTAMP fallback, for a report with no ``scorable_alerts_offset``.

    Its window holds only post-step alerts, the one shape in which the
    re-baseline fires.  The monitor's own reports never have that shape (see
    the real-monitor tests below), so this pins the fallback and nothing more.
    """
    ev = adaptive_posture.PostureEvaluator()
    ev._last_processed_alert_ts = 2_000_000.0  # cursor from a high pre-step clock
    # All incoming alerts predate the cursor (the clock stepped back).
    alerts = [
        {"type": "timing", "timestamp": 1_000_000.0},
        {"type": "timing", "timestamp": 1_000_001.0},
    ]
    fresh = ev._alerts_not_yet_scored(alerts)
    assert (
        len(fresh) == 2
    ), "post-step alerts were dropped by the forward-only cursor — scoring blinded"


def _raise_timing_critical(
    monkeypatch: pytest.MonkeyPatch, mon: AmaCryptographyMonitor, clock: _SteppableClock
) -> None:
    """One critical timing alert through the monitor's real append path.

    Only the detector's verdict is stubbed; the alert is stamped, appended,
    pruned and reported by AmaCryptographyMonitor itself, under the patched
    wall clock.
    """

    def _critical(
        operation: str, duration_ms: float, input_size: int | None = None
    ) -> TimingAnomaly:
        return TimingAnomaly(operation, 1.0, duration_ms, 9.0, "critical", clock.time())

    monkeypatch.setattr(mon.timing, "record_timing", _critical)
    mon.monitor_crypto_operation("sign", 50.0)


def test_real_monitor_alerts_are_scored_across_a_backward_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _SteppableClock()
    monkeypatch.setattr(monitoring, "time", clock)
    mon = AmaCryptographyMonitor(enabled=True)
    ev = adaptive_posture.PostureEvaluator()

    _raise_timing_critical(monkeypatch, mon, clock)
    assert ev.evaluate(mon.get_security_report()).signals["timing_alert_count"] == 1

    # NTP steps the clock back an hour; the attack is still being detected.
    clock.step_back(3600.0)
    _raise_timing_critical(monkeypatch, mon, clock)
    report = mon.get_security_report()
    stamps = [a["timestamp"] for a in report["scorable_alerts"]]
    # The shape the monitor really emits: the pre-step alert that set the
    # timestamp cursor is still retained, so the window's maximum equals the
    # cursor and a "every alert predates the cursor" re-baseline never fires.
    assert stamps == [1_000_000.0, 996_400.0]
    assert (
        ev.evaluate(report).signals["timing_alert_count"] == 1
    ), "the post-step alert was dropped: scoring is blind for the step's duration"

    # Still below the pre-step stamp ten seconds later: still scored.
    clock.advance(10.0)
    _raise_timing_critical(monkeypatch, mon, clock)
    assert ev.evaluate(mon.get_security_report()).signals["timing_alert_count"] == 1

    # And nothing is scored twice: a quiet cycle scores nothing.
    assert ev.evaluate(mon.get_security_report()).signals["timing_alert_count"] == 0


def test_arrival_cursor_counts_pruned_alerts(monkeypatch: pytest.MonkeyPatch) -> None:
    """The offset is what keeps a positional cursor exact while the window slides."""
    clock = _SteppableClock()
    monkeypatch.setattr(monitoring, "time", clock)
    mon = AmaCryptographyMonitor(enabled=True, alert_retention=3)
    ev = adaptive_posture.PostureEvaluator()

    for _ in range(2):
        clock.advance(1.0)
        _raise_timing_critical(monkeypatch, mon, clock)
    assert ev.evaluate(mon.get_security_report()).signals["timing_alert_count"] == 2

    # Four more: arrivals #2..#5.  Retention 3 prunes #0..#2, so #2 is gone
    # before it was ever reported and #3..#5 are the new, scorable ones.
    for _ in range(4):
        clock.advance(1.0)
        _raise_timing_critical(monkeypatch, mon, clock)
    report = mon.get_security_report()
    assert report["scorable_alerts_offset"] == 3
    assert len(report["scorable_alerts"]) == 3
    assert ev.evaluate(report).signals["timing_alert_count"] == 3


def test_arrival_cursor_restarts_for_a_new_monitor(monkeypatch: pytest.MonkeyPatch) -> None:
    """A stream that ends below the cursor is a different monitor: all of it is new."""
    clock = _SteppableClock()
    monkeypatch.setattr(monitoring, "time", clock)
    ev = adaptive_posture.PostureEvaluator()

    first = AmaCryptographyMonitor(enabled=True)
    for _ in range(5):
        clock.advance(1.0)
        _raise_timing_critical(monkeypatch, first, clock)
    assert ev.evaluate(first.get_security_report()).signals["timing_alert_count"] == 5

    replacement = AmaCryptographyMonitor(enabled=True)
    for _ in range(2):
        clock.advance(1.0)
        _raise_timing_critical(monkeypatch, replacement, clock)
    assert (
        ev.evaluate(replacement.get_security_report()).signals["timing_alert_count"] == 2
    ), "a replacement monitor's alerts were ignored until it outgrew the old one"
