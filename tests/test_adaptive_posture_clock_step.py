#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""A backward wall-clock step must not permanently wedge the adaptive posture.

2026-08 v5 audit, item 15 (adaptive-posture): the cooldown, grace-period,
retry-backoff and alert-scoring cursor all did wall-clock duration arithmetic.
A backward step (NTP step, VM snapshot restore, container clock adjustment) made
``now - stored`` negative, which read as "still in cooldown" / "grace not
elapsed" forever and silently muted protective actions and blinded alert
scoring for the step's duration. The fix re-anchors a stored timestamp left in
the future by a regression, converting a permanent wedge into a bounded delay.
"""

from __future__ import annotations

import pytest

from ama_cryptography import adaptive_posture


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


class _EmptyMonitor:
    """Minimal monitor stub: a quiet security report drives evaluate_and_respond
    through its cooldown guard without needing the real 3R monitor."""

    def get_security_report(self) -> dict:
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
