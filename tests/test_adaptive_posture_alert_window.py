#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""A flood of low-value alerts must not evict a genuine critical before scoring.

2026-08 v5 audit, item 15 (alert-window suppression): ``get_security_report``
returned only ``recent_alerts`` — the last TEN entries — and the posture
evaluator scored that window.  An attacker who emits >=10 non-scored-type
alerts (``volume_spike``, ``note_artifact``, ...) immediately after a real
timing/pattern critical pushes that critical out of the ten-entry window before
the next poll, so it is never scored and escalation is silently suppressed.

The fix adds ``scorable_alerts`` — the full retained alert list — to the report
and makes the evaluator score that when present, falling back to
``recent_alerts`` only when it is absent.  The per-evaluation cursor still
scores each alert exactly once, so widening the input cannot double-count.

These tests pin BOTH halves: that the monitor emits the full list, and that the
evaluator scores the buried critical from it — with the fallback path retained
as an explicit witness of the pre-fix suppression.
"""

from __future__ import annotations

import types

from ama_cryptography.adaptive_posture import PostureEvaluator
from ama_cryptography.monitoring import AmaCryptographyMonitor


def _timing_critical(ts: float) -> dict[str, object]:
    """A genuine timing critical shaped exactly as the timing scorer reads it."""
    return {
        "type": "timing",
        "timestamp": ts,
        "anomaly": types.SimpleNamespace(severity="critical", deviation_sigma=9.0),
    }


def _volume_spike(ts: float) -> dict[str, object]:
    """A low-value, non-scored-type alert — the flood the attacker controls."""
    return {"type": "volume_spike", "timestamp": ts}


class TestAlertWindowSuppression:
    def test_critical_survives_a_ten_alert_flood_via_scorable_alerts(self) -> None:
        ev = PostureEvaluator()
        crit = _timing_critical(1000.0)
        # Ten non-scored alerts stamped AFTER the critical: they fully occupy
        # the ten-entry recent_alerts display window and evict the critical.
        flood = [_volume_spike(1000.0 + i) for i in range(1, 11)]
        report = {
            "recent_alerts": flood,  # human-facing last-10 window: critical gone
            "scorable_alerts": [crit, *flood],  # full retained list: still there
            "total_alerts": 11,
        }
        result = ev.evaluate(report)
        assert (
            result.signals["timing_alert_count"] == 1
        ), "the buried timing critical was not scored even from scorable_alerts"
        assert result.signals["timing_score"] > 0.0

    def test_fallback_to_recent_alerts_reproduces_the_suppression(self) -> None:
        # The pre-fix path, kept as a witness: with only the ten-entry window
        # (no scorable_alerts), the flood hides the critical and it is never
        # scored.  This is exactly the failure the fix removes.
        ev = PostureEvaluator()
        flood = [_volume_spike(1000.0 + i) for i in range(1, 11)]
        report = {"recent_alerts": flood, "total_alerts": 11}
        result = ev.evaluate(report)
        assert result.signals["timing_alert_count"] == 0

    def test_report_exposes_the_full_retained_list_not_just_the_last_ten(self) -> None:
        # The monitor half of the fix: get_security_report must surface every
        # retained alert under scorable_alerts, while recent_alerts stays the
        # last-10 summary.
        mon = AmaCryptographyMonitor(enabled=True)
        # Append alerts in exactly the shape monitoring.py itself appends them
        # ({type, anomaly, timestamp}); get_security_report copies self.alerts.
        for i in range(15):
            mon.alerts.append({"type": "volume_spike", "anomaly": {}, "timestamp": 1000.0 + i})
        report = mon.get_security_report()
        assert len(report["recent_alerts"]) == 10
        assert len(report["scorable_alerts"]) == report["total_alerts"] >= 15
        # scorable_alerts is a defensive copy, not the live list.
        assert report["scorable_alerts"] is not mon.alerts
