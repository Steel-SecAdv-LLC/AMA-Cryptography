#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Pins for :meth:`EWMAStats._median_and_mad` — the memoized, single-sort MAD.

``record_timing`` consults the MAD several times per recorded operation, and
each consultation used to sort the whole recent-value window — up to four
O(w log w) sorts per crypto operation, which made the *monitoring* of a
signature several times more expensive than the Ed25519 signature it
monitored.  The replacement sorts once per new observation and selects the
deviation median with an O(w) two-pointer merge (the deviations of a sorted
window form two ascending runs walking outward from the median).

These tests pin the property that makes that replacement safe: the values are
**bit-identical** to the naive two-sort form, over randomized windows,
heavy-duplicate windows, and both parities of window length.  They also pin
the memoization contract — same window returns the cached pair, any new
observation or a reset invalidates it — because a stale cache would make the
anomaly detector compare fresh samples against an old window.
"""

from __future__ import annotations

import random

import pytest

from ama_cryptography.monitoring import EWMAStats


def _naive_median_and_mad(values: list[float]) -> tuple[float, float]:
    """The pre-optimization reference: two full sorts, no caching."""
    ordered = sorted(values)
    n = len(ordered)
    if n % 2:
        median = ordered[n // 2]
    else:
        median = (ordered[n // 2 - 1] + ordered[n // 2]) / 2.0
    deviations = sorted(abs(v - median) for v in ordered)
    if n % 2:
        mad = deviations[n // 2]
    else:
        mad = (deviations[n // 2 - 1] + deviations[n // 2]) / 2.0
    return float(median), float(mad)


class TestMedianAndMadEquivalence:
    """The merged selection must match the naive double-sort exactly."""

    def test_randomized_windows_bit_identical(self) -> None:
        rng = random.Random(0xA3A)  # noqa: S311 -- test data, not keys (MAD-001)
        for _ in range(1500):
            n = rng.randint(3, 130)
            stats = EWMAStats(window_size=256)
            values = [rng.uniform(-1e3, 1e3) for _ in range(n)]
            for v in values:
                stats.update(v)
            assert stats._median_and_mad() == _naive_median_and_mad(values)

    def test_heavy_duplicates_bit_identical(self) -> None:
        """Duplicate-laden windows exercise the bisect split around ties."""
        rng = random.Random(0xB4B)  # noqa: S311 -- test data, not keys (MAD-002)
        for _ in range(800):
            n = rng.randint(3, 90)
            stats = EWMAStats(window_size=128)
            values = [float(rng.randint(0, 4)) for _ in range(n)]
            for v in values:
                stats.update(v)
            assert stats._median_and_mad() == _naive_median_and_mad(values)

    def test_all_equal_window_is_zero_mad(self) -> None:
        stats = EWMAStats(window_size=32)
        for _ in range(20):
            stats.update(7.5)
        median, mad = stats._median_and_mad()
        assert median == 7.5
        assert mad == 0.0

    def test_both_parities(self) -> None:
        for n in (3, 4, 9, 10, 99, 100):
            stats = EWMAStats(window_size=256)
            values = [float(i * i % 37) for i in range(n)]
            for v in values:
                stats.update(v)
            assert stats._median_and_mad() == _naive_median_and_mad(values)

    def test_window_wrap_uses_only_recent_values(self) -> None:
        """Once the deque wraps, evicted samples must not influence the MAD."""
        stats = EWMAStats(window_size=10)
        for v in [1e6] * 50 + [float(i) for i in range(10)]:
            stats.update(v)
        assert stats._median_and_mad() == _naive_median_and_mad([float(i) for i in range(10)])


class TestMadMemoization:
    """One computation per observation; updates and resets invalidate."""

    def test_repeated_reads_hit_the_cache(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stats = EWMAStats(window_size=64)
        for i in range(40):
            stats.update(float(i))
        first = stats._median_and_mad()

        def _poisoned_sorted(*args: object, **kwargs: object) -> None:
            raise AssertionError("cache miss: _median_and_mad re-sorted an unchanged window")

        monkeypatch.setattr("builtins.sorted", _poisoned_sorted)
        assert stats._median_and_mad() == first
        assert stats.get_mad() == first[1]
        # is_anomaly_mad reads through the same memo.
        assert stats.is_anomaly_mad(first[0]) is False

    def test_update_invalidates(self) -> None:
        """A new observation must force a recomputation over the new window.

        The asserted signal is the recomputation itself, not a changed MAD —
        MAD is robust by design, so a single outlier can legitimately leave
        the value identical while the window contents differ.
        """
        stats = EWMAStats(window_size=64)
        for i in range(40):
            stats.update(float(i))
        stats.get_mad()
        cached_key = stats._mad_cache[0]
        stats.update(1e9)
        assert stats._mad_cache[0] == cached_key, "update itself must not compute"
        recomputed = stats._median_and_mad()
        assert stats._mad_cache[0] != cached_key, "read after update must recompute"
        naive = _naive_median_and_mad([float(i) for i in range(40)] + [1e9])
        assert recomputed == naive

    def test_reset_invalidates(self) -> None:
        stats = EWMAStats(window_size=64)
        for i in range(40):
            stats.update(float(i))
        stats.reset()
        for _ in range(5):
            stats.update(3.0)
        median, mad = stats._median_and_mad()
        assert (median, mad) == (3.0, 0.0)


class TestAnomalyBehaviourUnchanged:
    """The detector's observable answers must not move."""

    def test_get_mad_short_window_is_zero(self) -> None:
        stats = EWMAStats(window_size=16)
        stats.update(1.0)
        stats.update(2.0)
        assert stats.get_mad() == 0.0

    def test_is_anomaly_mad_short_window_is_false(self) -> None:
        stats = EWMAStats(window_size=16)
        for i in range(9):
            stats.update(float(i))
        assert stats.is_anomaly_mad(1e9) is False

    def test_spike_detected_and_normal_not(self) -> None:
        rng = random.Random(0xC5C)  # noqa: S311 -- test data, not keys (MAD-003)
        stats = EWMAStats(window_size=100)
        for _ in range(30):
            stats.update(10.0 + rng.uniform(-0.5, 0.5))
        assert stats.is_anomaly_mad(10.2) is False
        assert stats.is_anomaly_mad(100.0) is True
