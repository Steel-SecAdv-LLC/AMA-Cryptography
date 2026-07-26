#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Regression coverage for two robustness fixes from the refinement pass.

* ``legacy_compat._verify_timestamp_value`` must return a clean ``bool`` for a
  timezone-naive ISO-8601 timestamp instead of raising ``TypeError`` (naive vs.
  aware ``datetime`` comparison) on attacker-controlled input.
* ``monitoring._coerce_expiry_to_unix`` must interpret ``expires_at`` given as
  a Unix number, a ``datetime`` or an ISO-8601 string so key-expiry is actually
  enforced (the old ``isinstance(..., (int, float))`` guard silently ignored the
  latter two, treating expired keys as never-expiring).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ama_cryptography.legacy_compat import _verify_timestamp_value
from ama_cryptography.monitoring import _coerce_expiry_to_unix


class TestTimestampTimezoneNaive:
    def test_naive_recent_timestamp_is_valid(self) -> None:
        naive = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        # Must not raise; naive value is treated as UTC.
        assert _verify_timestamp_value(naive) is True

    def test_naive_future_timestamp_is_invalid(self) -> None:
        future = (datetime.now(timezone.utc) + timedelta(days=1)).replace(tzinfo=None)
        assert _verify_timestamp_value(future.isoformat()) is False

    def test_aware_timestamp_still_works(self) -> None:
        aware = datetime.now(timezone.utc).isoformat()
        assert _verify_timestamp_value(aware) is True


class TestExpiryCoercion:
    def test_unix_number(self) -> None:
        assert _coerce_expiry_to_unix(1_700_000_000) == 1_700_000_000.0
        assert _coerce_expiry_to_unix(1_700_000_000.5) == 1_700_000_000.5

    def test_aware_datetime(self) -> None:
        dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert _coerce_expiry_to_unix(dt) == dt.timestamp()

    def test_naive_datetime_treated_as_utc(self) -> None:
        naive = datetime(2026, 1, 1)
        expected = naive.replace(tzinfo=timezone.utc).timestamp()
        assert _coerce_expiry_to_unix(naive) == expected

    def test_iso_string(self) -> None:
        assert (
            _coerce_expiry_to_unix("2026-01-01T00:00:00+00:00")
            == datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
        )

    def test_bool_is_rejected(self) -> None:
        # bool is an int subclass; must not be read as epoch second 1.0/0.0.
        assert _coerce_expiry_to_unix(True) is None
        assert _coerce_expiry_to_unix(False) is None

    def test_unparseable_returns_none(self) -> None:
        assert _coerce_expiry_to_unix("not-a-timestamp") is None
        assert _coerce_expiry_to_unix(object()) is None
        assert _coerce_expiry_to_unix(None) is None
