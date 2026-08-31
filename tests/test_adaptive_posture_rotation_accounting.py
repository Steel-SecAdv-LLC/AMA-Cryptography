#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""A notifier callback must not mask a failing key-rotation mechanism.

2026-08 v5 audit, item 15 (adaptive-posture): ``_trigger_rotation`` OR-ed a
single ``succeeded`` flag across the KMS-backed ``rotation_manager`` AND the
``on_rotation`` notifier.  If the KMS raised (``register_key`` /
``initiate_rotation``) but a configured ``on_rotation()`` returned normally,
``succeeded`` was ``True``: the cooldown armed, the failure streak cleared, and
``get_posture_summary()['rotation_suspended']`` stayed ``False`` — so
``MAX_CONSECUTIVE_ROTATION_FAILURES`` never tripped even though NO key ever
rotated.  The docstring frames ``on_rotation`` as a notifier, so "notifier
healthy, KMS broken" is a realistic deployment.

The fix tracks the key-rotating mechanism separately: a notifier can only
confirm success when the KMS-backed rotation did not fail; a KMS failure now
dominates so the streak accrues and the cap eventually trips.  Callback-only
deployments (no ``rotation_manager``) keep counting the callback as the
mechanism.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from ama_cryptography.adaptive_posture import CryptoPostureController


def _broken_kms() -> MagicMock:
    """A rotation_manager whose actual rotation raises, as a down KMS would."""
    mgr = MagicMock()
    mgr.get_active_key.return_value = "key-001"
    mgr.register_key.side_effect = RuntimeError("KMS unreachable")
    return mgr


class TestRotationSuccessAccounting:
    def test_healthy_notifier_does_not_mask_a_failing_kms(self) -> None:
        on_rotation = MagicMock()  # a healthy notifier that always "succeeds"
        ctl = CryptoPostureController(
            rotation_manager=_broken_kms(),
            on_rotation=on_rotation,
            rotation_cooldown=0.0,  # defeat the retry backoff so failures accrue
        )
        ctl._last_rotation_time = 0.0

        ctl._trigger_rotation()

        # The notifier still fires (it is a notifier)...
        on_rotation.assert_called_once()
        # ...but it must NOT have converted the KMS failure into a success:
        assert ctl._rotation_failure_streak == 1, (
            "a broken KMS with a healthy notifier was accounted as a success — "
            "the notifier masked the failure"
        )
        assert (
            ctl._last_rotation_time == 0.0
        ), "the cooldown was armed on a rotation that never rotated a key"

    def test_masked_failure_streak_eventually_trips_the_cap(self) -> None:
        # The security property the mask defeated: with a healthy notifier over
        # a broken KMS, the consecutive-failure cap must still be reachable.
        on_rotation = MagicMock()
        ctl = CryptoPostureController(
            rotation_manager=_broken_kms(),
            on_rotation=on_rotation,
            rotation_cooldown=0.0,
        )
        for _ in range(ctl.MAX_CONSECUTIVE_ROTATION_FAILURES):
            ctl._trigger_rotation()

        assert ctl._rotation_failure_streak >= ctl.MAX_CONSECUTIVE_ROTATION_FAILURES
        assert ctl.get_posture_summary()["rotation_suspended"] is True, (
            "consecutive KMS failures never suspended rotation because a healthy "
            "notifier kept clearing the streak"
        )

    def test_successful_kms_rotation_still_arms_and_clears(self) -> None:
        # The fix must not break the happy path: a KMS that rotates plus a
        # healthy notifier is a success — cooldown armed, streak clear.
        mgr = MagicMock()
        mgr.get_active_key.return_value = "key-001"
        on_rotation = MagicMock()
        ctl = CryptoPostureController(
            rotation_manager=mgr, on_rotation=on_rotation, rotation_cooldown=300.0
        )
        ctl._last_rotation_time = 0.0

        ctl._trigger_rotation()

        mgr.register_key.assert_called_once()
        mgr.initiate_rotation.assert_called_once()
        assert ctl._rotation_failure_streak == 0
        assert ctl._last_rotation_time > 0.0, "a successful rotation must arm the cooldown"

    def test_callback_only_deployment_still_counts_the_callback(self) -> None:
        # With no rotation_manager configured, the callback IS the mechanism —
        # its success must still count, or a callback-only deployment would
        # never register a rotation.
        on_rotation = MagicMock()
        ctl = CryptoPostureController(on_rotation=on_rotation, rotation_cooldown=300.0)
        ctl._last_rotation_time = 0.0

        ctl._trigger_rotation()

        on_rotation.assert_called_once()
        assert ctl._rotation_failure_streak == 0
        assert ctl._last_rotation_time > 0.0
