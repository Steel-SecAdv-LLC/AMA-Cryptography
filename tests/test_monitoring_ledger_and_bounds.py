# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""NonceTracker capacity, ledger permissions, and live size normalisation.

Three findings, each of which the tree could not previously fail:

* **MON-004a** — ``NonceTracker._seen`` is keyed by ``(key_id_hash, nonce)``,
  so the per-key 2^32 limit bounded nothing across distinct key ids: memory
  and the on-disk ledger grew without limit.  The fix must NOT be eviction,
  because an evicted entry is a nonce the tracker would later call fresh.  It
  refuses instead, and these tests pin the refusal.
* **MON-004b** — the ledger names key-id digests and the nonces used with
  them, and was created at the process umask (0644 on a default account).
* **MON-005** — ``monitor_crypto_operation`` threaded ``input_size`` through
  correctly, but no shipped call site passed one, so every profile with
  ``normalize_by_size`` was dead configuration.
"""

from __future__ import annotations

import ast
import os
import pathlib
import stat
from typing import Any

import pytest

from ama_cryptography.monitoring import NonceTracker

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _anomaly(result: dict[str, Any] | None) -> dict[str, Any]:
    """The anomaly dict, asserting one was actually returned.

    ``check_and_record`` returns ``None`` on the happy path, so every
    assertion about an anomaly has to establish that one exists first --
    otherwise a regression that silently stopped reporting would read as a
    passing test rather than a failing one.
    """
    assert result is not None, "expected an anomaly, got None (nothing was reported)"
    return result


class TestCapacityRefusesRatherThanForgets:
    def test_a_full_tracker_refuses_new_entries(self, tmp_path: pathlib.Path) -> None:
        tracker = NonceTracker(persist_path=str(tmp_path / "ledger.dat"))
        tracker._MAX_TRACKED_ENTRIES = 3
        for i in range(3):
            assert tracker.check_and_record(b"k", i.to_bytes(12, "big")) is None
        anomaly = tracker.check_and_record(b"k", (99).to_bytes(12, "big"))
        assert anomaly is not None
        assert anomaly["type"] == "tracker_capacity_exceeded"
        assert anomaly["severity"] == "critical"

    def test_the_refused_nonce_is_not_silently_recorded(self, tmp_path: pathlib.Path) -> None:
        """A refusal that recorded anyway would hide the loss of coverage."""
        tracker = NonceTracker(persist_path=str(tmp_path / "ledger.dat"))
        tracker._MAX_TRACKED_ENTRIES = 1
        assert tracker.check_and_record(b"k", b"\x00" * 12) is None
        refused = (1).to_bytes(12, "big")
        assert (
            _anomaly(tracker.check_and_record(b"k", refused))["type"] == "tracker_capacity_exceeded"
        )
        # Still refused, not "reuse": it was never recorded.
        again = _anomaly(tracker.check_and_record(b"k", refused))
        assert again["type"] == "tracker_capacity_exceeded"

    def test_no_recorded_nonce_is_ever_forgotten(self, tmp_path: pathlib.Path) -> None:
        """The property an eviction policy would have broken."""
        tracker = NonceTracker(persist_path=str(tmp_path / "ledger.dat"))
        tracker._MAX_TRACKED_ENTRIES = 4
        first = b"\x01" * 12
        assert tracker.check_and_record(b"k", first) is None
        for i in range(2, 40):
            tracker.check_and_record(b"k", i.to_bytes(12, "big"))
        assert _anomaly(tracker.check_and_record(b"k", first))["type"] == "nonce_reuse"


class TestForgetKeyIsTheReclaimPath:
    def test_forget_key_frees_capacity_and_returns_the_count(self, tmp_path: pathlib.Path) -> None:
        ledger = tmp_path / "ledger.dat"
        tracker = NonceTracker(persist_path=str(ledger))
        tracker._MAX_TRACKED_ENTRIES = 2
        assert tracker.check_and_record(b"retired", b"\x00" * 12) is None
        assert tracker.check_and_record(b"live", b"\x00" * 12) is None
        assert tracker.check_and_record(b"live", b"\x01" * 12) is not None  # full

        assert tracker.forget_key(b"retired") == 1
        assert tracker.check_and_record(b"live", b"\x01" * 12) is None

    def test_forget_key_rewrites_the_ledger_and_keeps_the_mode(
        self, tmp_path: pathlib.Path
    ) -> None:
        ledger = tmp_path / "ledger.dat"
        tracker = NonceTracker(persist_path=str(ledger))
        tracker.check_and_record(b"retired", b"\x00" * 12)
        tracker.check_and_record(b"live", b"\x02" * 12)
        assert len(ledger.read_text().splitlines()) == 2

        tracker.forget_key(b"retired")
        assert len(ledger.read_text().splitlines()) == 1
        assert stat.S_IMODE(ledger.stat().st_mode) == NonceTracker._LEDGER_MODE

    def test_forget_key_survives_a_reload(self, tmp_path: pathlib.Path) -> None:
        ledger = tmp_path / "ledger.dat"
        tracker = NonceTracker(persist_path=str(ledger))
        tracker.check_and_record(b"retired", b"\x00" * 12)
        tracker.check_and_record(b"live", b"\x03" * 12)
        tracker.forget_key(b"retired")

        reloaded = NonceTracker(persist_path=str(ledger))
        assert _anomaly(reloaded.check_and_record(b"live", b"\x03" * 12))["type"] == "nonce_reuse"
        # The retired key's nonce is gone by an explicit decision, not by decay.
        assert reloaded.check_and_record(b"retired", b"\x00" * 12) is None

    def test_forget_key_reports_zero_for_an_unknown_key(self, tmp_path: pathlib.Path) -> None:
        tracker = NonceTracker(persist_path=str(tmp_path / "ledger.dat"))
        assert tracker.forget_key(b"never-seen") == 0


class TestTheLedgerIsOwnerOnly:
    def test_a_new_ledger_is_created_0600(self, tmp_path: pathlib.Path) -> None:
        ledger = tmp_path / "ledger.dat"
        NonceTracker(persist_path=str(ledger)).check_and_record(b"k", b"\x00" * 12)
        assert stat.S_IMODE(ledger.stat().st_mode) == 0o600

    @pytest.mark.parametrize(
        "stale_bits",
        [
            pytest.param(stat.S_IRGRP, id="group-read"),
            pytest.param(stat.S_IRGRP | stat.S_IROTH, id="world-read-0644"),
            pytest.param(stat.S_IWGRP | stat.S_IWOTH, id="world-write"),
            pytest.param(stat.S_IRWXG | stat.S_IRWXO, id="0677"),
            pytest.param(stat.S_IXUSR, id="owner-execute-only"),
        ],
    )
    def test_a_permissive_ledger_from_an_earlier_release_is_narrowed(
        self, tmp_path: pathlib.Path, stale_bits: int
    ) -> None:
        """O_CREAT does not change the mode of a file that already exists.

        Parametrised over every shape of stale bit rather than the single
        ``0o644`` an earlier release actually left, because the production
        narrowing keys on ``S_IMODE(st_mode) & ~_LEDGER_MODE`` — *any* bit
        outside ``0o600``, the owner-execute bit included. One starting mode
        exercised one row of that mask; these five cover group, world, read,
        write, execute and the owner-only case, so a narrowing rewritten to
        strip, say, only the world bits fails here instead of shipping.

        The starting mode is composed from ``stat`` constants and applied with
        ``Path.chmod`` — the idiom already used for this in
        ``tests/test_apt_retry_gate.py`` and ``tests/test_choco_retry_gate.py``
        — so each case names the bits under test instead of encoding them in an
        octal literal.
        """
        ledger = tmp_path / "ledger.dat"
        ledger.write_text("")
        ledger.chmod(stat.S_IRUSR | stat.S_IWUSR | stale_bits)
        assert stat.S_IMODE(ledger.stat().st_mode) != 0o600, "fixture is vacuous"
        NonceTracker(persist_path=str(ledger)).check_and_record(b"k", b"\x00" * 12)
        assert stat.S_IMODE(ledger.stat().st_mode) == 0o600

    @pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="no O_NOFOLLOW on this platform")
    def test_appending_through_a_planted_symlink_is_refused(self, tmp_path: pathlib.Path) -> None:
        target = tmp_path / "victim.txt"
        target.write_text("untouched")
        ledger = tmp_path / "ledger.dat"
        ledger.symlink_to(target)
        tracker = NonceTracker(persist_path=str(ledger), ephemeral=True)
        tracker._ephemeral = False  # keep the constructor from reading the link
        with pytest.raises(RuntimeError):
            tracker.check_and_record(b"k", b"\x00" * 12)
        assert target.read_text() == "untouched"


class TestSizeNormalisationIsLiveOnEveryShippedCallSite:
    """MON-005: the parameter existed and no caller supplied it."""

    @staticmethod
    def _call_sites() -> list[tuple[str, int, bool]]:
        found: list[tuple[str, int, bool]] = []
        for path in sorted((REPO_ROOT / "ama_cryptography").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "monitor_crypto_operation"
                ):
                    supplies = any(k.arg == "input_size" for k in node.keywords) or (
                        len(node.args) >= 3
                    )
                    found.append((str(path.relative_to(REPO_ROOT)), node.lineno, supplies))
        return found

    def test_there_are_call_sites_to_check(self) -> None:
        # Non-vacuity: an empty scan would make the assertion below say nothing.
        assert len(self._call_sites()) >= 10

    def test_every_shipped_call_site_supplies_an_input_size(self) -> None:
        blind = [f"{p}:{ln}" for p, ln, ok in self._call_sites() if not ok]
        assert blind == [], (
            "these call sites drop input_size, so a normalize_by_size profile "
            f"is dead configuration for them: {blind}"
        )
