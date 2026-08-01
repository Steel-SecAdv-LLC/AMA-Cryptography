# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""``AMA_CRYPTO_LIB_PATH`` must not steer the backend under set-uid/set-gid.

The variable names the shared object that supplies every cryptographic
primitive, and a shared object runs its constructors the moment it is mapped —
before the power-on self-test can execute, and without being covered by the
module-integrity digest (which hashes ``.py`` files only).

The dynamic loader refuses to honour ``LD_PRELOAD``/``LD_LIBRARY_PATH`` in
secure-execution mode precisely so a less-privileged caller cannot choose the
code a privileged process loads.  An override of our own has to follow the same
rule, otherwise it re-opens the hole the platform just closed.
"""

import ctypes
import logging
import os
import sys
from pathlib import Path
from typing import Any, Optional

import pytest

from ama_cryptography import pqc_backends


class TestSecureExecutionDetection:
    def test_reports_false_when_uid_matches_euid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(os, "getuid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "getgid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "getegid", lambda: 1000, raising=False)

        assert pqc_backends._in_secure_execution_mode() is False

    def test_reports_true_for_setuid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(os, "getuid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
        monkeypatch.setattr(os, "getgid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "getegid", lambda: 1000, raising=False)

        assert pqc_backends._in_secure_execution_mode() is True

    def test_reports_true_for_setgid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(os, "getuid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "getgid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "getegid", lambda: 0, raising=False)

        assert pqc_backends._in_secure_execution_mode() is True


def _auxv_blob(entries: list[tuple[int, int]]) -> bytes:
    """Serialise ``(type, value)`` pairs the way the kernel lays out auxv."""
    word = ctypes.sizeof(ctypes.c_void_p)
    out = bytearray()
    for key, value in entries:
        out += key.to_bytes(word, sys.byteorder)
        out += value.to_bytes(word, sys.byteorder)
    out += (0).to_bytes(word, sys.byteorder) * 2  # AT_NULL terminator
    return bytes(out)


class TestAtSecureIsConsulted:
    """``AT_SECURE`` covers privilege the uid/gid comparison cannot see.

    A binary carrying file capabilities (``setcap cap_net_bind_service=+ep``)
    executes with ``uid == euid`` and ``gid == egid``, so every comparison in
    the class above answers "not privileged" — while the kernel sets
    ``AT_SECURE=1`` and the dynamic loader duly ignores ``LD_PRELOAD``.  Left
    on the uid check alone, this module would have honoured
    ``AMA_CRYPTO_LIB_PATH`` in exactly the configuration the loader refuses to
    honour its own equivalents, which is the case this class pins.
    """

    def test_parses_at_secure_set(self, tmp_path: Path) -> None:
        blob = tmp_path / "auxv-secure"
        blob.write_bytes(_auxv_blob([(6, 4096), (23, 1), (11, 1000)]))
        assert pqc_backends._auxv_at_secure(str(blob)) is True

    def test_parses_at_secure_clear(self, tmp_path: Path) -> None:
        blob = tmp_path / "auxv-plain"
        blob.write_bytes(_auxv_blob([(6, 4096), (23, 0), (11, 1000)]))
        assert pqc_backends._auxv_at_secure(str(blob)) is False

    def test_absent_at_secure_reads_as_unknown_not_as_safe(self, tmp_path: Path) -> None:
        """A vector with no AT_SECURE entry must return None, not False.

        None routes the caller to the uid/gid fallback.  Returning False would
        assert "not privileged" on the strength of an entry that was never
        there, which is the fail-open direction.
        """
        blob = tmp_path / "auxv-no-secure"
        blob.write_bytes(_auxv_blob([(6, 4096), (11, 1000)]))
        assert pqc_backends._auxv_at_secure(str(blob)) is None

    def test_unreadable_auxv_reads_as_unknown(self, tmp_path: Path) -> None:
        assert pqc_backends._auxv_at_secure(str(tmp_path / "does-not-exist")) is None

    def test_at_secure_wins_when_uid_comparison_sees_nothing(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The file-capabilities case: privileged, but uid == euid."""
        monkeypatch.setattr(os, "getuid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "getgid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "getegid", lambda: 1000, raising=False)
        monkeypatch.setattr(pqc_backends, "_auxv_at_secure", lambda *a, **k: True)

        assert pqc_backends._in_secure_execution_mode() is True

    def test_uid_comparison_still_applies_when_auxv_is_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Masked procfs must not disable the check that does not need it."""
        monkeypatch.setattr(pqc_backends, "_auxv_at_secure", lambda *a, **k: None)
        monkeypatch.setattr(os, "getuid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
        monkeypatch.setattr(os, "getgid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "getegid", lambda: 1000, raising=False)

        assert pqc_backends._in_secure_execution_mode() is True

    @pytest.mark.skipif(not Path("/proc/self/auxv").exists(), reason="no procfs auxiliary vector")
    def test_agrees_with_the_running_kernel(self) -> None:
        """Non-vacuity: the parser must read the real vector, not just fixtures.

        pytest is not privileged, so the expected answer is False.  A parser
        that returned None here — a wrong word size, a mis-stepped stride —
        would silently fall back to the uid check forever and every fixture
        above would still pass.
        """
        assert pqc_backends._auxv_at_secure() is False


class TestOverrideIgnoredUnderSecureExecution:
    def test_override_file_is_not_loaded_when_setuid(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        tmp_path: Path,
    ) -> None:
        """The planted library must never be opened in secure-execution mode."""
        planted = tmp_path / "libama_cryptography.so"
        planted.write_bytes(b"")
        monkeypatch.setenv("AMA_CRYPTO_LIB_PATH", str(planted))
        monkeypatch.setattr(pqc_backends, "_in_secure_execution_mode", lambda: True)
        monkeypatch.setattr(pqc_backends, "_get_search_dirs", list)

        attempted: list[Path] = []

        def _record(path: Path) -> Optional[Any]:
            attempted.append(path)
            return None

        monkeypatch.setattr(pqc_backends, "_try_load_library", _record)

        with caplog.at_level(logging.WARNING):
            result = pqc_backends._find_native_library()

        assert result is None
        assert attempted == [], "override was loaded despite secure-execution mode"
        assert any("secure-execution mode" in r.message for r in caplog.records)

    def test_override_is_honoured_and_logged_when_not_setuid(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        tmp_path: Path,
    ) -> None:
        """Outside secure-execution the override still works, but it is visible."""
        planted = tmp_path / "libama_cryptography.so"
        planted.write_bytes(b"")

        sentinel = object()
        monkeypatch.setenv("AMA_CRYPTO_LIB_PATH", str(planted))
        monkeypatch.setattr(pqc_backends, "_in_secure_execution_mode", lambda: False)
        monkeypatch.setattr(pqc_backends, "_get_search_dirs", list)
        monkeypatch.setattr(pqc_backends, "_try_load_library", lambda path: sentinel)

        with caplog.at_level(logging.WARNING):
            result = pqc_backends._find_native_library()

        assert result is sentinel
        assert any(
            "AMA_CRYPTO_LIB_PATH" in r.message for r in caplog.records
        ), "an overridden cryptographic backend must be visible in the logs"
