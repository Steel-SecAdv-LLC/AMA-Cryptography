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

import logging
import os
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
