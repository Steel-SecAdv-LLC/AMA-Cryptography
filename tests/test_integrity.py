#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Tests for ama_cryptography.integrity — Module Integrity CLI
=============================================================

Covers:
  - CLI --update, --verify, --show modes
  - Mutual exclusion of CLI flags
  - Exit code on integrity failure
  - Integration with _self_test digest functions
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from ama_cryptography.integrity import main

#: The installed package directory, for the two subprocess tests that need a
#: real tree to verify and a real tree to tamper with.
PACKAGE_DIR = Path(__file__).resolve().parent.parent / "ama_cryptography"

# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------


class TestIntegrityCLI:
    """Test the integrity CLI entry point."""

    def test_update_calls_update_digest_under_build_pipeline(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--update only proceeds when AMA_BUILD_PIPELINE=1.

        The wheel build pipeline sets the env var before invoking the
        CLI so the digest can be regenerated post-build; outside that
        flow, --update would silently re-bless tampered .py files and
        defeat the FIPS 140-3 §4.9.1 tamper-detection contract.  The
        gate is documented in SECURITY.md.
        """
        monkeypatch.setenv("AMA_BUILD_PIPELINE", "1")
        with patch(
            "ama_cryptography.integrity.update_integrity_digest", return_value="abc123"
        ) as mock_update:
            with patch("sys.argv", ["integrity", "--update"]):
                rc = main()
            mock_update.assert_called_once()
            assert rc == 0

    def test_update_outside_build_pipeline_refuses(
        self, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        """--update without AMA_BUILD_PIPELINE=1 exits non-zero.

        This is the post-build tamper-detection guarantee — a user who
        edits a .py file post-install cannot re-bless their own copy
        with `python -m ama_cryptography.integrity --update`.
        """
        monkeypatch.delenv("AMA_BUILD_PIPELINE", raising=False)
        with patch(
            "ama_cryptography.integrity.update_integrity_digest", return_value="abc123"
        ) as mock_update:
            with patch("sys.argv", ["integrity", "--update"]):
                rc = main()
            mock_update.assert_not_called()
            assert rc != 0
        # The CLI prints a remediation hint to stderr.
        captured = capsys.readouterr()
        assert "AMA_BUILD_PIPELINE" in captured.err

    def test_verify_success(self) -> None:
        with patch(
            "ama_cryptography.integrity.verify_module_integrity",
            return_value=(True, ""),
        ):
            with patch("sys.argv", ["integrity", "--verify"]):
                rc = main()
                assert rc == 0

    def test_verify_failure_returns_non_zero(self) -> None:
        with patch(
            "ama_cryptography.integrity.verify_module_integrity",
            return_value=(False, "digest mismatch"),
        ):
            with patch("sys.argv", ["integrity", "--verify"]):
                rc = main()
                assert rc == 1

    def test_show_prints_digest(self, capsys: Any) -> None:
        with patch(
            "ama_cryptography.integrity._compute_module_digest",
            return_value="deadbeef1234",
        ):
            with patch("sys.argv", ["integrity", "--show"]):
                rc = main()
                assert rc == 0
        captured = capsys.readouterr()
        assert "deadbeef1234" in captured.out

    def test_no_args_exits_with_error(self) -> None:
        """No flags should cause argparse to exit with code 2."""
        with patch("sys.argv", ["integrity"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2

    def test_mutual_exclusion(self) -> None:
        """Providing multiple flags should fail."""
        with patch("sys.argv", ["integrity", "--update", "--verify"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2


# ---------------------------------------------------------------------------
# Integration: module invocation via python -m
# ---------------------------------------------------------------------------


class TestModuleInvocation:
    """Verify the module can be invoked as `python -m ama_cryptography.integrity`."""

    def test_module_runnable(self) -> None:
        """Module should be importable and callable via python -m."""
        result = subprocess.run(
            [sys.executable, "-m", "ama_cryptography.integrity", "--show"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert len(result.stdout.strip()) > 0

    def test_verify_via_subprocess(self) -> None:
        """``--verify`` must SUCCEED on this tree, and say so.

        It used to assert ``returncode in (0, 1)`` — which is every outcome the
        subcommand has, success and integrity failure alike — and then that the
        combined output contained "integrity" or "Module", which both the
        success and the failure banner do.  The only way it could fail was an
        unhandled crash at exit >= 2 with no matching text, so it did not test
        the verification it names.

        The clean direction is asserted here; the tampered direction is
        :meth:`test_a_tampered_tree_is_refused` below.  A one-sided pass
        proves nothing on its own — the command could return 0 unconditionally.
        """
        if not (PACKAGE_DIR / "_integrity_signature.py").exists():
            pytest.skip("unsigned tree: run `python -m ama_cryptography.integrity --update --sign`")
        result = subprocess.run(
            [sys.executable, "-m", "ama_cryptography.integrity", "--verify"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, (
            "--verify failed on the repository's own tree:\n"
            + (result.stdout + result.stderr)[-2000:]
        )
        assert "Module integrity: OK" in result.stdout, result.stdout[-2000:]

    def test_a_tampered_tree_is_refused(self, tmp_path: Path) -> None:
        """The other direction, in a copy: one changed byte must be caught.

        Without this the assertion above is satisfied by a command that always
        returns 0.
        """
        if not (PACKAGE_DIR / "_integrity_signature.py").exists():
            pytest.skip("unsigned tree: nothing to tamper with")
        import os
        import shutil

        root = tmp_path / "tree"
        root.mkdir()
        shutil.copytree(PACKAGE_DIR, root / "ama_cryptography")
        shutil.rmtree(root / "ama_cryptography" / "__pycache__", ignore_errors=True)

        # Change one signed .py file, leaving the artefact untouched.
        victim = root / "ama_cryptography" / "exceptions.py"
        victim.write_text(victim.read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8")

        result = subprocess.run(
            [sys.executable, "-m", "ama_cryptography.integrity", "--verify"],
            capture_output=True,
            text=True,
            cwd=str(root),
            env=dict(os.environ, PYTHONPATH=str(root), AMA_POST_DIAGNOSTIC_IMPORT="1"),
            timeout=120,
        )
        combined = result.stdout + result.stderr
        assert result.returncode != 0, combined[-2000:]
        assert "Module integrity: OK" not in result.stdout, combined[-2000:]


# ---------------------------------------------------------------------------
# Digest computation sanity
# ---------------------------------------------------------------------------


class TestDigestSanity:
    """Verify digest functions produce consistent results."""

    def test_compute_digest_is_deterministic(self) -> None:
        from ama_cryptography._self_test import _compute_module_digest

        d1 = _compute_module_digest()
        d2 = _compute_module_digest()
        assert d1 == d2

    def test_digest_is_hex_string(self) -> None:
        from ama_cryptography._self_test import _compute_module_digest

        d = _compute_module_digest()
        assert isinstance(d, str)
        assert len(d) > 0
        # Should be a valid hex string
        int(d, 16)

    def test_verify_returns_tuple(self) -> None:
        from ama_cryptography._self_test import verify_module_integrity

        result = verify_module_integrity()
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], str)
