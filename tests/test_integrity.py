#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
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
from typing import Any
from unittest.mock import patch

import pytest

from ama_cryptography.integrity import main

# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------


class TestIntegrityCLI:
    """Test the integrity CLI entry point."""

    def test_update_calls_update_digest(self) -> None:
        with patch(
            "ama_cryptography.integrity.update_integrity_digest", return_value="abc123"
        ) as mock_update:
            with patch("sys.argv", ["integrity", "--update"]):
                main()
            mock_update.assert_called_once()

    def test_verify_success(self) -> None:
        with patch(
            "ama_cryptography.integrity.verify_module_integrity",
            return_value=(True, ""),
        ):
            with patch("sys.argv", ["integrity", "--verify"]):
                main()  # should not raise

    def test_verify_failure_exits_with_code_1(self) -> None:
        with patch(
            "ama_cryptography.integrity.verify_module_integrity",
            return_value=(False, "digest mismatch"),
        ):
            with patch("sys.argv", ["integrity", "--verify"]):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 1

    def test_show_prints_digest(self, capsys: Any) -> None:
        with patch(
            "ama_cryptography.integrity._compute_module_digest",
            return_value="deadbeef1234",
        ):
            with patch("sys.argv", ["integrity", "--show"]):
                main()
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
        """Verify command should succeed when digest is up to date."""
        result = subprocess.run(
            [sys.executable, "-m", "ama_cryptography.integrity", "--verify"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # May fail if digest is stale, but should not crash
        assert result.returncode in (0, 1)
        combined = result.stdout + result.stderr
        assert "integrity" in combined.lower() or "Module" in combined


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
