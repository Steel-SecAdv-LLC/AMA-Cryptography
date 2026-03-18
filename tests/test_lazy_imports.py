#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Tests for imports in ama_cryptography.__init__.

Validates that:
1. `import ama_cryptography` succeeds (no external dependencies required).
2. All symbols in __all__ load correctly.
3. Unknown attributes raise AttributeError.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest


def _run_script(script: str) -> subprocess.CompletedProcess[str]:
    """Run a Python script in a subprocess, return the result."""
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script)],
        capture_output=True,
        text=True,
        timeout=30,
    )


class TestImportWithoutExternalDeps:
    """Tests that the package loads without any external numerical libraries."""

    def test_import_without_numpy(self) -> None:
        """import ama_cryptography succeeds and exposes __version__ without numpy."""
        result = _run_script("""\
            import sys
            sys.modules['numpy'] = None
            sys.modules['scipy'] = None
            import ama_cryptography
            print(ama_cryptography.__version__)
        """)
        assert (
            result.returncode == 0
        ), f"Import failed with numpy blocked.\nstdout: {result.stdout}\nstderr: {result.stderr}"
        assert result.stdout.strip() == "2.0"

    def test_phi_accessible_without_numpy(self) -> None:
        """PHI is accessible without numpy (uses pure-Python _numeric)."""
        result = _run_script("""\
            import sys
            sys.modules['numpy'] = None
            sys.modules['scipy'] = None
            import ama_cryptography
            print(f'{ama_cryptography.PHI:.10f}')
        """)
        assert (
            result.returncode == 0
        ), f"PHI access failed without numpy.\nstdout: {result.stdout}\nstderr: {result.stderr}"
        assert result.stdout.strip().startswith("1.618033")

    def test_equation_engine_without_numpy(self) -> None:
        """AmaEquationEngine instantiates without numpy."""
        result = _run_script("""\
            import sys
            sys.modules['numpy'] = None
            sys.modules['scipy'] = None
            import ama_cryptography
            engine = ama_cryptography.AmaEquationEngine(state_dim=10, random_seed=42)
            print(f'dim={engine.state_dim}')
        """)
        assert (
            result.returncode == 0
        ), f"Engine init failed without numpy.\nstdout: {result.stdout}\nstderr: {result.stderr}"
        assert "dim=10" in result.stdout


class TestAllSymbolsLoad:
    """Tests that all symbols load correctly."""

    def test_all_symbols_in_all(self) -> None:
        """All symbols in __all__ load correctly."""
        import ama_cryptography

        for name in ama_cryptography.__all__:
            attr = getattr(ama_cryptography, name)
            assert attr is not None, f"Symbol {name!r} resolved to None"

    def test_phi_value(self) -> None:
        """PHI has the expected golden ratio value."""
        import ama_cryptography

        phi = ama_cryptography.PHI
        assert abs(phi - 1.6180339887) < 1e-6

    def test_equation_engine_instantiates(self) -> None:
        """AmaEquationEngine can be instantiated."""
        import ama_cryptography

        engine = ama_cryptography.AmaEquationEngine()
        assert engine is not None


class TestAttributeError:
    """Tests that unknown attributes raise AttributeError."""

    def test_unknown_attribute(self) -> None:
        """Accessing a non-existent attribute raises AttributeError."""
        import ama_cryptography

        with pytest.raises(AttributeError):
            _ = ama_cryptography.NONEXISTENT_SYMBOL
