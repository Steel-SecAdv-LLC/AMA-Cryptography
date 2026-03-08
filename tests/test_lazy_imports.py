#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Tests for lazy (PEP 562) imports in ama_cryptography.__init__.

Validates that:
1. `import ama_cryptography` succeeds without numpy installed.
2. Accessing a math symbol without numpy gives a clear error.
3. All symbols in __all__ load correctly when numpy IS present.
"""

import subprocess
import sys
import textwrap

import pytest


def _run_script(script: str) -> subprocess.CompletedProcess:
    """Run a Python script in a subprocess, return the result."""
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script)],
        capture_output=True,
        text=True,
        timeout=30,
    )


class TestLazyImportWithoutNumpy:
    """Tests that the package loads without numpy."""

    def test_import_without_numpy(self):
        """import ama_cryptography succeeds and exposes __version__ without numpy."""
        result = _run_script(
            """\
            import sys
            sys.modules['numpy'] = None
            sys.modules['scipy'] = None
            import ama_cryptography
            print(ama_cryptography.__version__)
        """
        )
        assert (
            result.returncode == 0
        ), f"Import failed with numpy blocked.\nstdout: {result.stdout}\nstderr: {result.stderr}"
        assert result.stdout.strip() == "2.0"

    def test_math_import_gives_clear_error(self):
        """Accessing PHI without numpy gives a clear ModuleNotFoundError."""
        result = _run_script(
            """\
            import sys
            sys.modules['numpy'] = None
            sys.modules['scipy'] = None
            import ama_cryptography
            try:
                _ = ama_cryptography.PHI
                print('ERROR: No exception raised')
                sys.exit(1)
            except ImportError as e:
                if 'numpy' in str(e).lower():
                    print('OK: clear numpy error')
                else:
                    print(f'ERROR: exception did not mention numpy: {e}')
                    sys.exit(1)
        """
        )
        assert (
            result.returncode == 0
        ), f"Expected clear numpy error.\nstdout: {result.stdout}\nstderr: {result.stderr}"
        assert "OK" in result.stdout

    def test_engine_import_gives_clear_error(self):
        """Accessing AmaEquationEngine without numpy gives a clear error."""
        result = _run_script(
            """\
            import sys
            sys.modules['numpy'] = None
            sys.modules['scipy'] = None
            import ama_cryptography
            try:
                _ = ama_cryptography.AmaEquationEngine
                print('ERROR: No exception raised')
                sys.exit(1)
            except ImportError as e:
                if 'numpy' in str(e).lower():
                    print('OK: clear numpy error')
                else:
                    print(f'ERROR: exception did not mention numpy: {e}')
                    sys.exit(1)
        """
        )
        assert (
            result.returncode == 0
        ), f"Expected clear numpy error.\nstdout: {result.stdout}\nstderr: {result.stderr}"
        assert "OK" in result.stdout


class TestLazyImportWithNumpy:
    """Tests that all symbols load correctly when numpy IS present."""

    @pytest.fixture(autouse=True)
    def _require_numpy(self):
        """Skip these tests if numpy is not installed."""
        pytest.importorskip("numpy")

    def test_math_imports_work_with_numpy(self):
        """All symbols in __all__ load correctly when numpy is present."""
        import ama_cryptography

        for name in ama_cryptography.__all__:
            attr = getattr(ama_cryptography, name)
            assert attr is not None, f"Symbol {name!r} resolved to None"

    def test_phi_value(self):
        """PHI has the expected golden ratio value."""
        import ama_cryptography

        phi = ama_cryptography.PHI
        assert abs(phi - 1.6180339887) < 1e-6

    def test_equation_engine_instantiates(self):
        """AmaEquationEngine can be instantiated."""
        import ama_cryptography

        engine = ama_cryptography.AmaEquationEngine()
        assert engine is not None


class TestAttributeError:
    """Tests that unknown attributes raise AttributeError."""

    def test_unknown_attribute(self):
        """Accessing a non-existent attribute raises AttributeError."""
        import ama_cryptography

        with pytest.raises(AttributeError, match="no attribute"):
            _ = ama_cryptography.NONEXISTENT_SYMBOL
