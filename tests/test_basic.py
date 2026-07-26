#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Basic tests for AMA Cryptography"""

import pytest

import ama_cryptography


def test_version() -> None:
    """``__version__`` matches the version declared in ``pyproject.toml``.

    Compared against the packaging source of truth rather than a hardcoded
    literal.  A literal here had to be hand-edited on every release — friction
    that eventually gets forgotten, at which point the test pins a stale
    version and fails for a reason that has nothing to do with the defect it
    was meant to catch.  Deriving it keeps the real property (``__init__.py``
    must not drift from the packaging metadata) while costing nothing per
    release.  ``tools/check_version_consistency.py`` enforces agreement across
    all ten declaration sites; this is the fast in-suite check of the pair
    that matters most at import time.

    Parsed with a regex rather than ``tomllib`` so the test also runs on the
    project's Python 3.10 floor, where ``tomllib`` is unavailable.
    """
    import re
    from pathlib import Path

    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    if not pyproject.is_file():
        pytest.skip("pyproject.toml not present (installed-package checkout)")

    match = re.search(
        r'^\s*version\s*=\s*"([^"]+)"', pyproject.read_text(encoding="utf-8"), re.MULTILINE
    )
    assert match is not None, "could not locate [project].version in pyproject.toml"
    assert ama_cryptography.__version__ == match.group(1)


def test_version_consistency() -> None:
    """Version in __init__.py matches package metadata."""
    import importlib.metadata

    try:
        meta_version = importlib.metadata.version("ama-cryptography")
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("package not pip-installed; metadata unavailable")
    else:
        assert ama_cryptography.__version__ == meta_version


def test_author() -> None:
    """Test that author is correctly set"""
    assert "Andrew E. A." in ama_cryptography.__author__


def test_imports() -> None:
    """Test that key components can be imported via the public API."""
    # Verify constants are defined
    assert ama_cryptography.PHI is not None
    assert ama_cryptography.PHI_SQUARED is not None
    assert ama_cryptography.PHI_CUBED is not None
    assert ama_cryptography.OMNI_CODES is not None
    assert ama_cryptography.HELIX_PARAMS is not None
    assert ama_cryptography.LAMBDA_DECAY is not None
    assert ama_cryptography.SIGMA_QUADRATIC_THRESHOLD is not None

    # Verify callables exist
    assert callable(ama_cryptography.AmaEquationEngine)
    assert callable(ama_cryptography.calculate_sigma_quadratic)
    assert callable(ama_cryptography.enforce_sigma_quadratic_threshold)
    assert callable(ama_cryptography.golden_ratio_convergence_proof)
    assert callable(ama_cryptography.helix_curvature)
    assert callable(ama_cryptography.helix_torsion)
    assert callable(ama_cryptography.initialize_ethical_matrix)
    assert callable(ama_cryptography.lyapunov_function)
    assert callable(ama_cryptography.lyapunov_stability_proof)
    assert callable(ama_cryptography.verify_all_codes)
    assert callable(ama_cryptography.verify_mathematical_foundations)


def test_equation_engine_exists() -> None:
    """Test that AmaEquationEngine can be instantiated"""
    # Just verify it exists and is callable
    assert ama_cryptography.AmaEquationEngine is not None
    assert callable(ama_cryptography.AmaEquationEngine)


def test_mathematical_constants() -> None:
    """Test that mathematical constants are correctly defined"""
    # Golden ratio should be approximately 1.618
    assert 1.6 < ama_cryptography.PHI < 1.7
    assert abs(ama_cryptography.PHI**2 - ama_cryptography.PHI_SQUARED) < 0.001
    assert abs(ama_cryptography.PHI**3 - ama_cryptography.PHI_CUBED) < 0.001
