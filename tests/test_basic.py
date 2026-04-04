#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""Basic tests for AMA Cryptography"""

import pytest

import ama_cryptography


def test_version() -> None:
    """Test that version is correctly set"""
    assert ama_cryptography.__version__ == "2.1.0"


def test_version_consistency() -> None:
    """Version in __init__.py matches pyproject.toml (and metadata if installed)."""
    import importlib.metadata
    from pathlib import Path

    checked = False

    # Check against pyproject.toml (works whether pip-installed or not)
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    if pyproject.exists():
        try:
            import tomllib
        except ModuleNotFoundError:
            try:
                import tomli as tomllib  # type: ignore[no-redef] -- Python < 3.11 fallback (AMA-0)
            except ModuleNotFoundError:
                tomllib = None  # type: ignore[assignment] -- neither available
        if tomllib is not None:
            with open(pyproject, "rb") as f:
                meta = tomllib.load(f)
            assert ama_cryptography.__version__ == meta["project"]["version"], (
                f"__init__.py has {ama_cryptography.__version__!r}, "
                f"pyproject.toml has {meta['project']['version']!r}"
            )
            checked = True

    # Also check importlib.metadata when package is pip-installed
    try:
        meta_version = importlib.metadata.version("ama-cryptography")
        assert ama_cryptography.__version__ == meta_version, (
            f"__init__.py has {ama_cryptography.__version__!r}, "
            f"installed metadata has {meta_version!r}"
        )
        checked = True
    except importlib.metadata.PackageNotFoundError:
        pass  # Not pip-installed; pyproject.toml check above is sufficient

    if not checked:
        pytest.skip("No TOML parser and package not pip-installed; cannot verify version")


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
