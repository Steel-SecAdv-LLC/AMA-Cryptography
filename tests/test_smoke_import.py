"""
Copyright 2025-2026 Steel Security Advisors LLC
Licensed under the Apache License, Version 2.0

Smoke test for compiled Cython extensions
==========================================

This test verifies that the compiled Cython math_engine module can be
imported and that core exported functions are available.
"""

import importlib

import pytest


def test_import_math_engine() -> None:
    """Test that math_engine module can be imported."""
    try:
        mod = importlib.import_module("ama_cryptography.math_engine")
        assert mod is not None, "Module imported but is None"
    except ImportError as e:
        pytest.skip(f"math_engine not built (Cython extension): {e}")


def test_math_engine_has_matrix_vector_multiply() -> None:
    """Test that math_engine exports matrix_vector_multiply function."""
    try:
        mod = importlib.import_module("ama_cryptography.math_engine")
        assert hasattr(
            mod, "matrix_vector_multiply"
        ), "matrix_vector_multiply function not found in math_engine"
        # Verify it's callable
        assert callable(mod.matrix_vector_multiply), "matrix_vector_multiply is not callable"
    except ImportError as e:
        pytest.skip(f"math_engine not built (Cython extension): {e}")


def test_math_engine_has_core_functions() -> None:
    """Test that math_engine exports other core functions."""
    try:
        mod = importlib.import_module("ama_cryptography.math_engine")

        # Check for other key exported functions
        expected_functions = [
            "matrix_multiply",
            "lyapunov_function_fast",
            "helix_evolution_step",
            "fibonacci_fast",
            "phi_amplification",
        ]

        for func_name in expected_functions:
            assert hasattr(mod, func_name), f"{func_name} function not found in math_engine"
            assert callable(getattr(mod, func_name)), f"{func_name} is not callable"
    except ImportError as e:
        pytest.skip(f"math_engine not built (Cython extension): {e}")


if __name__ == "__main__":
    # Allow running this test directly
    test_import_math_engine()
    test_math_engine_has_matrix_vector_multiply()
    test_math_engine_has_core_functions()
    print("✓ All smoke tests passed!")
