# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Shape-safety regression tests for the Cython math_engine kernels
================================================================

The numeric kernels in ``src/cython/math_engine.pyx`` compile with
``boundscheck=False`` and ``wraparound=False`` for speed.  That makes any
shape mismatch between their array arguments an *out-of-bounds read* rather
than a clean error: a slightly-short array silently returns adjacent heap
memory, and a badly-mismatched one crashes the process with SIGSEGV.

The kernels are part of the documented public ``math_engine`` surface
(README, ``test_smoke_import``), so a caller passing mismatched arrays — an
easy mistake — must get a ``ValueError``, never a crash and never a value
derived from memory past the end of the input.  These tests pin that
contract.  They are the negative-input twin of the smoke tests and mirror
the boundary validation already present in ``token_family_counts`` /
``volume_spike_scores``.

If the extension is not built (source checkout without the accelerator), the
whole module is skipped, exactly like ``test_smoke_import``.
"""

from types import ModuleType
from typing import cast

import pytest

np = pytest.importorskip("numpy")


def _engine() -> ModuleType:
    """Return the compiled math_engine, skipping the module if it is absent.

    `pytest.importorskip` rather than a try/except around `importlib`: the
    latter mixed an explicit `return` in the `try` with an implicit fall-through
    `return None` in the `except`, because static analysis cannot know
    `pytest.skip` never returns (CodeQL py/mixed-returns). One explicit return
    makes the contract legible to a reader and to the analyser without needing
    a suppression, and it matches how `numpy` is already imported above.

    The `cast` is there because `pytest.importorskip` is stubbed as returning
    `Any`, and `mypy --strict` enables `warn_return_any`. Returning `Any`
    outright would silence the warning by discarding the type for every caller;
    the cast keeps `ModuleType` at the call sites and states the one thing the
    stub leaves imprecise — importorskip either returns a module or raises.
    """
    return cast(
        ModuleType,
        pytest.importorskip(
            "ama_cryptography.math_engine",
            reason="math_engine not built (Cython extension)",
        ),
    )


def test_matrix_vector_multiply_rejects_length_mismatch() -> None:
    m = _engine()
    matrix = np.ones((4, 8), dtype=np.float64)
    vector = np.ones(4, dtype=np.float64)  # 4 short of the 8 columns
    with pytest.raises(ValueError):
        m.matrix_vector_multiply(matrix, vector)


def test_matrix_vector_multiply_accepts_matching_shapes() -> None:
    m = _engine()
    matrix = np.ones((2, 3), dtype=np.float64)
    vector = np.array([1.0, 2.0, 3.0], dtype=np.float64)
    out = m.matrix_vector_multiply(matrix, vector)
    assert np.allclose(out, [6.0, 6.0])


def test_matrix_multiply_rejects_inner_dimension_mismatch() -> None:
    m = _engine()
    a = np.ones((2, 5), dtype=np.float64)
    b = np.ones((3, 2), dtype=np.float64)  # rows (3) != A cols (5)
    with pytest.raises(ValueError):
        m.matrix_multiply(a, b)


def test_matrix_multiply_accepts_matching_shapes() -> None:
    m = _engine()
    a = np.eye(2, dtype=np.float64)
    b = np.array([[5.0, 6.0], [7.0, 8.0]], dtype=np.float64)
    out = m.matrix_multiply(a, b)
    assert np.allclose(out, b)


def test_lyapunov_function_fast_rejects_length_mismatch() -> None:
    m = _engine()
    # Small mismatch: the dangerous case is a silent OOB read that does NOT
    # crash and returns a plausible number.  It must raise instead.
    with pytest.raises(ValueError):
        m.lyapunov_function_fast(np.ones(8, dtype=np.float64), np.zeros(4, dtype=np.float64))


def test_lyapunov_function_fast_accepts_matching_shapes() -> None:
    m = _engine()
    v = m.lyapunov_function_fast(
        np.array([1.0, 2.0, 3.0], dtype=np.float64),
        np.array([0.0, 0.0, 0.0], dtype=np.float64),
    )
    assert v == pytest.approx(14.0)


def test_helix_evolution_step_rejects_short_target() -> None:
    m = _engine()
    with pytest.raises(ValueError):
        m.helix_evolution_step(
            np.ones(16, dtype=np.float64),
            np.ones(4, dtype=np.float64),  # short
            np.eye(16, dtype=np.float64),
            0.1,
            0.1,
            0.1,
        )


def test_helix_evolution_step_rejects_nonsquare_matrix() -> None:
    m = _engine()
    with pytest.raises(ValueError):
        m.helix_evolution_step(
            np.ones(8, dtype=np.float64),
            np.ones(8, dtype=np.float64),
            np.ones((3, 3), dtype=np.float64),  # not (8, 8)
            0.1,
            0.1,
            0.1,
        )


def test_helix_evolution_step_accepts_matching_shapes() -> None:
    m = _engine()
    out = m.helix_evolution_step(
        np.ones(4, dtype=np.float64),
        np.zeros(4, dtype=np.float64),
        np.eye(4, dtype=np.float64),
        0.0,
        0.0,
        0.1,
    )
    assert out.shape == (4,)


if __name__ == "__main__":  # pragma: no cover
    test_matrix_vector_multiply_rejects_length_mismatch()
    test_matrix_vector_multiply_accepts_matching_shapes()
    test_matrix_multiply_rejects_inner_dimension_mismatch()
    test_matrix_multiply_accepts_matching_shapes()
    test_lyapunov_function_fast_rejects_length_mismatch()
    test_lyapunov_function_fast_accepts_matching_shapes()
    test_helix_evolution_step_rejects_short_target()
    test_helix_evolution_step_rejects_nonsquare_matrix()
    test_helix_evolution_step_accepts_matching_shapes()
    print("✓ math_engine shape-safety tests passed!")
