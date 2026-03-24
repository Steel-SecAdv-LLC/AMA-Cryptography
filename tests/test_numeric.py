#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Tests for _numeric.py — Pure-Python Numerical Primitives
=========================================================

Comprehensive coverage of Vec, Mat, construction helpers, element-wise math,
linear algebra (eigvals, dot, norm), FFT/IFFT, and seeded PRNG.
"""

from __future__ import annotations

import math

import pytest

from ama_cryptography._numeric import (
    Mat,
    Vec,
    abs_,
    allclose,
    array,
    clip,
    concatenate,
    cos,
    diag,
    dot,
    eigvals,
    exp,
    eye,
    fft,
    fill_diagonal,
    ifft,
    linspace,
    log,
    max_,
    maximum,
    mean,
    min_,
    norm,
    ones,
    ones_like,
    random,
    real,
    sign,
    sin,
    sqrt,
    sum_,
    zeros,
    zeros_like,
)

# ---------------------------------------------------------------------------
# Vec basics
# ---------------------------------------------------------------------------


class TestVecConstruction:
    """Vec construction, sequence protocol, and properties."""

    def test_from_list(self) -> None:
        v = Vec([1.0, 2.0, 3.0])
        assert len(v) == 3
        assert v[0] == 1.0
        assert v[2] == 3.0

    def test_from_ints_converts_to_float(self) -> None:
        v = Vec([1, 2, 3])
        assert all(isinstance(x, float) for x in v)

    def test_empty_vec(self) -> None:
        v = Vec([])
        assert len(v) == 0
        assert v.shape == (0,)

    def test_shape(self) -> None:
        assert Vec([1, 2, 3]).shape == (3,)

    def test_getitem_slice(self) -> None:
        v = Vec([10, 20, 30, 40])
        sliced = v[1:3]
        assert isinstance(sliced, Vec)
        assert len(sliced) == 2
        assert sliced[0] == 20.0

    def test_setitem_scalar(self) -> None:
        v = Vec([1, 2, 3])
        v[1] = 99.0
        assert v[1] == 99.0

    def test_setitem_slice_with_vec(self) -> None:
        v = Vec([1, 2, 3, 4])
        v[1:3] = Vec([88, 99])
        assert v[1] == 88.0
        assert v[2] == 99.0

    def test_setitem_slice_with_list(self) -> None:
        v = Vec([1, 2, 3])
        v[0:2] = [10.0, 20.0]
        assert v[0] == 10.0
        assert v[1] == 20.0

    def test_iter(self) -> None:
        v = Vec([1, 2, 3])
        assert list(v) == [1.0, 2.0, 3.0]

    def test_repr(self) -> None:
        v = Vec([1.0, 2.0])
        assert "Vec(" in repr(v)

    def test_copy(self) -> None:
        v = Vec([1, 2, 3])
        c = v.copy()
        c[0] = 999.0
        assert v[0] == 1.0  # original unchanged

    def test_tolist(self) -> None:
        v = Vec([1, 2, 3])
        lst = v.tolist()
        assert lst == [1.0, 2.0, 3.0]
        lst[0] = 999.0
        assert v[0] == 1.0  # original unchanged

    def test_reversed(self) -> None:
        v = Vec([1, 2, 3])
        r = reversed(v)
        assert isinstance(r, Vec)
        assert r[0] == 3.0
        assert r[2] == 1.0

    def test_equality(self) -> None:
        assert Vec([1, 2]) == Vec([1, 2])
        assert Vec([1, 2]) != Vec([1, 3])

    def test_equality_not_implemented_for_other_types(self) -> None:
        v = Vec([1, 2])
        assert v.__eq__("not a vec") is NotImplemented


# ---------------------------------------------------------------------------
# Vec arithmetic
# ---------------------------------------------------------------------------


class TestVecArithmetic:
    """Element-wise arithmetic operations on Vec."""

    def test_add_vec(self) -> None:
        assert Vec([1, 2]) + Vec([3, 4]) == Vec([4, 6])

    def test_add_scalar(self) -> None:
        assert Vec([1, 2]) + 10 == Vec([11, 12])

    def test_radd_scalar(self) -> None:
        assert 10 + Vec([1, 2]) == Vec([11, 12])

    def test_add_length_mismatch(self) -> None:
        result = Vec([1, 2]).__add__(Vec([1, 2, 3]))
        assert result is NotImplemented

    def test_add_unsupported_type(self) -> None:
        assert Vec([1]).__add__("x") is NotImplemented

    def test_iadd_vec(self) -> None:
        v = Vec([1, 2])
        v += Vec([3, 4])
        assert v == Vec([4, 6])

    def test_iadd_scalar(self) -> None:
        v = Vec([1, 2])
        v += 5
        assert v == Vec([6, 7])

    def test_iadd_length_mismatch_raises(self) -> None:
        v = Vec([1, 2])
        with pytest.raises(ArithmeticError, match="length mismatch"):
            v += Vec([1, 2, 3])

    def test_iadd_unsupported_type(self) -> None:
        assert Vec([1]).__iadd__("x") is NotImplemented

    def test_sub_vec(self) -> None:
        assert Vec([5, 3]) - Vec([1, 2]) == Vec([4, 1])

    def test_sub_scalar(self) -> None:
        assert Vec([10, 20]) - 5 == Vec([5, 15])

    def test_sub_length_mismatch(self) -> None:
        assert Vec([1]).__sub__(Vec([1, 2])) is NotImplemented

    def test_rsub_scalar(self) -> None:
        assert 10 - Vec([1, 2]) == Vec([9, 8])

    def test_rsub_unsupported(self) -> None:
        assert Vec([1]).__rsub__("x") is NotImplemented

    def test_mul_vec(self) -> None:
        assert Vec([2, 3]) * Vec([4, 5]) == Vec([8, 15])

    def test_mul_scalar(self) -> None:
        assert Vec([2, 3]) * 10 == Vec([20, 30])

    def test_rmul_scalar(self) -> None:
        assert 10 * Vec([2, 3]) == Vec([20, 30])

    def test_mul_length_mismatch(self) -> None:
        assert Vec([1]).__mul__(Vec([1, 2])) is NotImplemented

    def test_imul_scalar(self) -> None:
        v = Vec([2, 3])
        v *= 5
        assert v == Vec([10, 15])

    def test_imul_unsupported(self) -> None:
        assert Vec([1]).__imul__("x") is NotImplemented

    def test_truediv_vec(self) -> None:
        result = Vec([10, 9]) / Vec([2, 3])
        assert result == Vec([5, 3])

    def test_truediv_scalar(self) -> None:
        assert Vec([10, 20]) / 5 == Vec([2, 4])

    def test_truediv_unsupported(self) -> None:
        assert Vec([1]).__truediv__("x") is NotImplemented

    def test_rtruediv_scalar(self) -> None:
        result = 12 / Vec([3, 4])
        assert result == Vec([4, 3])

    def test_rtruediv_unsupported(self) -> None:
        assert Vec([1]).__rtruediv__("x") is NotImplemented

    def test_neg(self) -> None:
        assert -Vec([1, -2, 3]) == Vec([-1, 2, -3])

    def test_pow(self) -> None:
        result = Vec([2, 3]) ** 2
        assert result == Vec([4, 9])

    def test_pow_unsupported(self) -> None:
        assert Vec([1]).__pow__("x") is NotImplemented

    def test_abs(self) -> None:
        assert abs(Vec([-1, 2, -3])) == Vec([1, 2, 3])

    def test_matmul_dot_product(self) -> None:
        result = Vec([1, 2, 3]) @ Vec([4, 5, 6])
        assert result == 32.0

    def test_matmul_length_mismatch_raises(self) -> None:
        with pytest.raises(ArithmeticError, match="length mismatch"):
            Vec([1, 2]) @ Vec([1, 2, 3])

    def test_matmul_unsupported(self) -> None:
        assert Vec([1]).__matmul__("x") is NotImplemented


# ---------------------------------------------------------------------------
# Mat basics
# ---------------------------------------------------------------------------


class TestMatConstruction:
    """Mat construction, indexing, and properties."""

    def test_from_nested_list(self) -> None:
        m = Mat([[1, 2], [3, 4]])
        assert m.rows == 2
        assert m.cols == 2
        assert m.shape == (2, 2)

    def test_getitem_tuple(self) -> None:
        m = Mat([[1, 2], [3, 4]])
        assert m[0, 0] == 1.0
        assert m[1, 1] == 4.0

    def test_getitem_row(self) -> None:
        m = Mat([[1, 2], [3, 4]])
        assert m[0] == [1.0, 2.0]

    def test_setitem_tuple(self) -> None:
        m = Mat([[1, 2], [3, 4]])
        m[0, 1] = 99.0
        assert m[0, 1] == 99.0

    def test_setitem_row(self) -> None:
        m = Mat([[1, 2], [3, 4]])
        m[0] = [10.0, 20.0]
        assert m[0] == [10.0, 20.0]

    def test_repr(self) -> None:
        m = Mat([[1, 2]])
        assert "Mat(" in repr(m)

    def test_transpose(self) -> None:
        m = Mat([[1, 2, 3], [4, 5, 6]])
        t = m.T
        assert t.shape == (3, 2)
        assert t[0, 0] == 1.0
        assert t[0, 1] == 4.0
        assert t[2, 1] == 6.0

    def test_copy(self) -> None:
        m = Mat([[1, 2], [3, 4]])
        c = m.copy()
        c[0, 0] = 999.0
        assert m[0, 0] == 1.0

    def test_empty_mat(self) -> None:
        m = Mat([])
        assert m.rows == 0
        assert m.cols == 0


# ---------------------------------------------------------------------------
# Mat arithmetic
# ---------------------------------------------------------------------------


class TestMatArithmetic:
    """Element-wise and matrix arithmetic on Mat."""

    def test_add_mat(self) -> None:
        a = Mat([[1, 2], [3, 4]])
        b = Mat([[5, 6], [7, 8]])
        c = a + b
        assert c[0, 0] == 6.0
        assert c[1, 1] == 12.0

    def test_add_scalar(self) -> None:
        m = Mat([[1, 2], [3, 4]]) + 10
        assert m[0, 0] == 11.0

    def test_radd_scalar(self) -> None:
        m = 10 + Mat([[1, 2], [3, 4]])
        assert m[0, 0] == 11.0

    def test_add_unsupported(self) -> None:
        assert Mat([[1]]).__add__("x") is NotImplemented

    def test_sub_mat(self) -> None:
        c = Mat([[5, 6], [7, 8]]) - Mat([[1, 2], [3, 4]])
        assert c[0, 0] == 4.0

    def test_sub_scalar(self) -> None:
        m = Mat([[10, 20]]) - 5
        assert m[0, 0] == 5.0

    def test_sub_unsupported(self) -> None:
        assert Mat([[1]]).__sub__("x") is NotImplemented

    def test_rsub_scalar(self) -> None:
        m = 10 - Mat([[1, 2]])
        assert m[0, 0] == 9.0

    def test_rsub_unsupported(self) -> None:
        assert Mat([[1]]).__rsub__("x") is NotImplemented

    def test_mul_scalar(self) -> None:
        m = Mat([[1, 2], [3, 4]]) * 3
        assert m[0, 1] == 6.0

    def test_rmul_scalar(self) -> None:
        m = 3 * Mat([[1, 2], [3, 4]])
        assert m[0, 1] == 6.0

    def test_mul_unsupported(self) -> None:
        assert Mat([[1]]).__mul__("x") is NotImplemented

    def test_truediv_scalar(self) -> None:
        m = Mat([[10, 20]]) / 5
        assert m[0, 0] == 2.0

    def test_truediv_unsupported(self) -> None:
        assert Mat([[1]]).__truediv__("x") is NotImplemented

    def test_matmul_mat(self) -> None:
        a = Mat([[1, 2], [3, 4]])
        b = Mat([[5, 6], [7, 8]])
        c = a @ b
        assert c[0, 0] == 19.0  # 1*5 + 2*7
        assert c[0, 1] == 22.0  # 1*6 + 2*8
        assert c[1, 0] == 43.0  # 3*5 + 4*7
        assert c[1, 1] == 50.0  # 3*6 + 4*8

    def test_matmul_vec(self) -> None:
        m = Mat([[1, 2], [3, 4]])
        v = Vec([5, 6])
        result = m @ v
        assert isinstance(result, Vec)
        assert result[0] == 17.0  # 1*5 + 2*6
        assert result[1] == 39.0  # 3*5 + 4*6

    def test_matmul_unsupported(self) -> None:
        result: object = Mat([[1]]).__matmul__("x")  # type: ignore[operator]
        assert result is NotImplemented

    def test_vec_matmul_mat(self) -> None:
        """Vec @ Mat (row vector times matrix)."""
        v = Vec([1, 2])
        m = Mat([[3, 4], [5, 6]])
        result = v @ m
        assert isinstance(result, Vec)
        assert result[0] == 13.0  # 1*3 + 2*5
        assert result[1] == 16.0  # 1*4 + 2*6


# ---------------------------------------------------------------------------
# Construction functions
# ---------------------------------------------------------------------------


class TestConstructionFunctions:
    """Test array, zeros, ones, eye, diag, linspace, concatenate, etc."""

    def test_array_1d(self) -> None:
        v = array([1, 2, 3])
        assert isinstance(v, Vec)
        assert len(v) == 3

    def test_array_2d(self) -> None:
        m = array([[1, 2], [3, 4]])
        assert isinstance(m, Mat)
        assert m.shape == (2, 2)

    def test_array_empty(self) -> None:
        v = array([])
        assert isinstance(v, Vec)
        assert len(v) == 0

    def test_zeros(self) -> None:
        v = zeros(5)
        assert len(v) == 5
        assert all(x == 0.0 for x in v)

    def test_ones(self) -> None:
        v = ones(3)
        assert len(v) == 3
        assert all(x == 1.0 for x in v)

    def test_zeros_like(self) -> None:
        v = zeros_like(Vec([1, 2, 3]))
        assert len(v) == 3
        assert all(x == 0.0 for x in v)

    def test_ones_like(self) -> None:
        v = ones_like(Vec([1, 2, 3]))
        assert len(v) == 3
        assert all(x == 1.0 for x in v)

    def test_eye(self) -> None:
        m = eye(3)
        assert m.shape == (3, 3)
        assert m[0, 0] == 1.0
        assert m[0, 1] == 0.0
        assert m[1, 1] == 1.0
        assert m[2, 2] == 1.0

    def test_diag_from_vec(self) -> None:
        m = diag(Vec([2, 3, 4]))
        assert m.shape == (3, 3)
        assert m[0, 0] == 2.0
        assert m[1, 1] == 3.0
        assert m[2, 2] == 4.0
        assert m[0, 1] == 0.0

    def test_diag_from_list(self) -> None:
        m = diag([5, 6])
        assert m[0, 0] == 5.0
        assert m[1, 1] == 6.0

    def test_linspace(self) -> None:
        v = linspace(0, 1, 5)
        assert len(v) == 5
        assert v[0] == pytest.approx(0.0)
        assert v[4] == pytest.approx(1.0)
        assert v[2] == pytest.approx(0.5)

    def test_linspace_single_point(self) -> None:
        v = linspace(5.0, 10.0, 1)
        assert len(v) == 1
        assert v[0] == 5.0

    def test_concatenate(self) -> None:
        v = concatenate([Vec([1, 2]), Vec([3, 4, 5])])
        assert len(v) == 5
        assert v.tolist() == [1.0, 2.0, 3.0, 4.0, 5.0]

    def test_clip(self) -> None:
        v = clip(Vec([-5, 0, 5, 10, 15]), 0, 10)
        assert v.tolist() == [0.0, 0.0, 5.0, 10.0, 10.0]

    def test_fill_diagonal(self) -> None:
        m = Mat([[1, 2, 3], [4, 5, 6], [7, 8, 9]])
        fill_diagonal(m, 0.0)
        assert m[0, 0] == 0.0
        assert m[1, 1] == 0.0
        assert m[2, 2] == 0.0
        assert m[0, 1] == 2.0  # off-diagonal unchanged

    def test_fill_diagonal_non_square(self) -> None:
        m = Mat([[1, 2, 3], [4, 5, 6]])
        fill_diagonal(m, 99.0)
        assert m[0, 0] == 99.0
        assert m[1, 1] == 99.0

    def test_maximum(self) -> None:
        v = maximum(3.0, Vec([1, 5, 2, 7]))
        assert v.tolist() == [3.0, 5.0, 3.0, 7.0]

    def test_allclose_true(self) -> None:
        a = Vec([1.0, 2.0, 3.0])
        b = Vec([1.0, 2.0, 3.0 + 1e-10])
        assert allclose(a, b) is True

    def test_allclose_false(self) -> None:
        assert allclose(Vec([1.0]), Vec([2.0])) is False

    def test_allclose_different_lengths(self) -> None:
        assert allclose(Vec([1.0]), Vec([1.0, 2.0])) is False

    def test_real(self) -> None:
        v = Vec([1.0, 2.0, 3.0])
        r = real(v)
        assert r == Vec([1.0, 2.0, 3.0])


# ---------------------------------------------------------------------------
# Element-wise math
# ---------------------------------------------------------------------------


class TestElementWiseMath:
    """sqrt, log, exp, sin, cos, abs_, sign, sum_, mean, max_, min_."""

    def test_sqrt_vec(self) -> None:
        v = sqrt(Vec([4, 9, 16]))
        assert allclose(v, Vec([2, 3, 4]))

    def test_sqrt_scalar(self) -> None:
        assert sqrt(25.0) == pytest.approx(5.0)

    def test_log_vec(self) -> None:
        v = log(Vec([1, math.e, math.e**2]))
        assert v[0] == pytest.approx(0.0)
        assert v[1] == pytest.approx(1.0)
        assert v[2] == pytest.approx(2.0)

    def test_log_scalar(self) -> None:
        assert log(math.e) == pytest.approx(1.0)

    def test_log_clamps_near_zero(self) -> None:
        """log should clamp values near zero to avoid -inf."""
        result = log(Vec([0.0]))
        assert math.isfinite(result[0])

    def test_exp_vec(self) -> None:
        v = exp(Vec([0, 1]))
        assert v[0] == pytest.approx(1.0)
        assert v[1] == pytest.approx(math.e)

    def test_exp_scalar(self) -> None:
        assert exp(0.0) == pytest.approx(1.0)

    def test_sin_vec(self) -> None:
        v = sin(Vec([0, math.pi / 2]))
        assert v[0] == pytest.approx(0.0)
        assert v[1] == pytest.approx(1.0)

    def test_sin_scalar(self) -> None:
        assert sin(0.0) == pytest.approx(0.0)

    def test_cos_vec(self) -> None:
        v = cos(Vec([0, math.pi]))
        assert v[0] == pytest.approx(1.0)
        assert v[1] == pytest.approx(-1.0)

    def test_cos_scalar(self) -> None:
        assert cos(0.0) == pytest.approx(1.0)

    def test_abs_(self) -> None:
        assert abs_(Vec([-1, 2, -3])) == Vec([1, 2, 3])

    def test_sign(self) -> None:
        v = sign(Vec([-5, 0, 7]))
        assert v.tolist() == [-1.0, 0.0, 1.0]

    def test_sum_(self) -> None:
        assert sum_(Vec([1, 2, 3, 4])) == 10.0

    def test_mean(self) -> None:
        assert mean(Vec([2, 4, 6])) == pytest.approx(4.0)

    def test_max_(self) -> None:
        assert max_(Vec([3, 1, 4, 1, 5])) == 5.0

    def test_min_(self) -> None:
        assert min_(Vec([3, 1, 4, 1, 5])) == 1.0


# ---------------------------------------------------------------------------
# Linear algebra
# ---------------------------------------------------------------------------


class TestLinearAlgebra:
    """dot, norm, eigvals."""

    def test_dot(self) -> None:
        assert dot(Vec([1, 2, 3]), Vec([4, 5, 6])) == 32.0

    def test_dot_length_mismatch(self) -> None:
        with pytest.raises(ValueError, match="length mismatch"):
            dot(Vec([1, 2]), Vec([1, 2, 3]))

    def test_norm(self) -> None:
        assert norm(Vec([3, 4])) == pytest.approx(5.0)

    def test_norm_zero(self) -> None:
        assert norm(Vec([0, 0, 0])) == 0.0

    def test_eigvals_1x1(self) -> None:
        vals = eigvals(Mat([[7.0]]))
        assert len(vals) == 1
        assert vals[0] == pytest.approx(7.0)

    def test_eigvals_empty(self) -> None:
        assert eigvals(Mat([])) == []

    def test_eigvals_2x2_diagonal(self) -> None:
        vals = eigvals(Mat([[3.0, 0.0], [0.0, 5.0]]))
        vals_sorted = sorted(vals)
        assert vals_sorted[0] == pytest.approx(3.0, abs=1e-6)
        assert vals_sorted[1] == pytest.approx(5.0, abs=1e-6)

    def test_eigvals_symmetric_3x3(self) -> None:
        """Eigenvalues of a known symmetric matrix."""
        m = Mat([[2, 1, 0], [1, 3, 1], [0, 1, 2]])
        vals = sorted(eigvals(m))
        # Known eigenvalues: 1, 2, 4
        assert vals[0] == pytest.approx(1.0, abs=1e-6)
        assert vals[1] == pytest.approx(2.0, abs=1e-6)
        assert vals[2] == pytest.approx(4.0, abs=1e-6)

    def test_eigvals_identity(self) -> None:
        """Identity matrix has all eigenvalues = 1."""
        vals = eigvals(eye(4))
        for v in vals:
            assert v == pytest.approx(1.0, abs=1e-6)


# ---------------------------------------------------------------------------
# FFT / IFFT
# ---------------------------------------------------------------------------


class TestFFT:
    """FFT and IFFT round-trip and correctness."""

    def test_fft_ifft_roundtrip_power_of_2(self) -> None:
        """fft then ifft should recover the original signal (power-of-2 length)."""
        original = Vec([1, 2, 3, 4, 5, 6, 7, 8])
        recovered = real(ifft(fft(original)))
        for i in range(len(original)):
            assert recovered[i] == pytest.approx(original[i], abs=1e-10)

    def test_fft_ifft_roundtrip_non_power_of_2(self) -> None:
        """Bluestein's algorithm for non-power-of-2 lengths."""
        original = Vec([1, 2, 3, 4, 5])
        recovered = real(ifft(fft(original)))
        for i in range(len(original)):
            assert recovered[i] == pytest.approx(original[i], abs=1e-10)

    def test_fft_empty(self) -> None:
        assert len(fft(Vec([]))) == 0

    def test_ifft_empty(self) -> None:
        assert len(ifft(Vec([]))) == 0

    def test_fft_single_element(self) -> None:
        result = fft(Vec([42.0]))
        assert len(result) == 1

    def test_fft_dc_component(self) -> None:
        """DC component (index 0) of FFT should be the sum of all elements."""
        v = Vec([1, 2, 3, 4])
        f = fft(v)
        # The DC component is the sum
        dc = f[0]
        if isinstance(dc, complex):
            assert dc.real == pytest.approx(10.0, abs=1e-10)
        else:
            assert dc == pytest.approx(10.0, abs=1e-10)


# ---------------------------------------------------------------------------
# Seeded PRNG
# ---------------------------------------------------------------------------


class TestRandom:
    """Seeded PRNG: reproducibility and shape correctness."""

    def test_seed_reproducibility(self) -> None:
        random.seed(42)
        a = random.randn(10)
        random.seed(42)
        b = random.randn(10)
        assert a == b

    def test_randn_scalar(self) -> None:
        random.seed(0)
        x = random.randn()
        assert isinstance(x, float)

    def test_randn_1d(self) -> None:
        random.seed(0)
        v = random.randn(5)
        assert isinstance(v, Vec)
        assert len(v) == 5

    def test_randn_2d(self) -> None:
        random.seed(0)
        m = random.randn(3, 4)
        assert isinstance(m, Mat)
        assert m.shape == (3, 4)

    def test_randn_invalid_dims(self) -> None:
        with pytest.raises(ValueError, match="up to 2-D"):
            random.randn(2, 3, 4)  # type: ignore[call-overload]

    def test_rand_scalar(self) -> None:
        random.seed(0)
        x = random.rand()
        assert isinstance(x, float)
        assert 0.0 <= x < 1.0

    def test_rand_1d(self) -> None:
        random.seed(0)
        v = random.rand(100)
        assert isinstance(v, Vec)
        assert all(0.0 <= x < 1.0 for x in v)

    def test_rand_2d(self) -> None:
        random.seed(0)
        m = random.rand(2, 3)
        assert isinstance(m, Mat)
        assert m.shape == (2, 3)

    def test_rand_invalid_dims(self) -> None:
        with pytest.raises(ValueError, match="up to 2-D"):
            random.rand(2, 3, 4)  # type: ignore[call-overload]

    def test_uniform_scalar(self) -> None:
        random.seed(0)
        x = random.uniform(5.0, 10.0)
        assert isinstance(x, float)
        assert 5.0 <= x <= 10.0

    def test_uniform_vec(self) -> None:
        random.seed(0)
        v = random.uniform(0.0, 1.0, size=50)
        assert isinstance(v, Vec)
        assert len(v) == 50

    def test_binomial(self) -> None:
        random.seed(0)
        v = random.binomial(10, 0.5, size=100)
        assert isinstance(v, Vec)
        assert len(v) == 100
        assert all(0.0 <= x <= 10.0 for x in v)

    def test_binomial_clamps_probability(self) -> None:
        """Probability should be clamped to [0, 1]."""
        random.seed(0)
        v = random.binomial(5, 1.5, size=10)  # p > 1 clamped to 1
        assert all(x == 5.0 for x in v)

        v2 = random.binomial(5, -0.5, size=10)  # p < 0 clamped to 0
        assert all(x == 0.0 for x in v2)


# ---------------------------------------------------------------------------
# Module __all__
# ---------------------------------------------------------------------------


class TestModuleExports:
    """Verify __all__ exports are accessible."""

    def test_all_exports_importable(self) -> None:
        from ama_cryptography import _numeric as mod

        for name in mod.__all__:
            assert hasattr(mod, name), f"{name} listed in __all__ but not defined"
