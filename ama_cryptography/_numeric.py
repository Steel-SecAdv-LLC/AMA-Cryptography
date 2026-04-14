#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
AMA Cryptography — Pure-Python Numerical Primitives
=========================================================

Zero-dependency numerical library replacing numpy for the mathematical
framework layer (equations.py, double_helix_engine.py).  Every operation
is owned end-to-end — no external numerical libraries.

Provides:
  - Vec / Mat types with arithmetic operators and ``@`` (matmul)
  - Element-wise math (sqrt, exp, log, sin, cos, …)
  - Reductions (sum, mean, max, min, norm)
  - Linear-algebra (eigvals via QR iteration for real symmetric matrices)
  - FFT / IFFT (Cooley–Tukey radix-2)
  - Seeded PRNG (random.randn, random.binomial, random.uniform)
"""

from __future__ import annotations

import cmath
import math
import random as _stdlib_random
from typing import Iterator, List, Sequence, Tuple, overload

__all__ = [
    "Vec",
    "Mat",
    "array",
    "zeros",
    "ones",
    "zeros_like",
    "ones_like",
    "eye",
    "diag",
    "linspace",
    "concatenate",
    "clip",
    "fill_diagonal",
    "maximum",
    "allclose",
    "real",
    "fft",
    "ifft",
    "eigvals",
    "norm",
    "dot",
    "sqrt",
    "log",
    "exp",
    "sin",
    "cos",
    "abs_",
    "sign",
    "sum_",
    "mean",
    "max_",
    "min_",
    "random",
]

# ---------------------------------------------------------------------------
# Vec — 1-D numerical array
# ---------------------------------------------------------------------------


class Vec:
    """1-D array of floats with element-wise arithmetic and ``@`` (dot)."""

    __slots__ = ("_data",)

    def __init__(self, data: Sequence[float]) -> None:
        self._data: List[float] = [float(x) for x in data]

    # -- construction helpers ------------------------------------------------

    @staticmethod
    def _wrap(data: List[float]) -> Vec:
        v = object.__new__(Vec)
        v._data = data
        return v

    # -- sequence protocol ---------------------------------------------------

    def __len__(self) -> int:
        return len(self._data)

    @overload
    def __getitem__(self, idx: int) -> float:
        pass

    @overload
    def __getitem__(self, idx: slice) -> Vec:
        pass

    def __getitem__(self, idx: int | slice) -> float | Vec:
        if isinstance(idx, slice):
            return Vec._wrap(self._data[idx])
        return self._data[idx]

    def __setitem__(self, idx: int | slice, value: float | Vec | Sequence[float]) -> None:
        if isinstance(idx, slice):
            if isinstance(value, Vec):
                self._data[idx] = value._data
            else:
                self._data[idx] = list(value)  # type: ignore[arg-type]  # Sequence[float] is list-compatible (NUM-001)
        else:
            self._data[idx] = float(value)  # type: ignore[arg-type]  # scalar coercion from union (NUM-002)

    def __iter__(self) -> Iterator[float]:
        return iter(self._data)

    def __repr__(self) -> str:
        return f"Vec({self._data!r})"

    # -- arithmetic (element-wise) -------------------------------------------

    def __add__(self, other: object) -> Vec:
        if isinstance(other, Vec):
            if len(self._data) != len(other._data):
                return NotImplemented
            return Vec._wrap([a + b for a, b in zip(self._data, other._data)])
        if isinstance(other, (int, float)):
            return Vec._wrap([a + other for a in self._data])
        return NotImplemented

    def __radd__(self, other: object) -> Vec:
        return self.__add__(other)

    def __iadd__(self, other: object) -> Vec:
        if isinstance(other, Vec):
            if len(self._data) != len(other._data):
                raise ArithmeticError(
                    f"Vec length mismatch in __iadd__: {len(self._data)} vs {len(other._data)}"
                )
            for i in range(len(self._data)):
                self._data[i] += other._data[i]
            return self
        if isinstance(other, (int, float)):
            for i in range(len(self._data)):
                self._data[i] += other
            return self
        return NotImplemented

    def __sub__(self, other: object) -> Vec:
        if isinstance(other, Vec):
            if len(self._data) != len(other._data):
                return NotImplemented
            return Vec._wrap([a - b for a, b in zip(self._data, other._data)])
        if isinstance(other, (int, float)):
            return Vec._wrap([a - other for a in self._data])
        return NotImplemented

    def __rsub__(self, other: object) -> Vec:
        if isinstance(other, (int, float)):
            return Vec._wrap([other - a for a in self._data])
        return NotImplemented

    def __mul__(self, other: object) -> Vec:
        if isinstance(other, Vec):
            if len(self._data) != len(other._data):
                return NotImplemented
            return Vec._wrap([a * b for a, b in zip(self._data, other._data)])
        if isinstance(other, (int, float)):
            return Vec._wrap([a * other for a in self._data])
        return NotImplemented

    def __rmul__(self, other: object) -> Vec:
        return self.__mul__(other)

    def __imul__(self, other: object) -> Vec:
        if isinstance(other, (int, float)):
            for i in range(len(self._data)):
                self._data[i] *= other
            return self
        return NotImplemented

    def __truediv__(self, other: object) -> Vec:
        if isinstance(other, Vec):
            return Vec._wrap([a / b for a, b in zip(self._data, other._data)])
        if isinstance(other, (int, float)):
            return Vec._wrap([a / other for a in self._data])
        return NotImplemented

    def __rtruediv__(self, other: object) -> Vec:
        if isinstance(other, (int, float)):
            return Vec._wrap([other / a for a in self._data])
        return NotImplemented

    def __neg__(self) -> Vec:
        return Vec._wrap([-a for a in self._data])

    def __pow__(self, exp: object) -> Vec:
        if isinstance(exp, (int, float)):
            return Vec._wrap([a**exp for a in self._data])
        return NotImplemented

    def __abs__(self) -> Vec:
        return Vec._wrap([abs(a) for a in self._data])

    # -- matmul (dot product for Vec @ Vec) ----------------------------------

    def __matmul__(self, other: object) -> float:
        if isinstance(other, Vec):
            if len(self._data) != len(other._data):
                raise ArithmeticError(
                    f"Vec length mismatch in __matmul__: "
                    f"{len(self._data)} vs {len(other._data)}"
                )
            return sum(a * b for a, b in zip(self._data, other._data))
        if isinstance(other, Mat):
            # row-vector @ matrix  →  Vec
            # Treat self as (1, n); result is (1, m) flattened to Vec
            n = len(self._data)
            m = other.cols
            out = [0.0] * m
            for j in range(m):
                s = 0.0
                for k in range(n):
                    s += self._data[k] * other._data[k][j]
                out[j] = s
            return Vec._wrap(out)  # type: ignore[return-value]  # Vec @ Mat -> Vec (NUM-003)
        return NotImplemented

    # -- comparison helpers --------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Vec):
            return self._data == other._data
        return NotImplemented

    # -- slicing / reversing -------------------------------------------------

    def __reversed__(self) -> Vec:
        return Vec._wrap(self._data[::-1])

    def copy(self) -> Vec:
        return Vec._wrap(self._data[:])

    def tolist(self) -> List[float]:
        return self._data[:]

    # -- properties ----------------------------------------------------------

    @property
    def shape(self) -> Tuple[int]:
        return (len(self._data),)


# ---------------------------------------------------------------------------
# Mat — 2-D numerical array (row-major list of lists)
# ---------------------------------------------------------------------------


class Mat:
    """2-D array of floats with arithmetic, transpose, and ``@`` (matmul)."""

    __slots__ = ("_data", "cols", "rows")

    def __init__(self, data: Sequence[Sequence[float]]) -> None:
        self._data: List[List[float]] = [[float(x) for x in row] for row in data]
        self.rows = len(self._data)
        self.cols = len(self._data[0]) if self.rows > 0 else 0

    @staticmethod
    def _wrap(data: List[List[float]], rows: int, cols: int) -> Mat:
        m = object.__new__(Mat)
        m._data = data
        m.rows = rows
        m.cols = cols
        return m

    # -- sequence protocol ---------------------------------------------------

    @overload
    def __getitem__(self, idx: Tuple[int, int]) -> float:
        pass

    @overload
    def __getitem__(self, idx: int) -> List[float]:
        pass

    def __getitem__(self, idx: int | Tuple[int, int]) -> float | List[float]:
        if isinstance(idx, tuple):
            r, c = idx
            return self._data[r][c]
        return self._data[idx]

    def __setitem__(self, idx: int | Tuple[int, int], value: float | List[float]) -> None:
        if isinstance(idx, tuple):
            r, c = idx
            self._data[r][c] = float(value)  # type: ignore[arg-type]  # scalar coercion from union (NUM-004)
        else:
            if isinstance(value, list):
                self._data[idx] = [float(x) for x in value]

    def __repr__(self) -> str:
        return f"Mat({self._data!r})"

    # -- shape ---------------------------------------------------------------

    @property
    def shape(self) -> Tuple[int, int]:
        return (self.rows, self.cols)

    # -- transpose -----------------------------------------------------------

    @property
    def T(self) -> Mat:
        t = [[self._data[r][c] for r in range(self.rows)] for c in range(self.cols)]
        return Mat._wrap(t, self.cols, self.rows)

    # -- arithmetic ----------------------------------------------------------

    def __add__(self, other: object) -> Mat:
        if isinstance(other, Mat):
            d = [
                [self._data[r][c] + other._data[r][c] for c in range(self.cols)]
                for r in range(self.rows)
            ]
            return Mat._wrap(d, self.rows, self.cols)
        if isinstance(other, (int, float)):
            d = [[self._data[r][c] + other for c in range(self.cols)] for r in range(self.rows)]
            return Mat._wrap(d, self.rows, self.cols)
        return NotImplemented

    def __radd__(self, other: object) -> Mat:
        return self.__add__(other)

    def __sub__(self, other: object) -> Mat:
        if isinstance(other, Mat):
            d = [
                [self._data[r][c] - other._data[r][c] for c in range(self.cols)]
                for r in range(self.rows)
            ]
            return Mat._wrap(d, self.rows, self.cols)
        if isinstance(other, (int, float)):
            d = [[self._data[r][c] - other for c in range(self.cols)] for r in range(self.rows)]
            return Mat._wrap(d, self.rows, self.cols)
        return NotImplemented

    def __rsub__(self, other: object) -> Mat:
        if isinstance(other, (int, float)):
            d = [[other - self._data[r][c] for c in range(self.cols)] for r in range(self.rows)]
            return Mat._wrap(d, self.rows, self.cols)
        return NotImplemented

    def __mul__(self, other: object) -> Mat:
        if isinstance(other, (int, float)):
            d = [[self._data[r][c] * other for c in range(self.cols)] for r in range(self.rows)]
            return Mat._wrap(d, self.rows, self.cols)
        return NotImplemented

    def __rmul__(self, other: object) -> Mat:
        return self.__mul__(other)

    def __truediv__(self, other: object) -> Mat:
        if isinstance(other, (int, float)):
            d = [[self._data[r][c] / other for c in range(self.cols)] for r in range(self.rows)]
            return Mat._wrap(d, self.rows, self.cols)
        return NotImplemented

    # -- matmul --------------------------------------------------------------

    @overload
    def __matmul__(self, other: Mat) -> Mat:
        pass

    @overload
    def __matmul__(self, other: Vec) -> Vec:
        pass

    def __matmul__(self, other: object) -> Mat | Vec:
        if isinstance(other, Mat):
            # (m×n) @ (n×p) → (m×p)
            d = [
                [
                    sum(self._data[r][k] * other._data[k][c] for k in range(self.cols))
                    for c in range(other.cols)
                ]
                for r in range(self.rows)
            ]
            return Mat._wrap(d, self.rows, other.cols)
        if isinstance(other, Vec):
            # (m×n) @ (n,) → (m,)
            out = [0.0] * self.rows
            for r in range(self.rows):
                s = 0.0
                for c in range(self.cols):
                    s += self._data[r][c] * other._data[c]
                out[r] = s
            return Vec._wrap(out)
        return NotImplemented

    def copy(self) -> Mat:
        return Mat._wrap([row[:] for row in self._data], self.rows, self.cols)


# ---------------------------------------------------------------------------
# Construction functions
# ---------------------------------------------------------------------------


def array(data: Sequence[float] | Sequence[Sequence[float]]) -> Vec | Mat:
    """Create a Vec (1-D) or Mat (2-D) from nested sequences."""
    if not data:
        return Vec._wrap([])
    first = data[0]
    if isinstance(first, (list, tuple)):
        return Mat(data)  # type: ignore[arg-type]  # nested sequence is Mat-compatible (NUM-006)
    return Vec(data)  # type: ignore[arg-type]  # flat sequence is Vec-compatible (NUM-007)


def zeros(n: int) -> Vec:
    return Vec._wrap([0.0] * n)


def ones(n: int) -> Vec:
    return Vec._wrap([1.0] * n)


def zeros_like(v: Vec) -> Vec:
    return Vec._wrap([0.0] * len(v))


def ones_like(v: Vec) -> Vec:
    return Vec._wrap([1.0] * len(v))


def eye(n: int) -> Mat:
    d = [[1.0 if r == c else 0.0 for c in range(n)] for r in range(n)]
    return Mat._wrap(d, n, n)


def diag(values: Vec | List[float] | Sequence[float]) -> Mat:
    if isinstance(values, Vec):
        vals = values._data
    else:
        vals = list(values)
    n = len(vals)
    d = [[vals[r] if r == c else 0.0 for c in range(n)] for r in range(n)]
    return Mat._wrap(d, n, n)


def linspace(start: float, stop: float, n: int) -> Vec:
    if n <= 1:
        return Vec._wrap([start])
    step = (stop - start) / (n - 1)
    return Vec._wrap([start + i * step for i in range(n)])


def concatenate(parts: Sequence[Vec]) -> Vec:
    out: List[float] = []
    for p in parts:
        out.extend(p._data)
    return Vec._wrap(out)


def clip(v: Vec, lo: float, hi: float) -> Vec:
    return Vec._wrap([max(lo, min(hi, x)) for x in v._data])


def fill_diagonal(m: Mat, val: float) -> None:
    n = min(m.rows, m.cols)
    for i in range(n):
        m._data[i][i] = val


def maximum(a: float, v: Vec) -> Vec:
    """Element-wise max(a, v[i])."""
    return Vec._wrap([max(a, x) for x in v._data])


def allclose(a: Vec, b: Vec, atol: float = 1e-8) -> bool:
    if len(a) != len(b):
        return False
    return all(abs(x - y) <= atol for x, y in zip(a._data, b._data))


def real(v: Vec) -> Vec:
    """Return real parts (identity for real Vecs; handles complex leftovers from FFT)."""
    return Vec._wrap([x.real if isinstance(x, complex) else x for x in v._data])


# ---------------------------------------------------------------------------
# Element-wise math  (operate on Vec, return Vec)
# ---------------------------------------------------------------------------


@overload
def sqrt(x: Vec) -> Vec:
    pass


@overload
def sqrt(x: float) -> float:
    pass


def sqrt(x: Vec | float) -> Vec | float:
    if isinstance(x, Vec):
        return Vec._wrap([math.sqrt(v) for v in x._data])
    return math.sqrt(x)


@overload
def log(x: Vec) -> Vec:
    pass


@overload
def log(x: float) -> float:
    pass


def log(x: Vec | float) -> Vec | float:
    if isinstance(x, Vec):
        return Vec._wrap([math.log(max(v, 1e-300)) for v in x._data])
    return math.log(max(x, 1e-300))


@overload
def exp(x: Vec) -> Vec:
    pass


@overload
def exp(x: float) -> float:
    pass


def exp(x: Vec | float) -> Vec | float:
    if isinstance(x, Vec):
        return Vec._wrap([math.exp(v) for v in x._data])
    return math.exp(x)


@overload
def sin(x: Vec) -> Vec:
    pass


@overload
def sin(x: float) -> float:
    pass


def sin(x: Vec | float) -> Vec | float:
    if isinstance(x, Vec):
        return Vec._wrap([math.sin(v) for v in x._data])
    return math.sin(x)


@overload
def cos(x: Vec) -> Vec:
    pass


@overload
def cos(x: float) -> float:
    pass


def cos(x: Vec | float) -> Vec | float:
    if isinstance(x, Vec):
        return Vec._wrap([math.cos(v) for v in x._data])
    return math.cos(x)


def abs_(x: Vec) -> Vec:
    return Vec._wrap([abs(v) for v in x._data])


def sign(x: Vec) -> Vec:
    return Vec._wrap([(1.0 if v > 0 else (-1.0 if v < 0 else 0.0)) for v in x._data])


def sum_(x: Vec) -> float:
    return math.fsum(x._data)


def mean(x: Vec) -> float:
    return math.fsum(x._data) / len(x._data)


def max_(x: Vec) -> float:
    return max(x._data)


def min_(x: Vec) -> float:
    return min(x._data)


# ---------------------------------------------------------------------------
# Linear algebra
# ---------------------------------------------------------------------------


def dot(a: Vec, b: Vec) -> float:
    a_data: List[float] = a._data if hasattr(a, "_data") else list(a)
    b_data: List[float] = b._data if hasattr(b, "_data") else list(b)
    if len(a_data) != len(b_data):
        raise ValueError(f"Vec length mismatch in dot(): {len(a_data)} vs {len(b_data)}")
    return sum(x * y for x, y in zip(a_data, b_data))


def norm(v: Vec) -> float:
    data: List[float] = v._data if hasattr(v, "_data") else list(v)
    return math.sqrt(sum(x * x for x in data))


def eigvals(m: Mat) -> List[float]:
    """
    Compute eigenvalues of a real symmetric matrix via QR iteration.

    Uses the implicit-shift QR algorithm on a Hessenberg (tridiagonal for
    symmetric) matrix.  Sufficient for the moderate-dimension ethical
    matrices used in this library (typically ≤ 250×250).
    """
    n = m.rows
    if n == 0:
        return []
    if n == 1:
        return [m._data[0][0]]

    # Work on a copy
    A = [row[:] for row in m._data]

    # Reduce to tridiagonal via Householder reflections (for symmetric matrices)
    A = _tridiagonalize(A, n)

    # QR iteration on the tridiagonal matrix
    return _qr_tridiagonal_eigvals(A, n)


def _tridiagonalize(A: List[List[float]], n: int) -> List[List[float]]:
    """Householder reduction to tridiagonal form for a symmetric matrix."""
    for k in range(n - 2):
        # Compute Householder vector for column k, rows k+1..n-1
        x = [A[i][k] for i in range(k + 1, n)]
        alpha = math.sqrt(sum(v * v for v in x))
        if alpha < 1e-300:
            continue
        if x[0] >= 0:
            alpha = -alpha
        x[0] -= alpha
        x_norm = math.sqrt(sum(v * v for v in x))
        if x_norm < 1e-300:
            continue
        for i in range(len(x)):
            x[i] /= x_norm

        # Apply P = I - 2*v*v^T from left and right
        # PA: for each column j, update rows k+1..n-1
        m = n - k - 1
        for j in range(n):
            dot_val = sum(x[i] * A[k + 1 + i][j] for i in range(m))
            for i in range(m):
                A[k + 1 + i][j] -= 2.0 * x[i] * dot_val

        # AP^T: for each row i, update cols k+1..n-1
        for i in range(n):
            dot_val = sum(x[j] * A[i][k + 1 + j] for j in range(m))
            for j in range(m):
                A[i][k + 1 + j] -= 2.0 * x[j] * dot_val

    return A


def _qr_tridiagonal_eigvals(A: List[List[float]], n: int, max_iter: int = 30) -> List[float]:
    """
    Eigenvalues of a symmetric tridiagonal matrix via the QL algorithm
    with implicit Wilkinson shifts (Numerical Recipes tqli).
    """
    # Extract diagonal and sub-diagonal
    d = [A[i][i] for i in range(n)]
    e = [A[i + 1][i] for i in range(n - 1)]
    e.append(0.0)

    for lam in range(n):  # QL algorithm loop variable (lambda index)
        itr = 0
        while True:
            # Find small sub-diagonal element
            m = lam
            while m < n - 1:
                dd = abs(d[m]) + abs(d[m + 1])
                if abs(e[m]) <= 1e-15 * dd:
                    break
                m += 1
            if m == lam:
                break
            if itr >= max_iter:
                break
            itr += 1

            # Wilkinson shift: eigenvalue of trailing 2x2 closer to d[lam]
            g = (d[lam + 1] - d[lam]) / (2.0 * e[lam])
            r = math.hypot(g, 1.0)
            if g >= 0:
                g = d[m] - d[lam] + e[lam] / (g + r)
            else:
                g = d[m] - d[lam] + e[lam] / (g - r)

            s = 1.0
            c = 1.0
            p = 0.0

            for i in range(m - 1, lam - 1, -1):
                f = s * e[i]
                b = c * e[i]
                r = math.hypot(f, g)
                e[i + 1] = r
                if r < 1e-300:
                    # Recover from underflow
                    d[i + 1] -= p
                    e[m] = 0.0
                    break
                s = f / r
                c = g / r
                g = d[i + 1] - p
                r = (d[i] - g) * s + 2.0 * c * b
                p = s * r
                d[i + 1] = g + p
                g = c * r - b
            else:
                # Loop completed without break
                d[lam] -= p
                e[lam] = g
                e[m] = 0.0

    return d


# ---------------------------------------------------------------------------
# FFT / IFFT  (Cooley–Tukey radix-2, arbitrary length via Bluestein)
# ---------------------------------------------------------------------------


def _next_pow2(n: int) -> int:
    p = 1
    while p < n:
        p <<= 1
    return p


def _fft_radix2(x: List[complex], inverse: bool = False) -> List[complex]:
    """In-place iterative radix-2 FFT.  len(x) must be a power of 2."""
    n = len(x)
    # Bit-reversal permutation
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            x[i], x[j] = x[j], x[i]

    # Cooley-Tukey butterflies
    length = 2
    while length <= n:
        angle = 2 * math.pi / length * (-1 if inverse else 1)
        wlen = cmath.exp(1j * angle)
        i = 0
        while i < n:
            w = 1 + 0j
            for k in range(length // 2):
                u = x[i + k]
                v = w * x[i + k + length // 2]
                x[i + k] = u + v
                x[i + k + length // 2] = u - v
                w *= wlen
            i += length
        length <<= 1

    if inverse:
        for i in range(n):
            x[i] /= n
    return x


def _bluestein_fft(x: List[complex], n: int, inverse: bool) -> List[complex]:
    """Bluestein's algorithm: DFT of arbitrary length via convolution."""
    sign = 1.0 if inverse else -1.0
    # Chirp: w[k] = exp(sign * j * pi * k^2 / n)
    chirp = [cmath.exp(1j * sign * math.pi * k * k / n) for k in range(n)]
    chirp_conj = [c.conjugate() for c in chirp]

    # Pad to convolution length (power of 2 >= 2n-1)
    m = _next_pow2(2 * n - 1)

    # a[k] = x[k] * chirp_conj[k]
    a: List[complex] = [x[k] * chirp_conj[k] if k < n else 0j for k in range(m)]
    # b[k] = chirp[k] for k < n, chirp[m-k] for k > m-n, else 0
    b: List[complex] = [0j] * m
    for k in range(n):
        b[k] = chirp[k]
    for k in range(1, n):
        b[m - k] = chirp[k]

    # Convolve via FFT
    fa = _fft_radix2(a, inverse=False)
    fb = _fft_radix2(b, inverse=False)
    fc = [fa[i] * fb[i] for i in range(m)]
    c = _fft_radix2(fc, inverse=True)

    result = [chirp_conj[k] * c[k] for k in range(n)]
    if inverse:
        result = [v / n for v in result]
    return result


def fft(v: Vec) -> Vec:
    """Compute the DFT of a real-valued Vec.  Returns complex values stored as Vec."""
    n = len(v)
    if n == 0:
        return Vec._wrap([])

    x: List[complex] = [complex(v._data[i]) for i in range(n)]

    if n & (n - 1) == 0:  # power of 2
        result = _fft_radix2(x, inverse=False)
    else:
        result = _bluestein_fft(x, n, inverse=False)

    out = Vec.__new__(Vec)
    out._data = result  # type: ignore[assignment]  # complex list stored in Vec for FFT output (NUM-009)
    return out


def ifft(v: Vec) -> Vec:
    """Compute the inverse DFT.  Input may contain complex values from fft()."""
    n = len(v)
    if n == 0:
        return Vec._wrap([])

    x: List[complex] = [
        v._data[i] if isinstance(v._data[i], complex) else complex(v._data[i]) for i in range(n)
    ]

    if n & (n - 1) == 0:  # power of 2
        result = _fft_radix2(x, inverse=True)
    else:
        result = _bluestein_fft(x, n, inverse=True)

    out = Vec.__new__(Vec)
    out._data = result  # type: ignore[assignment]  # complex list stored in Vec for IFFT output (NUM-010)
    return out


# ---------------------------------------------------------------------------
# Seeded PRNG  (wraps stdlib random for reproducibility)
# ---------------------------------------------------------------------------


class _Random:
    """Numpy-compatible random interface backed by stdlib random."""

    def __init__(self) -> None:
        self._rng = _stdlib_random.Random()  # fmt: skip  # nosec B311 — non-crypto PRNG for math engine only

    def seed(self, s: int) -> None:
        self._rng.seed(s)

    @overload
    def randn(self) -> float:
        pass

    @overload
    def randn(self, __n: int) -> Vec:
        pass

    @overload
    def randn(self, __n: int, __m: int) -> Mat:
        pass

    def randn(self, *shape: int) -> Vec | Mat | float:
        """Standard-normal samples (Box–Muller)."""
        if len(shape) == 0:
            return self._box_muller_single()
        if len(shape) == 1:
            return Vec._wrap([self._box_muller_single() for _ in range(shape[0])])
        if len(shape) == 2:
            rows, cols = shape
            d = [[self._box_muller_single() for _ in range(cols)] for _ in range(rows)]
            return Mat._wrap(d, rows, cols)
        raise ValueError(f"randn supports up to 2-D, got {len(shape)}-D")

    def binomial(self, n: int, p: float, size: int) -> Vec:
        """Binomial samples."""
        p = max(0.0, min(1.0, p))
        return Vec._wrap(
            [float(sum(1 for _ in range(n) if self._rng.random() < p)) for _ in range(size)]
        )

    @overload
    def uniform(self, lo: float = ..., hi: float = ..., size: None = ...) -> float:
        pass

    @overload
    def uniform(self, lo: float, hi: float, size: int) -> Vec:
        pass

    def uniform(self, lo: float = 0.0, hi: float = 1.0, size: int | None = None) -> float | Vec:
        if size is None:
            return self._rng.uniform(lo, hi)
        return Vec._wrap([self._rng.uniform(lo, hi) for _ in range(size)])

    @overload
    def rand(self) -> float:
        pass

    @overload
    def rand(self, __n: int) -> Vec:
        pass

    @overload
    def rand(self, __n: int, __m: int) -> Mat:
        pass

    def rand(self, *shape: int) -> Vec | Mat | float:
        """Uniform [0, 1) samples."""
        if len(shape) == 0:
            return self._rng.random()
        if len(shape) == 1:
            return Vec._wrap([self._rng.random() for _ in range(shape[0])])
        if len(shape) == 2:
            rows, cols = shape
            d = [[self._rng.random() for _ in range(cols)] for _ in range(rows)]
            return Mat._wrap(d, rows, cols)
        raise ValueError(f"rand supports up to 2-D, got {len(shape)}-D")

    # -- internal ------------------------------------------------------------

    def _box_muller_single(self) -> float:
        u1 = self._rng.random()
        u2 = self._rng.random()
        while u1 < 1e-300:
            u1 = self._rng.random()
        return math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)


random = _Random()
