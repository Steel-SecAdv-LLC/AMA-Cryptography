# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
# cython: initializedcheck=False
# cython: embedsignature=True

"""
AMA Cryptography High-Performance Mathematical Engine (Cython)
=============================================================

Optimized mathematical operations for cryptographic primitives.
Targets 10-50x speedup over pure Python through:
- C-level array operations
- Elimination of Python overhead
- Memory-efficient algorithms
- SIMD-friendly data layouts
"""

import numpy as np

cimport numpy as cnp
from libc.math cimport cos, exp, fabs, log, sin, sqrt
from libc.stdint cimport int64_t, uint8_t, uint16_t, uint32_t, uint64_t

cimport cython

# Initialize NumPy C API
cnp.import_array()

# Golden ratio constant
cdef double PHI = 1.618033988749895
cdef double PHI_SQUARED = 2.618033988749895
cdef double PHI_CUBED = 4.236067977499790

# ============================================================================
# POLYNOMIAL ARITHMETIC (for lattice-based cryptography)
# ============================================================================

@cython.boundscheck(False)
@cython.wraparound(False)
cdef void polynomial_add(
    int64_t* result,
    const int64_t* a,
    const int64_t* b,
    size_t degree
) nogil:
    """
    Polynomial addition: result = a + b (mod q)

    All operations in-place for cache efficiency.
    """
    cdef size_t i
    for i in range(degree):
        result[i] = a[i] + b[i]


@cython.boundscheck(False)
@cython.wraparound(False)
cdef void polynomial_sub(
    int64_t* result,
    const int64_t* a,
    const int64_t* b,
    size_t degree
) nogil:
    """
    Polynomial subtraction: result = a - b (mod q)
    """
    cdef size_t i
    for i in range(degree):
        result[i] = a[i] - b[i]


@cython.boundscheck(False)
@cython.wraparound(False)
cdef void polynomial_mul_schoolbook(
    int64_t* result,
    const int64_t* a,
    const int64_t* b,
    size_t degree,
    int64_t modulus
) nogil:
    """
    Schoolbook polynomial multiplication: result = a * b (mod x^n + 1, mod q)

    O(n²) complexity - suitable for small degrees.
    For large degrees, use NTT-based multiplication.
    """
    cdef size_t i, j, k
    cdef int64_t tmp

    # Initialize result
    for i in range(2 * degree):
        result[i] = 0

    # Schoolbook multiplication
    for i in range(degree):
        for j in range(degree):
            k = i + j
            if k < degree:
                result[k] += a[i] * b[j]
            else:
                # Reduction by x^n + 1
                result[k - degree] -= a[i] * b[j]

    # Modular reduction
    for i in range(degree):
        result[i] %= modulus


# ============================================================================
# NUMBER THEORETIC TRANSFORM (NTT) - Fast polynomial multiplication
# ============================================================================

@cython.boundscheck(False)
@cython.wraparound(False)
cdef int64_t mod_pow(int64_t base, int64_t exp, int64_t modulus) nogil:
    """
    Modular exponentiation: base^exp mod modulus

    Uses binary exponentiation for O(log exp) complexity.
    """
    cdef int64_t result = 1
    base %= modulus

    while exp > 0:
        if exp & 1:
            result = (result * base) % modulus
        exp >>= 1
        base = (base * base) % modulus

    return result


@cython.boundscheck(False)
@cython.wraparound(False)
cdef void ntt_forward(
    int64_t* coeffs,
    size_t n,
    int64_t modulus,
    int64_t root
) nogil:
    """
    Forward Number Theoretic Transform

    Converts polynomial from coefficient to evaluation representation.
    O(n log n) complexity using Cooley-Tukey FFT algorithm.

    Args:
        coeffs: Polynomial coefficients (modified in-place)
        n: Degree (must be power of 2)
        modulus: Prime modulus
        root: Primitive n-th root of unity mod modulus
    """
    cdef size_t i, j, k, m, step
    cdef int64_t t, w, wm

    # Bit-reversal permutation
    j = 0
    for i in range(1, n):
        k = n >> 1
        while j >= k:
            j -= k
            k >>= 1
        j += k
        if i < j:
            t = coeffs[i]
            coeffs[i] = coeffs[j]
            coeffs[j] = t

    # Cooley-Tukey butterfly
    step = 1
    while step < n:
        wm = mod_pow(root, (modulus - 1) // (2 * step), modulus)
        m = 0
        while m < n:
            w = 1
            for j in range(step):
                t = (w * coeffs[m + j + step]) % modulus
                coeffs[m + j + step] = (coeffs[m + j] - t + modulus) % modulus
                coeffs[m + j] = (coeffs[m + j] + t) % modulus
                w = (w * wm) % modulus
            m += 2 * step
        step <<= 1


@cython.boundscheck(False)
@cython.wraparound(False)
cdef void ntt_inverse(
    int64_t* coeffs,
    size_t n,
    int64_t modulus,
    int64_t root
) nogil:
    """
    Inverse Number Theoretic Transform

    Converts from evaluation back to coefficient representation.
    """
    cdef int64_t root_inv = mod_pow(root, modulus - 2, modulus)
    cdef int64_t n_inv = mod_pow(n, modulus - 2, modulus)
    cdef size_t i

    # Forward NTT with inverse root
    ntt_forward(coeffs, n, modulus, root_inv)

    # Scale by 1/n
    for i in range(n):
        coeffs[i] = (coeffs[i] * n_inv) % modulus


# ============================================================================
# MATRIX OPERATIONS (for ML-DSA)
# ============================================================================

@cython.boundscheck(False)
@cython.wraparound(False)
def matrix_vector_multiply(
    cnp.ndarray[cnp.float64_t, ndim=2] matrix,
    cnp.ndarray[cnp.float64_t, ndim=1] vector
):
    """
    Optimized matrix-vector multiplication: result = matrix @ vector

    Args:
        matrix: 2D array of shape (m, n)
        vector: 1D array of shape (n,)

    Returns:
        1D array of shape (m,)
    """
    cdef size_t m = matrix.shape[0]
    cdef size_t n = matrix.shape[1]
    cdef cnp.ndarray[cnp.float64_t, ndim=1] result = np.zeros(m, dtype=np.float64)
    cdef size_t i, j
    cdef double sum_val

    # The inner loops run with bounds checking disabled for speed, so a shape
    # mismatch here is an out-of-bounds read of `vector`, not a clean error:
    # it silently returns adjacent heap memory or crashes the process.  Reject
    # it at the boundary, exactly as token_family_counts validates its inputs.
    if <size_t>vector.shape[0] != n:
        raise ValueError(
            "vector length must equal matrix.shape[1] "
            f"({vector.shape[0]} != {n})"
        )

    for i in range(m):
        sum_val = 0.0
        for j in range(n):
            sum_val += matrix[i, j] * vector[j]
        result[i] = sum_val

    return result


@cython.boundscheck(False)
@cython.wraparound(False)
def matrix_multiply(
    cnp.ndarray[cnp.float64_t, ndim=2] A,
    cnp.ndarray[cnp.float64_t, ndim=2] B
):
    """
    Optimized matrix multiplication: C = A @ B

    Uses cache-friendly access pattern.
    """
    cdef size_t m = A.shape[0]
    cdef size_t n = A.shape[1]
    cdef size_t p = B.shape[1]
    cdef cnp.ndarray[cnp.float64_t, ndim=2] C = np.zeros((m, p), dtype=np.float64)
    cdef size_t i, j, k
    cdef double sum_val

    # Inner loops run unchecked; a row-count mismatch would read past B.
    if <size_t>B.shape[0] != n:
        raise ValueError(
            "A.shape[1] must equal B.shape[0] "
            f"({n} != {B.shape[0]})"
        )

    for i in range(m):
        for j in range(p):
            sum_val = 0.0
            for k in range(n):
                sum_val += A[i, k] * B[k, j]
            C[i, j] = sum_val

    return C


# ============================================================================
# LYAPUNOV FUNCTION (optimized)
# ============================================================================

@cython.boundscheck(False)
@cython.wraparound(False)
def lyapunov_function_fast(
    cnp.ndarray[cnp.float64_t, ndim=1] state,
    cnp.ndarray[cnp.float64_t, ndim=1] target
):
    """
    Fast Lyapunov function: V(x) = ||x - x*||²

    10-20x faster than pure Python implementation.
    """
    cdef size_t n = state.shape[0]
    cdef double result = 0.0
    cdef double diff
    cdef size_t i

    # Unchecked loop below; a length mismatch reads past `target`.
    if <size_t>target.shape[0] != n:
        raise ValueError(
            "state and target must be the same length "
            f"({n} != {target.shape[0]})"
        )

    for i in range(n):
        diff = state[i] - target[i]
        result += diff * diff

    return result


# ============================================================================
# HELIX OPERATIONS (optimized)
# ============================================================================

@cython.boundscheck(False)
@cython.wraparound(False)
def helix_evolution_step(
    cnp.ndarray[cnp.float64_t, ndim=1] state,
    cnp.ndarray[cnp.float64_t, ndim=1] target,
    cnp.ndarray[cnp.float64_t, ndim=2] ethical_matrix,
    double beta,
    double gamma,
    double delta
):
    """
    Optimized helix evolution step

    Combines multiple terms efficiently in a single pass.
    """
    cdef size_t n = state.shape[0]
    cdef cnp.ndarray[cnp.float64_t, ndim=1] result = np.copy(state)
    cdef cnp.ndarray[cnp.float64_t, ndim=1] direction = np.zeros(n, dtype=np.float64)
    cdef double norm = 0.0
    cdef size_t i, j
    cdef double diff, ethical_grad

    # Unchecked loops below read target[i] and ethical_matrix[i, j] for
    # i, j in [0, n); a shorter target or a non-(n, n) matrix is an
    # out-of-bounds read.  Validate the contract at the boundary.
    if <size_t>target.shape[0] != n:
        raise ValueError(
            "state and target must be the same length "
            f"({n} != {target.shape[0]})"
        )
    if <size_t>ethical_matrix.shape[0] != n or <size_t>ethical_matrix.shape[1] != n:
        raise ValueError(
            "ethical_matrix must be square with dimension len(state) "
            f"(({ethical_matrix.shape[0]}, {ethical_matrix.shape[1]}) != ({n}, {n}))"
        )

    # Compute direction toward target
    for i in range(n):
        diff = target[i] - state[i]
        direction[i] = diff
        norm += diff * diff

    if norm > 0:
        norm = sqrt(norm)
        for i in range(n):
            direction[i] /= norm

    # Apply updates
    for i in range(n):
        # Quantum noise
        result[i] += beta * (np.random.randn() if i % 2 == 0 else 0.0)

        # Perturbation
        result[i] += gamma * np.random.randn()

        # Drift
        result[i] += delta * direction[i]

        # Ethical gradient
        ethical_grad = 0.0
        for j in range(n):
            ethical_grad += ethical_matrix[i, j] * state[j]
        result[i] += 0.1 * ethical_grad

    return result


# ============================================================================
# GOLDEN RATIO UTILITIES
# ============================================================================

@cython.boundscheck(False)
@cython.wraparound(False)
def fibonacci_fast(int n):
    """
    Fast Fibonacci sequence generation using Binet's formula and iteration.
    """
    cdef cnp.ndarray[cnp.int64_t, ndim=1] fib = np.zeros(n, dtype=np.int64)
    cdef int i

    if n <= 0:
        return fib

    fib[0] = 0
    if n > 1:
        fib[1] = 1

    for i in range(2, n):
        fib[i] = fib[i-1] + fib[i-2]

    return fib


def phi_amplification(double value, int power=3):
    """
    Apply φ^power amplification to a value.

    Args:
        value: Input value
        power: Power of φ to apply (default: 3 for φ³)

    Returns:
        Amplified value
    """
    if power == 1:
        return value * PHI
    elif power == 2:
        return value * PHI_SQUARED
    elif power == 3:
        return value * PHI_CUBED
    else:
        return value * (PHI ** power)


# ============================================================================
# PERFORMANCE BENCHMARKING
# ============================================================================

def benchmark_matrix_operations(int size=1000, int iterations=100):
    """
    Benchmark Cython matrix operations vs NumPy.

    Returns:
        Dictionary with timing results
    """
    import time

    matrix = np.random.randn(size, size)
    vector = np.random.randn(size)

    # Cython version
    start = time.perf_counter()
    for _ in range(iterations):
        result_cython = matrix_vector_multiply(matrix, vector)
    cython_time = time.perf_counter() - start

    # NumPy version
    start = time.perf_counter()
    for _ in range(iterations):
        result_numpy = matrix @ vector
    numpy_time = time.perf_counter() - start

    return {
        'cython_time': cython_time,
        'numpy_time': numpy_time,
        'speedup': numpy_time / cython_time,
        'size': size,
        'iterations': iterations
    }


# ============================================================================
# 3R AGENTIC-ABUSE DETECTOR KERNELS
# ============================================================================
#
# Two numeric kernels backing the detectors in ama_cryptography.monitoring.
# Both have exact pure-Python fallbacks in that module (see
# _volume_spike_scores_py / _token_family_counts_py).  token_family_counts is
# pure integer work and the tests pin it EXACTLY; volume_spike_scores is an
# EWMA recursion, so on FMA targets (ARM) the per-step rounding differs from
# Python's and accumulates over the series — the tests pin it to a small
# relative tolerance (1e-9), bit-for-bit only where the target has no FMA
# contraction.  Either way the Cython extension is an optimisation and never a
# correctness dependency.
#
# Neither kernel touches key material.  They run on operation *counts* and on
# payloads the caller has explicitly handed to the monitor, so there is no
# constant-time obligation here and none is claimed.


@cython.boundscheck(False)
@cython.wraparound(False)
def volume_spike_scores(counts, double alpha, int warmup):
    """
    EWMA residual scores over a per-bucket operation-count series.

    Counts of independent events are Poisson-ish, and a Gaussian z-score on
    raw counts misbehaves at low rates: the variance moves with the mean, so a
    quiet baseline produces a near-zero sigma and every mild uptick reads as a
    huge deviation.  That is precisely the false-positive mode a burst
    detector must not have.

    We therefore work in the Anscombe variance-stabilising transform

        a(c) = 2 * sqrt(c + 3/8)

    under which a Poisson(lambda) count is approximately Normal with unit
    variance and mean 2*sqrt(lambda), independent of lambda.  The score of
    bucket i is then simply

        (a(c_i) - m_i) / sigma_i

    where m_i is the EWMA of a() over the *preceding* buckets and sigma_i is
    max(1, sqrt(EWMA of squared residual)).  The floor of 1 is the Poisson
    value: real traffic is overdispersed relative to Poisson, so sigma may
    rise above it, but never below — which keeps the detector from becoming
    hair-triggered on unusually regular workloads.

    Each bucket is scored against the baseline as it stood BEFORE that bucket,
    so a burst cannot inflate the baseline it is being judged against.

    Args:
        counts:  sequence of per-bucket counts (non-negative)
        alpha:   EWMA smoothing factor in (0, 1]
        warmup:  number of leading buckets used for baseline only; their
                 scores are reported as 0.0

    Returns:
        list of float scores, one per input bucket
    """
    cdef Py_ssize_t n = len(counts)
    cdef Py_ssize_t i
    cdef double a, resid, sigma, var_est
    cdef double mean_est = 0.0
    cdef double sq_est = 1.0
    cdef list out = [0.0] * n

    if alpha <= 0.0 or alpha > 1.0:
        raise ValueError("alpha must be in (0, 1]")
    if n == 0:
        return out

    for i in range(n):
        a = 2.0 * sqrt(<double>counts[i] + 0.375)
        if i == 0:
            mean_est = a
            sq_est = 1.0
            out[i] = 0.0
            continue

        resid = a - mean_est
        var_est = sq_est
        sigma = sqrt(var_est)
        if sigma < 1.0:
            sigma = 1.0

        if i >= warmup:
            out[i] = resid / sigma
        else:
            out[i] = 0.0

        # Update the baseline AFTER scoring, from this bucket.
        mean_est = mean_est + alpha * resid
        sq_est = (1.0 - alpha) * sq_est + alpha * resid * resid

    return out


@cython.boundscheck(False)
@cython.wraparound(False)
def token_family_counts(const unsigned char[::1] data,
                        const uint64_t[::1] uni_hashes,
                        const uint8_t[::1] uni_families,
                        const uint64_t[::1] bi_hashes,
                        const uint8_t[::1] bi_families,
                        int num_families,
                        int max_token_len):
    """
    Single-pass tokenising scan for note-like artefacts.

    Splits `data` on non-alphanumeric bytes, lowercases ASCII in flight, and
    FNV-1a-64 hashes each token.  Every token is looked up in a sorted unigram
    table, and every adjacent token PAIR in a sorted bigram table, by binary
    search.  One pass, no allocation per token, no regular expressions.

    The bigram table is what makes the caller's successor family usable: the
    words that signal "this is addressed to a later instance of me" are all
    individually ordinary English ("next", "future", "instance"), and scoring
    them as unigrams flags a large fraction of ordinary documentation.  The
    adjacent pair is the discriminative feature.

    Bigram hashes are derived from the two token hashes as

        h_bigram = (h_prev * FNV_PRIME) XOR h_current

    so no second pass over the token bytes is needed.  The Python twin in
    ama_cryptography.monitoring computes the identical mix.

    Reports per family both the total occurrence count and the number of
    DISTINCT markers matched.  The distinct count is what the detector scores
    on: repeating one word fifty times says much less about a payload than
    matching five different markers once each.

    Also returns the count of printable-ASCII bytes: signatures, keys and
    ciphertext are high-entropy binary, so a low printable ratio is the cheap
    structural reject that keeps this detector off the hot path's back.

    Args:
        data:          bytes to scan
        uni_hashes:    FNV-1a-64 hashes of single-token markers, SORTED ascending
        uni_families:  family id per entry of uni_hashes (parallel array)
        bi_hashes:     mixed hashes of two-token markers, SORTED ascending
        bi_families:   family id per entry of bi_hashes (parallel array)
        num_families:  number of families (ids are 0..num_families-1)
        max_token_len: tokens longer than this are skipped, not truncated

    Returns:
        (per-family occurrences, per-family distinct markers, printable bytes,
         token count)
    """
    cdef Py_ssize_t n = data.shape[0]
    cdef Py_ssize_t mu = uni_hashes.shape[0]
    cdef Py_ssize_t mb = bi_hashes.shape[0]
    cdef Py_ssize_t i, lo, hi, mid
    cdef unsigned char c
    cdef uint64_t h = 0
    cdef uint64_t prev_h = 0
    cdef uint64_t target
    cdef int have_prev = 0
    cdef int tok_len = 0
    cdef int printable = 0
    cdef int tokens = 0
    cdef int in_token = 0
    cdef int usable
    cdef list families = [0] * num_families
    cdef list distinct = [0] * num_families
    cdef bytearray seen_uni_buf
    cdef bytearray seen_bi_buf
    cdef unsigned char[::1] seen_uni
    cdef unsigned char[::1] seen_bi

    if uni_families.shape[0] != mu:
        raise ValueError("uni_hashes and uni_families must be the same length")
    if bi_families.shape[0] != mb:
        raise ValueError("bi_hashes and bi_families must be the same length")
    if num_families <= 0:
        raise ValueError("num_families must be positive")

    seen_uni_buf = bytearray(mu if mu > 0 else 1)
    seen_bi_buf = bytearray(mb if mb > 0 else 1)
    seen_uni = seen_uni_buf
    seen_bi = seen_bi_buf

    i = 0
    while i <= n:
        if i < n:
            c = data[i]
            # Printable ASCII plus the three whitespace bytes that appear in
            # real prose.  Everything else counts against the text ratio.
            if (c >= 0x20 and c < 0x7F) or c == 0x09 or c == 0x0A or c == 0x0D:
                printable += 1
            if c >= 0x41 and c <= 0x5A:
                c = c + 32          # ASCII fold to lowercase
            if (c >= 0x61 and c <= 0x7A) or (c >= 0x30 and c <= 0x39):
                if in_token == 0:
                    in_token = 1
                    h = 14695981039346656037UL   # FNV-1a-64 offset basis
                    tok_len = 0
                h = (h ^ <uint64_t>c) * 1099511628211UL
                tok_len += 1
                i += 1
                continue

        # Token boundary (or end of input).
        if in_token != 0:
            in_token = 0
            tokens += 1
            # An over-long token (base64 blob, hex digest) is not a word; it
            # also breaks the bigram chain so it cannot bridge two real words
            # that were never adjacent.
            usable = 1 if tok_len <= max_token_len else 0

            if usable != 0 and mu > 0:
                target = h
                lo = 0
                hi = mu - 1
                while lo <= hi:
                    mid = (lo + hi) >> 1
                    if uni_hashes[mid] < target:
                        lo = mid + 1
                    elif uni_hashes[mid] > target:
                        hi = mid - 1
                    else:
                        families[<int>uni_families[mid]] += 1
                        if seen_uni[mid] == 0:
                            seen_uni[mid] = 1
                            distinct[<int>uni_families[mid]] += 1
                        break

            if usable != 0 and have_prev != 0 and mb > 0:
                target = (prev_h * 1099511628211UL) ^ h
                lo = 0
                hi = mb - 1
                while lo <= hi:
                    mid = (lo + hi) >> 1
                    if bi_hashes[mid] < target:
                        lo = mid + 1
                    elif bi_hashes[mid] > target:
                        hi = mid - 1
                    else:
                        families[<int>bi_families[mid]] += 1
                        if seen_bi[mid] == 0:
                            seen_bi[mid] = 1
                            distinct[<int>bi_families[mid]] += 1
                        break

            if usable != 0:
                prev_h = h
                have_prev = 1
            else:
                have_prev = 0
        i += 1

    return families, distinct, printable, tokens
