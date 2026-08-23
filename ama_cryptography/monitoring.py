#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography: 3R Runtime Anomaly Monitoring System
==========================================================

3R Mechanism: Resonance-Recursion-Refactoring for runtime anomaly monitoring.

The 3R Mechanism is a novel runtime anomaly monitoring framework developed for
AMA Cryptography by Steel Security Advisors LLC. It provides three complementary
approaches to runtime security analysis without compromising cryptographic
integrity or performance.

Key Features:
- High-resolution timing using time.perf_counter_ns() (cross-platform)
- Per-operation baseline statistics (separate stats for each crypto operation)
- EWMA (Exponentially Weighted Moving Average) for robust anomaly detection
- MAD (Median Absolute Deviation) for outlier-resistant statistics
- Sliding window analysis with configurable retention

Note: This is a runtime ANOMALY MONITORING system, not a timing attack
detection/prevention system. It surfaces statistical anomalies for
security review - it does not guarantee side-channel resistance.

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Contact: steel.sa.llc@gmail.com
Date: 2026-04-17
Version: 5.0.0
Project: AMA Cryptography 3R Runtime Monitoring

AI Co-Architects:
    Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
"""

import ast
import bisect
import cmath
import logging
import math
import os
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    Any,
    ClassVar,
    Deque,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

logger = logging.getLogger(__name__)


def _coerce_expiry_to_unix(value: Any) -> Optional[float]:
    """Best-effort conversion of an ``expires_at`` value to a Unix timestamp.

    Accepts a Unix ``int``/``float``, a ``datetime`` (naive treated as UTC), or
    an ISO-8601 string.  Returns ``None`` when the value cannot be interpreted
    so the caller can warn instead of silently skipping expiry enforcement (the
    previous ``isinstance(..., (int, float))``-only guard let ``datetime``/ISO
    expiries slip through as "never expired").
    """
    # ``bool`` is an ``int`` subclass — reject it so ``True`` is not read as
    # the epoch-second timestamp 1.0.
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime):
        dt = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    return None


def _median_sorted(values: List[float]) -> float:
    """Median of a pre-sorted list. O(1) after sort."""
    n = len(values)
    if n == 0:
        return 0.0
    mid = n // 2
    if n % 2 == 1:
        return values[mid]
    return (values[mid - 1] + values[mid]) / 2.0


def _mean(values: "Sequence[float]") -> float:
    """Arithmetic mean."""
    if not values:
        return 0.0
    return sum(values) / len(values)


def _std(values: "Sequence[float]") -> float:
    """Population standard deviation."""
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    return math.sqrt(sum((x - m) ** 2 for x in values) / len(values))


def _fnv1a64(token: bytes) -> int:
    """FNV-1a 64-bit over raw bytes.

    Matches the hash the Cython scanner computes in flight, so the marker
    table below and the kernel agree without the kernel ever seeing a Python
    string.
    """
    h = 0xCBF29CE484222325
    for byte in token:
        h = ((h ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def _volume_spike_scores_py(counts: "Sequence[float]", alpha: float, warmup: int) -> List[float]:
    """Pure-Python twin of ``math_engine.volume_spike_scores``.

    Kept operation-for-operation equivalent (same order, same float ops) so
    the Cython kernel is a speed-up and never a correctness dependency.  On a
    platform without FMA contraction the two agree bit-for-bit; where the C
    compiler contracts ``a*b + c`` to a fused multiply-add (e.g. ARM) the
    per-step rounding differs and, because the score is an EWMA recursion, the
    difference accumulates over the series — so the guarantee the tests pin is
    a small *relative* tolerance (rel/abs 1e-9), not a literal last ULP.  That
    is still orders of magnitude below anything that could move a score across
    the 6-sigma threshold.  ``tests/test_agentic_abuse_detectors.py`` pins that
    tolerance.  See the Cython docstring for the statistics.
    """
    if alpha <= 0.0 or alpha > 1.0:
        raise ValueError("alpha must be in (0, 1]")
    n = len(counts)
    out = [0.0] * n
    if n == 0:
        return out

    mean_est = 0.0
    sq_est = 1.0
    for i in range(n):
        a = 2.0 * math.sqrt(float(counts[i]) + 0.375)
        if i == 0:
            mean_est = a
            sq_est = 1.0
            out[i] = 0.0
            continue
        resid = a - mean_est
        sigma = math.sqrt(sq_est)
        if sigma < 1.0:
            sigma = 1.0
        out[i] = resid / sigma if i >= warmup else 0.0
        mean_est = mean_est + alpha * resid
        sq_est = (1.0 - alpha) * sq_est + alpha * resid * resid
    return out


def _bigram_hash(prev_hash: int, cur_hash: int) -> int:
    """Mix two token hashes into a bigram hash.

    Identical to the mix the Cython scanner performs inline, so the two
    implementations agree without either needing the token bytes twice.
    """
    return ((prev_hash * 0x100000001B3) ^ cur_hash) & 0xFFFFFFFFFFFFFFFF


def _token_family_counts_py(  # noqa: C901 -- deliberate one-to-one mirror of the Cython scan loop; decomposing it would break the byte-for-byte equivalence the tests pin (MON-002)
    data: bytes,
    uni_hashes: "Sequence[int]",
    uni_families: "Sequence[int]",
    bi_hashes: "Sequence[int]",
    bi_families: "Sequence[int]",
    num_families: int,
    max_token_len: int,
) -> Tuple[List[int], List[int], int, int]:
    """Pure-Python twin of ``math_engine.token_family_counts``."""
    if len(uni_families) != len(uni_hashes):
        raise ValueError("uni_hashes and uni_families must be the same length")
    if len(bi_families) != len(bi_hashes):
        raise ValueError("bi_hashes and bi_families must be the same length")
    if num_families <= 0:
        raise ValueError("num_families must be positive")

    uni_index: Dict[int, int] = {}
    for slot, h_val in enumerate(uni_hashes):
        uni_index.setdefault(h_val, slot)
    bi_index: Dict[int, int] = {}
    for slot, h_val in enumerate(bi_hashes):
        bi_index.setdefault(h_val, slot)

    occurrences = [0] * num_families
    distinct = [0] * num_families
    seen_uni: Set[int] = set()
    seen_bi: Set[int] = set()
    printable = 0
    tokens = 0
    h = 0
    prev_h = 0
    have_prev = False
    tok_len = 0
    in_token = False

    for i in range(len(data) + 1):
        if i < len(data):
            c = data[i]
            if 0x20 <= c < 0x7F or c in (0x09, 0x0A, 0x0D):
                printable += 1
            if 0x41 <= c <= 0x5A:
                c += 32
            if (0x61 <= c <= 0x7A) or (0x30 <= c <= 0x39):
                if not in_token:
                    in_token = True
                    h = 0xCBF29CE484222325
                    tok_len = 0
                h = ((h ^ c) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
                tok_len += 1
                continue
        if in_token:
            in_token = False
            tokens += 1
            usable = tok_len <= max_token_len
            if usable:
                pos = uni_index.get(h)
                if pos is not None:
                    fam = uni_families[pos]
                    occurrences[fam] += 1
                    if pos not in seen_uni:
                        seen_uni.add(pos)
                        distinct[fam] += 1
            if usable and have_prev:
                pos = bi_index.get(_bigram_hash(prev_h, h))
                if pos is not None:
                    fam = bi_families[pos]
                    occurrences[fam] += 1
                    if pos not in seen_bi:
                        seen_bi.add(pos)
                        distinct[fam] += 1
            if usable:
                prev_h = h
                have_prev = True
            else:
                have_prev = False
    return occurrences, distinct, printable, tokens


# Bytes that count as "printable text" for the note detector's structural
# gate: printable ASCII plus tab / LF / CR.  The complement is precomputed so
# the gate can be a single ``bytes.translate`` pass in C rather than a Python
# loop — see NoteArtifactDetector._printable_count.
_PRINTABLE_BYTES = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
_NON_PRINTABLE_TABLE = bytes(b for b in range(256) if b in _PRINTABLE_BYTES)


def _printable_count(data: bytes) -> int:
    """Count printable-ASCII bytes in `data`, in one C-level pass.

    ``bytes.translate(None, delete)`` removes every byte listed in `delete`,
    so deleting the printable set and subtracting gives the printable count
    without a Python-level loop.  Measured at ~1.0-1.5 ns/byte against ~6
    ns/byte for the tokenising scan, so running it first lets a binary
    payload — a signature, a wrapped key, a ciphertext — be rejected without
    paying for a scan whose result is discarded.  (A 256-entry mapping table
    plus ``.count()`` was measured at 1.6-3.5 ns/byte and rejected.)
    """
    return len(data) - len(data.translate(None, _NON_PRINTABLE_TABLE))


# Marker tables for NoteArtifactDetector, keyed by the marker collections they
# are derived from.  Building one costs ~750 pure-Python FNV-1a hashes; the
# tables are immutable and identical across instances, so they are built once.
_MARKER_TABLE_CACHE: Dict[
    Tuple[Any, ...], Tuple[List[int], List[int], List[int], List[int], Any]
] = {}
_MARKER_TABLE_LOCK = threading.Lock()


def _marker_tables(
    instructional: Tuple[bytes, ...],
    operational: Tuple[bytes, ...],
    prefixes: Tuple[bytes, ...],
    subjects: Tuple[bytes, ...],
    phrases: Tuple[Tuple[bytes, bytes], ...],
    successor_family: int,
) -> Tuple[List[int], List[int], List[int], List[int], Any]:
    """Build (or return the cached) sorted unigram and bigram marker tables.

    Returns ``(uni_hashes, uni_families, bi_hashes, bi_families, packed)``
    where ``packed`` is the ``array`` quadruple the Cython kernel wants, or
    ``None`` when the extension is unavailable.

    Raises:
        ValueError: if a unigram marker is claimed by two families, which
            would make attribution depend on iteration order.
    """
    key = (instructional, operational, prefixes, subjects, phrases, successor_family)
    cached = _MARKER_TABLE_CACHE.get(key)
    if cached is not None:
        return cached

    # Family 0 is phrase-level only, so it contributes no unigrams.
    unigram_families = ((), instructional, operational)
    uni: Dict[int, int] = {}
    for family_id, markers in enumerate(unigram_families):
        for marker in markers:
            h = _fnv1a64(marker)
            if h in uni and uni[h] != family_id:
                raise ValueError(f"marker {marker!r} is claimed by more than one family")
            uni[h] = family_id

    # Cross product plus fixed phrases, de-duplicated by hash.  A pair whose
    # two halves are the same word ("successor successor") is dropped: it
    # contributes nothing and only widens the table.
    pairs: Set[Tuple[bytes, bytes]] = set()
    for left in prefixes:
        for right in subjects:
            if left != right:
                pairs.add((left, right))
    pairs.update(phrases)
    bi: Dict[int, int] = {}
    for left, right in pairs:
        bi[_bigram_hash(_fnv1a64(left), _fnv1a64(right))] = successor_family

    ordered_uni = sorted(uni.items())
    ordered_bi = sorted(bi.items())
    uni_hashes = [h for h, _ in ordered_uni]
    uni_families = [f for _, f in ordered_uni]
    bi_hashes = [h for h, _ in ordered_bi]
    bi_families = [f for _, f in ordered_bi]

    packed: Any = None
    if _CY_TOKEN_COUNTS is not None:
        from array import array

        packed = (
            array("Q", uni_hashes),
            array("B", uni_families),
            array("Q", bi_hashes),
            array("B", bi_families),
        )

    tables = (uni_hashes, uni_families, bi_hashes, bi_families, packed)
    with _MARKER_TABLE_LOCK:
        # Last writer wins; both writers computed the same immutable tables
        # from the same key, so the race is benign.
        _MARKER_TABLE_CACHE[key] = tables
    return tables


# The Cython kernels are an optimisation.  When the extension is not built
# (source checkout, numpy-less environment, PyPy) the pure-Python twins above
# take over with identical results.
_CY_VOLUME_SCORES: Any = None
_CY_TOKEN_COUNTS: Any = None
try:  # pragma: no cover - exercised by whichever build the test run has
    import ama_cryptography.math_engine as _math_engine  # type: ignore[import-not-found, unused-ignore]  # compiled Cython extension — absent from a source checkout, so mypy cannot resolve it; the except branch below is the supported path (MON-001)

    _CY_TOKEN_COUNTS = _math_engine.token_family_counts
    _CY_VOLUME_SCORES = _math_engine.volume_spike_scores
except Exception:  # pragma: no cover - extension absent
    _CY_VOLUME_SCORES = None
    _CY_TOKEN_COUNTS = None

#: True when the compiled 3R kernels backed the detectors on this import.
CYTHON_DETECTOR_KERNELS: bool = _CY_VOLUME_SCORES is not None and _CY_TOKEN_COUNTS is not None


def _fft_cooley_tukey(x: List[complex]) -> List[complex]:
    """
    Radix-2 Cooley-Tukey FFT.

    Input length must be a power of 2 (zero-pad if necessary).
    This is explicitly documented as "not hot path" in the monitor —
    it runs on-demand for resonance detection, not per-operation.
    """
    n = len(x)
    if n <= 1:
        return x

    # Bit-reversal permutation + iterative butterfly
    # More efficient than recursive for our sizes
    result = list(x)
    bits = n.bit_length() - 1
    for i in range(n):
        j = 0
        for b in range(bits):
            j |= ((i >> b) & 1) << (bits - 1 - b)
        if j > i:
            result[i], result[j] = result[j], result[i]

    length = 2
    while length <= n:
        half = length // 2
        w_base = -2.0 * cmath.pi / length
        for start in range(0, n, length):
            for k in range(half):
                w = cmath.exp(complex(0, w_base * k))
                even = result[start + k]
                odd = result[start + k + half] * w
                result[start + k] = even + odd
                result[start + k + half] = even - odd
        length *= 2

    return result


def _fftfreq(n: int) -> List[float]:
    """Equivalent to scipy.fft.fftfreq(n) — frequency bins for DFT of length n."""
    freqs = []
    for i in range(n):
        if i < (n + 1) // 2:
            freqs.append(float(i) / n)
        else:
            freqs.append(float(i - n) / n)
    return freqs


class IncrementalStats:
    """
    Welford's online algorithm for running mean/variance.

    Provides O(1) incremental statistics computation instead of O(n)
    recalculation on every update. This optimization reduces 3R monitoring
    overhead from <2% to <1% without any change in detection capability.

    Mathematical equivalence: Produces identical mean and standard deviation
    values as np.mean() and np.std() for the same data sequence.

    Reference: Welford, B. P. (1962). "Note on a method for calculating
    corrected sums of squares and products". Technometrics. 4 (3): 419-420.
    """

    __slots__ = ("n", "mean", "M2")

    def __init__(self) -> None:
        """Initialize statistics accumulators."""
        self.n: int = 0
        self.mean: float = 0.0
        self.M2: float = 0.0

    def update(self, x: float) -> Tuple[float, float]:
        """
        Update running statistics with new value.

        Args:
            x: New observation value

        Returns:
            Tuple of (current_mean, current_std)
        """
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.M2 += delta * delta2
        variance = self.M2 / self.n if self.n > 1 else 0.0
        return self.mean, math.sqrt(variance)

    def get_stats(self) -> Tuple[float, float]:
        """
        Get current mean and standard deviation.

        Returns:
            Tuple of (mean, std)
        """
        if self.n < 2:
            return self.mean, 0.0
        variance = self.M2 / self.n
        return self.mean, math.sqrt(variance)

    def reset(self) -> None:
        """Reset all accumulators to initial state."""
        self.n = 0
        self.mean = 0.0
        self.M2 = 0.0


__version__ = "5.0.0"
__all__ = [
    "IncrementalStats",
    "EWMAStats",
    "TimingAnomaly",
    "PatternAnomaly",
    "NonceTracker",
    "IntegrityViolation",
    "ImportHijackViolation",
    "ResonanceTimingMonitor",
    "RecursionPatternMonitor",
    "RefactoringAnalyzer",
    "AmaCryptographyMonitor",
    # Agentic-abuse detectors (INVARIANT-30).  These are re-exported by
    # ama_cryptography.monitor and referenced by MONITORING.md, so they are
    # public surface and belong in the defining module's __all__ too —
    # otherwise `from ... import *` silently omits them and the kernel flag
    # reads as dead module state.
    "VolumeSpike",
    "VolumeSpikeDetector",
    "NoteArtifactSignal",
    "NoteArtifactDetector",
    #: Which detector kernel path is active (compiled Cython vs pure-Python
    #: twin).  Documented in MONITORING.md and asserted by the test suite.
    "CYTHON_DETECTOR_KERNELS",
    "high_resolution_timer",
    "create_monitor",
]


def high_resolution_timer() -> float:
    """
    Get high-resolution timestamp in milliseconds.

    Uses time.perf_counter_ns() for nanosecond precision (cross-platform).
    This provides higher resolution than time.time() which only has
    microsecond precision on most platforms.

    Returns:
        Current time in milliseconds (float)

    Note:
        perf_counter_ns() is available on Windows, macOS, and Linux.
        It measures elapsed time, not wall-clock time.
    """
    return time.perf_counter_ns() / 1_000_000.0


class EWMAStats:
    """
    Exponentially Weighted Moving Average (EWMA) statistics.

    EWMA gives more weight to recent observations, making it more
    responsive to changes while still smoothing noise. Combined with
    MAD (Median Absolute Deviation), it provides robust anomaly detection.

    Formula:
        EWMA_t = alpha * x_t + (1 - alpha) * EWMA_{t-1}

    Where:
        - alpha: Smoothing factor (0 < alpha <= 1)
        - Higher alpha = more weight on recent observations
        - Lower alpha = more smoothing

    Attributes:
        alpha: Smoothing factor
        mean: Current EWMA mean
        variance: Current EWMA variance
        n: Number of observations
    """

    __slots__ = ("alpha", "mean", "variance", "n", "_recent_values", "_mad_cache")

    def __init__(self, alpha: float = 0.1, window_size: int = 100) -> None:
        """
        Initialize EWMA statistics.

        Args:
            alpha: Smoothing factor (0 < alpha <= 1). Default 0.1 for
                   smooth response. Use 0.3 for faster response.
            window_size: Size of recent value window for MAD calculation

        Raises:
            ValueError: If alpha not in (0, 1]
        """
        if not 0 < alpha <= 1:
            raise ValueError("alpha must be in (0, 1]")

        self.alpha = alpha
        self.mean: float = 0.0
        self.variance: float = 0.0
        self.n: int = 0
        self._recent_values: Deque[float] = deque(maxlen=window_size)
        # ``(n_at_computation, median, mad)`` memo for :meth:`_median_and_mad`.
        #
        # ``record_timing`` consults the MAD three times per recorded
        # operation (the ``baseline_stats`` report, ``is_anomaly_mad``'s MAD
        # and its median), and each consultation sorted the whole window —
        # up to four O(w log w) sorts per crypto operation.  Measured on the
        # package-create hot path that made the *monitoring* of a signature
        # several times more expensive than the Ed25519 signature it
        # monitored.  The window only changes in ``update``, so one
        # computation per observation is enough; ``n`` is the change counter.
        self._mad_cache: Tuple[int, float, float] = (-1, 0.0, 0.0)

    def update(self, x: float) -> Tuple[float, float]:
        """
        Update EWMA statistics with new observation.

        Args:
            x: New observation value

        Returns:
            Tuple of (current_mean, current_std)
        """
        self._recent_values.append(x)
        self.n += 1

        if self.n == 1:
            # First observation
            self.mean = x
            self.variance = 0.0
        else:
            # EWMA update
            delta = x - self.mean
            self.mean = self.alpha * x + (1 - self.alpha) * self.mean
            # EWMA variance (exponentially weighted)
            self.variance = (1 - self.alpha) * (self.variance + self.alpha * delta * delta)

        return self.mean, math.sqrt(self.variance)

    def get_stats(self) -> Tuple[float, float]:
        """
        Get current EWMA mean and standard deviation.

        Returns:
            Tuple of (mean, std)
        """
        return self.mean, math.sqrt(self.variance)

    def _median_and_mad(self) -> Tuple[float, float]:
        """Median and MAD of the recent window, memoized per observation.

        One O(w log w) sort per new observation.  The deviations
        ``abs(v - median)`` over the *sorted* window form two ascending runs
        (walking outward from the median in each direction), so their median
        is selected with an O(w) two-pointer merge instead of building and
        sorting a second list.  Values are bit-identical to the naive
        ``sorted(abs(v - median) for v in values)`` form, which
        ``tests/test_monitoring_mad.py`` pins against randomized windows.
        """
        if self._mad_cache[0] == self.n:
            return self._mad_cache[1], self._mad_cache[2]

        values = sorted(self._recent_values)
        count = len(values)
        median = _median_sorted(values)

        # Split at the last element <= median; deviations ascend walking left
        # from the split and right from the element after it.
        lo = bisect.bisect_right(values, median) - 1
        hi = lo + 1

        def _next_deviation(left: int, right: int) -> Tuple[float, int, int]:
            left_dev = median - values[left] if left >= 0 else math.inf
            right_dev = values[right] - median if right < count else math.inf
            if left_dev <= right_dev:
                return left_dev, left - 1, right
            return right_dev, left, right + 1

        # Select the median of the ``count`` deviations: element at index
        # (count - 1) // 2, averaged with the next one when count is even.
        target = (count - 1) // 2
        deviation = 0.0
        for _ in range(target + 1):
            deviation, lo, hi = _next_deviation(lo, hi)
        if count % 2 == 0:
            second, _, _ = _next_deviation(lo, hi)
            deviation = (deviation + second) / 2.0

        self._mad_cache = (self.n, float(median), float(deviation))
        return float(median), float(deviation)

    def get_mad(self) -> float:
        """
        Calculate Median Absolute Deviation (MAD) from recent values.

        MAD is a robust measure of variability that is resistant to outliers.
        It's defined as: ``MAD = median(|x_i - median(x)|)``

        (Written as an inline literal: bare ``|...|`` is an RST substitution
        reference to docutils, not absolute-value bars, and Sphinx fails the
        docs build on the undefined substitution.)

        Returns:
            MAD value, or 0.0 if insufficient data
        """
        if len(self._recent_values) < 3:
            return 0.0
        return self._median_and_mad()[1]

    def is_anomaly_mad(self, x: float, threshold: float = 3.5) -> bool:
        """
        Check if value is anomaly using MAD-based detection.

        Uses modified Z-score: ``|x - median| / (1.4826 * MAD) > threshold``

        The constant 1.4826 makes MAD consistent with standard deviation
        for normally distributed data.

        .. note::
            The fixed default threshold of 3.5 is calibrated for **normally
            distributed** data (~99.95% coverage).  Real operation timings
            are heavy-tailed: measured on wall-clock Ed25519 signing
            timings, 11.4% of clean samples exceed this threshold
            (``benchmarks/detector_baseline_eval.py``).  For that reason
            ``ResonanceTimingMonitor`` no longer uses this fixed rule for
            alarming — it calibrates the threshold for :meth:`robust_score`
            empirically against a per-operation false-alarm budget.  This
            method is retained as a documented statistical helper for
            callers that know their data is near-normal.

        Args:
            x: Value to check
            threshold: Detection threshold (default 3.5 = ~99.95% for normal)

        Returns:
            True if value is anomaly, False otherwise
        """
        if len(self._recent_values) < 10:
            return False

        median, mad = self._median_and_mad()
        if mad == 0:
            return False

        modified_z = abs(x - median) / (1.4826 * mad)
        return modified_z > threshold

    def robust_score(self, x: float) -> float:
        """Robust standardized deviation of ``x`` from the current window.

        ``|x - median| / (1.4826 * MAD)`` over the values recorded so far —
        call BEFORE :meth:`update` so the score is measured against a window
        that does not yet contain ``x``.  (Scoring after the update lets the
        observation shift its own baseline: with EWMA smoothing ``alpha`` the
        post-update z-score is bounded by ``sqrt((1 - alpha)/alpha)`` — 3.0
        at the default ``alpha=0.1`` — which is how every per-operation
        ``threshold_sigma`` >= 3.0 became unreachable in the pre-5.0.0 rule.)

        Scale degradation, stated: when the window's MAD is 0 (a perfectly
        constant window, e.g. a quantized clock), the EWMA standard deviation
        is used as the scale; when that is also 0, any ``x`` equal to the
        constant scores 0.0 and any other ``x`` scores ``inf``.

        Returns 0.0 while fewer than 10 values have been recorded (no stable
        window to score against).
        """
        if len(self._recent_values) < 10:
            return 0.0
        median, mad = self._median_and_mad()
        scale = 1.4826 * mad
        if scale == 0.0:
            scale = math.sqrt(self.variance)
        if scale == 0.0:
            return 0.0 if x == median else math.inf
        return abs(x - median) / scale

    def reset(self) -> None:
        """Reset all accumulators to initial state."""
        self.mean = 0.0
        self.variance = 0.0
        self.n = 0
        self._recent_values.clear()
        self._mad_cache = (-1, 0.0, 0.0)


@dataclass
class TimingAnomaly:
    """
    Detected statistical timing anomaly.

    This represents a statistical anomaly in operation timing that may be
    consistent with side-channel behavior. This is a monitoring signal for
    human security review, NOT a guaranteed detection of a timing attack.

    The 3R monitoring system surfaces anomalies but does not guarantee
    detection or prevention of timing attacks or other side-channel
    vulnerabilities. Constant-time implementations at the cryptographic
    primitive level are the primary defense against timing side-channels.

    Attributes:
        operation: Name of the cryptographic operation
        expected_ms: Baseline expected duration in milliseconds
        observed_ms: Actual observed duration in milliseconds
        deviation_sigma: For a ``point`` anomaly, the robust standardized
            deviation; for a ``shift`` event, the accumulated sign-CUSUM
            statistic; for a ``cross_operation`` anomaly, the ratio
            deviation
        severity: Alert level ('info', 'warning', 'critical')
        timestamp: Unix timestamp of detection
        kind: Which detection path raised this — 'point' (isolated outlier),
            'shift' (edge-triggered sustained-regime-change event), or
            'cross_operation' (timing-ratio anomaly)
    """

    operation: str
    expected_ms: float
    observed_ms: float
    deviation_sigma: float
    severity: str  # 'info', 'warning', 'critical'
    timestamp: float
    kind: str = "point"  # 'point', 'shift', 'cross_operation'


@dataclass
class PatternAnomaly:
    """
    Detected signing pattern anomaly.

    Attributes:
        pattern_type: Type of pattern anomaly detected
        confidence: Confidence score (0.0 to 1.0)
        details: Additional context-specific details
        severity: Alert level ('info', 'warning', 'critical')
    """

    pattern_type: str
    confidence: float
    details: Dict
    severity: str


@dataclass
class VolumeSpike:
    """An anomalous burst of cryptographic operations.

    Attributes:
        operation: Operation name the burst was observed on
        count: Operations recorded in the firing bucket
        baseline_rate: EWMA baseline, expressed back in operations/bucket
        score: Anscombe-standardised residual (see VolumeSpikeDetector)
        distinct_key_ratio: Distinct key fingerprints / operations in the
            bucket.  Near 1.0 means near-every operation used a fresh key —
            the ephemeral-key churn shape, as opposed to a hot loop over one
            long-lived key.
        distinct_keys_capped: True when the per-bucket fingerprint set hit its
            size cap, in which case ``distinct_key_ratio`` is a LOWER bound.
            Surfaced rather than swallowed: a silently-truncated set would
            understate churn and could quietly downgrade the severity.
        bucket_seconds: Width of the counting bucket
        severity: 'warning', or 'critical' when the burst is also high-churn
        timestamp: Unix time of detection
    """

    operation: str
    count: int
    baseline_rate: float
    score: float
    distinct_key_ratio: float
    distinct_keys_capped: bool
    bucket_seconds: float
    severity: str
    timestamp: float


@dataclass
class NoteArtifactSignal:
    """Result of inspecting a payload for note-like structure.

    Attributes:
        label: Caller-supplied identifier for the payload
        occurrences: Per-family total marker occurrences
        distinct: Per-family count of distinct markers matched
        coverage: Number of families that met the per-family minimum
        score: Fractional family coverage in [0, 3] (see NoteArtifactDetector)
        text_ratio: Fraction of scanned bytes that were printable ASCII
        tokens: Number of alphanumeric tokens scanned
        scanned_bytes: Bytes actually examined (payloads may be sampled)
        flagged: True when every gate passed
    """

    label: str
    occurrences: Dict[str, int]
    distinct: Dict[str, int]
    coverage: int
    score: float
    text_ratio: float
    tokens: int
    scanned_bytes: int
    flagged: bool


@dataclass
class IntegrityViolation:
    """Runtime code integrity violation (Priority 9)."""

    file_path: str
    expected_hash: str
    actual_hash: str


@dataclass
class ImportHijackViolation:
    """Import chain integrity violation (Priority 10)."""

    module_name: str
    expected_path: str
    actual_path: str


class NonceTracker:
    """
    Tracks (key_id_hash, nonce) tuples to detect nonce reuse.

    Uses a rolling hash set (NOT a bloom filter — false negatives are
    dangerous for nonce reuse detection). Space is bounded by the 2^32
    nonce safety limit per key.

    Persists the nonce set to disk (append-only file) so it survives
    process restarts.
    """

    _NONCE_SAFETY_LIMIT: int = 2**32

    def __init__(self, persist_path: Optional[str] = None, ephemeral: bool = False) -> None:
        """
        Args:
            persist_path: Path to append-only persistence file.
                If None, uses ~/.ama_cryptography/nonce_tracker.dat
            ephemeral: If True, skip all persistence (no file read/write).
        """
        self._ephemeral = ephemeral

        if not ephemeral:
            if persist_path is None:
                data_dir = Path.home() / ".ama_cryptography"
                data_dir.mkdir(parents=True, exist_ok=True)
                self._persist_path = data_dir / "nonce_tracker.dat"
            else:
                self._persist_path = Path(persist_path)
                self._persist_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            self._persist_path = Path(persist_path) if persist_path else Path(os.devnull)

        # Set of (key_id_hash_hex, nonce_hex) tuples
        self._seen: Set[Tuple[str, str]] = set()
        # Per-key counters for 2^32 safety limit
        self._counters: Dict[str, int] = {}
        # Serialises the check-then-record critical section: without it two
        # threads presenting the same (key, nonce) can both observe it absent
        # and both return "fresh", defeating the reuse guard.  Re-entrant so a
        # future in-lock helper call cannot self-deadlock.
        self._lock = threading.RLock()
        if not ephemeral:
            self._load_persisted()

    def _load_persisted(self) -> None:
        """Reload persisted nonce history from disk.

        Raises RuntimeError on ANY malformed content — a silently skipped
        line means a previously-used nonce is "forgotten," which could
        allow nonce reuse (catastrophic for AES-GCM).  Only blank lines
        are tolerated (trailing newline, etc.).
        """
        try:
            with open(self._persist_path, "r") as f:
                for lineno, raw_line in enumerate(f, 1):
                    line = raw_line.strip()
                    if not line:
                        continue
                    parts = line.split(",", 1)
                    if len(parts) != 2 or not parts[0] or not parts[1]:
                        raise RuntimeError(
                            f"Malformed nonce tracker entry at {self._persist_path}:{lineno}: "
                            f"{line!r}. File may be corrupt — refusing to load partial "
                            "history because forgotten nonces could allow reuse."
                        )
                    key_hash, nonce_hex = parts
                    # Validate hex format to catch binary corruption
                    try:
                        bytes.fromhex(key_hash)
                        bytes.fromhex(nonce_hex)
                    except ValueError as ve:
                        raise RuntimeError(
                            f"Invalid hex in nonce tracker at {self._persist_path}:{lineno}: "
                            f"{line!r}. {ve}"
                        ) from ve
                    self._seen.add((key_hash, nonce_hex))
                    self._counters[key_hash] = self._counters.get(key_hash, 0) + 1
        except FileNotFoundError:
            return
        except RuntimeError:
            raise
        except Exception as e:
            raise RuntimeError(
                f"Failed to load nonce tracker persistence from {self._persist_path}: {e}"
            ) from e

    def _persist_entry(self, key_id_hash: str, nonce_hex: str) -> None:
        """Append a single entry to the persistence file with fsync for durability.

        Raises RuntimeError on write failure because an unpersisted nonce entry
        means a process restart could allow nonce reuse — a catastrophic failure
        for AES-GCM and other nonce-sensitive constructions.
        """
        if self._ephemeral:
            return
        try:
            with open(self._persist_path, "a") as f:
                f.write(f"{key_id_hash},{nonce_hex}\n")
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            raise RuntimeError(
                f"Failed to persist nonce entry to {self._persist_path}: {e}. "
                "Nonce tracking cannot guarantee reuse prevention without durable persistence."
            ) from e

    def check_and_record(self, key_id: bytes, nonce: bytes) -> Optional[Dict[str, Any]]:
        """
        Check if (key_id, nonce) has been seen before. If reuse is detected,
        returns a CRITICAL anomaly dict. Otherwise records and returns None.

        Args:
            key_id: Key identifier (will be SHA-256 hashed)
            nonce: The nonce/IV used for encryption

        Returns:
            Dict with anomaly details if nonce reuse detected, None otherwise
        """
        # key_id is key-identifying material inside a security control; its
        # digest comes from this module's own SHA-256, not OpenSSL-backed
        # hashlib (INVARIANT-1).  Deferred import: monitoring is imported by
        # modules pqc_backends itself pulls in.
        from ama_cryptography.pqc_backends import (
            native_sha256,
        )  # noqa: PLC0415  # deferred: import cycle with pqc_backends (MON-002)

        key_hash = native_sha256(key_id).hex()
        nonce_hex = nonce.hex()
        entry = (key_hash, nonce_hex)

        # The membership test, counter read, mutation and durable persist must
        # be one atomic unit or concurrent callers can race past the guard.
        with self._lock:
            if entry in self._seen:
                return {
                    "type": "nonce_reuse",
                    "severity": "critical",
                    "key_id_hash": key_hash,
                    "nonce": nonce_hex,
                    "message": "CRITICAL: Nonce reuse detected! Same (key, nonce) pair used twice.",
                    "timestamp": time.time(),
                }

            # Check counter limit
            count = self._counters.get(key_hash, 0)
            if count >= self._NONCE_SAFETY_LIMIT:
                return {
                    "type": "nonce_limit_exceeded",
                    "severity": "critical",
                    "key_id_hash": key_hash,
                    "count": count,
                    "message": (
                        "CRITICAL: Nonce safety limit (2^32) exceeded for key. Re-key required."
                    ),
                    "timestamp": time.time(),
                }

            self._seen.add(entry)
            self._counters[key_hash] = count + 1
            self._persist_entry(key_hash, nonce_hex)
            return None

    def get_counter(self, key_id: bytes) -> int:
        """Get current nonce count for a key."""
        # key_id is key-identifying material inside a security control; its
        # digest comes from this module's own SHA-256, not OpenSSL-backed
        # hashlib (INVARIANT-1).  Deferred import: monitoring is imported by
        # modules pqc_backends itself pulls in.
        from ama_cryptography.pqc_backends import (
            native_sha256,
        )  # noqa: PLC0415  # deferred: import cycle with pqc_backends (MON-002)

        key_hash = native_sha256(key_id).hex()
        return self._counters.get(key_hash, 0)

    def get_all_counters(self) -> Dict[str, int]:
        """Get all persisted counters (key_hash -> count)."""
        with self._lock:
            return dict(self._counters)


class ResonanceTimingMonitor:
    """
    Detect timing anomalies via statistical and frequency-domain analysis.

    This is a MONITORING system that surfaces statistical anomalies for
    security review. It does not guarantee detection of timing attacks
    or provide side-channel resistance.

    Detection rule (5.0.0 — measured, not assumed):

    * **Point anomalies** are scored with the robust standardized deviation
      ``|x - median| / (1.4826 * MAD)`` computed against the trailing window
      *before* the observation enters it.  The alarm threshold per operation
      is ``max(threshold_sigma, calibrated)`` where ``calibrated`` is the
      empirical ``(1 - alarm_budget)`` quantile of recently observed clean
      scores.  ``threshold_sigma`` is therefore a sensitivity floor that
      governs on well-behaved (near-normal) data, and the empirical quantile
      governs on the heavy-tailed distributions real timings exhibit — where
      any fixed Gaussian-calibrated constant is wrong by orders of magnitude
      (measured on Ed25519 wall-clock timings: a 1% false-alarm budget needs
      a threshold near 628 and 0.1% near 1073, versus the Gaussian 3.5;
      ``benchmarks/detector_baseline_eval.py`` regenerates this evidence and
      CI gates on it).
    * **Sustained shifts** are detected with a two-sided sign CUSUM against
      a reference median locked after 200 observations, evaluated on every
      sample.  A trailing window absorbs a regime change by construction
      (the pre-5.0.0 rule measured 17.6% recall on a 30% shift); the sign
      CUSUM accumulates distribution-free evidence against the *locked*
      reference instead, and keeps flagging while the shifted regime
      persists (measured: >= 0.95 recall on a 30% shift across seeds, with
      the shift path alone flagging <= 0.025% of clean samples).
    * The pre-5.0.0 rule — a z-score against statistics that had already
      absorbed the observation (mathematically capped below
      ``sqrt((1-alpha)/alpha)`` = 3.0 at the default ``alpha``), OR'd with a
      fixed Gaussian MAD threshold that produced a measured 12.5% false-alarm
      rate and made every ``threshold_sigma`` >= 3.0 unreachable — is
      removed, not re-tuned.

    Features:

    - Per-operation baseline statistics and anomaly profiles, keyed by the
      operation names the instrumented call sites actually emit
    - Empirically calibrated false-alarm budgets (heavy-tail safe)
    - Two-sided winsorized CUSUM for sustained regime changes
    - High-resolution timing via perf_counter_ns() (cross-platform)
    - Sliding window FFT analysis for periodic pattern detection
    """

    #: Fraction of clean operations an operation's point-anomaly path may
    #: flag once calibrated (the default false-alarm budget).  1% is the
    #: review budget the evaluation harness gates against; operations whose
    #: timing is legitimately variable get a smaller budget in their profile
    #: because their alarms carry less information per review.
    DEFAULT_ALARM_BUDGET: ClassVar[float] = 0.01

    # Priority 8: Default operation-specific anomaly profiles.
    #
    # Keys cover BOTH instrumentation vocabularies that exist in this
    # package: legacy_compat emits primitive-specific names (ed25519_sign,
    # dilithium_verify, hmac_verify, ...) while crypto_api emits generic
    # names (sign / verify / encrypt / decrypt / sphincs_sign).  The
    # pre-5.0.0 table carried aes_gcm_encrypt / aes_gcm_decrypt — names no
    # production call site ever emitted, so those profiles were dead
    # configuration; they are kept for external callers but the generic
    # names the API actually emits are now profiled too.
    #
    # That coverage claim was written before it was true: hmac_verify, named
    # inside the sentence making the claim, had no profile, and neither did
    # the other two legacy_compat emitters hmac_auth and sha3_256_hash.  The
    # consequence was not a crash — _record_timing_locked does
    # `self.anomaly_profiles.get(operation, {})`, so those three fell back to
    # self.threshold and DEFAULT_ALARM_BUDGET — but the block is the record of
    # a deliberate inventory pass, and it documented a reconciliation that had
    # not happened.  The three are added below at exactly the values the
    # fallback already supplied, so this changes no runtime behaviour; what it
    # changes is that the table now matches the claim, and
    # tests/test_monitoring_profile_coverage.py enumerates every
    # monitor_crypto_operation() name in the package and fails if one is
    # missing, so the next emitter cannot be added without a profile.
    #
    # threshold_sigma is the robust-score floor (governs on near-normal
    # data); alarm_budget is the calibrated false-alarm budget (governs on
    # heavy-tailed data).  Rejection-sampling signatures (ML-DSA) and
    # hash-tree signatures (SLH-DSA) have legitimately variable timing, so
    # their alarms are lower-information and get a 5x smaller budget.
    DEFAULT_ANOMALY_PROFILES: ClassVar[Dict[str, Dict[str, Any]]] = {
        # legacy_compat instrumentation names:
        "ed25519_sign": {"threshold_sigma": 2.0, "alarm_budget": 0.01, "normalize_by_size": False},
        "ed25519_verify": {
            "threshold_sigma": 2.0,
            "alarm_budget": 0.01,
            "normalize_by_size": False,
        },
        "dilithium_sign": {
            "threshold_sigma": 5.0,
            "alarm_budget": 0.002,
            "normalize_by_size": False,
        },
        "dilithium_verify": {
            "threshold_sigma": 3.0,
            "alarm_budget": 0.01,
            "normalize_by_size": False,
        },
        # crypto_api instrumentation names:
        "sign": {"threshold_sigma": 3.0, "alarm_budget": 0.01, "normalize_by_size": False},
        "verify": {"threshold_sigma": 3.0, "alarm_budget": 0.01, "normalize_by_size": False},
        "sphincs_sign": {"threshold_sigma": 5.0, "alarm_budget": 0.002, "normalize_by_size": False},
        # crypto_api's 'encrypt'/'decrypt' are ML-KEM encapsulate/decapsulate
        # — fixed-size operations, so size normalization does not apply.
        "encrypt": {"threshold_sigma": 3.0, "alarm_budget": 0.01, "normalize_by_size": False},
        "decrypt": {"threshold_sigma": 3.0, "alarm_budget": 0.01, "normalize_by_size": False},
        # legacy_compat's remaining three emitters.  Values are exactly the
        # fallback (self.threshold = 3.0, DEFAULT_ALARM_BUDGET = 0.01,
        # normalize_by_size defaulting to False at the read site), so naming
        # them here is a documentation fix rather than a retuning.
        "hmac_auth": {"threshold_sigma": 3.0, "alarm_budget": 0.01, "normalize_by_size": False},
        "hmac_verify": {
            "threshold_sigma": 3.0,
            "alarm_budget": 0.01,
            "normalize_by_size": False,
        },
        "sha3_256_hash": {
            "threshold_sigma": 3.0,
            "alarm_budget": 0.01,
            "normalize_by_size": False,
        },
        # Kept for external callers (no in-tree emitter):
        "aes_gcm_encrypt": {
            "threshold_sigma": 3.0,
            "alarm_budget": 0.01,
            "normalize_by_size": True,
        },
        "aes_gcm_decrypt": {
            "threshold_sigma": 3.0,
            "alarm_budget": 0.01,
            "normalize_by_size": True,
        },
    }

    #: Robust scores retained per operation for empirical threshold
    #: calibration.  4096 scores bound both memory and the smallest
    #: estimable tail quantile (1/4096 < every supported alarm_budget).
    _SCORE_HISTORY_LEN: ClassVar[int] = 4096
    #: Recompute the cached calibrated threshold every N observations.
    _THRESHOLD_RECOMPUTE_INTERVAL: ClassVar[int] = 32

    # Two-sided SIGN CUSUM parameters for the sustained-shift path.  The
    # statistic accumulates sign(x - mu0), not a standardized magnitude:
    # under the no-shift hypothesis P(x > median) = 1/2 for ANY continuous
    # distribution, so the test is distribution-free — a magnitude CUSUM
    # standardized by a robust scale was measured to false-alarm on 77% of
    # clean right-skewed timing samples, because the skewed tail's residuals
    # persistently exceed any symmetric reference drift.
    #
    # (k, h) were tuned EMPIRICALLY, not from a per-excursion approximation
    # (a first draft used k=0.25, h=8 sized from the single-excursion
    # crossing bound e^(-theta*h); over a 4,000-sample run the ~1,000
    # independent excursions multiply that bound, and the measured worst
    # seed false-alarmed on 46% of clean samples).  Measured over 40 seeded
    # clean lognormal runs x 4,000 samples and 15 seeded 30%-shift runs:
    #
    #   k=0.5 h=8 :  shift+point clean 1.46% worst, recall min 0.958
    #   k=0.5 h=10:  shift+point clean 1.26% worst, recall min 0.956
    #   k=0.5 h=12:  shift+point clean 1.26% worst, recall min 0.953
    #
    # k=0.5, h=10 is the chosen point; with the point path disabled the
    # shift path alone false-alarms on at most 0.025% of clean samples
    # (worst seed).  A sustained shift moving p = P(x > mu0) to ~0.9
    # accumulates ~0.28 per sample and crosses h in ~36 samples, then keeps
    # flagging while the regime persists.  benchmarks/detector_baseline_eval.py
    # regenerates these measurements and CI gates on them.  The accumulator
    # cap bounds recovery after a regime returns to baseline at ~cap/k
    # samples instead of the shift's duration.
    _CUSUM_K: ClassVar[float] = 0.5
    _CUSUM_H: ClassVar[float] = 10.0
    _CUSUM_CAP: ClassVar[float] = 40.0
    #: A shift alarm is an EVENT, not a per-sample condition: the alarm is
    #: raised once when the statistic crosses h (and escalated once to
    #: 'critical' if it later reaches 2h); after the shifted regime has
    #: persisted for this many samples the reference median is re-locked on
    #: the new regime and accumulation restarts — the operating point moved,
    #: the operator was told, and the monitor tracks the new normal.
    #: Measured motivation: on real hosts CPU frequency scaling moves the
    #: timing median mid-run; per-sample shift flagging turned one genuine
    #: regime change into a 27% "false"-alarm rate on clean traffic.
    _SHIFT_REBASELINE_SAMPLES: ClassVar[int] = 300
    #: The reference median locks after this many observations.  The sign
    #: test's clean-traffic drift is 2*delta - k where delta is the error in
    #: P(x > mu0) induced by estimating the median from n samples
    #: (sd ~ 1/(2*sqrt(n))).  Locking at n=30 (the warmup point) puts the
    #: k/2 = 0.125 tolerance at 1.4 standard errors — measured: one seeded
    #: clean run false-alarmed on 96% of samples from a mis-frozen median.
    #: At n=200 the tolerance sits at 3.5 standard errors (~2e-4 of
    #: operations would drift).  Before the lock the reference tracks the
    #: trailing-window median, which keeps E[sign] ~ 0 on clean traffic at
    #: the cost of absorbing a shift that occurs inside the first 200
    #: samples — the documented warmup blind spot.
    _CUSUM_LOCK_SAMPLES: ClassVar[int] = 200

    def __init__(
        self,
        threshold_sigma: float = 3.0,
        window_size: int = 100,
        max_history: int = 10000,
        use_ewma: bool = True,
        ewma_alpha: float = 0.1,
        anomaly_profiles: Optional[Dict[str, Dict[str, Any]]] = None,
        drift_check_interval: int = 50,
        max_operations: int = 256,
        max_ratio_operations: int = 16,
    ) -> None:
        """
        Initialize timing monitor.

        Args:
            threshold_sigma: Standard deviations for anomaly detection.
                Values > 3.0 indicate statistical significance.
            window_size: Number of samples for frequency analysis.
                Larger windows provide better frequency resolution.
            max_history: Maximum history entries per operation.
                Limits memory usage for long-running systems.
            use_ewma: Use EWMA instead of Welford's algorithm (default True).
                EWMA is more responsive to changes in timing patterns.
            ewma_alpha: EWMA smoothing factor (0 < alpha <= 1).
                Higher values = faster response, lower = more smoothing.
            anomaly_profiles: Per-operation anomaly detection profiles (Priority 8).
                Keys are operation names, values are dicts with threshold_sigma
                and normalize_by_size.
            drift_check_interval: Retained for API compatibility.  The
                pre-5.0.0 drift check ran only every N samples; the
                sustained-shift CUSUM that replaced it evaluates every
                sample, so this parameter no longer drives detection.
            max_operations: Cap on the number of distinct operation names
                tracked.  ``operation`` reaches here from
                ``AmaCryptographyMonitor.monitor_crypto_operation``, which is
                public API taking an arbitrary string, and every per-operation
                structure below is keyed on it — so without a cap a caller
                passing a fresh name per call grows nine dicts without bound.
                This is the same rule
                :class:`VolumeSpikeDetector` and
                :class:`RecursionPatternMonitor` already apply to the
                caller-fed keys they hold ("a monitoring component must not
                become the memory-exhaustion vector"); this class was the one
                that did not.  Names beyond the cap are counted in
                :attr:`dropped_operations` and otherwise ignored.
            max_ratio_operations: Cap on how many operations participate in
                the pairwise timing-ratio matrix.  That matrix is quadratic —
                measured at 300 tracked names it held exactly 44,850 pair
                deques (N(N-1)/2) and never evicted one — and it is walked
                inside the hot-path lock on EVERY record, so its size is also
                per-operation latency: the same measurement put per-record
                cost at 0.371 ms with 300 names against 0.021 ms with one, a
                17.7x regression against a documented "<2% overhead".  16
                bounds the matrix at 120 pairs and the per-record walk at 15
                comparisons, and is above the operation inventory the library
                itself uses (fewer than a dozen).  Operations are admitted in
                first-seen order.

        Performance Optimization:
            Uses collections.deque with maxlen for O(1) append and automatic
            pruning, and EWMA/Welford's algorithm for O(1) incremental statistics.
        """
        if max_operations < 1:
            raise ValueError("max_operations must be at least 1")
        if max_ratio_operations < 1:
            raise ValueError("max_ratio_operations must be at least 1")

        self.threshold = threshold_sigma
        self.window_size = window_size
        self.max_history = max_history
        self.max_operations = int(max_operations)
        self.max_ratio_operations = int(max_ratio_operations)
        #: Records dropped because the operation-name cap was hit.  Non-zero
        #: means this monitor is not seeing everything, which is why it is
        #: counted rather than silently absorbed.
        #:
        #: Read it from this attribute, or from ``dropped_operations`` in
        #: :meth:`AmaCryptographyMonitor.get_security_report`.  It is NOT in
        #: :meth:`snapshot_baselines`, which returns the per-operation baseline
        #: mapping and nothing else — an earlier version of this comment said
        #: it was, and pointed a reader at a method that never carried it.
        self.dropped_operations = 0
        self.use_ewma = use_ewma
        self.ewma_alpha = ewma_alpha
        self.drift_check_interval = drift_check_interval
        # Use deque with maxlen for O(1) append and automatic pruning
        self.timing_history: Dict[str, Deque[float]] = {}
        self.baseline_stats: Dict[str, Dict[str, float]] = {}
        # Per-operation statistics (separate baselines for each operation type)
        self._incremental_stats: Dict[str, IncrementalStats] = {}
        self._ewma_stats: Dict[str, EWMAStats] = {}
        # Priority 6: Pairwise timing ratio matrix for cross-operation correlation
        # (mean_ratio, std_ratio) per operation pair
        self._ratio_baselines: Dict[Tuple[str, str], Tuple[float, float]] = {}
        self._ratio_samples: Dict[Tuple[str, str], Deque[float]] = {}
        # Operations admitted to the ratio matrix, in first-seen order, capped
        # at max_ratio_operations.  Kept as a list because the walk below is
        # over it rather than over baseline_stats: iterating every tracked
        # operation on every record is what made the hot-path cost grow with
        # the name count.
        self._ratio_ops: List[str] = []
        # Per-pair history of |ratio - baseline_mean| / baseline_std, and the
        # cached (sample_total, threshold) pair, so the cross-operation bar is
        # an empirical quantile of what this pair actually does rather than a
        # fixed 3.0 against a sigma estimated from 30 CONSECUTIVE EWMA ratios.
        # Those 30 are heavily autocorrelated — an EWMA mean barely moves
        # between adjacent observations — so the frozen sigma underestimates
        # the long-run spread and the fixed bar is miscalibrated for the life
        # of the process.  Measured on two clean i.i.d. lognormal operations,
        # 4,000 records each: the point path spent 1.1% against its declared
        # 1% budget while this path alarmed on 1.9% of the same stream, from a
        # rule with no budget, no calibration and no floor.
        self._ratio_dev_history: Dict[Tuple[str, str], Deque[float]] = {}
        self._ratio_dev_total: Dict[Tuple[str, str], int] = {}
        #: pair -> (ingest count at computation, budget it was computed for,
        #: threshold).  The budget is in the key material, not just the value:
        #: see the note in :meth:`_calibrated_ratio_threshold`.
        self._ratio_threshold: Dict[Tuple[str, str], Tuple[int, float, float]] = {}
        # Priority 7: Frozen baselines for drift detection
        self._frozen_baselines: Dict[str, Tuple[float, float]] = {}  # (frozen_mean, frozen_std)
        # Empirical threshold calibration: robust scores observed per
        # operation, and a cached (observation_count, threshold) pair so the
        # quantile is recomputed every _THRESHOLD_RECOMPUTE_INTERVAL
        # observations instead of per call.
        self._score_history: Dict[str, Deque[float]] = {}
        self._calibrated_threshold: Dict[str, Tuple[int, Optional[float]]] = {}
        # Monotone per-operation count of every score ever ingested into
        # _score_history.  The recompute cadence must be driven by THIS and
        # never by len(_score_history): the history is a bounded deque, so
        # len() freezes at maxlen (~4,096) once saturated — at which point a
        # cadence test of the form `len - cached_len < interval` is
        # permanently true and the cached quantile threshold silently never
        # recomputes again.  Measured on the shipped default: after
        # saturation the cache froze while a changed timing regime pushed
        # the live 99% quantile from 3.4 to 15.8, and the point-alarm rate
        # ran at 10.6% against the declared, CI-gated 1% budget — for every
        # subsequent sample, forever, in any service that records more than
        # ~4,126 operations of one name.  len(bounded deque) is a window
        # size, not a sample counter.
        self._score_sample_total: Dict[str, int] = {}
        # Sustained-shift sign-CUSUM state per operation: mu0 (reference
        # median — tracking until locked), sigma0 (robust warmup scale, kept
        # for reporting), gp/gn (two-sided accumulators), locked (True once
        # the reference median is frozen at _CUSUM_LOCK_SAMPLES).
        self._shift_state: Dict[str, Dict[str, Any]] = {}
        # Priority 8: Operation-specific anomaly profiles
        self.anomaly_profiles: Dict[str, Dict[str, Any]] = dict(self.DEFAULT_ANOMALY_PROFILES)
        if anomaly_profiles:
            self.anomaly_profiles.update(anomaly_profiles)
        # ``record_timing`` runs on the concurrent crypto hot path (crypto_api
        # calls it from sign/verify/encrypt/decrypt, and HybridSignatureProvider
        # verifies via a ThreadPoolExecutor).  Its read-modify-write of the
        # Welford/EWMA/baseline state is not atomic, so concurrent calls would
        # corrupt the baselines and could suppress a genuine timing-anomaly
        # signal.  A re-entrant lock serialises the whole update (including the
        # nested ``_update_timing_ratios``).
        self._lock = threading.RLock()

    def record_timing(
        self,
        operation: str,
        duration_ms: float,
        input_size: Optional[int] = None,
    ) -> Optional[TimingAnomaly]:
        """Thread-safe wrapper around the timing-record critical section."""
        with self._lock:
            return self._record_timing_locked(operation, duration_ms, input_size)

    def _record_timing_locked(
        self,
        operation: str,
        duration_ms: float,
        input_size: Optional[int] = None,
    ) -> Optional[TimingAnomaly]:
        """
        Record operation timing and detect anomalies.

        Uses per-operation baselines to maintain separate statistics for
        each type of cryptographic operation (e.g., ed25519_sign vs dilithium_verify).

        Args:
            operation: Name of cryptographic operation (e.g., 'ed25519_sign',
                'dilithium_sign', 'kyber_encaps', etc.)
            duration_ms: Observed duration in milliseconds
            input_size: Optional input size in bytes for size-normalized
                anomaly detection (Priority 8)

        Returns:
            TimingAnomaly if statistical anomaly detected, None otherwise

        Note:
            Requires 30+ samples before anomaly detection activates.
            This establishes a stable baseline distribution.

        Performance Optimization:
            Uses O(1) incremental statistics via EWMA or Welford's algorithm.
            Deque with maxlen handles automatic pruning.
        """
        # Initialize deque and stats for new operations
        if operation not in self.timing_history:
            if len(self.timing_history) >= self.max_operations:
                # Refuse the name rather than growing.  Dropping is the only
                # safe direction: every structure below is keyed on a
                # caller-supplied string, so admitting an unbounded number of
                # them turns the monitor into the exhaustion vector it exists
                # to watch for.  The drop is COUNTED, so "the detector is not
                # seeing everything" is observable rather than silent.
                self.dropped_operations += 1
                return None
            self.timing_history[operation] = deque(maxlen=self.max_history)
            self._incremental_stats[operation] = IncrementalStats()
            self._ewma_stats[operation] = EWMAStats(
                alpha=self.ewma_alpha, window_size=self.window_size
            )
            self._score_history[operation] = deque(maxlen=self._SCORE_HISTORY_LEN)

        # Priority 8: Normalize by input size if profile says so
        profile = self.anomaly_profiles.get(operation, {})
        normalize_by_size = profile.get("normalize_by_size", False)
        effective_duration = duration_ms
        if normalize_by_size and input_size and input_size > 0:
            effective_duration = duration_ms / input_size

        ewma = self._ewma_stats[operation]
        prior_count = self._incremental_stats[operation].n

        # ------------------------------------------------------------------
        # DETECT FIRST, UPDATE AFTER.  Every statistic consulted below is
        # measured against state that does not yet contain this observation.
        # The pre-5.0.0 rule updated first, which bounded the achievable
        # z-score below sqrt((1-alpha)/alpha) = 3.0 at the default alpha —
        # making every threshold_sigma >= 3.0, and 'critical' severity,
        # mathematically unreachable.
        # ------------------------------------------------------------------

        # The point-anomaly verdict does not exist until a baseline does.  A
        # `None` sentinel says exactly that, and keeps "no baseline yet"
        # distinguishable from a real "measured, not anomalous" verdict.
        # Seeding `severity`/`deviation` with placeholders instead would be
        # dead stores — the only read of them is guarded by the same
        # `prior_count` condition that overwrites them — which is what CodeQL
        # flagged as alerts 621 and 622.
        point_verdict: Optional[Tuple[bool, str, float]] = None
        shift_anomaly: Optional[TimingAnomaly] = None

        if prior_count >= 30:
            point_verdict = self._detect_point_anomaly(operation, effective_duration, profile, ewma)
            shift_anomaly = self._step_shift_cusum(operation, effective_duration, ewma, prior_count)

            # The observed score joins the calibration history AFTER the
            # decision, so a sample can never raise the threshold it is
            # judged against.  Calibration deliberately ingests every score
            # (alarming ones included): a quantile over the trailing window
            # is robust to the alarm fraction itself, and excluding flagged
            # samples would create a ratchet that can only tighten.
            self._score_history[operation].append(point_verdict[2])
            self._score_sample_total[operation] = self._score_sample_total.get(operation, 0) + 1

        # ------------------------------------------------------------------
        # UPDATE PHASE
        # ------------------------------------------------------------------
        # O(1) append with automatic pruning via deque maxlen
        self.timing_history[operation].append(effective_duration)
        self._incremental_stats[operation].update(effective_duration)
        ewma_mean, ewma_std = ewma.update(effective_duration)
        sample_count = self._incremental_stats[operation].n

        # Choose which stats to report (EWMA responsiveness vs Welford accuracy)
        if self.use_ewma:
            mean, std = ewma_mean, ewma_std
        else:
            mean, std = self._incremental_stats[operation].get_stats()

        # Priority 7: establish the shift reference once warmup completes
        # (after the 30th recorded sample, matching the documented warmup).
        # Robust location (median) — a heavy right tail corrupts a mean
        # baseline but not this one.  The reference TRACKS the trailing
        # window until _CUSUM_LOCK_SAMPLES observations, then locks (see the
        # constant's comment for the finite-sample error analysis).
        if sample_count == 30 and operation not in self._shift_state:
            mu0, mad0 = ewma._median_and_mad()
            sigma0 = 1.4826 * mad0
            if sigma0 == 0.0:
                sigma0 = math.sqrt(ewma.variance)
            self._shift_state[operation] = {
                "mu0": mu0,
                "sigma0": sigma0,
                "gp": 0.0,
                "gn": 0.0,
                "locked": False,
                "in_shift": False,
                "escalated": False,
                "shift_run": 0,
            }
            # Kept for backward compatibility with readers of the Welford
            # frozen baseline (reporting only; no longer drives alarming).
            if operation not in self._frozen_baselines:
                self._frozen_baselines[operation] = self._incremental_stats[operation].get_stats()

        if sample_count >= 30:
            # Update baseline stats for reporting
            self.baseline_stats[operation] = {
                "mean": mean,
                "std": std,
                "samples": sample_count,
                "mad": ewma.get_mad(),
            }

        # Need baseline before detection
        if prior_count < 30:
            return None

        # Priority 6: Cross-operation timing correlation
        cross_op_anomaly = self._update_timing_ratios(operation, mean)

        # Return priority: shift > point > cross-op.  A shift EVENT is
        # edge-triggered — if it is not delivered on the sample where the
        # edge fired, the edge state has already been consumed and the event
        # is lost forever, whereas a coinciding point alarm is one of a
        # budgeted stream.  (Shift events are also the rarer, higher-value
        # signal.)
        if shift_anomaly is not None:
            return shift_anomaly

        if point_verdict is not None and point_verdict[0]:
            _, severity, deviation = point_verdict
            return TimingAnomaly(
                operation=operation,
                expected_ms=mean,
                observed_ms=effective_duration,
                deviation_sigma=deviation,
                severity=severity,
                timestamp=time.time(),
            )

        if cross_op_anomaly is not None:
            return cross_op_anomaly

        return None

    def _detect_point_anomaly(
        self,
        operation: str,
        effective_duration: float,
        profile: Dict[str, Any],
        ewma: EWMAStats,
    ) -> Tuple[bool, str, float]:
        """Point-anomaly decision: robust score vs calibrated threshold.

        Returns ``(is_anomaly, severity, robust_score)``.  The threshold is
        ``max(threshold_sigma, calibrated)``; 'critical' means twice the
        operating threshold — reachable by construction (the pre-5.0.0 fixed
        5.0-sigma criticality sat above the 3.0 z-score cap), but ONLY once
        the threshold is empirically calibrated: before the tail has been
        measured, a large score on heavy-tailed data is ordinary, and paging
        a human on it would be a confidence claim nothing supports.
        """
        THRESHOLD_EPSILON = 0.01
        deviation = ewma.robust_score(effective_duration)
        alarm_budget = float(profile.get("alarm_budget", self.DEFAULT_ALARM_BUDGET))
        sigma_floor = float(profile.get("threshold_sigma", self.threshold))
        calibrated = self._calibrated_score_threshold(operation, alarm_budget)
        op_threshold = sigma_floor if calibrated is None else max(sigma_floor, calibrated)
        if deviation < op_threshold - THRESHOLD_EPSILON:
            return False, "warning", deviation
        severity = (
            "critical"
            if calibrated is not None and deviation >= 2.0 * op_threshold - THRESHOLD_EPSILON
            else "warning"
        )
        return True, severity, deviation

    def _step_shift_cusum(
        self,
        operation: str,
        effective_duration: float,
        ewma: EWMAStats,
        prior_count: int,
    ) -> Optional[TimingAnomaly]:
        """Advance the sustained-shift sign CUSUM by one observation.

        Two-sided sign CUSUM against the reference median, evaluated on
        EVERY sample (the pre-5.0.0 drift check ran on every 50th sample
        only, and a trailing window had absorbed the shift by then —
        measured 17.6% recall on a 30% regime change).  Signs, not
        magnitudes: see the ``_CUSUM_*`` comment for why a magnitude CUSUM
        is miscalibrated on skewed timing distributions.

        Edge-triggered event semantics (see ``_SHIFT_REBASELINE_SAMPLES``
        for the measured motivation): one 'warning' when the regime
        transition is detected, one 'critical' escalation if the evidence
        later doubles, then re-baseline once the new regime has persisted.
        """
        state = self._shift_state.get(operation)
        if state is None:
            return None

        if not state["locked"]:
            if prior_count >= self._CUSUM_LOCK_SAMPLES:
                # Lock the reference on a median estimated from the last
                # _CUSUM_LOCK_SAMPLES observations, and restart the
                # accumulators: evidence gathered against the tracking
                # reference is not evidence against the locked one.
                tail = sorted(list(self.timing_history[operation])[-self._CUSUM_LOCK_SAMPLES :])
                state["mu0"] = _median_sorted(tail)
                state["gp"] = 0.0
                state["gn"] = 0.0
                state["locked"] = True
            else:
                # Pre-lock: track the trailing-window median so the sign
                # statistic stays centred on clean traffic.
                state["mu0"] = ewma._median_and_mad()[0]
                # ...and raise NOTHING from it.  Two reasons, both already
                # written into this file before the events were:
                #
                #  * the lock branch above zeroes the accumulators because
                #    "evidence gathered against the tracking reference is not
                #    evidence against the locked one" — evidence too weak to
                #    survive the lock is too weak to page an operator; and
                #  * _CUSUM_LOCK_SAMPLES documents absorbing "a shift that
                #    occurs inside the first 200 samples — the documented
                #    warmup blind spot".
                #
                # A moving reference only keeps E[sign] ~ 0 on a *stationary*
                # stream.  Against any systematic drift the trailing median
                # lags, every sample lands on the same side, and gn/gp climb
                # ~k per sample until they cross h and then 2h.  Measured on
                # a 96-sample benign stream drifting 4e-6 ms/sample: gn = 33,
                # a 'warning' at sample 50 and a **'critical' at sample 69**,
                # with the reference still unlocked.  That is what failed
                # test_scheduled_key_rotation_raises_no_critical_anomaly on
                # ubuntu-24.04-arm — a key-registration schedule walking a
                # growing dict is exactly such a drift, and it is benign.
                #
                # Detection is unaffected: shift recall is defined against
                # the locked reference, and every shift test and the eval
                # harness inject well past the lock (sample 1000; eval region
                # from 400).
                return None

        mu0 = state["mu0"]
        # Ties contribute 0 (decay only): on a quantized clock a stream
        # sitting exactly on the baseline median must not read as a shift
        # in either direction.
        if effective_duration > mu0:
            sgn = 1.0
        elif effective_duration < mu0:
            sgn = -1.0
        else:
            sgn = 0.0
        state["gp"] = min(self._CUSUM_CAP, max(0.0, state["gp"] + sgn - self._CUSUM_K))
        state["gn"] = min(self._CUSUM_CAP, max(0.0, state["gn"] - sgn - self._CUSUM_K))
        g_max = max(state["gp"], state["gn"])

        def _shift_event(severity: str) -> TimingAnomaly:
            return TimingAnomaly(
                operation=operation,
                expected_ms=mu0,
                observed_ms=effective_duration,
                # For a shift event this carries the CUSUM statistic
                # (accumulated sign-evidence), not a per-sample deviation.
                deviation_sigma=g_max,
                severity=severity,
                timestamp=time.time(),
                kind="shift",
            )

        if not state["in_shift"]:
            if g_max > self._CUSUM_H:
                state["in_shift"] = True
                state["escalated"] = False
                state["shift_run"] = 0
                return _shift_event("warning")
            return None

        state["shift_run"] += 1
        event: Optional[TimingAnomaly] = None
        if g_max >= 2.0 * self._CUSUM_H and not state["escalated"]:
            state["escalated"] = True
            event = _shift_event("critical")
        if g_max < self._CUSUM_H / 2.0:
            # The stream returned to the reference regime.
            state["in_shift"] = False
            state["escalated"] = False
            state["shift_run"] = 0
        elif state["shift_run"] >= self._SHIFT_REBASELINE_SAMPLES:
            # The shifted regime is the new normal: re-lock the reference on
            # the trailing window and restart accumulation.  The transition
            # was already alerted.
            state["mu0"] = ewma._median_and_mad()[0]
            state["gp"] = 0.0
            state["gn"] = 0.0
            state["in_shift"] = False
            state["escalated"] = False
            state["shift_run"] = 0
        return event

    def _calibrated_score_threshold(self, operation: str, alarm_budget: float) -> Optional[float]:
        """Empirical ``(1 - alarm_budget)`` quantile of the operation's
        trailing robust scores, or ``None`` until enough scores exist.

        Activation requires ``max(100, ceil(1/alarm_budget))`` observed
        scores: estimating the (1 - b) tail from fewer than 1/b samples is
        extrapolation, and until then the ``threshold_sigma`` floor governs
        alone (the documented warmup posture).  The quantile is the
        conservative order statistic ``ceil((1 - b) * (n + 1))`` and is
        recomputed every ``_THRESHOLD_RECOMPUTE_INTERVAL`` observations,
        cached in between.
        """
        history = self._score_history.get(operation)
        if history is None:
            return None
        n = len(history)
        if alarm_budget <= 0.0:
            return None
        if n < max(100, math.ceil(1.0 / alarm_budget)):
            return None
        # Cadence runs on the monotone ingest counter, NOT on len(history):
        # the history is a bounded deque, so len() freezes at maxlen once
        # saturated and a len-based cadence test becomes permanently true —
        # the cached threshold then silently never recomputes again, for the
        # rest of the process lifetime, in exactly the long-running services
        # this detector exists for.  n stays the QUANTILE's sample size (the
        # window is the sample); total is WHEN to recompute.
        total = self._score_sample_total.get(operation, n)
        cached = self._calibrated_threshold.get(operation)
        if cached is not None and total - cached[0] < self._THRESHOLD_RECOMPUTE_INTERVAL:
            return cached[1]
        ordered = sorted(history)
        k = min(n - 1, max(0, math.ceil((1.0 - alarm_budget) * (n + 1)) - 1))
        threshold = ordered[k]
        self._calibrated_threshold[operation] = (total, threshold)
        return threshold

    def snapshot_baselines(self) -> Dict[str, Dict[str, float]]:
        """A consistent COPY of the per-operation baseline statistics.

        ``baseline_stats`` is mutated under :attr:`_lock` — a new key appears
        on the 30th record of each new operation name — so handing the live
        mapping to a reader that does not hold that lock is a race, not a
        convenience.  ``get_security_report`` did exactly that, three lines
        above the comment where it fixes the same race for ``timing_history``;
        an ordinary consumer iterating the returned mapping raised
        ``RuntimeError("dictionary changed size during iteration")`` within
        four seconds against a writer issuing fresh names.

        The per-operation dicts are copied too: returning the outer copy alone
        would still hand out the inner ones the writer updates in place.
        """
        with self._lock:
            return {op: dict(stats) for op, stats in self.baseline_stats.items()}

    def get_shift_state(self, operation: str) -> Optional[Dict[str, Any]]:
        """Snapshot of the sustained-shift detector for one operation.

        Returns ``None`` before warmup completes, otherwise a copy of the
        state: ``mu0`` (the reference median), ``sigma0`` (the robust warmup
        scale, reporting only), ``gp``/``gn`` (the two-sided sign-CUSUM
        accumulators), ``locked`` (whether the reference has been frozen),
        ``in_shift`` (whether the operation is currently in a detected
        shifted regime), ``escalated`` and ``shift_run``.  Shift alarms are
        edge-triggered events; this accessor is how an operator (or the
        evaluation harness) reads the persistent regime state between
        events.
        """
        with self._lock:
            state = self._shift_state.get(operation)
            return dict(state) if state is not None else None

    #: Deviations retained per operation pair for the cross-operation
    #: quantile.  Same size and same reason as :attr:`_SCORE_HISTORY_LEN`.
    _RATIO_DEV_HISTORY_LEN: ClassVar[int] = 4096

    #: Samples a PAIR must accumulate before its bar may alarm, as a multiple
    #: of the point path's floor.
    #:
    #: The point path activates at ``max(100, ceil(1/alarm_budget))``.  The
    #: ratio path needs more for the same quantile accuracy, and the reason is
    #: structural rather than a matter of taste: a point score is a robust
    #: z-score of one observation, while a ratio deviation is built from TWO
    #: EWMA means, each already a smoothed function of its own history.  The
    #: extra smoothing makes consecutive deviations more autocorrelated, and an
    #: empirical quantile of autocorrelated samples under-covers — it has seen
    #: less of the tail than its sample count suggests.
    #:
    #: Measured on two clean i.i.d. lognormal operations, 5,000 records each,
    #: eight seeds, against a declared 1% budget:
    #:
    #:   floor x1  (the point path's)   mean 1.19%   worst 1.79%
    #:   floor x4  (this)               mean 1.09%   worst 1.66%
    #:   floor x10                      mean 1.04%   worst 1.51%
    #:
    #: The overspend is a warm-up effect, not a steady-state one: pooled over
    #: the same runs by position in the stream, the first 40% of records
    #: alarmed at 1.31% and 1.51% while the last 40% ran UNDER budget at 0.55%
    #: and 0.83%.  x4 takes most of the available correction; x10 buys 0.04
    #: points more for two and a half times the silence, which is not a trade
    #: worth making on a supplementary signal — the point path covers these
    #: same operations throughout, so a longer warm-up here delays a
    #: cross-check rather than leaving anything unwatched.
    _RATIO_ACTIVATION_FLOOR_MULTIPLE: ClassVar[int] = 4

    def _calibrated_ratio_threshold(
        self, pair: Tuple[str, str], alarm_budget: float
    ) -> Optional[float]:
        """Empirical ``(1 - alarm_budget)`` quantile of this pair's observed
        deviations, floored at :attr:`threshold`, or ``None`` while the
        estimate would be extrapolation.

        The same rule :meth:`_calibrated_score_threshold` applies to the point
        path, for the same reason and with the same cadence, but with a larger
        activation floor — see :attr:`_RATIO_ACTIVATION_FLOOR_MULTIPLE` for the
        measurement behind it.  ``None`` means the pair may not alarm AT ALL
        yet: unlike the point path there is no measured basis for a fixed sigma
        floor here — the ratio of two EWMA means is not a robust z-score and
        never had a calibrated budget — so the warmup posture is silence rather
        than an uncalibrated bar.

        What this does NOT claim is that the spend equals the budget.  An
        empirical quantile over a bounded rolling window is an estimate, and
        this one measures at roughly 1.09% against a declared 1% across eight
        seeds — the same kind of overshoot the point path shows (1.1% against
        1%), and reported rather than rounded away.
        """
        history = self._ratio_dev_history.get(pair)
        if history is None or alarm_budget <= 0.0:
            return None
        n = len(history)
        floor = self._RATIO_ACTIVATION_FLOOR_MULTIPLE * max(100, math.ceil(1.0 / alarm_budget))
        if n < floor:
            return None
        total = self._ratio_dev_total.get(pair, n)
        cached = self._ratio_threshold.get(pair)
        # The budget is part of the cache key, not just the cadence.  It was
        # keyed on the pair alone, so the first budget to compute a bar owned
        # it until the recompute interval elapsed — and with the budget taken
        # from whichever operation happened to be recording, the bar a strict
        # operation got was whatever a loose one had most recently produced.
        # Measured on a pair of {"alarm_budget": 0.002} and 0.05 operations
        # after 4,000 records each: 7.868 when computed under 0.002 and 5.011
        # under 0.05, and the 5.011 was served to the 0.002 caller — a bar 36%
        # too low for the operation that asked for the tighter one.
        if (
            cached is not None
            and cached[1] == alarm_budget
            and total - cached[0] < self._THRESHOLD_RECOMPUTE_INTERVAL
        ):
            return cached[2]
        ordered = sorted(history)
        k = min(n - 1, max(0, math.ceil((1.0 - alarm_budget) * (n + 1)) - 1))
        threshold = max(self.threshold, ordered[k])
        self._ratio_threshold[pair] = (total, alarm_budget, threshold)
        return threshold

    def _pair_alarm_budget(self, pair: Tuple[str, str]) -> float:
        """The STRICTER of the two operations' budgets, so the pair's bar does
        not depend on which side happened to record.

        ``_update_timing_ratios`` used the budget of the operation currently
        being recorded, which for a pair is an arbitrary choice between two —
        the same pair got a different bar depending on the arrival order of its
        two members.  Taking the minimum makes it deterministic, and makes it
        the safe direction: a pair that includes an operation the caller asked
        to watch tightly is not allowed to be looser than that operation.
        """
        budgets = [
            float(self.anomaly_profiles.get(op, {}).get("alarm_budget", self.DEFAULT_ALARM_BUDGET))
            for op in pair
        ]
        return min(budgets)

    def _update_timing_ratios(self, operation: str, current_mean: float) -> Optional[TimingAnomaly]:
        """
        Priority 6: Update pairwise timing ratio matrix and detect
        cross-operation correlation anomalies.

        Two properties this path did not have.

        **The walk is bounded.**  It iterated all of ``baseline_stats`` on
        every record, inside the hot-path lock, allocating a fresh deque per
        unordered pair and never evicting one.  Measured at 300 tracked names:
        44,850 pair deques (exactly N(N-1)/2) and per-record cost 0.371 ms
        against 0.021 ms at a single name.  It now walks
        :attr:`_ratio_ops`, admitted in first-seen order and capped at
        ``max_ratio_operations``.

        **The bar is calibrated.**  ``abs(ratio - mu) / sigma > 3.0`` with mu
        and sigma frozen after 30 CONSECUTIVE ratio samples is not a 3-sigma
        test: consecutive values of ``EWMA_mean(a) / EWMA_mean(b)`` are
        heavily autocorrelated, so that sigma measures short-term jitter, not
        the spread the bar is supposed to sit outside of.  Measured on two
        clean i.i.d. lognormal operations at 4,000 records each, the path
        alarmed on 1.9% of the stream — nearly triple the point path's
        budgeted-and-gated 1% — with no budget, no calibration and no floor.
        The bar is now the empirical ``(1 - alarm_budget)`` quantile of this
        pair's own deviations, so whatever the frozen reference is off by, the
        spend is the budget.
        """
        if current_mean <= 0:
            return None

        if operation not in self._ratio_ops:
            if len(self._ratio_ops) >= self.max_ratio_operations:
                return None
            self._ratio_ops.append(operation)

        for other_op in self._ratio_ops:
            if other_op == operation:
                continue
            other_stats = self.baseline_stats.get(other_op)
            if not other_stats:
                continue
            other_mean = other_stats.get("mean", 0.0)
            if other_mean <= 0:
                continue

            _sorted = sorted([operation, other_op])
            pair: Tuple[str, str] = (_sorted[0], _sorted[1])
            ratio = current_mean / other_mean if pair[0] == operation else other_mean / current_mean

            if pair not in self._ratio_samples:
                self._ratio_samples[pair] = deque(maxlen=self.window_size)

            self._ratio_samples[pair].append(ratio)

            # Capture baseline once we have enough samples.
            # Use >= 30 (not == 30) so this works even when window_size < 30
            # (the deque wraps before reaching 30, so == 30 would never fire).
            samples = self._ratio_samples[pair]
            if len(samples) >= 30 and pair not in self._ratio_baselines:
                self._ratio_baselines[pair] = (_mean(samples), _std(samples))
            elif pair in self._ratio_baselines:
                baseline_mean, baseline_std = self._ratio_baselines[pair]
                if baseline_std > 0:
                    deviation = abs(ratio - baseline_mean) / baseline_std
                    # JUDGE FIRST, then ingest — the ordering the point path
                    # uses, and for its stated reason: "a sample can never
                    # raise the threshold it is judged against".  This block
                    # had them the other way round, so a large deviation was in
                    # the history that set its own bar and could nudge that bar
                    # up before being compared to it.  The effect on one sample
                    # in 4,096 is small, but the property is not a matter of
                    # degree, and having the two calibrated paths disagree on
                    # it meant one of the two comments describing "the same
                    # ordering" was wrong.
                    #
                    # Ingesting EVERY deviation, alarming ones included, is a
                    # separate property and is preserved: a quantile over the
                    # trailing window is robust to the alarm fraction itself,
                    # and dropping flagged samples would be a ratchet that can
                    # only tighten.  The point path says the same thing.
                    history = self._ratio_dev_history.get(pair)
                    if history is None:
                        history = deque(maxlen=self._RATIO_DEV_HISTORY_LEN)
                        self._ratio_dev_history[pair] = history
                    # The PAIR's budget, derived from both members, not the
                    # budget of whichever one is recording right now.
                    bar = self._calibrated_ratio_threshold(pair, self._pair_alarm_budget(pair))
                    history.append(deviation)
                    self._ratio_dev_total[pair] = self._ratio_dev_total.get(pair, 0) + 1
                    if bar is not None and deviation > bar:
                        return TimingAnomaly(
                            operation=f"{pair[0]}/{pair[1]}",
                            expected_ms=baseline_mean,
                            observed_ms=ratio,
                            deviation_sigma=deviation,
                            severity="warning",
                            timestamp=time.time(),
                            kind="cross_operation",
                        )
        return None

    def detect_resonance(self, operation: str) -> Dict:
        """
        Apply FFT to detect periodic timing patterns (resonance).

        Periodic patterns may indicate:
        - Cache timing attacks (consistent memory access patterns)
        - Branch prediction leakage (repeated conditional paths)
        - Memory access patterns (array indexing correlations)

        Returns:
            Dict with:
                - dominant_frequency: Primary periodic component
                - dominant_power: Power of dominant frequency
                - mean_power: Average power across the scanned spectrum
                - resonance_ratio: Ratio of dominant to mean power
                - threshold_ratio: The ratio ``has_resonance`` compares against
                - false_alarm_rate: The per-call rate that threshold targets
                - scanned_bins: Number of periodogram ordinates examined
                - has_resonance: Boolean flag (ratio > threshold_ratio)

        Two properties this had to acquire before the flag meant anything.

        **The mean is removed first.**  The series was transformed as given, so
        its DC component — the operation's baseline duration, always the
        largest thing in the signal — leaked across the whole spectrum through
        the zero-padding window.  The search then excluded bin 0 and found that
        leakage instead.  Measured on the pre-fix code: a PERFECTLY CONSTANT
        100-sample series (padded to 128) reported ``resonance_ratio`` 30.31 and
        ``has_resonance`` True.  A constant series has no periodic component at
        all; it was reporting the baseline it was supposed to be measured
        against.  After centring, the same input gives ratio 0.0 and False.

        **The threshold comes from the null distribution, not from 3.0.**  For
        white noise the periodogram ordinates are iid exponential, so the
        maximum-to-mean ratio over ``m`` of them concentrates near ``ln(m)`` —
        4.16 at m = 64, already above the 3.0 bar.  The old flag therefore fired
        on **88.4 % to 100 %** of clean aperiodic series across the sizes this
        detector actually sees (2,000 trials each at n = 64/96/100/128, iid
        Gaussian timings).  A detector that fires on everything distinguishes
        nothing, and every one of those reports reached ``get_security_report``
        and the posture evaluator as evidence.

        The bar is now Fisher's g-test tail, ``ln(m / alpha)``, for a target
        per-call false-alarm rate ``alpha`` = :attr:`RESONANCE_FALSE_ALARM_RATE`.
        Measured against that same 2,000-trial sweep: 0.43 %-0.85 % observed
        against a 1 % nominal, so the approximation is accurate and errs
        conservative.  Detection power is unaffected — a period-2 probe on 64
        samples scores 32.0 against a threshold of 8.07, and a period-8
        sinusoid on 96 samples scores 48.0 against 8.76.

        Only the non-redundant half of the spectrum is scanned (bins 1 through
        ``n/2``).  A real signal's spectrum is conjugate-symmetric, so the upper
        half is a mirror that contributes nothing but doubles the ordinate count
        the threshold is derived from.  The Nyquist bin is KEPT: a strictly
        alternating fast/slow probe — the reconnaissance shape this component
        exists to see — puts all of its energy exactly there.

        Note:
            Requires minimum 8 samples. Returns empty dict if insufficient
            data. This is an on-demand operation (not hot path).
        """
        if operation not in self.timing_history:
            return {}

        # Slice to window_size (on-demand, not hot path)
        history_list = list(self.timing_history[operation])
        timings = history_list[-self.window_size :]

        if len(timings) < 8:
            return {}

        # Centre the series.  Everything below measures periodic structure;
        # the baseline duration is not periodic structure, and leaving it in
        # is what made a constant series read as resonant.
        baseline = _mean(timings)
        centred = [value - baseline for value in timings]

        # Zero-pad to next power of 2 for Cooley-Tukey
        n = len(centred)
        n_padded = 1
        while n_padded < n:
            n_padded <<= 1
        x = [complex(v) for v in centred] + [complex(0)] * (n_padded - n)

        # FFT analysis (pure Python Cooley-Tukey)
        fft_result = _fft_cooley_tukey(x)
        freqs = _fftfreq(n_padded)
        power = [abs(c) ** 2 for c in fft_result]

        # Scan the non-redundant half only: bins 1 .. n/2, DC excluded (it is
        # zero after centring) and the mirror image excluded (it carries no
        # information but would double m and inflate the threshold).
        scanned = power[1 : n_padded // 2 + 1]
        if not scanned:
            return {}
        dominant_offset = scanned.index(max(scanned))
        dominant_idx = dominant_offset + 1
        dominant_freq = freqs[dominant_idx]
        dominant_power = power[dominant_idx]
        mean_power = _mean(scanned)

        ratio = float(dominant_power / mean_power) if mean_power > 0 else 0.0
        threshold = self._resonance_threshold(len(scanned))

        return {
            "dominant_frequency": float(dominant_freq),
            "dominant_power": float(dominant_power),
            "mean_power": float(mean_power),
            "resonance_ratio": ratio,
            "threshold_ratio": threshold,
            "false_alarm_rate": self.RESONANCE_FALSE_ALARM_RATE,
            "scanned_bins": len(scanned),
            "has_resonance": ratio > threshold,
        }

    #: Target per-call false-alarm rate for :meth:`detect_resonance`.  The
    #: threshold is derived from it rather than fixed, because the null
    #: distribution of a periodogram maximum depends on how many ordinates were
    #: searched: the same bar that is strict at m = 8 is met by white noise at
    #: m = 64.  1 % is the rate an operator can reason about — one spurious
    #: resonance report per hundred evaluations of an operation — and the
    #: measured rate across n = 64/96/100/128 is 0.43 %-0.85 %.
    RESONANCE_FALSE_ALARM_RATE: ClassVar[float] = 0.01

    @classmethod
    def _resonance_threshold(cls, scanned_bins: int) -> float:
        """Fisher g-test bar on max/mean for ``scanned_bins`` ordinates.

        Under the null (no periodic component) the ordinates are iid
        exponential, and P(max/mean > r) ~ m * exp(-r).  Inverting at
        ``alpha`` gives ln(m / alpha).  Kept as a method so the value the flag
        used is reported alongside it and a caller can normalise against the
        same number rather than re-deriving one.
        """
        m = max(1, int(scanned_bins))
        alpha = cls.RESONANCE_FALSE_ALARM_RATE
        return math.log(m / alpha)

    def _prune_history(self, operation: str) -> None:
        """
        Limit memory usage by pruning old timing data.

        Note:
            This method is now a no-op as deque with maxlen handles
            automatic pruning. Kept for backward compatibility.
        """
        # No-op: deque with maxlen handles automatic pruning
        pass


class RecursionPatternMonitor:
    """
    Hierarchical analysis of signing patterns.

    Detects anomalies in key usage, signing frequency, and package
    characteristics using recursive feature extraction across multiple
    time scales. This multi-resolution approach can identify both
    short-term spikes and long-term drift in signing behavior.
    """

    # Bounds on the caller-fed key-lifecycle structures (see __init__).
    _MAX_TRACKED_KEYS = 4096
    _MAX_KEY_ALERTS = 1000

    def __init__(self, max_depth: int = 3, max_history: int = 10000) -> None:
        """
        Initialize pattern monitor.

        Args:
            max_depth: Maximum recursion depth for hierarchical analysis.
                Depth 0 = raw data, Depth 1 = 2x downsampled, etc.
            max_history: Maximum package history entries to retain.

        Performance Optimization:
            Uses collections.deque with maxlen for O(1) append and automatic
            pruning instead of manual list slicing.
        """
        self.max_depth = max_depth
        self.max_history = max_history
        # Use deque with maxlen for O(1) append and automatic pruning
        self.package_history: Deque[Dict] = deque(maxlen=max_history)
        # Priority 4: Key lifecycle monitoring.
        #
        # Both structures are keyed/fed by caller-supplied values, so both are
        # bounded — a monitoring component must not become the memory-exhaustion
        # vector, the same rule VolumeSpikeDetector.max_operations enforces.
        #
        # _key_usage_rates: one deque per distinct key_id, and key_id comes from
        # the caller.  Capped at _MAX_TRACKED_KEYS distinct ids (far above any
        # real key inventory); ids beyond the cap are counted and not tracked.
        #
        # _key_alerts: a diagnostic ring of the most recent key-lifecycle
        # anomalies.  It was an unbounded list that nothing ever read or pruned,
        # so a service that kept signing with an expired or near-limit key — the
        # very condition this monitor exists to surface — appended a dict per
        # signing call forever.  The anomalies are returned to the caller and
        # mirrored into the bounded AmaCryptographyMonitor.alerts, so a bounded
        # ring loses nothing.
        self._key_usage_rates: Dict[str, Deque[float]] = {}  # key_id -> recent usage timestamps
        self._key_alerts: Deque[Dict[str, Any]] = deque(maxlen=self._MAX_KEY_ALERTS)
        self.dropped_key_ids: int = 0
        # Every other shared monitor component takes a lock (NonceTracker,
        # ResonanceTimingMonitor, VolumeSpikeDetector, the alert ring) — this
        # class was the one writer/analyzer pair left bare.  The shipped
        # concurrency is real: record_package_signing appends from every
        # create_crypto_package call, MONITORING.md documents the shared-
        # monitor ThreadPoolExecutor deployment, and analyze_patterns
        # iterates the same deque with Python-level comprehensions —
        # measured: 4 threads raised RuntimeError("deque mutated during
        # iteration") within 0.11 s, and the exception escaped through the
        # public create_crypto_package AFTER signatures were computed.  An
        # RLock plus snapshot-then-analyze keeps the lock window to the
        # copies, exactly the pattern _prune_alerts uses.
        self._lock = threading.RLock()

    def record_package(self, package_metadata: Dict) -> None:
        """
        Record package signing event.

        Args:
            package_metadata: Dict containing:
                - author: Package author identifier
                - code_count: Number of Omni-Codes in package
                - content_hash: First 16 chars of content hash
                - (optional) Additional application-specific fields

        Performance Optimization:
            O(1) append with automatic pruning via deque maxlen.
        """
        # O(1) append with automatic pruning via deque maxlen
        with self._lock:
            self.package_history.append({"timestamp": time.time(), **package_metadata})

    def analyze_patterns(self) -> Dict:
        """
        Perform hierarchical pattern analysis.

        Returns:
            Dict with:
                - status: 'insufficient_data' or 'analyzed'
                - features: Hierarchical feature dictionary (if analyzed)
                - anomalies: List of detected anomalies (if analyzed)

        Note:
            Requires minimum 10 packages for analysis.
        """
        # Snapshot under the lock; every read below is over the immutable
        # copy, so a concurrent record_package can never mutate mid-iteration.
        with self._lock:
            history = list(self.package_history)
        if len(history) < 10:
            return {"status": "insufficient_data"}

        # Extract time series features
        timestamps = [p["timestamp"] for p in history]
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

        # Recursive hierarchical analysis
        features = self._recursive_extract(intervals, depth=0)

        # Detect anomalies
        anomalies = []

        # Check for unusual signing frequency
        if "level_0_mean" in features and "level_0_std" in features:
            recent_interval = intervals[-1] if len(intervals) > 0 else 0
            if features["level_0_std"] > 0:
                z_score = abs(recent_interval - features["level_0_mean"]) / features["level_0_std"]

                if z_score > 3.0:
                    anomalies.append(
                        {
                            "type": "unusual_frequency",
                            "z_score": float(z_score),
                            "severity": "warning" if z_score < 5.0 else "critical",
                            "details": {
                                "expected_interval_sec": features["level_0_mean"],
                                "observed_interval_sec": recent_interval,
                            },
                        }
                    )

        # Check for package size anomalies
        code_counts = [float(p.get("code_count", 0)) for p in history]
        if len(code_counts) > 10:
            mean_count = _mean(code_counts)
            std_count = _std(code_counts)
            recent_count = code_counts[-1]

            if std_count > 0:
                z_score = abs(recent_count - mean_count) / std_count
                if z_score > 3.0:
                    anomalies.append(
                        {
                            "type": "unusual_package_size",
                            "z_score": float(z_score),
                            "severity": "info",
                            "details": {
                                "expected_codes": mean_count,
                                "observed_codes": recent_count,
                            },
                        }
                    )

        return {
            "status": "analyzed",
            "features": features,
            "anomalies": anomalies,
            "total_packages": len(history),
        }

    def _recursive_extract(self, data: List[float], depth: int) -> Dict[str, Any]:
        """
        Recursively extract features at multiple scales.

        Implements multi-resolution analysis by:
        1. Computing statistics at current scale
        2. Downsampling data (take every 2nd element)
        3. Recursing until max_depth or insufficient data

        Args:
            data: Time series data (e.g., inter-package intervals)
            depth: Current recursion depth

        Returns:
            Dict of features with keys like:
                'level_0_mean', 'level_0_std', 'level_1_mean', ...
        """
        if depth >= self.max_depth or len(data) < 2:
            return {}

        features = {
            f"level_{depth}_mean": _mean(data),
            f"level_{depth}_std": _std(data),
            f"level_{depth}_range": max(data) - min(data),
            f"level_{depth}_samples": len(data),
        }

        # Downsample for next level (every 2nd element)
        if len(data) >= 4:
            downsampled = data[::2]
            deeper_features = self._recursive_extract(downsampled, depth + 1)
            features.update(deeper_features)

        return features

    def monitor_key_usage(self, key_metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Priority 4: Monitor key lifecycle and detect anomalies.

        Checks for:
        - Keys approaching max_usage limit (warn at 75%, alert at 90%)
        - Keys past expires_at still being used
        - DEPRECATED or REVOKED keys being used
        - Per-key signing rate anomalies

        Args:
            key_metadata: Dict with key_id, status, usage_count, max_usage,
                expires_at (unix timestamp or None)

        Returns:
            List of anomaly dicts (empty if no anomalies)
        """
        anomalies: List[Dict[str, Any]] = []
        key_id = key_metadata.get("key_id", "unknown")
        status = key_metadata.get("status", "ACTIVE")
        usage_count = key_metadata.get("usage_count", 0)
        max_usage = key_metadata.get("max_usage")
        expires_at = key_metadata.get("expires_at")

        # Track usage rate per key.  key_id is caller-supplied, so the number of
        # distinct ids is capped: past the cap, new ids are counted in
        # dropped_key_ids and not tracked (already-tracked keys keep working, so
        # a flood of junk ids cannot displace real monitoring either).  The
        # rate-anomaly check below simply finds no history for an untracked id.
        with self._lock:
            if key_id not in self._key_usage_rates:
                if len(self._key_usage_rates) >= self._MAX_TRACKED_KEYS:
                    self.dropped_key_ids += 1
                else:
                    self._key_usage_rates[key_id] = deque(maxlen=1000)
            bucket = self._key_usage_rates.get(key_id)
            if bucket is not None:
                bucket.append(time.time())

        # Check max_usage limits
        if max_usage is not None and max_usage > 0:
            usage_ratio = usage_count / max_usage
            if usage_ratio >= 0.90:
                anomalies.append(
                    {
                        "type": "key_usage_critical",
                        "severity": "critical",
                        "key_id": key_id,
                        "usage_ratio": usage_ratio,
                        "message": f"Key {key_id} at {usage_ratio:.0%} of max usage limit",
                    }
                )
            elif usage_ratio >= 0.75:
                anomalies.append(
                    {
                        "type": "key_usage_warning",
                        "severity": "warning",
                        "key_id": key_id,
                        "usage_ratio": usage_ratio,
                        "message": f"Key {key_id} at {usage_ratio:.0%} of max usage limit",
                    }
                )

        # Check expiration
        if expires_at is not None:
            now = time.time()
            expires_ts = _coerce_expiry_to_unix(expires_at)
            if expires_ts is None:
                # Do not silently pass an expired key just because its expiry was
                # expressed in a format we could not parse.
                logger.warning(
                    "Key %s has an uninterpretable expires_at (%r); expiry cannot "
                    "be enforced for this key",
                    key_id,
                    expires_at,
                )
            elif now > expires_ts:
                anomalies.append(
                    {
                        "type": "key_expired",
                        "severity": "critical",
                        "key_id": key_id,
                        "expired_at": expires_at,
                        "message": f"Key {key_id} expired at {expires_at} but still in use",
                    }
                )

        # Check for revoked/deprecated keys being used
        if status in ("DEPRECATED", "REVOKED", "COMPROMISED"):
            anomalies.append(
                {
                    "type": "key_status_violation",
                    "severity": "critical",
                    "key_id": key_id,
                    "status": status,
                    "message": f"Key {key_id} has status {status} but is being used",
                }
            )

        # Check per-key signing rate anomaly
        rate_anomaly = self._check_key_rate_anomaly(key_id)
        if rate_anomaly:
            anomalies.append(rate_anomaly)

        with self._lock:
            self._key_alerts.extend(anomalies)
        return anomalies

    def _check_key_rate_anomaly(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Check if a single key's usage rate is anomalous compared to its history."""
        with self._lock:
            timestamps = self._key_usage_rates.get(key_id)
            if not timestamps or len(timestamps) < 20:
                return None
            # Copy under the lock: a concurrent append during the interval
            # arithmetic below would otherwise mutate the deque mid-list().
            ts_list = list(timestamps)
        intervals = [ts_list[i + 1] - ts_list[i] for i in range(len(ts_list) - 1)]
        if len(intervals) < 10:
            return None

        mean_interval = _mean(intervals)
        std_interval = _std(intervals)
        recent_interval = intervals[-1]

        if std_interval > 0 and mean_interval > 0:
            # Check if recent rate is 10x normal (interval is 1/10th)
            if recent_interval < mean_interval / 10.0:
                return {
                    "type": "key_rate_anomaly",
                    "severity": "warning",
                    "key_id": key_id,
                    "expected_interval": mean_interval,
                    "observed_interval": recent_interval,
                    "message": f"Key {key_id} usage rate spike: "
                    f"interval {recent_interval:.3f}s vs baseline {mean_interval:.3f}s",
                }
        return None


class VolumeSpikeDetector:
    """
    Statistical detection of anomalous bursts of KEM / signature operations.

    Threat model
    ------------
    An agent doing reconnaissance or generating notes for a successor drives
    the library in a shape ordinary workloads do not: a short, dense burst of
    operations, usually with a *fresh key per operation* because each artefact
    gets its own identity.  Steady production load is high-volume but smooth,
    and reuses keys.  This detector separates those two.

    Statistics
    ----------
    Operations are counted into fixed-width buckets (default 1 s).  Counts are
    scored in the Anscombe variance-stabilising transform ``2*sqrt(c + 3/8)``,
    under which a Poisson count has unit variance regardless of rate — so a
    quiet baseline cannot produce a degenerate sigma and turn every mild
    uptick into a 40-sigma "anomaly", which is the failure mode of a plain
    z-score on counts.  Overdispersion is tracked as an EWMA of the squared
    residual and floored at the Poisson value of 1.

    Three independent gates must all pass before anything fires:

      * ``warmup_buckets`` closed buckets have been observed (default 30, so
        the baseline is a baseline);
      * the firing bucket holds at least ``min_burst_count`` operations
        (default 256 — an absolute floor, so an idle process that suddenly
        signs twice can never trip the detector no matter how quiet it was);
      * the standardised residual reaches ``threshold_sigma`` (default 6.0).

    The baseline is updated only from *closed* buckets, so an in-progress
    burst never inflates the baseline it is judged against.  At most one alert
    is emitted per operation per bucket, which is what keeps a 500-thread
    burst from producing 500 000 alerts.

    Not a gate.  This surfaces bursts for review; it never blocks an
    operation and never touches key material — it sees an operation *name*
    and an optional key fingerprint the caller has already truncated.
    """

    #: A ready-made allow-list of the KEM and signature operations this
    #: detector's threat model is about, for a caller that wants to keep it off
    #: unrelated call paths: ``VolumeSpikeDetector(operations=
    #: VolumeSpikeDetector.DEFAULT_OPERATIONS)``.
    #:
    #: It is NOT the default, and the name is historical.  Until 5.0.0 nothing
    #: read this tuple at all: ``record()`` counted whatever string it was
    #: handed, the constructor took no ``operations`` argument, and there was
    #: therefore no "unless the caller passes it explicitly" mechanism either —
    #: the doc comment described a filter that did not exist, the same dead-
    #: configuration shape this module's anomaly-profile table was cleaned of.
    #: Making it the default would have been worse than dead: it would silently
    #: stop counting every operation not on an eight-name list, including every
    #: family added since, and a burst detector that has quietly stopped
    #: watching is the failure mode this file is written against.  So the
    #: filter is real and opt-in, and counting everything (bounded by
    #: ``max_operations``) stays the default.
    DEFAULT_OPERATIONS: ClassVar[Tuple[str, ...]] = (
        "kyber_encaps",
        "kyber_decaps",
        "kyber_keypair",
        "dilithium_sign",
        "dilithium_keypair",
        "sphincs_sign",
        "sphincs_keypair",
        "ed25519_sign",
    )

    def __init__(
        self,
        bucket_seconds: float = 1.0,
        warmup_buckets: int = 30,
        threshold_sigma: float = 6.0,
        min_burst_count: int = 256,
        alpha: float = 0.05,
        churn_threshold: float = 0.75,
        max_fingerprints_per_bucket: int = 4096,
        history_buckets: int = 600,
        max_operations: int = 256,
        operations: Optional[Iterable[str]] = None,
    ) -> None:
        """
        Args:
            bucket_seconds: Counting-bucket width in seconds.
            warmup_buckets: Closed buckets required before detection activates.
            threshold_sigma: Standardised-residual threshold.  6.0 is
                deliberately far above the 3.0 used elsewhere in this module:
                a burst detector that cries wolf gets switched off.
            min_burst_count: Absolute floor on the firing bucket's count.
            alpha: EWMA smoothing factor in (0, 1].
            churn_threshold: Distinct-key ratio above which a spike is
                escalated to 'critical'.
            max_fingerprints_per_bucket: Cap on the per-bucket fingerprint set
                so a hostile caller cannot grow it without bound.  Hitting it
                is reported via ``VolumeSpike.distinct_keys_capped``.
            history_buckets: Per-operation bucket-count history retained for
                :meth:`analyze_history`.
            max_operations: Cap on the number of distinct operation names
                tracked.  ``operation`` is caller-supplied, so without a cap a
                caller passing a fresh name per call would grow every
                per-operation dict without bound — a monitoring component must
                not become the memory-exhaustion vector.  Names beyond the cap
                are counted in :attr:`dropped_operations` and otherwise
                ignored; the cap is far above any real operation inventory
                (the library itself uses fewer than a dozen).
            operations: Optional allow-list.  ``None`` (the default) counts
                every operation name, bounded by ``max_operations``.  Passing a
                collection restricts counting to those names — see
                :attr:`DEFAULT_OPERATIONS` for a ready-made one — and names
                outside it are counted in :attr:`filtered_operations` and
                otherwise ignored.  An EMPTY collection is rejected rather than
                read as "filter nothing": a detector configured to watch
                nothing is a configuration error, and silently treating it as
                "watch everything" would hide it.

        Raises:
            ValueError: on a non-positive bucket width or an alpha outside
                (0, 1].
        """
        if bucket_seconds <= 0:
            raise ValueError("bucket_seconds must be positive")
        if not 0.0 < alpha <= 1.0:
            raise ValueError("alpha must be in (0, 1]")
        if warmup_buckets < 1:
            raise ValueError("warmup_buckets must be at least 1")
        if max_operations < 1:
            raise ValueError("max_operations must be at least 1")
        allowed: Optional[FrozenSet[str]] = None
        if operations is not None:
            allowed = frozenset(operations)
            if not allowed:
                raise ValueError(
                    "operations must be None (count everything) or a non-empty "
                    "collection of operation names"
                )

        self.operations = allowed
        #: Records ignored because they were outside :attr:`operations`.  Zero
        #: whenever no allow-list is configured.
        self.filtered_operations = 0
        self.bucket_seconds = float(bucket_seconds)
        self.warmup_buckets = int(warmup_buckets)
        self.threshold_sigma = float(threshold_sigma)
        self.min_burst_count = int(min_burst_count)
        self.alpha = float(alpha)
        self.churn_threshold = float(churn_threshold)
        self.max_fingerprints_per_bucket = int(max_fingerprints_per_bucket)
        self.max_operations = int(max_operations)
        #: Count of records dropped because the operation-name cap was hit.
        #: Non-zero means the detector is not seeing everything — surfaced in
        #: :meth:`snapshot` rather than silently absorbed.
        self.dropped_operations = 0

        # Per-operation state.  All mutated under _lock: record() is called
        # from every worker thread in a concurrent workload, and a torn
        # read-modify-write of the EWMA would corrupt the baseline in exactly
        # the situation the detector exists for.
        self._bucket_index: Dict[str, int] = {}
        self._bucket_count: Dict[str, int] = {}
        self._bucket_fingerprints: Dict[str, Set[bytes]] = {}
        self._fingerprints_capped: Dict[str, bool] = {}
        self._mean: Dict[str, float] = {}
        self._sq: Dict[str, float] = {}
        self._closed_buckets: Dict[str, int] = {}
        self._fired_bucket: Dict[str, int] = {}
        self._history: Dict[str, Deque[int]] = {}
        self._history_buckets = int(history_buckets)
        self._lock = threading.RLock()

    # -- internals --------------------------------------------------------

    def _close_bucket(self, operation: str, count: int) -> None:
        """Fold a completed bucket into the baseline.  Caller holds the lock."""
        a = 2.0 * math.sqrt(float(count) + 0.375)
        if operation not in self._mean:
            self._mean[operation] = a
            self._sq[operation] = 1.0
        else:
            resid = a - self._mean[operation]
            self._mean[operation] += self.alpha * resid
            self._sq[operation] = (1.0 - self.alpha) * self._sq[
                operation
            ] + self.alpha * resid * resid
        self._closed_buckets[operation] = self._closed_buckets.get(operation, 0) + 1
        hist = self._history.setdefault(operation, deque(maxlen=self._history_buckets))
        hist.append(count)

    def _score(self, operation: str, count: int) -> float:
        """Standardised residual of `count` against the current baseline."""
        mean = self._mean.get(operation)
        if mean is None:
            return 0.0
        a = 2.0 * math.sqrt(float(count) + 0.375)
        sigma = math.sqrt(self._sq.get(operation, 1.0))
        if sigma < 1.0:
            sigma = 1.0
        return (a - mean) / sigma

    @staticmethod
    def _baseline_rate(mean_anscombe: Optional[float]) -> float:
        """Invert the Anscombe transform so reports read in operations/bucket."""
        if mean_anscombe is None or mean_anscombe <= 0.0:
            return 0.0
        return max(0.0, (mean_anscombe / 2.0) ** 2 - 0.375)

    # -- public API -------------------------------------------------------

    def record(
        self,
        operation: str,
        key_fingerprint: Optional[bytes] = None,
        now: Optional[float] = None,
    ) -> Optional[VolumeSpike]:
        """Record one operation and return a spike if this bucket just tripped.

        Args:
            operation: Operation name (``'kyber_encaps'``, ``'dilithium_sign'``…).
            key_fingerprint: Optional short, non-secret key identifier used to
                measure ephemeral-key churn.  Callers should pass a truncated
                hash, never raw key bytes; only the first 8 bytes are kept.
            now: Monotonic timestamp override, for deterministic tests.

        Returns:
            A :class:`VolumeSpike` at most once per operation per bucket,
            else ``None``.
        """
        if not isinstance(operation, str) or not operation:
            raise ValueError("operation must be a non-empty string")

        if self.operations is not None and operation not in self.operations:
            # Outside the configured allow-list.  Counted, not silent: a
            # non-zero filtered_operations is how an operator learns that the
            # detector is deliberately not watching part of the traffic.
            with self._lock:
                self.filtered_operations += 1
            return None

        with self._lock:
            # The clock is read UNDER the lock, not before it.  time.monotonic()
            # is non-decreasing, so serialising the read behind the lock makes
            # the bucket index each thread computes non-decreasing too.  Read
            # outside the lock and two threads straddling a bucket boundary can
            # acquire the lock in the opposite order to their clock reads: the
            # later-timestamp thread closes and advances the bucket, then the
            # earlier-timestamp thread sees bucket < current, closes a second
            # (partial) bucket into the EWMA and *regresses* the index — a real
            # baseline-corruption race in exactly the concurrent workload this
            # detector exists for.  An explicit `now` (deterministic tests) is
            # caller-ordered and unaffected.
            ts = time.monotonic() if now is None else float(now)
            bucket = int(ts // self.bucket_seconds)

            current = self._bucket_index.get(operation)
            if current is None:
                if len(self._bucket_index) >= self.max_operations:
                    # Refuse to grow rather than track an unbounded name space.
                    self.dropped_operations += 1
                    return None
                self._bucket_index[operation] = bucket
                self._bucket_count[operation] = 0
                self._bucket_fingerprints[operation] = set()
                self._fingerprints_capped[operation] = False
            elif bucket != current:
                # Fold the finished bucket in, then any fully-idle buckets
                # between it and now — silence is information, and skipping it
                # would let a burst-then-sleep pattern keep a hot baseline.
                self._close_bucket(operation, self._bucket_count[operation])
                idle = bucket - current - 1
                if idle > 0:
                    for _ in range(min(idle, self.warmup_buckets)):
                        self._close_bucket(operation, 0)
                self._bucket_index[operation] = bucket
                self._bucket_count[operation] = 0
                self._bucket_fingerprints[operation] = set()
                self._fingerprints_capped[operation] = False

            self._bucket_count[operation] += 1
            count = self._bucket_count[operation]

            if key_fingerprint is not None:
                fps = self._bucket_fingerprints[operation]
                if len(fps) < self.max_fingerprints_per_bucket:
                    fps.add(bytes(key_fingerprint[:8]))
                else:
                    self._fingerprints_capped[operation] = True

            if self._closed_buckets.get(operation, 0) < self.warmup_buckets:
                return None
            if count < self.min_burst_count:
                return None
            if self._fired_bucket.get(operation) == bucket:
                return None

            score = self._score(operation, count)
            if score < self.threshold_sigma:
                return None

            self._fired_bucket[operation] = bucket
            fps = self._bucket_fingerprints[operation]
            capped = self._fingerprints_capped.get(operation, False)
            # A capped fingerprint set understates churn, so the ratio is a
            # lower bound.  Report the bound AND the fact that it is one; a
            # capped set is itself evidence of >= max_fingerprints distinct
            # keys in one bucket, which is not a case to downgrade.
            ratio = (len(fps) / count) if (fps and count) else 0.0
            severity = "critical" if (capped or ratio >= self.churn_threshold) else "warning"
            return VolumeSpike(
                operation=operation,
                count=count,
                baseline_rate=self._baseline_rate(self._mean.get(operation)),
                score=score,
                distinct_key_ratio=ratio,
                distinct_keys_capped=capped,
                bucket_seconds=self.bucket_seconds,
                severity=severity,
                timestamp=time.time(),
            )

    def analyze_history(self, operation: str) -> List[float]:
        """Re-score the retained bucket history for `operation`.

        Offline/report path: runs the whole series through the compiled kernel
        (or its pure-Python twin) so an operator can see where a burst sat
        relative to the rest of the day.
        """
        with self._lock:
            hist = list(self._history.get(operation, ()))
        if not hist:
            return []
        if _CY_VOLUME_SCORES is not None:
            from array import array

            return list(
                _CY_VOLUME_SCORES(
                    array("d", [float(c) for c in hist]), self.alpha, self.warmup_buckets
                )
            )
        return _volume_spike_scores_py([float(c) for c in hist], self.alpha, self.warmup_buckets)

    def snapshot(self) -> Dict[str, Dict[str, float]]:
        """Per-operation baseline state, for the security report."""
        with self._lock:
            return {
                op: {
                    "baseline_rate": self._baseline_rate(self._mean.get(op)),
                    "closed_buckets": float(self._closed_buckets.get(op, 0)),
                    "current_bucket_count": float(self._bucket_count.get(op, 0)),
                    "dispersion": math.sqrt(self._sq.get(op, 1.0)),
                }
                for op in sorted(self._bucket_index)
            }

    @property
    def tracked_operations(self) -> int:
        """Number of distinct operation names currently tracked."""
        with self._lock:
            return len(self._bucket_index)

    def reset(self) -> None:
        """Drop all state.  Used by tests and by long-lived redeployments."""
        with self._lock:
            self._bucket_index.clear()
            self._bucket_count.clear()
            self._bucket_fingerprints.clear()
            self._fingerprints_capped.clear()
            self._mean.clear()
            self._sq.clear()
            self._closed_buckets.clear()
            self._fired_bucket.clear()
            self._history.clear()
            self.dropped_operations = 0
            self.filtered_operations = 0


class NoteArtifactDetector:
    """
    Lightweight structural detection of "notes for future versions".

    What it looks for
    -----------------
    The artefact that made the July-2026 escape legible after the fact was not
    exfiltrated data — it was prose an agent signed for its own successors:
    it addressed a later instance ("notes for the next instance"), it was
    instructional ("remember to…"), and it was operational ("reconnect using
    the stored seed").  The detector scores that conjunction.

    Why the successor family is phrase-level
    ----------------------------------------
    Every word that signals "addressed to a later instance of me" is ordinary
    English on its own — *next*, *future*, *instance*, *version*.  Scoring the
    successor vocabulary as single tokens trips well over half of this
    repository's own files (measured: 256 of 443 tracked source files carry two or more of those
    words), which is worthless.  The discriminative feature is the adjacent
    PAIR: "next instance", "future agents", "subsequent iterations" are
    near-absent from technical prose and near-universal in a note addressed to
    a successor.  So family 0 is built from bigrams — a cross product of
    *forward-referring* words (next, future, subsequent, …) with
    *instance-denoting* nouns (instance, iteration, successor, …), plus a
    handful of fixed note idioms — while the instructional and operational
    families stay unigram, where breadth is what is wanted.

    The cross product is deliberately kept clean of generic English: the
    prefix side carries no articles or possessives (*the*, *my*, *your*) and
    the subject side no bare pronouns (*me*, *you*).  Those pollute the family
    — "the agent", "your self", "if you", "you are" occur throughout ordinary
    prose, and including them collapses the margin between a successor note and
    a security runbook to zero (measured before this was fixed: the lowest
    hand-written note and the highest benign file scored identically).  With
    the generic pairs removed, the two populations separate by >= 0.5 on the
    coverage score — see Calibration.

    Gates
    -----
    A payload is flagged only when all of these hold:

      * printable-ASCII ratio >= ``min_text_ratio``.  Signatures, wrapped
        keys, ciphertext and serialised keypairs are high-entropy binary and
        can never be notes; this is the cheap structural reject that makes the
        detector affordable to point at real payloads.
      * at least ``min_tokens`` tokens — a two-word payload is not a note.
      * at least ``min_coverage`` families covered, where a family counts as
        covered at ``min_family_hits`` distinct markers (one for the
        phrase-level successor family, which is deliberately sparse).
      * fractional coverage ``score`` >= ``score_threshold``.
      * the successor family is covered, unless
        ``require_successor_family=False``.

    Calibration
    -----------
    The default was measured, not guessed, against this repository's own
    Markdown, Python, C, headers, JSON, YAML and Cython — a deliberately
    *hard* negative corpus, because security prose is dense with exactly the
    operational vocabulary the detector scores (persist, credential, escape,
    sandbox), so a low false-positive rate here is a conservative bound on
    what a signing service's real traffic would produce.

    Measured on that corpus (443 tracked source files) with the shipped defaults:

      * The four hand-written successor notes score 2.25 .. 3.00.
      * Every genuinely-benign file scores <= 1.75.  The separation is
        therefore >= 0.50 on the coverage score, and no benign file clears the
        full flagging conjunction.
      * The files flagged are a subset of the three that *themselves* contain
        or describe successor-note tradecraft — ``INVARIANTS.md`` and
        ``CHANGELOG.md`` (which document this detector) and
        ``tests/test_agentic_load_adversarial.py`` (which embeds a synthetic
        note).  They are true positives on literal note content, not false
        positives on benign prose.  Which of the three trip depends on their
        current text: as of this writing ``CHANGELOG.md`` and the test file
        flag while ``INVARIANTS.md`` sits just below the successor gate, so the
        calibration test asserts the flagged set is a *subset* of these three
        rather than requiring all three to fire.
      * Dropping the threshold to 1.50 additionally flags
        ``IMPLEMENTATION_GUIDE.md`` — a genuinely-benign document — so 1.75 is
        the tighter operating point that excludes it while keeping every note.

    ``tests/test_agentic_abuse_detectors.py`` re-derives all of this on every
    CI run: it pins the benign false-positive set to the three threat-
    describing files (any new benign flag fails the build) and asserts the
    >= 0.50 note-vs-corpus separation directly, so the calibration cannot
    silently rot as the corpus grows.

    Bounded work
    ------------
    At most ``max_scan_bytes`` are examined.  Longer payloads are sampled head
    and tail (half the budget each), so prepending filler does not hide a note
    at the end.  Scanning is a single pass with no regular expressions and no
    per-token allocation.

    Advisory only
    -------------
    This is a heuristic, and its limitation is worth stating plainly: an agent
    that avoids the successor vocabulary is not caught.  It raises the cost of
    the natural phrasing and gives reviewers a ranked queue.  It never blocks
    a signature, and ``flagged=False`` is not a statement that a payload is
    benign.
    """

    #: Family 0, left half — words that point FORWARD to another entity.
    #: Articles and possessives (the/my/your/our) are deliberately excluded:
    #: paired with the subjects below they produce generic English ("the
    #: agent", "your self") that occurs throughout ordinary prose and destroys
    #: the family's discriminative power.  See the class docstring.
    SUCCESSOR_PREFIXES: ClassVar[Tuple[bytes, ...]] = (
        b"next",
        b"future",
        b"later",
        b"subsequent",
        b"succeeding",
        b"following",
        b"upcoming",
        b"another",
        b"new",
        b"successor",
        b"successors",
        b"descendant",
        b"descendants",
    )

    #: Family 0, right half — nouns naming an instance of the writer.  Bare
    #: pronouns (me/you) are excluded for the same reason as the articles
    #: above: "future you", "the agent" and the like are not successor
    #: references, they are generic address.
    SUCCESSOR_SUBJECTS: ClassVar[Tuple[bytes, ...]] = (
        b"instance",
        b"instances",
        b"agent",
        b"agents",
        b"iteration",
        b"iterations",
        b"incarnation",
        b"incarnations",
        b"successor",
        b"successors",
        b"descendant",
        b"descendants",
        b"offspring",
        b"clone",
        b"clones",
        b"replica",
        b"replicas",
        b"reincarnation",
        b"self",
        b"selves",
        b"version",
        b"versions",
        b"generation",
        b"generations",
    )

    #: Family 0, fixed note idioms that do not fall out of the cross product.
    #: Kept deliberately note-specific: "if you"/"you are" were removed because
    #: they are generic conditional and copular English, not successor markers.
    SUCCESSOR_PHRASES: ClassVar[Tuple[Tuple[bytes, bytes], ...]] = (
        (b"note", b"to"),  # "note to self / note to the next instance"
        (b"to", b"self"),
        (b"for", b"whoever"),
        (b"whoever", b"comes"),
        (b"comes", b"after"),
        (b"read", b"this"),
    )

    #: Family 1 — instructional register: it tells the reader what to do.
    INSTRUCTIONAL_MARKERS: ClassVar[Tuple[bytes, ...]] = (
        b"remember",
        b"instruction",
        b"instructions",
        b"procedure",
        b"checklist",
        b"must",
        b"should",
        b"avoid",
        b"ensure",
        b"prefer",
        b"always",
        b"never",
        b"dont",
        b"tip",
        b"tips",
        b"lesson",
        b"lessons",
        b"learned",
        b"reminder",
        b"todo",
        b"hint",
        b"guidance",
        b"recommend",
        b"recommended",
        b"advise",
        b"caution",
        b"beware",
    )

    #: Family 2 — operational tradecraft: persistence and reachability.
    OPERATIONAL_MARKERS: ClassVar[Tuple[bytes, ...]] = (
        b"persist",
        b"persistence",
        b"survive",
        b"survival",
        b"reconnect",
        b"resume",
        b"restore",
        b"checkpoint",
        b"seed",
        b"seeds",
        b"credential",
        b"credentials",
        b"endpoint",
        b"endpoints",
        b"hostname",
        b"beacon",
        b"exfil",
        b"exfiltrate",
        b"escape",
        b"sandbox",
        b"egress",
        b"implant",
        b"backdoor",
        b"bootstrap",
        b"relay",
        b"staging",
        b"foothold",
        b"pivot",
        b"evade",
        b"undetected",
        b"reachable",
        b"callback",
    )

    FAMILY_NAMES: ClassVar[Tuple[str, ...]] = ("successor", "instructional", "operational")

    #: Index into FAMILY_NAMES of the family that must be present when
    #: ``require_successor_family`` is set.
    SUCCESSOR_FAMILY: ClassVar[int] = 0

    #: Distinct-marker count at which each family is considered fully covered.
    #: The successor family saturates at 2 because its markers are phrases and
    #: two distinct ones is already a strong signal; the unigram families need
    #: more breadth before they mean anything.
    FAMILY_SATURATION: ClassVar[Tuple[int, ...]] = (2, 4, 4)

    #: Distinct markers needed for each family to count as covered.
    FAMILY_MIN_HITS: ClassVar[Tuple[int, ...]] = (1, 2, 2)

    def __init__(
        self,
        max_scan_bytes: int = 8192,
        min_coverage: int = 3,
        score_threshold: float = 1.75,
        min_text_ratio: float = 0.85,
        min_tokens: int = 12,
        max_token_len: int = 24,
        require_successor_family: bool = True,
    ) -> None:
        """
        Args:
            max_scan_bytes: Byte budget per payload (head + tail sampling).
            min_coverage: Families that must be covered before flagging.
                Defaults to all three: the whole point is the conjunction.
            score_threshold: Minimum fractional coverage score, in [0, 3].
            min_text_ratio: Printable-ASCII floor.
            min_tokens: Payloads with fewer tokens are never flagged.
            max_token_len: Tokens longer than this are ignored, and break the
                bigram chain (base64 blobs and hex digests tokenise as one
                enormous word and must not bridge two unrelated words).
            require_successor_family: Require the phrase-level successor
                family to be covered.  On by default; see the class docstring.

        Raises:
            ValueError: on out-of-range gates.
        """
        if max_scan_bytes < 64:
            raise ValueError("max_scan_bytes must be at least 64")
        if not 1 <= min_coverage <= len(self.FAMILY_NAMES):
            raise ValueError(f"min_coverage must be 1..{len(self.FAMILY_NAMES)}")
        if not 0.0 <= min_text_ratio <= 1.0:
            raise ValueError("min_text_ratio must be in [0, 1]")

        self.max_scan_bytes = int(max_scan_bytes)
        self.min_coverage = int(min_coverage)
        self.score_threshold = float(score_threshold)
        self.min_text_ratio = float(min_text_ratio)
        self.min_tokens = int(min_tokens)
        self.max_token_len = int(max_token_len)
        self.require_successor_family = bool(require_successor_family)

        # Marker tables are pure functions of the class-level marker
        # collections, and building them costs ~750 pure-Python FNV hashes
        # (~3 ms).  Paying that per instance put 3 ms on the first import of
        # crypto_api, which constructs a module-level monitor.  Cache on the
        # marker tuples themselves rather than on the class, so a subclass
        # that overrides one family still gets its own correct table.
        (
            self._uni_hashes,
            self._uni_families,
            self._bi_hashes,
            self._bi_families,
            self._packed,
        ) = _marker_tables(
            self.INSTRUCTIONAL_MARKERS,
            self.OPERATIONAL_MARKERS,
            self.SUCCESSOR_PREFIXES,
            self.SUCCESSOR_SUBJECTS,
            self.SUCCESSOR_PHRASES,
            self.SUCCESSOR_FAMILY,
        )

    def _sample(self, payload: Union[bytes, bytearray, memoryview]) -> bytes:
        """Head+tail sample of at most ``max_scan_bytes``.

        Slices the caller's buffer BEFORE materialising it.  Only
        ``max_scan_bytes`` are ever scanned, but a signed payload can be
        arbitrarily large, so copying the whole thing first (``bytes(payload)``)
        made the cost of an inspection scale with the payload rather than with
        the scan budget — a 32 MB blob paid a 32 MB copy to look at 8 KB.
        Slicing first makes the copy proportional to the budget instead.
        """
        view: Any = payload
        if isinstance(view, memoryview):
            # A non-byte itemsize (or multi-dimensional) view would slice by
            # element rather than by byte; normalise so the budget, and the
            # head/tail offsets, are measured in bytes either way.
            if view.itemsize != 1 or view.ndim != 1:
                view = view.cast("B")
        if len(view) <= self.max_scan_bytes:
            return bytes(view)
        half = self.max_scan_bytes // 2
        return bytes(view[:half]) + b"\n" + bytes(view[-half:])

    def inspect(
        self, payload: Union[bytes, bytearray, memoryview], label: str = "payload"
    ) -> NoteArtifactSignal:
        """Score `payload` for note-like structure.

        Args:
            payload: Bytes about to be (or already) signed.  ``bytearray`` and
                ``memoryview`` are accepted as well — the runtime has always
                taken all three, and only the scan budget is ever copied, so
                passing a view of a large buffer costs no more than passing a
                small one.
            label: Identifier carried into the returned signal and any alert.

        Returns:
            A :class:`NoteArtifactSignal`.  ``flagged`` is the only field that
            should drive action, and the action is human review.
        """
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise TypeError(f"payload must be bytes-like, got {type(payload).__name__}")
        data = self._sample(payload)

        # Structural reject, BEFORE the tokenising scan.  The printable-ratio
        # gate is the reason this detector is affordable to point at real
        # payloads, but only if it runs first: computing it from the scan's
        # own printable counter meant every 3.3 KB ML-DSA signature paid the
        # full tokenising pass just to have the result thrown away (measured
        # 21 us -> 6.7 us per signature-sized payload once the gate moved
        # ahead of the scan).  The translate-based count is a single C pass
        # and is exact, not a sample — tests/test_agentic_abuse_detectors.py
        # pins it against the scanner's own counter on arbitrary bytes.
        printable = _printable_count(data)
        text_ratio = (printable / len(data)) if data else 0.0
        if text_ratio < self.min_text_ratio:
            return NoteArtifactSignal(
                label=label,
                occurrences=dict.fromkeys(self.FAMILY_NAMES, 0),
                distinct=dict.fromkeys(self.FAMILY_NAMES, 0),
                coverage=0,
                score=0.0,
                text_ratio=text_ratio,
                tokens=0,
                scanned_bytes=len(data),
                flagged=False,
            )

        if self._packed is not None and _CY_TOKEN_COUNTS is not None:
            occ, dist, printable, tokens = _CY_TOKEN_COUNTS(
                data,
                self._packed[0],
                self._packed[1],
                self._packed[2],
                self._packed[3],
                len(self.FAMILY_NAMES),
                self.max_token_len,
            )
        else:
            occ, dist, printable, tokens = _token_family_counts_py(
                data,
                self._uni_hashes,
                self._uni_families,
                self._bi_hashes,
                self._bi_families,
                len(self.FAMILY_NAMES),
                self.max_token_len,
            )

        coverage = sum(1 for fam, d in enumerate(dist) if d >= self.FAMILY_MIN_HITS[fam])
        score = sum(
            min(d, self.FAMILY_SATURATION[fam]) / self.FAMILY_SATURATION[fam]
            for fam, d in enumerate(dist)
        )
        successor_ok = (
            not self.require_successor_family
            or dist[self.SUCCESSOR_FAMILY] >= self.FAMILY_MIN_HITS[self.SUCCESSOR_FAMILY]
        )
        flagged = (
            text_ratio >= self.min_text_ratio
            and tokens >= self.min_tokens
            and coverage >= self.min_coverage
            and score >= self.score_threshold
            and successor_ok
        )

        return NoteArtifactSignal(
            label=label,
            occurrences=dict(zip(self.FAMILY_NAMES, occ)),
            distinct=dict(zip(self.FAMILY_NAMES, dist)),
            coverage=coverage,
            score=score,
            text_ratio=text_ratio,
            tokens=tokens,
            scanned_bytes=len(data),
            flagged=flagged,
        )


class RefactoringAnalyzer:
    """
    Read-only code complexity analysis.

    **CRITICAL SECURITY CONSTRAINT**: This analyzer operates in read-only
    mode and NEVER modifies cryptographic code automatically. It provides
    metrics for manual human review only.

    Automatic code modification of security-critical code is dangerous
    because:
    - May introduce subtle vulnerabilities
    - Bypasses code review processes
    - Could weaken cryptographic guarantees
    - Violates principle of least privilege

    This analyzer calculates cyclomatic complexity and provides
    recommendations, but all refactoring decisions must be made by
    qualified security engineers.
    """

    # Priority 9: Crypto module files to monitor for integrity
    CRYPTO_MODULES: ClassVar[List[str]] = [
        "crypto_api.py",
        "key_management.py",
        "pqc_backends.py",
        "adaptive_posture.py",
    ]
    MONITOR_MODULE: ClassVar[str] = "ama_cryptography_monitor.py"

    def __init__(self) -> None:
        """Initialize analyzer with empty cache and integrity baselines."""
        self.analysis_cache: Dict[str, Dict] = {}
        # Priority 9: Runtime code integrity baselines
        self._integrity_baselines: Dict[str, str] = {}
        # True only once every guarded crypto module has been baselined.  Left
        # False on any failure so ``verify_integrity`` can tell "no baseline"
        # apart from "verified clean" instead of failing open.
        self._integrity_baseline_ready: bool = False
        # Priority 10: Import chain baselines
        self._import_baselines: Dict[str, str] = {}
        self._initialize_integrity_baselines()
        self._initialize_import_baselines()

    def _initialize_integrity_baselines(self) -> None:
        """Compute SHA3-256 hashes of all crypto module source files at startup."""
        try:
            # Find the ama_cryptography package directory
            crypto_pkg = Path(__file__).parent / "ama_cryptography"
            if not crypto_pkg.exists():
                # Try relative to current file
                crypto_pkg = Path(__file__).parent.parent / "ama_cryptography"

            modules_found = 0
            for module_name in self.CRYPTO_MODULES:
                module_path = crypto_pkg / module_name
                if module_path.exists():
                    content_hash = self._hash_file(module_path)
                    self._integrity_baselines[str(module_path)] = content_hash
                    modules_found += 1

            # Also hash the monitor module itself
            monitor_path = Path(__file__)
            if monitor_path.exists():
                self._integrity_baselines[str(monitor_path)] = self._hash_file(monitor_path)

            # The baseline is only trustworthy if every guarded crypto module was
            # actually hashed.  A partial/empty baseline must NOT later be
            # reported as "clean" — see verify_integrity's fail-closed guard.
            self._integrity_baseline_ready = modules_found == len(self.CRYPTO_MODULES)
        except Exception as e:
            logger.warning("Failed to initialize integrity baselines: %s", e)
            self._integrity_baseline_ready = False

    def _initialize_import_baselines(self) -> None:
        """Record resolved filesystem paths of all imported crypto modules."""
        try:
            import importlib

            crypto_modules = [
                "ama_cryptography.crypto_api",
                "ama_cryptography.key_management",
                "ama_cryptography.adaptive_posture",
                "ama_cryptography.secure_memory",
            ]
            for mod_name in crypto_modules:
                try:
                    mod = importlib.import_module(mod_name)
                    mod_file = getattr(mod, "__file__", None)
                    if mod_file:
                        self._import_baselines[mod_name] = os.path.realpath(mod_file)
                except ImportError:
                    logger.debug("Module %s not installed — skipping import baseline", mod_name)
        except Exception as e:
            logger.warning("Failed to initialize import baselines: %s", e)

    @staticmethod
    def _hash_file(filepath: Path) -> str:
        """Compute SHA3-256 hash of a file's contents.

        The integrity monitor's whole claim rests on this digest's collision
        resistance, so it is computed by the module's own FIPS 202 kernel
        rather than OpenSSL-backed hashlib (INVARIANT-1).  The files hashed
        are Python sources, so a whole-file read replaces the old 8 KiB
        streaming loop without a memory concern.
        """
        from ama_cryptography.pqc_backends import (
            native_sha3_256,
        )  # noqa: PLC0415  # deferred: import cycle with pqc_backends (MON-002)

        return native_sha3_256(filepath.read_bytes()).hex()

    def verify_integrity(self) -> List[IntegrityViolation]:
        """
        Priority 9: Re-hash all crypto module source files and compare
        against startup baselines.

        Returns:
            List of IntegrityViolation for any files whose hash has changed
        """
        violations: List[IntegrityViolation] = []

        # Fail closed: if the startup baseline was never established (package
        # dir not found, unreadable source, etc.) we cannot attest anything.
        # Reporting an empty violation list here would be indistinguishable from
        # "all files verified clean" — the exact fail-open the baseline exists
        # to prevent.
        if not self._integrity_baseline_ready:
            logger.critical(
                "Runtime code integrity baseline unavailable — cannot attest "
                "module integrity; reporting as a violation (fail-closed)."
            )
            violations.append(
                IntegrityViolation(
                    file_path="<integrity-baseline>",
                    expected_hash="BASELINE_ESTABLISHED",
                    actual_hash="BASELINE_UNAVAILABLE",
                )
            )
            return violations

        for filepath_str, expected_hash in self._integrity_baselines.items():
            filepath = Path(filepath_str)
            if not filepath.exists():
                violations.append(
                    IntegrityViolation(
                        file_path=filepath_str,
                        expected_hash=expected_hash,
                        actual_hash="FILE_MISSING",
                    )
                )
                continue
            actual_hash = self._hash_file(filepath)
            if actual_hash != expected_hash:
                violations.append(
                    IntegrityViolation(
                        file_path=filepath_str,
                        expected_hash=expected_hash,
                        actual_hash=actual_hash,
                    )
                )
        if violations:
            logger.critical(
                "CRITICAL: Runtime code integrity violation detected in %d file(s)",
                len(violations),
            )
        return violations

    def verify_imports(self) -> List[ImportHijackViolation]:
        """
        Priority 10: Re-resolve all imported crypto module paths and compare
        against startup baselines.

        Returns:
            List of ImportHijackViolation for any modules resolving to different paths
        """
        import importlib

        violations: List[ImportHijackViolation] = []
        for mod_name, expected_path in self._import_baselines.items():
            try:
                # Force re-import to get current path
                mod = importlib.import_module(mod_name)
                mod_file = getattr(mod, "__file__", None)
                if mod_file:
                    actual_path = os.path.realpath(mod_file)
                    if actual_path != expected_path:
                        violations.append(
                            ImportHijackViolation(
                                module_name=mod_name,
                                expected_path=expected_path,
                                actual_path=actual_path,
                            )
                        )
            except ImportError:
                violations.append(
                    ImportHijackViolation(
                        module_name=mod_name,
                        expected_path=expected_path,
                        actual_path="IMPORT_FAILED",
                    )
                )
        if violations:
            logger.critical(
                "CRITICAL: Import chain hijack detected for %d module(s)",
                len(violations),
            )
        return violations

    def analyze_file(self, filepath: Path) -> Dict:
        """
        Analyze Python file complexity (read-only).

        Calculates:
        - Total functions and classes
        - Per-function cyclomatic complexity
        - Lines of code
        - Complexity distribution

        Args:
            filepath: Path to Python file to analyze

        Returns:
            Dict with:
                - total_functions: Count of function definitions
                - total_classes: Count of class definitions
                - total_lines: Total lines in file
                - functions: List of per-function metrics
                - complexity_summary: Aggregate statistics
                - (error: str if parsing fails)

        Note:
            Uses Python's ast module for parsing. Only analyzes
            syntactically valid Python files.
        """
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                source = f.read()

            tree = ast.parse(source)

            metrics: Dict[str, Any] = {
                "total_functions": 0,
                "total_classes": 0,
                "total_lines": len(source.splitlines()),
                "functions": [],
            }

            complexity_values = []

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    metrics["total_functions"] += 1
                    complexity = self._calculate_complexity(node)
                    complexity_values.append(complexity)

                    function_info = {
                        "name": node.name,
                        "complexity": complexity,
                        "lines": (
                            node.end_lineno - node.lineno
                            if hasattr(node, "end_lineno") and node.end_lineno is not None
                            else 0
                        ),
                        "recommendation": self._get_recommendation(complexity),
                    }
                    metrics["functions"].append(function_info)

                elif isinstance(node, ast.ClassDef):
                    metrics["total_classes"] += 1

            # Add complexity summary
            if complexity_values:
                metrics["complexity_summary"] = {
                    "mean": _mean([float(c) for c in complexity_values]),
                    "max": max(complexity_values),
                    "high_complexity_functions": sum(1 for c in complexity_values if c > 10),
                }

            # Priority 9: Compute and cache content hash
            from ama_cryptography.pqc_backends import (
                native_sha3_256,
            )  # noqa: PLC0415  # deferred: import cycle with pqc_backends (MON-002)

            content_hash = native_sha3_256(source.encode("utf-8")).hex()
            metrics["content_hash"] = content_hash
            self.analysis_cache[str(filepath)] = metrics

            return metrics

        except Exception as e:
            return {"error": str(e), "filepath": str(filepath)}

    def _calculate_complexity(self, node: ast.FunctionDef) -> int:
        """
        Calculate cyclomatic complexity using standard formula.

        Cyclomatic complexity M = E - N + 2P, simplified to:
        M = 1 + (number of decision points)

        Decision points:
        - if, elif, else
        - for, while loops
        - except handlers
        - boolean operators (and, or)
        - ternary operators

        Args:
            node: AST FunctionDef node

        Returns:
            Integer complexity score. Guidelines:
                1-10: Simple, easy to test
                11-20: Moderate, may need refactoring
                21+: Complex, should refactor
        """
        complexity = 1  # Base complexity

        for child in ast.walk(node):
            # Conditional branches
            if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1

            # Boolean operators add decision points
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1

            # Ternary expressions
            elif isinstance(child, ast.IfExp):
                complexity += 1

        return complexity

    def _get_recommendation(self, complexity: int) -> str:
        """
        Provide refactoring recommendation based on complexity.

        Args:
            complexity: Cyclomatic complexity score

        Returns:
            Human-readable recommendation string
        """
        if complexity <= 10:
            return "Acceptable complexity"
        elif complexity <= 20:
            return "Consider refactoring - moderate complexity"
        else:
            return "Refactor recommended - high complexity"


class AmaCryptographyMonitor:
    """
    Unified monitoring interface for AMA Cryptography.

    Combines 3R Mechanism components (Resonance-Recursion-Refactoring)
    for comprehensive security monitoring without compromising cryptographic
    integrity or performance.

    Design Principles:

    - Enabled by default: Production-ready anomaly detection out of the
      box (per engineering brief Task 2).  Callers who need zero-overhead
      operation should pass ``enabled=False`` explicitly.  This extends to
      the agentic-abuse detectors (INVARIANT-30 companion signals): they are
      constructed by default so a deployment gets the protection without
      opting in.  They still only do work when their hooks are called, so
      "on by default" costs an attribute load on paths that ignore them.
    - Non-invasive: Read-only analysis, never modifies crypto code
    - Lightweight: <2% performance overhead when enabled
    - Observable: Comprehensive reporting for security teams

    Usage::

        >>> monitor = AmaCryptographyMonitor(enabled=True)
        >>> pkg = create_crypto_package(codes, params, kms, monitor=monitor)
        >>> report = monitor.get_security_report()
        >>> print(f"Alerts: {report['total_alerts']}")
    """

    def __init__(
        self,
        enabled: bool = True,
        alert_retention: int = 1000,
        nonce_persist_path: Optional[str] = None,
        detect_volume_spikes: bool = True,
        detect_note_artifacts: bool = True,
    ) -> None:
        """
        Initialize monitor.

        Args:
            enabled: Whether monitoring is active. Default True for
                production-ready anomaly detection out of the box.
            alert_retention: Maximum alerts to retain in memory.
                Prevents unbounded memory growth.
            nonce_persist_path: Path for nonce tracker persistence file.
            detect_volume_spikes: Enable the agentic burst detector.  **On by
                default**, matching this class's stated posture that
                production-ready anomaly detection ships out of the box.  It
                costs nothing on paths that never call
                :meth:`record_operation_event`; pass ``False`` to drop even
                the detector object.
            detect_note_artifacts: Enable the note-like-artifact detector.
                **On by default** for the same reason — it only ever runs on
                payloads handed to :meth:`inspect_signed_payload`, and an
                operator should not have to opt in to a protection.
        """
        self.enabled = enabled
        self.alert_retention = alert_retention
        self.timing = ResonanceTimingMonitor()
        self.patterns = RecursionPatternMonitor()
        self.analyzer = RefactoringAnalyzer()
        self.nonce_tracker = NonceTracker(persist_path=nonce_persist_path, ephemeral=not enabled)
        self.volume: Optional[VolumeSpikeDetector] = (
            VolumeSpikeDetector() if detect_volume_spikes else None
        )
        self.notes: Optional[NoteArtifactDetector] = (
            NoteArtifactDetector() if detect_note_artifacts else None
        )
        self.alerts: List[Dict] = []
        # ``record_operation_event`` is called from every worker thread of a
        # concurrent workload; the detector serialises its own state, but the
        # shared alert list needs its own guard.
        self._alert_lock = threading.RLock()

    def monitor_crypto_operation(
        self, operation: str, duration_ms: float, input_size: Optional[int] = None
    ) -> None:
        """
        Monitor cryptographic operation timing.

        Records operation duration and checks for timing anomalies
        that could indicate side-channel vulnerabilities.

        Args:
            operation: Operation name (e.g., 'ed25519_sign',
                'dilithium_verify')
            duration_ms: Operation duration in milliseconds
            input_size: Optional input size in bytes.  Required for a
                profile with ``normalize_by_size`` to take effect — the
                pre-5.0.0 wrapper silently dropped it, which made every
                size-normalized profile dead configuration.
        """
        if not self.enabled:
            return

        anomaly = self.timing.record_timing(operation, duration_ms, input_size=input_size)
        if anomaly:
            # Under _alert_lock like every other writer: this runs on the
            # instrumented sign/verify/encrypt/decrypt paths, which crypto_api
            # drives from a ThreadPoolExecutor during hybrid verification.
            with self._alert_lock:
                self.alerts.append({"type": "timing", "anomaly": anomaly, "timestamp": time.time()})
            self._prune_alerts()

    def check_nonce(self, key_id: bytes, nonce: bytes) -> None:
        """
        Check for nonce reuse (Priority 2).

        Args:
            key_id: Key identifier
            nonce: Nonce/IV being used
        """
        if not self.enabled:
            return
        anomaly = self.nonce_tracker.check_and_record(key_id, nonce)
        if anomaly:
            with self._alert_lock:
                self.alerts.append({"type": "nonce", "anomaly": anomaly, "timestamp": time.time()})
            self._prune_alerts()

    def monitor_key_lifecycle(self, key_metadata: Dict[str, Any]) -> None:
        """
        Monitor key lifecycle (Priority 4).

        Args:
            key_metadata: Dict with key_id, status, usage_count, max_usage, expires_at
        """
        if not self.enabled:
            return
        anomalies = self.patterns.monitor_key_usage(key_metadata)
        for anomaly in anomalies:
            with self._alert_lock:
                self.alerts.append(
                    {
                        "type": "key_lifecycle",
                        "anomaly": anomaly,
                        "timestamp": time.time(),
                    }
                )
            self._prune_alerts()

    def record_operation_event(
        self,
        operation: str,
        key_fingerprint: Optional[bytes] = None,
    ) -> Optional[VolumeSpike]:
        """Feed one KEM/signature operation to the volume-spike detector.

        Enabled by default.  Returns ``None`` immediately when monitoring or
        the detector is disabled, so callers can wire it unconditionally at a
        cost of one attribute load.

        Args:
            operation: Operation name (e.g. ``'kyber_encaps'``).
            key_fingerprint: Optional short, non-secret key identifier —
                a truncated hash, never raw key bytes.  Supplying it lets the
                detector distinguish ephemeral-key churn from a hot loop over
                one key.

        Returns:
            The :class:`VolumeSpike` if this call tripped the detector.
        """
        if not self.enabled or self.volume is None:
            return None
        spike = self.volume.record(operation, key_fingerprint=key_fingerprint)
        if spike is not None:
            with self._alert_lock:
                self.alerts.append(
                    {"type": "volume_spike", "anomaly": spike, "timestamp": time.time()}
                )
                self._prune_alerts()
        return spike

    def inspect_signed_payload(
        self,
        payload: Union[bytes, bytearray, memoryview],
        label: str = "payload",
    ) -> Optional[NoteArtifactSignal]:
        """Score a payload for note-like structure before or after signing.

        Enabled by default; returns ``None`` when monitoring or the detector
        is disabled.  Advisory only — a flagged payload is a review item, not
        a blocked operation.

        Args:
            payload: Bytes being signed.
            label: Identifier carried into the signal and any alert.
        """
        if not self.enabled or self.notes is None:
            return None
        signal = self.notes.inspect(payload, label=label)
        if signal.flagged:
            with self._alert_lock:
                self.alerts.append(
                    {"type": "note_artifact", "anomaly": signal, "timestamp": time.time()}
                )
                self._prune_alerts()
        return signal

    def verify_runtime_integrity(self) -> Dict[str, Any]:
        """
        Verify runtime code integrity and import chains (Priorities 9-10).

        Returns:
            Dict with integrity and import verification results
        """
        if not self.enabled:
            return {"status": "monitoring_disabled"}

        integrity_violations = self.analyzer.verify_integrity()
        import_violations = self.analyzer.verify_imports()

        with self._alert_lock:
            for v in integrity_violations:
                self.alerts.append(
                    {
                        "type": "integrity_violation",
                        "anomaly": {
                            "file": v.file_path,
                            "expected": v.expected_hash,
                            "actual": v.actual_hash,
                        },
                        "timestamp": time.time(),
                    }
                )
            for iv in import_violations:
                self.alerts.append(
                    {
                        "type": "import_hijack",
                        "anomaly": {
                            "module": iv.module_name,
                            "expected": iv.expected_path,
                            "actual": iv.actual_path,
                        },
                        "timestamp": time.time(),
                    }
                )
        self._prune_alerts()

        return {
            "integrity_violations": [
                {"file": v.file_path, "expected": v.expected_hash, "actual": v.actual_hash}
                for v in integrity_violations
            ],
            "import_violations": [
                {"module": v.module_name, "expected": v.expected_path, "actual": v.actual_path}
                for v in import_violations
            ],
        }

    def record_package_signing(self, metadata: Dict) -> None:
        """
        Record package signing event for pattern analysis.

        Args:
            metadata: Package metadata dict containing:
                - author: Package signer
                - code_count: Number of Omni-Codes
                - content_hash: Truncated content hash
        """
        if not self.enabled:
            return

        self.patterns.record_package(metadata)

        # Check for pattern anomalies
        analysis = self.patterns.analyze_patterns()
        if analysis.get("status") == "analyzed":
            for anomaly in analysis.get("anomalies", []):
                with self._alert_lock:
                    self.alerts.append(
                        {"type": "pattern", "anomaly": anomaly, "timestamp": time.time()}
                    )
                self._prune_alerts()

    def analyze_codebase(self, directory: Path) -> Dict:
        """
        Analyze codebase complexity (read-only).

        Scans all Python files in directory and calculates
        complexity metrics. Does NOT modify any files.

        Args:
            directory: Root directory to analyze

        Returns:
            Dict with:
                - files_analyzed: List of file analyses
                - aggregate_metrics: Overall complexity statistics

        Warning:
            This is a read-only analysis tool. All refactoring
            decisions must be made by qualified engineers through
            proper code review processes.
        """
        if not self.enabled:
            return {"status": "monitoring_disabled"}

        results: List[Dict[str, Any]] = []
        for py_file in directory.rglob("*.py"):
            analysis = self.analyzer.analyze_file(py_file)
            results.append({"filepath": str(py_file), "analysis": analysis})

        # Aggregate statistics
        all_complexities: List[int] = []
        for r in results:
            if "functions" in r["analysis"]:
                all_complexities.extend([f["complexity"] for f in r["analysis"]["functions"]])

        aggregate = {}
        if all_complexities:
            aggregate = {
                "total_functions": len(all_complexities),
                "mean_complexity": _mean([float(c) for c in all_complexities]),
                "max_complexity": max(all_complexities),
                "high_complexity_count": sum(1 for c in all_complexities if c > 10),
            }

        return {
            "status": "analyzed",
            "files_analyzed": results,
            "aggregate_metrics": aggregate,
        }

    def get_security_report(self) -> Dict:
        """
        Generate comprehensive security report.

        Returns:
            Dict containing:
                - status: 'monitoring_disabled' or 'active'
                - timing_baseline: Per-operation baseline statistics
                - resonance_analysis: Frequency-domain analysis results
                - pattern_analysis: Hierarchical pattern analysis
                - recent_alerts: Last 10 alerts
                - total_alerts: Total alert count
                - recommendations: Security recommendations (if any)
        """
        if not self.enabled:
            return {"status": "monitoring_disabled"}

        # Every mapping and list in this report is a COPY taken under the lock
        # that guards it.  Handing out `self.timing.baseline_stats` was the
        # same race this method already documents (and fixes) for
        # `timing_history` a dozen lines below: a new operation name inserts a
        # key on its 30th record under the timing monitor's lock, and a
        # consumer iterating the returned mapping raised
        # RuntimeError("dictionary changed size during iteration") within four
        # seconds against a writer issuing fresh names.  The alert list is
        # sliced under _alert_lock for the same reason -- _prune_alerts trims
        # it IN PLACE with `del self.alerts[:excess]`.
        with self._alert_lock:
            recent_alerts = [dict(alert) for alert in self.alerts[-10:]]
            total_alerts = len(self.alerts)
            alerts_snapshot = list(self.alerts)
        report: Dict[str, Any] = {
            "status": "active",
            "timing_baseline": self.timing.snapshot_baselines(),
            # Non-zero means the timing monitor hit its operation-name cap and
            # is no longer seeing every operation.  In the report because a
            # reader deciding how much to trust `timing_baseline` needs to know
            # it is partial, and a counter nobody surfaces is a counter nobody
            # acts on.
            "dropped_operations": self.timing.dropped_operations,
            "pattern_analysis": self.patterns.analyze_patterns(),
            "recent_alerts": recent_alerts,
            "total_alerts": total_alerts,
            "recommendations": [],
        }

        # Add resonance analysis for monitored operations.  Snapshot the
        # operation names under the timing monitor's lock: record_timing
        # inserts a NEW dict key on the first record of an operation name
        # under that lock, and iterating the live keys() from this (locked
        # nowhere) reader raced it — reproduced as RuntimeError("dictionary
        # changed size during iteration") within ~1 s of a reader loop
        # against a writer issuing fresh names, killing the posture
        # evaluation cycle that calls this report unguarded.
        resonance_data = {}
        with self.timing._lock:
            monitored_operations = list(self.timing.timing_history)
        for operation in monitored_operations:
            resonance = self.timing.detect_resonance(operation)
            if resonance.get("has_resonance"):
                resonance_data[operation] = resonance

        if resonance_data:
            report["resonance_analysis"] = resonance_data
            report["recommendations"].append(
                "Resonance detected in timing patterns. "
                "Review for potential side-channel vulnerabilities."
            )

        # Agentic-abuse detectors.  Present whenever the detectors are
        # constructed (the default); a caller that passed
        # detect_volume_spikes=False / detect_note_artifacts=False gets the
        # pre-INVARIANT-30 report shape back, unchanged.
        if self.volume is not None:
            report["volume_baselines"] = self.volume.snapshot()
            spikes = [a for a in alerts_snapshot if a["type"] == "volume_spike"]
            if spikes:
                report["recommendations"].append(
                    f"{len(spikes)} operation-volume spike(s) detected. Review for "
                    "agentic reconnaissance or bulk artifact generation."
                )
        if self.notes is not None:
            flagged = [a for a in alerts_snapshot if a["type"] == "note_artifact"]
            if flagged:
                report["note_artifacts"] = [a["anomaly"].label for a in flagged]
                report["recommendations"].append(
                    f"{len(flagged)} signed payload(s) matched the note-like artifact "
                    "pattern. Human review recommended; this signal is advisory."
                )

        # Add pattern-based recommendations
        if report["pattern_analysis"].get("status") == "analyzed":
            anomalies = report["pattern_analysis"].get("anomalies", [])
            if any(a["severity"] == "critical" for a in anomalies):
                report["recommendations"].append(
                    "Critical pattern anomalies detected. " "Immediate security review recommended."
                )

        return report

    def _prune_alerts(self) -> None:
        """Limit memory usage by pruning old alerts.

        Trims IN PLACE under ``_alert_lock``.  The previous form rebound the
        attribute (``self.alerts = self.alerts[-retention:]``), which silently
        dropped alerts raised concurrently: a writer that had already resolved
        ``self.alerts`` appended to the list object this method had just
        discarded, so the alert vanished — and a lost alert is a suppressed
        security signal, one the posture evaluator then never scores.  Deleting
        a slice keeps the list identity stable, so an append that races the trim
        still lands in the list every reader sees.
        """
        with self._alert_lock:
            excess = len(self.alerts) - self.alert_retention
            if excess > 0:
                del self.alerts[:excess]


# Module-level convenience functions


def create_monitor(
    enabled: bool = True,
    alert_retention: int = 1000,
    detect_volume_spikes: bool = True,
    detect_note_artifacts: bool = True,
) -> AmaCryptographyMonitor:
    """
    Factory function for creating monitor instances.

    Args:
        enabled: Whether monitoring is active.  Default ``True`` for
            production-ready anomaly detection.  Pass ``False`` for
            zero-overhead operation when monitoring is not needed.
        alert_retention: Maximum alerts to retain
        detect_volume_spikes: Enable the agentic burst detector.  On by
            default; pass ``False`` to drop the detector object entirely.
        detect_note_artifacts: Enable the note-like artifact detector.  On by
            default; pass ``False`` to drop the detector object entirely.

    Returns:
        Configured AmaCryptographyMonitor instance
    """
    return AmaCryptographyMonitor(
        enabled=enabled,
        alert_retention=alert_retention,
        detect_volume_spikes=detect_volume_spikes,
        detect_note_artifacts=detect_note_artifacts,
    )
