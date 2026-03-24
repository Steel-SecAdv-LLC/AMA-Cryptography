#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
Date: 2026-03-08
Version: 2.0
Project: AMA Cryptography 3R Runtime Monitoring

AI Co-Architects:
    Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
"""

import ast
import cmath
import hashlib
import logging
import math
import os
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, Deque, Dict, List, Optional, Sequence, Set, Tuple

logger = logging.getLogger(__name__)


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


__version__ = "2.1"
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
    "high_resolution_timer",
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

    __slots__ = ("alpha", "mean", "variance", "n", "_recent_values")

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

    def get_mad(self) -> float:
        """
        Calculate Median Absolute Deviation (MAD) from recent values.

        MAD is a robust measure of variability that is resistant to outliers.
        It's defined as: MAD = median(|x_i - median(x)|)

        Returns:
            MAD value, or 0.0 if insufficient data
        """
        if len(self._recent_values) < 3:
            return 0.0

        values = sorted(self._recent_values)
        median = _median_sorted(values)
        deviations = sorted(abs(v - median) for v in values)
        mad = _median_sorted(deviations)
        return float(mad)

    def is_anomaly_mad(self, x: float, threshold: float = 3.5) -> bool:
        """
        Check if value is anomaly using MAD-based detection.

        Uses modified Z-score: |x - median| / (1.4826 * MAD) > threshold

        The constant 1.4826 makes MAD consistent with standard deviation
        for normally distributed data.

        Args:
            x: Value to check
            threshold: Detection threshold (default 3.5 = ~99.95% for normal)

        Returns:
            True if value is anomaly, False otherwise
        """
        if len(self._recent_values) < 10:
            return False

        mad = self.get_mad()
        if mad == 0:
            return False

        values = sorted(self._recent_values)
        median = _median_sorted(values)
        modified_z = abs(x - median) / (1.4826 * mad)
        return modified_z > threshold

    def reset(self) -> None:
        """Reset all accumulators to initial state."""
        self.mean = 0.0
        self.variance = 0.0
        self.n = 0
        self._recent_values.clear()


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
        deviation_sigma: Number of standard deviations from baseline
        severity: Alert level ('info', 'warning', 'critical')
        timestamp: Unix timestamp of detection
    """

    operation: str
    expected_ms: float
    observed_ms: float
    deviation_sigma: float
    severity: str  # 'info', 'warning', 'critical'
    timestamp: float


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
            self._persist_path = Path(persist_path) if persist_path else Path("/dev/null")

        # Set of (key_id_hash_hex, nonce_hex) tuples
        self._seen: Set[Tuple[str, str]] = set()
        # Per-key counters for 2^32 safety limit
        self._counters: Dict[str, int] = {}
        if not ephemeral:
            self._load_persisted()

    def _load_persisted(self) -> None:
        """Reload persisted nonce history from disk."""
        try:
            with open(self._persist_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(",", 1)
                    if len(parts) == 2:
                        key_hash, nonce_hex = parts
                        self._seen.add((key_hash, nonce_hex))
                        self._counters[key_hash] = self._counters.get(key_hash, 0) + 1
        except FileNotFoundError:
            return
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
        key_hash = hashlib.sha256(key_id).hexdigest()
        nonce_hex = nonce.hex()
        entry = (key_hash, nonce_hex)

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
                "message": "CRITICAL: Nonce safety limit (2^32) exceeded for key. Re-key required.",
                "timestamp": time.time(),
            }

        self._seen.add(entry)
        self._counters[key_hash] = count + 1
        self._persist_entry(key_hash, nonce_hex)
        return None

    def get_counter(self, key_id: bytes) -> int:
        """Get current nonce count for a key."""
        key_hash = hashlib.sha256(key_id).hexdigest()
        return self._counters.get(key_hash, 0)

    def get_all_counters(self) -> Dict[str, int]:
        """Get all persisted counters (key_hash -> count)."""
        return dict(self._counters)


class ResonanceTimingMonitor:
    """
    Detect timing anomalies via frequency-domain analysis.

    Uses FFT-based resonance detection to identify periodic timing patterns
    that may indicate anomalous behavior in cryptographic operations.

    This is a MONITORING system that surfaces statistical anomalies for
    security review. It does not guarantee detection of timing attacks
    or provide side-channel resistance.

    Features:
    - Per-operation baseline statistics (ed25519_sign, dilithium_verify, etc.)
    - EWMA with MAD for robust, outlier-resistant anomaly detection
    - High-resolution timing via perf_counter_ns() (cross-platform)
    - Sliding window FFT analysis for periodic pattern detection
    """

    # Priority 8: Default operation-specific anomaly profiles
    DEFAULT_ANOMALY_PROFILES: ClassVar[Dict[str, Dict[str, Any]]] = {
        "ed25519_sign": {"threshold_sigma": 2.0, "normalize_by_size": False},
        "ed25519_verify": {"threshold_sigma": 2.0, "normalize_by_size": False},
        "dilithium_sign": {"threshold_sigma": 5.0, "normalize_by_size": False},
        "dilithium_verify": {"threshold_sigma": 3.0, "normalize_by_size": False},
        "aes_gcm_encrypt": {"threshold_sigma": 3.0, "normalize_by_size": True},
        "aes_gcm_decrypt": {"threshold_sigma": 3.0, "normalize_by_size": True},
    }

    def __init__(
        self,
        threshold_sigma: float = 3.0,
        window_size: int = 100,
        max_history: int = 10000,
        use_ewma: bool = True,
        ewma_alpha: float = 0.1,
        anomaly_profiles: Optional[Dict[str, Dict[str, Any]]] = None,
        drift_check_interval: int = 50,
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
            drift_check_interval: Check for timing drift every N samples (Priority 7).

        Performance Optimization:
            Uses collections.deque with maxlen for O(1) append and automatic
            pruning, and EWMA/Welford's algorithm for O(1) incremental statistics.
        """
        self.threshold = threshold_sigma
        self.window_size = window_size
        self.max_history = max_history
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
        # Priority 7: Frozen baselines for drift detection
        self._frozen_baselines: Dict[str, Tuple[float, float]] = {}  # (frozen_mean, frozen_std)
        # Priority 8: Operation-specific anomaly profiles
        self.anomaly_profiles: Dict[str, Dict[str, Any]] = dict(self.DEFAULT_ANOMALY_PROFILES)
        if anomaly_profiles:
            self.anomaly_profiles.update(anomaly_profiles)

    def record_timing(
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
            self.timing_history[operation] = deque(maxlen=self.max_history)
            self._incremental_stats[operation] = IncrementalStats()
            self._ewma_stats[operation] = EWMAStats(
                alpha=self.ewma_alpha, window_size=self.window_size
            )

        # Priority 8: Normalize by input size if profile says so
        profile = self.anomaly_profiles.get(operation, {})
        normalize_by_size = profile.get("normalize_by_size", False)
        effective_duration = duration_ms
        if normalize_by_size and input_size and input_size > 0:
            effective_duration = duration_ms / input_size

        # O(1) append with automatic pruning via deque maxlen
        self.timing_history[operation].append(effective_duration)

        # Update both stats (EWMA provides responsiveness, Welford provides accuracy)
        self._incremental_stats[operation].update(effective_duration)
        ewma_mean, ewma_std = self._ewma_stats[operation].update(effective_duration)

        # Get sample count
        sample_count = self._incremental_stats[operation].n

        # Priority 7: Capture frozen baseline after warmup
        if sample_count == 30 and operation not in self._frozen_baselines:
            welford_mean, welford_std = self._incremental_stats[operation].get_stats()
            self._frozen_baselines[operation] = (welford_mean, welford_std)

        # Need baseline before detection
        if sample_count < 30:
            return None

        # Choose which stats to use
        if self.use_ewma:
            mean, std = ewma_mean, ewma_std
        else:
            mean, std = self._incremental_stats[operation].get_stats()

        # Update baseline stats for reporting
        self.baseline_stats[operation] = {
            "mean": mean,
            "std": std,
            "samples": sample_count,
            "mad": self._ewma_stats[operation].get_mad(),
        }

        # Priority 8: Use operation-specific threshold or global
        op_threshold = profile.get("threshold_sigma", self.threshold)

        # Detect statistical anomaly using both Z-score and MAD
        is_anomaly = False
        deviation = 0.0

        # Numerical tolerance for floating-point threshold comparisons
        THRESHOLD_EPSILON = 0.01

        # Primary: Z-score based detection
        if std > 0:
            deviation = abs(effective_duration - mean) / std
            if deviation >= op_threshold - THRESHOLD_EPSILON:
                is_anomaly = True

        # Secondary: MAD-based detection (more robust to outliers)
        if self.use_ewma and self._ewma_stats[operation].is_anomaly_mad(effective_duration):
            is_anomaly = True

        # Priority 7: Drift detection (does NOT preempt Z-score/MAD — both reported)
        drift_anomaly: Optional[TimingAnomaly] = None
        if (
            sample_count > 30
            and sample_count % self.drift_check_interval == 0
            and operation in self._frozen_baselines
        ):
            frozen_mean, frozen_std = self._frozen_baselines[operation]
            if frozen_std > 0:
                drift = abs(mean - frozen_mean) / frozen_std
                if drift > 2.0:
                    drift_anomaly = TimingAnomaly(
                        operation=operation,
                        expected_ms=frozen_mean,
                        observed_ms=mean,
                        deviation_sigma=drift,
                        severity="warning",
                        timestamp=time.time(),
                    )

        # Priority 6: Cross-operation timing correlation
        cross_op_anomaly = self._update_timing_ratios(operation, mean)

        # Return the most severe anomaly found (point > drift > cross-op)
        if is_anomaly:
            CRITICAL_THRESHOLD = 5.0
            severity = (
                "critical" if deviation >= CRITICAL_THRESHOLD - THRESHOLD_EPSILON else "warning"
            )
            return TimingAnomaly(
                operation=operation,
                expected_ms=mean,
                observed_ms=effective_duration,
                deviation_sigma=deviation,
                severity=severity,
                timestamp=time.time(),
            )

        if drift_anomaly is not None:
            return drift_anomaly

        if cross_op_anomaly is not None:
            return cross_op_anomaly

        return None

    def _update_timing_ratios(self, operation: str, current_mean: float) -> Optional[TimingAnomaly]:
        """
        Priority 6: Update pairwise timing ratio matrix and detect
        cross-operation correlation anomalies.
        """
        if current_mean <= 0:
            return None

        for other_op, other_stats in self.baseline_stats.items():
            if other_op == operation:
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

            # Baseline ratios after 30 samples
            samples = self._ratio_samples[pair]
            if len(samples) == 30:
                self._ratio_baselines[pair] = (_mean(samples), _std(samples))
            elif len(samples) > 30 and pair in self._ratio_baselines:
                baseline_mean, baseline_std = self._ratio_baselines[pair]
                if baseline_std > 0:
                    deviation = abs(ratio - baseline_mean) / baseline_std
                    if deviation > 3.0:
                        return TimingAnomaly(
                            operation=f"{pair[0]}/{pair[1]}",
                            expected_ms=baseline_mean,
                            observed_ms=ratio,
                            deviation_sigma=deviation,
                            severity="warning",
                            timestamp=time.time(),
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
                - mean_power: Average power across spectrum
                - resonance_ratio: Ratio of dominant to mean power
                - has_resonance: Boolean flag (ratio > 3.0)

        Note:
            Requires minimum 8 samples. Returns empty dict if insufficient
            data. This is an on-demand operation (not hot path) so numpy
            array conversion is acceptable here.
        """
        if operation not in self.timing_history:
            return {}

        # Slice to window_size (on-demand, not hot path)
        history_list = list(self.timing_history[operation])
        timings = history_list[-self.window_size :]

        if len(timings) < 8:
            return {}

        # Zero-pad to next power of 2 for Cooley-Tukey
        n = len(timings)
        n_padded = 1
        while n_padded < n:
            n_padded <<= 1
        x = [complex(v) for v in timings] + [complex(0)] * (n_padded - n)

        # FFT analysis (pure Python Cooley-Tukey)
        fft_result = _fft_cooley_tukey(x)
        freqs = _fftfreq(n_padded)
        power = [abs(c) ** 2 for c in fft_result]

        # Find dominant frequency (excluding DC component at index 0)
        power_no_dc = power[1:]
        dominant_idx = power_no_dc.index(max(power_no_dc)) + 1
        dominant_freq = freqs[dominant_idx]
        dominant_power = power[dominant_idx]

        # Mean power excluding DC
        mean_power = _mean(power_no_dc)

        return {
            "dominant_frequency": float(dominant_freq),
            "dominant_power": float(dominant_power),
            "mean_power": float(mean_power),
            "resonance_ratio": (float(dominant_power / mean_power) if mean_power > 0 else 0),
            "has_resonance": dominant_power > 3.0 * mean_power,
        }

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
        # Priority 4: Key lifecycle monitoring
        self._key_usage_rates: Dict[str, Deque[float]] = {}  # key_id -> recent usage timestamps
        self._key_alerts: List[Dict[str, Any]] = []

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
        if len(self.package_history) < 10:
            return {"status": "insufficient_data"}

        # Extract time series features
        timestamps = [p["timestamp"] for p in self.package_history]
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
        code_counts = [float(p.get("code_count", 0)) for p in self.package_history]
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
            "total_packages": len(self.package_history),
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

        # Track usage rate per key
        if key_id not in self._key_usage_rates:
            self._key_usage_rates[key_id] = deque(maxlen=1000)
        self._key_usage_rates[key_id].append(time.time())

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
            if isinstance(expires_at, (int, float)) and now > expires_at:
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

        self._key_alerts.extend(anomalies)
        return anomalies

    def _check_key_rate_anomaly(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Check if a single key's usage rate is anomalous compared to its history."""
        timestamps = self._key_usage_rates.get(key_id)
        if not timestamps or len(timestamps) < 20:
            return None

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

            for module_name in self.CRYPTO_MODULES:
                module_path = crypto_pkg / module_name
                if module_path.exists():
                    content_hash = self._hash_file(module_path)
                    self._integrity_baselines[str(module_path)] = content_hash

            # Also hash the monitor module itself
            monitor_path = Path(__file__)
            if monitor_path.exists():
                self._integrity_baselines[str(monitor_path)] = self._hash_file(monitor_path)
        except Exception as e:
            logger.warning("Failed to initialize integrity baselines: %s", e)

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
        """Compute SHA3-256 hash of a file's contents."""
        h = hashlib.sha3_256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def verify_integrity(self) -> List[IntegrityViolation]:
        """
        Priority 9: Re-hash all crypto module source files and compare
        against startup baselines.

        Returns:
            List of IntegrityViolation for any files whose hash has changed
        """
        violations: List[IntegrityViolation] = []
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
            content_hash = hashlib.sha3_256(source.encode("utf-8")).hexdigest()
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
    - Opt-in: Disabled by default for zero overhead
    - Non-invasive: Read-only analysis, never modifies crypto code
    - Lightweight: <2% performance overhead when enabled
    - Observable: Comprehensive reporting for security teams

    Usage:
        >>> monitor = AmaCryptographyMonitor(enabled=True)
        >>> pkg = create_crypto_package(codes, params, kms, monitor=monitor)
        >>> report = monitor.get_security_report()
        >>> print(f"Alerts: {report['total_alerts']}")
    """

    def __init__(
        self,
        enabled: bool = False,
        alert_retention: int = 1000,
        nonce_persist_path: Optional[str] = None,
    ) -> None:
        """
        Initialize monitor.

        Args:
            enabled: Whether monitoring is active. Default False for
                zero-overhead operation when not needed.
            alert_retention: Maximum alerts to retain in memory.
                Prevents unbounded memory growth.
            nonce_persist_path: Path for nonce tracker persistence file.
        """
        self.enabled = enabled
        self.alert_retention = alert_retention
        self.timing = ResonanceTimingMonitor()
        self.patterns = RecursionPatternMonitor()
        self.analyzer = RefactoringAnalyzer()
        self.nonce_tracker = NonceTracker(persist_path=nonce_persist_path, ephemeral=not enabled)
        self.alerts: List[Dict] = []

    def monitor_crypto_operation(self, operation: str, duration_ms: float) -> None:
        """
        Monitor cryptographic operation timing.

        Records operation duration and checks for timing anomalies
        that could indicate side-channel vulnerabilities.

        Args:
            operation: Operation name (e.g., 'ed25519_sign',
                'dilithium_verify')
            duration_ms: Operation duration in milliseconds
        """
        if not self.enabled:
            return

        anomaly = self.timing.record_timing(operation, duration_ms)
        if anomaly:
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
            self.alerts.append(
                {
                    "type": "key_lifecycle",
                    "anomaly": anomaly,
                    "timestamp": time.time(),
                }
            )
            self._prune_alerts()

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

        report: Dict[str, Any] = {
            "status": "active",
            "timing_baseline": self.timing.baseline_stats,
            "pattern_analysis": self.patterns.analyze_patterns(),
            "recent_alerts": self.alerts[-10:],
            "total_alerts": len(self.alerts),
            "recommendations": [],
        }

        # Add resonance analysis for monitored operations
        resonance_data = {}
        for operation in self.timing.timing_history.keys():
            resonance = self.timing.detect_resonance(operation)
            if resonance.get("has_resonance"):
                resonance_data[operation] = resonance

        if resonance_data:
            report["resonance_analysis"] = resonance_data
            report["recommendations"].append(
                "Resonance detected in timing patterns. "
                "Review for potential side-channel vulnerabilities."
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
        """Limit memory usage by pruning old alerts."""
        if len(self.alerts) > self.alert_retention:
            self.alerts = self.alerts[-self.alert_retention :]


# Module-level convenience functions


def create_monitor(enabled: bool = False, alert_retention: int = 1000) -> AmaCryptographyMonitor:
    """
    Factory function for creating monitor instances.

    Args:
        enabled: Whether monitoring is active
        alert_retention: Maximum alerts to retain

    Returns:
        Configured AmaCryptographyMonitor instance
    """
    return AmaCryptographyMonitor(enabled=enabled, alert_retention=alert_retention)
