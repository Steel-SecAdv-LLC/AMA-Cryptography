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
import math
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

# numpy/scipy are optional — used by equations/double_helix when available,
# but the core 3R monitor operates without them.
_HAS_NUMPY = False
try:
    import numpy  # noqa: F401

    _HAS_NUMPY = True
except ImportError:
    pass


def _median_sorted(values: List[float]) -> float:
    """Median of a pre-sorted list. O(1) after sort."""
    n = len(values)
    if n == 0:
        return 0.0
    mid = n // 2
    if n % 2 == 1:
        return values[mid]
    return (values[mid - 1] + values[mid]) / 2.0


def _mean(values: List[float]) -> float:
    """Arithmetic mean."""
    if not values:
        return 0.0
    return sum(values) / len(values)


def _std(values: List[float]) -> float:
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


__version__ = "2.0"
__all__ = [
    "IncrementalStats",
    "EWMAStats",
    "TimingAnomaly",
    "PatternAnomaly",
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

    def __init__(
        self,
        threshold_sigma: float = 3.0,
        window_size: int = 100,
        max_history: int = 10000,
        use_ewma: bool = True,
        ewma_alpha: float = 0.1,
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

        Performance Optimization:
            Uses collections.deque with maxlen for O(1) append and automatic
            pruning, and EWMA/Welford's algorithm for O(1) incremental statistics.
        """
        self.threshold = threshold_sigma
        self.window_size = window_size
        self.max_history = max_history
        self.use_ewma = use_ewma
        self.ewma_alpha = ewma_alpha
        # Use deque with maxlen for O(1) append and automatic pruning
        self.timing_history: Dict[str, Deque[float]] = {}
        self.baseline_stats: Dict[str, Dict[str, float]] = {}
        # Per-operation statistics (separate baselines for each operation type)
        self._incremental_stats: Dict[str, IncrementalStats] = {}
        self._ewma_stats: Dict[str, EWMAStats] = {}

    def record_timing(self, operation: str, duration_ms: float) -> Optional[TimingAnomaly]:
        """
        Record operation timing and detect anomalies.

        Uses per-operation baselines to maintain separate statistics for
        each type of cryptographic operation (e.g., ed25519_sign vs dilithium_verify).

        Args:
            operation: Name of cryptographic operation (e.g., 'ed25519_sign',
                'dilithium_sign', 'kyber_encaps', etc.)
            duration_ms: Observed duration in milliseconds

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

        # O(1) append with automatic pruning via deque maxlen
        self.timing_history[operation].append(duration_ms)

        # Update both stats (EWMA provides responsiveness, Welford provides accuracy)
        self._incremental_stats[operation].update(duration_ms)
        ewma_mean, ewma_std = self._ewma_stats[operation].update(duration_ms)

        # Get sample count
        sample_count = self._incremental_stats[operation].n

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

        # Detect statistical anomaly using both Z-score and MAD
        is_anomaly = False
        deviation = 0.0

        # Numerical tolerance for floating-point threshold comparisons
        # This prevents flaky behavior when deviation is very close to threshold
        # (e.g., 2.9984 vs 3.0 due to EWMA variance calculation)
        THRESHOLD_EPSILON = 0.01

        # Primary: Z-score based detection
        # Use >= with epsilon tolerance for numerical robustness
        if std > 0:
            deviation = abs(duration_ms - mean) / std
            if deviation >= self.threshold - THRESHOLD_EPSILON:
                is_anomaly = True

        # Secondary: MAD-based detection (more robust to outliers)
        if self.use_ewma and self._ewma_stats[operation].is_anomaly_mad(duration_ms):
            is_anomaly = True

        if is_anomaly:
            # Critical threshold: 5.0σ with same epsilon tolerance
            CRITICAL_THRESHOLD = 5.0
            severity = (
                "critical" if deviation >= CRITICAL_THRESHOLD - THRESHOLD_EPSILON else "warning"
            )
            return TimingAnomaly(
                operation=operation,
                expected_ms=mean,
                observed_ms=duration_ms,
                deviation_sigma=deviation,
                severity=severity,
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

    def __init__(self) -> None:
        """Initialize analyzer with empty cache."""
        self.analysis_cache: Dict[str, Dict] = {}

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

    def __init__(self, enabled: bool = False, alert_retention: int = 1000) -> None:
        """
        Initialize monitor.

        Args:
            enabled: Whether monitoring is active. Default False for
                zero-overhead operation when not needed.
            alert_retention: Maximum alerts to retain in memory.
                Prevents unbounded memory growth.
        """
        self.enabled = enabled
        self.alert_retention = alert_retention
        self.timing = ResonanceTimingMonitor()
        self.patterns = RecursionPatternMonitor()
        self.analyzer = RefactoringAnalyzer()
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
