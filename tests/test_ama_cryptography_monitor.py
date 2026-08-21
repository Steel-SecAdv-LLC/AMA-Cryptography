#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography: 3R Monitoring Test Suite
===============================================

Comprehensive test suite for AMA Cryptography 3R Monitoring.

Tests cover:
- ResonanceEngine timing detection
- RecursionEngine pattern analysis
- RefactoringAnalyzer complexity metrics
- AmaCryptographyMonitor integration
- Performance overhead validation

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Contact: steel.sa.llc@gmail.com
Date: 2026-04-17
Version: 3.0.0
Project: AMA Cryptography 3R Test Suite

AI Co-Architects:
    Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
"""

import ast
import math
import sys
import time
from typing import Any

import pytest

try:
    import numpy as np
except ImportError:
    pytest.skip("numpy not installed", allow_module_level=True)

from ama_cryptography.monitor import (
    AmaCryptographyMonitor,
    IncrementalStats,
    RecursionPatternMonitor,
    RefactoringAnalyzer,
    ResonanceTimingMonitor,
    TimingAnomaly,
    VolumeSpikeDetector,
)


class TestIncrementalStats:
    """
    Test suite for IncrementalStats (Welford's online algorithm).

    Tests verify O(1) incremental statistics computation produces identical
    results to numpy's mean() and std() functions.
    """

    def test_initialization_empty_state(self) -> None:
        """Test that IncrementalStats initializes with empty state."""
        stats = IncrementalStats()
        assert stats.n == 0
        assert stats.mean == 0.0
        assert stats.M2 == 0.0

    def test_single_value_addition(self) -> None:
        """Test statistics after adding a single value."""
        stats = IncrementalStats()
        mean, std = stats.update(10.0)

        assert stats.n == 1
        assert mean == 10.0
        assert std == 0.0  # No variance with single value

    def test_multiple_value_addition(self) -> None:
        """Test statistics after adding multiple values."""
        stats = IncrementalStats()
        values = [10.0, 20.0, 30.0, 40.0, 50.0]

        for v in values:
            stats.update(v)

        mean, std = stats.get_stats()

        # Compare to numpy
        expected_mean = np.mean(values)
        expected_std = np.std(values)

        assert abs(mean - expected_mean) < 1e-10
        assert abs(std - expected_std) < 1e-10

    def test_mean_calculation_accuracy(self) -> None:
        """Test mean calculation accuracy compared to numpy."""
        stats = IncrementalStats()
        values = [1.5, 2.7, 3.2, 4.8, 5.1, 6.9, 7.3, 8.6, 9.4, 10.2]

        for v in values:
            stats.update(v)

        mean, _ = stats.get_stats()
        expected_mean = np.mean(values)

        assert abs(mean - expected_mean) < 1e-10

    def test_standard_deviation_accuracy(self) -> None:
        """Test standard deviation calculation accuracy compared to numpy."""
        stats = IncrementalStats()
        values = [2.3, 4.5, 6.7, 8.9, 10.1, 12.3, 14.5, 16.7, 18.9, 20.1]

        for v in values:
            stats.update(v)

        _, std = stats.get_stats()
        expected_std = np.std(values)

        assert abs(std - expected_std) < 1e-10

    def test_variance_calculation(self) -> None:
        """Test variance calculation (M2/n)."""
        stats = IncrementalStats()
        values = [1.0, 2.0, 3.0, 4.0, 5.0]

        for v in values:
            stats.update(v)

        # Variance = M2 / n
        variance = stats.M2 / stats.n
        expected_variance = np.var(values)

        assert abs(variance - expected_variance) < 1e-10

    def test_edge_case_zero_values(self) -> None:
        """Test with all zero values."""
        stats = IncrementalStats()
        values = [0.0, 0.0, 0.0, 0.0, 0.0]

        for v in values:
            stats.update(v)

        mean, std = stats.get_stats()

        assert mean == 0.0
        assert std == 0.0

    def test_edge_case_negative_values(self) -> None:
        """Test with negative values."""
        stats = IncrementalStats()
        values = [-10.0, -5.0, 0.0, 5.0, 10.0]

        for v in values:
            stats.update(v)

        mean, std = stats.get_stats()
        expected_mean = np.mean(values)
        expected_std = np.std(values)

        assert abs(mean - expected_mean) < 1e-10
        assert abs(std - expected_std) < 1e-10

    def test_edge_case_very_large_values(self) -> None:
        """Test with very large values for numerical stability."""
        stats = IncrementalStats()
        values = [1e10, 1e10 + 1, 1e10 + 2, 1e10 + 3, 1e10 + 4]

        for v in values:
            stats.update(v)

        mean, std = stats.get_stats()
        expected_mean = np.mean(values)
        expected_std = np.std(values)

        # Allow slightly larger tolerance for large values
        assert abs(mean - expected_mean) < 1e-5
        assert abs(std - expected_std) < 1e-5

    def test_numerical_stability_many_values(self) -> None:
        """Test numerical stability with 1000+ values."""
        stats = IncrementalStats()
        np.random.seed(42)  # Reproducible
        values = list(np.random.randn(1000) * 100 + 500)  # Mean ~500, std ~100

        for v in values:
            stats.update(float(v))

        mean, std = stats.get_stats()
        expected_mean = np.mean(values)
        expected_std = np.std(values)

        # Welford's algorithm should maintain accuracy even with many values
        assert abs(mean - expected_mean) < 1e-8
        assert abs(std - expected_std) < 1e-8

    def test_reset_functionality(self) -> None:
        """Test that reset() clears all accumulators."""
        stats = IncrementalStats()

        # Add some values
        for v in [10.0, 20.0, 30.0]:
            stats.update(v)

        assert stats.n == 3
        assert stats.mean != 0.0

        # Reset
        stats.reset()

        assert stats.n == 0
        assert stats.mean == 0.0
        assert stats.M2 == 0.0

    def test_get_stats_with_insufficient_data(self) -> None:
        """Test get_stats() with 0 or 1 values."""
        stats = IncrementalStats()

        # No values
        mean, std = stats.get_stats()
        assert mean == 0.0
        assert std == 0.0

        # One value
        stats.update(42.0)
        mean, std = stats.get_stats()
        assert mean == 42.0
        assert std == 0.0  # No variance with single value

    def test_update_returns_current_stats(self) -> None:
        """Test that update() returns current mean and std."""
        stats = IncrementalStats()

        mean1, std1 = stats.update(10.0)
        assert mean1 == 10.0
        assert std1 == 0.0

        mean2, std2 = stats.update(20.0)
        assert mean2 == 15.0  # (10 + 20) / 2
        # std should be non-zero now
        assert std2 > 0

    def test_consistency_with_numpy_random_data(self) -> None:
        """Test consistency with numpy using random data."""
        np.random.seed(123)
        for _ in range(10):  # Run multiple trials
            stats = IncrementalStats()
            values = np.random.uniform(-1000, 1000, size=100).tolist()

            for v in values:
                stats.update(v)

            mean, std = stats.get_stats()
            expected_mean = np.mean(values)
            expected_std = np.std(values)

            assert abs(mean - expected_mean) < 1e-8
            assert abs(std - expected_std) < 1e-8


class TestResonanceTimingMonitor:
    """Test suite for ResonanceEngine timing analysis."""

    def test_initialization(self) -> None:
        """Test monitor initialization with various parameters."""
        monitor = ResonanceTimingMonitor()
        assert monitor.threshold == 3.0
        assert monitor.window_size == 100
        assert monitor.max_history == 10000
        assert len(monitor.timing_history) == 0

        # Custom parameters
        monitor = ResonanceTimingMonitor(threshold_sigma=2.5, window_size=50, max_history=5000)
        assert monitor.threshold == 2.5
        assert monitor.window_size == 50
        assert monitor.max_history == 5000

    def test_record_timing_builds_baseline(self) -> None:
        """Test that baseline statistics are established after 30+ samples."""
        monitor = ResonanceTimingMonitor()

        # Record timings
        for _ in range(50):
            _ = monitor.record_timing("test_op", 10.0 + np.random.randn())

        # Baseline should exist
        assert "test_op" in monitor.baseline_stats
        stats = monitor.baseline_stats["test_op"]
        assert "mean" in stats
        assert "std" in stats
        assert abs(stats["mean"] - 10.0) < 1.0  # Should be ~10.0

    def test_anomaly_detection_no_baseline(self) -> None:
        """Test that anomaly detection requires baseline (30+ samples)."""
        monitor = ResonanceTimingMonitor()

        # Record few samples
        for _ in range(10):
            monitor.record_timing("test_op", 10.0)

        # No anomaly should be detected yet
        anomaly = monitor.record_timing("test_op", 100.0)  # Huge spike
        assert anomaly is None  # Baseline not established

    def test_anomaly_detection_with_baseline(self) -> None:
        """Test anomaly detection after baseline established."""
        monitor = ResonanceTimingMonitor(threshold_sigma=3.0)

        # Establish baseline with tight distribution
        for _ in range(50):
            monitor.record_timing("test_op", 10.0 + 0.1 * np.random.randn())

        # Inject anomaly - use extreme value to ensure detection with EWMA
        # EWMA updates stats with the anomaly value before checking, so we need
        # a value far enough from baseline to still be detected as anomaly
        anomaly = monitor.record_timing("test_op", 50.0)  # Clear outlier

        assert anomaly is not None
        assert isinstance(anomaly, TimingAnomaly)
        assert anomaly.operation == "test_op"
        # With EWMA, deviation may be slightly below threshold due to variance update
        # The implementation uses epsilon tolerance (0.01) for numerical robustness
        assert anomaly.deviation_sigma >= 2.99  # Allow for EWMA variance effects
        assert anomaly.severity in ["warning", "critical"]

    def test_anomaly_severity_levels(self) -> None:
        """Severity escalates with magnitude — once the threshold is calibrated.

        The 5.0.0 contract has two stages:

        * Pre-calibration (fewer than ~100 post-warmup scores): the sigma
          floor governs, and severity is capped at 'warning' — paging a
          human requires an empirically measured tail, not an assumption.
        * Calibrated: 'critical' at twice the operating threshold.

        On the deterministic alternating baseline the robust scale is
        1.4826 * MAD = 0.14826, so with the default 3.0 floor the warning
        band starts at ~10.44 and (once calibrated) criticality at ~10.89.
        """
        monitor = ResonanceTimingMonitor(threshold_sigma=3.0)

        # Stage 1: 50 samples — beyond warmup (30) but far below the ~100
        # scores calibration needs.  A gross outlier alarms, but only at
        # 'warning': criticality is not available uncalibrated.
        for value in [9.9, 10.1] * 25:
            monitor.record_timing("test_op", value)
        anomaly = monitor.record_timing("test_op", 50.0)
        assert anomaly is not None
        assert anomaly.severity == "warning", "uncalibrated operations must not page"

        # Stage 2: continue the clean baseline until the empirical threshold
        # activates (>= 100 post-warmup scores), on a fresh monitor so the
        # 50.0 spike does not sit in the calibration history.
        monitor = ResonanceTimingMonitor(threshold_sigma=3.0)
        for value in [9.9, 10.1] * 100:  # 200 samples -> 170 scores
            monitor.record_timing("test_op", value)

        # Warning band: 10.6 is ~4.0 robust sigma — above the 3.0 floor
        # (clean alternating scores calibrate near 0.67, so the floor
        # governs), below the 6.0 criticality boundary.
        anomaly = monitor.record_timing("test_op", 10.6)
        assert anomaly is not None
        assert anomaly.severity == "warning"

        # Critical: 11.0 is ~6.7 robust sigma >= 2 x the operating
        # threshold.  Unreachable before 5.0.0 (the z-score was
        # mathematically capped below 3.0); reachable and pinned now.
        anomaly = monitor.record_timing("test_op", 11.0)
        assert anomaly is not None
        assert anomaly.severity == "critical"

    def test_detect_resonance_insufficient_data(self) -> None:
        """Test resonance detection with insufficient samples."""
        monitor = ResonanceTimingMonitor()

        # Too few samples
        for _ in range(5):
            monitor.record_timing("test_op", 10.0)

        resonance = monitor.detect_resonance("test_op")
        assert resonance == {}  # Empty dict

    def test_detect_resonance_with_periodic_pattern(self) -> None:
        """Test resonance detection with artificial periodic pattern."""
        monitor = ResonanceTimingMonitor()

        # Create periodic timing pattern (sine wave)
        for i in range(100):
            timing = 10.0 + 2.0 * np.sin(2 * np.pi * i / 10)
            monitor.record_timing("test_op", timing)

        resonance = monitor.detect_resonance("test_op")

        assert "dominant_frequency" in resonance
        assert "dominant_power" in resonance
        assert "has_resonance" in resonance
        # Strong periodic pattern should trigger resonance detection
        assert resonance["resonance_ratio"] > 1.0

    def test_history_pruning(self) -> None:
        """Test that history is pruned to prevent memory exhaustion."""
        monitor = ResonanceTimingMonitor(max_history=100)

        # Record more than max_history samples
        for _ in range(200):
            monitor.record_timing("test_op", 10.0)

        # History should be capped
        assert len(monitor.timing_history["test_op"]) == 100


class TestRecursionPatternMonitor:
    """Test suite for RecursionEngine pattern analysis."""

    def test_initialization(self) -> None:
        """Test pattern monitor initialization."""
        monitor = RecursionPatternMonitor()
        assert monitor.max_depth == 3
        assert monitor.max_history == 10000
        assert len(monitor.package_history) == 0

    def test_record_package(self) -> None:
        """Test package metadata recording."""
        monitor = RecursionPatternMonitor()

        metadata = {"author": "test-user", "code_count": 7, "content_hash": "abc123"}

        monitor.record_package(metadata)

        assert len(monitor.package_history) == 1
        assert monitor.package_history[0]["author"] == "test-user"
        assert "timestamp" in monitor.package_history[0]

    def test_analyze_patterns_insufficient_data(self) -> None:
        """Test analysis with insufficient data."""
        monitor = RecursionPatternMonitor()

        # Record < 10 packages
        for _ in range(5):
            monitor.record_package({"code_count": 7})

        analysis = monitor.analyze_patterns()
        assert analysis["status"] == "insufficient_data"

    def test_analyze_patterns_normal_behavior(self, monkeypatch: Any) -> Any:
        """Test analysis with normal signing patterns.

        Uses deterministic timestamps to avoid CI timing jitter causing
        false positive anomalies. The test verifies that perfectly regular
        intervals (0.01s apart) produce zero anomalies.
        """
        monitor = RecursionPatternMonitor()

        # Create deterministic timestamps: exactly 0.01s apart
        base_time = 1000000.0
        call_count = [0]

        def mock_time() -> Any:
            result = base_time + call_count[0] * 0.01
            call_count[0] += 1
            return result

        # Patch time.time in the ama_cryptography_monitor module
        monkeypatch.setattr(sys.modules["ama_cryptography_monitor"].time, "time", mock_time)

        # Record normal packages with deterministic timestamps
        for _ in range(20):
            monitor.record_package({"code_count": 7})

        analysis = monitor.analyze_patterns()

        assert analysis["status"] == "analyzed"
        assert "features" in analysis
        assert "anomalies" in analysis
        assert len(analysis["anomalies"]) == 0  # Normal behavior

    def test_analyze_patterns_detects_frequency_anomaly(self, monkeypatch: Any) -> Any:
        """Test detection of unusual signing frequency.

        Uses deterministic timestamps to reliably trigger frequency anomaly
        detection. Creates 15 regular intervals followed by one large gap.
        """
        monitor = RecursionPatternMonitor()

        # Create deterministic timestamps: 15 regular intervals, then one large gap
        base_time = 1000000.0
        # 15 packages at 0.05s intervals, then 16th package after 0.5s gap
        timestamps = [base_time + i * 0.05 for i in range(15)]
        timestamps.append(timestamps[-1] + 0.5)  # Large gap for anomaly
        timestamp_iter = iter(timestamps)

        def mock_time() -> Any:
            return next(timestamp_iter)

        # Patch time.time in the ama_cryptography_monitor module
        monkeypatch.setattr(sys.modules["ama_cryptography_monitor"].time, "time", mock_time)

        # Record packages with deterministic timestamps
        for _ in range(16):
            monitor.record_package({"code_count": 7})

        analysis = monitor.analyze_patterns()

        # Should detect frequency anomaly
        anomalies = analysis.get("anomalies", [])
        frequency_anomalies = [a for a in anomalies if a["type"] == "unusual_frequency"]
        assert len(frequency_anomalies) > 0

    def test_recursive_feature_extraction(self, monkeypatch: Any) -> Any:
        """Test hierarchical feature extraction.

        Uses deterministic timestamps to ensure consistent feature extraction
        across all CI environments.
        """
        monitor = RecursionPatternMonitor(max_depth=3)

        # Create deterministic timestamps: exactly 0.01s apart
        base_time = 1000000.0
        call_count = [0]

        def mock_time() -> Any:
            result = base_time + call_count[0] * 0.01
            call_count[0] += 1
            return result

        # Patch time.time in the ama_cryptography_monitor module
        monkeypatch.setattr(sys.modules["ama_cryptography_monitor"].time, "time", mock_time)

        # Record packages with deterministic timestamps
        for _ in range(30):
            monitor.record_package({"code_count": 7})

        analysis = monitor.analyze_patterns()
        features = analysis["features"]

        # Should have features at multiple levels
        assert "level_0_mean" in features
        assert "level_1_mean" in features
        # Level 2 may or may not exist depending on downsampling

    def test_package_size_anomaly_detection(self, monkeypatch: Any) -> Any:
        """Test detection of unusual package sizes.

        Uses deterministic timestamps to ensure consistent behavior across
        all CI environments.
        """
        monitor = RecursionPatternMonitor()

        # Create deterministic timestamps: exactly 0.01s apart
        base_time = 1000000.0
        call_count = [0]

        def mock_time() -> Any:
            result = base_time + call_count[0] * 0.01
            call_count[0] += 1
            return result

        # Patch time.time in the ama_cryptography_monitor module
        monkeypatch.setattr(sys.modules["ama_cryptography_monitor"].time, "time", mock_time)

        # Normal size: 7 codes
        for _ in range(15):
            monitor.record_package({"code_count": 7})

        # Unusual size: 100 codes
        monitor.record_package({"code_count": 100})

        analysis = monitor.analyze_patterns()

        # Should detect size anomaly
        anomalies = analysis.get("anomalies", [])
        size_anomalies = [a for a in anomalies if a["type"] == "unusual_package_size"]
        # May or may not trigger depending on variance
        # But structure should be correct
        for anomaly in size_anomalies:
            assert "z_score" in anomaly
            assert "severity" in anomaly


class TestSharedMonitorConcurrency:
    """The reader/analyzer races the PR's writer locks had not covered.

    Both were reproduced as RuntimeError crashes against the pre-fix code
    (deque/dict mutated during iteration) with the tracebacks landing in
    analyze_patterns and get_security_report — the first escaping through
    the public create_crypto_package after signatures were computed, the
    second killing an unguarded posture-evaluation cycle.  Threaded by
    necessity: the property is exactly "no exception under concurrent
    writers", and each pre-fix failure reproduced well inside the window
    driven here.  The workers catch Exception, not BaseException: every
    failure class the fixes close (and any future library error) is an
    Exception, while BaseException would also swallow KeyboardInterrupt /
    SystemExit inside the loop — masking a Ctrl-C during a local run, which
    is CodeQL's objection (alerts 626/627) and correct.
    """

    def test_pattern_monitor_analyze_survives_concurrent_recording(self) -> None:
        import threading

        monitor = RecursionPatternMonitor(max_history=2000)
        stop = threading.Event()
        errors: list[Exception] = []

        def writer() -> None:
            i = 0
            while not stop.is_set():
                monitor.record_package(
                    {"author": f"a{i % 7}", "code_count": i % 13, "content_hash": "x" * 16}
                )
                i += 1

        threads = [threading.Thread(target=writer) for _ in range(4)]
        for t in threads:
            t.start()
        try:
            deadline = time.time() + 2.0
            while time.time() < deadline:
                try:
                    monitor.analyze_patterns()
                    monitor.monitor_key_usage({"key_id": "k1", "usage_count": 1, "max_usage": 1000})
                except Exception as exc:
                    errors.append(exc)
                    break
        finally:
            stop.set()
            for t in threads:
                t.join()
        assert errors == [], f"analysis raced concurrent recording: {errors!r}"

    def test_security_report_survives_concurrent_first_time_operations(self) -> None:
        import threading

        monitor = AmaCryptographyMonitor()
        stop = threading.Event()
        errors: list[Exception] = []

        def writer() -> None:
            i = 0
            while not stop.is_set():
                # A FRESH operation name each record: the race window is the
                # first-ever insert of a key into timing_history.
                monitor.monitor_crypto_operation(f"op-{i}", 0.01)
                i += 1

        t = threading.Thread(target=writer)
        t.start()
        try:
            deadline = time.time() + 2.0
            while time.time() < deadline:
                try:
                    monitor.get_security_report()
                except Exception as exc:
                    errors.append(exc)
                    break
        finally:
            stop.set()
            t.join()
        assert errors == [], f"report reader raced first-time inserts: {errors!r}"


class TestRefactoringAnalyzer:
    """Test suite for RefactoringEngine code analysis."""

    @pytest.fixture
    def sample_code_simple(self, tmp_path: Any) -> Any:
        """Create simple Python file for testing."""
        code = """
def simple_function(x):
    \"\"\"A simple function.\"\"\"
    return x + 1

def moderate_function(x, y):
    \"\"\"A function with some complexity.\"\"\"
    if x > 0:
        if y > 0:
            return x + y
        else:
            return x - y
    return 0

class SimpleClass:
    \"\"\"A simple class.\"\"\"
    pass
"""
        file_path = tmp_path / "simple.py"
        file_path.write_text(code)
        return file_path

    @pytest.fixture
    def sample_code_complex(self, tmp_path: Any) -> Any:
        """Create complex Python file for testing."""
        code = """
def complex_function(a, b, c, d):
    \"\"\"A complex function with high cyclomatic complexity.\"\"\"
    result = 0

    if a > 0:
        if b > 0:
            if c > 0:
                if d > 0:
                    result = a + b + c + d
                else:
                    result = a + b + c
            else:
                result = a + b
        else:
            result = a
    else:
        result = 0

    for i in range(10):
        if i % 2 == 0:
            result += i
        else:
            result -= i

    while result > 100:
        result -= 10

    return result
"""
        file_path = tmp_path / "complex.py"
        file_path.write_text(code)
        return file_path

    def test_initialization(self) -> None:
        """Test analyzer initialization."""
        analyzer = RefactoringAnalyzer()
        assert len(analyzer.analysis_cache) == 0

    def test_analyze_simple_file(self, sample_code_simple: Any) -> None:
        """Test analysis of simple code."""
        analyzer = RefactoringAnalyzer()
        results = analyzer.analyze_file(sample_code_simple)

        assert "error" not in results
        assert results["total_functions"] == 2
        assert results["total_classes"] == 1
        assert len(results["functions"]) == 2

        # Check function details
        func = results["functions"][0]
        assert "name" in func
        assert "complexity" in func
        assert "lines" in func
        assert "recommendation" in func

    def test_analyze_complex_file(self, sample_code_complex: Any) -> None:
        """Test analysis of complex code."""
        analyzer = RefactoringAnalyzer()
        results = analyzer.analyze_file(sample_code_complex)

        assert results["total_functions"] == 1
        func = results["functions"][0]

        # Complex function should have moderate complexity (8 for this code)
        assert func["complexity"] >= 8
        # With complexity 8, should get "acceptable" recommendation
        assert "complexity" in func["recommendation"].lower()

    def test_complexity_calculation(self) -> None:
        """Test cyclomatic complexity calculation."""
        analyzer = RefactoringAnalyzer()

        # Simple function: complexity = 1
        code = "def f(x): return x"
        tree = ast.parse(code)
        func_node = tree.body[0]
        assert isinstance(func_node, ast.FunctionDef)
        complexity = analyzer._calculate_complexity(func_node)
        assert complexity == 1

        # Function with if: complexity = 2
        code = "def f(x):\n    if x > 0:\n        return x\n    return 0"
        tree = ast.parse(code)
        func_node = tree.body[0]
        assert isinstance(func_node, ast.FunctionDef)
        complexity = analyzer._calculate_complexity(func_node)
        assert complexity == 2

    def test_recommendation_generation(self) -> None:
        """Test refactoring recommendations."""
        analyzer = RefactoringAnalyzer()

        assert "Acceptable" in analyzer._get_recommendation(5)
        assert "Consider" in analyzer._get_recommendation(15)
        assert "Refactor recommended" in analyzer._get_recommendation(25)

    def test_analyze_invalid_file(self, tmp_path: Any) -> None:
        """Test analysis of invalid Python file."""
        invalid_file = tmp_path / "invalid.py"
        invalid_file.write_text("def invalid syntax!")

        analyzer = RefactoringAnalyzer()
        results = analyzer.analyze_file(invalid_file)

        assert "error" in results


class TestAmaCryptographyMonitor:
    """Test suite for integrated monitor."""

    def test_initialization_disabled(self) -> None:
        """Test monitor initialization in disabled state."""
        monitor = AmaCryptographyMonitor(enabled=False)

        assert monitor.enabled is False
        assert len(monitor.alerts) == 0

    def test_initialization_enabled(self) -> None:
        """Test monitor initialization in enabled state."""
        monitor = AmaCryptographyMonitor(enabled=True)

        assert monitor.enabled is True
        assert isinstance(monitor.timing, ResonanceTimingMonitor)
        assert isinstance(monitor.patterns, RecursionPatternMonitor)
        assert isinstance(monitor.analyzer, RefactoringAnalyzer)

    def test_monitor_crypto_operation_disabled(self) -> None:
        """Test that monitoring is no-op when disabled."""
        monitor = AmaCryptographyMonitor(enabled=False)

        # Should do nothing
        monitor.monitor_crypto_operation("test_op", 10.0)

        assert len(monitor.timing.timing_history) == 0
        assert len(monitor.alerts) == 0

    def test_monitor_crypto_operation_enabled(self) -> None:
        """Test operation monitoring when enabled."""
        monitor = AmaCryptographyMonitor(enabled=True)

        # Record operations
        for _ in range(50):
            monitor.monitor_crypto_operation("test_op", 10.0 + np.random.randn())

        assert "test_op" in monitor.timing.timing_history
        assert len(monitor.timing.timing_history["test_op"]) == 50

    def test_record_package_signing_disabled(self) -> None:
        """Test package recording is no-op when disabled."""
        monitor = AmaCryptographyMonitor(enabled=False)

        monitor.record_package_signing({"code_count": 7})

        assert len(monitor.patterns.package_history) == 0

    def test_record_package_signing_enabled(self, monkeypatch: Any) -> Any:
        """Test package recording when enabled.

        Uses deterministic timestamps to ensure consistent behavior across
        all CI environments.
        """
        monitor = AmaCryptographyMonitor(enabled=True)

        # Create deterministic timestamps
        base_time = 1000000.0
        call_count = [0]

        def mock_time() -> Any:
            result = base_time + call_count[0] * 0.01
            call_count[0] += 1
            return result

        # Patch time.time in the ama_cryptography_monitor module
        monkeypatch.setattr(sys.modules["ama_cryptography_monitor"].time, "time", mock_time)

        for _ in range(15):
            monitor.record_package_signing({"code_count": 7})

        assert len(monitor.patterns.package_history) == 15

    def test_get_security_report_disabled(self) -> None:
        """Test report generation when disabled."""
        monitor = AmaCryptographyMonitor(enabled=False)

        report = monitor.get_security_report()
        assert report["status"] == "monitoring_disabled"

    def test_get_security_report_enabled(self, monkeypatch: Any) -> Any:
        """Test comprehensive report generation.

        Uses deterministic timestamps to ensure consistent behavior across
        all CI environments.
        """
        monitor = AmaCryptographyMonitor(enabled=True)

        # Create deterministic timestamps
        base_time = 1000000.0
        call_count = [0]

        def mock_time() -> Any:
            result = base_time + call_count[0] * 0.01
            call_count[0] += 1
            return result

        # Patch time.time in the ama_cryptography_monitor module
        monkeypatch.setattr(sys.modules["ama_cryptography_monitor"].time, "time", mock_time)

        # Generate some activity
        for _ in range(20):
            monitor.monitor_crypto_operation("test_op", 10.0)
            monitor.record_package_signing({"code_count": 7})

        report = monitor.get_security_report()

        assert report["status"] == "active"
        assert "timing_baseline" in report
        assert "pattern_analysis" in report
        assert "recent_alerts" in report
        assert "total_alerts" in report
        assert "recommendations" in report

    def test_alert_pruning(self) -> None:
        """Test that alerts are pruned to prevent memory exhaustion."""
        monitor = AmaCryptographyMonitor(enabled=True, alert_retention=10)

        # Generate many alerts by establishing baseline then injecting
        # anomalies
        for _ in range(50):
            monitor.monitor_crypto_operation("test_op", 10.0)

        # Inject anomalies
        for _ in range(20):
            monitor.monitor_crypto_operation("test_op", 100.0)

        # Alerts should be capped
        assert len(monitor.alerts) <= 10


# Integration test markers
@pytest.mark.integration
class TestMonitorIntegration:
    """Integration tests with full AMA Cryptography system."""

    def test_end_to_end_monitoring(self) -> None:
        """Test complete workflow with monitoring and baseline convergence."""
        # Import here to avoid circular dependency
        import sys
        from pathlib import Path

        # Add parent directory to path
        sys.path.insert(0, str(Path(__file__).parent.parent))

        try:
            from ama_cryptography.legacy_compat import (
                MASTER_CODES_STR,
                MASTER_HELIX_PARAMS,
                create_crypto_package,
                generate_key_management_system,
                verify_crypto_package,
            )
        except RuntimeError:
            pytest.skip("Native C library required for ama_cryptography.legacy_compat")
            return  # pragma: no cover — unreachable; tells static analysis skip() diverges

        # Setup
        monitor = AmaCryptographyMonitor(enabled=True)
        kms = generate_key_management_system("integration-test")

        # Run 32 create+verify cycles to exceed the 30-sample baseline threshold.
        # The monitor requires 30+ timing samples per operation before populating
        # baseline_stats for anomaly detection.
        for _cycle in range(32):
            pkg = create_crypto_package(
                MASTER_CODES_STR, MASTER_HELIX_PARAMS, kms, "test", monitor=monitor
            )

            results = verify_crypto_package(
                MASTER_CODES_STR,
                MASTER_HELIX_PARAMS,
                pkg,
                kms.hmac_key,
                monitor=monitor,
            )

        # Core checks should pass (rfc3161 is None when no TSA is used)
        core_checks = {k: v for k, v in results.items() if v is not None}
        assert all(core_checks.values()), f"Failed checks: {results}"

        # Monitor should be active with populated baseline stats
        report = monitor.get_security_report()
        assert report["status"] == "active"
        assert (
            len(report["timing_baseline"]) > 0
        ), "timing_baseline should be populated after 32 cycles"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])


class TestResonanceFlagIsCalibrated:
    """``has_resonance`` must mean something, in both directions.

    Two independent defects made it mean nothing before 5.0.0, and each is
    pinned separately here so a regression in either is attributable.

    1. **The DC component was never removed.**  The series was transformed as
       given, so the operation's baseline duration — the largest thing in the
       signal by orders of magnitude — leaked across the whole spectrum through
       the zero-padding window, and the search, which excluded only bin 0,
       found that leakage.  Measured on the pre-fix code, a PERFECTLY CONSTANT
       100-sample series reported ``resonance_ratio`` 30.31 and
       ``has_resonance`` True.

    2. **The bar was a constant 3.0.**  For white noise the periodogram
       ordinates are iid exponential, so the maximum-to-mean ratio over m of
       them concentrates near ln(m) — 4.16 at m = 64, already past 3.0.
       Measured over 2,000 iid-Gaussian trials at each of n = 64/96/100/128,
       the old flag fired on 88.4 %, 100 %, 100 % and 99.1 % of clean series.

    The same sweep against the current code gives 0.40 %-0.60 %, against a
    nominal :attr:`ResonanceTimingMonitor.RESONANCE_FALSE_ALARM_RATE` of 1 %.
    """

    @staticmethod
    def _feed(window: int, values: list[float]) -> dict[str, Any]:
        monitor = ResonanceTimingMonitor(window_size=window)
        for value in values:
            monitor.record_timing("op", value)
        return dict(monitor.detect_resonance("op"))

    @staticmethod
    def _lcg(seed: int) -> Any:
        """A deterministic uniform stream, so the sweep below is reproducible
        on every runner without depending on ``random``'s global state."""
        state = seed & 0xFFFFFFFF

        def nxt() -> float:
            nonlocal state
            state = (1103515245 * state + 12345) & 0x7FFFFFFF
            return state / float(0x7FFFFFFF)

        return nxt

    def test_a_constant_series_does_not_resonate(self) -> None:
        """The regression this class exists for.

        A constant series has no periodic component whatsoever.  100 samples
        is the interesting length: it pads to 128, and it was the padding that
        spread the un-removed DC term.
        """
        for n in (12, 64, 100, 127):
            result = self._feed(n, [1.0] * n)
            assert result["resonance_ratio"] == 0.0, (n, result)
            assert result["has_resonance"] is False, (n, result)

    def test_a_periodic_probe_still_resonates(self) -> None:
        """Non-vacuity: the fix must not have been "return False".

        A strictly alternating fast/slow probe is the reconnaissance shape this
        component exists to see, and it lands exactly on the Nyquist bin — the
        one a naive "scan the lower half, drop the mirror" would discard.
        """
        result = self._feed(64, [1.0 if i % 2 == 0 else 2.0 for i in range(96)])
        assert result["has_resonance"] is True, result
        # Measured: ratio 32.0 against a threshold of 8.07, a margin of 3.96x.
        # The bar is 3.5x so a real loss of sensitivity fails here rather than
        # only in the boolean above, without pinning the exact measured value.
        assert result["resonance_ratio"] > 3.5 * result["threshold_ratio"], result

    def test_the_threshold_is_the_fisher_bar_for_the_bins_it_searched(self) -> None:
        """The bar must depend on m; a constant bar is what failed."""
        seen = set()
        for n in (16, 64, 100, 128):
            result = self._feed(n, [1.0 + 0.01 * (i % 7) for i in range(n)])
            m = result["scanned_bins"]
            expected = math.log(m / ResonanceTimingMonitor.RESONANCE_FALSE_ALARM_RATE)
            assert result["threshold_ratio"] == pytest.approx(expected), (n, result)
            seen.add(m)
        assert len(seen) > 1, "the sweep must actually vary the ordinate count"

    def test_clean_aperiodic_traffic_is_within_the_declared_false_alarm_rate(
        self,
    ) -> None:
        """The property the ``alpha`` parameter promises, measured.

        300 trials per size, deterministic. The bar is 5x the nominal rate: the
        test must catch "fires on nearly everything" (the measured pre-fix
        behaviour, 88-100 %) without failing on the binomial spread of a
        300-trial estimate of a 1 % rate.
        """
        nominal = ResonanceTimingMonitor.RESONANCE_FALSE_ALARM_RATE
        for n in (64, 100, 128):
            nxt = self._lcg(0xA5A5 + n)
            trials = 300
            fired = 0
            for _ in range(trials):
                # Irwin-Hall(4): symmetric, finite-support, no dependence on
                # the platform's normal-variate implementation.
                series = [1.0 + 0.05 * (sum(nxt() for _ in range(4)) - 2.0) for _ in range(n)]
                fired += bool(self._feed(n, series)["has_resonance"])
            rate = fired / trials
            assert rate <= 5.0 * nominal, (
                f"n={n}: has_resonance fired on {rate * 100:.1f}% of clean aperiodic "
                f"series against a declared {nominal * 100:.1f}% false-alarm rate"
            )


class TestTheMonitorIsBoundedAndItsReportIsASnapshot:
    """Three properties this monitor claimed and did not have.

    All three are about ``operation``, which reaches the monitor from
    :meth:`AmaCryptographyMonitor.monitor_crypto_operation` — public API taking
    an arbitrary string.  Its two sibling detectors in the same module already
    bound what a caller can make them hold (``VolumeSpikeDetector`` caps
    operation names, ``RecursionPatternMonitor`` caps tracked keys, both with
    the same one-line rationale: a monitoring component must not become the
    memory-exhaustion vector).  ``ResonanceTimingMonitor`` was the one that did
    not.
    """

    @staticmethod
    def _lcg(seed: int) -> Any:
        state = seed & 0xFFFFFFFF

        def nxt() -> float:
            nonlocal state
            state = (1103515245 * state + 12345) & 0x7FFFFFFF
            return state / float(0x7FFFFFFF)

        return nxt

    def test_operation_names_are_capped_and_the_drops_are_counted(self) -> None:
        """Nine per-operation dicts are keyed on a caller-supplied string."""
        monitor = ResonanceTimingMonitor(max_operations=8)
        for name in range(50):
            for _ in range(3):
                monitor.record_timing(f"op{name}", 1.0)
        assert len(monitor.timing_history) == 8
        assert monitor.dropped_operations == (50 - 8) * 3, monitor.dropped_operations
        # Every keyed structure must respect the same bound, not just the one
        # the admission test happens to consult.
        assert len(monitor.baseline_stats) <= 8
        assert len(monitor._incremental_stats) == 8
        assert len(monitor._ewma_stats) == 8
        assert len(monitor._score_history) == 8

    def test_an_admitted_operation_is_unaffected_by_the_cap(self) -> None:
        """Non-vacuity: the cap must not be "stop recording"."""
        monitor = ResonanceTimingMonitor(max_operations=2)
        for _ in range(40):
            monitor.record_timing("kept", 1.0)
        for _ in range(40):
            monitor.record_timing("dropped_one", 1.0)
            monitor.record_timing("dropped_two", 1.0)
        assert len(monitor.timing_history["kept"]) == 40
        anomaly = monitor.record_timing("kept", 50.0)
        assert anomaly is not None, "a real anomaly on an admitted name must still fire"

    def test_the_ratio_matrix_is_bounded_however_many_names_arrive(self) -> None:
        """It held exactly N(N-1)/2 deques and evicted none.

        Measured before the cap, at 300 names: 44,850 pair deques and a
        per-record cost of 0.371 ms against 0.021 ms at a single name — paid
        inside the lock that serialises every instrumented crypto call.
        """
        for names in (40, 300):
            monitor = ResonanceTimingMonitor(max_ratio_operations=6)
            for name in range(names):
                for _ in range(31):
                    monitor.record_timing(f"op{name}", 1.0 + 0.001 * name)
            assert len(monitor._ratio_ops) == 6
            assert len(monitor._ratio_samples) <= 6 * 5 // 2, len(monitor._ratio_samples)

    def test_the_report_is_a_snapshot_not_the_live_state(self) -> None:
        """``get_security_report`` handed out the monitor's live dict.

        Three lines below the comment where it fixes exactly this race for
        ``timing_history``.  An ordinary consumer iterating the returned
        mapping raised ``RuntimeError("dictionary changed size during
        iteration")`` within four seconds against a writer issuing fresh
        operation names.
        """
        monitor = AmaCryptographyMonitor()
        for _ in range(60):
            monitor.monitor_crypto_operation("sign", 1.0)
        # Force at least one alert so the alert assertions below are not
        # vacuous: a report with an empty alert list proves nothing about
        # whether the list it returns is the live one.
        for _ in range(4):
            monitor.monitor_crypto_operation("sign", 90.0)

        report = monitor.get_security_report()
        assert monitor.alerts, "the fixture failed to produce an alert"
        assert report["recent_alerts"], "the report carried no alert to check"

        assert report["timing_baseline"] is not monitor.timing.baseline_stats
        for op, stats in report["timing_baseline"].items():
            assert stats is not monitor.timing.baseline_stats[op], op
        # Mutating the snapshot must not reach the monitor.
        report["timing_baseline"]["injected"] = {"mean": 0.0}
        assert "injected" not in monitor.timing.baseline_stats

        assert report["recent_alerts"] is not monitor.alerts
        for alert in report["recent_alerts"]:
            assert all(
                alert is not live for live in monitor.alerts
            ), "the report shares alert dicts with the monitor's live list"

    def test_cross_operation_alarms_stay_within_the_declared_budget(self) -> None:
        """The ratio path had no budget, no calibration and no floor.

        ``abs(ratio - mu) / sigma > 3.0`` with mu, sigma frozen after 30
        CONSECUTIVE samples of ``EWMA_mean(a) / EWMA_mean(b)`` is not a
        3-sigma test: adjacent EWMA ratios are heavily autocorrelated, so that
        sigma measures short-term jitter rather than the spread the bar must
        sit outside.  Measured on two clean i.i.d. lognormal operations at
        4,000 records each, it alarmed on 1.9 % of the stream — nearly triple
        the point path's budgeted-and-gated 1 %.  The same stream now spends
        0.79 %.
        """
        nxt = self._lcg(0x5EED)
        monitor = ResonanceTimingMonitor()
        counts = {"point": 0, "shift": 0, "cross_operation": 0}
        records = 1500
        for _ in range(records):
            for op, scale in (("sign", 0.020), ("verify", 0.041)):
                # Irwin-Hall(4) jitter: deterministic, platform-independent.
                jitter = sum(nxt() for _ in range(4)) - 2.0
                anomaly = monitor.record_timing(op, scale * math.exp(0.25 * jitter))
                if anomaly is not None:
                    counts[anomaly.kind] = counts.get(anomaly.kind, 0) + 1
        total = 2 * records
        budget = ResonanceTimingMonitor.DEFAULT_ALARM_BUDGET
        rate = counts["cross_operation"] / total
        assert rate <= 3.0 * budget, (
            f"cross-operation alarms spent {rate * 100:.2f}% of a clean stream "
            f"against a declared {budget * 100:.1f}% budget: {counts}"
        )

    def test_a_real_cross_operation_divergence_still_alarms(self) -> None:
        """Non-vacuity for the budget test above.

        Calibrating the bar must not have turned the path off: a sustained
        change in the RATIO of two operations, with each operation's own
        distribution otherwise unremarkable, is the signal this path exists
        for and it must still be reported.
        """
        nxt = self._lcg(0xC0FFEE)
        monitor = ResonanceTimingMonitor()
        for _ in range(1500):
            for op, scale in (("sign", 0.020), ("verify", 0.041)):
                jitter = sum(nxt() for _ in range(4)) - 2.0
                monitor.record_timing(op, scale * math.exp(0.25 * jitter))
        # 'verify' alone slows by 8x: each operation's own baseline shifts, and
        # so does the pair ratio.
        seen = set()
        for _ in range(400):
            for op, scale in (("sign", 0.020), ("verify", 0.041 * 8.0)):
                jitter = sum(nxt() for _ in range(4)) - 2.0
                anomaly = monitor.record_timing(op, scale * math.exp(0.25 * jitter))
                if anomaly is not None:
                    seen.add(anomaly.kind)
        assert "cross_operation" in seen, seen


class TestTheVolumeAllowListIsRealConfiguration:
    """``DEFAULT_OPERATIONS`` described a filter nothing implemented.

    Its doc comment said "Everything else is ignored unless the caller passes
    it explicitly" while no code read the tuple, ``record()`` counted whatever
    string it was handed, and the constructor took no ``operations`` argument —
    so there was no "passes it explicitly" either.  Making the tuple the
    DEFAULT would have been worse than leaving it dead: it would silently stop
    counting every operation outside an eight-name list.  The filter is now
    real, opt-in, and its skips are counted.
    """

    def test_no_allow_list_counts_everything(self) -> None:
        detector = VolumeSpikeDetector()
        assert detector.operations is None
        for name in ("kyber_encaps", "some_new_kem", "x25519_scalarmult"):
            detector.record(name, now=0.0)
        assert detector.tracked_operations == 3
        assert detector.filtered_operations == 0

    def test_an_allow_list_filters_and_counts_the_skips(self) -> None:
        detector = VolumeSpikeDetector(operations=("kyber_encaps", "dilithium_sign"))
        for name in ("kyber_encaps", "dilithium_sign", "unrelated", "also_unrelated"):
            detector.record(name, now=0.0)
        assert detector.tracked_operations == 2
        assert detector.filtered_operations == 2

    def test_the_shipped_constant_is_usable_as_that_list(self) -> None:
        detector = VolumeSpikeDetector(operations=VolumeSpikeDetector.DEFAULT_OPERATIONS)
        for name in VolumeSpikeDetector.DEFAULT_OPERATIONS:
            detector.record(name, now=0.0)
        detector.record("not_in_the_list", now=0.0)
        assert detector.tracked_operations == len(VolumeSpikeDetector.DEFAULT_OPERATIONS)
        assert detector.filtered_operations == 1

    def test_an_empty_allow_list_is_rejected_rather_than_read_as_no_filter(self) -> None:
        """A detector configured to watch nothing is a configuration error."""
        with pytest.raises(ValueError):
            VolumeSpikeDetector(operations=())

    def test_a_filtered_operation_cannot_produce_a_spike(self) -> None:
        """Non-vacuity in the other direction: filtering must actually filter.

        Drives a burst well past every gate the detector has — warmup,
        min_burst_count, threshold_sigma — under a name outside the list.
        """
        detector = VolumeSpikeDetector(
            operations=("watched",), warmup_buckets=2, min_burst_count=4, threshold_sigma=1.0
        )
        spikes = []
        for bucket in range(6):
            for _ in range(2):
                spikes.append(detector.record("ignored", now=float(bucket)))
        for _ in range(500):
            spikes.append(detector.record("ignored", now=6.0))
        assert all(s is None for s in spikes)
        assert detector.tracked_operations == 0
        assert detector.filtered_operations == 512
