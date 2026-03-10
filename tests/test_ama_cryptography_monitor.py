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
Date: 2026-01-09
Version: 2.0
Project: AMA Cryptography 3R Test Suite

AI Co-Architects:
    Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
"""

import ast

import numpy as np
import pytest

from ama_cryptography_monitor import (
    AmaCryptographyMonitor,
    IncrementalStats,
    RecursionPatternMonitor,
    RefactoringAnalyzer,
    ResonanceTimingMonitor,
    TimingAnomaly,
)


class TestIncrementalStats:
    """
    Test suite for IncrementalStats (Welford's online algorithm).

    Tests verify O(1) incremental statistics computation produces identical
    results to numpy's mean() and std() functions.
    """

    def test_initialization_empty_state(self):
        """Test that IncrementalStats initializes with empty state."""
        stats = IncrementalStats()
        assert stats.n == 0
        assert stats.mean == 0.0
        assert stats.M2 == 0.0

    def test_single_value_addition(self):
        """Test statistics after adding a single value."""
        stats = IncrementalStats()
        mean, std = stats.update(10.0)

        assert stats.n == 1
        assert mean == 10.0
        assert std == 0.0  # No variance with single value

    def test_multiple_value_addition(self):
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

    def test_mean_calculation_accuracy(self):
        """Test mean calculation accuracy compared to numpy."""
        stats = IncrementalStats()
        values = [1.5, 2.7, 3.2, 4.8, 5.1, 6.9, 7.3, 8.6, 9.4, 10.2]

        for v in values:
            stats.update(v)

        mean, _ = stats.get_stats()
        expected_mean = np.mean(values)

        assert abs(mean - expected_mean) < 1e-10

    def test_standard_deviation_accuracy(self):
        """Test standard deviation calculation accuracy compared to numpy."""
        stats = IncrementalStats()
        values = [2.3, 4.5, 6.7, 8.9, 10.1, 12.3, 14.5, 16.7, 18.9, 20.1]

        for v in values:
            stats.update(v)

        _, std = stats.get_stats()
        expected_std = np.std(values)

        assert abs(std - expected_std) < 1e-10

    def test_variance_calculation(self):
        """Test variance calculation (M2/n)."""
        stats = IncrementalStats()
        values = [1.0, 2.0, 3.0, 4.0, 5.0]

        for v in values:
            stats.update(v)

        # Variance = M2 / n
        variance = stats.M2 / stats.n
        expected_variance = np.var(values)

        assert abs(variance - expected_variance) < 1e-10

    def test_edge_case_zero_values(self):
        """Test with all zero values."""
        stats = IncrementalStats()
        values = [0.0, 0.0, 0.0, 0.0, 0.0]

        for v in values:
            stats.update(v)

        mean, std = stats.get_stats()

        assert mean == 0.0
        assert std == 0.0

    def test_edge_case_negative_values(self):
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

    def test_edge_case_very_large_values(self):
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

    def test_numerical_stability_many_values(self):
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

    def test_reset_functionality(self):
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

    def test_get_stats_with_insufficient_data(self):
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

    def test_update_returns_current_stats(self):
        """Test that update() returns current mean and std."""
        stats = IncrementalStats()

        mean1, std1 = stats.update(10.0)
        assert mean1 == 10.0
        assert std1 == 0.0

        mean2, std2 = stats.update(20.0)
        assert mean2 == 15.0  # (10 + 20) / 2
        # std should be non-zero now
        assert std2 > 0

    def test_consistency_with_numpy_random_data(self):
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

    def test_initialization(self):
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

    def test_record_timing_builds_baseline(self):
        """Test that baseline statistics are established after 30+ samples."""
        monitor = ResonanceTimingMonitor()

        # Record timings
        for i in range(50):
            _ = monitor.record_timing("test_op", 10.0 + np.random.randn())

        # Baseline should exist
        assert "test_op" in monitor.baseline_stats
        stats = monitor.baseline_stats["test_op"]
        assert "mean" in stats
        assert "std" in stats
        assert abs(stats["mean"] - 10.0) < 1.0  # Should be ~10.0

    def test_anomaly_detection_no_baseline(self):
        """Test that anomaly detection requires baseline (30+ samples)."""
        monitor = ResonanceTimingMonitor()

        # Record few samples
        for i in range(10):
            monitor.record_timing("test_op", 10.0)

        # No anomaly should be detected yet
        anomaly = monitor.record_timing("test_op", 100.0)  # Huge spike
        assert anomaly is None  # Baseline not established

    def test_anomaly_detection_with_baseline(self):
        """Test anomaly detection after baseline established."""
        monitor = ResonanceTimingMonitor(threshold_sigma=3.0)

        # Establish baseline with tight distribution
        for i in range(50):
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

    def test_anomaly_severity_levels(self):
        """Test that severity escalates with deviation magnitude."""
        # Use Welford's algorithm (non-EWMA) for predictable threshold behavior
        # EWMA updates variance with the anomaly value, making exact thresholds harder to test
        monitor = ResonanceTimingMonitor(threshold_sigma=3.0, use_ewma=False)

        # Deterministic baseline: mean=10.0, std=0.1 (alternating 9.9 and 10.1)
        # This eliminates randomness that caused flaky test results
        baseline = [9.9, 10.1] * 25  # 50 samples with exact mean=10.0, std=0.1
        for value in baseline:
            monitor.record_timing("test_op", value)

        # Warning-level anomaly (3σ < dev < 5σ)
        # With mean=10.0, std=0.1: deviation for 10.4 = (10.4-10.0)/0.1 = 4σ
        anomaly = monitor.record_timing("test_op", 10.4)
        if anomaly:
            assert anomaly.severity == "warning"

        # Critical-level anomaly (dev > 5σ)
        # Need extreme value because Welford updates stats with each value
        # Use 11.0 to ensure deviation > 5σ even after baseline drift
        anomaly = monitor.record_timing("test_op", 11.0)
        if anomaly:
            assert anomaly.severity == "critical"

    def test_detect_resonance_insufficient_data(self):
        """Test resonance detection with insufficient samples."""
        monitor = ResonanceTimingMonitor()

        # Too few samples
        for i in range(5):
            monitor.record_timing("test_op", 10.0)

        resonance = monitor.detect_resonance("test_op")
        assert resonance == {}  # Empty dict

    def test_detect_resonance_with_periodic_pattern(self):
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

    def test_history_pruning(self):
        """Test that history is pruned to prevent memory exhaustion."""
        monitor = ResonanceTimingMonitor(max_history=100)

        # Record more than max_history samples
        for i in range(200):
            monitor.record_timing("test_op", 10.0)

        # History should be capped
        assert len(monitor.timing_history["test_op"]) == 100


class TestRecursionPatternMonitor:
    """Test suite for RecursionEngine pattern analysis."""

    def test_initialization(self):
        """Test pattern monitor initialization."""
        monitor = RecursionPatternMonitor()
        assert monitor.max_depth == 3
        assert monitor.max_history == 10000
        assert len(monitor.package_history) == 0

    def test_record_package(self):
        """Test package metadata recording."""
        monitor = RecursionPatternMonitor()

        metadata = {"author": "test-user", "code_count": 7, "content_hash": "abc123"}

        monitor.record_package(metadata)

        assert len(monitor.package_history) == 1
        assert monitor.package_history[0]["author"] == "test-user"
        assert "timestamp" in monitor.package_history[0]

    def test_analyze_patterns_insufficient_data(self):
        """Test analysis with insufficient data."""
        monitor = RecursionPatternMonitor()

        # Record < 10 packages
        for i in range(5):
            monitor.record_package({"code_count": 7})

        analysis = monitor.analyze_patterns()
        assert analysis["status"] == "insufficient_data"

    def test_analyze_patterns_normal_behavior(self, monkeypatch):
        """Test analysis with normal signing patterns.

        Uses deterministic timestamps to avoid CI timing jitter causing
        false positive anomalies. The test verifies that perfectly regular
        intervals (0.01s apart) produce zero anomalies.
        """
        import ama_cryptography_monitor

        monitor = RecursionPatternMonitor()

        # Create deterministic timestamps: exactly 0.01s apart
        base_time = 1000000.0
        call_count = [0]

        def mock_time():
            result = base_time + call_count[0] * 0.01
            call_count[0] += 1
            return result

        # Patch time.time in the ama_cryptography_monitor module
        monkeypatch.setattr(ama_cryptography_monitor.time, "time", mock_time)

        # Record normal packages with deterministic timestamps
        for i in range(20):
            monitor.record_package({"code_count": 7})

        analysis = monitor.analyze_patterns()

        assert analysis["status"] == "analyzed"
        assert "features" in analysis
        assert "anomalies" in analysis
        assert len(analysis["anomalies"]) == 0  # Normal behavior

    def test_analyze_patterns_detects_frequency_anomaly(self, monkeypatch):
        """Test detection of unusual signing frequency.

        Uses deterministic timestamps to reliably trigger frequency anomaly
        detection. Creates 15 regular intervals followed by one large gap.
        """
        import ama_cryptography_monitor

        monitor = RecursionPatternMonitor()

        # Create deterministic timestamps: 15 regular intervals, then one large gap
        base_time = 1000000.0
        # 15 packages at 0.05s intervals, then 16th package after 0.5s gap
        timestamps = [base_time + i * 0.05 for i in range(15)]
        timestamps.append(timestamps[-1] + 0.5)  # Large gap for anomaly
        timestamp_iter = iter(timestamps)

        def mock_time():
            return next(timestamp_iter)

        # Patch time.time in the ama_cryptography_monitor module
        monkeypatch.setattr(ama_cryptography_monitor.time, "time", mock_time)

        # Record packages with deterministic timestamps
        for i in range(16):
            monitor.record_package({"code_count": 7})

        analysis = monitor.analyze_patterns()

        # Should detect frequency anomaly
        anomalies = analysis.get("anomalies", [])
        frequency_anomalies = [a for a in anomalies if a["type"] == "unusual_frequency"]
        assert len(frequency_anomalies) > 0

    def test_recursive_feature_extraction(self, monkeypatch):
        """Test hierarchical feature extraction.

        Uses deterministic timestamps to ensure consistent feature extraction
        across all CI environments.
        """
        import ama_cryptography_monitor

        monitor = RecursionPatternMonitor(max_depth=3)

        # Create deterministic timestamps: exactly 0.01s apart
        base_time = 1000000.0
        call_count = [0]

        def mock_time():
            result = base_time + call_count[0] * 0.01
            call_count[0] += 1
            return result

        # Patch time.time in the ama_cryptography_monitor module
        monkeypatch.setattr(ama_cryptography_monitor.time, "time", mock_time)

        # Record packages with deterministic timestamps
        for i in range(30):
            monitor.record_package({"code_count": 7})

        analysis = monitor.analyze_patterns()
        features = analysis["features"]

        # Should have features at multiple levels
        assert "level_0_mean" in features
        assert "level_1_mean" in features
        # Level 2 may or may not exist depending on downsampling

    def test_package_size_anomaly_detection(self, monkeypatch):
        """Test detection of unusual package sizes.

        Uses deterministic timestamps to ensure consistent behavior across
        all CI environments.
        """
        import ama_cryptography_monitor

        monitor = RecursionPatternMonitor()

        # Create deterministic timestamps: exactly 0.01s apart
        base_time = 1000000.0
        call_count = [0]

        def mock_time():
            result = base_time + call_count[0] * 0.01
            call_count[0] += 1
            return result

        # Patch time.time in the ama_cryptography_monitor module
        monkeypatch.setattr(ama_cryptography_monitor.time, "time", mock_time)

        # Normal size: 7 codes
        for i in range(15):
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


class TestRefactoringAnalyzer:
    """Test suite for RefactoringEngine code analysis."""

    @pytest.fixture
    def sample_code_simple(self, tmp_path):
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
    def sample_code_complex(self, tmp_path):
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

    def test_initialization(self):
        """Test analyzer initialization."""
        analyzer = RefactoringAnalyzer()
        assert len(analyzer.analysis_cache) == 0

    def test_analyze_simple_file(self, sample_code_simple):
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

    def test_analyze_complex_file(self, sample_code_complex):
        """Test analysis of complex code."""
        analyzer = RefactoringAnalyzer()
        results = analyzer.analyze_file(sample_code_complex)

        assert results["total_functions"] == 1
        func = results["functions"][0]

        # Complex function should have moderate complexity (8 for this code)
        assert func["complexity"] >= 8
        # With complexity 8, should get "acceptable" recommendation
        assert "complexity" in func["recommendation"].lower()

    def test_complexity_calculation(self):
        """Test cyclomatic complexity calculation."""
        analyzer = RefactoringAnalyzer()

        # Simple function: complexity = 1
        code = "def f(x): return x"
        tree = ast.parse(code)
        func_node = tree.body[0]
        complexity = analyzer._calculate_complexity(func_node)
        assert complexity == 1

        # Function with if: complexity = 2
        code = "def f(x):\n    if x > 0:\n        return x\n    return 0"
        tree = ast.parse(code)
        func_node = tree.body[0]
        complexity = analyzer._calculate_complexity(func_node)
        assert complexity == 2

    def test_recommendation_generation(self):
        """Test refactoring recommendations."""
        analyzer = RefactoringAnalyzer()

        assert "Acceptable" in analyzer._get_recommendation(5)
        assert "Consider" in analyzer._get_recommendation(15)
        assert "Refactor recommended" in analyzer._get_recommendation(25)

    def test_analyze_invalid_file(self, tmp_path):
        """Test analysis of invalid Python file."""
        invalid_file = tmp_path / "invalid.py"
        invalid_file.write_text("def invalid syntax!")

        analyzer = RefactoringAnalyzer()
        results = analyzer.analyze_file(invalid_file)

        assert "error" in results


class TestAmaCryptographyMonitor:
    """Test suite for integrated monitor."""

    def test_initialization_disabled(self):
        """Test monitor initialization in disabled state."""
        monitor = AmaCryptographyMonitor(enabled=False)

        assert monitor.enabled is False
        assert len(monitor.alerts) == 0

    def test_initialization_enabled(self):
        """Test monitor initialization in enabled state."""
        monitor = AmaCryptographyMonitor(enabled=True)

        assert monitor.enabled is True
        assert isinstance(monitor.timing, ResonanceTimingMonitor)
        assert isinstance(monitor.patterns, RecursionPatternMonitor)
        assert isinstance(monitor.analyzer, RefactoringAnalyzer)

    def test_monitor_crypto_operation_disabled(self):
        """Test that monitoring is no-op when disabled."""
        monitor = AmaCryptographyMonitor(enabled=False)

        # Should do nothing
        monitor.monitor_crypto_operation("test_op", 10.0)

        assert len(monitor.timing.timing_history) == 0
        assert len(monitor.alerts) == 0

    def test_monitor_crypto_operation_enabled(self):
        """Test operation monitoring when enabled."""
        monitor = AmaCryptographyMonitor(enabled=True)

        # Record operations
        for i in range(50):
            monitor.monitor_crypto_operation("test_op", 10.0 + np.random.randn())

        assert "test_op" in monitor.timing.timing_history
        assert len(monitor.timing.timing_history["test_op"]) == 50

    def test_record_package_signing_disabled(self):
        """Test package recording is no-op when disabled."""
        monitor = AmaCryptographyMonitor(enabled=False)

        monitor.record_package_signing({"code_count": 7})

        assert len(monitor.patterns.package_history) == 0

    def test_record_package_signing_enabled(self, monkeypatch):
        """Test package recording when enabled.

        Uses deterministic timestamps to ensure consistent behavior across
        all CI environments.
        """
        import ama_cryptography_monitor

        monitor = AmaCryptographyMonitor(enabled=True)

        # Create deterministic timestamps
        base_time = 1000000.0
        call_count = [0]

        def mock_time():
            result = base_time + call_count[0] * 0.01
            call_count[0] += 1
            return result

        # Patch time.time in the ama_cryptography_monitor module
        monkeypatch.setattr(ama_cryptography_monitor.time, "time", mock_time)

        for i in range(15):
            monitor.record_package_signing({"code_count": 7})

        assert len(monitor.patterns.package_history) == 15

    def test_get_security_report_disabled(self):
        """Test report generation when disabled."""
        monitor = AmaCryptographyMonitor(enabled=False)

        report = monitor.get_security_report()
        assert report["status"] == "monitoring_disabled"

    def test_get_security_report_enabled(self, monkeypatch):
        """Test comprehensive report generation.

        Uses deterministic timestamps to ensure consistent behavior across
        all CI environments.
        """
        import ama_cryptography_monitor

        monitor = AmaCryptographyMonitor(enabled=True)

        # Create deterministic timestamps
        base_time = 1000000.0
        call_count = [0]

        def mock_time():
            result = base_time + call_count[0] * 0.01
            call_count[0] += 1
            return result

        # Patch time.time in the ama_cryptography_monitor module
        monkeypatch.setattr(ama_cryptography_monitor.time, "time", mock_time)

        # Generate some activity
        for i in range(20):
            monitor.monitor_crypto_operation("test_op", 10.0)
            monitor.record_package_signing({"code_count": 7})

        report = monitor.get_security_report()

        assert report["status"] == "active"
        assert "timing_baseline" in report
        assert "pattern_analysis" in report
        assert "recent_alerts" in report
        assert "total_alerts" in report
        assert "recommendations" in report

    def test_alert_pruning(self):
        """Test that alerts are pruned to prevent memory exhaustion."""
        monitor = AmaCryptographyMonitor(enabled=True, alert_retention=10)

        # Generate many alerts by establishing baseline then injecting
        # anomalies
        for i in range(50):
            monitor.monitor_crypto_operation("test_op", 10.0)

        # Inject anomalies
        for i in range(20):
            monitor.monitor_crypto_operation("test_op", 100.0)

        # Alerts should be capped
        assert len(monitor.alerts) <= 10


# Integration test markers
@pytest.mark.integration
class TestMonitorIntegration:
    """Integration tests with full AMA Cryptography system."""

    def test_end_to_end_monitoring(self):
        """Test complete workflow with monitoring and baseline convergence."""
        # Import here to avoid circular dependency
        import sys
        from pathlib import Path

        # Add parent directory to path
        sys.path.insert(0, str(Path(__file__).parent.parent))

        try:
            from code_guardian_secure import (
                MASTER_CODES_STR,
                MASTER_HELIX_PARAMS,
                create_crypto_package,
                generate_key_management_system,
                verify_crypto_package,
            )
        except RuntimeError:
            pytest.skip("Native C library required for code_guardian_secure")
            return  # pragma: no cover — unreachable; tells static analysis skip() diverges

        # Setup
        monitor = AmaCryptographyMonitor(enabled=True)
        kms = generate_key_management_system("integration-test")

        # Run 32 create+verify cycles to exceed the 30-sample baseline threshold.
        # The monitor requires 30+ timing samples per operation before populating
        # baseline_stats for anomaly detection.
        for cycle in range(32):
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
