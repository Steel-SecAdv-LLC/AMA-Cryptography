#!/usr/bin/env python3
# Copyright 2025 Steel Security Advisors LLC
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
AMA Cryptography ♱ (AG♱): 3R Monitoring Demonstration
==================================================

Demonstrates:
1. Runtime timing anomaly monitoring (ResonanceEngine)
2. Pattern analysis (RecursionEngine)
3. Security reporting
4. Integration with existing crypto functions

Note: The 3R system is a runtime ANOMALY MONITORING framework. It surfaces
statistical anomalies for security review but does NOT guarantee detection
or prevention of timing attacks or other side-channel vulnerabilities.

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Contact: steel.sa.llc@gmail.com
Date: 2025-12-06
Version: 1.1
Project: AMA Cryptography ♱ 3R Runtime Monitoring

AI Co-Architects:
    Eris ⯰ | Eden ♱ | Veritas 💠 | X ⚛ | Caduceus ⚚ | Dev ⚕
"""

import time

from ama_cryptography_monitor import AmaCryptographyMonitor
from code_guardian_secure import (
    MASTER_CODES_STR,
    MASTER_HELIX_PARAMS,
    create_crypto_package,
    generate_key_management_system,
    verify_crypto_package,
)


def print_section(title: str) -> None:
    """Print formatted section header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def demo_timing_monitoring() -> None:
    """Demonstrate runtime timing anomaly monitoring."""
    print_section("3R DEMO: ResonanceEngine - Runtime Timing Anomaly Monitoring")

    monitor = AmaCryptographyMonitor(enabled=True)
    kms = generate_key_management_system("Demo-Timing")

    print("\n[1/4] Creating packages with normal timing...")
    # Use first 3 codes for faster demo
    test_codes = "\n".join(MASTER_CODES_STR.split("\n")[:3])
    test_params = MASTER_HELIX_PARAMS[:3]

    for i in range(25):
        _ = create_crypto_package(test_codes, test_params, kms, "demo", monitor=monitor)
        if (i + 1) % 5 == 0:
            print(f"  ✓ {i + 1}/25 packages created")
        time.sleep(0.01)

    print("\n[2/4] Baseline established")
    baseline = monitor.timing.baseline_stats.get("dilithium_sign", {})
    if baseline:
        print(f"  Dilithium signing: {baseline['mean']:.3f}ms ± {baseline['std']:.3f}ms")

    print("\n[3/4] Simulating timing anomaly...")
    # Force a slow operation (simulate cache miss, context switch, etc.)
    import numpy as np

    _ = np.random.rand(10000, 10000).sum()  # CPU-intensive operation

    _ = create_crypto_package(test_codes, test_params, kms, "demo", monitor=monitor)

    print("\n[4/4] Security Report:")
    report = monitor.get_security_report()

    if report["total_alerts"] > 0:
        print(f"  ⚠️  {report['total_alerts']} alert(s) detected")
        for alert in report["recent_alerts"][-3:]:
            if alert["type"] == "timing":
                anomaly = alert["anomaly"]
                print(f"\n  Operation: {anomaly.operation}")
                print(f"  Expected:  {anomaly.expected_ms:.3f} ms")
                print(f"  Observed:  {anomaly.observed_ms:.3f} ms")
                print(f"  Deviation: {anomaly.deviation_sigma:.2f}σ")
                print(f"  Severity:  {anomaly.severity.upper()}")
    else:
        print("  ✓ No anomalies detected (system too fast!)")
        print("  Note: Anomaly injection may not work on high-performance systems")


def demo_pattern_analysis() -> None:
    """Demonstrate signing pattern analysis."""
    print_section("3R DEMO: RecursionEngine - Pattern Analysis")

    monitor = AmaCryptographyMonitor(enabled=True)
    kms = generate_key_management_system("Demo-Pattern")

    print("\n[1/3] Creating normal package series...")
    for i in range(15):
        _ = create_crypto_package(
            MASTER_CODES_STR, MASTER_HELIX_PARAMS, kms, "demo", monitor=monitor
        )
        if (i + 1) % 5 == 0:
            print(f"  ✓ {i + 1}/15 packages created")
        time.sleep(0.05)  # Normal interval

    print("\n[2/3] Simulating unusual activity...")
    # Rapid burst of packages (unusual pattern)
    test_codes = "\n".join(MASTER_CODES_STR.split("\n")[:2])
    test_params = MASTER_HELIX_PARAMS[:2]
    for i in range(5):
        _ = create_crypto_package(test_codes, test_params, kms, "demo", monitor=monitor)
    print("  ⚠️  Burst of 5 packages created instantly")

    print("\n[3/3] Pattern Analysis:")
    report = monitor.get_security_report()
    pattern = report["pattern_analysis"]

    if pattern["status"] == "analyzed":
        print(f"  ✓ Analyzed {pattern['total_packages']} packages")
        print(f"  ✓ Hierarchical features: {len(pattern['features'])} metrics")

        # Show multi-scale features
        if "level_0_mean" in pattern["features"]:
            print("\n  Multi-Scale Analysis:")
            print(f"    Level 0 (Raw):     {pattern['features']['level_0_mean']:.3f}s mean")
            if "level_1_mean" in pattern["features"]:
                print(f"    Level 1 (2x):      {pattern['features']['level_1_mean']:.3f}s mean")
            if "level_2_mean" in pattern["features"]:
                print(f"    Level 2 (4x):      {pattern['features']['level_2_mean']:.3f}s mean")

        if pattern["anomalies"]:
            print(f"\n  ⚠️  {len(pattern['anomalies'])} anomaly(ies) detected:")
            for anomaly in pattern["anomalies"]:
                print(f"    Type: {anomaly['type']}")
                print(f"    Z-score: {anomaly['z_score']:.2f}")
                print(f"    Severity: {anomaly['severity'].upper()}")
        else:
            print("\n  ✓ No pattern anomalies detected")


def demo_resonance_detection() -> None:
    """Demonstrate FFT-based resonance detection."""
    print_section("3R DEMO: Resonance Detection via FFT")

    monitor = AmaCryptographyMonitor(enabled=True)
    kms = generate_key_management_system("Demo-Resonance")

    print("\n[1/2] Creating packages for frequency analysis...")
    test_codes = "\n".join(MASTER_CODES_STR.split("\n")[:3])
    test_params = MASTER_HELIX_PARAMS[:3]

    for i in range(50):
        _ = create_crypto_package(test_codes, test_params, kms, "demo", monitor=monitor)

    print("  ✓ Created 50 packages")

    print("\n[2/2] Resonance Analysis:")
    for operation in ["dilithium_sign", "ed25519_sign"]:
        resonance = monitor.timing.detect_resonance(operation)
        if resonance:
            print(f"\n  Operation: {operation}")
            print(f"    Dominant frequency: {resonance['dominant_frequency']:.4f} Hz")
            print(f"    Resonance ratio:    {resonance['resonance_ratio']:.2f}")
            print(f"    Has resonance:      {'⚠️ YES' if resonance['has_resonance'] else '✓ NO'}")

            if resonance["has_resonance"]:
                print("    → Periodic pattern detected! May indicate side-channel.")
        else:
            print(f"\n  Operation: {operation}")
            print("    Status: Insufficient data for FFT analysis")


def demo_security_report() -> None:
    """Demonstrate comprehensive security reporting."""
    print_section("3R DEMO: Comprehensive Security Report")

    monitor = AmaCryptographyMonitor(enabled=True)
    kms = generate_key_management_system("Demo-Report")

    print("\n[1/2] Simulating production workload...")
    for i in range(20):
        pkg = create_crypto_package(
            MASTER_CODES_STR, MASTER_HELIX_PARAMS, kms, "demo", monitor=monitor
        )
        # Verify packages too
        verify_crypto_package(
            MASTER_CODES_STR,
            MASTER_HELIX_PARAMS,
            pkg,
            kms.hmac_key,
            monitor=monitor,
        )

    print("  ✓ Created and verified 20 packages")

    print("\n[2/2] Security Report Summary:")
    report = monitor.get_security_report()

    print(f"  Status: {report['status']}")
    print(f"  Total alerts: {report['total_alerts']}")
    print("\n  Operations monitored:")
    for op, stats in report["timing_baseline"].items():
        print(f"    {op}: {stats['mean']:.3f}ms ± {stats['std']:.3f}ms")

    if report.get("recommendations"):
        print("\n  Recommendations:")
        for rec in report["recommendations"]:
            print(f"    • {rec}")


def main():
    """Run all demos."""
    print("=" * 70)
    print("  AVA GUARDIAN ♱ - 3R SECURITY MONITORING DEMONSTRATION")
    print("=" * 70)
    print("\n  Showcasing runtime security analysis capabilities")
    print("  Steel Security Advisors LLC - 2025")

    # Run demos
    demo_timing_monitoring()
    time.sleep(1)

    demo_pattern_analysis()
    time.sleep(1)

    demo_resonance_detection()
    time.sleep(1)

    demo_security_report()

    # Final summary
    print("\n" + "=" * 70)
    print("  3R MONITORING DEMO COMPLETE")
    print("=" * 70)
    print("\n  Key Takeaways:")
    print("    • ResonanceEngine detects timing anomalies via FFT analysis")
    print("    • RecursionEngine identifies pattern changes across time scales")
    print("    • RefactoringEngine provides code complexity metrics (read-only)")
    print("    • <2% performance overhead when enabled")
    print("    • Disabled by default for zero-cost operation")
    print("\n  📖 Full documentation: MONITORING.md")
    print("=" * 70)


if __name__ == "__main__":
    main()
