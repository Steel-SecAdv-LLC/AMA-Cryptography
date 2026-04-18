# 3R Security Monitoring

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 2.1.5 |
| Last Updated | 2026-04-17 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

## Overview

AMA Cryptography includes optional runtime security monitoring using the 3R Mechanism, a security framework developed by Steel Security Advisors LLC. The 3R Mechanism provides three complementary approaches to runtime security analysis:

| Component | Function | Purpose |
|-----------|----------|---------|
| ResonanceTimingMonitor | Runtime timing anomaly monitoring | Frequency-domain analysis of operation timings (statistical anomaly detection) |
| RecursionPatternMonitor | Pattern analysis | Hierarchical anomaly detection across time scales |
| RefactoringAnalyzer | Code complexity metrics | Static analysis for manual security review |

**Design Philosophy**: The 3R Mechanism follows a strict observe-analyze-alert paradigm. It never automatically modifies cryptographic code, ensuring that all security-critical changes require human review and approval.

**v2.0 Integration**: The 3R monitor is now bridged to the **Adaptive Cryptographic Posture System** (`ama_cryptography/adaptive_posture.py`), which can automatically respond to threat-level changes with key rotation and algorithm switching. See [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md) for details.

---

## Architecture

```
+-----------------------------------------------------------+
|                  3R Security Monitoring                    |
+-----------------------------------------------------------+
|  ResonanceTimingMonitor                                           |
|  - FFT-based timing analysis                               |
|  - Statistical anomaly detection                           |
|  - Side-channel vulnerability identification               |
+-----------------------------------------------------------+
|  RecursionPatternMonitor                                           |
|  - Multi-scale pattern extraction                          |
|  - Hierarchical feature analysis                           |
|  - Signing frequency anomaly detection                     |
+-----------------------------------------------------------+
|  RefactoringAnalyzer                                         |
|  - Cyclomatic complexity calculation                       |
|  - Code quality metrics                                    |
|  - Read-only analysis (never auto-modifies)                |
+-----------------------------------------------------------+
```

---

## Component Deep Dive

### ResonanceTimingMonitor: Runtime Timing Anomaly Monitoring

**Purpose**: Surface statistical timing anomalies through frequency-domain analysis for security review.

**IMPORTANT**: This is a MONITORING system that surfaces statistical anomalies. It does NOT guarantee detection or prevention of timing attacks or other side-channel vulnerabilities. Constant-time implementations at the cryptographic primitive level are the primary defense against timing side-channels.

**Technical Approach**:
1. Record operation timings (e.g., Ed25519 sign, Dilithium verify)
2. Apply Fast Fourier Transform (FFT) to timing samples
3. Detect periodic patterns (resonance) indicating side-channels
4. Alert on statistical anomalies (>3σ deviations)

**Anomaly Patterns Monitored** (examples of behaviors that can produce distinctive timing signatures; the system surfaces anomalies but does not guarantee detection of any particular attack):
- Cache timing patterns (e.g., Bernstein's attack on AES)
- Branch prediction leakage patterns
- Memory access pattern correlations
- CPU microarchitecture timing variations

**Configuration**:
- `threshold_sigma`: Anomaly sensitivity (default: 3.0)
- `window_size`: FFT sample window (default: 100)
- `max_history`: Memory limit per operation (default: 10,000)

**Performance**: <0.5% overhead per monitored operation

---

### RecursionPatternMonitor: Hierarchical Pattern Analysis

**Purpose**: Detect anomalies in signing patterns across multiple time scales.

**Technical Approach**:
1. Record package signing metadata (timestamp, author, code count)
2. Extract time-series features (inter-package intervals)
3. Recursive downsampling: Level 0 (raw) → Level 1 (2x) → Level 2 (4x)
4. Compute statistics at each scale: mean, std, range
5. Detect anomalies via z-score analysis (>3σ)

**Detected Anomalies**:
- Unusual signing frequency (burst or drought)
- Package size deviations (too many/few codes)
- Multi-scale pattern changes (gradual vs. sudden)

**Configuration**:
- `max_depth`: Recursion levels (default: 3)  
- `max_history`: Package history limit (default: 10,000)

**Performance**: O(n log n) for n packages, <1% overhead

---

### RefactoringAnalyzer: Code Complexity Analysis

**Purpose**: Provide complexity metrics for manual security review.

**⚠️ CRITICAL CONSTRAINT**: This component is **READ-ONLY**. It never modifies cryptographic code automatically.

**Why No Auto-Refactoring?**:
- May introduce subtle vulnerabilities
- Bypasses mandatory code review  
- Could weaken cryptographic guarantees
- Violates principle of least privilege

**Metrics Calculated**:
1. **Cyclomatic Complexity**: M = 1 + (decision points)
   - 1-10: Simple, easy to test
   - 11-20: Moderate complexity
   - 21+: Refactor recommended

2. **Lines of Code**: Per-function and per-file

3. **Complexity Distribution**: Mean, max, high-complexity count

---

## Usage Guide

### Basic Usage

```python
from ama_cryptography_monitor import AmaCryptographyMonitor
from ama_cryptography.legacy_compat import *

# Enable monitoring
monitor = AmaCryptographyMonitor(enabled=True)

# Generate keys
kms = generate_key_management_system("Steel-SecAdv-LLC")

# Create monitored package
pkg = create_crypto_package(
    MASTER_CODES_STR,
    MASTER_HELIX_PARAMS,
    kms,
    "author",
    monitor=monitor  # ← Pass monitor here
)

# Get security report
report = monitor.get_security_report()
print(f"Status: {report['status']}")
print(f"Total alerts: {report['total_alerts']}")
```

### Advanced Configuration

```python
# Custom thresholds
monitor = AmaCryptographyMonitor(
    enabled=True,
    alert_retention=5000  # Keep last 5000 alerts
)

# Configure timing sensitivity
monitor.timing.threshold = 2.5  # More sensitive (2.5σ vs 3σ)
monitor.timing.window_size = 200  # Larger FFT window

# Configure pattern analysis
monitor.patterns.max_depth = 4  # Deeper recursion
```

---

## When to Enable Monitoring

### Production Scenarios

**Enable Monitoring When**:
- Processing sensitive or high-value Omni-Codes
- Compliance requires audit trails
- Security incident investigation
- Performance regression testing
- Post-deployment validation

**Disable Monitoring When**:
- Maximum performance required
- Resource-constrained environments
- Development/testing with dummy data
- Batch processing non-sensitive data

### Performance Impact

| Scenario | Overhead | Recommendation |
|----------|----------|----------------|
| Light monitoring (timing only) | <1% | Safe for production |
| Full monitoring (3R active) | 1-2% | Acceptable for most cases |
| Resonance analysis enabled | <0.5% | Minimal added cost |
| Pattern analysis (1000+ packages) | <1% | Scales well |

**Total Impact**: <2% when all components enabled

---

## Security Considerations

### Log Security

Monitoring data can contain sensitive information:

**Timing Data**: May leak information about:
- Key sizes (via operation duration)
- Data sizes (via hash computation time)
- System load patterns

**Mitigation**:
- Store logs securely (encrypt at rest)
- Limit log retention (default: 10,000 entries)
- Control access (require authentication)
- Rotate logs regularly

### Alert Rate Limiting

Prevent denial-of-service via alert spam:

```python
# Built-in: max 1000 alerts retained by default
monitor = AmaCryptographyMonitor(alert_retention=1000)

# Alerts auto-pruned to prevent memory exhaustion
```

---

## API Reference

**Key Classes**:
- `AmaCryptographyMonitor`: Main interface
- `ResonanceTimingMonitor`: Timing analysis
- `RecursionPatternMonitor`: Pattern analysis  
- `RefactoringAnalyzer`: Code complexity

**Key Methods**:
- `monitor_crypto_operation(operation, duration_ms)`
- `record_package_signing(metadata)`
- `get_security_report()`
- `analyze_codebase(directory)`

See inline documentation in `ama_cryptography_monitor.py` for complete API details.

---

## Adaptive Posture Integration (v2.1)

The 3R monitor feeds into the **Adaptive Cryptographic Posture System**, which evaluates anomaly scores and triggers automated responses:

```python
from ama_cryptography.adaptive_posture import PostureEvaluator, CryptoPostureController

# Create evaluator with weighted scoring
evaluator = PostureEvaluator()

# Feed anomalies from 3R monitor
evaluator.record_timing_anomaly(score=0.7)
evaluator.record_pattern_anomaly(score=0.5)

# Evaluate threat level
level = evaluator.evaluate()
# Returns: NOMINAL | ELEVATED | HIGH | CRITICAL

# Controller automates responses
controller = CryptoPostureController(evaluator)
controller.respond()  # Key rotation, algorithm switching based on level
```

**Weighted Scoring Model:**
- Timing anomalies: 50% weight (ResonanceTimingMonitor)
- Pattern anomalies: 30% weight (RecursionPatternMonitor)
- Resonance analysis: 20% weight
- Exponential decay prevents stale anomalies from driving permanent escalation

**Automated Response Levels:**

| Level | Score | Response |
|-------|-------|----------|
| NOMINAL | 0.0-0.3 | No action |
| ELEVATED | 0.3-0.6 | Increase monitoring frequency |
| HIGH | 0.6-0.8 | Rotate keys |
| CRITICAL | 0.8-1.0 | Rotate keys + switch algorithm + alert |

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-11-26 | Initial professional release |
| 1.1.0 | 2026-01-09 | Version alignment |
| 2.0.0 | 2026-03-08 | Adaptive posture integration, weighted scoring model, Phase 2 primitives support |
| 2.1.0 | 2026-03-25 | Hand-written SIMD dispatch coverage, dashboard/chart overhaul |
| 2.1.5 | 2026-04-17 | Documentation version alignment, comprehensive monitoring test coverage |

---

Copyright 2025-2026 Steel Security Advisors LLC. Licensed under Apache License 2.0.
