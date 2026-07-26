# 3R Security Monitoring

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 3.4.0 |
| Last Updated | 2026-07-26 |
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

Two opt-in detectors extend the Resonance and Recursion components for agentic-abuse patterns:

| Detector | Function | Purpose |
|----------|----------|---------|
| VolumeSpikeDetector | Operation-burst detection | Anscombe-transformed statistical detection of KEM/signature bursts with ephemeral-key churn |
| NoteArtifactDetector | Signed-payload structure | Surfaces payloads shaped like instructions for a later agent instance |

Both are **on by default**; see [Agentic Abuse Detectors](#agentic-abuse-detectors).

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

**Measured detection envelope** (`tests/test_agentic_load_adversarial.py`, synthetic series, 96 samples in a 64-sample window). Periodicity is scored against *surrogates* of the same series — deterministic shuffles, which destroy temporal ordering while preserving the exact value multiset — so the figure below is a ratio to the series' own noise floor, not an absolute score. A ratio of 2.0 is the discrimination bar; sweeping 400 independent aperiodic series put the null distribution at median 0.65 / p99 1.49 / max 1.87, so nothing without real structure reaches it.

| Input | Ratio to own noise floor | Seen? |
|---|---|---|
| Period-2 probe (alternating cost) | 10.2x | Yes |
| Sinusoidal cadence, periods 2–24 | 3.7x–5.8x | Yes |
| Period-2 at SNR 0.5 (amplitude 0.25 vs ±0.5 jitter) | 3.2x | Yes |
| Period-2 at SNR 0.3 (amplitude 0.15) | 1.8x | **No** |
| Period-2 at SNR 0.1 (amplitude 0.05) | 0.6x | **No** |
| Aperiodic jitter (no structure) | 0.6x | No (correct) |

Read that as a floor, not a guarantee: a periodic component quieter than roughly a third of the ambient jitter is not distinguishable from noise. Square waves whose period does not divide the window leak across bins and score lower for that reason alone (a period-24 square reads 1.8x). Wall-clock timings of sub-millisecond operations on a shared/virtualised host routinely carry their own periodic structure — cache warm-up, allocator growth, scheduler quanta — so a raw resonance score from such a host is not on its own evidence of an attack.

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

### Agentic Abuse Detectors

Added in response to the July 2026 autonomous-agent sandbox escape, in which an
evaluation agent moved laterally, reached the open internet, and left signed
notes intended for future versions of itself.

Both detectors are **on by default**, matching this module's existing posture
that production-ready anomaly detection ships out of the box. A deployment gets
the protection with no opt-in step:

```python
monitor = create_monitor()            # both detectors active
```

Opting out drops the detector objects entirely and restores the
pre-INVARIANT-30 security-report shape:

```python
monitor = create_monitor(detect_volume_spikes=False, detect_note_artifacts=False)
```

**Cost of "on by default"** (measured on this repository's CI-class hardware):

| Item | Cost |
|------|------|
| Constructing both detectors | ~2.5 µs, once per monitor (marker tables are built once and shared) |
| `record_operation_event()` | ~1.3 µs enabled, ~0.2 µs when disabled |
| `inspect()` on a 3309-byte ML-DSA signature | ~6.7 µs (rejected by the printable-ratio gate before tokenising) |
| `inspect()` on a large payload | Bounded by `max_scan_bytes`, not by payload size — the head/tail sample is sliced from the caller's buffer before it is materialised, so a 32 MB `bytearray` or `memoryview` costs the same as a small one |

Against an ML-DSA-65 signature at ~200 µs these are sub-percent. The
`benchmarks/benchmark_runner.py` suite stays within its 10% regression
threshold on all 19 benchmarks with the detectors active.

**Where they are wired**: `create_crypto_package()` records the volume signal
at the three sites it already instrumented for timing (primary signature,
SPHINCS+ signature, ML-KEM encapsulation). Nothing was pushed down into the
providers, so the hot primitives are untouched and no new call path takes a
lock. The key fingerprint passed there is a slice of the **public** key — no
hashing is added to a signing path and no secret material reaches the monitor.

#### VolumeSpikeDetector

**Purpose**: Detect bursts of ML-KEM-1024 / ML-DSA-65 / SLH-DSA operations
consistent with agentic reconnaissance or bulk artifact generation.

**Statistics**: Per-operation counts are bucketed (default 1 s) and scored in
the Anscombe variance-stabilising transform `a(c) = 2·√(c + 3/8)`, under which
a Poisson count is approximately unit-variance Normal regardless of rate. A
plain z-score on raw counts fails here: a quiet baseline has near-zero sample
variance, so every mild uptick reads as an enormous deviation. Overdispersion
is tracked as an EWMA of the squared residual and floored at the Poisson value
of 1.

**Gates** — all three must pass before an alert is emitted:

| Gate | Default | Rationale |
|------|---------|-----------|
| `warmup_buckets` | 30 | The baseline must be a baseline |
| `min_burst_count` | 256 | Absolute floor: an idle service signing twice is not an incident |
| `threshold_sigma` | 6.0 | Deliberately far above the 3.0 used elsewhere — a burst detector that cries wolf gets switched off |

The baseline is updated only from **closed** buckets, so a burst never inflates
the baseline it is judged against, and at most one alert is emitted per
operation per bucket.

**Key churn**: an optional truncated key fingerprint (never raw key bytes) lets
the detector report `distinct_key_ratio`. A ratio near 1.0 — a fresh key per
operation — escalates the alert to `critical`; a hot loop over one long-lived
key stays `warning`.

**Hook**: `monitor.record_operation_event(operation, key_fingerprint=None)`

#### NoteArtifactDetector

**Purpose**: Surface signed payloads that read as instructions addressed to a
later instance of the signer.

**Method**: Three marker families are scored — a phrase-level *successor*
family (bigrams such as "next instance", "subsequent iterations", built from a
cross product of forward-referring words with instance-denoting nouns), plus
unigram *instructional* and *operational* families. The successor family is
phrase-level because its component words are ordinary English; scoring the
successor vocabulary as unigrams trips well over half of this repository's own
files (measured: 256 of 443). The cross product excludes generic articles,
possessives and bare pronouns (the/my/your/me/you), which would otherwise
generate non-discriminative pairs like "the agent" or "you are". A payload is
flagged only when all three families are covered, the fractional coverage score
reaches the threshold, and the printable-ASCII ratio clears its floor —
signatures, keys and ciphertext are high-entropy binary and are rejected before
any scoring.

**Calibration**: measured against a 443-file corpus (git-tracked source) of this repository's
Markdown, Python, C, headers, JSON, YAML and Cython — a deliberately *hard*
negative, since security prose is dense with the operational vocabulary the
detector scores. With the shipped defaults, every genuinely-benign file scores
≤ 1.75 while the four hand-written successor notes score 2.25–3.00 (a margin of
≥ 0.50); the only corpus files flagged are the three that themselves contain or
describe successor-note tradecraft (`INVARIANTS.md`, `CHANGELOG.md`, and the
adversarial-load test that embeds a synthetic note). Lowering the threshold to
1.50 additionally flags one genuinely-benign document, so 1.75 is the tighter
operating point. `tests/test_agentic_abuse_detectors.py` re-derives this on
every CI run — it pins the benign false-positive set (any new benign flag fails
the build) and asserts the ≥ 0.50 separation directly.

**Bounded work**: at most `max_scan_bytes` (default 8192) are examined, sampled
head and tail so prepended filler cannot hide a note at the end. One pass, no
regular expressions.

**Advisory only**: this is a heuristic. It never blocks a signature, and an
agent that avoids the successor vocabulary is not caught. `flagged=False` is
not a statement that a payload is benign.

**Hook**: `monitor.inspect_signed_payload(payload, label="...")`

#### Compiled kernels

Both detectors are backed by Cython kernels in `src/cython/math_engine.pyx`
(`volume_spike_scores`, `token_family_counts`) with exact pure-Python twins in
`ama_cryptography/monitoring.py`. Equivalence is pinned by property-based
tests, so the compiled extension is an optimisation and never a correctness
dependency. `monitoring.CYTHON_DETECTOR_KERNELS` reports which path is active.

`token_family_counts` is pure integer work and is asserted **exactly**.
`volume_spike_scores` is an EWMA recursion, so on FMA targets (ARM) the
per-step rounding differs from Python's and accumulates across the series; the
tests pin a small relative tolerance (1e-9) there, bit-for-bit only where the
target has no FMA contraction. Either way the difference is orders of magnitude
below anything that could move a score across the 6-sigma threshold.

#### How the detectors are verified

| Aspect | Verification |
|--------|--------------|
| Quiescence (no false positives) | `tests/test_agentic_abuse_detectors.py` — steady load, jittery load, gradual ramp, small absolute burst, pre-warmup burst, and idle gaps all assert **zero** alerts |
| Note-detector calibration | Re-derived every CI run against the repository's own git-tracked source as a hard-negative corpus: the benign false-positive set is pinned (any new benign flag fails the build) and the note-vs-corpus score separation is asserted directly |
| Kernel equivalence | Property-based (Hypothesis) equivalence of the Cython kernels against their pure-Python twins on arbitrary bytes |
| Concurrency | `tests/test_agentic_load_adversarial.py` drives real parallel ML-KEM/ML-DSA work through the monitor; the volume detector's clock is read under its lock so per-operation bucket indices are non-decreasing |
| Agentic scenarios | High-concurrency ephemeral load, future-version note simulation, lateral-probe simulation, and fail-closed-under-parallel-load, end to end against the real primitives |

The binding these detectors accompany is verified separately — byte-KAT C test,
strict dudect constant-time lane, and `fuzz/fuzz_agent_binding.c`, which asserts
fail-closed policy properties rather than merely the absence of crashes. See
[INVARIANTS.md](INVARIANTS.md) (INVARIANT-30).

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
- `VolumeSpikeDetector`: Operation-burst detection (on by default)
- `NoteArtifactDetector`: Note-like signed-payload detection (on by default)

**Key Methods**:
- `monitor_crypto_operation(operation, duration_ms)`
- `record_package_signing(metadata)`
- `get_security_report()`
- `analyze_codebase(directory)`
- `record_operation_event(operation, key_fingerprint=None)`
- `inspect_signed_payload(payload, label=...)`

See inline documentation in `tools/monitoring/ama_cryptography_monitor.py` for complete API details.

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
| 2.2.0 | 2026-07-26 | Agentic-abuse detectors: VolumeSpikeDetector, NoteArtifactDetector, on by default |

---

Copyright 2025-2026 Steel Security Advisors LLC. Licensed under Apache License 2.0.
