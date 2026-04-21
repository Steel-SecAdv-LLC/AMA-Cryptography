# Adaptive Posture

Documentation for the AMA Cryptography Adaptive Cryptographic Posture System (`ama_cryptography/adaptive_posture.py`), which provides runtime threat response with automatic algorithm switching.

---

## Overview

The Adaptive Posture system responds to real-time threat signals by:

1. **Evaluating** incoming monitoring signals against a threat model
2. **Determining** a threat level (`NOMINAL` → `ELEVATED` → `HIGH` → `CRITICAL`)
3. **Executing** cryptographic actions appropriate to the threat level
4. **Integrating** with the Key Management system for automatic key rotation

---

## Core Components

### `ThreatLevel` Enum

```python
from ama_cryptography.adaptive_posture import ThreatLevel

class ThreatLevel(Enum):
    NOMINAL   # Normal operation — no action required
    ELEVATED  # Slightly elevated signals — increase monitoring
    HIGH      # Significant signals — rotate keys, tighten algorithms
    CRITICAL  # Imminent threat — emergency actions required
```

### `PostureAction` Enum

```python
from ama_cryptography.adaptive_posture import PostureAction

class PostureAction(Enum):
    NONE                # No action (NOMINAL)
    INCREASE_MONITORING # Step up 3R monitoring frequency
    ROTATE_KEYS         # Trigger key rotation (ELEVATED)
    SWITCH_ALGORITHM    # Switch to stronger algorithm (HIGH)
```

### `PostureEvaluator`

Evaluates monitoring signals and produces a `PostureEvaluation`:

```python
from ama_cryptography.adaptive_posture import PostureEvaluator

evaluator = PostureEvaluator()

# Feed monitoring signals (from 3R engine, external threat feeds, etc.)
monitor_signals = {
    "anomaly_score": 0.3,
    "timing_variance": 0.05,
    "error_rate": 0.01,
    "entropy_deviation": 0.02,
}

evaluation = evaluator.evaluate(monitor_signals)
print(f"Threat level: {evaluation.threat_level}")
print(f"Recommended action: {evaluation.recommended_action}")
print(f"Confidence: {evaluation.confidence}")
```

### `CryptoPostureController`

Executes cryptographic actions based on a live evaluation. The controller
wires monitor → evaluator → response internally — the public entry point
is `evaluate_and_respond()`, which returns a `PostureEvaluation`. There is
no public `execute_action(evaluation, ...)` method; action dispatch is
private (`_execute_action()`) and invoked from `evaluate_and_respond()`.

```python
from ama_cryptography.adaptive_posture import (
    CryptoPostureController,
    PostureAction,
)
from ama_cryptography_monitor import AmaCryptographyMonitor

monitor    = AmaCryptographyMonitor(enabled=True)
controller = CryptoPostureController(monitor=monitor)

# Drive a full monitor → evaluate → respond cycle:
evaluation = controller.evaluate_and_respond()

# PostureEvaluation exposes `.action` — the evaluator's **recommended**
# action (there is no `.recommended_action` field; see
# adaptive_posture.py:68-81). The controller may, in order:
#   * execute the action immediately,
#   * queue it as a PendingAction if `confirmation_mode=True` is set on
#     the controller (destructive actions only; requires explicit
#     confirm_action(action_id) later), or
#   * skip execution when the `rotation_cooldown` window is still active
#     (default 300s since the last rotation).
# Check the controller's state (pending_actions, last_rotation_time) if
# you need to know whether a recommended action was actually applied.
if evaluation.action != PostureAction.NONE:
    logger.warning("Posture recommendation: %s", evaluation.action)
    summary = controller.get_posture_summary()
    for pa in summary["pending_actions"]:
        logger.info(
            "Queued for confirmation: %s (%s, reason=%s)",
            pa["action_id"], pa["action"], pa["reason"],
        )
```

---

## Threat Response Actions by Level

| Threat Level | Score Range | Actions Taken |
|-------------|-------------|---------------|
| `NOMINAL` | 0.0 – 0.2 | None — continue normal operation |
| `ELEVATED` | 0.2 – 0.5 | Increase 3R monitoring frequency |
| `HIGH` | 0.5 – 0.8 | Rotate keys, switch to hybrid/PQC-only mode |
| `CRITICAL` | 0.8 – 1.0 | Emergency key rotation, maximum security mode |

---

## Integration with 3R Monitoring

The Adaptive Posture system is designed to receive inputs from the 3R monitoring framework:

```python
from ama_cryptography.adaptive_posture import (
    PostureEvaluator,
    CryptoPostureController,
    ThreatLevel,
    PostureAction,
)
from ama_cryptography.double_helix_engine import AmaEquationEngine
from ama_cryptography_monitor import AmaCryptographyMonitor

# Initialize components. In production, wire the controller to a live
# AmaCryptographyMonitor and let evaluate_and_respond() drive the full
# monitor → evaluate → respond cycle.
engine     = AmaEquationEngine()
monitor    = AmaCryptographyMonitor(enabled=True)
controller = CryptoPostureController(monitor=monitor)

# If you only need to peek at an evaluation without dispatching actions,
# construct a PostureEvaluator and call .evaluate(monitor_report) directly.
# monitor_report is a dict (NOT a kwarg called monitor_signals).
evaluator       = PostureEvaluator()
state           = engine.get_current_state()
monitor_report  = engine.get_monitoring_metrics(state)
evaluation      = evaluator.evaluate(monitor_report)

if evaluation.threat_level >= ThreatLevel.HIGH:
    print(f"⚠ High threat detected: {evaluation.threat_level}")
    # Drive the controller to actually respond. It enforces cooldown
    # and confirmation_mode internally; there is no public
    # execute_action(evaluation, ...) method.
    applied = controller.evaluate_and_respond()
    print(f"Applied: {applied.action}, pending queue: "
          f"{len(controller.get_posture_summary()['pending_actions'])}")
```

---

## Algorithm Switching

When `PostureAction.SWITCH_ALGORITHM` is triggered, the application
decides how to react — for example, by instantiating a new
`AmaCryptography` dispatcher with a stricter `AlgorithmType`:

```python
from ama_cryptography.crypto_api import AmaCryptography, AlgorithmType

# Under HIGH threat: drop Ed25519 and run ML-DSA-65 only.
# The field is `action` (see adaptive_posture.py:68-81), not
# `recommended_action`. The controller may have queued the action under
# confirmation_mode or skipped it under rotation_cooldown — the field
# carries the *recommendation*, not a guarantee of immediate execution.
if evaluation.action == PostureAction.SWITCH_ALGORITHM:
    crypto_api = AmaCryptography(algorithm=AlgorithmType.ML_DSA_65)
    print("Switched to quantum-resistant-only mode")
```

| Algorithm | Description | Use Case |
|-----------|-------------|----------|
| `AlgorithmType.ED25519` | Ed25519 only | Legacy/transition environments |
| `AlgorithmType.ML_DSA_65` | ML-DSA-65 only | Maximum quantum protection |
| `AlgorithmType.HYBRID_SIG` | Ed25519 + ML-DSA-65 | **Recommended for production** |

---

## Monitoring Integration Loop

A typical production monitoring loop:

```python
import time
from ama_cryptography.adaptive_posture import (
    PostureEvaluator,
    CryptoPostureController,
    ThreatLevel,
)

evaluator = PostureEvaluator()
controller = CryptoPostureController()

def monitoring_loop(crypto_api, key_manager, interval_seconds=60):
    """Continuous threat evaluation loop."""
    while True:
        # Collect monitoring signals
        signals = collect_monitoring_signals()
        
        # Evaluate threat level
        evaluation = evaluator.evaluate(signals)
        
        # Log current posture
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
              f"Threat: {evaluation.threat_level.name} | "
              f"Action: {evaluation.recommended_action.name}")
        
        # Execute actions if needed
        if evaluation.recommended_action != PostureAction.NONE:
            controller.execute_action(evaluation, crypto_api, key_manager)
        
        time.sleep(interval_seconds)
```

---

## 3R Monitoring Engines

The Adaptive Posture system is backed by the 3R framework:

### Resonance Engine

FFT-based frequency-domain anomaly detection:

```python
from ama_cryptography.double_helix_engine import AmaEquationEngine

engine = AmaEquationEngine()

# Compute frequency domain analysis of operation timing
resonance_score = engine.compute_resonance(timing_samples)
```

### Recursion Engine

Multi-scale hierarchical pattern analysis:

```python
# Hierarchical pattern analysis across multiple time scales
recursion_score = engine.compute_recursion(operation_sequence)
```

### Refactoring Engine

Code complexity metrics for security review:

```python
# Code quality / complexity metrics
refactor_score = engine.compute_refactoring(code_metrics)
```

> **Note:** The 3R system surfaces statistical anomalies for human review. It does not automatically detect or block attacks, and should not be relied upon as the sole security mechanism.

---

## Configuration

```python
from ama_cryptography.adaptive_posture import PostureEvaluator

# Configure threat thresholds
evaluator = PostureEvaluator(
    elevated_threshold=0.25,   # Anomaly score threshold for ELEVATED
    high_threshold=0.55,       # Threshold for HIGH
    critical_threshold=0.80,   # Threshold for CRITICAL
    evaluation_window=100,     # Number of samples to evaluate over
)
```

---

*See [Architecture](Architecture) for the 3R monitoring framework overview, or [Hybrid Cryptography](Hybrid-Cryptography) for algorithm switching details.*
