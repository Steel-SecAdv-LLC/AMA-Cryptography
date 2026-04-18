# Security Design Notes — Original Constructions

**Version:** 2.1.5
**Date:** 2026-04-18
**Classification:** Public
**Maintainer:** Steel Security Advisors LLC

---

## Scope

This document provides written security arguments for the original
(non-standardized) constructions in AMA Cryptography. Individual cryptographic
primitives (SHA3-256, Ed25519, ML-DSA-65, ML-KEM-1024, SPHINCS+-SHA2-256f,
AES-256-GCM, HKDF-SHA3-256, etc.) rely on published security proofs from their
respective standards (NIST FIPS 202/203/204/205, RFC 2104/5869/7748/8032). This
document covers the *composition protocol* — how those primitives are combined —
and the two original subsystems:

1. **Double-Helix Evolution Engine** (`ama_cryptography/double_helix_engine.py`)
2. **Adaptive Cryptographic Posture System** (`ama_cryptography/adaptive_posture.py`)

Nothing in this document substitutes for independent cryptographic review.
Readers considering deployment in high-security or regulated environments
should commission an external audit by qualified cryptographers.

---

## 1. Double-Helix Evolution Engine

### 1.1 Purpose and Non-Cryptographic Status

The Double-Helix Evolution Engine is explicitly a **non-cryptographic** module
that provides mathematical modeling and analytical utilities for the 3R
monitoring subsystem. It implements state evolution, convergence, and
constraint-satisfaction algorithms inspired by biological and physical systems.

This is stated normatively in the module docstring
(`ama_cryptography/double_helix_engine.py` lines 20–33):

> **IMPORTANT: NON-CRYPTOGRAPHIC MODULE** […] It is NOT a cryptographic
> primitive and should NOT be relied upon for security guarantees.

The engine's outputs feed the Adaptive Cryptographic Posture System as one
signal source among several; it does not itself make cryptographic decisions,
derive keys, or touch secret material.

### 1.2 Security Boundary

The engine operates exclusively on **non-secret** monitoring metrics (anomaly
scores, Lyapunov values, ethical-constraint satisfaction indicators). It does
not:

- Accept, store, or process private-key material.
- Derive keys, MAC tags, signatures, or any secret-dependent output.
- Participate in the cryptographic critical path for encryption, signing,
  verification, or key exchange.

Consequently the engine sits **outside** the library's confidentiality and
integrity trust boundary. A fault in the engine cannot directly leak or
weaken cryptographic keys.

### 1.3 Failure Modes

Possible failure modes and their blast radius:

| Failure | Direct Effect | Blast Radius |
|---------|---------------|--------------|
| Numerical instability / NaN propagation | Invalid score returned to posture system | Availability only — posture system defaults to `NOMINAL` on invalid input |
| Incorrect score (too high) | Spurious escalation signal | Unnecessary key rotation / algorithm switch (availability / operational cost) |
| Incorrect score (too low) | Missed escalation signal | Delayed response to a *monitoring* anomaly; no reduction in baseline cryptographic strength |
| Exception during evaluation | Posture evaluator logs and continues | Availability only |

Crucially, none of these failures can weaken the confidentiality or integrity
of cryptographic operations performed by `crypto_api.py`, because those
operations do not depend on the engine's output for their security.

### 1.4 Assumptions

The engine's correctness properties hold under the following assumptions:

1. Monitoring signals (loss, gradient norms, anomaly counts) are produced by
   the 3R subsystem, not attacker-controlled inputs.
2. The engine runs in the same trust domain as the monitoring subsystem;
   process-boundary attacks (RCE, container escape) are out of scope and are
   handled by OS-level controls.
3. Numeric inputs are within the documented ranges; out-of-range inputs are
   clamped by `_numeric.clip` before evaluation.
4. The engine is *not* a source of truth for cryptographic policy — it is
   advisory. The posture controller applies its own safeguards (cooldowns,
   confirmation mode) before acting.

### 1.5 Limitations

- The engine has not undergone independent formal verification or peer review.
- The mathematical model is heuristic; it produces plausibility scores, not
  cryptographic proofs.
- Adding new signal sources requires re-evaluating whether the new sources
  remain outside the secret-data trust boundary.

---

## 2. Adaptive Cryptographic Posture System

### 2.1 Purpose

The Adaptive Cryptographic Posture System consumes 3R monitor output and
the Double-Helix Engine's analytical signals and maps them to one of four
threat levels (`NOMINAL`, `ELEVATED`, `HIGH`, `CRITICAL`). Each threat level
is bound to a concrete action selected from a fixed enumeration:
`NONE`, `INCREASE_MONITORING`, `ROTATE_KEYS`, `SWITCH_ALGORITHM`,
`ROTATE_AND_SWITCH`.

No new cryptographic logic is introduced. All actions delegate to existing,
standards-based primitives via `crypto_api.py` (algorithm selection) and
`key_management.py` (BIP32 derivation, key rotation manager).

### 2.2 Security Argument

The posture system is designed so that its behavior is **monotonic with
respect to cryptographic strength**:

1. **Escalation-only action set.** The action enumeration contains no
   "downgrade" operation. The system cannot move from a post-quantum algorithm
   to a classical one, or drop a cryptographic layer, or shorten a key.
   Algorithm switches select from a policy-defined set of equal-or-stronger
   primitives.
2. **Delegated security.** Every action invokes a vetted primitive
   (Ed25519, ML-DSA-65, ML-KEM-1024, HKDF-SHA3-256, AES-256-GCM, etc.). The
   posture system's security therefore reduces to the security of those
   primitives plus the correctness of the orchestration logic.
3. **Rate limiting via cooldowns.** `CryptoPostureController` enforces a
   cooldown between consecutive destructive actions (key rotation, algorithm
   switch), preventing a signal storm from degrading availability through
   unbounded rotation.
4. **Optional confirmation mode.** Destructive actions may be queued as
   `PendingAction` objects requiring explicit operator acknowledgement,
   providing a human-in-the-loop checkpoint in high-assurance deployments.
5. **Stateless evaluation.** Each `PostureEvaluation` is a pure function of
   the current signal window; there is no hidden mutable state that an
   attacker could poison over time.

### 2.3 Threat Boundaries

The posture system's threat model assumes monitoring signals may, in the
worst case, be **influenced but not arbitrarily forged** by an attacker.
Under signal injection:

| Attacker Capability | Worst-Case Consequence | Classification |
|---------------------|------------------------|----------------|
| Inject false-positive anomalies | Unnecessary `ROTATE_KEYS` / `SWITCH_ALGORITHM` | Availability / operational cost |
| Suppress true-positive anomalies | Delayed escalation; baseline cryptography remains in force | Reduced defence-in-depth, not broken crypto |
| Modulate signals near threshold | Toggle posture between `NOMINAL` and `ELEVATED` | Availability; mitigated by cooldown |
| Influence algorithm selection within policy set | Constrained to the policy-defined equal-or-stronger set | No weakening of baseline strength |

**Confidentiality and integrity of data protected by `crypto_api.py` are not
affected** by any of the above, because the posture system's action set
cannot downgrade cryptographic parameters below the baseline configured at
initialization.

### 2.4 Limitations

- The system has not undergone independent formal verification. It is a
  heuristic response layer, not a provably secure protocol.
- The posture state machine is specified in code, not in a formal
  specification language.
- Signal-to-threat-level mapping is based on engineering judgment informed
  by the 3R monitoring design; thresholds are tunable and should be
  calibrated to the deployment environment.

---

## 3. Composition Protocol (Multi-Layer Defense)

### 3.1 Security Argument

The library applies four independent cryptographic operations to each
protected package:

1. **SHA3-256** content hashing (FIPS 202)
2. **HMAC-SHA3-256** authentication (RFC 2104)
3. **Ed25519** classical signature (RFC 8032)
4. **ML-DSA-65** post-quantum signature (FIPS 204)

Plus supporting operations: HKDF-SHA3-256 key derivation (RFC 5869,
NIST SP 800-108) and RFC 3161 trusted timestamping.

The overall security argument is:

- **Bound.** Classical security is bounded below by the weakest primitive
  (approximately 2^128 via SHA3-256 / HMAC / HKDF). Quantum security is
  bounded below by 2^128 via Grover-resistant primitives; Ed25519 is
  quantum-vulnerable but is backed by ML-DSA-65.
- **Defence-in-depth.** Compromise of one primitive does not assist attack on
  another because each primitive uses an independently derived key and
  operates on an independently bound input transcript.
- **Forgery resistance.** Producing a forgery requires simultaneous breaks of
  both signature layers (Ed25519 *and* ML-DSA-65), under distinct hardness
  assumptions (elliptic-curve discrete log *and* module-lattice MLWE/MSIS).

### 3.2 Key Independence

All layer keys are derived from a master secret via HKDF-SHA3-256 using
distinct `info` strings for domain separation (RFC 5869 §3.3). Per RFC 5869
§3, when `info` strings are distinct, derived keys are cryptographically
independent under the assumption that SHA3-256 is a PRF.

Domain-separation strings are fixed, versioned, and length-prefixed per the
v2.1.5 security audit (see commit `b700050`, "Security audit fixes:
length-prefixed encoding, constant-time ops, and validation"). This prevents
canonicalization ambiguity between keys derived under different contexts.

### 3.3 Hybrid KEM Combiner

The hybrid KEM combiner binds X25519 and ML-KEM-1024 shared secrets per
Bindel, Brendel, Fischlin, Goncalves, Stebila (2019), "Hybrid Key
Encapsulation Mechanisms and Authenticated Key Exchange." The combiner is
IND-CCA2-secure as long as **at least one** underlying KEM remains
IND-CCA2-secure, providing graceful degradation if either classical or
post-quantum assumptions fail.

### 3.4 Known Limitations

- No **formal composition proof** has been written for the specific
  multi-layer construction used here. The informal argument above is a best
  effort; it is not a substitute for a mechanized or peer-reviewed proof.
- The composition has not been independently audited.
- Side-channel resistance of the composition depends on the side-channel
  resistance of each underlying primitive implementation. Constant-time
  behaviour is validated by dudect-style testing (see
  `CONSTANT_TIME_VERIFICATION.md`).
- Users should conduct independent review before deployment in
  high-security or regulated environments.

---

## 4. Review Status

This document is a **self-assessment** by Steel Security Advisors LLC.
It reflects the authors' understanding of the security properties of the
original constructions described above. It is explicitly **not** an
independent audit, formal verification, or peer-reviewed proof.

Independent review by qualified cryptographers is recommended before
relying on AMA Cryptography for high-assurance use cases. Please contact
`steel.sa.llc@gmail.com` to coordinate audit efforts (PGP key:
[`pgp-key.asc`](../pgp-key.asc)).

---

## See Also

- [`../SECURITY.md`](../SECURITY.md) — Vulnerability reporting and policy
- [`../THREAT_MODEL.md`](../THREAT_MODEL.md) — System threat model
- [`../CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md) — Algorithm summary
- [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — System architecture
- [`../CONSTANT_TIME_VERIFICATION.md`](../CONSTANT_TIME_VERIFICATION.md) — Timing-side-channel validation
- [`../CSRC_ALIGN_REPORT.md`](../CSRC_ALIGN_REPORT.md) — NIST ACVP vector conformance
