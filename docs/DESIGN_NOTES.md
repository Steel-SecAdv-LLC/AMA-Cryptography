# Security Design Notes — Original Constructions

**Version:** 5.0.0
**Date:** 2026-11-22
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

**Where the claims are.** [Section 5](#5-claim-boundaries) is the one place
that states, for the hybrid signature, the hybrid KEM combiner, the adaptive
posture system and the composed package, exactly what is claimed, under which
assumption, which code realises it, and where the claim stops.  Every other
document that describes these constructions points there;
`tests/test_composition_claim_boundaries.py` pins the code facts it cites.

---

## 1. Double-Helix Evolution Engine

### 1.1 Purpose and Non-Cryptographic Status

The Double-Helix Evolution Engine is explicitly a **non-cryptographic** module
that provides mathematical modeling and analytical utilities for the 3R
monitoring subsystem. It implements state evolution, convergence, and
constraint-satisfaction algorithms inspired by biological and physical systems.

This is stated normatively in the module docstring of
`ama_cryptography/double_helix_engine.py`, under its NON-CRYPTOGRAPHIC MODULE heading:

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
| Numerical instability / NaN propagation | Invalid score returned to posture system | Availability only — invalid values may propagate into posture evaluation and disrupt monitoring-driven posture updates unless handled by the caller |
| Incorrect score (too high) | Spurious escalation signal | Unnecessary key rotation / algorithm switch (availability / operational cost) |
| Incorrect score (too low) | Missed escalation signal | Delayed response to a *monitoring* anomaly; no reduction in baseline cryptographic strength |
| Exception during evaluation | Exception propagates out of posture evaluation | Availability only — may interrupt the evaluation loop rather than logging and continuing; callers should wrap in their own fault handler |

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

1. **Escalation by default; downgrade requires explicit acknowledgement.**
   The `PostureAction` enumeration contains no automatic "downgrade"
   operation. The system cannot autonomously move from a post-quantum
   algorithm to a classical one, or drop a cryptographic layer, or shorten a
   key. Algorithm switches select from a policy-defined set of
   equal-or-stronger primitives. A human-in-the-loop de-escalation path
   exists via `CryptoPostureController.acknowledge_downgrade(reason)`, which
   resets `_highest_algorithm_reached` to the current algorithm strength and
   logs the reason for audit. Downgrades therefore require an operator
   action; they never happen as an automatic response to monitoring signals.
2. **Delegated security.** Every action invokes a vetted primitive
   (Ed25519, ML-DSA-65, ML-KEM-1024, HKDF-SHA3-256, AES-256-GCM, etc.). The
   posture system's security therefore reduces to the security of those
   primitives plus the correctness of the orchestration logic.
3. **Rate limiting via cooldowns.** `CryptoPostureController` enforces a
   cooldown between consecutive destructive actions (key rotation, algorithm
   switch), preventing a signal storm from degrading availability through
   unbounded rotation.
4. **Optional confirmation mode.** Destructive actions may be queued as
   `PendingAction` objects that an operator can confirm (`confirm_action`)
   or cancel (`reject_action`) during a grace period (`grace_period`,
   default 300 s).  An action nobody answers **executes when the grace period
   expires** (`_process_expired_pending_actions`), so the checkpoint is a
   veto window, not a required acknowledgement.  *(Corrected 2026-11-22: this
   item said the actions "require explicit operator acknowledgement", which
   the code has never enforced; the fail-safe direction is deliberate.)*
5. **Bounded operational state only.** `PostureEvaluator` retains limited
   cross-call state — an exponentially decayed `_accumulated_score` and a
   `_consecutive_counts` tally per threat level — used to debounce noisy
   inputs and prevent oscillation near decision thresholds. This state is
   bounded in size, decays over time, contains no secrets or key material,
   and does not create unbounded mutable state an attacker could poison
   indefinitely. At worst, sustained signal manipulation can influence
   posture transitions within the threat boundaries described in §2.3.

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

Plus a supporting operation: HKDF-SHA3-256 key derivation (RFC 5869).

The optional RFC 3161 timestamp is deliberately **excluded** from the security
argument below. AMA verifies the §2.4.2 message-imprint binding and no TSA
signature, so the token carries no adversarial resistance and must not appear
in a bound (INVARIANT-37).

The overall security argument is:

- **Bound.** Stated exactly, with where it stops, in [§5.4](#54-composed-package-create_crypto_package).
  *(Corrected 2026-11-22: this bullet read "quantum security is bounded below
  by 2^128 via Grover-resistant primitives".  The signatures cover a
  transcript holding SHA3-256(content), not the content, so their binding to
  the content is SHA3-256 collision resistance, and Grover's algorithm is not
  the relevant attack on that.)*
- **Defence-in-depth.** Compromise of one primitive does not assist attack on
  another because each primitive uses an independently drawn key (§3.2) and
  operates on an independently bound input transcript.
- **Forgery resistance.** Producing a forgery requires simultaneous breaks of
  both signature layers (Ed25519 *and* ML-DSA-65), under distinct hardness
  assumptions (elliptic-curve discrete log *and* module-lattice MLWE/MSIS).

### 3.2 Key Independence

The HMAC key and the signing key pairs are drawn independently from the
CSPRNG (`secure_token_bytearray`, the providers' `generate_keypair`).  The
Layer-4 keys are derived from a separate master secret via HKDF-SHA3-256
using distinct `info` strings for domain separation (RFC 5869 §3.3). Per RFC
5869 §3, when `info` strings are distinct, derived keys are cryptographically
independent under the assumption that HKDF's underlying PRF, here
HMAC-SHA3-256, behaves as a PRF.  *(Corrected 2026-11-22: this paragraph said
ALL layer keys are derived from one master secret; the HMAC key never was.)*

Domain-separation strings are fixed, versioned, and length-prefixed per the
v2.1.5 security audit (see commit `b700050`, "Security audit fixes:
length-prefixed encoding, constant-time ops, and validation"). This prevents
canonicalization ambiguity between keys derived under different contexts.

### 3.3 Hybrid KEM Combiner

The hybrid KEM combiner binds X25519 and ML-KEM-1024 shared secrets per
Bindel, Brendel, Fischlin, Goncalves, Stebila (2019), "Hybrid Key
Encapsulation Mechanisms and Authenticated Key Exchange."  What is claimed,
under which assumption, and where it stops is [§5.2](#52-hybrid-kem-combiner-x25519--ml-kem-1024).
*(Corrected 2026-11-22: this paragraph stated the IND-CCA2 result without the
dual-PRF assumption it rests on, which SECURITY.md already named.)*

### 3.4 Known Limitations

- No **formal composition proof** has been written for the specific
  multi-layer construction used here. The informal argument above is a best
  effort; it is not a substitute for a mechanized or peer-reviewed proof.
- The composition has not been independently audited.
- Side-channel resistance of the composition depends on the side-channel
  resistance of each underlying primitive implementation, and stops where
  §5 says it does: ML-DSA-65 signing, and so the hybrid signer, does not run
  in fixed time (INVARIANT-12's carve-out).  The per-primitive measurements
  are in `CONSTANT_TIME_VERIFICATION.md` and `tools/check_ct_claims.py`.
- Users should conduct independent review before deployment in
  high-security or regulated environments.

---

## 4. Review Status

This document is a **self-assessment** by Steel Security Advisors LLC.
It reflects the authors' understanding of the security properties of the
original constructions described above. It is explicitly **not** an
independent audit, formal verification, or peer-reviewed proof.

Independent review by qualified cryptographers is recommended before
relying on AMA Cryptography for high-assurance use cases. To coordinate
audit efforts, use [GitHub Private Vulnerability Reporting](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/security/advisories/new)
(preferred) or email `steel.sa.llc@gmail.com` as a fallback. See
[`../SECURITY.md`](../SECURITY.md) for the full reporting policy.

---

## 5. Claim Boundaries

Added 2026-11-22.  This is the single statement of what the original
constructions claim.  Each subsection gives the construction as the code
builds it, the claim, the assumption it rests on, and the point at which it
stops.  Every claim here is an **informal, self-attested argument**: none has
a mechanised or peer-reviewed proof for the encoding AMA uses, and none has
been independently reviewed (§4, INVARIANT-16).  Nothing in this section adds
a claim the documents did not already make; where they made more, they were
corrected in the same change.

### 5.1 Hybrid signature (Ed25519 + ML-DSA-65), format v2

**Construction.** `ama_sign` / `ama_verify` with `AMA_ALG_HYBRID`
(`src/c/ama_core.c`, `hybrid_sign_body` / `hybrid_verify`) and
`crypto_api.HybridSignatureProvider` build the same bytes.  With
`D = "AMA-Cryptography/hybrid-sig/v2/Ed25519+ML-DSA-65"`
(`AMA_HYBRID_SIG_DOMAIN`, `HYBRID_SIG_DOMAIN`):

```
sig = Ed25519.Sign(sk_ed, 0x00 || len(D) || D || M)          (64 bytes)
   || ML-DSA-65.Sign(sk_ml, M, ctx = D)                     (3309 bytes)
verify = Ed25519.Verify(...) AND ML-DSA-65.Verify(..., ctx = D)
```

The C verifier evaluates both halves and ANDs the verdicts without
short-circuit.

**Claimed.** Existential unforgeability under chosen-message attack holds if
*either* component is EUF-CMA: a forgery must forge Ed25519 on the wrapped
message and ML-DSA-65 under context `D`.  Against a quantum adversary only the
ML-DSA-65 half counts (NIST category 3); Ed25519 contributes nothing.  Because
both halves bind `D`, neither half is a valid standalone signature on `M`, and
a standalone signature on `M` cannot be spliced in, when a key is also used
for standalone signing through these libraries' standalone entry points.

**Stops at.**
- The "either component" argument is the standard AND-combiner argument,
  applied to this encoding, not proven for it.
- Strong unforgeability of the pair is not claimed.
- Separability is excluded only for messages signed through the standalone
  APIs with their own framing; `ama_ed25519_sign` over a message that itself
  begins `0x00 || len(D) || D` produces a valid Ed25519 half.  Key reuse with
  raw Ed25519 is outside the claim.
- Timing: the hybrid signer does not run in fixed time.  Its Ed25519 half is
  held by the `ed25519-sign` count and taint gates; its ML-DSA-65 half is
  INVARIANT-12's carve-out (the FIPS 204 attempt count depends on the key and
  the message), held only by the `ml-dsa-sign` taint gate.

### 5.2 Hybrid KEM combiner (X25519 + ML-KEM-1024)

**Construction.** `crypto_api.HybridKEMProvider` calls
`hybrid_combiner.HybridCombiner.combine`, which derives the shared secret
through the native `ama_hkdf` (HKDF-SHA3-256) and never through Python
(INVARIANT-7, INVARIANT-19).  With `I32` a 4-byte big-endian length,
`c1` the ephemeral X25519 public key, `k1 = X25519(eph_sk, pk1)` and
`(c2, k2) = ML-KEM-1024.Encaps(pk2)`:

```
K = HKDF-SHA3-256(salt = I32(|c1|) || c1 || I32(|c2|) || c2,
                  ikm  = k1 || k2,
                  info = "ama-hybrid-kem-v2" || 0x02 || I32(|pk1|) || pk1 || I32(|pk2|) || pk2,
                  L    = 32)
```

**Claimed.** The combined KEM is IND-CCA2 if at least one component KEM is,
by the dual-PRF combiner argument of Bindel et al. (PQCrypto 2019), under the
assumption that HMAC-SHA3-256, as HKDF-Extract, is a **dual PRF** -- a PRF
when keyed through either input, here through its message by whichever of
`k1`, `k2` is pseudorandom -- and that HKDF-Expand is a PRF.  The
ML-KEM-1024 component is FIPS 203, category 5.  The X25519 component is a KEM
only in the sense of ephemeral-static Diffie-Hellman, whose IND-CCA security
is a random-oracle argument under the gap Diffie-Hellman assumption with the
ciphertext and public key hashed into the key, which `salt` and `info` do;
against a quantum adversary it contributes nothing.

**Stops at.**
- The paper's combiner hashes the secrets with a dual PRF and then applies a
  PRF to the ciphertexts; AMA places the ciphertexts in Extract's salt (HMAC's
  key) and the secrets in its message.  The argument is applied to that
  placement, not re-proven for it.
- `ikm` is a bare concatenation, unambiguous only because both components
  emit exactly 32 bytes.  `combine()` accepts other widths without that
  guarantee (its docstring says so).
- Public-key binding exists only when the caller supplies the public keys.
  `HybridKEMProvider` always does; `combine()` defaults them to empty.
- Implicit rejection is the ML-KEM half's alone (FIPS 203: a malformed
  ciphertext yields a pseudorandom secret, measured by `kyber-decaps`).  The
  X25519 half refuses a low-order point with an error (INVARIANT-21), which is
  observable.
- Timing: X25519 (`x25519`), ML-KEM decapsulation (`kyber-decaps`) and HKDF
  (`hkdf`) are measured.  The Python orchestration that copies the two secrets
  into one `bytearray` for the native HKDF takes no secret-dependent branch
  (INVARIANT-12 rule 1) and is not itself measured: the timing instruments run
  in C.

### 5.3 Adaptive posture system

**Construction.** `adaptive_posture.CryptoPostureController` maps evaluated
monitor signals to `PostureAction`s.  Escalation moves the current algorithm
to the next rung of its family's ladder (`ALGORITHM_FAMILIES`): signatures
`ED25519 (0) < ML_DSA_65 (1) < SPHINCS_256F (2) < HYBRID_SIG (3)`, KEMs
`KYBER_1024 (0) < HYBRID_KEM (1)`.

**Claimed.** No automatic action selects a lower rung than the highest
reached; moving down requires `acknowledge_downgrade(reason)`, which is
logged.  Manipulating the monitored signals can therefore cost availability
(unnecessary rotation or switching, bounded by the cooldown) but cannot lower
the cryptographic parameters below the configured baseline.

**Stops at.**
- It is a heuristic response layer with **no security bound**: no detection
  rate, no false-positive bound, no resistance to an attacker who controls
  the signals.
- A downgrade made by assigning `current_algorithm` from outside is detected
  and logged at CRITICAL on the next evaluation, not refused.
- A "switch" changes the controller's selection and calls
  `on_algorithm_switch`; what is actually used is the application's wiring of
  that callback.
- The ladders are policy orderings, not security reductions.
- Rotation does not undo a compromise: data protected under a leaked key
  stays exposed.
- Confirmation mode is a veto window: an unanswered action executes when the
  grace period expires (§2.2, item 4).
- It handles no secret material, so it carries no constant-time obligation.

### 5.4 Composed package (`create_crypto_package`)

**Construction.** SHA3-256(content); HMAC-SHA3-256 over the content with a
CSPRNG-drawn key; the hybrid signature (§5.1) over a canonical transcript of
the whole package (`package_transcript`), which holds SHA3-256(content), the
public keys, the add-ons and their presence, the HKDF parameters and the
metadata; HKDF-SHA3-256 Layer-4 keys from a separate master secret.

**Claimed.** Authenticity against an adversary who does not hold the signing
keys, **when the verifier supplies the expected public key**: forging a
package requires forging the hybrid signature (§5.1) or finding a SHA3-256
collision.  Classically the collision search sets it, at about 2^128: the
hybrid signature needs both halves forged, so it is the harder target.  Against a quantum adversary it is the lesser of SHA3-256
collision resistance, which is NIST post-quantum category 2 by that category's
definition, and ML-DSA-65's category 3: **category 2**.

**Stops at.**
- Verified against the package's own embedded public key, the package proves
  integrity and internal consistency only, not authenticity
  (`verify_crypto_package`'s docstring).
- The HMAC key and the Layer-4 master secret travel in the package
  (`package.hmac_key`, `package.hkdf_master_secret`).  Against anyone who
  holds the package, Layers 2 and 4 add no forgery resistance beyond
  Layer 1; their value is against a party who does not.
- The RFC 3161 timestamp is outside the claim (INVARIANT-37).

---

## See Also

- [`../SECURITY.md`](../SECURITY.md) — Vulnerability reporting and policy
- [`../THREAT_MODEL.md`](../THREAT_MODEL.md) — System threat model
- [`../CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md) — Algorithm summary
- [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — System architecture
- [`../CONSTANT_TIME_VERIFICATION.md`](../CONSTANT_TIME_VERIFICATION.md) — Timing-side-channel validation
- [`compliance/CSRC_ALIGN_REPORT.md`](compliance/CSRC_ALIGN_REPORT.md) — NIST ACVP vector conformance
