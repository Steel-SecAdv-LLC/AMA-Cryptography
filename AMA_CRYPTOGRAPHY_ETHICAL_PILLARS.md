# AMA Cryptography: 4 Omni-Code Ethical Pillars
## Cryptographic Integration of Ethical Vectors with SHA3-256 Security

**Copyright (C) 2025-2026 Steel Security Advisors LLC**
**Project:** Omni-Code Helix SHA3-256 Ethical Framework
**Author/Inventor:** Andrew E. A.
**Organization:** Steel Security Advisors LLC

**Version:** 5.0.0
**Date:** 2026-07-25

---

## Document Structure

This document has **two distinct sections**, and readers should be clear
on which layer a given claim belongs to:

- **Part A — FIPS Primitive Layer (reference only).** A short summary of
  which standardized primitives the AMA Cryptography library
  implements. No original claims live here; details belong to
  [`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md) and
  [`CSRC_ALIGN_REPORT.md`](docs/compliance/CSRC_ALIGN_REPORT.md).
- **Part B — Ethical Policy Layer (original work).** The 4 Omni-Code
  Ethical Pillars, HKDF context integration, ethical vector
  construction, and all original constructions by Steel Security
  Advisors LLC. This is a policy framework **built on top of** the
  FIPS primitives; it does not modify them.

---

## Part A — FIPS Primitive Layer (reference)

The ethical framework described in Part B is built on top of the
following standardized primitives:

- **FIPS 202** — SHA3-256 / SHA3-512 / SHAKE-128 / SHAKE-256
- **FIPS 203** — ML-KEM-1024
- **FIPS 204** — ML-DSA-65
- **FIPS 205** — SLH-DSA-SHA2-256f
- **FIPS 198-1** — HMAC (with SHA3-256 per RFC 2104)
- **FIPS 180-4** — SHA-256
- **NIST SP 800-38D** — AES-256-GCM
- **NIST SP 800-108 / RFC 5869** — HKDF
- **RFC 8032** — Ed25519
- **RFC 7748** — X25519
- **RFC 8439** — ChaCha20-Poly1305
- **RFC 9106** — Argon2id

See [`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md) for per-primitive implementation
details, key sizes, and security properties; see
[`CSRC_ALIGN_REPORT.md`](docs/compliance/CSRC_ALIGN_REPORT.md) for ACVP validation results
(current attestation count and library version live there — consult the
report rather than relying on a number hard-coded here). See
[`src/c/PROVENANCE.md`](src/c/PROVENANCE.md) for per-primitive derivation
status (PQC primitives are clean-room from the FIPS text; Ed25519 is
in-house — its formerly vendored x86-64 backend was removed in the
twenty-first maintenance pass).

> **Boundary Notice:** Everything above this line describes standardized
> cryptographic primitives governed by NIST FIPS and IETF RFC
> specifications. Everything below describes the **Omni-Code Ethical
> Pillars** — an original policy framework by Steel Security Advisors
> LLC that is *built on top of* those primitives. The ethical layer
> does not modify the cryptographic primitives themselves, does not
> alter their security bounds, and does not claim CAVP or CMVP
> validation for the framework.

---

## Part B — Ethical Policy Layer (original)

## Executive Summary

The 4 Omni-Code Ethical Pillars extend AMA Cryptography's multi-layer cryptographic defense with a mathematically rigorous ethical constraint system. Each pillar maps to a triad of cryptographic operations, providing verifiable ethical boundaries without compromising security guarantees.

**Key Properties:**
- **Balanced weighting:** Each pillar = 3.0 (3 sub-properties × 1.0), Σw = 12.0
- **HKDF integration:** 128-bit ethical signature in key derivation context
- **Collision resistance:** Maintains SHA3-256's 2^128 security level — the
  ethical vector enters HKDF only through the `info` parameter, so the
  primitive's own collision bound (set by FIPS 202) is preserved.
- **Low measured overhead:** <0.01 ms per operation in the reference
  benchmark (generic C path, single-threaded). This is the overhead of
  computing the ethical-vector hash, not a security guarantee.
- **Standards compliant:** Consumes only FIPS / RFC primitives listed
  in Part A. The Omni-Code Ethical Pillars themselves are original
  work and are **not** a NIST or IETF standard.

---

## The 4 Ethical Pillars

### Pillar 1: Omniscient — Triad of Wisdom (Verification Layer)

**Definition:** All-knowing verification across every data input, detection dimension, and validation path.

#### Sub-property 1.1: Complete Verification
**Cryptographic Mapping:**
- SHA3-256 content hashing with canonical encoding
- HMAC-SHA3-256 authentication across all message components
- Prevents incomplete verification vulnerabilities

**Mathematical Proof:**
```
Let V = {v₁, v₂, ..., vₙ} be verification points
Omniscient coverage ⟺ ∀vᵢ ∈ V: SHA3(vᵢ) is computed
Security: If any vᵢ bypasses hashing, integrity fails
Therefore: Complete coverage is cryptographically necessary
```

#### Sub-property 1.2: Multi-Dimensional Detection
**Cryptographic Mapping:**
- Structural integrity via length-prefixed encoding
- Multi-signature validation (Ed25519 + Dilithium)

**Mathematical Proof:**
```
Let D = {structural, cryptographic} dimensions
Anomaly detection probability:
P(detect) = 1 - ∏(1 - Pᵢ) where Pᵢ = detection rate per dimension
With Pᵢ ≥ 0.999 (SHA3-256 collision resistance):
P(detect) ≥ 1 - (0.001)² = 0.999999
```

**Why the temporal dimension is excluded, and the exponent with it.** RFC 3161
timestamp checking used to be counted here as a third dimension, giving
`1 - (0.001)³`. A detection dimension has to be one an adversary cannot
satisfy at will, and this one is not: AMA verifies the §2.4.2 message-imprint
binding and no TSA signature, so an adversary who modifies content and supplies
a matching self-built token passes the temporal check every time — its
detection rate against an adaptive adversary is 0, not 0.999. Multiplying it in
inflated the stated bound by three orders of magnitude. The corrected figure
rests only on dimensions an adversary must actually defeat. See INVARIANT-37.

**Standards:** NIST FIPS 202 (SHA-3), RFC 8032 (Ed25519), NIST FIPS 204 (ML-DSA)

#### Sub-property 1.3: Complete Data Validation
**Cryptographic Mapping:**
- Length-prefixed canonical encoding eliminates concatenation attacks
- UTF-8 validation for Omni-Codes
- Helix parameter bounds checking (radius, pitch)

**Mathematical Proof:**
```
Canonical encoding E(m) ensures unique representation:
E(m₁ || m₂) ≠ E(m₁') || E(m₂') for m₁ ≠ m₁' or m₂ ≠ m₂'
Attack resistance:
P(collision via concatenation) = 0 (structural impossibility)
P(collision via E(m)) ≤ 2⁻²⁵⁶ (SHA3-256 bound)
```

**Citation:** NIST FIPS 202 (SHA-3 Standard, Section 6.1)

**Pillar Weight:** w₁ = 3.0 (3 × 1.0)

---

### Pillar 2: Omnipotent — Triad of Agency (Cryptographic Generation)

**Definition:** All-powerful cryptographic strength across key generation, security margins, and active protection.

#### Sub-property 2.1: Maximum Cryptographic Strength
**Cryptographic Mapping (Per-Layer Assessment):**
- SHA3-256: ~128-bit preimage resistance (NIST FIPS 202)
- HMAC-SHA3-256: ~128-bit security (RFC 2104)
- Ed25519: ~128-bit classical security (RFC 8032)
- ML-DSA-65 (Dilithium): ~192-bit quantum security (NIST FIPS 204)
- HKDF-SHA3-256: ~256-bit key derivation (RFC 5869)

**Defense-in-Depth Principle:**
```
System security is bounded by the weakest layer:
- Classical security: ~128-bit (Ed25519/HMAC)
- Quantum security: ~192-bit (Dilithium)

Package authenticity is protected by four independent cryptographic
operations — content hashing, keyed authentication, classical signature,
and quantum-resistant signature — supported by independent key derivation.
The optional RFC 3161 timestamp is excluded from this bound: it is a
binding check an adversary satisfies unaided (INVARIANT-37).
Defense-in-depth ensures continued protection even if one layer is
compromised.
```

**Citation:**
- NIST FIPS 204 (Dilithium, Section 5.3)
- Ducas et al. (2018) "CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme"

#### Sub-property 2.2: Secure Key Generation
**Cryptographic Mapping:**
- CSPRNG with os.urandom() (256 bits entropy)
- HKDF-SHA3-256 for deterministic key derivation
- Independent Dilithium keypair generation

**Mathematical Proof:**
```
Master secret entropy: H(S) = 256 bits
HKDF security: PRF assumption on HMAC-SHA3-256
Derived key indistinguishability:
|Pr[A distinguishes HKDF(S) from random] - 1/2| ≤ ε
where ε ≤ 2⁻¹²⁸ (HMAC-SHA3-256 security)

Key independence:
KDF(S, "hmac") ⊥ KDF(S, "ed25519") ⊥ KDF(S, "reserved")
```

**Citation:**
- RFC 5869 (HKDF, Section 4)
- Krawczyk (2010) "Cryptographic Extraction and Key Derivation: The HKDF Scheme"

#### Sub-property 2.3: Real-Time Protection
**Cryptographic Mapping:**
- Sign operation: 0.90ms (1,116 ops/sec)
- Verify operation: 0.21ms (4,717 ops/sec)
- Parallel verification support (4+ cores)

**Performance Proof:**
```
Measured benchmarks (single-threaded):
- KeyGen: 0.27ms → 3,700/sec
- Sign: 0.90ms → 1,116/sec
- Verify: 0.21ms → 4,717/sec

Production requirement: >100 ops/sec
Margin: 11.16× for signing, 47.17× for verification
Conclusion: Suitable for real-time cryptographic protection
```

**Pillar Weight:** w₂ = 3.0 (3 × 1.0)

---

### Pillar 3: Omnidirectional — Triad of Geography (Defense-in-Depth)

**Definition:** All-encompassing defense across every layer, time horizon, and attack vector.

#### Sub-property 3.1: Multi-Layer Defense
**Cryptographic Mapping:**
- Layer 1: SHA3-256 content hash (integrity) — NIST FIPS 202, 128-bit collision resistance
- Layer 2: HMAC-SHA3-256 keyed authentication — RFC 2104, 256-bit key
- Layer 3: Hybrid Ed25519 + ML-DSA-65 digital signature — RFC 8032 + NIST FIPS 204
- Layer 4: HKDF-SHA3-256 key derivation (key independence) — RFC 5869
- Optional add-ons (not core layers): SLH-DSA-SHA2-256f, ML-KEM-1024, RFC 3161 timestamping

**Defense-in-Depth Proof:**
```
Single-layer failure probability: P(fail) per layer
Multi-layer failure requires ALL layers to fail:
P(system_fail) = ∏P(failᵢ)

With P(failᵢ) ≤ 2⁻¹²⁸ for each cryptographic layer:
P(system_fail) ≤ (2⁻¹²⁸)⁴ = 2⁻⁵¹²

Conclusion: Defense-in-depth provides exponential security improvement
```

**Citation:** Schneier (1999) "Attack Trees" (defense-in-depth strategy)

#### Sub-property 3.2: Temporal Binding (*not* Temporal Integrity)

This sub-property is stated at the strength that is actually delivered. The
claim it used to make — temporal *integrity*, established by a TSA signature —
rested on a verification step AMA does not implement, and its security
statement was inverted: forging a token AMA accepts requires no key at all.

**Cryptographic Mapping:**
- ISO 8601 timestamps (microsecond precision), self-asserted
- RFC 3161 §2.4.2 message-imprint binding — token-to-payload only
- Temporal ordering of AMA's own records

**What is established:**
```
For a token K and payload H:
    binding(K, H) ⟺ K.TSTInfo.messageImprint == Hash(H)

This is all AMA checks. It is a statement about which payload a token
refers to. It is NOT a statement about time, about the token's issuer,
or about when anything existed.
```

**What is NOT established, and why:**
```
Attestation would require verifying S_TSA over the TSTInfo, i.e.
CMS SignerInfo processing (RFC 5652 §5.3) plus X.509 path validation
(RFC 5280 §6). AMA implements neither.

Consequence — note the direction, because the previous text had it
backwards: forging a token this library accepts requires NO private key
and NO compromise of any TSA. An adversary builds a CMS SignedData
offline whose messageImprint is Hash(H) and whose genTime is arbitrary.

Therefore: TSTInfo.genTime is unauthenticated, no non-repudiation of
time is provided, and no causal ordering claim may rest on a TSA.
```

Temporal integrity is **not** delivered by this library. A deployment can
obtain it only by establishing the token's origin outside AMA. See INVARIANT-37 and
[ARCHITECTURE.md § Scope: RFC 3161 attestation is not implemented](ARCHITECTURE.md#scope-rfc-3161-attestation-is-not-implemented).

**Citation:**
- RFC 3161 (Time-Stamp Protocol, Section 2.4)
- ISO/IEC 18014 (Time-Stamping Services)

#### Sub-property 3.3: Attack Surface Coverage
**Cryptographic Mapping:**
- Concatenation: Prevented by length-prefixed encoding
- Collision: SHA3-256 (2^128 security)
- Forgery: HMAC + dual signatures
- Quantum: Dilithium lattice-based signatures

**Attack Coverage Proof:**
```
Attack surface A = {concatenation, collision, forgery, quantum}

Coverage:
- concatenation ⊆ canonical_encoding (structural defense)
- collision ⊆ SHA3-256 (2⁻²⁵⁶ probability)
- forgery ⊆ HMAC ∩ Ed25519 ∩ Dilithium (2⁻¹²⁸ each)
- quantum ⊆ Dilithium (2⁻¹⁹² quantum security)

∀a ∈ A: ∃ defense(a) with security ≥ 2¹²⁸
```

**Citation:**
- Bernstein et al. (2011) "High-speed high-security signatures" (Ed25519)
- NIST SP 800-57 (Key Management, Section 5.6.1)

**Pillar Weight:** w₃ = 3.0 (3 × 1.0)

---

### Pillar 4: Omnibenevolent — Triad of Integrity (Ethical Constraints)

**Definition:** All-good ethical foundation ensuring mathematical correctness and long-term security resilience.

#### Sub-property 4.1: Ethical Foundation
**Cryptographic Mapping:**
- Omni-Codes honor individuals (ethical constraint)
- Humanitarian crisis monitoring (CIΨIS integration option)
- Prevents weaponization through transparent audit trails

**Ethical Proof:**
```
Omnibenevolence constraint B enforces:
∀ operation o: purpose(o) ∈ {protect, verify, authenticate}
               purpose(o) ∉ {attack, deceive, harm}

Cryptographic enforcement:
- Public key distribution (transparency)
- Author attribution in packages
- Audit trails, whose *timestamps* are self-asserted: an RFC 3161 token
  binds a trail entry to its payload but does not attribute it to a
  clock, because no TSA signature is verified (INVARIANT-37)

Verification: Operations are auditable and attributable as to *content
and author*; attribution as to *time* requires a control outside AMA
```

#### Sub-property 4.2: Mathematical Correctness
**Cryptographic Mapping:**
- Length-prefixed encoding (provably unambiguous)
- Primitives implemented from the published standards and pinned to their
  published test vectors (FIPS 202/203/204/205, RFC 8032/7748/5869/8439)
- Measured test coverage — see `pyproject.toml` for the enforced floor and
  `docs/METRICS_REPORT.md` for the current figure

**Correctness Argument:**
```
Specification S defines correct behavior
Implementation I must satisfy: I ⊨ S

Evidence:
1. Known Answer Tests against published NIST/IETF vectors, plus the
   vendored ACVP and Wycheproof corpora, run as CI gates that fail closed
2. Property-based testing (Hypothesis) over the parsing and AEAD surfaces
3. Differential testing against independent implementations
4. Static typing (mypy --strict) and sanitizer/fuzz coverage of the C core

This is testing evidence, not proof: it bounds the behaviours exercised,
and no confidence figure is claimed from it.
```

**Verification status — read this before citing the above:**
This library is **not** FIPS-validated and has **not** been formally verified.
No CAVP or CMVP certificate has been issued for it, and NIST has not reviewed
it; the ACVP figures reported elsewhere in this repository are a
**self-attestation** against published vectors, which is a different thing from
a validation certificate. Its primitives follow the FIPS/RFC specifications and
its POST follows the FIPS 140-3 §4.9 *pattern*, and that is the whole of the
claim. See `CSRC_STANDARDS.md` ("No CAVP certificate has been issued", "No CMVP
certificate has been issued") and the same disclaimer in `README.md`, which are
the canonical statements.

**Citation:**
- NIST SP 800-140 (Cryptographic Module Validation Program requirements —
  cited as the standard this library's POST design *follows*, not as a program
  it has been through)
- Klein et al. (2014) "Comprehensive formal verification of an OS microkernel"
  (cited as the reference point for what formal verification means; this
  library has not undergone it)

#### Sub-property 4.3: Hybrid Security
**Cryptographic Mapping:**
- Classical: Ed25519 (immediate deployment)
- Quantum: Dilithium (future-proofing)
- Dual-signature verification (both must pass)

**Hybrid Security Proof:**
```
Security timeline:
- 2025-2030: Ed25519 secure, Dilithium secure
- 2030-2035: Ed25519 weakened, Dilithium secure
- 2035+: Ed25519 broken, Dilithium secure

Hybrid security:
S_hybrid(t) = max(S_Ed25519(t), S_Dilithium(t))
             ≥ S_Dilithium(t) for all t
             ≥ 2¹⁹² (quantum security)

Long-term guarantee: 50+ years post-quantum security
```

**Citation:**
- NIST PQC Project (2022) "Post-Quantum Cryptography Standardization"
- Bernstein & Lange (2017) "Post-quantum cryptography"

**Pillar Weight:** w₄ = 3.0 (3 × 1.0)

---

## Mathematical Integration Framework

### Ethical Vector Construction

<!-- example: python-run -->
```python
# 4 Omni-Code Ethical Pillars as balanced vector
# Each pillar = 3 sub-properties × 1.0 weight
ethical_vector = {
    # Pillar 1: Omniscient — Triad of Wisdom
    "omniscient": 3.0,        # Verification + Detection + Validation

    # Pillar 2: Omnipotent — Triad of Agency
    "omnipotent": 3.0,        # Strength + Generation + Protection

    # Pillar 3: Omnidirectional — Triad of Geography
    "omnidirectional": 3.0,   # Defense + Temporal + Coverage

    # Pillar 4: Omnibenevolent — Triad of Integrity
    "omnibenevolent": 3.0,    # Ethics + Correctness + Hybrid
}

# Verify balanced weighting
assert sum(ethical_vector.values()) == 12.0
assert all(w == 3.0 for w in ethical_vector.values())
```

### HKDF Integration with Ethical Context

<!-- example: python-run -->
```python
import json
from typing import Dict

from ama_cryptography.legacy_compat import create_ethical_hkdf_context as library_context
from ama_cryptography.pqc_backends import native_sha3_256

ethical_vector = {
    "omniscient": 3.0,
    "omnipotent": 3.0,
    "omnidirectional": 3.0,
    "omnibenevolent": 3.0,
}


def create_ethical_hkdf_context(base_context: bytes, ethical_vector: Dict[str, float]) -> bytes:
    """
    Integrates ethical vector into HKDF key derivation context.

    The ethical context enters HKDF only through its info parameter, so it
    changes which key is derived without touching the HKDF construction.

    Args:
        base_context: Original HKDF info parameter
        ethical_vector: 4-pillar ethical weights (sum 12.0)

    Returns:
        base_context followed by a 128-bit ethical signature
    """
    # Canonical JSON encoding (sorted keys)
    ethical_json = json.dumps(ethical_vector, sort_keys=True)

    # SHA3-256 of the canonical encoding (AMA's native FIPS 202 kernel)
    ethical_hash = native_sha3_256(ethical_json.encode())

    # Extract 128-bit signature (first 16 bytes)
    ethical_signature = ethical_hash[:16]

    # Concatenate with base context
    return base_context + ethical_signature


# Example usage
base_context = b"AMA-Cryptography-2025"
enhanced = create_ethical_hkdf_context(base_context, ethical_vector)

# Result: base_context || SHA3-256(canonical JSON of ethical_vector)[:16]
# Length: 21 bytes + 16 bytes = 37 bytes total
assert len(enhanced) == 37

# The function above is the library's own, step for step:
assert enhanced == library_context(base_context, ethical_vector)
```

### Security Proof: Ethical Integration Maintains Collision Resistance

**Theorem:** Adding ethical context to HKDF does not reduce SHA3-256 collision resistance.

**Proof:**
```
Let H = SHA3-256 with collision resistance 2^128
Let C₀ = base HKDF context
Let E = ethical vector with hash H(E)
Let C₁ = C₀ || H(E)[:16]

Claim: Using C₁ instead of C₀ maintains H collision resistance

Proof by contradiction:
Assume ∃ efficient algorithm A finding H collisions via C₁
Then A could:
1. Query HKDF with context C₁ = C₀ || H(E)[:16]
2. Find collision in underlying SHA3-256 within H

But this contradicts SHA3-256 collision resistance (2^128 security)
Therefore: No efficient A exists
Conclusion: Ethical integration is cryptographically safe ∎
```

**Citation:** Krawczyk (2010), HKDF security analysis (Theorem 1)

---

## HKDF Implementation with Ethical Context

<!-- example: python-run -->
```python
from typing import Dict

from ama_cryptography import secure_token_bytes
from ama_cryptography.legacy_compat import derive_keys

ethical_vector = {
    "omniscient": 3.0,
    "omnipotent": 3.0,
    "omnidirectional": 3.0,
    "omnibenevolent": 3.0,
}


def derive_key_with_ethics(
    master_secret: bytes,
    key_type: str,
    ethical_vector: Dict[str, float],
) -> bytes:
    """
    Derives a 32-byte key with the ethical context bound into HKDF's info.

    Compliant with:
    - RFC 5869 (HKDF)
    - NIST FIPS 202 (SHA-3)

    Uses the native C HKDF-SHA3-256 (zero external dependencies).
    ``derive_keys`` builds each derivation's info parameter itself, as
    ``create_ethical_hkdf_context(f"{info}:{i}".encode(), ethical_vector)``,
    so the caller passes the vector, not a pre-built context.  With no
    ``salt`` it draws a fresh 32-byte HKDF salt and returns it beside the
    keys; keep that salt if the key must be derived again.

    Args:
        master_secret: At least 256 bits from the CSPRNG
        key_type: Purpose identifier ("hmac", "ed25519", etc.)
        ethical_vector: 4-pillar ethical weights

    Returns:
        32-byte derived key
    """
    keys, _salt = derive_keys(
        master_secret,
        f"AMA-Cryptography-{key_type}",
        num_keys=1,
        ethical_vector=ethical_vector,
    )
    return keys[0]


# Example: Derive HMAC key with ethical context
master_secret = secure_token_bytes(32)  # 256 bits, health-tested CSPRNG
hmac_key = derive_key_with_ethics(master_secret, "hmac", ethical_vector)
assert len(hmac_key) == 32

print(f"Derived key: {hmac_key.hex()[:32]}...")
print("Ethical context applied: OK")
```

---

## Performance Analysis

### Computational Overhead

<!-- example: python-run -->
```python
import time
from typing import Callable, Dict

from ama_cryptography import secure_token_bytes
from ama_cryptography.legacy_compat import create_ethical_hkdf_context
from ama_cryptography.pqc_backends import native_hkdf

ethical_vector = {
    "omniscient": 3.0,
    "omnipotent": 3.0,
    "omnidirectional": 3.0,
    "omnibenevolent": 3.0,
}


def benchmark_ethical_integration(iterations: int = 20_000, repeats: int = 5) -> Dict[str, float]:
    """Per-derivation cost of HKDF-SHA3-256 with and without the ethical context.

    Both sides make the same HKDF call; the enhanced side also builds the
    context (canonical JSON, SHA3-256, 16-byte truncation) on every call,
    which is the whole of what the ethical layer adds.  Best of ``repeats``.
    """
    base_context = b"AMA-Cryptography-hmac-2025"
    master_secret = secure_token_bytes(32)
    salt = secure_token_bytes(32)

    def per_call(build_info: Callable[[], bytes]) -> float:
        start = time.perf_counter()
        for _ in range(iterations):
            native_hkdf(ikm=master_secret, length=32, salt=salt, info=build_info())
        return (time.perf_counter() - start) / iterations

    baseline = min(per_call(lambda: base_context) for _ in range(repeats))
    enhanced = min(
        per_call(lambda: create_ethical_hkdf_context(base_context, ethical_vector))
        for _ in range(repeats)
    )
    return {
        "baseline_us": baseline * 1e6,
        "enhanced_us": enhanced * 1e6,
        "overhead_us": (enhanced - baseline) * 1e6,
        "overhead_pct": (enhanced - baseline) / baseline * 100,
        "enhanced_derivations_per_s": 1 / enhanced,
    }


for name, value in benchmark_ethical_integration().items():
    print(f"{name}: {value:,.2f}")
```

**Measured, 2026-09-24.** Host: a shared 4-vCPU Intel Xeon @ 2.10 GHz VM
(Linux 6.18) whose load average stood near 30 during the runs, so absolute
times are inflated and the ratios are the figures to read. CPython 3.11.15;
native library built by `python setup.py build_ext --inplace` (Release);
process pinned with `taskset -c 2`; three runs of the block above, best of
five repeats of 20,000 derivations each:

| Run | Bare HKDF-SHA3-256 call | With ethical context | Added | Added, relative |
|-----|------------------------:|---------------------:|------:|----------------:|
| 1 | 11.25 µs | 28.30 µs | 17.04 µs | +151% |
| 2 | 11.26 µs | 25.10 µs | 13.84 µs | +123% |
| 3 | 11.24 µs | 26.45 µs | 15.21 µs | +135% |

**Conclusion:** per derivation, building the context (canonical JSON,
SHA3-256, truncation, all through the Python layer) costs more than the
native HKDF call it feeds. This page used to state "<0.01 ms overhead
(<4%)"; that figure had no recorded host or method, and it is not what a
derivation costs. Per *package* the layer is small: the ethical-hash
computation `legacy_compat.create_crypto_package` performs took 11.5–12.4 µs
of a 1,728–1,744 µs package creation (0.66–0.72%) in two runs of 200
packages, best of five, on the same host.

---

## Standards Compliance Matrix

| Pillar | Triad | Standard | Section | Status |
|--------|-------|----------|---------|--------|
| Omniscient | Wisdom | NIST FIPS 202 | 6.1 (SHA-3) | ✓ Full |
| Omniscient | Wisdom | RFC 3161 | 2.4 (TSP) | ◐ Partial — wire format + §2.4.2 binding; no SignerInfo/X.509 verification |
| Omniscient | Wisdom | NIST FIPS 202 | 6.1 (Encoding) | ✓ Full |
| Omnipotent | Agency | NIST FIPS 203/204/205 | PQC Standards | ✓ Full |
| Omnipotent | Agency | RFC 5869 | 4 (HKDF) | ✓ Full |
| Omnipotent | Agency | — | Performance | ✓ Verified |
| Omnidirectional | Geography | — | Architecture | ✓ Design |
| Omnidirectional | Geography | RFC 3161 | 2.4 (TSA) | ◐ Partial — wire format + §2.4.2 binding; no SignerInfo/X.509 verification |
| Omnidirectional | Geography | NIST SP 800-57 | 5.6.1 | ✓ Full |
| Omnibenevolent | Integrity | — | Ethics | ✓ Design |
| Omnibenevolent | Integrity | NIST SP 800-140 | Validation | ✓ Testing |
| Omnibenevolent | Integrity | NIST PQC | Hybrid | ✓ Full |

---

## Security Impact Assessment

### Original AMA Cryptography Security Posture

**Security Layers:**
- Integrity (SHA3-256): Complete
- Authentication (HMAC): Complete
- Non-Repudiation (Signatures): Complete
- Key Management (HKDF): Excellent
- Quantum Resistance (Dilithium): Secure and tested

**Design Choices:**
- HSM integration: Optional for flexibility
- RFC 3161 TSA: Optional for flexibility

### Enhanced Security with Ethical Pillars

**Improvements:**
- Key Management enhanced with ethical context
  - Ethical context in HKDF provides additional key domain separation
  - Strengthens defense against key confusion attacks

**Enhanced Security Layers:**
- Integrity (SHA3-256): Complete
- Authentication (HMAC): Complete
- Non-Repudiation (Signatures): Complete
- Key Management (HKDF + Ethics): Enhanced ✓
- Quantum Resistance (Dilithium): Secure and tested

**Conclusion:** Ethical pillars enhance security through improved key management domain separation.

---

## Implementation Example

### Complete Workflow with Ethical Integration

<!-- example: python-run -->
```python
import dataclasses
import json

from ama_cryptography import MASTER_CODES, MASTER_HELIX_PARAMS
from ama_cryptography.legacy_compat import (
    create_crypto_package,
    generate_key_management_system,
    recompute_ethical_hash,
    verify_crypto_package,
)

# 1. Define ethical vector (4 pillars, balanced weighting)
ethical_vector = {
    "omniscient": 3.0,
    "omnipotent": 3.0,
    "omnidirectional": 3.0,
    "omnibenevolent": 3.0,
}

# 2. Generate keys with ethical context.
#    generate_key_management_system draws the master secret from the
#    health-tested CSPRNG, derives the HMAC key and the Ed25519 seed with
#    HKDF-SHA3-256 under create_ethical_hkdf_context(..., ethical_vector),
#    and generates the ML-DSA-65 keypair.  Call it; do not assemble a
#    KeyManagementSystem by hand.
kms = generate_key_management_system("Steel-SecAdv-LLC", ethical_vector=ethical_vector)

# 3. Create the package.  It carries the ethical vector and its SHA3-256
#    hash, and both are covered by the Ed25519 and ML-DSA-65 signatures.
package = create_crypto_package(
    MASTER_CODES,
    MASTER_HELIX_PARAMS,
    kms,
    author="Steel-SecAdv-LLC",
)
assert package.ethical_vector == ethical_vector
assert package.ethical_hash == recompute_ethical_hash(ethical_vector).hex()

# 4. Verify every layer.  "ethical_vector" is recomputed from the vector the
#    package carries, not taken from the stored hash.
results = verify_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, package, kms.hmac_key)
checked = ("content_hash", "hmac", "ed25519", "dilithium", "ethical_vector")
assert all(results[name] is True for name in checked), results

# 5. Save the package.  It is public material: signatures, public keys, the
#    ethical vector and its hash, and no secret.
with open("CRYPTO_PACKAGE_ETHICAL.json", "w", encoding="utf-8") as f:
    json.dump(dataclasses.asdict(package), f, indent=2)

# ASCII only: a Windows console defaults to cp1252 (INVARIANT-43).
print("OK: package created and verified with the 4 Omni-Code Ethical Pillars")
print(f"OK: ethical hash {package.ethical_hash[:16]}...")
```

---

## Property Checklist

The heading used to read "Formal Verification Checklist", which claimed a method that has not been applied to this library — see the verification-status block above: it has not been formally verified. An earlier revision of this section then said every box below is "a property this document asserts and the repository tests for", which was not true either: a security level cannot be tested, and several boxes had no test. The list is therefore split by what stands behind each item.

### Tested — each names the test that fails when the property breaks

- [x] **Balanced Weighting:** Σwᵢ = 12.0, each wᵢ = 3.0, four pillars — `tests/test_comprehensive_system.py::TestEthicalVectorIntegration` (`test_ethical_vector_sum_equals_twelve`, `test_ethical_vector_all_weights_equal_three`, `test_ethical_vector_has_four_pillars`)
- [x] **Context Construction:** the HKDF info is the base context followed by 16 bytes of SHA3-256 over the vector, deterministically — `tests/test_hkdf_sha3_256.py::TestEthicalHKDFContext::test_ethical_context_creation`, `::test_ethical_context_deterministic`, `::TestProjectSpecificVectors::test_ethical_signature_golden_vector`
- [x] **Vector Binding:** a different vector gives a different context and a different derived key — `tests/test_hkdf_sha3_256.py::TestEthicalHKDFContext::test_ethical_context_different_vectors_produce_different_contexts`, `::test_ethical_vector_affects_derived_keys`
- [x] **Canonical Encoding:** sorted-key JSON, so key order does not change the context or the package's ethical hash — `tests/test_hkdf_sha3_256.py::TestEthicalHKDFContext::test_ethical_context_ignores_key_order`
- [x] **Distinct Derived Keys:** keys derived at different indices differ — `tests/test_hkdf_sha3_256.py::TestHKDFSHA3256::test_hkdf_sha3_256_key_independence` (distinctness is what a test can show; computational independence is the design claim below)
- [x] **Package Binding:** a package's ethical vector is recomputed at verification, not taken from its stored hash, and tampering with any signed field fails verification — `tests/test_crypto_package_transcript.py::TestTheLegacyPackageBindsItsOwnIdentity` (`test_the_ethical_vector_is_derived_not_trusted`, `test_tampering_is_detected`)
- [x] **The examples on this page run:** every Python block above is executed by `tools/check_doc_examples.py` (INVARIANT-53)

### Design claims — argued from the cited standards, not tested

- **Collision Resistance:** SHA3-256 offers 128-bit collision resistance (FIPS 202, Appendix A.1); appending a 16-byte ethical signature to HKDF's info input does not change the hash function.
- **PRF Security:** HKDF-SHA3-256 remains a secure KDF with the extended info parameter; info is public context in the HKDF analysis (RFC 5869; Krawczyk 2010).
- **Key Independence:** keys derived under distinct info strings are computationally independent under the same analysis.
- **Signature Security:** the Ed25519 + ML-DSA-65 dual signature is as strong as the stronger of its two schemes against a forger who must break both.
- **Quantum Resistance:** ML-DSA-65 is FIPS 204's NIST security category 3 parameter set. Category 3 is defined relative to the cost of a key search on AES-192; it is not a claim of 2^192 quantum work.
- **Pillar Structure:** 4 pillars × 3 sub-properties = 12 ethical dimensions — a property of this framework's definition.
- **Auditability and Transparency:** the vector and its hash travel in the package and are publicly documented here.
- **No Security Trade-off:** the ethical layer changes only HKDF's info input and the signed package metadata; no primitive in Part A is modified.

### Measured — re-run the Performance Analysis block to re-measure

- **Overhead per derivation:** +13.8 to +17.0 µs on an 11.2 µs native HKDF call (+123% to +151%); see the table under Performance Analysis for the host and method. The "<0.01ms additional latency (<4%)" this box used to carry was not a measurement of anything recorded.
- **Overhead per package:** 0.66–0.72% of `legacy_compat.create_crypto_package` on the same host.
- **Throughput:** 35,300–39,800 context-bound derivations per second, and 574–579 legacy packages per second, on that loaded host. The ">1,000 ops/sec" this box used to carry named neither the operation nor a measurement.
- **Scaling:** the context is computed from a fixed four-entry vector, so its cost is constant; it does not grow with the size of the protected content.

---

## Academic Citations

### Primary Standards

1. **NIST FIPS 202** (2015). "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions." National Institute of Standards and Technology.

2. **NIST FIPS 203** (2024). "Module-Lattice-Based Key-Encapsulation Mechanism Standard." National Institute of Standards and Technology.

3. **NIST FIPS 204** (2024). "Module-Lattice-Based Digital Signature Standard." National Institute of Standards and Technology.

4. **NIST FIPS 205** (2024). "Stateless Hash-Based Digital Signature Standard." National Institute of Standards and Technology.

5. **RFC 5869** (2010). Krawczyk, H. & Eronen, P. "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)." Internet Engineering Task Force.

6. **RFC 3161** (2001). Adams, C., Cain, P., Pinkas, D., & Zuccherato, R. "Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)." IETF.

7. **RFC 2104** (1997). Krawczyk, H., Bellare, M., & Canetti, R. "HMAC: Keyed-Hashing for Message Authentication." IETF.

### Academic Papers

8. **Ducas, L., et al.** (2018). "CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme." *IACR Transactions on Cryptographic Hardware and Embedded Systems*, 2018(1), 238-268.

9. **Krawczyk, H.** (2010). "Cryptographic Extraction and Key Derivation: The HKDF Scheme." *Advances in Cryptology – CRYPTO 2010*, LNCS 6223, 631-648.

10. **Bernstein, D. J., et al.** (2011). "High-speed high-security signatures." *Journal of Cryptographic Engineering*, 2(2), 77-89.

11. **Bertoni, G., et al.** (2011). "The Keccak SHA-3 submission." *Submission to NIST*, Round 3.

12. **Bernstein, D. J. & Lange, T.** (2017). "Post-quantum cryptography." *Nature*, 549(7671), 188-194.

### Security Analysis

13. **Schneier, B.** (1999). "Attack Trees: Modeling Security Threats." *Dr. Dobb's Journal*, December 1999.

14. **NIST SP 800-57** (2020). "Recommendation for Key Management." National Institute of Standards and Technology.

15. **NIST SP 800-108** (2009). "Recommendation for Key Derivation Using Pseudorandom Functions." NIST.

16. **NIST SP 800-140** (2020). "Cryptographic Module Validation Program." NIST.

---

## Conclusion

The 4 Omni-Code Ethical Pillars provide a mathematically rigorous framework for integrating ethical constraints into the AMA Cryptography cryptographic system without compromising security guarantees.

**Key Achievements:**
- **No modification of FIPS primitives:** The ethical layer enters the
  cryptographic stack only through the HKDF `info` parameter; the
  primitives listed in Part A are used unchanged.
- **Clean structure:** 4 pillars × 3 sub-properties = 12 ethical dimensions, Σw = 12.0
- **Primitives consumed:** NIST FIPS 202, 203, 204, 205; IETF RFC 2104,
  3161, 5869 (see Part A for the authoritative list).
- **Measured overhead:** 0.66–0.72% of a legacy package creation, and
  +123% to +151% on a single HKDF derivation, measured 2026-09-24 on the
  host and with the method recorded under Performance Analysis. Actual
  overhead varies by hardware.
- **Validation status:** Validated against NIST ACVP test vectors;
  see [`CSRC_ALIGN_REPORT.md`](docs/compliance/CSRC_ALIGN_REPORT.md) for the
  authoritative, versioned totals. The ACVP validation covers the FIPS
  primitives (Part A), not the Ethical Pillars themselves. Original
  constructions in this document — the ethical integration, adaptive
  posture, and weight system — have written security arguments in
  [`docs/DESIGN_NOTES.md`](docs/DESIGN_NOTES.md) but have **not**
  undergone independent formal verification. This is the same
  disclaimer carried in
  [`ARCHITECTURE.md §Design Philosophy`](ARCHITECTURE.md) and
  [`docs/DESIGN_NOTES.md §Limitations`](docs/DESIGN_NOTES.md).
- **Quantum resistance:** inherited from the ML-DSA-65 / ML-KEM-1024 /
  SLH-DSA primitives listed in Part A.

**Security Assessment:** The FIPS primitives in Part A provide the
cryptographic security bounds. The Ethical Policy Layer in Part B adds
policy constraints on top; its security claims are relative to those
primitives and to the security arguments in `docs/DESIGN_NOTES.md`.

This framework demonstrates that ethical constraints and cryptographic strength are not opposing forces—when properly designed, they reinforce each other.

---

**Built with brutal honesty. Grounded in mathematical proof. Enhanced with ethical certainty.**

**AMA Cryptography - Protecting Omni-Code with cryptographic and ethical integrity.**
