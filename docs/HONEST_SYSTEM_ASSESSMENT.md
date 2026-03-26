# AMA Cryptography — Honest System Assessment

> Generated 2026-03-26 | Based on repository state, measured benchmarks, and code inspection.
> No aspirational claims. No third-party audit/certification comparisons.

---

## What This System Is

AMA Cryptography is a **post-quantum cryptographic library** — a C + Python hybrid
providing digital signatures, key encapsulation, authenticated encryption, hashing,
and key derivation. It is a standalone crypto toolkit, not an application. Its
primary known consumer is Mercury Agent (an AI agent project by the same author).

---

## What's Actually Implemented (Verified by Code Inspection)

### Codebase Scale

| Component | Lines of Code | Notes |
|-----------|---------------|-------|
| C core (23 source files) | ~9,000 | Substantive implementations, not stubs |
| C SIMD (24 files: AVX2/NEON/SVE2) | ~8,000 | 8 algorithms x 3 architectures |
| Python API | ~11,000 | Full API layer + key management |
| Test suite | ~1,400 test functions | Across 48 test files |
| Total C library | ~17,000 | Zero external crypto dependencies |

### Algorithms With Real C Implementations

| Algorithm | File | Lines | Verified Substance |
|-----------|------|-------|--------------------|
| ML-DSA-65 (Dilithium) | `ama_dilithium.c` | 1,622 | NTT q=8380417, rejection sampling |
| ML-KEM-1024 (Kyber) | `ama_kyber.c` | 1,921 | NTT q=3329, Fujisaki-Okamoto, IND-CCA2 |
| SPHINCS+-SHA2-256f | `ama_sphincs.c` | 1,220 | WOTS+, FORS, hypertree d=17 |
| Ed25519 | `ama_ed25519.c` | 1,166 | Radix 2^51 field arithmetic (fe51.h) |
| SHA3-256 | `ama_sha3.c` | 866 | Keccak-f[1600] sponge |
| Argon2id | `ama_argon2.c` | 768 | Memory-hard password hashing |
| ChaCha20-Poly1305 | `ama_chacha20poly1305.c` | 573 | RFC 8439 AEAD |
| AES-256-GCM | `ama_aes_gcm.c` | 509 | NIST SP 800-38D |
| X25519 | `ama_x25519.c` | 351 | RFC 7748 key exchange |

### Infrastructure That Exists

- CI/CD: 8 GitHub Actions workflows (build, test, fuzzing, dudect, static analysis, security)
- NIST KAT vectors: ML-DSA (FIPS 204), ML-KEM (FIPS 203), SLH-DSA (FIPS 205)
- Dudect constant-time testing framework integrated
- OSS-Fuzz onboarding documentation
- Docker build support
- Benchmark suite with nanosecond-precision measurement

---

## Measured Performance (Actual Data)

From `benchmarks/phase0_baseline_results.json` — raw C library called via Python ctypes:

| Operation | Measured Throughput | Measured Latency (median) |
|-----------|--------------------|--------------------------:|
| SHA3-256 (1KB) | 298K ops/s | 3.4 us |
| SHA3-256 (64B) | 1.16M ops/s | 0.87 us |
| HMAC-SHA3-256 (1KB) | 203K ops/s | 4.9 us |
| HKDF-SHA3-256 | 133K ops/s | 7.5 us |
| Ed25519 keygen | 27K ops/s | 37.1 us |
| Ed25519 sign | 26K ops/s | 38.6 us |
| Ed25519 verify | 13K ops/s | 78.0 us |
| ML-DSA-65 keygen | 8.0K ops/s | 125.8 us |
| ML-DSA-65 sign | 5.2K ops/s | 191.3 us |
| Package create (all layers) | 4.4K ops/s | 224.7 us |
| Package verify (all layers) | 4.8K ops/s | 209.6 us |

### Benchmark Data Inconsistency (Flagged)

ML-DSA-65 verify has three conflicting numbers in the repository:

| Source | Value |
|--------|-------|
| `phase0_baseline_results.json` | 1,581,028 ops/s (0.63 us) |
| `baseline.json` (CI) | 530 ops/s |
| `README.md` | 8,859 ops/s (0.11 ms) |

The 1.58M ops/s figure is **physically implausible** — it would mean ML-DSA-65 verify
is faster than SHA3-256 hashing of 1KB. This likely indicates the benchmark is
measuring a cached/short-circuited path, not actual Dilithium verification. The
README figure of ~8.9K ops/s is the most plausible, but should be independently
verified.

---

## Comparison to Similar Products (Capabilities Only)

### Closest Competitors

#### 1. libsodium — Better for classical cryptography

| Dimension | libsodium | AMA Cryptography |
|-----------|-----------|------------------|
| Ed25519 sign throughput | ~50K+ ops/s | ~26K ops/s |
| Ed25519 verify throughput | ~20K+ ops/s | ~13K ops/s |
| ChaCha20-Poly1305 | Highly optimized | Implemented, less optimized |
| Production deployments | Signal, WireGuard, age, 1Password | Mercury Agent |
| PQC algorithms | None | ML-DSA-65, ML-KEM-1024, SPHINCS+ |
| SHA3 family | None | Full (SHA3-256, HMAC-SHA3, HKDF-SHA3) |
| Language bindings | 40+ languages | Python only |
| Codebase size | ~30K LOC (smaller attack surface) | ~28K LOC (C + SIMD) |

**Verdict:** libsodium is faster and more battle-tested for classical crypto. AMA's
advantage is PQC and SHA3 — areas libsodium doesn't cover at all.

#### 2. OpenSSL 3.x — Better as a general-purpose crypto library

| Dimension | OpenSSL | AMA Cryptography |
|-----------|---------|------------------|
| Algorithm catalog | ~100+ | 12 |
| AES-GCM performance | Best-in-class (AES-NI) | Implemented (AES-NI supported) |
| PQC support | Via oqs-provider plugin (3.4+) | Native, integrated |
| TLS support | Full | None |
| SHA3-based HMAC/HKDF | Not native | Native |
| Argon2 | No | Yes |
| External dependencies | Some | Zero |
| Codebase | ~500K LOC | ~28K LOC |

**Verdict:** OpenSSL has vastly broader functionality and ecosystem. AMA is simpler,
has native PQC, and uses SHA3 throughout. For anything involving TLS or broad protocol
support, OpenSSL wins decisively.

#### 3. liboqs (Open Quantum Safe) — Better for pure PQC research

| Dimension | liboqs | AMA Cryptography |
|-----------|--------|------------------|
| PQC algorithm count | 20+ (all NIST candidates) | 3 (winners only) |
| Classical crypto | None (requires pairing) | Full stack |
| SIMD optimization | Minimal | Hand-written for 8 algorithms |
| OpenSSL integration | Via oqs-provider | None |
| OpenSSH integration | Via OQS-SSH | None |
| Standalone usability | Requires OpenSSL/libsodium | Fully standalone |

**Verdict:** liboqs has broader PQC coverage and ecosystem integration. AMA is
standalone and includes classical crypto. For PQC-only needs, liboqs is more
comprehensive. For an all-in-one package, AMA has the edge.

#### 4. AWS-LC — Better for production deployment

| Dimension | AWS-LC | AMA Cryptography |
|-----------|--------|------------------|
| ML-KEM-1024 | Yes | Yes |
| ML-DSA-65 | No (as of 2026-Q1) | Yes |
| SPHINCS+ | No | Yes |
| SHA3 | No | Yes |
| Memory safety | Rust components | C only |
| Production use | AWS infrastructure | No known production use |

**Verdict:** AWS-LC is production-hardened with formal validation. AMA has broader
PQC algorithm coverage but lacks production deployment evidence.

---

## What AMA Does That No Single Competitor Does

These are factual, verifiable from the codebase:

1. **All three NIST PQC winners + classical crypto in one zero-dependency C library** — no other single library does this
2. **SIMD source files for 8 algorithms across 3 architectures** — the files exist; performance impact is not demonstrated in benchmarks
3. **4-layer defense composition** (SHA3 + HMAC + Ed25519 + ML-DSA-65) — novel architecture, unproven in production
4. **Python API with native C backend** for PQC — liboqs-python exists but requires liboqs as a dependency
5. **Adaptive security posture** — runtime algorithm escalation; novel, unproven
6. **3R monitoring framework** — runtime anomaly detection for crypto operations; novel, unproven

---

## What AMA Lacks vs. Every Major Competitor

1. **No independent security audit** — every major competitor (libsodium, OpenSSL, AWS-LC) has been professionally audited
2. **No production deployment track record** — the library has no known users beyond Mercury Agent
3. **Single maintainer** — bus factor of 1
4. **Classical crypto performance gap** — Ed25519 is ~50% slower than libsodium's measured throughput
5. **No TLS or protocol-level support** — it's algorithms only, no handshake/session/transport layer
6. **No language bindings beyond Python** — libsodium has 40+, OpenSSL has dozens

---

## Overstated Claims in Repository Documentation

The `docs/COMPETITIVE_ANALYSIS.md` file contains several claims that overstate AMA's position:

| Claim | Reality |
|-------|---------|
| "within 10-15% of best-in-class" for classical ops | Ed25519 is ~50% slower than libsodium |
| "SVE2 SIMD paths for all 8 algorithm families" | Files exist but no SVE2 benchmark data demonstrates gains |
| "8 algorithms with SIMD on 3 architectures" | SIMD source files exist; only x86 benchmarks available, run on CI shared runners without AVX2 verification |
| Performance table shows AMA Ed25519 at ~45us | Phase0 baseline measures 39us, but libsodium estimate of ~42us is too conservative (real libsodium is ~20us) |
| ML-DSA-65 verify "~0.5ms" vs liboqs "~0.6ms" | AMA's own data shows 0.63us to 0.11ms to 1.89ms depending on which file you read — inconsistent |

---

## Summary

AMA Cryptography is a **genuinely substantive** cryptographic library with real,
non-trivial C implementations of 12 algorithms. The breadth of coverage in a single
zero-dependency package is legitimately unique.

However, for any **specific** use case today:
- **Classical crypto** → libsodium is faster and battle-tested
- **PQC research** → liboqs has broader coverage and ecosystem
- **General-purpose crypto** → OpenSSL has vastly more functionality
- **Production deployment** → AWS-LC has formal validation and proven infrastructure use

AMA's niche is: "I want PQC + classical + SHA3 + Python API in one package with no
dependencies." That niche is real but narrow, and the library's value will increase
significantly if it obtains an independent audit and demonstrates consistent,
reproducible benchmark numbers.
