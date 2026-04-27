# AMA Cryptography: Competitive Analysis

> Generated 2026-04-20 | Covers AMA Cryptography post-Phase 3 (SIMD + PQC)

## Executive Summary

AMA Cryptography occupies a unique position in the cryptographic landscape: it is
the only open-source framework that ships **post-quantum signatures (ML-DSA-65,
ML-KEM-1024, SLH-DSA-256f), classical Ed25519, HMAC-SHA3-256, HKDF-SHA3-256,
AES-256-GCM, ChaCha20-Poly1305, and Argon2id** in a single, zero-dependency
native C library with hand-written **AVX2, NEON, and SVE2** SIMD paths and a
Python API layer.

No competing library offers the same combination of:

1. Full NIST PQC compliance (FIPS 203, 204, 205)
2. 4-layer defense architecture (signatures + HMAC + timestamps + HKDF)
3. Hand-optimized SIMD for 8 algorithms across 3 architectures
4. Runtime CPU dispatch (AVX-512 > AVX2 > generic; SVE2 > NEON > generic)
5. FIPS 140-3 self-test and integrity verification at startup
6. Adaptive security posture with threat-based algorithm escalation
7. Ethical constraint binding via HKDF context

---

## Detailed Comparison Matrix

| Feature | AMA Cryptography | libsodium 1.0.20 | OpenSSL 3.3 | liboqs 0.10 | Bouncy Castle 1.78 | AWS-LC 1.24 |
|---|---|---|---|---|---|---|
| **License** | Apache-2.0 | ISC | Apache-2.0 | MIT | MIT | Apache-2.0 |
| **Language** | C + Python | C | C | C | Java/C# | C |
| **ML-DSA-65 (Dilithium)** | Native | No | Provider (3.4+) | Yes | Yes | No |
| **ML-KEM-1024 (Kyber)** | Native | No | Provider (3.4+) | Yes | Yes | Yes |
| **SLH-DSA (SPHINCS+)** | Native | No | No | Yes | No | No |
| **Ed25519** | Native | Yes | Yes | No | Yes | Yes |
| **X25519** | Native | Yes | Yes | No | Yes | Yes |
| **AES-256-GCM** | Native (AES-NI) | AES-256-GCM | Yes (AES-NI) | No | Yes | Yes (AES-NI) |
| **ChaCha20-Poly1305** | Native | Yes | Yes | No | Yes | Yes |
| **SHA3-256 (Keccak)** | Native | No | Yes | Partial | Yes | No |
| **HMAC-SHA3-256** | Native (RFC 2104) | No | Yes | No | Yes | No |
| **HKDF-SHA3-256** | Native (RFC 5869) | HKDF-SHA256 | HKDF-SHA256 | No | Yes | HKDF-SHA256 |
| **Argon2id** | Native | argon2id | No | No | Argon2 | No |
| **AVX2 SIMD** | 8 algorithms | ChaCha20, Ed25519 | AES-GCM, SHA | No | No | AES-GCM, SHA |
| **NEON SIMD** | 8 algorithms | ChaCha20, Ed25519 | AES, SHA | No | No | AES, SHA |
| **SVE2 SIMD** | 8 algorithms | No | No | No | No | No |
| **Runtime dispatch** | Yes (cpuid) | Yes | Yes | No | N/A | Yes |
| **Constant-time** | Yes (dudect) | Yes | Partial | Partial | No | Yes |
| **FIPS 140-3 self-test** | Yes | No | Yes (module) | No | FIPS mode | Yes |
| **Zero ext. dependencies** | Yes | Yes | Depends | Depends | JVM | Depends |
| **Hybrid PQC+Classical** | Yes (combiner) | No | No | Yes | No | No |
| **RFC 3161 timestamps** | Yes | No | Yes (CMS) | No | Yes | No |
| **Adaptive posture** | Yes | No | No | No | No | No |
| **Python API** | Native | PyNaCl | pyOpenSSL | liboqs-python | No | No |

---

## Per-Competitor Deep Dive

### 1. libsodium (NaCl)

**Strengths**: Industry standard for misuse-resistant crypto. Excellent
constant-time guarantees. Small, audited codebase (~30 KLOC). Ships
XChaCha20-Poly1305, Ed25519, X25519, Argon2id, AEGIS-256 out of the box.
Widely deployed (Signal, Wireguard, age).

**Weaknesses**: No post-quantum algorithms. No SHA-3 family. No AES-GCM
(by design). No HKDF-SHA3. No hybrid PQC combiner. SIMD is limited to
Ed25519 and ChaCha20 (no Argon2, no SHA3, no NTT vectorization).

**AMA Cryptography advantage**: Full PQC suite, SHA3-256 throughout, 8-algorithm
SIMD vs 2-algorithm, adaptive posture, 4-layer defense, RFC 3161 timestamping.

**libsodium advantage**: Battle-tested in production for 10+ years. Smaller
attack surface. AEGIS-256 (faster than AES-GCM). More language bindings.

---

### 2. OpenSSL 3.3

**Strengths**: De facto TLS/crypto standard. Massive algorithm catalog.
FIPS 140-2/3 validated module. Excellent AES-NI and SHA-NI acceleration.
Used by >60% of web servers. Provider architecture allows PQC plugins
(oqs-provider for ML-DSA/ML-KEM in 3.4+).

**Weaknesses**: Enormous codebase (~500 KLOC), high CVE rate, complex API,
PQC only available via third-party providers. No SHA3-based HMAC/HKDF
natively. No Argon2. No adaptive security posture. No SVE2 SIMD paths.
No ethical constraint binding.

**AMA Cryptography advantage**: SHA3-256 as default hash (vs SHA-256),
integrated PQC (not a plugin), Argon2id, ethical HKDF context,
SVE2 SIMD paths, smaller attack surface, zero external dependencies.

**OpenSSL advantage**: FIPS 140-3 certificate (not just self-test), TLS support,
massive ecosystem, 25+ years of auditing, hardware security module integration.

---

### 3. liboqs (Open Quantum Safe)

**Strengths**: Reference PQC implementation library. Supports all NIST
PQC winners + candidates. Clean C99 codebase. Integration with OpenSSL
(oqs-provider) and OpenSSH (OQS-SSH). Active NIST tracking.

**Weaknesses**: No classical crypto (no Ed25519, AES-GCM, ChaCha20, Argon2).
No SIMD optimizations for most algorithms. No HMAC, HKDF, or key derivation.
Not designed for standalone use — requires pairing with OpenSSL or libsodium.
No constant-time verification (dudect). No runtime dispatch.

**AMA Cryptography advantage**: Complete standalone stack (PQC + classical),
hand-written SIMD for all PQC algorithms, runtime dispatch, FIPS self-test,
4-layer defense architecture, Python API.

**liboqs advantage**: Broader PQC algorithm coverage (HQC, BIKE, FrodoKEM
candidates), deeper integration with OQS ecosystem, focused PQC research.

---

### 4. Bouncy Castle (Java/C#)

**Strengths**: Comprehensive Java/C# crypto library. Supports ML-DSA, ML-KEM,
SPHINCS+, Ed25519, AES, ChaCha20, Argon2, HKDF. FIPS-certified configuration.
Mature (~20 years).

**Weaknesses**: JVM/CLR overhead (no native SIMD). Performance 5-50x slower
than C for NTT operations. No constant-time guarantees (JVM JIT unpredictable).
No Python support. No adaptive posture. Large JAR size.

**AMA Cryptography advantage**: Native C performance with SIMD (10-50x faster
for PQC operations), constant-time guarantees, Python API, smaller footprint,
adaptive posture.

**Bouncy Castle advantage**: Broader algorithm catalog, enterprise Java ecosystem,
ASN.1/CMS/PKCS support, longer track record.

---

### 5. AWS-LC (AWS libcrypto)

**Strengths**: Google BoringSSL fork maintained by AWS. FIPS 140-3 validated.
ML-KEM-1024 support. Excellent AES-NI acceleration. Memory-safe Rust components.
Used in AWS SDK, s2n-tls.

**Weaknesses**: No ML-DSA yet (as of 2026-Q1). No SPHINCS+. No SHA3 family
(uses SHA-256 throughout). No Argon2. No Python API. No adaptive posture.
AWS-centric ecosystem.

**AMA Cryptography advantage**: Full PQC suite (ML-DSA + SPHINCS+ + ML-KEM),
SHA3-256 default, Argon2id, Python API, SVE2 SIMD, adaptive posture,
ethical constraint binding.

**AWS-LC advantage**: FIPS 140-3 certificate, Rust memory safety, AWS ecosystem
integration, battle-tested in AWS infrastructure.

---

## SIMD Coverage Comparison

| Algorithm | AMA (AVX2) | AMA (NEON) | AMA (SVE2) | libsodium | OpenSSL | AWS-LC |
|---|---|---|---|---|---|---|
| ML-KEM NTT | Vectorized | Vectorized | Vectorized | N/A | N/A | Partial |
| ML-DSA NTT | Vectorized | Vectorized | Vectorized | N/A | N/A | N/A |
| SPHINCS+ tree | 4-way parallel | 4-way parallel | Scalable | N/A | N/A | N/A |
| SHA3 Keccak | Lane-parallel | Lane-parallel | Scalable | N/A | Yes | N/A |
| AES-GCM | 8-block pipeline | Crypto ext. | Crypto ext. | N/A | Yes | Yes |
| Ed25519 fe51 | Vectorized | Vectorized | Vectorized | Yes | Yes | Yes |
| ChaCha20 | 8-way parallel | 4-way parallel | Scalable | Yes | Yes | Yes |
| Poly1305 | Vectorized | Vectorized | Scalable | Yes | Yes | Yes |
| Argon2 Blake2b | Vectorized | Vectorized | Scalable | Partial | N/A | N/A |

**Key insight**: AMA Cryptography is the only library with SIMD coverage across
all 8 algorithm families on all 3 architectures (x86-64, AArch64, ARMv9).

---

## Unique Differentiators

### 1. 4-Layer Defense Architecture
No competitor implements a multi-layer verification pipeline:
- **Layer 1**: SHA3-256 content integrity (NIST FIPS 202)
- **Layer 2**: HMAC-SHA3-256 keyed authentication (RFC 2104)
- **Layer 3**: Hybrid Ed25519 + ML-DSA-65 digital signatures (RFC 8032 + NIST FIPS 204)
- **Layer 4**: HKDF-SHA3-256 key derivation verification (RFC 5869)

### 2. Adaptive Security Posture
AMA Cryptography dynamically escalates cryptographic strength based on threat
telemetry (via the 3R monitoring system). No other library adjusts algorithm
selection at runtime in response to detected anomalies.

### 3. Ethical Constraint Binding
HKDF key derivation contexts include ethical pillar weights, cryptographically
binding derived keys to governance constraints. This is novel in the field.

### 4. SHA3-256 as Default
While most libraries default to SHA-256, AMA Cryptography uses SHA3-256
(Keccak) throughout, providing resistance against length-extension attacks
and future-proofing against potential SHA-2 weaknesses.

### 5. SVE2 SIMD (Scalable Vector Extension 2)
AMA Cryptography is the first open-source crypto library to ship SVE2-optimized
paths for all 8 algorithm families, preparing for ARMv9 server adoption
(AWS Graviton4, Ampere Altra Max, etc.).

---

## Performance Positioning

### Performance Comparison (measured)

> **CI environmental context.** The throughput numbers published below
> are measured on a Linux x86-64 host that advertises **AES-NI +
> PCLMULQDQ + AVX2 + VAES + VPCLMULQDQ + AVX-512F/BW/DQ/VL/VBMI** all
> the way through to userland (no hypervisor masking). GitHub Actions
> shared runners frequently mask one or more of these features at the
> hypervisor layer — most often AVX-512 and VAES, occasionally even
> AES-NI + PCLMULQDQ on lower-tier hosts — so AMA's runtime dispatcher
> falls back to the generic-C scalar path. Concretely, the dispatcher
> consults `ama_has_aes_ni()`, `ama_has_pclmulqdq()`,
> `ama_cpuid_has_vaes_aesgcm()`, `ama_cpuid_has_avx2()`,
> `ama_cpuid_has_avx512_keccak()` (XCR0-aware AVX-512F/BW/DQ/VL gate),
> and `ama_cpuid_has_x25519_mulx()` (BMI2 + ADX gate for the X25519
> fe64 MULX+ADX kernel) before promoting an algorithm slot to a SIMD
> or hand-tuned-GPR kernel. When any of those return 0 the slot stays
> on the pure-C reference path. **Users who benchmark in cloud
> CI will therefore see numbers ~1.5–2× slower than the table for
> AES-GCM, ChaCha20-Poly1305, X25519, and ML-KEM-1024 keygen.** This
> is environmental, not a code regression. Verify which paths the
> dispatcher actually selected on your hardware by re-running with
> `AMA_DISPATCH_VERBOSE=1`; the printout names every promoted slot
> and the CPUID gate that allowed (or didn't allow) it. For
> reproducible peer comparison on cloud CI, expect the generic-C
> band, not the canonical-host band.

The table below combines (a) AMA's measured ops/sec from
`benchmark-results.json` (Linux x86-64 canonical-host run with the
SIMD gates listed above advertised) with (b) peer-library numbers.
Peer numbers are marked **(measured)** when
`benchmarks/comparative_benchmark.py` captured them in the same
environment and **(ref)** when they come from published reference
ranges in `benchmarks/baseline.json::metadata.peer_references`
(citations live there). Where a library does not ship the primitive,
the cell reads **N/A**.

| Primitive | AMA (measured) | libsodium | liboqs | OpenSSL | Verdict |
|---|---:|---:|---:|---:|---|
| SHA3-256 hash (1KB) | 184,112 ops/s | N/A | N/A | varies | AMA competitive |
| HMAC-SHA3-256 (1KB) | 115,408 ops/s | N/A | N/A | varies | AMA competitive |
| Ed25519 KeyGen | 55,716 ops/s | 40,000–60,000 ops/s (ref) | N/A | varies | inside libsodium reference band (base-point comb table) |
| Ed25519 Sign | 51,488 ops/s | 50,000–80,000 ops/s (ref) | N/A | ~20,000 ops/s (ref) | within libsodium band; OpenSSL ~2.5× slower |
| Ed25519 Verify | 21,338 ops/s | 15,000–30,000 ops/s (ref) | N/A | ~10,000 ops/s (ref) | within libsodium reference band (vartime, AVX2 SWE rectified) |
| HKDF-SHA3-256 (3 keys) | 81,703 ops/s | HKDF-SHA256 only | N/A | HKDF-SHA256 only | Different hash — not directly comparable |
| ML-DSA-65 KeyGen | 3,874 ops/s | N/A | 2,000–5,000 ops/s (ref) | Provider 3.4+ (ref) | inside liboqs reference band |
| ML-DSA-65 Sign | 4,312 ops/s | N/A | 500–1,500 ops/s (ref) | Provider 3.4+ (ref) | ~3× faster than the liboqs reference band |
| ML-DSA-65 Verify | 7,413 ops/s | N/A | 4,000–9,000 ops/s (ref) | Provider 3.4+ (ref) | inside liboqs band |
| ML-KEM-1024 KeyGen | 5,999 ops/s | N/A | 8,000–18,000 ops/s (ref) | Provider 3.4+ (ref) | trails liboqs ~2× on this canonical-host runtime-dispatch measurement |
| ML-KEM-1024 Encap | 12,365 ops/s | N/A | 7,000–15,000 ops/s (ref) | Provider 3.4+ (ref) | inside liboqs band |
| AES-256-GCM (1KB) | 293,143 ops/s | N/A (XChaCha preferred) | N/A | ~500K ops/s (AES-NI, ref) | OpenSSL AES-NI path ~1.7× faster (VAES YMM landed; gap closes at ≥4 KB) |
| ChaCha20-Poly1305 (1KB) | 256,249 ops/s | ~380,000 ops/s (ref) | N/A | ~300,000 ops/s (ref) | libsodium ~1.5× faster |
| X25519 scalar mult (fe64 + MULX+ADX) | 15,401 ops/s | ~40,000 ops/s (ref) | N/A | ~35,000 ops/s (ref) | libsodium ~2.6× faster on this canonical-host VM (number from `benchmarks/benchmark_runner.py` Python-via-ctypes harness; the raw-C `build/bin/benchmark_c_raw` harness measures ~16,983 ops/s on the same host — the gap is per-call FFI overhead, not field-arithmetic difference). The in-house kernel is hand-written GCC inline assembly — explicit ADCX (CF chain) + ADOX (OF chain) for dual-carry-chain interleave, plus a dedicated squaring kernel exploiting off-diagonal symmetry (10 mults vs 16 schoolbook) — running behind the `ama_cpuid_has_x25519_mulx()` gate. fe51 fallback measures ~21,800 ops/s on the same host (`-DAMA_X25519_FORCE_FE51`); pure-C fe64 (BMI2/ADX masked, e.g. `taskset` to a guest with the bits hidden) measures ~11,500 ops/s. The literature-reported 1.8-2.2× over pure-C schoolbook (OpenSSL `crypto/ec/asm/x25519-x86_64.pl`, BoringSSL fiat-crypto MULX/ADX) shows up on uncontended Skylake+/Zen+ silicon — the dispatcher lights this kernel up automatically wherever BMI2+ADX are reported, so heavier-iron hosts reach the upper end without further code changes. |

**Reproducing live peer numbers locally:**

```bash
# Option A (preferred) — install via the pyproject extra:
pip install ".[benchmark]"

# Option B — install from the standalone benchmark-only requirements file
# (equivalent, and useful when the repo is checked out without the
# project's build backend):
pip install -r benchmarks/requirements-bench.txt

python benchmarks/comparative_benchmark.py
```

The `benchmark` extra and `benchmarks/requirements-bench.txt` pin the same
three packages (`pynacl`, `liboqs-python`, `cryptography`) and are kept in
sync. Neither is a production dependency — INVARIANT-1 ("zero external
crypto dependencies") applies only to the core library surface.

This writes `benchmarks/comparative_benchmark_results.json` with a
`comparisons` object that has a per-operation `verdict` string of the
form "libsodium Ed25519 sign: 6.3× faster than AMA" — i.e. the same
ratio that appears in the table, but measured on your hardware.

**Key takeaways:**
- Classical Ed25519 trails libsodium by ~3–6× because libsodium ships
  a precomputed base-point table and hand-tuned `ref10` assembly, while
  AMA uses a radix-2^51 field layout (`fe51.h`) without a comparable
  table in the generic-C path. Narrowing this gap is an active
  development priority — see `docs/BENCHMARK_HISTORY.md`.
- PQC performance (ML-DSA-65, ML-KEM-1024) is **inside the liboqs
  reference band**. ML-DSA-65 sign in particular is rejection-sampled
  and its measured throughput has ~2× variance across runs even within
  the same library; the band reflects this.
- AES-256-GCM and ChaCha20-Poly1305 are competitive on generic C paths
  and will gain further speedups when AMA's AES-NI and AVX2 SIMD paths
  are enabled in CI (current CI numbers are from the generic fallback).

**Methodology.** AMA numbers are from `benchmark-results.json` (most
recent GitHub Actions run). Peer numbers come from (a) live measurements
via `benchmarks/comparative_benchmark.py` when the peer library was
installed, or (b) published reference figures from libsodium
documentation, SUPERCOP bench-amd64, and the Open Quantum Safe
benchmarking page. Sources are cited in
`benchmarks/baseline.json::metadata.peer_references`.

---

## Risk Assessment

| Risk | Severity | Mitigation |
|---|---|---|
| No formal FIPS 140-3 certificate | High | Self-test + dudect validation; pursue CMVP certification |
| Newer codebase (less battle-tested) | Medium | Comprehensive test suite (1415+ tests), KAT vectors, fuzzing |
| Ed25519 implementation differs from RFC 8032 vectors | Medium | Sign/verify roundtrip verified; investigate scalar clamping |
| SVE2 requires GCC 12+ (not available on all platforms) | Low | Graceful fallback to NEON on AArch64 |
| Single maintainer risk | Medium | Open-source (Apache-2.0), documented architecture |

---

## Conclusion

AMA Cryptography is the most **comprehensive** single-library cryptographic
framework available, combining post-quantum and classical algorithms with
SIMD optimization, adaptive security, and ethical governance — all in a
zero-dependency package. While individual competitors may outperform AMA
in specific niches (libsodium for misuse resistance, OpenSSL for ecosystem
breadth, liboqs for PQC algorithm count), no single library matches AMA's
breadth of coverage with hand-optimized performance across all three major
CPU architectures.

The primary areas for improvement are: obtaining formal FIPS 140-3 CMVP
certification, expanding the audit trail, and growing the contributor base
to reduce single-maintainer risk.
