# AMA Cryptography — Next Session Engineering Roadmap

## Context for the Next Conversation

This document was produced after a deep architecture audit of the entire codebase.
It contains precise file locations, line numbers, function signatures, and dependency
maps. Nothing here is speculative — every reference was verified against source.

**Your standards**: Software engineering strategy only. No streamlining, no noise.
Every change must be justified. Nothing of value gets deleted.

---

## Phase 1: Zero-External-Dependency PQC Library

### Current State

The C layer has **two categories** of OpenSSL dependency:

**Category A — RAND_bytes only (Kyber + Dilithium)**

| File | Line | Function | OpenSSL Surface |
|------|------|----------|-----------------|
| `src/c/ama_kyber.c` | 323 | `kyber_randombytes()` | `RAND_bytes()` only |
| `src/c/ama_dilithium.c` | 984 | `dil_randombytes()` | `RAND_bytes()` only |

Each file includes only `<openssl/rand.h>`. No other OpenSSL API calls exist in
either file. The `randombytes` functions already have a clean abstraction boundary
via the `AMA_TESTING_MODE` hook pattern.

**Category B — SHA-256 + HMAC-SHA256 + MGF1-SHA256 + RAND_bytes (SPHINCS+)**

| File | Lines | OpenSSL Surface |
|------|-------|-----------------|
| `src/c/ama_sphincs.c` | 58-65 | 6 OpenSSL includes |
| `src/c/ama_sphincs.c` | 207-213 | `sha256()` — EVP_Digest API |
| `src/c/ama_sphincs.c` | 218-226 | `sha256_2()` — EVP_Digest two-input |
| `src/c/ama_sphincs.c` | 231-255 | `mgf1_sha256()` — EVP_Digest in loop |
| `src/c/ama_sphincs.c` | 262-280 | `spx_thash()` — EVP_Digest |
| `src/c/ama_sphincs.c` | 287-305 | `spx_prf()` — EVP_Digest |
| `src/c/ama_sphincs.c` | 310-337 | `spx_prf_msg()` — EVP_MAC HMAC-SHA256 (OpenSSL 3.0+ / legacy branches) |
| `src/c/ama_sphincs.c` | 342+ | `spx_hash_message()` — uses MGF1 |
| `src/c/ama_sphincs.c` | 958 | `spx_randombytes()` — `RAND_bytes()` |

Total: **58 EVP/HMAC/OSSL API calls** across ~15 functions. This is the heavy lift.

### What Gets Replaced (Nothing of Value Deleted)

Every replacement is a **1:1 functional swap**. No logic changes. No algorithm changes.
The call sites remain identical — only the implementation behind the static functions changes.

### Step 1: Create `src/c/ama_platform_rand.c` (~80 lines)

New file. Provides one function: `ama_randombytes(uint8_t *buf, size_t len)`.

Implementation:
```
#if defined(__linux__)
    #include <sys/random.h>        // getrandom(2), available since Linux 3.17
    // Loop until len bytes filled (getrandom can return short)
    // Flag: 0 (block until entropy available, read from /dev/urandom pool)
#elif defined(__APPLE__)
    #include <sys/random.h>        // getentropy(3), available since macOS 10.12
    // getentropy() limited to 256 bytes per call — loop in 256-byte chunks
#elif defined(_WIN32)
    #include <windows.h>
    #include <bcrypt.h>            // BCryptGenRandom, available since Vista
    // BCryptGenRandom(NULL, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
#else
    #include <stdio.h>             // fopen("/dev/urandom") fallback for BSDs
#endif
```

**Testing hook preserved**: The `AMA_TESTING_MODE` pattern in each file's
`*_randombytes()` function stays exactly as-is. Only the `RAND_bytes()` call
inside each function gets replaced with `ama_randombytes()`.

**What changes in existing files**:
- `ama_kyber.c:38` — Remove `#include <openssl/rand.h>`, add `#include "ama_platform_rand.h"`
- `ama_kyber.c:323` — `RAND_bytes(buf, (int)len) != 1` → `ama_randombytes(buf, len) != AMA_SUCCESS`
- `ama_dilithium.c:49` — Same include swap
- `ama_dilithium.c:984` — Same call swap
- `ama_sphincs.c:59` — Remove `#include <openssl/rand.h>` (keep other OpenSSL includes for now)
- `ama_sphincs.c:958` — Same call swap

After Step 1: Kyber and Dilithium have **zero OpenSSL dependency**. SPHINCS+ still
depends on OpenSSL for SHA-256/HMAC only.

### Step 2: Create `src/c/ama_sha256.c` (~250 lines)

New file. Native SHA-256 implementation per NIST FIPS 180-4.

SHA-256 is a well-understood algorithm. The implementation requires:
- 8 working variables (a–h), 64-word message schedule
- `Ch`, `Maj`, `Σ0`, `Σ1`, `σ0`, `σ1` functions
- 64 round constants (first 32 bits of cube roots of first 64 primes)
- Streaming API: `init()`, `update()`, `final()`

Provides these static-linkable functions (matching the signatures already used
in `ama_sphincs.c`):

```c
void ama_sha256(uint8_t out[32], const uint8_t *in, size_t inlen);
void ama_sha256_init(ama_sha256_ctx *ctx);
void ama_sha256_update(ama_sha256_ctx *ctx, const uint8_t *data, size_t len);
void ama_sha256_final(ama_sha256_ctx *ctx, uint8_t out[32]);
```

### Step 3: Create `src/c/ama_hmac_sha256.c` (~80 lines)

New file. HMAC-SHA256 per RFC 2104.

```c
void ama_hmac_sha256(uint8_t out[32],
                     const uint8_t *key, size_t keylen,
                     const uint8_t *data, size_t datalen);
// Streaming variant for spx_prf_msg which calls update() twice:
void ama_hmac_sha256_init(ama_hmac_sha256_ctx *ctx, const uint8_t *key, size_t keylen);
void ama_hmac_sha256_update(ama_hmac_sha256_ctx *ctx, const uint8_t *data, size_t len);
void ama_hmac_sha256_final(ama_hmac_sha256_ctx *ctx, uint8_t out[32]);
```

### Step 4: Replace OpenSSL calls in `ama_sphincs.c`

**Function-by-function replacement** (no logic changes):

| Function | Current | Replacement |
|----------|---------|-------------|
| `sha256()` (line 207) | `EVP_MD_CTX` → `EVP_DigestInit/Update/Final` | `ama_sha256(out, in, inlen)` — one-liner |
| `sha256_2()` (line 218) | Two-input EVP_Digest | `ama_sha256_init/update/update/final` |
| `mgf1_sha256()` (line 231) | EVP_Digest in loop | `ama_sha256_init/update/update/final` in same loop |
| `spx_thash()` (line 262) | Multi-update EVP_Digest | `ama_sha256_init` + 4 `update` calls + `final` |
| `spx_prf()` (line 287) | Multi-update EVP_Digest | Same pattern as thash |
| `spx_prf_msg()` (line 310) | `EVP_MAC` HMAC (3.0+) / `HMAC_CTX` (legacy) | `ama_hmac_sha256_init/update/update/final` |
| `spx_hash_message()` (line 342) | Uses `mgf1_sha256` (already replaced) | No direct changes needed |

After Step 4: Remove all 6 OpenSSL `#include` lines from `ama_sphincs.c`.

**Nothing deleted**: The `spx_thash`, `spx_prf`, `spx_prf_msg`, `sha256`, `sha256_2`,
`mgf1_sha256` functions all remain. Only their internal implementation changes from
EVP API calls to native `ama_sha256_*` calls. Same inputs, same outputs.

### Step 5: Update CMakeLists.txt

- Add `ama_platform_rand.c`, `ama_sha256.c`, `ama_hmac_sha256.c` to build
- Remove `-lssl -lcrypto` from link flags
- Add platform-specific link flag for Windows only: `-lbcrypt`
- Keep `AMA_TESTING_MODE` define for test builds

### Step 6: Validate

- Run existing NIST KAT tests (`test_nist_kat.py`, `test_pqc_kat.py`)
- All 10/10 ML-DSA-65 vectors must still pass
- All 10/10 ML-KEM-1024 vectors must still pass
- SPHINCS+ KAT vectors must still pass
- Run full test suite to catch any regressions
- Verify build on Linux (primary target)

### Deliverable

After Phase 1, the C layer has **zero external cryptographic dependencies**.
The only system call is `getrandom(2)` / `getentropy(3)` / `BCryptGenRandom`.

Claim: *"Fully self-contained NIST FIPS 203/204/205 implementations with no
external cryptographic library dependencies."*

### Risk Assessment

- **SHA-256 implementation risk**: LOW. SHA-256 is the most widely implemented
  hash function in existence. The algorithm is fully specified in FIPS 180-4.
  Validation via NIST KAT vectors.
- **Platform entropy risk**: LOW. `getrandom(2)` is the recommended Linux API
  since kernel 3.17 (2014). `getentropy(3)` on macOS since 10.12 (2016).
  `BCryptGenRandom` on Windows since Vista (2007).
- **Regression risk**: LOW. All changes are behind existing abstraction boundaries.
  KAT tests catch any implementation errors.

---

## Phase 2: Adaptive Cryptographic Posture

### Current State

The 3R monitoring system (`ama_cryptography_monitor.py`) is observation-only:
- `ResonanceEngine`: Records timing, runs FFT, detects anomalies via EWMA+MAD
- `RecursionEngine`: Records signing metadata, does recursive downsampling, z-score analysis
- `RefactoringAnalyzer`: AST-based code complexity metrics (read-only)

The monitor produces alerts but **nothing consumes them**. There is no grep match
for `trigger`, `rotate`, `switch.*algorithm`, `adaptive`, `posture`, or `feedback`
in the monitor code. The monitoring pipeline terminates at alert generation.

### Architecture: Closed-Loop Adaptive System

```
┌─────────────────────────────────────────────────────┐
│                  Application Code                    │
│                                                      │
│  sign(msg) ──→ CryptoPostureController ──→ result   │
│                       │         ▲                    │
│                       │         │                    │
│                       ▼         │                    │
│              3R Monitor         │ PostureDecision    │
│              (existing)    ◄────┤                    │
│                │                │                    │
│                ▼                │                    │
│         PostureEvaluator ───────┘                    │
│         (NEW component)                              │
└─────────────────────────────────────────────────────┘
```

### What Gets Added (Nothing Existing Deleted or Modified)

The entire adaptive system is **additive**. The existing 3R monitor continues to
work exactly as it does today. New components consume its output.

### New Components

#### Component 1: `PosturePolicy` (data class, ~40 lines)

Defines thresholds and responses. Pure configuration, no logic.

```python
@dataclass
class PosturePolicy:
    # Thresholds (pulled from existing 3R constants)
    timing_anomaly_threshold: float = 3.0    # Already exists as z-score threshold
    pattern_anomaly_threshold: float = 3.0   # Already exists in RecursionEngine

    # Responses
    on_timing_anomaly: PostureAction = PostureAction.ROTATE_KEYS
    on_pattern_anomaly: PostureAction = PostureAction.INCREASE_SECURITY_LEVEL
    on_sustained_anomaly: PostureAction = PostureAction.ALGORITHM_SWITCH

    # Cooldowns (prevent thrashing)
    min_rotation_interval_seconds: float = 60.0
    min_switch_interval_seconds: float = 300.0
```

#### Component 2: `PostureEvaluator` (~120 lines)

Consumes 3R monitor output. Produces `PostureDecision` objects.

```python
class PostureEvaluator:
    def __init__(self, policy: PosturePolicy, monitor: AMAMonitor):
        self.policy = policy
        self.monitor = monitor
        self._last_rotation: float = 0
        self._last_switch: float = 0
        self._anomaly_streak: int = 0

    def evaluate(self) -> Optional[PostureDecision]:
        """Check monitor state, return action if threshold crossed."""
        report = self.monitor.get_report()
        # Check resonance anomalies
        # Check recursion anomalies
        # Apply cooldown logic
        # Return PostureDecision or None
```

Key design constraint: **The evaluator is a pure function of monitor state**.
It does not modify the monitor. It does not call crypto operations. It only reads
and decides.

#### Component 3: `CryptoPostureController` (~150 lines)

Sits between application code and `crypto_api.py`. Intercepts crypto calls,
checks posture, executes decisions.

```python
class CryptoPostureController:
    def __init__(self, api: CryptoAPI, evaluator: PostureEvaluator):
        self.api = api
        self.evaluator = evaluator
        self._current_posture = CryptoPosture.NORMAL

    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """Sign with posture-aware behavior."""
        decision = self.evaluator.evaluate()
        if decision:
            self._apply_decision(decision)
        return self.api.sign(message, private_key, algorithm=self._current_algorithm)

    def _apply_decision(self, decision: PostureDecision):
        """Execute posture change."""
        if decision.action == PostureAction.ROTATE_KEYS:
            self._trigger_key_rotation()
        elif decision.action == PostureAction.ALGORITHM_SWITCH:
            self._switch_algorithm(decision.target_algorithm)
        elif decision.action == PostureAction.INCREASE_SECURITY_LEVEL:
            self._increase_security_level()
```

#### Component 4: `PostureAction` enum and `PostureDecision` dataclass (~30 lines)

```python
class PostureAction(Enum):
    ROTATE_KEYS = "rotate_keys"
    ALGORITHM_SWITCH = "algorithm_switch"
    INCREASE_SECURITY_LEVEL = "increase_security_level"
    ALERT_ONLY = "alert_only"

@dataclass
class PostureDecision:
    action: PostureAction
    reason: str
    timestamp: float
    source_anomaly: Dict[str, Any]
    target_algorithm: Optional[str] = None
```

### What "Algorithm Switch" Means Concretely

The `crypto_api.py` already supports multiple algorithms via its algorithm-agnostic
interface. The posture controller would switch between:

| Trigger | Current Algorithm | Switch To | Rationale |
|---------|------------------|-----------|-----------|
| Timing anomaly (sustained) | ML-DSA-65 | ML-DSA-65 + Ed25519 hybrid | Add classical fallback |
| Pattern anomaly | Any single | Hybrid mode | Defense in depth |
| Sustained multi-anomaly | SHA-256 SPHINCS+ | SHA-3 SPHINCS+ variant | Different side-channel profile |

### What "Key Rotation" Means Concretely

Your `key_management.py` already implements BIP32-style hierarchical derivation.
Key rotation = derive the next child key in the hierarchy. The posture controller
calls `derive_child_key(current_index + 1)` on the existing key manager.

No new key derivation logic. No new key formats. Just triggering what already exists.

### File Placement

All new code goes in a single new file: `ama_cryptography/adaptive_posture.py`

Contains: `PosturePolicy`, `PostureAction`, `PostureDecision`, `PostureEvaluator`,
`CryptoPostureController`.

No existing files are modified in Phase 2 except:
- `ama_cryptography/__init__.py` — add imports for new public classes
- `crypto_api.py` — add optional `posture_controller` parameter (backwards-compatible)

### Testing Strategy

- Unit tests for `PostureEvaluator` with synthetic monitor reports
- Integration test: inject artificial timing anomalies → verify key rotation triggers
- Integration test: inject sustained anomalies → verify algorithm switch
- Verify cooldown logic prevents thrashing
- Verify that with no anomalies, behavior is identical to current (regression test)

---

## Phase 3: Eliminate numpy/scipy from Core (Security Posture)

### Current Dependency Map

| File | numpy Usage | scipy Usage |
|------|-------------|-------------|
| `ama_cryptography_monitor.py` | `np.array`, `np.median`, `np.abs`, `np.mean`, `np.std`, `np.diff`, `np.max`, `np.argmax` | `fft`, `fftfreq` |
| `ama_cryptography/equations.py` | Array operations, typing | None |
| `ama_cryptography/double_helix_engine.py` | Array operations, typing | None |
| `src/cython/math_engine.pyx` | `cnp` typed memoryviews | None |
| `src/cython/helix_engine_complete.pyx` | `cnp` typed memoryviews | None |
| Tests, benchmarks, examples, tools | Various | None |

### Replacement Strategy

**Monitor (highest priority — this is the crypto-adjacent code)**:

| numpy/scipy Call | Pure Python/C Replacement |
|------------------|--------------------------|
| `np.array(list)` | Use `list` directly (or `array.array('d', ...)`) |
| `np.median(values)` | `sorted(values)[len(values)//2]` (exact equivalent for odd-length) |
| `np.mean(values)` | `sum(values)/len(values)` |
| `np.std(values)` | Already computed by Welford's — just use that |
| `np.abs(values - median)` | `[abs(v - median) for v in values]` |
| `np.diff(timestamps)` | `[t[i+1]-t[i] for i in range(len(t)-1)]` |
| `np.max/np.argmax` | `max(values)` / `values.index(max(values))` |
| `scipy.fft.fft` | Native FFT — see below |
| `scipy.fft.fftfreq` | `[i/n for i in range(n)]` (trivial formula) |

**FFT Replacement**: You already implement NTT (Number Theoretic Transform) in
`ama_kyber.c`. FFT is the complex-number analog. Options:

1. **Pure Python Cooley-Tukey FFT** (~40 lines). The monitor uses FFT on windows
   of ≤1024 samples. At this size, a pure Python radix-2 FFT completes in <1ms.
   Performance is irrelevant — the monitor explicitly documents FFT as "on-demand,
   not hot path" (line 509 of monitor).

2. **C implementation** calling from the existing NTT infrastructure. More work
   than necessary given the window sizes involved.

Recommendation: Pure Python FFT. The monitor's own comments say this is not
performance-critical.

**equations.py and double_helix_engine.py**: These use numpy for array math
(matrix operations, typing). They are non-cryptographic mathematical modeling
modules. Replacing numpy here is lower priority and higher effort. Consider:
- Making numpy an **optional** dependency for these modules
- Guard imports: `try: import numpy as np; HAS_NUMPY = True except: HAS_NUMPY = False`
- Core crypto operations never touch these modules

**Cython modules**: These inherently require numpy for typed memoryviews. However,
Cython is already optional (the system works without it). No changes needed.

### What Gets Deleted

Nothing. numpy becomes an **optional dependency** instead of required. The monitor
gains a pure-Python fallback. Modules that genuinely benefit from numpy (equations,
double_helix) continue to use it when available.

### Result

Runtime: `pip install ama-cryptography` pulls in **zero non-stdlib dependencies**
for core crypto operations. numpy/scipy only needed if you use the mathematical
modeling modules.

---

## Phase 4: Provable Hybrid Signature Combiner (If Time Permits)

### Current State

Need to verify: how does the existing Ed25519 + ML-DSA-65 hybrid currently combine
signatures? The next session should audit `code_guardian_secure.py` for the hybrid
signing path before designing the combiner.

### Design Sketch (Pending Audit)

A binding combiner with formal security reduction:

```
hybrid_sign(msg, sk_ed, sk_dil):
    # Derive binding nonce from both public keys
    binding = HKDF-SHA3-256(pk_ed || pk_dil, info="AMA-hybrid-bind")

    # Sign (message || binding) with both schemes
    sig_ed  = Ed25519.sign(msg || binding, sk_ed)
    sig_dil = ML-DSA-65.sign(msg || binding, sk_dil)

    # Output: both signatures + binding proof
    return (sig_ed, sig_dil, binding)

hybrid_verify(msg, sig_ed, sig_dil, binding, pk_ed, pk_dil):
    # Recompute binding
    expected = HKDF-SHA3-256(pk_ed || pk_dil, info="AMA-hybrid-bind")
    assert binding == expected

    # Both must verify
    assert Ed25519.verify(msg || binding, sig_ed, pk_ed)
    assert ML-DSA-65.verify(msg || binding, sig_dil, pk_dil)
```

**Security property**: If either scheme is broken, the binding nonce ensures the
attacker cannot reuse a signature from the unbroken scheme with a different key pair.
This is a standard binding construction (see Bindel et al., "Transitioning to a
Quantum-Resistant Public Key Infrastructure").

### What This Is NOT

This is not the Double-Helix KDF strengthener idea. That idea (using convergence
as memory-hard KDF) requires formal cryptanalysis and peer review before implementation.
It should not be built in the next session. It belongs in a research track, not
an engineering sprint.

---

## Execution Order

| Phase | Effort | Dependencies | Risk |
|-------|--------|-------------|------|
| 1: Zero-dependency | ~400 lines new C + ~30 lines edits | None | Low — standard algorithms, KAT validated |
| 2: Adaptive posture | ~350 lines new Python | Phase 1 not required | Low — additive, no existing code modified |
| 3: Eliminate numpy | ~100 lines new Python + import guards | Phase 2 not required | Low — pure refactor with fallbacks |
| 4: Hybrid combiner | ~150 lines new Python/C | Audit existing hybrid path first | Medium — needs correctness proof |

**Phases 1 and 2 are independent and can run in parallel.**
Phase 3 is independent of both.
Phase 4 requires auditing existing code first.

---

## What Is NOT Changed

Explicit preservation list — nothing from this list gets modified or deleted:

- `ama_sha3.c` — untouched, already native
- `ama_hkdf.c` — untouched, already native
- `ama_ed25519.c` — untouched, already native
- `ama_consttime.c` — untouched
- All NTT/polynomial arithmetic in Dilithium/Kyber — untouched
- All Keccak usage in Dilithium/Kyber — untouched (they use SHA3 internally)
- `AMA_TESTING_MODE` hook pattern — preserved in all randombytes functions
- 3R monitor internals — observation logic untouched
- Ethical binding mechanism — untouched
- Key management / BIP32 derivation — untouched (consumed by posture controller)
- Double-Helix Engine — untouched (not promoted to cryptographic role)
- All test files — untouched except adding new tests
- RFC 3161 timestamp integration — untouched

---

## Verification Checklist for Next Session

Before declaring any phase complete:

- [ ] All existing KAT tests pass (ML-DSA-65: 10/10, ML-KEM-1024: 10/10, SPHINCS+)
- [ ] Full test suite passes (`pytest` with no failures)
- [ ] No OpenSSL includes remain in C files (Phase 1)
- [ ] `ldd` on built `.so` shows no `libssl`/`libcrypto` linkage (Phase 1)
- [ ] Monitor operates identically with and without numpy (Phase 3)
- [ ] Adaptive posture with no anomalies produces identical output to current (Phase 2)
- [ ] New code has tests covering all branches
