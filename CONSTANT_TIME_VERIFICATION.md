# Constant-Time Verification Guide

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 4.0.0 |
| Last Updated | 2026-08-01 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

This document describes the constant-time verification methodology and tooling for AMA Cryptography's cryptographic implementations.

## Overview

Constant-time implementations are critical for preventing timing side-channel attacks. AMA Cryptography employs a defense-in-depth approach to constant-time security:

1. **C Layer**: Custom constant-time utilities in `src/c/ama_consttime.c` (C11 atomics for thread safety)
2. **Python Layer**: `secure_memory.constant_time_compare()`, which calls AMA's
   own `ama_consttime_memcmp` through ctypes (INVARIANT-1: no third-party
   crypto) and **raises `RuntimeError` when that backend is unavailable**
   rather than substituting anything. It previously fell back to a padded
   pure-Python XOR accumulator, described here as constant-time. INVARIANT-7
   names that substitution as unacceptable for a secret-dependent operation,
   and INVARIANT-12 counts "pre-verification MAC/tag comparisons" as exactly
   that — the callers are HMAC tag verification and pinned-key comparison. The
   loop was not constant-time in fact either, only in shape: `ljust`
   allocates, `zip` builds tuples, and `|=` runs CPython's integer path with
   its small-int cache. A fallback documented as constant-time and not being
   so is worse than none, because callers stop asking.
3. **Native PQC Layer**: All PQC implementations (ML-DSA-65, ML-KEM-1024, SLH-DSA) use constant-time primitives internally
4. **Ed25519 Layer**: on the portable fe51 backend, dedicated `fe25519_sq()`
   field squaring and C11 `_Atomic` initialization guards; on x86-64 the
   vendored ed25519-donna backend is built instead (see "Native Ed25519")

## Constant-Time Implementations

### C Utilities (`src/c/ama_consttime.c`)

All 5 constant-time functions are implemented and verified:

| Function | Purpose | Implementation | dudect Verified |
|----------|---------|----------------|-----------------|
| `ama_consttime_memcmp()` | Byte array comparison | XOR accumulation without early exit | Yes |
| `ama_secure_memzero()` | Secure memory clearing | Volatile pointer to prevent optimization | Yes |
| `ama_consttime_swap()` | Conditional buffer swap | Bitwise masking based on condition | Yes |
| `ama_consttime_lookup()` | Table lookup | Full table scan with conditional copy | Yes |
| `ama_consttime_copy()` | Conditional copy | Bitwise masking based on condition | Yes |

### Python Utilities (`ama_cryptography/secure_memory.py`)

Every secret comparison in the Python layer goes through
`constant_time_compare()`, which calls AMA's own C primitive:

```python
def constant_time_compare(a: bytes, b: bytes) -> bool:
    # Primary: ama_consttime_memcmp from the native library.
    # Both operands are padded to the same length first, so the number of
    # bytes compared does not depend on either length, and the length
    # difference is folded into the result rather than short-circuited.
    ...
    # Fallback (no native library): a pure-Python XOR accumulator over the
    # padded inputs, which likewise never short-circuits.
```

> **Correction (2026-08-01).** Through 4.0.0 this section stated that the
> Python layer used `hmac.compare_digest()`, showed an `hmac_verify()` body
> calling it, and located that function in `crypto_api.py`. None of it was
> accurate, and it was never accurate — `git log -S compare_digest -- '*.py'`
> is empty across the whole history, and `crypto_api` has no `hmac_verify`.
> The behaviour described was equivalent in effect, so nothing was weaker
> than advertised; but a reader auditing the constant-time posture would have
> gone looking for a function that does not exist, and would not have audited
> the code that does. Verified after correcting: a live tripwire on
> `hmac.compare_digest` records zero calls during real verification, while
> `ama_consttime_memcmp` records two; and 3,000 randomised comparisons
> (lengths 0-40, equal and unequal, native and forced-fallback paths) agree
> with `==` and with each other in every case.

## Verification Methodology

### dudect-Style Timing Analysis

We provide a dudect-style timing analysis harness based on the methodology from:

> Reparaz, O., Balasch, J., & Verbauwhede, I. (2017).
> "Dude, is my code constant time?"
> https://eprint.iacr.org/2016/1123.pdf

The harness uses Welch's t-test to compare execution times between two input classes. A t-value with |t| < 4.5 after 10^6 measurements suggests no detectable timing leakage at the 99.999% confidence level.

### Running the Verification

#### Quick Test (100K iterations)

```bash
cd tools/constant_time
make
make test
```

#### Full Test (1M iterations, recommended)

```bash
cd tools/constant_time
make
make test-full
```

#### Manual Execution

```bash
cd tools/constant_time
make
./dudect_harness 1000000
```

### Expected Output

```
=======================================================
dudect-style Constant-Time Verification Harness
AMA Cryptography Cryptographic Library
=======================================================

Methodology: Welch's t-test on execution times
Threshold: |t| < 4.5 (99.999% confidence)
Iterations: 1000000 per test

Testing ama_consttime_memcmp (1000000 iterations)...
Testing ama_consttime_swap (1000000 iterations)...
Testing ama_secure_memzero (1000000 iterations)...

=======================================================
Results Summary
=======================================================
  ama_consttime_memcmp: t = 0.1234 [PASS - no leakage detected]
  ama_consttime_swap  : t = -0.5678 [PASS - no leakage detected]
  ama_secure_memzero  : t = 0.0912 [PASS - no leakage detected]

Overall: PASS - No timing leakage detected
=======================================================
```

### Interpreting Results

| t-value | Interpretation |
|---------|----------------|
| |t| < 4.5 | No detectable timing leakage (PASS) |
| 4.5 <= |t| < 10 | Potential leakage, investigate further |
| |t| >= 10 | Strong evidence of timing leakage (FAIL) |

**Note**: Environmental factors such as CPU frequency scaling, interrupts, and cache effects can cause false positives. Run the test multiple times and consider disabling CPU frequency scaling for more accurate results.

### Harness Setup-Symmetry Discipline

Two lanes in `tests/c/test_dudect.c` (`test_consttime_memcmp` and
`test_frost_scalar_negate_midrange`) were hardened in v3.2.0 against a
false-positive class identified on noisy CI runners.  The underlying
primitives (`ama_consttime_memcmp` and FROST `scalar_negate`) are
byte-by-byte branchless in source, but the harnesses fed them inputs
through asymmetric setup paths — class 1 in `test_consttime_memcmp`
made an extra `rand()` call and one extra branch-conditional write
before the timer started, and `test_frost_scalar_negate_midrange`
served class-0 inputs from a stack array while class-1 came from
`.rodata`.  The pre-timer asymmetries (branch-predictor state, cache
line provenance, libc call frequency) bled into the timed window and
surfaced as ~+12σ and ~−6σ false-positive readings respectively.

The post-fix pattern, codified at the top of each lane in
`tests/c/test_dudect.c`:

1. Perform identical setup work for both classes (same `rand()`
   draws, same memcpy count, same conditional writes — driven by an
   index that is independent of `class_idx`).
2. Stage every reference input into the same memory class (typically
   the local stack frame) so the kernel reads them through equivalent
   cache paths.
3. Pointer-select between the two staged inputs OUTSIDE the timing
   region.  The timed window contains exactly one indirect call with
   no class-correlated control flow.

Future dudect lanes should follow the same discipline.  Helper
patterns: a `b_equal` / `b_diff` pair for compare-style primitives, a
single stack-staged reference for scalar-input primitives.

## ctgrind/Valgrind Verification

For more rigorous verification, you can use ctgrind (constant-time grind) with Valgrind:

### Installation

```bash
# Install Valgrind
sudo apt-get install valgrind

# Clone ctgrind (optional, for ct_poison/ct_unpoison macros)
git clone https://github.com/agl/ctgrind.git
```

### Running ctgrind Analysis

```bash
cd tools/constant_time
make

# Run under Valgrind with memcheck
valgrind --tool=memcheck --track-origins=yes ./dudect_harness 10000

# For more detailed analysis, use cachegrind
valgrind --tool=cachegrind ./dudect_harness 10000
```

### Expected Valgrind Output

A clean run should show:
- No memory errors
- No uninitialized value usage
- Consistent cache behavior across input classes

## Upstream Library Guarantees

### Native PQC (ML-DSA-65, ML-KEM-1024, SLH-DSA-256f)

The native C implementations provide constant-time operations:

- All NTT and polynomial arithmetic use constant-time primitives
- No secret-dependent branches or memory accesses
- Validated through NIST KAT (Known Answer Test) vectors (FIPS 203/204/205)
- Rejection sampling uses constant-time comparisons

### Native Ed25519

**Which backend you are reading about.** The tree ships two Ed25519
implementations and builds exactly one. `CMakeLists.txt` defaults
`AMA_ED25519_ASSEMBLY` **ON for x86-64**, which *removes* `src/c/ama_ed25519.c`
from the source list and substitutes `src/c/ed25519_donna_shim.c` (vendored
ed25519-donna). Every x86-64 CI lane, and every x86-64 wheel, therefore
contains **no** `ama_ed25519.c` at all: `nm` on the built library finds zero
`comb_signed` and zero `fe25519_sq` symbols, and `ge25519_niels_base_multiples`
instead — donna's base-point table, which is `.rodata`.

The section below describes `ama_ed25519.c`, the portable **fe51** backend
that AArch64 and everything else builds. Read it as the ARM/portable analysis.
Until 4.0.0 this heading did not say so and the document never mentioned donna
once, so an auditor on x86-64 would have analysed a file their build does not
compile.

Two consequences worth stating rather than leaving implied:

- The C11 `_Atomic` base-point initialisation guard below exists only in
  `ama_ed25519.c`. donna's base-point table is a compile-time constant in
  `.rodata`, so on x86-64 there is no runtime initialisation to guard and the
  mechanism is simply absent — not weaker, inapplicable.
- The two backends are held to *behavioural* equivalence by
  `tools/check_ed25519_backend_parity.py`, which builds both and requires
  identical verdicts across 1,836 cases including the canonical-`y` decode
  pair (INVARIANT-38). That gate is what makes the portable analysis below
  load-bearing for the donna build's accept/reject set — it does not make
  donna's *internal* constant-time properties identical, which are donna's own
  (x86-64 inline assembly for constant-time table selection, see
  `ed25519-donna-64bit-x86.h`).

#### The portable fe51 backend (`src/c/ama_ed25519.c`, AArch64 and generic)

The native C Ed25519 implementation provides constant-time operations:

- Constant-time base-point scalar multiplication for keygen and signing:
  `ge25519_scalarmult_base_comb_signed()`, a 32-table signed 4-bit-window comb
  read by masked full-table scan, so the access trace is independent of the
  secret scalar. (Not a Montgomery ladder — this file previously said "Montgomery
  ladder", which named an algorithm `ama_ed25519.c` has never contained and sent
  an auditor looking for the wrong construct.)
- Verification uses `ge25519_double_scalarmult_vartime()` (width-5 wNAF +
  Shamir's trick) and the variable-base `ge25519_scalarmult()` uses
  double-and-add; both are variable-time **by design**, because every scalar on
  the verify path — `H(R,A,M)` — is public.
- No secret-dependent branches or memory accesses on the secret-scalar paths
- Dedicated `fe25519_sq()` exploiting multiplication symmetry (~55 muls vs ~100)
- C11 `_Atomic` with `memory_order_acquire`/`memory_order_release` for thread-safe base point initialization
- Fallback to volatile for pre-C11 compilers (MSVC compatibility)
- Sign/verify roundtrip validated against RFC 8032 Test Vector 1 (12 tests)

### Native AES-256-GCM (`src/c/ama_aes_gcm.c`)

**Default build is constant-time.** `AMA_AES_CONSTTIME` defaults to `ON`
(`CMakeLists.txt`), which selects the algebraic bitsliced S-box in
`src/c/ama_aes_bitsliced.c` — no table, no secret-dependent memory access.
Hosts with AES-NI / VAES dispatch to the hardware kernels instead, which are
likewise table-free.

**Caveat, and it is now narrow:** building with `-DAMA_AES_CONSTTIME=OFF`
selects the 256-byte table S-box, which is **not** constant-time against
cache-timing side channels in shared-tenant environments. That opt-out is
deliberately awkward — CMake requires an explicit acknowledgement string before
it will configure (INVARIANT-20) — so a build reaches the unsafe path only on
purpose.

*(An earlier revision of this section stated the table S-box unconditionally,
which stopped being true when the bitsliced path became the default. It
understated the library's posture rather than overstating it, but it was still
wrong: a reader could conclude a stock build needed mitigation it already had.)*

**GHASH** is also table-free, and its mask is laundered through
`ama_ct_value_barrier_u8` so an optimizer cannot convert the branch-free
selection back into a branch on the secret subkey — a real regression clang 18
introduced at `-O2`/`-O3`. `tools/check_ghash_constant_time.py` measures
retired instructions across key classes under callgrind and fails on any
key-dependent count; it runs unconditionally in `dudect.yml`.

## Functional Correctness Tests

In addition to timing analysis, we provide functional correctness tests for the constant-time utilities:

```bash
cd tests/c
# Build and run C tests (requires CMake)
mkdir build && cd build
cmake ..
make
./test_consttime
```

These tests verify:
- `ama_consttime_memcmp`: Identical buffers return 0, different buffers return non-zero
- `ama_secure_memzero`: Buffer is completely zeroed
- `ama_consttime_swap`: Buffers are swapped when condition=1, unchanged when condition=0

## Limitations and Caveats

1. **Statistical Nature**: Timing analysis is statistical and cannot prove the absence of all timing leaks. It can only detect leaks above a certain threshold.

2. **Environment Sensitivity**: Results depend on the execution environment. Factors like CPU microarchitecture, OS scheduler, and system load can affect measurements.

3. **Compiler Optimizations**: Aggressive compiler optimizations may introduce timing variations. The harness is compiled with `-O2` which balances optimization with predictability.

4. **Scope**: This verification covers the C constant-time utilities. The
   Python layer routes secret comparisons into the same C primitive via
   `secure_memory.constant_time_compare()`, so it inherits that coverage
   rather than relying on an upstream guarantee.

## Recommendations for Production

1. **Run verification on target hardware**: Timing characteristics vary by CPU architecture.

2. **Disable CPU frequency scaling**: For accurate measurements, set CPU governor to "performance":
   ```bash
   sudo cpupower frequency-set -g performance
   ```

3. **Isolate the test**: Run on an otherwise idle system to minimize interference.

4. **Regular re-verification**: Re-run timing analysis after any changes to cryptographic code paths.

5. **Independent audit**: For high-security deployments, engage a third-party security firm to perform formal constant-time verification.

## References

1. Reparaz, O., Balasch, J., & Verbauwhede, I. (2017). "Dude, is my code constant time?" https://eprint.iacr.org/2016/1123.pdf

2. Langley, A. "ctgrind" - Valgrind-based constant-time verification. https://github.com/agl/ctgrind

3. NIST FIPS 204 - ML-DSA (Dilithium) Standard. https://csrc.nist.gov/pubs/fips/204/final

4. Open Quantum Safe Project. https://openquantumsafe.org/

5. AMA Cryptography Ed25519 Implementation. `src/c/ama_ed25519.c`
