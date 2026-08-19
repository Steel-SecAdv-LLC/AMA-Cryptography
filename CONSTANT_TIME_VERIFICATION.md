# Constant-Time Verification Guide

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 5.0.0 |
| Last Updated | 2026-08-14 |
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
    # ama_consttime_memcmp from the native library, or RuntimeError.
    # There is no fallback: see item 2 above.
    #
    # min(len(a), len(b)) bytes are compared in place — no padding, no
    # allocation — and the length difference is OR-ed into the verdict
    # rather than short-circuiting the content scan.  The scan itself
    # never short-circuits: ama_consttime_memcmp accumulates over all n
    # bytes.
```

**Why the cost is bounded by the *shorter* operand, and why that is not a
weakening.** Through 4.0.0 both operands were padded to
`max(len(a), len(b))` with `ljust`, on the reasoning that a fixed comparison
length hides the lengths. It does not need to: the values AMA compares in
constant time — HMAC-SHA3-256 tags, Ed25519 / ML-DSA-65 public keys, ML-KEM
shared secrets — each have exactly one length fixed by their specification, so
an observer learns nothing from a comparison whose cost depends on them. What
the padding did do was let an *attacker* set that cost. Every call site
compares a locally computed value against one that arrived from outside:
`verify_crypto_package` recomputes a 32-byte tag and compares it against
`package.hmac_tag`, so a package declaring an 8 MiB tag caused 16 MiB of
allocation and an 8 MiB scan before any check had established the package was
worth looking at. Bounding the work by the shorter operand removes that, and
removes it independently of argument order, while leaving every return value
and the content-scan property exactly as they were.

`secure_memory.lengths_match()` is the public length pre-check to run first
where the expected size is known: it refuses a malformed value *as malformed*,
rather than folding a structural defect into a cryptographic verdict.

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

The harness uses Welch's t-test to compare execution times between two input classes, with the percentile cropping the paper specifies in §3.3: the pooled samples are cut at a ladder of 20 thresholds and the reported statistic is the signed t of largest magnitude over those rungs and the uncropped one. Cropping is what lets the test see a systematic shift in the *bulk* of the distribution rather than losing it under the heavy right tail that preemption and frequency changes produce; measured against a textbook early-exit `memcmp` at 50,000 iterations, the cropped statistic detected the leak 48 times out of 48 where a single raw Welch t detected it 19 times.

A t-value below `DUDECT_T_THRESHOLD` suggests no detectable timing leakage at the 99.999% confidence level. **That threshold is 5.0, not the 4.5 usually quoted**, because the statistic is a maximum over 21 rungs rather than one t-test, and the maximum of 21 correlated t-values has a wider null distribution: 6,000,000 null replicates put E|t| at 1.618 and sd at 1.717, against 0.798 and 1.000 for a single t. Under that null `P(|t| >= 4.5)` is 7.2e-5 — seven times the 1e-5 that "99.999%" asserts — while `P(|t| >= 5.0)` is 6.5e-6. The calibration is re-derived on every run by the harness self-test, which fails if a change to the rung ladder moves the null out of its measured band.

Two properties of the measurement matter as much as the statistic:

- **A verdict needs a majority of rounds.** A lane must exceed the threshold in more than half of the rounds run, with a consistent sign, before the run fails; excursions that disagree about direction are reported as unusable measurements rather than findings. See `tests/c/dudect/dudect_rounds.h`.
- **A verdict needs an effect size, not just a t-value.** |t| grows as sqrt(n), so significance measures how well a difference was *resolved*, not how large it is — and at these measurement counts the statistic resolves well under one CPU cycle. On one CI run the lanes that failed had per-class differences of 0.199, 0.596 and 1.141 ns while lanes that passed had differences of 35, 78 and 53,932 ns: the verdict was tracking precision, not size. A lane therefore fails only if it is significant **and** its difference reaches `DUDECT_MIN_EFFECT_NS` (2 ns) — above every artefact observed on shared runners and below every real mechanism (a mispredicted branch is 7–10 ns, an L1 miss 30–50 ns, an early-exit `memcmp` hundreds). Below that, a wall-clock test on shared hardware cannot separate a source-level leak from data-operand-dependent execution in the CPU (Intel DOITM / ARM PSTATE.DIT), and the deterministic instruction-count gates own the range — they measure it with a zero-instruction noise floor. Sub-floor excursions are printed with their own `SUB-FLOOR` verdict, never folded into a pass. Because the floor adjudicates on a number the harness supplies, a lane that trips the threshold while reporting a difference of exactly zero is treated as a harness fault rather than a sub-floor pass: the statistic *is* `delta / se`, so that combination cannot come from a measurement — it can only mean the field was never populated, and a lane in that state would be permanently unable to fail a build. Info-only lanes are exempt, since they are classified as noise before the verdict reaches an effect size at all.

- **The floor is a precondition for adjudication, so it is applied before the direction rule rather than after it.** The direction rule's premise is that a real leak keeps a fixed sign; that presupposes the effect is resolvable. Below the floor it is not, and the consequence was observed: `Ascon-AEAD128 encrypt` read 3/3 consistently signed at +0.596 ns on one CI runner and 2+/1− at +0.607 ns on another — same binary, same measurement count, same effect size to within 2%, opposite verdicts (SUB-FLOOR/green vs UNUSABLE/red). A sign-consistency test applied to a quantity whose sign is not reproducible decides nothing. No sensitivity is lost: at or above 2 ns direction disagreement is still `UNUSABLE` and still fails, and the floor sits below every mechanism that can produce a real difference. A sub-floor excursion whose signs disagreed says so in the report rather than being printed identically to a consistently-signed one.

- **The sub-floor exemption's claim is now true for the lanes that reach it.** It says the deterministic instruction-count gates own the range below 2 ns. For two of the lanes observed reaching it, they did not: nothing covered `ama_ascon_aead128_encrypt`, and nothing covered `ama_agent_binding_check`. Both are now covered rather than the claim softened — Ascon-AEAD128 encryption retires 32,069,814 instructions identically across all eight key classes, and the agent binding check 612,810,230 identically whether it accepts or rejects; cross-class delta 0 and noise floor 0 in both cases.
- **Both classes are staged through one buffer.** Cropping resolves the bulk of the distribution, which at these sample counts means a standard error near 0.04 ns — finer than one CPU cycle. At that resolution the *address* of a lane's input is a confounder: with identical data in both classes, placing one class's key across two cache lines drives |t| to 13.5–30.9 with a consistent sign, which is what a leak looks like and is not one. Every lane therefore copies the selected class's input into a single cache-line-aligned buffer before the timed region, so the classes differ in data and not in address.

Each lane also reports the per-class mean difference in nanoseconds beside its t-value, because |t| alone does not distinguish a 0.2 ns measurement artefact from an exploitable difference.

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
Threshold: |t| < 5.0 (99.999% confidence, calibrated for the
           max-over-21-rungs statistic; a single Welch t would be 4.5)
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
| \|t\| < 5.0 | No detectable timing leakage (PASS) |
| 5.0 <= \|t\| < 10 | Over threshold: a finding only if it reproduces in a majority of rounds with a consistent sign |
| \|t\| >= 10 | Strong evidence of timing leakage (FAIL) |

Read the reported per-class mean difference alongside the t-value. |t| grows
as sqrt(n) for any non-zero difference, so at high measurement counts the
statistic reaches the threshold on differences far below one CPU cycle, and
the difference in nanoseconds is what says whether a finding is exploitable.
A real leak mechanism — a mispredicted branch, an extra cache line, an extra
round — costs nanoseconds to tens of nanoseconds; a lane reporting |t| over
the threshold on a difference of 0.2 ns is measuring the harness or the host,
not the primitive.

**Note**: Environmental factors such as CPU frequency scaling, interrupts, and cache effects can cause false positives. The multi-round majority rule exists for exactly this and handles excursions that vary between rounds; it does **not** handle a bias that is fixed for a given binary and host, which reproduces every round with the same sign. That class is removed by construction instead — see the staging discipline below. Run the test multiple times and consider disabling CPU frequency scaling for more accurate results.

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
3. Choose the class OUTSIDE the timing region.  The timed window
   contains exactly one call with no class-correlated control flow.

**Point 3 was necessary and not sufficient, and the missing half is now
point 4.** Selecting a *pointer* outside the timer still leaves the two
classes reading two different addresses inside it, and an address is
something a load's timing legitimately depends on: which cache line it
falls in, whether it spans two, which set it maps to.  Unlike scheduler
noise, that difference is fixed for a given binary on a given host, so it
reproduces in every round with the same sign — the shape the multi-round
majority rule is specifically unable to distinguish from a leak.

Measured with the Ascon-AEAD128-encrypt lane's own cipher call and
**identical key data in both classes**, so the true effect is exactly zero:
placing class 0's key across two cache lines while class 1's sits inside one
drives the cropped statistic to |t| = 13.5–30.9, over threshold in 10 of 10
runs, all one sign.  Staged through a single buffer, the same measurement
reports 0 of 10.  This became reachable when the harnesses adopted percentile
cropping: cropping resolves the bulk of the distribution, which for that lane
means a bulk standard deviation of about 4 ns over ~22,000 samples per class,
a standard error near 0.04 ns, and a threshold crossed by a systematic
difference of roughly 0.2 ns — under half a cycle at 2.1 GHz.

4. Copy the selected class's input into ONE shared, cache-line-aligned
   buffer, and hand the timed call that buffer.  Both classes then present
   the same address and the same alignment, and only the data differs.  The
   copy is identical work for both classes and happens outside the timed
   region.  `dudect_stage()` in `tests/c/dudect/dudect.h` is the helper; it
   is used by every lane in `tests/c/test_dudect.c` and by the keyed lanes
   in `tools/constant_time/dudect_crypto.c`.

Sensitivity is untouched by point 4: a data-dependent leak follows the data,
which still differs by class.  For compare-style primitives the equivalent —
and stronger — form is a single reused probe whose bytes are rewritten
class-symmetrically each iteration, which is what the AES-GCM and Ascon
tag-compare lanes use.

Future dudect lanes should follow all four points.

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
(`CMakeLists.txt`), which selects the masked full-table-scan S-box in
`src/c/ama_aes_bitsliced.c` — a lookup reads all 256 entries and selects with
an arithmetic mask, so the memory access pattern is uniform and independent of
the secret index.  (The construct is a masked scan, not an algebraic circuit:
both are constant-time, but a side-channel reviewer assesses them differently,
and THREAT_MODEL.md:136 already describes it correctly.)
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
`ama_ct_value_barrier_u64` so an optimizer cannot convert the branch-free
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
