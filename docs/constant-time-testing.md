# Constant-Time Testing Guide

## Overview

AMA Cryptography uses two complementary approaches to verify constant-time properties:

1. **Structural tests** (`tests/c/test_consttime.c`) — Unit tests that verify functional correctness of constant-time primitives
2. **Empirical timing tests** (`tests/c/test_dudect.c` and `tools/constant_time/`) — Statistical analysis that detects actual timing leakage using the dudect methodology

Both are essential: structural tests catch logic bugs, while empirical tests catch timing leaks that may arise from compiler optimizations, CPU microarchitecture effects, or implementation errors.

## What is dudect?

**dudect** ("Dude, is my code constant time?") is a methodology for empirically verifying that code runs in constant time. It was introduced by:

> Reparaz, O., Balasch, J., & Verbauwhede, I. (2017).
> "Dude, is my code constant time?"
> Design, Codes and Cryptography, 86(12), 2497-2508.
> https://eprint.iacr.org/2016/1123.pdf

### How It Works

1. **Define two input classes**: Class 0 (e.g., fixed/known input) and Class 1 (e.g., random input)
2. **Measure execution times**: For many iterations, randomly select a class, prepare the input, and time the computation
3. **Apply Welch's t-test**: Compare the timing distributions of the two classes
4. **Crop and reduce**: Cut the pooled samples at a ladder of 20 percentile thresholds and take the signed t of largest magnitude over those rungs and the uncropped one. Cropping is what lets a systematic shift in the *bulk* survive the heavy right tail that preemption and frequency changes add.
5. **Evaluate**: If |t| exceeds the calibrated threshold, the timing distributions are statistically distinguishable at 99.999% confidence — indicating timing leakage.

The threshold is **5.0, not 4.5**. 4.5 is the critical value of a *single* Welch t; step 4 reports the maximum of 21 correlated t-values, whose null distribution is wider. Measured over 6,000,000 null replicates: E|t| = 1.618 and sd = 1.717, against 0.798 and 1.000 for one t; `P(|t| >= 4.5)` = 7.2e-5 where the stated confidence asserts 1e-5, and `P(|t| >= 5.0)` = 6.5e-6.

The key insight is that if code is truly constant-time, the execution time should be independent of the input class, and Welch's t-test will show no significant difference.

## Running Tests Locally

### CMake-based dudect tests

```bash
# Build with dudect enabled
cmake -B build -DAMA_ENABLE_DUDECT=ON -DAMA_USE_NATIVE_PQC=ON
cmake --build build

# Run all dudect tests
./build/bin/test_dudect

# Run with more measurements for higher confidence
./build/bin/test_dudect --measurements 10000000

# Run with timeout
./build/bin/test_dudect --measurements 5000000 --timeout 300

# For best results, pin to a single core and elevate priority
taskset -c 0 nice -n -20 ./build/bin/test_dudect --measurements 10000000
```

### Runner script

```bash
# Run the full dudect suite with defaults (1M measurements)
./tools/run_dudect.sh

# Customize
./tools/run_dudect.sh --measurements 5000000 --timeout 600

# Build only (useful for CI integration)
./tools/run_dudect.sh --build-only
```

### Legacy harnesses (tools/constant_time/)

```bash
cd tools/constant_time
make all

# Quick test (100K iterations)
make test-all

# Full test (1M iterations)
make test-full
make test-crypto-full
```

## Functions Under Test

### Utility Functions (always tested)

| Function | Test Description | Input Classes |
|----------|-----------------|---------------|
| `ama_consttime_memcmp` | Memory comparison timing | Class 0: identical buffers / Class 1: differing buffers |
| `ama_consttime_swap` | Conditional swap timing | Class 0: condition=0 / Class 1: condition=1 |
| `ama_secure_memzero` | Memory zeroing timing | Class 0: all-zero buffer / Class 1: all-0xFF buffer |
| `ama_consttime_lookup` | Table lookup timing | Class 0: first half index / Class 1: second half index |
| `ama_consttime_copy` | Conditional copy timing | Class 0: condition=0 / Class 1: condition=1 |

### Cryptographic Primitives

| Function | Test Description | Input Classes |
|----------|-----------------|---------------|
| Ed25519 sign | Key-independent timing | Class 0: zero-seed key / Class 1: 0xFF-seed key |
| AES-GCM tag verify | Tag match-independent timing | Class 0: valid tag / Class 1: invalid tag |
| HKDF-SHA3-256 | IKM-independent timing | Class 0: zero IKM / Class 1: 0xFF IKM |
| HMAC-SHA256 verify | MAC comparison timing | Class 0: valid MAC / Class 1: invalid MAC |

### Post-Quantum Cryptography (when `AMA_USE_NATIVE_PQC=ON`)

| Function | Test Description | Input Classes |
|----------|-----------------|---------------|
| ML-KEM-1024 decaps | Implicit rejection timing | Class 0: valid ciphertext / Class 1: corrupted ciphertext |
| ML-DSA-65 sign | Message-independent timing | Class 0: zero message / Class 1: 0xFF message |

## Interpreting Results

### PASS (|t| < 5.0)

No statistically significant timing difference detected between the two input classes. The implementation is empirically constant-time at the 99.999% confidence level.

### OVER THRESHOLD (|t| >= 5.0)

A single round over the threshold is not a verdict. A lane fails only if it exceeds the threshold in a **majority of rounds with a consistent sign, and the per-class mean difference is at least 2 ns**; excursions that disagree about direction are classified `UNUSABLE` rather than as a leak finding — but `UNUSABLE` still FAILS the build, because a gate that cannot measure has not cleared anything; what changes is the diagnosis and the operator's next action (re-run on a quiet host, versus audit the primitive). Excursions below 2 ns are reported as `SUB-FLOOR` and do NOT fail. `SUB-FLOOR` means the excursion is not adjudicable by a wall-clock test on shared hardware — not that a difference was shown to be absent. The deterministic instruction-count gates in `.github/workflows/dudect.yml` cover the part of that range that changes the instruction *sequence*, for the calls they target; a difference living only in operand-dependent latency is measured by neither instrument.

The magnitude condition is load-bearing, not a rounding rule. Measured on one host, five consecutive runs of the same binary at 100,000 measurements: of the eleven lanes whose mean difference stayed under 2 ns, ten changed sign at least once. A sign-consistency test is meaningless where the sign is not reproducible — which is exactly the range the floor covers. Read the per-class mean difference the harness prints beside the t-value: |t| grows as sqrt(n), so at high measurement counts the statistic reaches the threshold on differences well under one CPU cycle, and the nanosecond figure is what says whether a difference is exploitable.

A statistically significant timing difference was detected. This could indicate:

1. **Actual timing leakage** — the implementation is not constant-time
2. **Environmental noise** — shared CI machines, CPU frequency scaling, interrupts, etc.

### INFO results

Some tests are marked as "INFO" rather than strict pass/fail:

- **AES-GCM tag verify**: The table-based AES S-box backend has inherent cache-timing variation. Use `AMA_AES_CONSTTIME=ON` for the bitsliced backend.
- **ML-DSA-65 sign**: Dilithium uses rejection sampling, which has intentional timing variation by design.

### Reducing False Positives

For the most accurate results:

```bash
# Pin to single CPU core (avoid migration noise)
taskset -c 0 \
# Elevate scheduling priority
nice -n -20 \
# Use many measurements
./build/bin/test_dudect --measurements 10000000
```

The test suite runs up to 3 rounds — a single passing round is sufficient.

## Adding New Functions

To add a new function to the dudect test suite:

1. **Edit `tests/c/test_dudect.c`**:

<!-- example: pseudocode: a template for a new lane inside tests/c/test_dudect.c, where my_function is a placeholder -->
```c
static double test_my_function(int iterations) {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx, "my_function_name");

    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;

        // Prepare class-specific input
        // Class 0: one category of input
        // Class 1: another category of input

        uint64_t start = dudect_get_time_ns();
        // Call the function under test
        my_function(...);
        uint64_t end = dudect_get_time_ns();

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    dudect_print_result(&ctx);
    return dudect_get_t(&ctx);
}
```

2. **Add to `run_all_tests()`** in the same file

3. **Rebuild and test**:
```bash
cmake --build build
./build/bin/test_dudect
```

## Relationship to test_consttime.c

| Aspect | test_consttime.c | test_dudect.c |
|--------|-----------------|---------------|
| **What it tests** | Functional correctness | Timing behavior |
| **Method** | Assertions on return values | Statistical timing analysis |
| **Catches** | Logic bugs, wrong return values | Timing leaks, compiler issues |
| **Speed** | Fast (milliseconds) | Slow (minutes with enough measurements) |
| **False positives** | None | Possible on noisy hardware |
| **CI integration** | Always runs | Runs on schedule and src/c/ changes |

Both test suites should pass before deploying constant-time code to production.

## CI Integration

The dudect tests run via `.github/workflows/dudect.yml`:

- **Trigger**: Push/PR touching `src/c/`, weekly schedule, manual dispatch
- **Jobs**: Utility functions, PQC primitives, legacy harnesses
- **Noise mitigation**: `taskset -c 0 nice -n -10` for CPU pinning
- **Timeout**: 5-10 minutes per job to prevent hanging

## Deterministic gates: instruction counting and secret taint

The wall-clock lanes above measure *time*; the two gates in this section
measure *what the program did*, so they need no quiet machine and no
significance threshold.  Both live in `tools/check_ghash_constant_time.py`
and run on every pull request from the `ghash-scalar-invariance` job of
`.github/workflows/dudect.yml`.

### What each instrument can and cannot see

| Instrument | Sees | Blind to |
|---|---|---|
| callgrind instruction / data-reference / cache-miss counts (`--target <t>`) | any secret-dependent difference in the **instruction sequence**: an early exit, a data-dependent loop bound, a branch whose arms differ in length | a branch whose two arms retire the same count; a conditional move; a secret-indexed load that stays cache-resident (the simulated D1 has 32 KiB — a 4 KiB table never misses, so its miss counts are identical for every index) |
| Memcheck secret taint (`--target <t> --taint`) | every **conditional jump, conditional move and memory address** that depends on the secret, wherever the dependency flows (the ctgrind construction: the secret is marked undefined and Memcheck's definedness tracking does the rest) | a secret **operand** of an arithmetic instruction (Memcheck propagates definedness through a `div` without reporting it); the *magnitude* of a leak it reports |
| secret-operand gate (`tools/check_ct_operand.py`, below) | every instruction that **consumes** a secret-derived operand, by mnemonic, and whether the operand reached a division, floating-point or square-root operation | whether the CPU is running in the vendor's data-independent-timing mode (that is the runtime half: `ama_ct_hw_mode_status`); the paths no driver executes |

None of the three sees a difference that lives only in the CPU's
data-dependent execution *of an instruction its vendor lists as
data-independent*; that is the deployment-mode question (Intel DOITM, Arm
PSTATE.DIT) answered at the end of this guide, and it is why the dudect
lanes stay strict.

The miss figures the instruction-count gate prints therefore do **not** by
themselves rule out a secret-dependent memory access; the taint gate is the
instrument for that claim.  An earlier revision of this guide let the count
gate's "cache misses are all invariant" line stand for more than it measures.
Planted defects were used to check both instruments: a secret-indexed
4 KiB table lookup passed every callgrind metric and was reported by the
taint gate at the load; a balanced two-arm branch on a secret bit passed the
instruction count and was reported by the taint gate at the jump.

### Taint targets and what they found

`--taint` drivers exist for `x25519`, `x25519-batch`, `ed25519-sign`,
`ed25519-sign-expanded`, `ed25519-sign-sse2fold`, `secp256k1-scalarmult`,
`ecdsa`, `nistp-ecdsa`, `kyber-decaps`, `consttime`, `ghash`, `ascon-encrypt`,
`agent-binding`, `argon2id-verify`, `slhdsa-sign`, `base64`,
`secp256k1-seckey` and `aead-verify`.
`slhdsa-sign` is the one target with a taint driver and no instruction-count
driver: SLH-DSA signing does different work per key by construction (the
WOTS+ chain lengths are digits of values derived from SK.seed), so a count
target would fail a correct implementation, and the tool refuses to run it
without `--taint`.
On its first run over the tree the gate reported, and the tree then removed:

- the RFC 7748 all-zero-output branch in `ama_x25519_key_exchange` and its
  batch counterpart (now a mask over the outputs and a masked return code);
- the safegcd product re-check in `fe_invert_ct`, a conditional on a value
  derived from the projective Z of `[r]B` on every Ed25519 keygen and sign
  (removed; the divstep bound and `tests/c/test_ed25519_safegcd.c` carry the
  correctness argument);
- the zero-scalar and point-at-infinity branches in
  `ama_secp256k1_point_mul` (now masks);
- a conditional move gcc made of the AES-GCM verify mask at `-O2` (the mask
  now passes through `ama_ct_value_barrier_u64`, as in ChaCha20-Poly1305);
- in `ama_nistp_ecdh`, once the `nistp-ecdsa` driver was extended to run ECDH
  under the same tainted key (ECDH is the only P-curve entry point that feeds
  a secret scalar to the variable-base windowed multiplier), six reports: the
  scalar-range verdict and the at-infinity flag were undeclassified branches
  on the key, and the compiler had reused the range check's zero result as
  the multiplier's loop-counter start, so that loop's bound, its scalar-byte
  address and its nibble select read as key-dependent too.  Both values are
  now declassified exactly as on the key-derivation and signing paths, and
  the driver reports none.

The branches that remain on secret-derived values are in ECDSA, ECDH and
SLH-DSA signing, on values the function returns.  In SLH-DSA they are the
randomizer R (the signature's first n bytes), the FORS public key and each
layer's XMSS root, all of which verification recomputes from the signature, and
from which every chain length and leaf position is computed.  In ECDSA and ECDH
they are an out-of-range private key (the verdict is the return code), `r == 0`
/ `s == 0` (the emitted signature), a scalar multiple at infinity (impossible
for a key in range, on the fixed generator or on a validated prime-order peer
point), and the RFC 6979 candidate rejection that every conforming signer
shares.  Each is declassified at its
site with `AMA_CT_DECLASSIFY` (`src/c/internal/ama_ct_declassify.h`), a
no-op in production and a Memcheck client request in `AMA_TESTING_MODE`
builds — the construction libsecp256k1 and BoringSSL use.
`grep -rn AMA_CT_DECLASSIFY src/c` is the complete list; adding a site is a
review item.

### Which machine code is measured

Every count and taint run above links its driver against the
`AMA_TESTING_MODE` static archive built with LTO off.  The wheel ships
`libama_cryptography.so` built with LTO on, and a driver linked against the
archive re-optimises it at link time, so those runs measure code of the same
source but not the same bytes.  The job therefore also builds the shared
object the way the wheel does and runs the taint gate against it
(`--optimized-witness build-shared/CMakeCache.txt`) for every target whose
driver uses only public symbols.  `ghash` and `aead-verify` need the
test-only scalar-forcing hook, and `ecdsa` / `nistp-ecdsa` carry
declassification points that are no-ops outside `AMA_TESTING_MODE`, so those
four are measured on the archive only.

On x86-64 the Keccak permutation the gates measure is the one production
runs: the single-state AVX2 kernel is no longer installed by the dispatcher
(it retired about three times the instructions of the BMI2 scalar kernel and
the auto-tune reverted it on every host measured), so `sha3-256`,
`kyber-decaps` and every other SHA3-consuming target measure the BMI2 path
that `ama_get_dispatch_info()` reports.  The 4-way AVX2 kernel remains for
batched callers and is auto-tuned on its own.

## Secret-operand gate: instructions whose latency may depend on their operands

### Leakage model, and what this gate claims within it

A **violation** is a secret-derived value that reaches (a) a conditional
branch, (b) a memory address, or (c) an instruction whose latency may depend
on its operands on a supported target. Supported targets are the ISAs this
repository builds for, x86-64 and AArch64, with the SIMD tiers the
dispatcher selects. (a) and (b) are the Memcheck taint lane above. This
section is (c), and it claims nothing beyond it.

"May depend on its operands" is decided by the CPU vendors, not by this
repository. An instruction is admitted only if Intel's *Data Operand
Independent Timing Instructions* list (x86-64) or Arm's DIT list (AArch64)
names it. Both lists, with their URLs, retrieval dates (2026-11-07) and the
way each was read and cross-checked, are in
`tools/ct_operand/allowlists.json`: 594 Intel mnemonics, 651 Arm mnemonics
(the SME groups are left out because this library contains no SME code). No
entry was written from memory. Intel's page refuses non-browser clients, so
its bytes could not be pinned by digest; the table was read twice through a
rendering fetcher with independent prompts and the two readings agree
exactly. Arm's page was read from a mirror of Arm's own released XHTML
(2026-03 release) three times; the second reading dropped four entries the
first carried, and a third, targeted reading quoted each of the four from
its category. Re-verify both against a browser copy when the vendors next
update them.

What the lists say about the classes this gate exists for:

| Class | Intel DOIT list | Arm DIT list |
|---|---|---|
| Division | no `DIV`, `IDIV` or SSE/AVX divide | no `SDIV`, `UDIV`, `FDIV` |
| Floating point (subnormal operands included) | no FP arithmetic; only data movement such as `MOVAPS`, `MOVSS`, `XORPS`. Intel's ISA guidance adds that MXCSR may need configuring for some listed instructions | of scalar FP, only `FCSEL` |
| Square root | none | no `FSQRT` |
| Multiply (early termination) | `MUL`, `IMUL`, `MULX`, `PMULUDQ`, `VPMADD52LUQ` … **listed** | `MADD`, `UMULH`, `SMULH`, `UMADDL`, NEON `MUL`/`UMULL`/`PMULL`, SVE `MUL` … **listed** (`SQDMULL` is not) |

So an early-terminating multiply is excluded by the vendor contract, but
only while the vendor's timing mode is in force; see *Runtime modes* below.

### Method, and why this instrument

`tools/ct_operand/ctoperand.c` is a Valgrind tool on VEX IR, built by the
gate from the installed Valgrind headers and archives. Of the three
candidate approaches (a Valgrind tool, a DynamoRIO or Pin client, static
relational analysis such as Binsec/Rel) it is the only one that runs the
existing taint drivers unmodified: it implements Memcheck's
`MAKE_MEM_UNDEFINED` / `MAKE_MEM_DEFINED` client requests, so every driver
in `check_ghash_constant_time._TAINT_DRIVERS` and every `AMA_CT_DECLASSIFY`
site in `src/c` means exactly what it means to the Memcheck lane, and its
coverage is the Memcheck lane's coverage by construction. It needs nothing
`dudect.yml` does not already install.

The tool keeps a byte-granular taint shadow of memory and of the guest
register file and a one-bit shadow per IR temporary, propagated
pessimistically (an operation's result is tainted if any operand is; the
zero idioms `x ^ x` and `x - x` are the only exceptions). At the end of every
guest instruction it records the instruction if any value the instruction
USED as an operand was tainted. Two rules make "used" precise, and each was
forced by a measured false report: a value no register write, store, exit or
helper call consumes is not an operand (the ignored effective address of a
multi-byte `nop`), and a fetch is not a use, so the charge goes to the
instruction that operates on the value rather than to the one whose register
read VEX happened to share (a clang padding `nop [rax+rax]` and the
`and r9b, al` after it read `rax` through one IR temporary). Guest IR is not
optimised before instrumentation (`--vex-iropt-level=0`), so an
instruction's computation stays attached to its own address. Each record
carries class bits taken from the VEX operation that consumed the taint:
DIV, FP and SQRT, generated from the installed Valgrind VEX IR header by
`check_ct_operand.op_class` (the op names say what they compute), and
BRANCH for an exit guard or indirect target. The gate disassembles every
recorded address with objdump (Intel syntax on x86-64, `-M no-aliases` on
AArch64, so mnemonics are the architectural names the lists use; condition
code synonyms such as `CMOVZ`/`cmove` are learned by assembling both
spellings, not tabulated) and reports `symbol+offset`, the object, the
execution count and the call chain.

### The verdict: one blocking half, one inventory

* **Blocking, with no exemption.** The run FAILS if a secret-derived
  operand reaches a division, floating-point or square-root operation
  anywhere in the process. On this tree no target does.
* **Inventory, reported and not blocking.** Every consuming instruction whose
  mnemonic the vendor list does not name is printed. On this tree that
  residue is compiler instruction selection with no vendor statement either
  way, and blocking on it would need a standing exemption list (which would
  also drift with every compiler release) — the construction AGENTS.md
  section 10 rejects. So this half is a measurement instrument with the
  reviewed inventory below, and `--require-listed` turns it into a blocking
  check for anyone who wants that. Saying so plainly is the point: the
  inventory items are secret operands at instructions Intel or Arm does not
  vouch for, and they are open, not cleared.

### Reviewed inventory (gcc 13.3.0, x86-64, 2026-11-07)

Measured on the `AMA_TESTING_MODE` archive (Release, LTO off) for all 18
taint targets and on the LTO shared object for the 10 the Memcheck
shipped-object lane runs. Every row has a secret-derived operand; none is in
a blocking class.

| Mnemonic | Where | Classification |
|---|---|---|
| `REP MOVSQ` | `ama_sha512_oneshot`, `ama_sha512_ctx_update`, `ama_sha3_update`, `ama_sha3_512`, `ama_shake256`, `sha2_HT`, `ed25519_sign_core` | gcc's inline expansion of a fixed-size block copy of hash state. Intel lists `REP MOVSB/W/D` and `REP STOSB/W/D`, footnoting that their latency varies with the count in (E/R)CX, and does not list the quadword form. The count is a compile-time constant here. Unlisted: open. |
| `LEAVE` | `ama_ed25519_select15_avx2` epilogue | restores a frame pointer whose saved value is a caller's secret-holding register; `LEAVE` is not listed (`MOV` and `POP` are). Unlisted: open. |
| `CWDE` | `poly_compress`, `poly_basemul`, `polyvec_basemul_acc` | gcc's short form of a 16→32-bit sign extension; `MOVSX` is listed, `CWDE` is not (`CQO` is). Unlisted: open. |
| `SHUFPS` | `kyber_decapsulate_internal`, `kyber_gennoise`, `ama_shake256`, `ama_shake256_x4_squeezeblocks` | auto-vectorised integer shuffles emitted in the FP domain; `PSHUFD` is listed, `SHUFPS` is not. Unlisted: open. |
| `MOVHLPS` | `ascon_aead128_encrypt_frame` | auto-vectorised lane move; not listed. Unlisted: open. |
| `JE`, `JNE` | `ama_aes256_gcm_decrypt` | BRANCH-tagged: conditional control flow, leakage class (a). The bit-exact Memcheck lane passes `aead-verify`, so the condition does not depend on the secret bit for bit; the coarser taint here over-approximates it. Adjudicated by Memcheck, not by this gate. |

The same sweep on a **clang 18.1.3** archive (all 18 targets, every one
passing the blocking criterion) inventories a different set, because clang
moves integer data through the floating-point domain: `MOVAPD`,
`MOVSD` (the SSE scalar move, not the listed string move), `VMOVAPS`,
`VMOVUPS`, `VXORPS`, `VANDNPS`, `ANDPS`, `MOVMSKPS`, `VMOVLHPS`, `SHUFPD`,
`SHUFPS` — data movement and bitwise operations, none of them FP arithmetic,
which is why the blocking FP class (taken from the IR operation, not the
mnemonic) does not fire on them — plus `XSAVE` / `XRSTOR` in the dynamic
loader's lazy-binding trampoline (`_dl_runtime_resolve_xsave`), which saves
and restores vector registers that hold secret data across a PLT call, and
31 branch sites. The Memcheck lane, run on the same clang archive for each of
the eight targets those branches occur in, passes all eight, so they are
over-approximation by this tool's coarser propagation, not secret branches.
Every one is unlisted and open in the sense above.

Clearing a row means changing the code generation (or obtaining a vendor
statement), not adding it to a list.

### Mutation evidence (section 6.2)

Each plant fed a secret into one real kernel, `kyber_compress_d_impl`
(inlined into `poly_compress`, the ML-KEM re-encryption inside
decapsulation: the KyberSlash site), and was reverted after the run.

| Class | Plant | Result (`--target kyber-decaps`) |
|---|---|---|
| Division | `quotient = n / q` with `q` volatile | FAIL: 24 `div` sites, class DIV, in `poly_compress` and its inlined copies in `kyber_decapsulate_internal`; also FAIL on the LTO shared object (`div rcx` at `poly_compress+0xfe`) |
| Floating point | `(double)quotient * one`, `one` volatile | FAIL: `cvtsi2sd`, `mulsd`, `cvttsd2si`, class FP, 24 sites each |
| Square root | `sqrt((double)q * (double)q)` | FAIL: `sqrtsd` ×16 and `sqrtpd` ×4 (gcc vectorised one copy), class SQRT, plus the conversions as FP |
| Multiply | `quotient * one`, `one` volatile | PASS by default (the vendor lists admit integer multiply); with `--deny IMUL,MUL,MULX --require-listed` FAIL; the planted run carries 44 two-register `imul` sites against the unplanted run's 20 under the same flags, and the 24 added are in `poly_compress` (16) and `kyber_decapsulate_internal` (8), the same 24 inlined copies the divide plant hit |

`tests/test_ct_operand_gate.py` pins the instrument itself on a small
program: a secret divide, a secret double multiply and a secret square root
are reported with the right class, a secret multiply is consumed but in no
blocking class, and a divide of a declassified value is not recorded.

### Tiers analysed, and not

* **Analysed:** x86-64 under Valgrind's CPU model, which exposes AVX2 and
  not AVX-512: the default dispatch wiring on that model (AVX2 Kyber and
  ML-DSA NTT, the BMI2 scalar Keccak, the AVX2 Ed25519 niels-select fold,
  scalar X25519), on the archive and the shipped `.so` with gcc 13.3.0, and
  on the archive with clang 18.1.3 (measured here; CI runs gcc only).
* **Not analysed:** every AVX-512 and VAES kernel (Valgrind does not
  implement AVX-512, and no hosted runner is guaranteed to carry it);
  the AES-NI / PCLMULQDQ AES-GCM kernels (the AES-GCM drivers force the
  scalar path); the opt-in AVX2 X25519 batch kernel; scalar tiers that the
  default wiring replaces; clang in CI, and the clang shared object; and
  **all of AArch64** — NEON, the
  Crypto Extensions and SVE2. The tool and the gate are written for
  `arm64-linux` and the Arm list is in place, but this PR could not run
  Valgrind on AArch64 and does not wire an unvalidated lane: running
  `tools/check_ct_operand.py` on an AArch64 host with Valgrind (SVE2 still
  excluded, since Valgrind does not implement SVE) is what it takes.
* **Not executed by any driver:** Argon2id's password-dependent addressing,
  whose divide `J2 % lanes` is on a secret dividend by RFC 9106's design
  (the drivers deliberately do not taint the password; see
  `tools/check_secret_division.py`).

### Runtime modes: DOITM and PSTATE.DIT

The vendor lists are contracts about a mode. Arm: with PSTATE.DIT = 0 "the
architecture makes no statement about the timing properties of any
instructions". Intel: the listed instructions are data-operand independent
in DOIT mode, and parts that predate Ice Lake (Core) or Gracemont (Atom) and
do not enumerate the control may be assumed to behave that way.

The library **does not enable either mode on its own**, and it now reports
what it can see (`include/ama_dispatch.h`):

* `ama_ct_hw_mode_status()` — ENABLED / DISABLED / NOT_IMPLEMENTED /
  UNKNOWN for the calling thread; `ama_ct_hw_mode_control()` names the
  control (`arm-pstate-dit`, `intel-doitm`, `none`).
* `ama_ct_hw_mode_enable()` — on AArch64 Linux with FEAT_DIT (HWCAP_DIT) it
  sets PSTATE.DIT for the calling thread, which EL0 may do, and returns
  ENABLED. Elsewhere it changes nothing.

On x86-64 the library cannot know: DOITM is enumerated in
`IA32_ARCH_CAPABILITIES` and controlled by `IA32_UARCH_MISC_CTL`, both MSRs,
and `RDMSR` from user mode faults (measured, SIGSEGV on Linux). An Intel part
that enumerates `IA32_ARCH_CAPABILITIES` therefore reports UNKNOWN; one that
does not, and every non-Intel part, reports NOT_IMPLEMENTED.
`tests/c/test_ct_hw_mode.c` checks each answer against its own CPUID / HWCAP /
`MRS` probe; it was run on x86-64 and, under QEMU, on AArch64 with and
without FEAT_DIT, and each of three planted defects (x86 enable claiming
ENABLED, AArch64 enable not writing DIT, the HWCAP guard removed) makes it
fail.

**Deployment requirement.** Where the guarantee matters:

* **AArch64:** call `ama_ct_hw_mode_enable()` on every thread that performs
  secret-dependent operations, and check that it returned
  `AMA_CT_HW_MODE_ENABLED`. On a core without FEAT_DIT there is no vendor
  timing statement for any instruction.
* **Intel x86-64:** DOITM must be enabled by privileged software (the OS or
  hypervisor writing `IA32_UARCH_MISC_CTL[0]` on every logical processor);
  the library cannot assume or verify that privilege. On parts that do not
  enumerate the control, Intel's statement covers only the generations it
  names.
* **AMD and other x86-64 vendors:** this repository found no vendor list
  equivalent to Intel's; the gate's x86-64 allowlist is Intel's, and makes
  no claim about other vendors' parts.

### Out of scope, named

This gate does not establish resistance to power, electromagnetic or
acoustic side channels, fault attacks, speculative-execution leaks, or
frequency-scaling channels (Hertzbleed); Intel's own list says a listed
instruction is not thereby resistant to power, thermal or frequency
channels. It does not establish that the library is constant-time. It
checks one thing — that no secret-derived operand reaches a division,
floating-point or square-root operation, plus the inventory of unlisted
instructions — on the paths the taint drivers execute, on the builds and the
tier named above.
