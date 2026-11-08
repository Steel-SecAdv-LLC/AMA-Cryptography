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
`secp256k1-seckey`, `ml-dsa-sign`, `ml-kem-keygen`, `hkdf`, `frost-sign`,
`aead-bulk` and `aead-verify`.
Four targets have a taint driver and no instruction-count driver, each for a
reason in `_TAINT_ONLY`: ML-DSA signing's rejection loop and ML-KEM key
generation's SampleNTT do seed-dependent work by construction, and FROST's
binding factors hash the group public key into variable-time public-point
arithmetic.  The oldest of them, `slhdsa-sign`, has no instruction-count
driver because SLH-DSA signing does different work per key by construction (the
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
`check_ct_operand.op_class` (the op names say what they compute); BRANCH when
a tainted value the instruction used flows, through IR temporaries, into an
exit guard or an indirect target; and OTHER when one flows anywhere else (a
register, memory, a helper). BRANCH is a property of that data flow, not of
which instruction owns the exit statement: CI's gcc 15.2.0 build put a `je`
in `poly_basemul` whose consumption was recorded with no exit of its own, and
the first version of the tool, which tagged only the exit's instruction,
printed it as an ordinary unlisted instruction. A site is labelled a class (a)
branch only with BRANCH and without OTHER, so an unlisted instruction whose
result also feeds a branch keeps its operand-latency question. The gate
disassembles every recorded address with objdump (Intel syntax on x86-64,
`-M no-aliases` on AArch64, so mnemonics are the architectural names the lists
use; condition code synonyms such as `CMOVZ`/`cmove` are learned by
assembling both spellings, each probe read back by its own label so that
section padding cannot shift the pairing — positional pairing broke on
MinGW's COFF output — and checked on ELF, COFF and Mach-O objects) and
reports `symbol+offset`, the object, the execution count and the call chain.

### The verdict: blocking, with no exemption

* **Every consuming instruction must be on the vendor list.** The run FAILS
  if a secret-derived operand reaches a division, floating-point or
  square-root operation, or any instruction Intel's DOIT list (x86-64) or
  Arm's DIT list (AArch64) does not name. There is no exemption list.
* **A branch is decided by the bit-exact instrument, in the same run.** A
  site whose only tainted use is a conditional exit or an indirect target
  (BRANCH without OTHER) is leakage class (a), and this tool's byte-granular
  shadow over-approximates it. When a run has any such site, the gate runs
  the same driver under Memcheck and FAILS on any conditional jump or move on
  the secret; it never passes a branch on the strength of its label.
* **`--inventory`** reports unlisted sites without failing. It is a
  measurement mode for bringing up a new target; CI never uses it
  (`tests/test_ct_operand_gate.py` fails if a CI step does).
* **A failing site explains itself.** For each consuming instruction outside
  the list, the gate re-runs the driver with `--ct-dump-ir-at` and prints the
  VEX IR under that instruction's IMark: which statement read the secret. It
  exists because the first AArch64 verdict named an `mrs` of DCZID_EL0, which
  VEX lifts to a constant and which takes no data operand. Its first output
  (CI, `fbefa4c`) answered that: VEX had chased a conditional branch in glibc's
  memset and lifted the `mrs` as `PUT(x5) = ITE(guard, 0x10, GET(x5))`, and the
  tool charged the unchanged arm, which held a secret from the caller.
* **A guarded write is charged its own value only.** An ITE whose guard was
  computed under an earlier instruction is a speculatively chased write, not a
  select the instruction performs. For it, the arm that passes the register
  through unchanged is not an operand, and the guard is the branch's. A CMOV or
  CSEL computes its condition under its own IMark and keeps the ordinary rule,
  under which every arm is an operand. amd64 VEX does not chase conditional
  branches, so the rule acts on AArch64 only. CI's AArch64 lane is its pin, and
  `test_a_guarded_write_does_not_charge_the_register_it_left_unchanged` probes
  it on an arm64 host.
* **`--static`** is the same rule, taken over every instruction of named
  archive members, for kernels Valgrind cannot execute (AVX-512, VAES): each
  must be on the list, a control transfer, or padding. Without taint it
  cannot tell secret from public, so it holds both to the rule.

### What the gate found, and how each was cured (2026-11-08)

The first version of this gate reported unlisted instructions as an open
inventory. Every row was then removed at source, the verdict made blocking,
and the targets extended. Each cure's pin is the blocking gate itself: on
the tree before the cure the same command fails with the row named.

| Row | Cause | Cure |
|---|---|---|
| `REP MOVSQ`, `REP STOSQ` (SHA-2, SHA-3 state and buffer copies) | gcc's inline `memcpy`/`memset` expansion; Intel lists the REP forms only at byte, word and doubleword width | `CMakeLists.txt`: GCC on x86-64 builds with `-mmemcpy-strategy=`/`-mmemset-strategy=unrolled_loop:256,rep_byte:-1` (unrolled `MOV` up to 256 bytes, listed `REP MOVSB`/`STOSB` above, public count). Configure fails if GCC rejects the flags. |
| `SHUFPS` (`ama_shake256`, x4 squeeze) | byte-wise `store64_le` vectorised across lanes | `src/c/ama_sha3.c`: one 64-bit store, as `ama_ascon_store64` already was |
| `SHUFPS`, `CWDE` (Kyber compress, Montgomery reduction) | vectorised 64-bit product narrowing; `(int32_t)(int16_t)u` as `CWDE` | `src/c/ama_kyber.c`: Compress_d kept scalar by a value barrier; normalised coefficients zero-extended; `montgomery_reduce` from the unsigned residue with an exact correction, bit-identical (`tests/c/test_kyber_montgomery.c`, 93.7 million inputs, fails on a dropped correction term) |
| `LEAVE` (`ama_ed25519_select15_avx2`) | twelve YMM accumulators spilled to a realigned frame | `src/c/avx2/ama_ed25519_select_avx2.c`: even and odd entries fold into one accumulator set |
| `MOVHLPS` (Ascon key, `sc_is_zero`), `MOVMSKPS` (`sc_is_zero`, clang) | SLP-merged adjacent loads; vectorised OR reduction | value barriers in `src/c/ama_ascon.c` and `src/c/ama_secp256k1.c` |
| `XSAVE`/`XRSTOR` (clang) | ld.so's lazy-binding trampoline in the gate's own driver | the driver runs with `LD_BIND_NOW=1`, as the project links its binaries and the shipped `.so` (`-z relro -z now`); a harness artifact, not library code |
| clang FP-domain moves and logic (`VMOVAPS`, `VMOVUPS`, `VXORPS`, `VANDNPS`, `VMOVLHPS`, `MOVAPD`, `MOVSD`, `SHUFPS`, `SHUFPD`, `ANDPS`, `VSHUFPS`, `VBLENDPS`) | clang's execution-domain pass puts load-to-store chains with no integer instruction in the FP domain, and auto-vectorises scalar secret loops with FP shuffles | AVX2 Keccak x4 restructured plane by plane with an integer pack/unpack (`src/c/avx2/ama_sha3_avx2.c`); Argon2 G with every XOR fused into a BlaMka round (`src/c/avx2/ama_argon2_avx2.c`); scalar secret loops pinned to general-purpose registers in the Kyber and ML-DSA decode, encode, pack and NTT-tail code, base64 `in_range`/`enc6` and Ed25519 `fe_cswap` (`internal/ama_ct_barrier.h`, `ama_ct_value_barrier_u32`) |
| `DIV` (Argon2id `argon2_index_alpha`), **a real secret division** | `J2 % lanes` and `(start + z) % lane_length` on password-derived words | `src/c/ama_argon2.c`: Lemire-Kaser-Kurz `fastmod_u32` for the lane (exact for all 32-bit n and every lane count, checked exhaustively: 1,095,216,660,480 pairs) and one masked subtraction for the index; the reference-lane selection by mask. RFC 9106 vectors unchanged. |
| `VMOVAPS`, `VMOVUPS`, `VXORPS`, `VMOVLHPS` (static, clang: VAES GCM, AVX-512 Keccak x4) | a stack copy of the broadcast YMM round keys; the `set_epi64x` pack; a load-xor-store theta pass | `src/c/avx2/ama_aes_gcm_vaes_avx2.c` broadcasts each round key at its use from a pointer re-read per call (`vaes_rk_fresh`: clang otherwise hoists the keys out of the block loops and spills them), and assembles partial blocks in general registers rather than through `memcpy`, whose call spilled the keystream; mutation: removing either brings back 10 and 3 unlisted moves; `src/c/avx512/ama_sha3_x4_avx512.c` packs in the integer domain and unrolls theta under clang (not under gcc, where unrolling realigns the frame and leaves through `LEAVE`) |
| `MOVHLPS` (`x25519_scalarmult`, MULX+ADX ladder, gcc 13; found with `--assume-adx`) | gcc SLP-vectorised `fe64_cswap` (`PXOR`/`PAND` on limb pairs) and moved halves back to general registers: 4 sites, 510 times per scalar multiplication, on the path every ADX-capable CPU runs and Valgrind's CPUID never selected | `src/c/fe64.h` and `src/c/fe51.h`: each swap word through a value barrier, which keeps the swap scalar; mutation: the pre-fix tree fails at the 4 sites |
| `MOVHLPS` (`x25519_scalarmult+0x12b`, CI gcc 15.2 only) | the 32-byte scalar copy and clamp moved through XMM registers | `src/c/ama_x25519.c` `x25519_copy_clamp`: four 64-bit words through value barriers; gcc 13/14 and clang never emitted the row, so locally the cure is SMOKE and CI's gcc 15 run is its pin |
| `FMOV` general <-> SIMD (AArch64, gcc 13; first AArch64 run, `x25519`) | the auto-vectoriser and register allocator moved the portable C's secret words into the SIMD file: 514 such FMOVs over the library (static census of the cross-built archive), among them the X25519 ladder's output, its all-zero check, P-256 and ML-DSA signing, SHA-256 and bitsliced AES | `CMakeLists.txt`: every portable source on AArch64 GCC/Clang compiles with `-mgeneral-regs-only` (configure fails if refused), after which those objects contain no SIMD instruction at all; the NEON kernels compile without the auto-vectoriser; 514 -> 5, and the 5 left move public values (NTT zetas, the GCM length block, the ChaCha20 block counter) |
| `FMOV` from NEON intrinsics (Keccak theta, AES-256 key schedule; clang: the GHASH multiply) | gcc lowers `vgetq_lane_u64/u32(v, 0)` to FMOV and `vcombine_u64(vcreate_u64(..))` to FMOV + INS; clang routed GHASH's Karatsuba halves (H and the accumulator) through general registers | `src/c/neon/ama_neon_dit.h` pins lane moves to UMOV, DUP and INS; `ghash_mul_neon` keeps every operand in its vector register (PMULL/PMULL2 on lanes in place); NEON AES-GCM equivalence and the SHA-3, ML-KEM, ML-DSA NEON KAT sweeps pass under QEMU |
| `CDQE` (`ama_dilithium_ntt_avx2`, `_invntt_avx2`, CI gcc 15.2) | `(int64_t)` of a secret coefficient in the scalar len <= 4 layers and the Montgomery fallback, emitted as CDQE (Intel lists MOVSXD, not CDQE) | `src/c/avx2/ama_dilithium_avx2.c` `dil_sext32`: zero-extend through a value barrier, then `(z ^ 2^31) - 2^31`; exact for all 2^32 inputs; gcc 13/14 and clang emit no CDQE/CWDE/CDQ in the object |
| Memcheck-confirmed branch in `ama_argon2_g_avx2` (`argon2id`, CI gcc 15.2) | the loop iterated on a pointer derived from the reference block's address, which is password-derived by RFC 9106's design, so its exit inherited that taint | the reference index is declassified where it becomes an address (AMA_TESTING_MODE only; see the declassification list) |
| `VMOVUPS` (`ama_chacha20_block_x8_avx2`, clang; reached once `aead-bulk` ran 768 bytes) | sixteen saved initial rows beside sixteen working rows overflowed the YMM file, and clang spilled the key-word broadcasts (VBROADCASTSS from memory, merged with the add-back) and the transposed output with VMOVUPS | `src/c/avx2/ama_chacha20poly1305_avx2.c`: the initial rows are re-broadcast at the add-back, each key word from a general register through a volatile barrier (`chacha_bcast_key_word`), and each transposed half is stored as soon as it is formed; clang, gcc 13 and gcc 14 now emit no FP-domain move in the kernel; mutation: the pre-fix kernel fails at its 4 sites |

The instrument itself had two false positives, fixed and pinned: an `OR`
with all ones or an `AND` with zero now yields an untainted result (gcc 14's
`or rax, -1` before a public `div` carried a stale secret into the dividend;
probe `k_ones_div`), and objdump's selector-immediate aliases of `PCLMULQDQ`
(`pclmullqlqdq` ...) are normalised to the listed name.

Extending the targets to every secret-handling primitive found more, also
cured at source and pinned by the drivers that found them
(`check_ghash_constant_time.py --taint`):

* **ML-DSA** (`ml-dsa-sign`, 64 Memcheck reports before): MakeHint
  short-circuited on the secret r0, so a rejected attempt's timing said which
  clause fired -- now branch-free; the hint positions of every attempt,
  rejected ones included, were written at a secret-dependent index -- now
  the bits go to fixed slots and are packed only once the attempt is
  accepted; and the values FIPS 204 publishes or that decide only a
  discarded candidate are declassified at their computation: rho, c~, the
  accepted z and hint, each per-attempt rejection decision (FIPS 204 sec.
  3.6.1 note 3: signing's timing leakage is information about the message,
  not the private key) and each RejBoundedPoly accept bit (the accept pattern
  of uniform nibbles carries no information about any accepted coefficient).
* **ML-KEM key generation** (`ml-kem-keygen`): rho, the encapsulation key's
  trailing field, declassified before SampleNTT.
* **FROST** (`frost-sign`): the zero-scalar, consumed-nonce and
  own-commitment verdicts it returns as errors, declassified.
* **Bulk AEAD decryption** (`aead-bulk`): the tag verdict that bounds the
  decryption (so a forgery writes no plaintext) is the `VERIFY_FAILED` the
  function returns; declassified in the scalar, AES-NI, VAES, NEON and
  ChaCha20-Poly1305 decrypts.
* **Argon2id** (`argon2id`, operand-only): the reference block index, where
  it becomes an address. Unlike every entry above it is not published: it is
  password-derived, and the address channel it opens is RFC 9106 sec. 3.4's
  design (data-dependent addressing), which no implementation can remove and
  which the operand-only target excludes by definition. The index's
  computation stays measured and the blocks' contents stay tainted; gcc 15.2's
  pointer-induction loop in `ama_argon2_g_avx2` is what made the address's
  taint reach a branch.

**Measured, 2026-11-08 (x86-64):** all 24 targets (the 18 above, plus
`ml-dsa-sign`, `ml-kem-keygen`, `hkdf`, `frost-sign`, `aead-bulk` and the
operand-only `argon2id`) pass the blocking gate on the archive under gcc
13.3.0, gcc 14.2.0 and clang 18.1.3; `aead-bulk` also pinned to
`aes-gcm-aesni`, the pin confirmed by the dispatcher; 12 targets on the LTO
shared object; the static listing of the production AVX-512 Keccak and VAES
GCM objects under gcc and clang. CI (`dudect.yml`, `secret-operand-check`
and `secret-operand-check-arm64`) runs every one of these, fail-closed.

### Mutation evidence (section 6.2)

Each plant fed a secret into one real kernel, `kyber_compress_d_impl`
(inlined into `poly_compress`, the ML-KEM re-encryption inside
decapsulation: the KyberSlash site), and was reverted after the run.

| Class | Plant | Result (`--target kyber-decaps`) |
|---|---|---|
| Division | `quotient = n / q` with `q` volatile | FAIL: 24 `div` sites, class DIV, in `poly_compress` and its inlined copies in `kyber_decapsulate_internal`; also FAIL on the LTO shared object (`div rcx` at `poly_compress+0xfe`) |
| Floating point | `(double)quotient * one`, `one` volatile | FAIL: `cvtsi2sd`, `mulsd`, `cvttsd2si`, class FP, 24 sites each |
| Square root | `sqrt((double)q * (double)q)` | FAIL: `sqrtsd` ×16 and `sqrtpd` ×4 (gcc vectorised one copy), class SQRT, plus the conversions as FP |
| Multiply | `quotient * one`, `one` volatile | PASS by default (the vendor lists admit integer multiply); with `--deny IMUL,MUL,MULX` FAIL; the planted run carries 44 two-register `imul` sites against the unplanted run's 20 under the same flags, and the 24 added are in `poly_compress` (16) and `kyber_decapsulate_internal` (8), the same 24 inlined copies the divide plant hit |

`tests/test_ct_operand_gate.py` pins the instrument itself on a small
program (in CI from `ci.yml`'s `security-checks` job, the one pytest lane that
installs Valgrind, under `AMA_CI_REQUIRE_MEMCHECK` so that a skip fails; until
2026-11-07 these tests skipped on every pytest lane and pinned nothing in CI): a secret divide, a secret double multiply and a secret square root
are reported with the right class, a secret multiply is consumed but in no
blocking class, and a divide of a declassified value is not recorded.

### Tiers analysed, and not

* **Analysed, dynamically (x86-64, Valgrind's CPU model: AVX2, AES-NI,
  PCLMULQDQ, no AVX-512):** the default dispatch wiring on that model (AVX2
  Kyber and ML-DSA NTT, BMI2 Keccak, AVX2 Keccak x4, the AVX2 Ed25519
  niels-select fold, AVX2 ChaCha20 x8 and Argon2 G, AES-NI + PCLMULQDQ GCM),
  plus the scalar AES-GCM the `ghash` and `aead-verify` drivers force and
  the AES-NI tier pinned; on the archive under gcc and clang and on the
  shipped `.so`.
* **Analysed, dynamically, with `--assume-adx`:** the X25519 MULX+ADX ladder
  and the P-256/384/521 MULX Montgomery multiply, the kernels production
  selects on every ADX-capable x86-64 CPU. Valgrind 3.22 executes ADCX/ADOX
  but reports CPUID ADX clear, so until 2026-11-08 no Valgrind lane (taint,
  count or operand) had selected them. The AMA_TESTING_MODE archive honours
  `AMA_TESTING_ASSUME_ADX=1` when CPUID reports BMI2 (`src/c/ama_cpuid.c`;
  absent from every shipped object, `tests/c/test_cpuid_assume_adx.c`), and
  a run is trusted only when the library confirms it and, for the operand
  gate, a MULX consumed the secret. The first such run found gcc's
  vectorised `fe64_cswap` (below). The Ed25519 MULX instantiation is an
  opt-in benchmark override, off by default, and is not measured.
* **Analysed, dynamically (AArch64, natively on `ubuntu-24.04-arm`):** the
  same targets against Arm's DIT list, on the NEON and Crypto Extensions
  tiers that runner's dispatcher selects, under gcc (the runner's compiler).
  clang on AArch64 (the macOS arm64 wheels) is not run under Valgrind; its
  code shape was checked statically for the GPR <-> SIMD moves above.
* **Analysed, statically:** the AVX-512 Keccak x4 and the VAES AES-GCM
  kernels, every instruction of their production objects, under gcc and
  clang. This settles class (c) for them as an over-approximation; their
  classes (a) and (b) are not dynamically checked, because nothing here
  executes them under taint. They are functionally checked on AVX-512
  hardware (`kat_sweep__sha3-avx512x4__*`, `test_aes_gcm_vaes_equiv`).
* **Not analysed:** SVE2 (Valgrind implements no SVE); the opt-in Ed25519
  MULX override (`ama_ed25519_set_mulx_override(1)`); scalar tiers the
  default wiring replaces, except where a `--dispatch-only` pin exists; the
  opt-in AVX2 X25519 batch kernel's alternative selections; MSVC builds.
* **Argon2id** (`argon2id`, operand-only): its memory addressing is
  data-dependent by RFC 9106's design, which no implementation can remove, so
  it is not a Memcheck taint target; how the index is computed is
  implementation, and class (c) and the branch question are checked.

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
