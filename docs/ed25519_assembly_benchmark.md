# Ed25519 Assembly Benchmark — donna vs fe51

**Date:** 2026-03-20
**Branch:** `claude/ed25519-assembly-optimization-IIZOZ`
**Platform:** Intel Xeon @ 2.10GHz (AVX-512, SHA-NI, AES-NI, BMI2)
**Compiler:** GCC 13.3.0, C11, `-O3 -march=native -funroll-loops`

## Summary

The ed25519-donna x86-64 assembly path delivers a massive improvement over
AMA's fe51 C implementation across all Ed25519 operations. The donna path
uses a precomputed 256-entry Niels basepoint table with inline x86-64
assembly for constant-time table selection, plus sliding-window
double-scalar multiplication for verification.

## Results (median of 3 runs)

| Operation | fe51 (default) | donna assembly | Delta | Cycles (fe51) | Cycles (donna) |
|---|---:|---:|---:|---:|---:|
| keygen | 22,189 ops/s | 85,715 ops/s | **+286%** | 94,613 | 24,455 |
| sign (240B) | 21,242 ops/s | 72,388 ops/s | **+241%** | 99,204 | 29,009 |
| verify (240B) | 10,082 ops/s | 25,823 ops/s | **+156%** | 208,274 | 81,477 |

Benchmark parameters: 50K keygen, 50K sign, 20K verify iterations per run.

## Raw Runs

### fe51 Baseline (AMA_ED25519_ASSEMBLY=OFF)

```
Run 1:  keygen: 22189 ops/sec  94642 cycles/op
        sign:   20976 ops/sec 100115 cycles/op
        verify: 10067 ops/sec 208608 cycles/op

Run 2:  keygen: 22287 ops/sec  94225 cycles/op
        sign:   21290 ops/sec  98637 cycles/op
        verify: 10100 ops/sec 207912 cycles/op

Run 3:  keygen: 22112 ops/sec  94971 cycles/op
        sign:   21242 ops/sec  98861 cycles/op
        verify: 10082 ops/sec 208301 cycles/op
```

### donna Assembly (AMA_ED25519_ASSEMBLY=ON)

```
Run 1:  keygen: 85715 ops/sec  24500 cycles/op
        sign:   72330 ops/sec  29033 cycles/op
        verify: 25823 ops/sec  81321 cycles/op

Run 2:  keygen: 85968 ops/sec  24428 cycles/op
        sign:   72388 ops/sec  29010 cycles/op
        verify: 25634 ops/sec  81923 cycles/op

Run 3:  keygen: 85931 ops/sec  24438 cycles/op
        sign:   72457 ops/sec  28983 cycles/op
        verify: 25866 ops/sec  81188 cycles/op
```

## Analysis

The 3-4x improvement in keygen/sign comes from donna's optimized Niels
basepoint table (256 entries of precomputed {y-x, y+x, 2dxy}) combined
with inline x86-64 assembly for constant-time table selection. AMA's fe51
implementation uses a 16-entry table with a C-based constant-time scan.

The 2.5x improvement in verify comes from donna's sliding-window
double-scalar multiplication (`ge25519_double_scalarmult_vartime`), which
computes [s]B + [h]A in a single interleaved loop. AMA's fe51 computes
them separately and adds.

The flag defaults to OFF because:
1. It is x86-64 only (no ARM/AArch64 support)
2. The vendored code is additional attack surface to audit
3. The fe51 default is portable and correct
