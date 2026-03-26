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
4. **Evaluate**: If |t| > 4.5, the timing distributions are statistically distinguishable at 99.999% confidence — indicating timing leakage

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
| Kyber-1024 decaps | Implicit rejection timing | Class 0: valid ciphertext / Class 1: corrupted ciphertext |
| ML-DSA-65 sign | Message-independent timing | Class 0: zero message / Class 1: 0xFF message |

## Interpreting Results

### PASS (|t| < 4.5)

No statistically significant timing difference detected between the two input classes. The implementation is empirically constant-time at the 99.999% confidence level.

### FAIL (|t| >= 4.5)

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
