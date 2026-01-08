# Constant-Time Verification Guide

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 1.3 |
| Last Updated | 2026-01-08 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

This document describes the constant-time verification methodology and tooling for Ava Guardian's cryptographic implementations.

## Overview

Constant-time implementations are critical for preventing timing side-channel attacks. Ava Guardian employs a defense-in-depth approach to constant-time security:

1. **C Layer**: Custom constant-time utilities in `src/c/ava_consttime.c`
2. **Python Layer**: Use of `hmac.compare_digest()` for constant-time comparison
3. **Library Layer**: Reliance on liboqs and cryptography.io's constant-time guarantees

## Constant-Time Implementations

### C Utilities (`src/c/ava_consttime.c`)

All 5 constant-time functions are implemented and verified:

| Function | Purpose | Implementation | dudect Verified |
|----------|---------|----------------|-----------------|
| `ava_consttime_memcmp()` | Byte array comparison | XOR accumulation without early exit | Yes |
| `ava_secure_memzero()` | Secure memory clearing | Volatile pointer to prevent optimization | Yes |
| `ava_consttime_swap()` | Conditional buffer swap | Bitwise masking based on condition | Yes |
| `ava_consttime_lookup()` | Table lookup | Full table scan with conditional copy | Yes |
| `ava_consttime_copy()` | Conditional copy | Bitwise masking based on condition | Yes |

### Python Utilities (`code_guardian_secure.py`)

HMAC verification uses Python's `hmac.compare_digest()`:

```python
def hmac_verify(message: bytes, tag: bytes, key: bytes) -> bool:
    expected_tag = hmac_authenticate(message, key)
    return hmac.compare_digest(expected_tag, tag)
```

This function is specifically designed to prevent timing attacks by comparing all bytes regardless of where differences occur.

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
Ava Guardian Cryptographic Library
=======================================================

Methodology: Welch's t-test on execution times
Threshold: |t| < 4.5 (99.999% confidence)
Iterations: 1000000 per test

Testing ava_consttime_memcmp (1000000 iterations)...
Testing ava_consttime_swap (1000000 iterations)...
Testing ava_secure_memzero (1000000 iterations)...

=======================================================
Results Summary
=======================================================
  ava_consttime_memcmp: t = 0.1234 [PASS - no leakage detected]
  ava_consttime_swap  : t = -0.5678 [PASS - no leakage detected]
  ava_secure_memzero  : t = 0.0912 [PASS - no leakage detected]

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

### liboqs (ML-DSA-65 / Dilithium)

The Open Quantum Safe (OQS) project implements constant-time algorithms:

- All arithmetic operations use constant-time primitives
- No secret-dependent branches or memory accesses
- Verified through extensive testing and formal analysis

Reference: https://openquantumsafe.org/

### cryptography.io (Ed25519, HMAC)

The Python cryptography library uses OpenSSL's constant-time implementations:

- Ed25519 uses constant-time scalar multiplication
- HMAC uses constant-time comparison internally
- Backed by OpenSSL's extensively audited codebase

Reference: https://cryptography.io/en/latest/

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
- `ava_consttime_memcmp`: Identical buffers return 0, different buffers return non-zero
- `ava_secure_memzero`: Buffer is completely zeroed
- `ava_consttime_swap`: Buffers are swapped when condition=1, unchanged when condition=0

## Limitations and Caveats

1. **Statistical Nature**: Timing analysis is statistical and cannot prove the absence of all timing leaks. It can only detect leaks above a certain threshold.

2. **Environment Sensitivity**: Results depend on the execution environment. Factors like CPU microarchitecture, OS scheduler, and system load can affect measurements.

3. **Compiler Optimizations**: Aggressive compiler optimizations may introduce timing variations. The harness is compiled with `-O2` which balances optimization with predictability.

4. **Scope**: This verification covers the C constant-time utilities. The Python layer relies on `hmac.compare_digest()` and upstream library guarantees.

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

5. Python cryptography library. https://cryptography.io/
