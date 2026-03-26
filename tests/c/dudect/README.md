# dudect - Vendored Constant-Time Verification Library

This directory contains a vendored implementation of the dudect methodology for
empirical constant-time verification.

## Origin

- **Paper**: "Dude, is my code constant time?" by Oscar Reparaz, Josep Balasch, and Ingrid Verbauwhede
- **Paper URL**: https://eprint.iacr.org/2016/1123.pdf
- **Reference Implementation**: https://github.com/oreparaz/dudect
- **License**: MIT
- **Vendored Date**: 2026-03-26

## What is dudect?

dudect uses statistical hypothesis testing (Welch's t-test) to detect timing
leakage in cryptographic implementations. It measures execution times for two
classes of inputs and tests whether the timing distributions are statistically
distinguishable.

A |t| value exceeding 4.5 indicates timing leakage at the 99.999% confidence
level.

## Usage

See `tests/c/test_dudect.c` for harness examples and `docs/constant-time-testing.md`
for detailed documentation.
