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

A |t| value exceeding `DUDECT_T_THRESHOLD` indicates timing leakage at the
99.999% confidence level.

That threshold is **5.0, not the 4.5 usually quoted for dudect**, and the
difference is not a matter of taste. 4.5 is the two-sided critical value of a
*single* Welch t-test. The statistic these harnesses compute is the maximum
over 21 percentile-cropped rungs of the same samples (`dudect_percentile.h`,
following eprint 2016/1123 §3.3), and the maximum of 21 correlated t-values
has a measurably wider null distribution than any one of them — 6,000,000 null
replicates put E|t| at 1.618 and sd at 1.717, against 0.798 and 1.000 for a
single t. Comparing that maximum to 4.5 claimed a confidence the construction
does not have; `P(|t| >= 4.5)` under the null measures 7.2e-5, seven times the
1e-5 the "99.999%" asserts, while `P(|t| >= 5.0)` measures 6.5e-6. Upstream
dudect takes the same maximum and quotes 10 and 500 for the same reason.

The calibration is re-derived on every run by `dudect_cropped_self_test()`,
which fails if a change to the rung ladder or the reduction moves the null out
of its measured band.

### Class staging

A lane must differ between its two classes in the property under test and in
nothing else, and that includes the *address* of the input. Handing the timed
call one of two per-class buffers leaves the classes reading two different
addresses, which is a difference a load's timing legitimately depends on —
and one that is fixed for a given binary on a given host, so it reproduces
every round with the same sign and is indistinguishable from a leak.

Measured with the Ascon-AEAD128-encrypt lane's own cipher call and *identical
key data in both classes*: placing class 0's key across two cache lines drives
|t| to 13.5–30.9, over threshold in 10 of 10 runs. Staged through one shared
buffer the same measurement reports 0 of 10. Every lane therefore copies the
selected class's input into a single cache-line-aligned buffer
(`dudect_stage()`) before the timed region.

## Usage

See `tests/c/test_dudect.c` for harness examples and `docs/constant-time-testing.md`
for detailed documentation.
