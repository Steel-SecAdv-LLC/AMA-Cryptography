# Benchmark Baseline History

> **Why this file exists.** `benchmarks/baseline.json` drives the CI
> regression-detection gate. Silent changes to its `baseline_value`
> entries — whether lowering (which hides code regressions) or raising
> (which creates noisy follow-up failures) — undermine the gate. This
> document catalogues observed silent changes and anchors the guard
> put in place to prevent them going forward.

## The guard

Every PR that modifies `benchmarks/baseline.json` must include, in its
commit messages and/or the PR body, for **each primitive whose
`baseline_value` changed**:

1. **A line-item mention by name** of the primitive (its JSON key).
2. **At least one measured ops/sec (or latency) reading.**
3. **The CI runner identifier** on which the measurement was taken
   (e.g. `ubuntu-latest`, `macos-14`, `benchmark_c_raw`, `self-hosted`).

Enforcement mechanisms:

- `.github/workflows/baseline-guard.yml` runs
  `benchmarks/check_baseline_justification.py` on every PR touching
  `benchmarks/baseline.json` and fails CI if any of the three
  requirements is missing.
- `.github/CODEOWNERS` routes review of `benchmarks/baseline.json`,
  `benchmarks/check_baseline_justification.py`, and
  `.github/workflows/baseline-guard.yml` to
  `@Steel-SecAdv-LLC`.

The script is deterministic and reproducible locally:

```bash
python benchmarks/check_baseline_justification.py \
    --base-ref origin/main \
    --head-ref HEAD \
    --pr-body "$(gh pr view --json body -q .body)"
```

## Documented silent changes (pre-guard)

These are the changes the guard is designed to prevent. Both pass their
own authored CI at the time they landed because no such guard existed.

### `c9f4722` — "SIMD dispatch resolution: Kyber + Dilithium NTT/invNTT/pointwise, production hardening" (2026-04-04)

Author: `devin-ai-integration[bot]`. 10 baselines **lowered** without
any mention in the PR body:

| Primitive | Before | After | Change |
| --- | ---: | ---: | ---: |
| `ama_sha3_256_hash` | 15,000 | 12,450 | **-17%** |
| `hmac_sha3_256` | 12,000 | 8,370 | **-30%** |
| `ed25519_keygen` | 10,600 | 3,650 | **-66%** |
| `ed25519_sign` | 8,527 | 3,470 | **-59%** |
| `ed25519_verify` | 3,416 | 1,810 | **-47%** |
| `hkdf_derive` | 6,500 | 5,210 | **-20%** |
| `full_package_create` | 280 | 180 | **-36%** |
| `full_package_verify` | 380 | 320 | **-16%** |
| `dilithium_keygen` | 500 | 425 | **-15%** |
| `dilithium_sign` | 140 | 240 | +71% |
| `dilithium_verify` | 530 | 410 | **-23%** |

The PR title advertised SIMD *additions*, which should raise
performance, not lower expectations of it.

### `6b2cf82` — "Finalize AMA Cryptography: All 11 engineering tasks across 3 tiers" (2026-04-04)

Author: `devin-ai-integration[bot]`. All baselines **raised 9–10×**
without line-item justification:

| Primitive | Before | After | Multiplier |
| --- | ---: | ---: | ---: |
| `ama_sha3_256_hash` | 12,450 | 113,388 | **9.1×** |
| `hmac_sha3_256` | 8,370 | 76,215 | **9.1×** |
| `ed25519_keygen` | 3,650 | 10,560 | **2.9×** |
| `ed25519_sign` | 3,470 | 10,430 | **3.0×** |
| `ed25519_verify` | 1,810 | 5,113 | **2.8×** |
| `hkdf_derive` | 5,210 | 53,193 | **10.2×** |
| `full_package_create` | 180 | 746 | **4.1×** |
| `full_package_verify` | 320 | 2,044 | **6.4×** |
| `dilithium_keygen` | 425 | 1,943 | **4.6×** |
| `dilithium_sign` | 240 | 1,918 | **8.0×** |
| `dilithium_verify` | 410 | 4,303 | **10.5×** |

The source-code changes in that commit were SVE2 additions (AArch64
only) — which cannot affect `ubuntu-latest` x86-64 CI performance.
The 10× jump is therefore not explained by code.

## What is **not** concluded

- The C primitives themselves have not been degraded. The commit
  history of `src/c/ama_{sha3,ed25519,kyber,dilithium,aes_gcm}.c`
  shows monotonic improvement (donna integration `3ea4aa6`, SIMD
  dispatch `86f02bd`/`c9f4722`, AVX2 wiring `2c26a90`, etc.).
  The code got faster; only the *baselines* moved unaccountably.

- The current baselines (post-`6b2cf82`, stable through v2.1.5)
  appear approximately honest. A local run of
  `build/bin/benchmark_c_raw --json` on an unloaded x86-64 host
  produces numbers within ±20% of the current baseline values.

The goal of this document plus the guard is therefore not to roll back
history but to stop the pattern from recurring.
