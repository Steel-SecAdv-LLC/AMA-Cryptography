# Benchmark Baseline History

> **Why this file exists.** `benchmarks/baseline.json` drives the CI
> regression-detection gate. Silent changes to its `baseline_value`
> entries — whether lowering (which hides code regressions) or raising
> (which creates noisy follow-up failures) — undermine the gate. This
> document catalogues observed silent changes and anchors the guard
> put in place to prevent them going forward.

## The guard

Every PR that modifies `benchmarks/baseline.json` or
`benchmarks/arm-baseline.json` must include, in its commit messages
and/or the PR body, for **each primitive whose
`baseline_value` changed**:

1. **A line-item mention by name** of the primitive (its JSON key).
2. **At least one measured ops/sec (or latency) reading.**
3. **The CI runner identifier** on which the measurement was taken
   (e.g. `ubuntu-latest`, `macos-14`, `benchmark_c_raw`, `self-hosted`).

Enforcement mechanisms:

- `.github/workflows/baseline-guard.yml` runs
  `benchmarks/check_baseline_justification.py` on every PR touching
  either baseline JSON and fails CI if any of the three requirements
  is missing.
- The benchmark-regression CI job passes `--require-runner-class` and
  `--require-populated-baseline`, so x86 and AArch64 matrix entries
  must consume their matching baseline file and no `baseline_value: 0`
  first-run placeholder can pass as a real regression floor.
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

## ChaCha20-Poly1305 / Argon2id AVX2 wiring (`perf: wire chacha20poly1305 + argon2 AVX2`)

Landed with `tests/c/test_chacha20poly1305.c`, `tests/c/test_argon2id.c`,
the dispatch hook in `ama_dispatch.c`, the `benchmark_c_raw` coverage
for both primitives, and the scalar-vs-AVX2 A/B harness that can be
toggled without a rebuild (`AMA_DISPATCH_NO_CHACHA_AVX2=1` and
`AMA_DISPATCH_NO_ARGON2_AVX2=1`).

Measured on x86-64 sandbox (median-of-N from `benchmark_c_raw`):

| Primitive                            | Scalar (µs) | AVX2 (µs) | Speedup |
| --- | ---: | ---: | ---: |
| ChaCha20-Poly1305 encrypt 256 B *    | 1.19        | 1.15      | 1.03×   |
| ChaCha20-Poly1305 encrypt 1 KB       | 3.59        | 1.70      | **2.11×** |
| ChaCha20-Poly1305 encrypt 4 KB       | 13.23       | 5.91      | **2.24×** |
| ChaCha20-Poly1305 encrypt 64 KB      | 208.2       | 90.8      | **2.29×** |
| Argon2id m=64 KiB, t=1, p=1          | 73.0        | 55.7      | **1.31×** |
| Argon2id m=1 MiB, t=1, p=1           | 755         | 562       | **1.34×** |

\* 256 B is below the 512 B 8-way threshold — AVX2 path is not
entered, and the matching latency is expected.

Correctness of the AVX2 paths is asserted byte-for-byte:
- ChaCha20 — against an independent RFC 8439 §2.3 reference block
  function embedded in `tests/c/test_chacha20poly1305.c`.
- Argon2 — against the scalar `argon2_G` via the
  `ama_test_force_argon2_g_scalar()` dispatch hook across six
  parameter combinations.

No baseline values in `benchmarks/baseline.json` were changed by the
wiring work; the entries above are new benchmark columns in the
`benchmark_c_raw` output, not entries the CI regression gate
currently tracks.

## 2026-05: Benchmark coverage expansion (no baseline_value changes)

In May 2026 the raw-C harness gained five new benchmark families to
close the gap list audited in the May 2026 review:

| Family                                     | Rows added to `benchmark_c_raw` |
|--------------------------------------------|---------------------------------|
| SLH-DSA (FIPS 205 L1, SHAKE-128s)          | `SLH-DSA-SHAKE-128s KeyGen` / `Sign` / `Verify` |
| secp256k1 pubkey-from-privkey              | `secp256k1 pubkey` |
| FROST 2-of-3 (RFC 9591)                    | `FROST round1 commit` / `round2 sign` / `aggregate` |
| Dilithium NTT kernel isolation             | `ML-DSA-65 NTT (scalar)` / `NTT (dispatch)` / `invNTT (scalar)` / `invNTT (dispatch)` |
| X25519 MULX/ADX kernel on-vs-off ratio     | `X25519 DH (MULX off)` / `X25519 DH (MULX on)` |

The Dilithium-NTT and X25519-MULX rows depend on benchmark/test-only
entry points added to `include/ama_cryptography.h`
(`ama_dilithium_ntt_bench`, `ama_dilithium_invntt_bench`,
`ama_x25519_set_mulx_override`). These are documented as **not part of
the production crypto surface** — they exist so a single shipped
binary can produce paired scalar-vs-dispatched and kernel-on-vs-off
rows without per-row rebuilds.

Sample raw-C medians on the sandbox host (Linux x86-64, GCC, AVX2,
ed25519-donna + ML-DSA AVX2 dispatched, MULX+ADX kernel available):

| Row | Median latency | Throughput |
|-----|---------------:|-----------:|
| X25519 DH (MULX off)         | ~75.1 µs | ~13,300 ops/s |
| X25519 DH (MULX on)          | ~51.5 µs | ~19,400 ops/s (**~1.46× over off**) |
| ML-DSA-65 NTT (scalar)       | ~1.26 µs | ~796,000 ops/s |
| ML-DSA-65 NTT (dispatch)     | ~1.04 µs | ~965,000 ops/s (**~1.21×**) |
| ML-DSA-65 invNTT (scalar)    | ~1.32 µs | ~759,000 ops/s |
| ML-DSA-65 invNTT (dispatch)  | ~1.11 µs | ~898,000 ops/s (**~1.18×**) |
| SLH-DSA-SHAKE-128s KeyGen    | ~164 ms  | ~6 ops/s |
| SLH-DSA-SHAKE-128s Sign      | ~1.25 s  | ~1 op/s |
| SLH-DSA-SHAKE-128s Verify    | ~1.15 ms | ~870 ops/s |
| secp256k1 pubkey             | ~329 µs  | ~3,000 ops/s |
| FROST round1 commit          | ~24.6 µs | ~40,700 ops/s |
| FROST round2 sign            | ~185 µs  | ~5,400 ops/s |
| FROST aggregate              | ~113 µs  | ~8,900 ops/s |

Sandbox numbers are for sanity-checking only and not authoritative;
re-run on the deployment host before quoting externally.

No `baseline_value` entries in `benchmarks/baseline.json` or
`benchmarks/arm-baseline.json` were changed by the coverage expansion.
The five new families are not yet wired into the CI regression-detection
runner (`benchmarks/benchmark_runner.py`); they extend the **raw-C
harness output surface** and the visualisation surface
(`benchmarks/generate_charts.py`) only.

---

## 2026-07-29: secp256k1 fixed-base comb + baseline validity-window enforcement

Two changes here touch `baseline_value` entries, so both are recorded per
"The guard" above.

### 1. Why the floors moved: the window was never enforced

Both baseline files declare `metadata.applies_through_release`. A repo-wide
search found that field **only inside the two JSON files and the prose
describing them** — never in a gate, a workflow, or the runner. The floors were
measured against v2.1.2 and declared valid through v3.0.0 while the library
shipped 3.4.0, and the regression job kept reporting PASS: `benchmark-report.md`
was recording "regressions" of -642 % and -1806 % as passes.

Measured sensitivity against the old floors, before any change:

| entry | measured / floor | regression needed before the gate fires |
|---|---|---|
| crypto package create | 18.7x | 95 % |
| ML-DSA-65 sign | 11.3x | 91 % |
| HMAC-SHA3-256 | 9.4x | 89 % |
| SHA3-256 (1 KiB) | 8.4x | 88 % |
| AES-256-GCM (1 KiB) | 0.65x | already below its floor |

`tests/test_benchmark_baseline_freshness.py` now enforces the window on
`(major, minor)` — patch bumps are tolerated, since a z-bump carries no
performance intent — and names the remedy when it fires.

**Recalibration rule**, applied to `benchmarks/baseline.json` only:

    new_floor = max(existing_floor, 0.65 * min(measured, canonical))

* `0.65` is this project's own documented convention (35 % headroom).
* `min(measured, canonical)` caps each floor by the committed canonical-host
  numbers in `benchmark-report.md`, so a host that is fast on one primitive
  cannot push a floor above what the canonical runner delivers. This is what
  keeps ML-DSA-65 signing honest: the measuring host reported 3,561 ops/s
  against a canonical 1,104, and the cap took 1,104.
* `max(existing_floor, …)` means **no floor was lowered**. Where the measuring
  host is slower than canonical — AES-GCM and X25519, both SIMD-availability
  dependent — the existing floor simply stands.

Together those two clamps make the result robust to the measuring host's
run-to-run variance in both directions: the cap absorbs high outliers, the
never-lower rule absorbs low ones. Variance on that host was substantial and is
recorded here rather than hidden — AES-GCM measured 152,935 then 97,130 ops/s
across two consecutive runs, and ML-DSA-65 sign 3,561 then 1,463.

**Runner:** container, Linux x86-64, 4 cores, gcc 13.3, Python 3.11.15, native
C backend. Commands: `python benchmarks/benchmark_runner.py` and
`./build/bin/benchmark_c_raw`.

**Not authoritative for AArch64.** `benchmarks/arm-baseline.json` had its window
extended to 3.4.0 but **no floor value changed**, because recalibrating it needs
the `ubuntu-24.04-arm` runner. That gate is therefore exactly as strong (and
exactly as loose) as it was; the carry-forward is recorded in that file's
`baseline_change_log` so it is auditable rather than silent.

**AES-256-GCM is flagged, not adjusted.** Its floor was already above the
measuring host's throughput *before* any change here, so it clears the gate only
on the 40 % tolerance. That wants a canonical-runner measurement, not a floor
edit, and no floor edit was made.

### 2. secp256k1 fixed-base comb (algorithm change, affects two floors)

`ama_secp256k1.c` used the generic Montgomery ladder for *every* scalar
multiplication, including the two whose base point is the compile-time
generator: public-key derivation and the ECDSA signing nonce `R = k*G`. The
ladder spends one addition **and** one doubling per scalar bit because it must
not branch — correct for a caller-supplied base, pure waste for a constant.
`ama_nistp.c` already solved this with a comb, which gave a same-host control:
secp256k1 `d*G` cost 351.93 µs against 138.16 µs for the equivalent P-256
operation, even though secp256k1's prime reduces *faster* than P-256's.

A 4-block comb (16 entries, ~1.9 KB, L1-resident) replaces 256 doublings and
256 additions with 64 of each:

| raw-C operation | before | after | |
|---|---|---|---|
| secp256k1 pubkey | 354.97 µs / 2,817 ops/s | **83.36 µs / 11,997 ops/s** | 4.26x |
| secp256k1 ECDSA sign | 392.94 µs / 2,545 ops/s | **125.54 µs / 7,966 ops/s** | 3.13x |
| secp256k1 ECDSA verify | 282.45 µs / 3,540 ops/s | 274.98 µs / 3,637 ops/s | unchanged, as intended |

Verification is deliberately untouched: it is variable-time by design and
already uses Shamir's trick.

This supersedes the `secp256k1 pubkey` row in the 2026-05 sandbox table above
(`~329 µs / ~3,000 ops/s`), which measured the ladder. That row is left in place
because this file is an append-only record; it is historical, not current.

Constant-time preserved (INVARIANT-12), verified rather than asserted: Welch's
t-test over 60,000 samples gives fixed-vs-random `|t| = 0.29` and a
Hamming-weight split of `|t| = 1.03`, against dudect's leakage threshold of 4.5.

`secp256k1_ecdsa_sign` and `secp256k1_ecdsa_verify` floors rise to 1,900 and
2,600 ops/s under the rule above. Both sit well below the post-change
measurement, so the gate now protects the optimisation: reverting the comb would
drop signing to roughly 2,545 ops/s raw C and trip the floor.

### 3. AVX-512 4-way Keccak: measured, and off by default on purpose

`AMA_ENABLE_AVX512` gates the in-house 4-way Keccak kernel and defaults to
`OFF` for the five reasons in `docs/AVX512_KECCAK_ADR.md`. It had no measured
throughput figure attached, so the cost of leaving it off was not visible to
anyone deciding whether to turn it on.

Measured on this host (AVX-512F present), min-of-3 back-to-back runs of
`benchmark_c_raw`, same source, same compiler, only the flag differing:

| operation | AVX-512 OFF | AVX-512 ON | |
|---|---|---|---|
| ML-KEM-1024 Encaps | 104.33 us | **85.64 us** | 1.22x |
| ML-KEM-1024 KeyGen | 107.11 us | **87.82 us** | 1.22x |
| ML-KEM-1024 Decaps | 118.14 us | **101.21 us** | 1.17x |
| ML-DSA-65 Sign | 208.15 us | **180.60 us** | 1.15x |
| ML-DSA-65 Verify | 139.81 us | **118.88 us** | 1.18x |
| ML-DSA-65 KeyGen | 167.48 us | **142.69 us** | 1.17x |

Both lattice schemes expand their matrix through the 4-way SHAKE call sites, so
the kernel lands on every ML-KEM and ML-DSA operation rather than on hashing
alone. The ADR's reasoning for the default is unchanged — this records what the
default costs on hardware that could use it, so the trade is made with a number
rather than an intuition.

**Not the whole gap.** Against the widely published amd64 reference figures for
these schemes, ML-KEM-1024 remains roughly 2x off even with the kernel on,
while every elliptic-curve operation in the tree is at or better than its
reference figure. Kyber's core — NTT, inverse NTT, pointwise multiply — is
already dispatched (`dt->kyber_ntt`), so the remaining distance is not a
missing SIMD path and wants a profile before anyone guesses at it. Those
reference figures are literature values, not measurements taken here; running
SUPERCOP on this host is the way to turn that comparison into evidence.
