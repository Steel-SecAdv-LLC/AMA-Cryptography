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
  is missing. A lowered floor must also cite an ops/sec figure between
  the old and new floors and the CI run id it came from, and a floor may
  not be deleted while `benchmarks/benchmark_runner.py` still defines its
  benchmark: no text justifies that, because the deletion stops the
  primitive being measured at all.
- `benchmarks/benchmark_runner.py` refuses, whatever its flags, a baseline
  entry with no benchmark function behind it and a benchmark function with
  no floor in its section, so neither a rename nor a deletion can retire a
  gate while the run stays green.
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
  shows monotonic improvement (integration of the formerly vendored
  Ed25519 x86-64 backend `3ea4aa6` — since removed in the twenty-first
  maintenance pass — SIMD dispatch `86f02bd`/`c9f4722`, AVX2 wiring
  `2c26a90`, etc.).
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
| FROST 2-of-3 (RFC 9591-style)              | `FROST round1 commit` / `round2 sign` / `aggregate` |
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
the Ed25519 x86-64 backend of the time — the formerly vendored one, since
removed in the twenty-first maintenance pass — and ML-DSA AVX2 dispatched,
MULX+ADX kernel available):

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

### 4. Where AMA places against a field rather than a pair

Two comparators is not a field. Measured in the same process, same buffers,
best-of-5 rounds, on the primitives all four libraries expose natively
(`benchmarks/multi_library_bench.cpp`), reported in cycles/byte so the ranking
does not move with clock speed:

| AES-256-GCM, 64 KiB | cycles/byte | MB/s |
|---|---|---|
| OpenSSL 3.0.13 | 0.266 | 10,529.5 |
| **AMA Cryptography** | **2.815** | **995.5** |
| Botan 2.19.3 | 4.767 | 587.9 |
| wolfSSL 5.6.6 | 24.419 | 114.8 |

| SHA3-256, 64 KiB | cycles/byte | MB/s |
|---|---|---|
| OpenSSL 3.0.13 | 6.966 | 402.3 |
| Botan 2.19.3 | 8.249 | 339.8 |
| wolfSSL 5.6.6 | 9.513 | 294.6 |
| **AMA Cryptography** | **11.048** | **253.7** |

AMA places **2nd of 4 on AES-GCM** — ahead of Botan by 1.69x and wolfSSL by
8.7x, behind only OpenSSL's AES-NI + VPCLMULQDQ path — and it reaches that
while refusing key-dependent table lookups (INVARIANT-20). On SHA3-256 it
places 4th, but the field spans only 1.59x end to end, so last place here is a
narrow margin rather than a different class of implementation.

**Caveats, stated rather than buried.** The wolfSSL AES-GCM figure is far off
what that library achieves when built with AES-NI; this is Ubuntu's stock
`libwolfssl-dev` 5.6.6 and the number reflects that package's build flags, not
the library's capability. Crypto++ is absent because `wolfssl/options.h`
defines `byte`/`word32` macros that break `crypto++/cryptlib.h` in the same
translation unit — it needs a separate TU, which was not built.

### 5. The lattice gap is real, and it is not a missing kernel

ML-KEM-1024 encapsulation costs ~72 us (~202,000 cycles) on this host against
roughly 16-20 us for a fully vectorised AVX2 implementation of the same
parameter set — a gap of about 4x. Two hypotheses were tested and **both were
wrong**:

* *"The 4-way Keccak is not wired."* It is. `ama_keccak_f1600_x4_avx2` is
  selected natively (`ama_dispatch.c:1329`) and is covered by
  `tests/c/test_keccak_equiv.c`.
* *"Profiling shows 60% of encapsulation is scalar Keccak."* That profile was
  an artefact. Valgrind masks CPUID, so the callgrind run selected the generic
  4x-scalar fallback rather than the AVX2 kernel that a native run uses —
  verified by comparing the resolved function pointer under both. **The figure
  is withdrawn.**

What is measured and stands: SIMD is engaged and contributes 1.28x
(AVX2 on 71.96 us vs SIMD off 92.09 us), and AVX-512 contributes a further
1.22x when enabled. The remaining distance is breadth of vectorisation —
reference implementations vectorise rejection sampling, CBD, compression and
the full NTT chain, where AMA vectorises a subset. Closing it is a
vectorisation project measured in weeks, not a configuration change, and
nothing here should be read as implying a quick fix exists.

## 2026-09-24: canonical-host tables re-measured on the 5.0.0 tree

The `README.md` canonical-bench region and `benchmarks/canonical-host.json` carried figures measured 2026-04-25 to 2026-04-27 against the 4.x code. 5.0.0 changed most of the paths they timed (the INVARIANT-41 pairwise-consistency test on every Python keypair, the INVARIANT-51 per-signature derivation, the INVARIANT-52 package transcript, the in-house Ed25519 backend, FIPS 204 §5.2 external ML-DSA), so they described neither the code nor any host this repository could reproduce them on. They are replaced here; the figures they replace are kept in the table below.

**Host.** Intel Xeon, family 6 model 207 (Emerald Rapids) @ 2.10 GHz, 4 vCPU KVM guest (Firecracker), flags `avx512f avx512vl avx512bw avx512dq avx512vbmi avx512ifma vaes vpclmulqdq sha_ni bmi2 adx hypervisor`; Linux 6.18.44; gcc 13.3.0, CMake Release, `-DAMA_USE_NATIVE_PQC=ON`; Python 3.11.15; native library and all six Cython bindings built by `python setup.py build_ext --inplace` at `974cb019` (runner provenance: `python_bindings: 6 of 6 compiled bindings imported`). The previous record's own note called its canonical host a VM, with the same ISA list and the same Python; this one is a VM too, and says so. It is not bare metal. Whether bare metal would move these figures is not measured here.

**Method.** Five rounds; each round ran `taskset -c 0 python benchmarks/benchmark_runner.py --output runner_N.json`, then `taskset -c 0 build/bin/benchmark_c_raw --json`, then the X25519 kernel pair (`ama_x25519_set_mulx_override(0)` and `(1)` around `benchmark_runner.run_x25519_benchmark`), so the three harnesses interleave across host phases. Published figure: the median of the five rounds; the ranges in `README.md` are min–max. No other benchmark ran concurrently; unrelated work was confined to cores 2–3 with `nice -n 19`.

**Auto-tune.** The dispatcher demoted the AVX-512 four-way Keccak to the scalar BMI1/BMI2 path in 5 of 5 benchmark-runner process starts, four-way against scalar 676,105 / 466,984 ns, 766,260 / 528,823 ns, 742,740 / 518,622 ns, 1,193,889 / 957,746 ns, 678,014 / 465,534 ns (1.45×, 1.45×, 1.43×, 1.25×, 1.46×). The SHA3 and ML-KEM rows therefore measure the scalar Keccak on this host, as the 2026-07-29 section above found on the earlier AVX-512 host.

### Python API rows (`benchmark_runner.py`), ops/sec

| Row | 2026-04 (4.x) | Run 1 | Run 2 | Run 3 | Run 4 | Run 5 | **Median** |
|---|---|---|---|---|---|---|---|
| `dilithium_keygen` | 3,626 | 1,578 | 1,699 | 1,617 | 1,616 | 1,627 | **1,617** |
| `dilithium_sign` | 2,976 | 3,028 | 3,125 | 3,171 | 3,244 | 3,242 | **3,171** |
| `dilithium_verify` | 7,576 | 11,443 | 11,368 | 10,815 | 10,630 | 10,817 | **10,817** |
| `kyber_keygen` | 4,965 | 3,891 | 3,865 | 3,515 | 3,402 | 3,602 | **3,602** |
| `kyber_encapsulate` | 10,253 | 17,417 | 17,984 | 18,171 | 16,715 | 18,398 | **17,984** |
| `full_package_create` | 2,853 | 1,939 | 2,050 | 1,900 | 1,955 | 2,044 | **1,955** |
| `full_package_verify` | 4,973 | 3,455 | 3,402 | 3,270 | 3,128 | 3,336 | **3,336** |
| `ama_sha3_256_hash` | 184,112 | 411,552 | 412,231 | 420,412 | 427,840 | 408,425 | **412,231** |
| `hmac_sha3_256` | 115,408 | 270,827 | 275,758 | 297,557 | 289,167 | 276,791 | **276,791** |
| `hkdf_derive` | 81,703 | 187,480 | 182,789 | 184,618 | 174,595 | 197,367 | **184,618** |
| `ed25519_keygen` | 55,716 | 13,361 | 13,939 | 13,354 | 14,028 | 13,191 | **13,361** |
| `ed25519_sign` | 51,488 | 40,547 | 41,626 | 41,825 | 41,300 | 39,986 | **41,300** |
| `ed25519_sign_expanded` | — | 63,692 | 63,939 | 66,512 | 66,228 | 65,411 | **65,411** |
| `ed25519_verify` | 21,338 | 30,299 | 29,664 | 32,200 | 30,659 | 30,199 | **30,299** |
| `aes_256_gcm_encrypt` | 293,143 | 297,439 | 314,871 | 299,214 | 292,062 | 304,615 | **299,214** |
| `chacha20poly1305_encrypt` | 256,249 | 279,284 | 288,960 | 311,899 | 289,768 | 281,060 | **288,960** |
| `x25519_scalarmult` | 15,401 | 20,284 | 20,329 | 20,026 | 20,828 | 21,738 | **20,329** |

### Raw C rows (`benchmark_c_raw --json`, median-of-iterations basis), ops/sec

| Row | 2026-04 (4.x) | Run 1 | Run 2 | Run 3 | Run 4 | Run 5 | **Median** |
|---|---|---|---|---|---|---|---|
| ML-DSA-65 KeyGen | ~4,845 | 9,321 | 9,397 | 9,358 | 9,299 | 9,498 | **9,358** |
| ML-DSA-65 Sign | ~3,929 | 6,023 | 3,716 | 2,826 | 7,713 | 7,196 | **6,023** |
| ML-DSA-65 Verify | ~7,773 | 11,559 | 11,101 | 11,532 | 11,666 | 7,568 | **11,532** |
| ML-KEM-1024 KeyGen | — | 16,734 | 17,254 | 10,684 | 18,931 | 10,229 | **16,734** |
| ML-KEM-1024 Encaps | — | 19,016 | 19,977 | 11,626 | 19,604 | 15,783 | **19,016** |
| ML-KEM-1024 Decaps | ~10,834 | 15,839 | 17,094 | 9,383 | 16,466 | 16,117 | **16,117** |
| X25519 DH (MULX off) | — | 12,383 | 12,486 | 12,115 | 12,819 | 12,465 | **12,465** |
| X25519 DH (MULX on) | ~16,983 | 20,592 | 21,188 | 19,848 | 21,369 | 20,709 | **20,709** |

Four raw-C PQC rows were not stable across rounds: ML-KEM-1024 KeyGen and Encaps were slow in rounds 3 and 5 and Decaps in round 3, ML-DSA-65 Verify in round 5, and ML-DSA-65 Sign ranged 2,826–7,713 (its signing time varies by design with rejection sampling, and 200 iterations per round do not average that out). The Python-API rows of the same rounds stayed within 4.3–13.6% (max–min over median). The median is what is published; the spread is stated here rather than trimmed.

*Added 2026-09-24, after these runs.* The ML-DSA-65 Sign spread above was not noise, and 200 iterations could not average it out, because all 200 did the same work: the row signed one fixed message under one per-run key, and `ama_dilithium_sign` is FIPS 204's deterministic signer, whose rejection count is a constant per (key, message) pair. Measured with callgrind on the development host (retired instructions per signature of the harness's message, sixteen seeded keys): 2,153,304 to 10,761,001, a 5.00x spread from the key alone. The row now times whole passes over a pool of 256 distinct messages — the pool `benchmark_runner.py` cycles — and reports the pass time per signature, which puts a run on its key's pool-mean cost: 4,442,497 to 5,176,191 instructions per signature over the same sixteen keys (1.17x). The ML-DSA-65 Sign column in the table above was measured with the one-pair row and is left as measured; it is not comparable with the row's output from this change on. The row was re-measured on the canonical host the same day, and the README's raw-C Sign figure now quotes that measurement instead of this table's:

| Row | Run 1 | Run 2 | Run 3 | Run 4 | Run 5 | **Median** |
|---|---|---|---|---|---|---|
| ML-DSA-65 Sign (pooled, per signature) | 3,435 | 3,199 | 3,360 | 3,880 | 3,356 | **3,360** |

`build/bin/benchmark_c_raw --json` built at `352fb916` (gcc 13.3.0, CMake Release, `-DAMA_USE_NATIVE_PQC=ON`), five consecutive rounds on an otherwise idle host, each pinned with `taskset -c 0`; 25 passes of 256 signatures per round. The one-pair median it replaces, 6,023, sat inside a 2,826–7,713 spread; the pooled rounds span 3,199–3,880. `tests/c/test_benchmark_mldsa_sign_pool.c` pins what the row signs.

### X25519 through the Python harness, kernel pinned, ops/sec

| Configuration | 2026-04 (4.x) | Run 1 | Run 2 | Run 3 | Run 4 | Run 5 | **Median** |
|---|---|---|---|---|---|---|---|
| MULX+ADX pinned off (pure-C fe64) | ~11,500 | 11,561 | 11,283 | 10,580 | 12,027 | 11,412 | **11,412** |
| MULX+ADX pinned on | ~15,401 | 19,931 | 20,213 | 20,830 | 19,348 | 20,632 | **20,213** |
| default dispatch | — | 21,360 | 19,303 | 20,373 | 20,955 | 21,937 | **20,955** |

**Why rows moved.** Throughput rows that now include work 4.x did not do fell: ML-DSA-65 and ML-KEM-1024 KeyGen and Ed25519 KeyGen run a pairwise-consistency test on every Python keypair (INVARIANT-41), Ed25519 Sign on the 64-byte key derives `A = [a]B` per call (INVARIANT-51; the expanded-key row is the once-at-load form), and the package rows carry the INVARIANT-52 transcript and the KEM commitment. Rows whose work did not grow rose on this host (SHA3, HMAC, HKDF, Ed25519 Verify, the AEADs, X25519, ML-KEM Encapsulate, ML-DSA Sign and Verify). The two sets were measured on different VMs five months apart, so a row-by-row ratio between them is not a code-only comparison and is not published as one.


## 2026-09-07: Ed25519 floors on the in-house backend — a single-run floor replaced by four-run medians

PR #394's twenty-first maintenance pass replaced the vendored ed25519-donna
backend with the in-house backend (radix-2^51 and, on BMI2+ADX hosts,
radix-2^64 field arithmetic), and commit `6892863` raised the three Ed25519
floors in both baseline files to the benchmark-regression jobs' measurement of
it at head `c6020ac`: 16,751 / 77,991 / 32,019 ops/sec (keygen / sign /
verify) on `ubuntu-latest` x86_64 and 14,595 / 58,452 / 31,259 on
`ubuntu-24.04-arm`. One run each.

The four benchmark-regression runs that followed on identical Ed25519 code
(heads `f2ac1d8`, `4a45408`, `755cd22`, `447cdf0`; workflow runs 34070019745,
34082980156, 34084425292, 34084821515) showed the x86_64 sample to be a
fast-class one: keygen 16,622 / 14,436 / 16,304 / 14,349, sign 73,660 /
67,625 / 73,366 / 67,521, verify 33,234 / 28,003 / 32,777 / 28,306 ops/sec —
the two-class `ubuntu-latest` fleet the 2026-08-14 recalibration already
documents. The aarch64 runs sat within 1.5% of each other.

Per "The guard" above, the floors are re-based to the median of those four
runs (even count: mean of the middle two, rounded), computed by script from
the job logs:

| Primitive | x86_64 before → after | aarch64 before → after |
|---|---|---|
| `ed25519_keygen` | 16,751 → 15,370 | 14,595 → 14,678 |
| `ed25519_sign` | 77,991 → 70,496 | 58,452 → 58,762 |
| `ed25519_verify` | 32,019 → 30,542 | 31,259 → 31,270 |

Tolerances are unchanged (45% x86_64, 15% aarch64). The x86_64 effective
minimums (floor × 0.55) fall with the floors — 9,213 → 8,454, 42,895 → 38,773,
17,610 → 16,798 ops/sec — which is stated rather than hidden: it is the same
convention every other x86_64 row uses (the floor is the measured median, the
tolerance is the fleet's spread), applied to a measured median instead of one
fast sample. Every one of the four runs clears the new minimums by 67–74%, and
the slowest of them is above the removed donna backend's last measurement on
the same runner class (11,855 / 59,847 / 21,322) on every row. The other
sixteen floors, `calibration_evidence` and `floor_drift_acknowledged` are
untouched; both `baseline_change_log`s carry the run and job IDs. `README.md`
publishes the same four runs' medians for all nineteen benchmarks on both
runner classes.

## 2026-09-16: the audit remediation's cost, measured rather than derived

The 2026-09 audit remediation added work to three benchmarked paths, and the
first attempt to floor one of them was a derivation rather than a measurement.
This section records the correction.

`ama_ed25519_sign` now derives `A = [a]B` and refuses a key whose stored
public half disagrees (INVARIANT-51, audit finding B-2), so signing does two
fixed-base scalar multiplications where it did one. On x86_64 that is a
measured 1.85x, and the x86_64 floor was re-based from it. No aarch64 host was
available, so the aarch64 floor was set at the worst case the structure
admits — `58,762 / 2.0 = 29,381 ops/sec` — with the change log entry saying
plainly that it was **derived, not measured**, and marking the first aarch64
benchmark run after it as ACTION REQUIRED.

That run is workflow run `35155721711`, job `104994944714`, at head
`84ad90d2`, on `ubuntu-24.04-arm`. It measured `ed25519_sign` at **32,852
ops/sec** — above the 30,266 the branch inherited from `main`, so on aarch64
the second multiplication costs less than the conservative bound allowed for,
and the derived floor was 11% below what the runner actually delivers.

The same run showed two floors that a derivation had not anticipated at all:

| Primitive | aarch64 before → after | measured | cause |
|---|---|---|---|
| `ed25519_keygen` | 14,678 → 12,271 | 12,271 ops/sec | the row times the Python `keypair()` call, which runs a FIPS 140-3 pairwise-consistency **sign** on every key, so it pays the INVARIANT-51 multiplication too |
| `ed25519_sign` | 29,381 → 32,852 | 32,852 ops/sec | derived bound replaced by the runner's own figure |
| `full_package_verify` | 4,426 → 3,441 | 3,441 ops/sec | the verify path now rebuilds and checks the INVARIANT-52 canonical transcript and rejects small-order Ed25519 points (audit A-2, A-3) |

`ed25519_keygen` is the entry worth reading twice. Nothing in Ed25519 key
generation changed; the row moved 16.4% because the benchmark measures the
public API call, and that call signs. x86_64 shows the same movement — 14,405
against a 15,370 floor — and passed only because that file's tolerance is 45
where this one's is 15. A floor that describes a composite operation moves
when any part of the composite moves, which is the property that makes the
tolerance, not the floor, the wrong place to absorb a known change.

Tolerances are unchanged (15% on all three). These are single-run figures
rather than four-run medians: the fleet this file describes has a documented
cross-run spread of <= 3% on these rows, so 15% is a 5x margin over it, and
the next aarch64 run on this branch is the confirmation.


## 2026-09-22: `ed25519_sign_expanded` — INVARIANT-51 paid once, at key load, and a new row at a derived floor

The 2026-09-16 section below re-based `ed25519_sign` for a deliberate
slowdown: INVARIANT-51 makes `ama_ed25519_sign` derive `A = [a]B` on every
signature and refuse a stored public half that disagrees. That is the cost of
the property when the key is a bare 64-byte string with nothing binding its
halves. The tree now carries a form in which the binding travels with the
key — `ama_ed25519_expand_secret_key` derives `A` once and writes
`a ‖ prefix ‖ A ‖ tag`, and `ama_ed25519_sign_expanded` re-checks the tag
(two SHA-512 compressions) instead of re-deriving (a fixed-base scalar
multiplication). Same core, identical signature bytes; every one of the 128
bytes is load-bearing. `pqc_backends.Ed25519SigningKey` owns it in Python.

**Measured, one host, one session** (Intel Xeon @2.80GHz, 4 vCPU container,
Linux 6.18.44, `taskset -c 0`, tree `24341f8`):

| level | `ed25519_sign` | `ed25519_sign_expanded` | ratio |
|---|---|---|---|
| C, `build/bin/benchmark_c_raw`, median of 1,000, 63-byte message | 24,780 ns | 13,613 ns | 1.820× |
| C, CI benchmark flags (`AMA_ENABLE_AVX512=ON`, `AMA_ENABLE_NATIVE_ARCH=ON`) | 22,977 ns | 12,605 ns | 1.823× |
| Python API, `benchmark_runner.py` harness, 240-byte message, run 1 | 34,566 ops/s | 55,524 ops/s | 1.606× |
| Python API, run 2 | 34,977 ops/s | 55,607 ops/s | 1.590× |
| Python API, run 3 | 34,713 ops/s | 55,728 ops/s | 1.605× |
| Python API, a full snapshot run at `24341f8` (superseded, see below) | 34,900 ops/s | 55,465 ops/s | 1.589× |
| Python API, the committed record (`benchmarks/benchmark-results.json`, run at `4e4fa7f`) | 35,287 ops/s | 56,746 ops/s | 1.608× |

`ama_ed25519_expand_secret_key` itself: 12,632 ns, paid once per key. The
Python ratio sits below the C ratio by the fixed ctypes cost each call
carries (and `ed25519_sign` reaches the C through the Cython binding when
one is built, while the expanded path is ctypes). `ama_ed25519_sign`'s own
instruction count is unchanged by the shared core: 331,814 → 331,864 Ir,
+0.02%, `benchmarks/ic_driver.c` base against head.

**Correction, 2026-09-24.** The committed record's `ed25519_sign` row went on
carrying the ledger's older description, "native C, expanded key", after
`c126037` rewrote the ledger to say what the row measures: the 64-byte
`seed ‖ A` key with INVARIANT-51's derivation on every call. The once-at-load
form is the separate `ed25519_sign_expanded` row, so the record labelled the
two rows the wrong way round. That one copied field was corrected in place to
the ledger's text, and `benchmark-report.md` re-rendered from the record. The
measurement, floor, tolerance and provenance are unchanged. The record could
not be re-run that day: the only host available was a 4-vCPU container with a
load average above 50. `tests/test_published_benchmark_artefacts_are_current.py`
now compares every description and tolerance a row copies with the ledger,
as it already did the floor.

**The new row's floors are derived, not measured on the canonical runners,
and say so.** The canonical runner has never run this row, so there is no
four-run median to take. Both change-log entries record the derivation:

| file | source floor | ratio applied | floor | tolerance | failure point |
|---|---|---|---|---|---|
| `baseline.json` (x86_64) | `ed25519_sign` 38,811 | 1.589 (the lowest of the five Python ratios above; the run it came from was re-run at `4e4fa7f` and only this table and the change-log entry keep its figures — the lower ratio is the conservative floor) | **61,671** | 45% | 33,919 |
| `arm-baseline.json` (aarch64) | `ed25519_sign` 32,852 | 1.5 (conservative: no aarch64 host was available, and this file's band is 15%) | **49,278** | 15% | 41,886 |

The operation removed from the timed path is one of two fixed-base scalar
multiplications, the same fraction of the work on any microarchitecture, so
a ratio below the measured one is a floor a correct build cannot miss. Both
entries say the floor is to be re-based to the runner's own median after its
first run — as this file did for `ed25519_sign` on aarch64 (derived 29,381,
then measured 32,852). A derived floor is a placeholder for a measurement,
not a substitute for one.

`ed25519_sign` itself is not re-based: its floor describes the per-call path,
which is unchanged. The property test that pins it
(`test_the_ed25519_sign_floor_tracks_invariant_51`) still holds because that
path still pays the derivation.

**AEAD encrypt wrappers, same commit.** `native_aes256_gcm_encrypt` and
`native_chacha20poly1305_encrypt` allocate one output buffer instead of two.
A/B in one process against the previous wrapper under identical checks
(20,000-call windows, best of five, `taskset -c 0`): AES-256-GCM 64 B
3.367 → 3.001 µs, 1 KiB 3.959 → 3.647 µs (−7.9%), 16 KiB 11.434 → 11.407 µs;
ChaCha20-Poly1305 1 KiB 4.493 → 4.390 µs. No floor moves for it: the change
is inside the 45% band and the rows' floors describe the same operation.
For the record, the kernel behind the AES row measures 0.65 µs per 1 KiB
(`benchmark_c_raw`, 1.54 M ops/s); the Python row's ~3.6 µs is mostly
marshalling, and that is what the row's floor has always measured.

## 2026-09-22: the audit remediation's cost on both runner classes — four-run re-base, and the 2026-09-16 floors confirmed

The 2026-09-16 section above re-based three aarch64 floors from a single run
and left the x86_64 file with one derived floor (`ed25519_sign`) and three
rows it acknowledged were sitting below their floors inside the 45% band
(`ed25519_keygen`, `full_package_create`, `full_package_verify`). Four
`benchmark-regression` runs have since landed on identical measured paths —
heads `ebc80b9`, `1bf806b`, `da8901d` and `1e79cd1` (a gate pin, a benchmark
skip message, a dead FROST store and a dead Argon2 branch); workflow runs
35545407750, 35548705329, 35608144468 and 35611329428, 2026-09-20 to
2026-09-21 — which is the protocol the 2026-09-07 section established.
Medians are the mean of the middle two, rounded half up, computed by script
from the job logs.

**x86_64 — `ubuntu-latest`, jobs 106170292775, 106179299451, 106360245063,
106370902549.** Run 35548705329 is a fast-class sample on every row (20–45%
above the other three), so the medians are slow-class medians:

| primitive | runs ebc80b9, 1bf806b, da8901d, 1e79cd1 (ops/sec) | median | floor before → after | note |
|---|---|---|---|---|
| `ama_sha3_256_hash` | 362,192 / 484,921 / 364,191 / 362,956 | 363,574 | 327,222 | unchanged; median +11.1% vs floor |
| `hmac_sha3_256` | 248,186 / 331,652 / 249,009 / 247,946 | 248,598 | 215,299 | unchanged; median +15.5% vs floor |
| `ed25519_keygen` | 12,374 / 16,618 / 12,362 / 12,343 | 12,368 | 15,370 → **12,368** | re-based (median) |
| `ed25519_sign` | 38,655 / 50,286 / 38,813 / 38,808 | 38,811 | 38,170 → **38,811** | re-based (median) |
| `ed25519_verify` | 27,759 / 38,799 / 27,942 / 27,925 | 27,934 | 30,542 → **27,934** | re-based (median) |
| `hkdf_derive` | 166,632 / 220,752 / 166,598 / 166,721 | 166,677 | 131,341 | unchanged; median +26.9% vs floor |
| `full_package_create` | 1,857 / 2,479 / 1,836 / 1,855 | 1,856 | 1,983 → **1,856** | re-based (median) |
| `full_package_verify` | 2,793 / 4,244 / 2,803 / 2,811 | 2,807 | 3,442 → **2,807** | re-based (median) |
| `secp256k1_ecdsa_sign` | 9,211 / 11,869 / 9,179 / 9,187 | 9,199 | 8,068 | unchanged; median +14.0% vs floor |
| `secp256k1_ecdsa_verify` | 3,717 / 4,874 / 3,724 / 3,722 | 3,723 | 3,302 | unchanged; median +12.7% vs floor |
| `dilithium_keygen` | 1,511 / 1,907 / 1,548 / 1,497 | 1,530 | 1,312 | unchanged; median +16.6% vs floor |
| `dilithium_sign` | 3,143 / 3,905 / 3,106 / 3,126 | 3,135 | 2,636 | unchanged; median +18.9% vs floor |
| `dilithium_verify` | 10,367 / 13,208 / 10,379 / 10,383 | 10,381 | 8,897 | unchanged; median +16.7% vs floor |
| `kyber_keygen` | 3,238 / 4,360 / 3,262 / 3,265 | 3,264 | 2,726 | unchanged; median +19.7% vs floor |
| `kyber_encapsulate` | 15,894 / 21,394 / 15,950 / 16,006 | 15,978 | 11,994 | unchanged; median +33.2% vs floor |
| `aes_256_gcm_encrypt` | 230,869 / 315,191 / 233,991 / 231,406 | 232,699 | 224,406 | unchanged; median +3.7% vs floor |
| `chacha20poly1305_encrypt` | 231,429 / 306,089 / 235,640 / 234,548 | 235,094 | 227,521 | unchanged; median +3.3% vs floor |
| `x25519_scalarmult` | 18,894 / 24,705 / 18,966 / 19,001 | 18,984 | 16,876 | unchanged; median +12.5% vs floor |
| `x25519_scalarmult_batch4` | 4,540 / 5,906 / 4,547 / 4,554 | 4,551 | 4,074 | unchanged; median +11.7% vs floor |

**aarch64 — `ubuntu-24.04-arm`, jobs 106170292802, 106179299071,
106360244481, 106370902832.** Homogeneous; every row but `dilithium_sign`
(rejection-sampled) spreads 1.5% or less:

| primitive | runs ebc80b9, 1bf806b, da8901d, 1e79cd1 (ops/sec) | median | floor before → after | note |
|---|---|---|---|---|
| `ama_sha3_256_hash` | 436,301 / 436,555 / 433,513 / 436,658 | 436,428 | 426,967 | unchanged; median +2.2% vs floor |
| `hmac_sha3_256` | 304,312 / 303,642 / 303,360 / 303,993 | 303,818 | 285,176 | unchanged; median +6.5% vs floor |
| `ed25519_keygen` | 12,315 / 12,278 / 12,269 / 12,286 | 12,282 | 12,271 | unchanged; median +0.1% vs floor |
| `ed25519_sign` | 32,843 / 32,839 / 32,848 / 32,852 | 32,846 | 32,852 | unchanged; median -0.0% vs floor |
| `ed25519_verify` | 31,111 / 31,101 / 31,031 / 30,719 | 31,066 | 31,270 | unchanged; median -0.7% vs floor |
| `hkdf_derive` | 209,182 / 209,407 / 209,153 / 208,684 | 209,168 | 176,697 | unchanged; median +18.4% vs floor |
| `full_package_create` | 2,114 / 2,155 / 2,110 / 2,177 | 2,135 | 2,379 → **2,135** | re-based (median) |
| `full_package_verify` | 3,556 / 3,509 / 3,482 / 3,522 | 3,516 | 3,441 | unchanged; median +2.2% vs floor |
| `secp256k1_ecdsa_sign` | 10,924 / 10,897 / 10,927 / 10,899 | 10,912 | 10,342 | unchanged; median +5.5% vs floor |
| `secp256k1_ecdsa_verify` | 4,530 / 4,532 / 4,517 / 4,518 | 4,524 | 4,316 | unchanged; median +4.8% vs floor |
| `dilithium_keygen` | 1,682 / 1,670 / 1,664 / 1,670 | 1,670 | 1,634 | unchanged; median +2.2% vs floor |
| `dilithium_sign` | 3,944 / 3,570 / 3,456 / 3,637 | 3,604 | 3,316 | unchanged; median +8.7% vs floor |
| `dilithium_verify` | 11,678 / 11,664 / 11,683 / 11,672 | 11,675 | 11,733 | unchanged; median -0.5% vs floor |
| `kyber_keygen` | 3,860 / 3,861 / 3,853 / 3,842 | 3,857 | 3,729 | unchanged; median +3.4% vs floor |
| `kyber_encapsulate` | 21,999 / 21,989 / 21,950 / 21,586 | 21,970 | 20,105 | unchanged; median +9.3% vs floor |
| `aes_256_gcm_encrypt` | 234,782 / 233,826 / 235,180 / 233,887 | 234,335 | 234,678 | unchanged; median -0.1% vs floor |
| `chacha20poly1305_encrypt` | 195,505 / 195,800 / 197,531 / 196,184 | 195,992 | 195,365 | unchanged; median +0.3% vs floor |
| `x25519_scalarmult` | 25,410 / 25,406 / 25,394 / 25,394 | 25,400 | 25,167 | unchanged; median +0.9% vs floor |
| `x25519_scalarmult_batch4` | 6,070 / 6,075 / 6,062 / 6,053 | 6,066 | 6,011 | unchanged; median +0.9% vs floor |

Six floors move, all for changes already recorded in this ledger:

* x86_64 `ed25519_keygen` 15,370 → 12,368: `keypair()` runs a FIPS 140-3
  pairwise-consistency sign on every key, so it pays the INVARIANT-51
  multiplication; the aarch64 file re-based this row on 2026-09-16 and the
  x86_64 file did not.
* x86_64 `ed25519_sign` 38,170 → 38,811: the derived floor (70,496 / 1.8469)
  replaced by the runner's own median, which sits 1.7% above the derivation.
  A raise, on the three-token rule.
* x86_64 `ed25519_verify` 30,542 → 27,934. **Correction, per AGENTS.md §6.6.**
  The 2026-09-16 x86_64 ledger entry stated that verify "gains the two
  INVARIANT-48 small-order byte predicates at +0.7% and needs no re-base".
  That was a C-level estimate of the two predicates alone, measured on a
  development host; the canonical runner measures the whole Python-API verify
  at −8.5% between the two medians, across a window that also carries the
  constant-time passes `e8b9c8c` and `1f43143` and the audit remediation
  `9b86086`. The statement is withdrawn; this entry records the measurement
  and does not attribute it between those commits.
* x86_64 `full_package_create` 1,983 → 1,856 and aarch64 `full_package_create`
  2,379 → 2,135: the INVARIANT-51 multiplication inside the package's Ed25519
  signature plus the INVARIANT-52 canonical transcript. The aarch64 row sat
  10.3% under its floor on a 25% band — the same "known change absorbed by the
  tolerance" the 2026-09-16 section argued against.
* x86_64 `full_package_verify` 3,442 → 2,807: the INVARIANT-52 transcript
  rebuild and the small-order rejection before verify (audit A-2, A-3) — the
  change the aarch64 file re-based for on 2026-09-16 (4,426 → 3,441), now
  applied to the x86_64 file from its own runner.

Tolerances are unchanged everywhere (45 x86_64; 15 aarch64, 25 for the two
composites). The x86_64 effective minimums (floor × 0.55) move 8,454 → 6,802,
20,994 → 21,346, 16,798 → 15,364, 1,091 → 1,021 and 1,893 → 1,544; the
slowest of the four runs clears each new minimum by at least 79%. The aarch64
`full_package_create` minimum (floor × 0.75) moves 1,784 → 1,601, cleared by
32% at the slowest run.

The three aarch64 floors the 2026-09-16 entry set from one run are confirmed
and left as set: `ed25519_keygen` median 12,282 against 12,271 (+0.1%),
`ed25519_sign` 32,846 against 32,852 (−0.02%), `full_package_verify` 3,516
against 3,441 (+2.2%). No other floor moves; every other row measured above
its floor on all four runs of both classes, the closest being aarch64
`aes_256_gcm_encrypt` (median 0.1% under a floor taken from two runs on
2026-08-14, inside its 15% band) and aarch64 `ed25519_verify` (0.7% under).

`README.md`'s 5.0.0 throughput table now publishes these four runs' medians
for all nineteen rows on both classes, superseding the 2026-09-07 table
(kept in the section above). Both `baseline_change_log`s carry the run and job
ids.

**The committed snapshot, and what its provenance now says.** In the same
pass `benchmarks/benchmark_runner.py` gained two provenance rows and changed
no measurement path: the `Tree` row names the paths `git status --porcelain`
reported (every CI benchmark lane re-signs
`ama_cryptography/_integrity_signature.py` before the package will import, so
every record those lanes ever produced read `DIRTY` for that one file,
indistinguishable from uncommitted changes to a primitive), and a
`Python bindings` row records which of the six Cython extensions were imported
— a source checkout without them built and a wheel measure different code on
the hash, MAC, KDF and signature rows, and nothing in the record said which.
