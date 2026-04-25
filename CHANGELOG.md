# Changelog

## Document Information

| Property | Value |
|----------|-------|
| Applies to Release | 2.1.5 |
| Last Updated | 2026-04-25 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

## Overview

All notable changes to AMA Cryptography will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---




## [Unreleased]


### Added

- **AVX-512 Keccak 4-way decision record** (`docs/AVX512_KECCAK_PLAN.md`).
  Terminal record for the PR C closing plan: work shipped since PR #261
  (#265 ed25519 verify SWE; #266 VAES + VPCLMULQDQ YMM AES-256-GCM),
  status of the closed PR cluster (#262 / #263 / #264 superseded by
  #266), the two unblock gates for PR C (an AVX-512-capable CI runner
  + priority clearance for the +20–40% SHA3-256 1 KB gain), an
  inventory of the ~28 AVX-512 references already in `main` (flagged
  as load-bearing safety code, not scaffolding), the PR C
  implementation sketch when both gates clear (vendor
  KeccakP-1600-AVX512.s under CC0, build via `AMA_ENABLE_AVX512`,
  drop the dispatcher downgrade for the SHA3 slot only, tighten
  `ama_has_avx512f()` XCR0 gating, KAT byte-identity vs the AVX2
  4-way and scalar reference), and the validation ladder (local
  Intel SDE → CPUID-gated CI job → quarterly bare-metal bench on
  Sapphire Rapids / Zen 4). Doc-only change, cherry-picked from
  `claude/avx512-keccak-ci-plan-cwVrX`.

### Changed

- **Benchmark and ACVP re-run (2026-04-25).** Full validation and
  performance suite re-executed on a Linux x86-64 host with AVX-512F /
  BW / DQ / VL / VBMI + VAES + VPCLMULQDQ after the cherry-pick above.
  NIST ACVP: **1,215 / 1,215 pass, 0 fail**, 5,789 skipped (4,667
  `vectors_skipped` + 1,122 `mct_skipped`) — matches the attestation
  in `docs/compliance/acvp_attestation.json` exactly. `ctest`: 20 / 20
  pass. FIPS-140 self-test + KAT + SIMD KAT Python lanes: 128 / 128
  pass. Regression benchmark: 16 / 16 pass, 0 warnings. Refreshed
  ops/sec tables in `README.md`, `benchmark-report.md`,
  `benchmark-results.json`, and `docs/COMPETITIVE_ANALYSIS.md` so they
  reflect the current tree including the post-#261 base-point comb
  table, #265 verify-path SWE rectification, and #266 VAES YMM
  AES-256-GCM landed on the 2.1.5 line. Notable deltas on this host:
  Ed25519 sign 10,569 → 51,206 ops/sec, Ed25519 verify 7,547 →
  21,129 ops/sec, Ed25519 keygen 9,162 → 35,946 ops/sec, ML-DSA-65
  sign 1,017 → 2,976 ops/sec, ML-KEM-1024 encap 9,138 → 10,253
  ops/sec. AES-256-GCM 1KB (278,298 → 271,449 ops/sec) and
  ChaCha20-Poly1305 1KB (271,362 → 263,430 ops/sec) are within
  run-to-run noise at the 1KB block size; the VAES YMM win shows up
  at ≥ 4KB in `build/bin/benchmark_c_raw --json`. A new row captures
  the rerun in `docs/METRICS_REPORT.md` under §Change Log.


### BREAKING

- **Argon2id output bit-space change (RFC 9106 conformance fix).** AMA's
  scalar Argon2id implementation contained a pre-existing bug in
  `blake2b_long` (H' / variable-output BLAKE2b, RFC 9106 §3.2): the loop
  ran one iteration too far and re-hashed `V_{r+1}` to produce the tail
  bytes instead of writing `V_{r+1}`'s output verbatim. Every memory
  block produced during the fill, plus the final tag, had its trailing
  32 bytes set to `BLAKE2b-32(V_{r+1})` rather than `V_{r+1}[32..63]`,
  so AMA's Argon2id output diverged from the spec for every parameter
  combination (verified against `argon2-cffi` 25.1.0 / phc-winner-argon2
  master). This affects AMA versions ≤ 2.1.5 (the bug is reachable in
  every prior release of `ama_argon2.c`'s scalar path). The fix in this
  release brings AMA byte-for-byte in line with RFC 9106 across an
  11-case parameter sweep including `t ∈ {1,2,3,4}`,
  `m ∈ {8,32,64,128,1024} KiB`, `p ∈ {1,2,4}`, and
  `out_len ∈ {16,32,64,128}`.

  **Migration required for any system storing AMA-derived Argon2id
  hashes.** Hashes produced by AMA ≤ 2.1.5 sit in the prior non-spec
  bit-space and will not verify against post-fix AMA — or against any
  other RFC 9106 implementation. This release ships the legacy path
  under two new symbols so downstream consumers can verify stored tags
  without forking the old code:

  - **C API** (`include/ama_cryptography.h`):
    `ama_argon2id_legacy(...)` — derive using the pre-2.1.5 buggy
    `blake2b_long` loop; identical signature to `ama_argon2id`.
    `ama_argon2id_legacy_verify(password, ..., expected_tag, tag_len)`
    — constant-time compare of `expected_tag` against the legacy
    derivation; returns `AMA_SUCCESS` on match,
    `AMA_ERROR_VERIFY_FAILED` on mismatch.

  - **Python API** (`ama_cryptography.pqc_backends`):
    `native_argon2id_legacy(password, salt, ...)` — derive using the
    pre-2.1.5 buggy path. Exposed so migration tooling and regression
    tests can generate reference tags without forking the old code;
    **never use it for new hashes** — `native_argon2id` is the
    spec-compliant path. Every call emits an
    `ama_cryptography.exceptions.SecurityWarning` so that accidental
    use in a production code path is loud at runtime; migration
    tooling can suppress the warning explicitly via
    `warnings.catch_warnings()`.
    `native_argon2id_legacy_verify(password, salt, expected_tag, ...)`
    — returns `True` on match, `False` on mismatch. Raises
    `RuntimeError` when running against an older native library that
    does not export the shim. Does NOT emit a `SecurityWarning` — it
    is the intended migration-verification path, so a warning on
    every call during a rotation would drown operators in noise.

  Recommended migration:
    1. On the next successful login, call `ama_argon2id_legacy_verify`
       (C) or `native_argon2id_legacy_verify` (Python) with the stored
       tag.
    2. On match, re-derive with the post-fix `ama_argon2id` and
       overwrite the stored hash in the same transaction.
    3. After a deprecation window appropriate for the deployment's
       login frequency, remove calls to the legacy path. The symbols
       remain exported for binary compatibility until the next major
       bump.

  No other public API or output format changes; ChaCha20-Poly1305,
  Ed25519, X25519, AES-256-GCM, SHA-3, ML-KEM, ML-DSA, and SPHINCS+
  outputs are unaffected.

- **Argon2id output length capped at `AMA_ARGON2ID_MAX_TAG_LEN`
  (1024 bytes).** Previously all three public Argon2id entry points
  (`ama_argon2id`, `ama_argon2id_legacy`, `ama_argon2id_legacy_verify`
  in C; `native_argon2id`, `native_argon2id_legacy`,
  `native_argon2id_legacy_verify` in Python) accepted
  `out_len` / `tag_len` up to `UINT32_MAX` (4 GiB) — the RFC 9106
  §3.2 theoretical maximum.  That surface was a caller-controlled
  memory-exhaustion / DoS vector because
  `ama_argon2id_legacy_verify` heap-allocates a `computed[tag_len]`
  buffer to hold the freshly-derived tag, and all three derivation
  paths pay CPU time proportional to `out_len / 32` BLAKE2b
  compressions in the `blake2b_long` tail.

  A new ceiling `AMA_ARGON2ID_MAX_TAG_LEN = 1024` (32× the default
  32-byte tag) is now enforced at every entry point.  This covers
  every practical deployment — Argon2id tags are universally
  16–64 bytes in the wild, and sizes above ~128 bytes are
  cryptographically indistinguishable from 64 so only waste compute
  and memory.

  **Behaviour change:** calls with `out_len > 1024` or
  `tag_len > 1024` now return `AMA_ERROR_INVALID_PARAM` from C and
  raise `ValueError` from Python, whereas ≤ 2.1.5 would have
  attempted the allocation and either succeeded (small-to-medium
  values) or silently truncated / OOMed (large values).  The Python
  `ValueError` message text also changed from the prior
  `"Argon2id output length must be >= 4, got N"` wording to
  `"Argon2id out_len must be in [4, 1024] bytes, got N"`; any caller
  doing substring matching on the error message must update to the
  new `"out_len"` text.  No spec-compliant user of the library is
  affected; any caller that relied on the old unbounded behaviour
  was already outside the recommended parameter space and should
  switch to a ≤ 1024-byte tag.  The cap is exposed as
  `AMA_ARGON2ID_MAX_TAG_LEN` in `include/ama_cryptography.h` and
  mirrored as `ama_cryptography.pqc_backends._ARGON2ID_MAX_TAG_LEN`
  so downstream callers can gate on it at compile / import time.

### Performance

- X25519 scalar multiplication: rewrite `ama_x25519.c` onto the radix-2^51
  (`fe51.h`) field arithmetic already used by Ed25519. The portable
  radix-2^16 (TweetNaCl-style) path is retained as a fallback for
  toolchains that lack native `__int128` (MSVC and clang-cl on x86-64,
  any 32-bit target); the fast path is gated on `AMA_FE51_AVAILABLE`,
  which `fe51.h` defines when `__SIZEOF_INT128__` is set. Measured on
  x86-64 sandbox (median-of-5 via `build/bin/benchmark_c_raw --json`):
  X25519 DH ~45 µs / ~19.5K ops/s, X25519 KeyGen ~62 µs / ~13K ops/s —
  roughly 15–20× the pre-change scalar path. Reproduce with
  `cmake --build build && ./build/bin/benchmark_c_raw --json`.

- ChaCha20-Poly1305 AVX2 wiring: `ama_chacha20_block_x8_avx2` (8-way
  parallel ChaCha20 block function emitting 512 B of keystream) is
  now wired through the dispatch table and invoked by the CTR inner
  loop in `ama_chacha20poly1305.c` for chunks ≥ 512 B. Keystream is
  byte-identical to the scalar RFC 8439 §2.3 path (verified by
  `tests/c/test_chacha20poly1305.c` with an independent reference
  implementation across sizes 1..4096 B including 511/512/513/1023/
  1024/1025 B boundaries). Measured on x86-64 sandbox via
  `benchmark_c_raw`: 2.11× at 1 KB, 2.24× at 4 KB, 2.29× at 64 KB.
  Messages < 512 B remain on the scalar path (no regression). Opt
  out with `AMA_DISPATCH_NO_CHACHA_AVX2=1`.

- Argon2 AVX2 BlaMka G wiring: `ama_argon2_g_avx2` is now a correct
  RFC 9106 §3.5 BlaMka compression (previously the file contained a
  Blake2b-style permutation that would have produced wrong output if
  wired). The new implementation packs four BlaMka G invocations into
  a single AVX2 4-way kernel using `_mm256_mul_epu32` for the
  `2·(a mod 2^32)·(b mod 2^32)` multiplication-hardened addition, and
  uses `_mm256_permute4x64_epi64` to rotate YMM lanes by 1/2/3 for the
  diagonal pass. Wired via `ama_dispatch_table_t::argon2_g`; called by
  every G invocation in the memory-fill loop of `ama_argon2id`. Byte-
  identical to scalar (verified by `tests/c/test_argon2id.c` which
  toggles dispatch between AVX2 and scalar and asserts tag equality
  across six parameter combinations). Measured on x86-64 sandbox:
  1.31× at m=64 KiB, 1.34× at m=1 MiB. Opt out with
  `AMA_DISPATCH_NO_ARGON2_AVX2=1`.

- SHA-3 auto-tune hysteresis: the dispatch microbench in
  `ama_dispatch.c` previously compared single-run timings and
  reverted the AVX2/NEON Keccak pointer to generic whenever
  `simd_ns > generic_ns` — a condition easily tripped by scheduler
  jitter on shared CI runners. The rewrite takes best-of-5 trials
  (min is jitter-resistant) and only reverts when SIMD is more than
  10 % slower than generic's best time. Opt out entirely with
  `AMA_DISPATCH_NO_AUTOTUNE=1`.

### Changed

- Remove dead `ama_ed25519_*_avx2` trampolines and associated dispatch
  wiring: the "AVX2" Ed25519 entry points forwarded directly to the scalar
  path (which already uses the fast `fe51` field), and the dispatch log
  claimed `Ed25519: AVX2` when no SIMD path executed. `ama_dispatch_info_t`
  now reports `AMA_IMPL_GENERIC` for `ed25519`, reflecting what actually
  runs. No runtime behavior change.

- Dependency consolidation (rolls up Dependabot #241–#246 into a single
  sweep applied consistently across `pyproject.toml`, `setup.py`,
  `setup.cfg`, `requirements*.txt`, and the relevant workflow pins):
  `github/codeql-action` 4.35.1 → 4.35.2 (SHA pinned);
  `pydantic` 2.12.5 → 2.13.2 paired with `pydantic_core` 2.41.5 → 2.46.2
  (pydantic 2.13.2 declares `pydantic-core==2.46.2` — verified via
  `importlib.metadata`); `ruff` 0.15.10 → 0.15.11 (lockfile) with the
  floor raised from `>=0.4.0` to `>=0.15.11` so the installed version
  always matches the lint ruleset in `pyproject.toml`;
  `PyKCS11` floor `>=1.5.0` → `>=1.5.18`; `sphinx-rtd-theme` major
  `>=1.2.0` → `>=3.1.0`. Incidental: dropped `canonical_url`,
  `analytics_id`, `logo_only`, and `display_version` from `docs/conf.py`
  (removed by sphinx-rtd-theme 3.x), fixed the `index.rst` title
  underline length, and added the missing `docs/_static/` referenced by
  `html_static_path`.

### Added

- **NIST ACVP self-attestation artifact.**
  `docs/compliance/ACVP_SELF_ATTESTATION.md` (formal, customer-facing),
  `docs/compliance/acvp_attestation.json` (machine-readable), and
  `.github/workflows/acvp_validation.yml` (continuous validation on
  push, PR, and weekly Monday cron with an `EXPECTED_VECTORS=815`
  floor) package the existing 815/815 AFT coverage from
  `CSRC_ALIGN_REPORT.md` into a formal deliverable. README gains a
  `## NIST Algorithm Compliance` section with prominent CAVP/CMVP/
  FIPS-140-3 non-endorsement disclaimers. **Self-attestation only —
  NOT CAVP, NOT CMVP, NOT FIPS 140-3.**

- `tests/c/test_x25519.c`: RFC 7748 §5.2 TV1/TV2, §6.1 Alice/Bob KATs
  (both directions), random DH symmetry, low-order point (`u = 0`)
  rejection, and NULL parameter validation.

- `tests/c/test_chacha20poly1305.c`: RFC 8439 §2.8.2 AEAD test vector
  (tag bytes asserted exactly), size sweep 1..4096 B crossing the
  512 B AVX2 threshold (511/512/513/1023/1024/1025 B), and tag-
  mismatch zero-plaintext verification. An independent scalar
  ChaCha20 block function embedded in the test serves as the
  reference — not the library itself — so SIMD regressions are
  caught even when both scalar and AVX2 paths drift together.

- `tests/c/test_argon2id.c`: six-case AVX2/scalar parity test using
  a test-only dispatch hook (`ama_test_force_argon2_g_scalar`,
  compiled only into `ama_cryptography_test` under
  `AMA_TESTING_MODE`), plus determinism, salt-divergence and
  parameter validation checks.

- Dispatch test hooks `ama_test_force_*_scalar` /
  `ama_test_restore_*_avx2` in `ama_dispatch.c`, guarded by
  `AMA_TESTING_MODE` so they never appear in the shipped library.

- Benchmark coverage for `ama_chacha20poly1305_encrypt` at 256 B,
  1 KB, 4 KB, 64 KB and `ama_argon2id` at m=64 KiB and m=1 MiB in
  `benchmarks/benchmark_c_raw.c`.

### Documentation

- Repository-wide documentation alignment sweep (2026-04-20): refreshed
  "Last Updated" headers across `README.md`, `ARCHITECTURE.md`,
  `SECURITY.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `CRYPTOGRAPHY.md`, `CONSTANT_TIME_VERIFICATION.md`, `MONITORING.md`,
  `ENHANCED_FEATURES.md`, `IMPLEMENTATION_GUIDE.md`, `THREAT_MODEL.md`,
  `CSRC_STANDARDS.md`, `CSRC_ALIGN_REPORT.md`,
  `AMA_CRYPTOGRAPHY_ETHICAL_PILLARS.md`, `.github/INVARIANTS.md`,
  `docs/DESIGN_NOTES.md`, `docs/METRICS_REPORT.md`,
  `docs/COMPETITIVE_ANALYSIS.md`, `wiki/Home.md`, and
  `wiki/Security-Model.md` to a consistent 2026-04-20 timestamp to
  restore cross-document date alignment. No functional or technical
  content was modified; historical release-history rows and
  benchmark-measurement dates were preserved.

- Post-review documentation correctness pass (2026-04-21):

  - **Wiki API rewrite.** Five wiki pages (`API-Reference`,
    `Quick-Start`, `Hybrid-Cryptography`, `Post-Quantum-Cryptography`,
    `Adaptive-Posture`, `Cryptography-Algorithms`, `Key-Management`)
    documented `CryptoMode`, `SymmetricCryptoAlgorithm`,
    `AsymmetricCryptoAlgorithm`, `PackageSigner`, `HybridSigner`, and
    `KeyManager` — classes that do not exist in `ama_cryptography/`.
    Every affected example was rewritten against the real API
    (`AmaCryptography` + `AlgorithmType`, `AESGCMProvider`,
    `HDKeyDerivation`, `KeyRotationManager`, `HybridCombiner.{encapsulate,
    decapsulate}_hybrid`). Every `from ama_cryptography...` import in
    the docs tree now resolves against the shipped package.

  - **Top-level doc fixes.** `AMA_CRYPTOGRAPHY_ETHICAL_PILLARS.md`
    imported `derive_keys` / `create_ethical_hkdf_context` from
    `crypto_api` instead of `legacy_compat` where they actually live;
    `CONTRIBUTING.md`'s example test referenced
    `generate_ed25519_keypair` / `sign_data` that never existed.
    Both corrected.

  - **Benchmark refresh.** Re-ran `benchmarks/benchmark_runner.py`,
    `benchmark_suite.py`, and `build/bin/benchmark_c_raw --json` on
    2026-04-21; refreshed the ops/sec tables in `README.md`
    (Performance Metrics section) and `wiki/Performance-Benchmarks.md`
    so they match `benchmark-results.json`. The previously documented
    figures (e.g. SHA3-256 18,205 ops/sec → 170,834 ops/sec; Ed25519
    sign 5,069 → 10,569 ops/sec; ML-DSA-65 verify 697 → 6,322 ops/sec)
    predated the PR #238 X25519 `fe51` rewrite and PR #239 ChaCha20 +
    Argon2 AVX2 wiring; the new tables reflect the current tree.

  - **Test / file counts.** Replaced the stale "1,855+ tests across 47
    files (37 Python + 10 C)" figure in `README.md` with the
    `docs/METRICS_REPORT.md` anchor of 2,028 Python test functions
    across 70 files plus 14 C test files.

  - **`docs/METRICS_REPORT.md` anchor.** The commit anchor `d4806b9`
    was unreachable in git history; replaced with a branch-snapshot
    note and a 2026-04-21 change-log entry documenting the rerun.

---


## [2.1.5] - 2026-04-17


### Added

- Add HSM support with PyKCS11 and improve fd leak protection (#217) (679f69b)
- Add comprehensive test coverage for secure_memory, crypto_api, and PQC backends (#230) (6deb1be)

### Fixed

- Fix three cryptographic audit findings; restore INVARIANT-13 with 52 tracked suppressions (#218) (2fa49e8)

### Security

- Security audit fixes: length-prefixed encoding, constant-time ops, and validation (#224) (b700050)
- PR #224 Follow-up: Add comprehensive test coverage for security audit fixes (#226) (ca8f357)

### Security — PR #224 Follow-up (Wire-Incompatible Changes)

The following changes from PR #224 are **deliberately wire-incompatible** with
prior versions.  They address security audit findings and MUST NOT be reverted
for backward compatibility.

- **Hybrid combiner HKDF construction (audit finding C6):** Salt and info fields
  now use fixed-size length-prefixed encoding to prevent ambiguous
  concatenation and component stripping attacks: component counts are encoded
  as `u8(count)`, and ciphertext/public-key fields are encoded as
  `u32be(len(field)) || field`.  Keys derived with the v2.1.4 construction
  will differ from v2.1.5+.
- **Secure channel protocol version bump (v1 → v2):** AAD now includes
  `rekey_epoch` to prevent multi-target tag forgery across key epochs (audit
  finding H2).  `PROTOCOL_VERSION` changed from `\x01` to `\x02`.
- **`ama_ed25519_scalar_mult` → `ama_ed25519_scalarmult_public` rename (audit
  finding C7):** A `#define` macro provides **source compatibility only** (not
  ABI).  Downstream C consumers linking against the shared library must
  recompile.
- **INVARIANT-7 enforcement in `HybridCombiner.combine()`:** Now raises
  `RuntimeError` instead of falling through to the Python HKDF fallback when the
  native C backend is unavailable.

### Changed — Code Hygiene (PR #224 Follow-up)

- Promoted inline magic numbers `_MAX_CT_BYTES`, `_MAX_SS_BYTES` (hybrid
  combiner) and `_MAX_FIELD_BYTES` (secure channel) to module-level named
  constants
- Added safety docstring to `HybridCombiner._hkdf_python()` marking it as
  internal test-only fallback (not constant-time; may only be used with
  controlled test inputs such as test vectors, never for production/live
  secret handling)
- Added comprehensive test coverage for `HandshakeResponse.deserialize()`
  validation paths (truncated, malformed, oversized inputs)
- Added test coverage for `create_handshake()` KEM encapsulation result
  validation (empty/invalid shared secret, empty ciphertext)
- Added regression test proving length-prefixed HKDF encoding prevents
  ambiguous concatenation attacks
- Added test coverage for `encapsulate_hybrid()` / `decapsulate_hybrid()`
  input validation (empty, oversized, non-bytes)

---
## [2.1.4] - 2026-04-14

### Security

- **CodeQL #297 (File is not always closed):** Guarded `os.fdopen()` calls in `legacy_compat.py` with explicit `os.close(fd)` on failure, matching the pattern used in `crypto_api.py`

### Added

- `AmaHSMUnavailableError` exception class in `ama_cryptography.exceptions` — always importable without PyKCS11 or native C library; raised instead of bare `ImportError` for missing HSM dependency
- `HSMKeyStorage.destroy_key()` alias for `delete_key()` for API symmetry
- feat(frost): add FROST threshold Ed25519 signing (RFC 9591) with KeypairCache (#193) (a8b23fa)

### Changed

- `HSM_AVAILABLE` module-level flag via `importlib.util.find_spec("PyKCS11")` — no import binding, no unused-import CodeQL alert
- `HSMKeyStorage._import_pykcs11()` now raises `AmaHSMUnavailableError` instead of `ImportError` for consistent exception contract
- Removed `PostureAction.HALT` enum value (unwired: no evaluator path produced it, `_execute_action` had no handler)
- feat: Cherry-pick audit fixes — AVX-512 stub, context API, benchmarks, ruff S110 hardening (#213) (caaedd0)
- chore: Consolidate completed dependency updates from Dependabot PRs #200-#208 (#212) (eee1e72)
- ci: Bump actions/upload-artifact from 7.0.0 to 7.0.1 (#196) (359d364)
- ci: Bump docker/build-push-action from 7.0.0 to 7.1.0 (#198) (5d8075e)
- ci: Bump trufflesecurity/trufflehog from 3.94.2 to 3.94.3 (#197) (fcf9f51)

---
## [2.1.3] - 2026-04-13

### Fixed — CodeQL Alert Resolution

- **Alert #343 (test_pqc_backends_coverage.py:264):** Replaced explicit `__del__()` call with `del`/`gc.collect()` pattern; finalizer verified via `finalizer_error_count()` before/after (INVARIANT-3 compliant)
- **Alert #272 (test_hsm_integration.py:628):** Replaced explicit `__del__()` call with `del`/`gc.collect()` pattern; mock assertions preserved
- **Alert #345 (legacy_compat.py:463, 473):** Replaced `try/except BaseException` fd wrapper with flat `with os.fdopen(fd, "wb")` pattern CodeQL traces natively — both occurrences fixed
- **Alert #20 (ama_ed25519.c:314):** Removed contradictory `__attribute__((hot))`, added `AMA_UNUSED` annotation to `ge25519_p1p1_to_p2` (function retained for future scalar multiplication)

---

## [2.1.2] - 2026-04-06

### Fixed - Critical Bug Fixes

- **SVE2 NTT correctness:** Fixed missing `lo_buf` store in `ama_dilithium_ntt_sve2` — butterfly low-half was never extracted to memory before Montgomery reduction, causing silent data corruption on AArch64 SVE2 platforms
- **NEON SHA3 Chi step:** Removed unused NEON vector variables in `ama_keccak_f1600_neon` Chi computation; replaced with correct scalar implementation
- **SHA2 header:** Added missing `<limits.h>` include to `ama_sha2.h` for portable `UINT_MAX`/`INT_MAX` usage
- **AVX2 Dilithium:** Added `AMA_UNUSED` annotation to `caddq_avx2` to resolve compiler warnings (function retained for future NTT post-processing)
- **Alert #318 (legacy_compat.py:474):** Fixed file descriptor not always closed — replaced `_open_fd` context manager with inline `os.fdopen()` try/with pattern that CodeQL traces natively
- **Alert #333 (ama_dilithium_avx2.c:77):** Resolved unused static function CodeQL alert

### Changed - CI/CD Improvements

- **Auto-docs workflow:** Replaced direct commit-and-push to `main` with PR-based flow using `gh pr create`, avoiding direct writes to protected branches
- **Workflow permissions:** Added `pull-requests: write` permission to `auto-docs.yml`
- **CI build matrix:** Added Windows MSVC to `ci-build-test.yml`; dropped `--no-build-isolation` from pip install
- **setup.py:** Added `ama_cryptography_monitor` as `py_module`; refactored `CMakeBuild.run()` to separate Cython extension builds from CMake library build; removed duplicate `super().run()` in `_build_cmake()` and unnecessary sentinel filtering

### Added - Compliance & Licensing

- **ed25519-donna LICENSE:** Added public domain license file for vendored ed25519-donna library
- **NOTICE:** Added third-party software attribution for ed25519-donna

### Changed - Documentation

- Synchronized all documentation dates to 2026-04-06 across 20+ files (README, ARCHITECTURE, SECURITY, CONTRIBUTING, wiki, and all standards/compliance documents)
- Updated version references to consistent `2.1.2` format across wiki and README

---

## [2.1.1] - 2026-03-26

### Security Fixes & SIMD Optimization (PR #145)

- **Security fixes S1-S6:** Hand-written AVX2/NEON/SVE2 SIMD intrinsics for polynomial and NTT operations
- **Dashboard & chart overhaul:** Updated performance visualization assets

### Fixed - Code Correctness (PR #143)

- **`_counters_dirty` immediate-retry:** Fixed race condition in counter dirty flag handling
- **INVARIANT-2 compliance:** Ensured thread-safe CPU dispatch via platform once-primitive (renumbered to INVARIANT-15 in a later docs-consolidation PR)
- **3 Devin review security fixes:** Addressed security issues identified during code review

### Documentation Corrections (PR #142)

- **C1-C5 documentation corrections:** Standardized "6-layer" terminology to "multi-layer" across README.md, ARCHITECTURE.md, SECURITY.md, wiki/Architecture.md, and ENHANCED_FEATURES.md
- **Layer architecture clarification:** Distinguished 4 core cryptographic operations (SHA3-256, HMAC-SHA3-256, Ed25519, ML-DSA-65) from supporting infrastructure (HKDF, RFC 3161, canonical encoding)
- **ML-DSA-65 signature size:** Corrected from 3,293 to 3,309 bytes per FIPS 204
- **Removed "production-grade" claims:** Replaced with accurate "community-tested, not externally audited" language
- **CI security audit fix:** Added CVE-2026-4539 (pygments ReDoS) exclusion to pip-audit across all CI workflows

### Changed - Dependency Consolidation (PR #140)

- Consolidated Dependabot PRs #130-#136 into a single CI/deps update

---

## [2.0.0] - 2026-03-07

### Changed - CI & Toolchain Overhaul (PR #116)

Resolved all CI failures with surgical, security-hardened fixes:

- **HMAC-SHA512 (INVARIANT-1 compliance):** Replaced stdlib `hmac` import with hand-rolled `_hmac_sha512()` in `key_management.py`, eliminating the last stdlib crypto dependency
- **Linter migration:** Fully replaced flake8 + isort with **ruff** (`ruff==0.15.6` pinned in `requirements-lock.txt`); updated `.pre-commit-config.yaml` and `Makefile`
- **Semgrep security scan:** Added Semgrep to CI pipeline (fail-closed), enforcing static security analysis on every PR
- **mypy --strict:** Now passes with 0 errors; mypy `python_version` bumped from `3.8` to `3.9` (mypy >=1.14 dropped 3.8 support); minimum Python bumped to 3.9
- **CVE-2026-26007 mitigation:** Pinned `cryptography>=46.0.5` in all CI workflows
- **cyclonedx-bom pinned:** `cyclonedx-bom==7.2.2` for reproducible SBOM generation
- **TruffleHog SHA bumped:** Updated to `d17df484…` commit SHA for secret scanning
- **MSVC shared library:** Switched from `WINDOWS_EXPORT_ALL_SYMBOLS` to explicit `AMA_API` (`__declspec(dllexport)`) macros for controlled symbol visibility
- **Native C `ama_consttime_memcmp` loader:** Added to `secure_memory.py` for hardware-speed constant-time comparison via ctypes

### Added - Phase 2 Cryptographic Primitives (PR #92)

Expanded the native C cryptographic library with additional primitives:

- **`ama_x25519.c`**: X25519 Diffie-Hellman key exchange (RFC 7748) — used as classical component in hybrid KEM combiner
- **`ama_chacha20poly1305.c`**: ChaCha20-Poly1305 AEAD (RFC 8439) — constant-time alternative to AES-256-GCM for shared-tenant environments
- **`ama_argon2.c`**: Argon2id memory-hard password hashing (RFC 9106) — configurable memory/time cost
- **`ama_secp256k1.c`**: secp256k1 elliptic curve operations — BIP32-compliant HD key derivation support

All 64 CI jobs passing after Phase 2 integration.

### Added - Constant-Time Testing & Fuzzing Infrastructure (PR #94)

- 11 coverage-guided fuzzing harnesses (libFuzzer) for all cryptographic primitives
- dudect-style constant-time verification harness with Welch's t-test (|t| < 4.5 threshold)
- Comprehensive threat model documentation (`THREAT_MODEL.md`) with threat catalog, mitigations, and verification matrix

### Changed - Benchmark Refactoring (PR #95)

- Refactored benchmark suite to target native C backend with updated performance baselines
- Removed legacy Python-only benchmarks that no longer reflect v2.0 architecture

### Changed - Import System Refactoring (PR #96)

- Refactored lazy loading to eager imports for math modules when numpy is available
- Fixed code quality issues identified during import system audit
- Improved error messages when optional dependencies are missing

### Fixed - Windows CI Resilience (PR #93)

- Made Windows CMake install resilient to Chocolatey CDN outages
- Added fallback mechanisms for package manager failures in CI

### Documentation Updates (2026-03-10)

- **Composition protocol clarification**: All documentation now accurately states that AMA Cryptography uses standardized primitives with an original composition protocol
- **Mercury Agent integration**: Documented AMA Cryptography's role as the cryptographic protection layer for [Mercury Agent](https://github.com/Steel-SecAdv-LLC/Mercury-Agent)
- **Ethical pillar redesign**: Consolidated from 12 named pillars to 4 Omni-Code Ethical Pillars (Omniscient, Omnipotent, Omnidirectional, Omnibenevolent), each governing a triad of three sub-properties (Wisdom, Agency, Geography, Integrity)
- **Phase 2 primitives**: Added X25519, ChaCha20-Poly1305, Argon2, secp256k1 to all relevant documentation

### Security Hardening

- **AES-256-GCM S-box documentation:** Corrected header comments that falsely claimed "bitsliced S-box". The implementation uses a standard 256-byte lookup table on round-key XOR'd state (public data). Added explicit side-channel caveat for shared-tenant environments.
- **Ed25519 thread safety:** Replaced `volatile int` check-then-set pattern with C11 `_Atomic` using `memory_order_acquire`/`memory_order_release` for base point and precomputed table initialization. Includes pre-C11 `volatile` fallback for MSVC/older compilers.
- **Ed25519 field arithmetic:** Replaced generic `fe25519_mul(h, f, f)` squaring with dedicated `fe25519_sq()` that exploits `f[j]*f[k] == f[k]*f[j]` symmetry, reducing ~100 multiplications to ~55 per squaring. Based on SUPERCOP ref10 `fe_sq`.
- **Ed25519 verification fixed:** Sign/verify roundtrip now passes RFC 8032 Test Vector 1 (public key, empty-message signature, and verification). Previously skipped due to field arithmetic issues.

### Changed

- **Ed25519 test suite:** Expanded from 6 tests (sign-only) to 12 tests including RFC 8032 KAT vector matching, full sign/verify roundtrip, tamper detection (modified signature and message rejection), and deterministic signature verification.
- **Ed25519 code cleanup:** Replaced verbose element-by-element `p3->p2` coordinate copying with `ge25519_p3_to_p2()` helper using `fe25519_copy()`.

### Added - Native C Cryptographic Library

Implemented native C cryptographic primitives for high-performance operations:

- **`ama_sha3.c`**: SHA3-256, SHAKE128, SHAKE256 with streaming API (init/update/final)
- **`ama_hkdf.c`**: HKDF-SHA3-256 with HMAC-SHA3-256 per RFC 5869
- **`ama_ed25519.c`**: Ed25519 keygen/sign/verify with windowed scalar multiplication
- **`ama_kyber.c`**: ML-KEM-1024 with NTT, inverse NTT, Montgomery reduction
- **`ama_dilithium.c`**: ML-DSA-65 (FIPS 204) with rejection sampling
- **`ama_sphincs.c`**: SPHINCS+-SHA2-256f (FIPS 205) with WOTS+/FORS/Hypertree
- **`ama_aes_gcm.c`**: AES-256-GCM authenticated encryption (NIST SP 800-38D)
- **`ama_consttime.c`**: Constant-time memcmp, memzero, swap, lookup, copy

### Added - Constant-Time Verification

- dudect-style Welch's t-test timing analysis harness for all 5 constant-time functions
- Threshold: |t| < 4.5 (dudect convention, ~10^-5 false positive probability)

### Added - Strict Type Checking

- Type annotations on all functions in `crypto_api.py`, `secure_memory.py`, `key_management.py`, `double_helix_engine.py`
- Enabled `disallow_untyped_defs = true` in mypy; `continue-on-error: false` in CI

### Added - Ethical Integration

- 12-dimensional ethical vector (4 triads x 3 pillars) cryptographically bound via SHA3-256
- `create_ethical_hkdf_context()`: integrates ethical vector into HKDF context parameter
- CryptoPackage schema extended with `ethical_vector` and `ethical_hash` fields
- Mathematical proof in SECURITY.md

### Changed - HKDF Algorithm Unification

**BREAKING:** `derive_keys()` now uses HKDF-SHA3-256 instead of HKDF-SHA256. Keys derived with v1.0.0 will differ. Regenerate all derived keys after upgrade.

### Improved - Code Quality

- Audited all 32 silenced checks (type: ignore, noqa, nosec, pragma: no cover)
- 94% confirmed necessary; 2 unnecessary `# noqa: E402` fixed; 2 unused variables removed

### Bug Fixes

- **ama_sha3.c:** Fixed undefined behavior in `rotl64()` when n=0 (64-bit shift by 64 is UB)
- **ama_ed25519.c:** Added missing `#include <stdlib.h>` for macOS clang compatibility

### Migration Guide

After upgrading to v2.0:
1. Regenerate all derived keys (HKDF algorithm changed)
2. Update CryptoPackage consumers for new `ethical_vector`/`ethical_hash` fields

---

## [1.0.0] - 2025-11-22

**First Public Release - Apache License 2.0**

### Core Cryptographic Features

**Six Independent Security Layers:**
- SHA3-256 content hashing (NIST FIPS 202)
- HMAC-SHA3-256 authentication (RFC 2104)
- Ed25519 digital signatures (RFC 8032)
- CRYSTALS-Dilithium quantum-resistant signatures (NIST FIPS 204)
- HKDF key derivation (RFC 5869, NIST SP 800-108)
- RFC 3161 trusted timestamps

### Added
- Apache License 2.0 with proper headers and NOTICE file
- `pyproject.toml`, `setup.cfg`, Black/isort/MyPy configuration
- GitHub Actions CI (Python 3.8-3.11), security scanning (CodeQL, Safety, Bandit)
- Dependabot, SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md
- Issue/PR templates with security checklists
- pytest test suite with `requirements.txt` and `requirements-dev.txt`

### Security
- Vulnerability disclosure process
- Security-focused code review requirements
- Automated security dependency updates

---

## Version History Summary

| Version | Date | Description |
|---------|------|-------------|
| 2.0.0 | 2026-03-07 | Zero-dependency native C, AES-256-GCM, adaptive posture, hybrid KEM combiner, Ed25519 atomics, Phase 2 primitives, CI hardening (PR #116: ruff, Semgrep, HMAC-SHA512, mypy --strict, CVE-2026-26007), FIPS 203/204/205 |
| 1.0.0 | 2025-11-22 | First public open-source release (Apache 2.0) |

---

## Upgrade Guide

### Installation

**Requirements:**
- Python 3.9 or higher

**Basic Installation:**
```bash
pip install ama-cryptography
```

**With Native PQC (Recommended):**
```bash
pip install ama-cryptography
cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build
```

**Development Installation:**
```bash
git clone https://github.com/Steel-SecAdv-LLC/AMA-Cryptography.git
cd AMA-Cryptography
pip install -e ".[dev]"
pytest
```

---

## Deprecation Notices

No features are currently deprecated.

---

## Security Advisories

No security advisories at this time.

Security advisories will be published at:
- GitHub Security Advisories: https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/security/advisories

---

Copyright 2025-2026 Steel Security Advisors LLC. Licensed under Apache License 2.0.
