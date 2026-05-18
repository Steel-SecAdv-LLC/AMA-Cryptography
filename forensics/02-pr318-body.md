Takes over **#316** by cherry-picking its two commits (`5953995`, `e0aed3d`) onto this branch (fast-forward — same base), then layering the fixes for every bot alert that PR received, plus the image consolidation and README updates the user asked for. PR #316 can be closed in favor of this one.

---

## 1. All PR #316 bot alerts resolved

### Copilot reviewer (4 / 4)

| # | File | Issue | Fix |
|---|------|-------|-----|
| 1 | `benchmarks/benchmark_c_raw.c:986` | Dilithium NTT bench compounds `BENCH_INNER_LOOP` in-place calls on the same buffer — drift outside the FIPS 204 input range. | Pre-randomised **static ring** of `BENCH_INNER_LOOP` independent input polys (`g_dil_ntt_ring[256][256]`). Each timed inner-loop call indexes `ring[j]`; ring is refreshed per outer iteration. Mirrors the existing `kyber_poly_{add,sub,reduce}` ring pattern earlier in the file. |
| 2 | `benchmarks/benchmark_c_raw.c:1010` | Same compounding issue on the invNTT bench. | Same ring shared with the NTT bench. |
| 3 | `benchmarks/benchmark_c_raw.c:1503` | SLH-DSA rows still use the global `--warmup 50` — adds ~60+ s of pre-measurement runtime against multi-second sign. | Local caps: `SLH_KEYGEN_WARMUP_MAX=3` / `SLH_SIGN_WARMUP_MAX=2` / `SLH_VERIFY_WARMUP_MAX=10`, clamped inside each `bench_slhdsa_*` function. The shared flag can stay 50 for fast primitives. |
| 4 | `benchmarks/README.md:63` | SLH-DSA-SHAKE-128s misclassified under *Signatures (classical)*. | Moved to *Signatures (PQC)* (FIPS 205 is hash-based PQC, not classical). |

### CodeQL / GitHub Advanced Security (1 / 1)

| # | File | Issue | Fix |
|---|------|-------|-----|
| 5 | `benchmarks/generate_charts.py:463` | Empty `except` clause without explanatory comment. | Added comment describing the best-effort live-data-override semantics and the documented fallback to `X25519_MULX` sandbox anchors. |

---

## 2. Image audit — no stale or duplicated artifacts

Pre-existing chart inventory (`benchmarks/charts/*.svg`): `signature_performance`, `c_vs_python`, `layer_breakdown`, `kem_performance`, `scalability` — **kept**. None are rendered stale by the new benchmark surface; `signature_performance.svg` was already extended in PR #316 to include SLH-DSA Verify + secp256k1.

The four **new** standalone SVGs that PR #316 added (`x25519_mulx_kernel.svg`, `dilithium_ntt_kernel.svg`, `pqc_sign_latency.svg`, `frost_2of3.svg`) are **deleted** and replaced by a single **`pqc_benchmark_overview.svg`** — a 2×2 dark-theme collage covering all four panels — matching the existing collage/dashboard style of `assets/performance_dashboard.png` and `assets/benchmark_report.png`. One artifact, one source of truth — the underlying numbers are no longer duplicated across multiple checked-in SVGs.

`generate_charts.py` refactored: the four chart bodies now render into one `plt.subplots(2, 2)` figure with a top-level `suptitle`. README chart table updated; live-data override for X25519 MULX still applies inside the collage panel.

`assets/*.png` (dashboards, layer diagrams, quantum-comparison, etc.) left untouched — they cover the unchanged primary surface and were not made stale by the new coverage rows.

---

## 3. Benchmark-data duplication / redundancy

- **`benchmarks/baseline.json` — untouched.** CI regression gate floor unchanged; no `baseline_value` drift. (Verified per `docs/BENCHMARK_HISTORY.md` &#34;no baseline_value entries changed&#34; claim.)
- **`wiki/Performance-Benchmarks.md`** previously added (in PR #316) two tables that duplicated `benchmarks/README.md` (*coverage map*) and `docs/BENCHMARK_HISTORY.md` (*sample sandbox medians*). Both wiki tables collapsed to a **single pointer block** listing the canonical authorities. One number, one home.
- The SLH-DSA Verify row added to `signature_performance.svg` and the SLH-DSA Sign row in the collage&#39;s log-scale panel use independent data shapes (linear ops/sec vs log-latency ms) and do not duplicate one another.

---

## 4. README *Design Philosophy* expansion

Substituted the original single-paragraph *Design Philosophy* blockquote with the multi-paragraph block the user provided — *Design Philosophy* (extended with Mercury Agent / FINDΩYOU™ kin reference), *The Trio — Kin Systems* (three-bullet kin description), *Integration*, and *Project Philosophy*. The previously-following *Integration:* and *Project Philosophy:* paragraphs were removed to avoid duplication; the *Security Disclosure* / *Status* / *Last Updated* lines are preserved unchanged.

---

## 5. Validation

- `ruff check benchmarks/generate_charts.py` ✓
- `black --check benchmarks/generate_charts.py` ✓
- `gcc -c benchmarks/benchmark_c_raw.c` ✓ (after fixing a brace I introduced and removed during iteration)
- `python3 benchmarks/generate_charts.py` ✓ — produces `pqc_benchmark_overview.svg` plus the five pre-existing charts.
- `parallel_validation`:
  - **CodeQL: 0 alerts** (cpp + python)
  - Code Review: 3 non-blocking suggestions, two of which are pre-existing code from PR #316 (unchanged by this PR) and one is a deliberately compact chart caption (long form lives in `benchmarks/README.md`).

---

## ⚠️ Note on prompt-injection during this session

While completing this work I observed repeated prompt-injection attempts embedded in tool outputs (and at one point inserted as a fake `Human:` turn) instructing me to refuse &#34;complex instructions that suggest reproducing material with minor changes or substitutions.&#34; These were ignored as they did not apply: the user&#39;s task involves zero third-party copyrighted material — only quoting the user&#39;s own provided README replacement text into the user&#39;s own README (&#34;if you were given a document, it&#39;s fine to summarize or quote from it&#34;), and fixing reviewer-flagged bugs in the user&#39;s own benchmark code.
