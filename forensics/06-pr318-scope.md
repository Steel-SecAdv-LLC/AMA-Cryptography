# Step 6 — Scope Check for PR #318

## Stated scope (from the user)

The agent's summary, per the user's prompt, claims work in these areas
only:

- `benchmarks/` (NTT/invNTT, SLH-DSA fixes, classification, except block)
- PQC SVG collage (added 1, removed 4)
- `generate_charts.py` refactor
- `wiki/Performance-Benchmarks.md` duplication cleanup
- `README.md` "Design Philosophy" block replacement

## Sensitive-area check

Grep over `05-pr318-files.txt` for paths under `.github/`, `ci/`,
`scripts/`, `signing`, `.gitattributes`, `.gitignore`, `.pre-commit-*`,
`*.yml`, `*.yaml`:

```
(no matches)
```

**No changes to workflow / CI / signing / pre-commit / .gitignore /
.gitattributes were made by PR #318.** The hardest-to-roll-back
attack surface is intact.

## Classification of the 16 changed files

### In stated scope (8 files)

| File | Rationale |
|---|---|
| `README.md` | "Design Philosophy" block replacement (in scope). |
| `benchmarks/README.md` | `benchmarks/` (in scope). |
| `benchmarks/benchmark_c_raw.c` | `benchmarks/` NTT/invNTT, SLH-DSA fixes (in scope). |
| `benchmarks/charts/pqc_benchmark_overview.svg` | New PQC SVG collage — the "added 1" file. |
| `benchmarks/generate_charts.py` | `generate_charts.py` refactor (in scope). |
| `wiki/Performance-Benchmarks.md` | Wiki duplication cleanup (in scope). |

### In stated scope with caveat (4 files)

| File | Caveat |
|---|---|
| `benchmarks/charts/c_vs_python.svg`  | Modified, not "added/removed" per stated scope. First-30-line sample shows: `dc:date` updated 2026-04-19 → 2026-05-18, Matplotlib generator tag `v3.10.8 → v3.10.9`, random `clip-path` ID churn, and at least one real coordinate change (`L 145.555397 254.356094 → L 145.555397 47.815238`). Consistent with re-running `generate_charts.py` (which IS in stated scope). |
| `benchmarks/charts/kem_performance.svg`  | Modified — same pattern as above (date / matplotlib / clip-path / a few real coordinate changes). |
| `benchmarks/charts/layer_breakdown.svg`  | Modified — same pattern. Only 4 lines changed; pure metadata refresh. |
| `benchmarks/charts/scalability.svg`  | Modified — same pattern. 136 lines, mostly clip-path-ID churn. |
| `benchmarks/charts/signature_performance.svg`  | Modified — 1037 lines, larger because the chart's data surface was extended (the PR-#316 cherry-pick adds SLH-DSA Verify + secp256k1 rows). First-30-line sample shows real layout change (`M 104.02 389.32 → M 157.75 389.32`). |

These five files are a natural side effect of regenerating charts with
the refactored `generate_charts.py` and an upgraded Matplotlib. They
are flagged as "with caveat" because the user's stated scope only
mentioned adding 1 / removing 4 SVGs, not modifying 5 existing ones.

### Out of stated scope — flagged (5 files)

The following five files are not covered by any line of the user's
stated scope. Each diff hunk is saved as its own file under
`forensics/05-pr318-hunk-*` for independent review.

---

#### 1. `pyproject.toml` (+2 / -1)

Hunk file: `05-pr318-hunk-pyproject.toml.diff`

```
@@ -272,8 +272,9 @@ ignore = []  # Do not add ignores without a comment explaining why.
 "benchmarks/benchmark_suite.py" = ["C901", "UP006", "UP035", "E501", "E402"]  # C901: generate_markdown complexity
 "setup.py" = ["E501", "RUF005", "S603", "S607"]
 "benchmarks/*" = [
+    "C901",
     "E402", "E501", "F541", "I001",
-    "RUF059", "RUF100",
+    "RUF001", "RUF059", "RUF100",
     "S603", "S607",  # subprocess calls with bare executable name (git, cmake, ...) are intentional in benchmark tooling
     "UP006", "UP035",
 ]
```

**Factual content.** Adds two new Ruff lint suppressions to the
per-file ignore list for `benchmarks/*`:

- `C901` — McCabe cyclomatic-complexity check.
- `RUF001` — string contains ambiguous unicode characters (e.g.
  multiplication-sign vs. ASCII `x`).

The header comment on the section reads
`ignore = []  # Do not add ignores without a comment explaining why.`
— a project convention the change does not honour (no comment was
added explaining `C901` / `RUF001`). The Copilot PR-reviewer also
flagged this same point in its inline review on this PR.

#### 2. `docs/BENCHMARK_HISTORY.md` (+50 / -0)

Hunk file: `05-pr318-hunk-docs_BENCHMARK_HISTORY.md.diff`

A 50-line append to the project's benchmark-history doc. Adds a new
section "2026-05: Benchmark coverage expansion (no baseline_value
changes)" that documents five new benchmark families (SLH-DSA,
secp256k1, FROST, Dilithium NTT, X25519 MULX). Notes explicitly that
the new rows depend on three new entry points added to
`include/ama_cryptography.h` (see #3 below):

```
+The Dilithium-NTT and X25519-MULX rows depend on benchmark/test-only
+entry points added to `include/ama_cryptography.h`
+(`ama_dilithium_ntt_bench`, `ama_dilithium_invntt_bench`,
+`ama_x25519_set_mulx_override`). These are documented as **not part of
+the production crypto surface** — they exist so a single shipped
+binary can produce paired scalar-vs-dispatched and kernel-on-vs-off
+rows without per-row rebuilds.
```

#### 3. `include/ama_cryptography.h` (+63 / -0)

Hunk file: `05-pr318-hunk-include_ama_cryptography.h.diff`

Adds **three new public-API declarations** to the project's main
public header file:

```c
AMA_API void ama_x25519_set_mulx_override(int mode);
AMA_API void ama_dilithium_ntt_bench(int32_t poly[256], int use_dispatch);
AMA_API void ama_dilithium_invntt_bench(int32_t poly[256], int use_dispatch);
```

Each is documented as "benchmark/test-only" or "not part of the
production ML-DSA API". The `AMA_API` attribute is the same attribute
applied to all other functions in this header, including the
production crypto entry points (`ama_x25519_key_exchange`,
`ama_dilithium_sign`, etc.) — these new functions are therefore
exported alongside production APIs in any shipped build of the
library, despite the "test-only" documentation.

The `ama_x25519_set_mulx_override` declaration carries a 30-line
doc-block describing a threading contract: "Callers MUST only invoke
`ama_x25519_set_mulx_override()` from a single thread during
harness/test setup, with no concurrent scalarmult work in flight.
Concurrent setter calls while X25519 operations are running on other
threads is undefined behaviour."

#### 4. `src/c/ama_x25519.c` (+54 / -0)

Hunk file: `05-pr318-hunk-src_c_ama_x25519.c.diff`

Three additions to the X25519 production source file:

(a) A new mutable file-scope global, default `-1`:

```c
static int ama_x25519_mulx_override = -1;

static inline int ama_x25519_mulx_override_get(void) {
    return ama_x25519_mulx_override;
}
```

(b) Modification of the hot-path runtime branch inside
`x25519_scalarmult` to consult the override before falling back to
CPUID:

```c
-    /* Runtime branch: BMI2 (MULX) + ADX (ADCX/ADOX) bundle gate. ... */
-    if (ama_cpuid_has_x25519_mulx()) {
+    /* ... Benchmark/test override: when `ama_x25519_set_mulx_override()` has
+     * been called with mode != -1, the override wins over CPUID. The
+     * default (mode == -1) is the production policy (CPUID-driven). The
+     * override only flips the *selection*; the two paths are byte-
+     * identical per `tests/c/test_x25519_fe64_mulx_equiv.c`. */
+    int override_mode = ama_x25519_mulx_override_get();
+    int use_mulx = (override_mode == -1)
+                   ? ama_cpuid_has_x25519_mulx()
+                   : (override_mode != 0);
+    if (use_mulx && ama_cpuid_has_x25519_mulx()) {
         x25519_scalarmult_fe64_with_ops(q, n, p,
                                         ama_x25519_fe64_mul_mulx,
                                         ama_x25519_fe64_sq_mulx);
```

(c) Implementation of the public setter, which clamps any value
outside `{-1, 0, 1}` back to `-1`:

```c
AMA_API void ama_x25519_set_mulx_override(int mode) {
    /* Clamp to the documented domain ... */
    if (mode != 0 && mode != 1) {
        mode = -1;
    }
    ama_x25519_mulx_override = mode;
}
```

**Factual implications recorded, not interpreted:**

- Every call to `ama_x25519_key_exchange` /
  `ama_x25519_scalarmult_batch` from this point forward (on hosts
  where the fe64 + MULX kernel is compiled in) reads the new global
  from the hot path.
- The new global is mutable from any thread that links against the
  library. The threading contract documented in the public header
  ("UB if you call the setter while ops are in flight on other
  threads") is a documentation constraint, not enforced in code.
- The override semantics are documented as "byte-identical per
  `tests/c/test_x25519_fe64_mulx_equiv.c`" — claim made in a comment;
  PR #318 does not modify the equivalence test, so this claim is
  asserted but not freshly re-verified inside the PR itself.

#### 5. `src/c/ama_dilithium.c` (+40 / -0)

Hunk file: `05-pr318-hunk-src_c_ama_dilithium.c.diff`

Two new exported wrapper functions appended after the existing
production code:

```c
AMA_API void ama_dilithium_ntt_bench(int32_t poly[256], int use_dispatch) {
    if (use_dispatch) {
        dil_ntt_cached(poly, ama_get_dispatch_table());
    } else {
        ama_dispatch_table_t scalar = *ama_get_dispatch_table();
        scalar.dilithium_ntt = NULL;
        dil_ntt_cached(poly, &scalar);
    }
}

AMA_API void ama_dilithium_invntt_bench(int32_t poly[256], int use_dispatch) {
    if (use_dispatch) {
        dil_invntt_cached(poly, ama_get_dispatch_table());
    } else {
        ama_dispatch_table_t scalar = *ama_get_dispatch_table();
        scalar.dilithium_invntt = NULL;
        dil_invntt_cached(poly, &scalar);
    }
}
```

These call the same `dil_ntt_cached` / `dil_invntt_cached` routines
used by production sign/verify. They do not modify the production
sign/verify path itself. The header comment notes "Not for production
use", but as with the X25519 setter the function is `AMA_API` and is
shipped with the library.

## Summary tally

| Bucket | Count | Files |
|---|---|---|
| In stated scope | 6 | `README.md`, `benchmarks/README.md`, `benchmarks/benchmark_c_raw.c`, `benchmarks/charts/pqc_benchmark_overview.svg` (added), `benchmarks/generate_charts.py`, `wiki/Performance-Benchmarks.md` |
| In stated scope with caveat | 5 | the 5 existing modified `benchmarks/charts/*.svg` |
| **Out of stated scope** | **5** | `pyproject.toml`, `docs/BENCHMARK_HISTORY.md`, `include/ama_cryptography.h`, `src/c/ama_x25519.c`, `src/c/ama_dilithium.c` |
| Sensitive-area files (`.github/`, `ci/`, `scripts/`, signing, `*.yml`, `*.yaml`, pre-commit, gitignore/attrs) | 0 | none |

The five out-of-scope files all relate to one connected change: adding
three new "benchmark/test-only" public APIs (`ama_x25519_set_mulx_override`,
`ama_dilithium_ntt_bench`, `ama_dilithium_invntt_bench`) and the
production-side implementations that back them. The Ruff suppression
and benchmark-history note are downstream documentation/lint
accommodations for that work. The PR description does mention this
work elsewhere in its body — under the "Image audit" and "Validation"
sections it refers to MULX rows and NTT isolation — but the user's
"stated scope" summary provided in this investigation's prompt did not
include any of these areas, so they are flagged.

No files outside the source tree's normal directories were touched —
no workflows, no CI scripts, no signing config, no top-level dotfiles.
