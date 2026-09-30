# Adversarial review — PR #407 (branch `steel/version-cov5`)

**Date:** 2026-09-29 · **Base diff reviewed:** full branch at `1ef0c93`
**Severities:** AGENTS.md §7 · **Standard of evidence:** AGENTS.md §6 (measure
before asserting; mutation-test every guard claimed protected)

This is the fourth adversarial review of the branch. It found twelve items —
one High family of four, three Medium, and five Low — each located against the
tree and reproduced before the fix. Every behavioural fix carries a test that
fails against the previous code, established by mutation (§6.2). This document
is the review's index and verdict; the authoritative per-finding record, with
each fix's mutation count and the exact strings and measurements, is the
**"fourth adversarial review"** round in `CHANGELOG.md`, and each fix lives in
the commit that touches its file.

## Verdict

No Critical finding. All twelve are fixed at source. The full C suite (`ctest`)
and Python suite (`pytest tests/`) pass, and the §9 gate set is green (see
**Verification**). Two §6.6 corrections were also made to the third review's
CHANGELOG entry, where measurement contradicted it (the POST record and the
SLH-DSA compile-time assertion).

## Findings

| # | Sev | Area | Fix (see CHANGELOG for detail) |
|---|-----|------|--------------------------------|
| 1–4 | **High** | `check_crypto_construction_docs.py`, five texts + two diagrams | The retired quantum-strength claim survived in orders and forms the gate could not read (reversed order, a parenthesised strength, "PQ", 128/256 magnitudes). A sentence-scoped rule, `_rule_quantum_bit_strength`, is added beside the work-factor rule; every text is restated as its NIST category (ML-DSA-65 cat 3 / FIPS 204, SLH-DSA-SHA2-256f cat 5 / FIPS 205); the quantum chart no longer draws a fabricated post-quantum bit bar, and `quantum_comparison.png` / `defense_layers.png` are regenerated. §6.6: the earlier "every instance is corrected" / "matches whichever order" records are corrected. |
| 5 | Medium | `measure_branch_coverage.py` | The child suites ran with the caller's `PYTEST_ADDOPTS`, so a `-k`/`-m`/`--lf` narrowed the run while counters still moved and inflated the never-taken figures. The suites now run without it (`_suite_env`); an option is passed via `--pytest-arg`. |
| 6 | Medium | `_self_test.py` | A failed POST's own run could be buried by an ERROR racing into the recording window. `last_failure()` gains a `failed_post` key that carries the failing run from its own sequence and reason with its table; the live-ERROR keys keep their meaning. §6.6 correction to the third review's "decided by that number". |
| 7 | Medium | `check_vendor_isolation.py` | The container-recipe scan caught an `ImportError` of `tools._repo` and walked inside a checkout — fail-open. The walk moved into `tools._repo`; a failed import is now an error in both modes and the gate exits 2. |
| 8 | Low | `tools/_repo.py` + three call sites | `worktree_names(root, *pathspecs, walk_skip_dirs=())` now carries the tracked-or-walk split once; three hand-rolled sites converge onto it. A `**` sharing its path component is refused (git reads it as `*` only in some positions), checked by a fuzz differential against `git ls-files`. |
| 9 | Low | `ama_cryptography/__init__.py` | The refused-import traceback strip followed only `__cause__`/`__context__`; it now walks a `BaseExceptionGroup`'s members too (recognised by type, skipped below Python 3.11 where no group can be raised). Hardening — nothing in the package raises a group today. |
| 10 | Low | `src/c/ama_slhdsa.c` | `SLH_MAX_N` was enforced by a per-row `_Static_assert` a new row could omit, reading `n` alone. The parameter table is now one X-macro list, `SLH_PARAM_ROWS`, and one `_Static_assert` checks every column's maximum against the bound each row-sized buffer is declared through. Shipped objects byte-identical. |
| 11 | Low | `ama_testing_exports.h`, `ama_slhdsa.c` | The fault-hook comment said "per SHAKE absorb, in call order"; it is consulted once per hash call, at its finish (in `shake_finish` after the squeeze for SHAKE), skipped after an earlier failed step. Comments corrected and the position pinned by `test_slhdsa_fault_residue.c`. Shipped objects byte-identical. |
| 12 | Low | `measure_branch_coverage.py` | `_undo_swap` read both libraries whole to decide whether the swap happened. The backup's digest is now taken once at swap time and compared against a block-streamed digest of the installed file. |

## Verified clean (not re-opened)

Per the review's own list: the SHAKE finalizer scrub, the CSPRNG-failure
scrubs, the FROST verdict and position validation, POST lock ordering,
`_finish_self_test`'s compare-and-set, and `check_crypto_permitted`'s refusals.

## The two framing asks

- **`pqc_backends.py` nit.** The three optional Cython bindings
  (`ed25519_binding`, `dilithium_binding`, `hkdf_binding`) were imported behind
  a bare `# type: ignore` that silenced every error on the line, not just the
  missing import. They now join `hmac_binding` and `math_engine` in the
  `[[tool.mypy.overrides]]` block for extension modules with no stubs
  (`ignore_missing_imports`), and the imports are the clean idiomatic form with
  no inline marker — the same treatment `hmac_binding` already had. mypy
  `--strict` and the suppression-hygiene gate both pass; three bare markers
  removed.
- **This report**, saved under `docs/reviews/`.

## Verification (AGENTS.md §9)

- `black --check .`, `ruff check .`, `flake8 .` — clean.
- `mypy --strict` (CI scope) — the changed files add no error.
- `check_crypto_construction_docs.py`, `check_suppression_hygiene.py`,
  `check_vendor_isolation.py`, `check_headers.py`, `refresh_derived_docs.py`
  (reached its fixpoint) — all green.
- `ctest` — pass, 0 failures. `pytest tests/` — pass.
- The integrity digest was refreshed and signed after the package `.py` change;
  `_integrity_signature.py` is per-build and gitignored, so only
  `_integrity_digest.txt` is committed.

## Note recorded for the maintainer (not acted on)

The gate's `_rule_quantum_bit_strength` deliberately passes a line that pairs a
bit-strength phrase with its NIST category, so `pqc_backends.py`'s two
`KyberKeyPair`/`SphincsKeyPair` docstrings — `"256-bit classical / 128-bit
quantum security (NIST security category 5)"` — are accepted although the
bit-strength half is the retired phrasing. This is the construction gate's
design (a category anchor on the line is treated as corrected), so it is left
to the finding-1–4 owner rather than tightened here.
