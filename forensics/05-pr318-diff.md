# Step 5 — Full Diff of PR #318 against its base

Base: `origin/main` @ `d9757ef1514926f54519359eaede32f63f5495d3`
Head: `refs/forensics/pr318-head` @ `9e03407c7d71d7dc3ea0b9dfc76fec53d950f1a8`
Merge-base: `d9757ef1514926f54519359eaede32f63f5495d3` (= base; PR is rebased on tip of main)

Commands run (all read-only):

```
git diff origin/main..refs/forensics/pr318-head > forensics/05-pr318.diff
git diff --stat origin/main..refs/forensics/pr318-head > forensics/05-pr318.stat
git diff --name-only origin/main..refs/forensics/pr318-head > forensics/05-pr318-files.txt
git diff --name-status origin/main..refs/forensics/pr318-head > forensics/05-pr318-name-status.txt
```

## Artifacts written

| File | Lines | What it contains |
|---|---|---|
| `05-pr318.diff` | 9371 | Full unified diff, all 16 files, no truncation. |
| `05-pr318.stat` | 17 | `git diff --stat` summary (matches API: 7359 insertions, 779 deletions, 16 files). |
| `05-pr318-files.txt` | 16 | Bare file path list (one per line, no status). |
| `05-pr318-name-status.txt` | 16 | Same list with A/M/D/R status prefix. |

## File inventory (with change type)

```
M	README.md
M	benchmarks/README.md
M	benchmarks/benchmark_c_raw.c
M	benchmarks/charts/c_vs_python.svg
M	benchmarks/charts/kem_performance.svg
M	benchmarks/charts/layer_breakdown.svg
A	benchmarks/charts/pqc_benchmark_overview.svg
M	benchmarks/charts/scalability.svg
M	benchmarks/charts/signature_performance.svg
M	benchmarks/generate_charts.py
M	docs/BENCHMARK_HISTORY.md
M	include/ama_cryptography.h
M	pyproject.toml
M	src/c/ama_dilithium.c
M	src/c/ama_x25519.c
M	wiki/Performance-Benchmarks.md
```

Summary by change type vs `origin/main`:

- **1 file added** — `benchmarks/charts/pqc_benchmark_overview.svg`
- **15 files modified**
- **0 files deleted**

Stat-by-file (from `05-pr318.stat`):

```
 README.md                                    |   17 +-
 benchmarks/README.md                         |   62 +-
 benchmarks/benchmark_c_raw.c                 |  443 +-
 benchmarks/charts/c_vs_python.svg            |  355 +-
 benchmarks/charts/kem_performance.svg        |   48 +-
 benchmarks/charts/layer_breakdown.svg        |    4 +-
 benchmarks/charts/pqc_benchmark_overview.svg | 5575 ++++++++++++++++++++++++++
 benchmarks/charts/scalability.svg            |  136 +-
 benchmarks/charts/signature_performance.svg  | 1037 +++--
 benchmarks/generate_charts.py                |  215 +
 docs/BENCHMARK_HISTORY.md                    |   50 +
 include/ama_cryptography.h                   |   63 +
 pyproject.toml                               |    3 +-
 src/c/ama_dilithium.c                        |   40 +
 src/c/ama_x25519.c                           |   54 +-
 wiki/Performance-Benchmarks.md               |   36 +-
 16 files changed, 7359 insertions(+), 779 deletions(-)
```

Totals exactly match the GitHub-side API report for this PR (16 files /
7359 / 779).

## Incidental observation (deferred to Step 6)

PR #318's body asserts that the change "deletes" four SVGs added in
PR #316 (`x25519_mulx_kernel.svg`, `dilithium_ntt_kernel.svg`,
`pqc_sign_latency.svg`, `frost_2of3.svg`) and replaces them with one
(`pqc_benchmark_overview.svg`). Against the base actually used by this
PR (`origin/main`), those four files **never existed** — they were
added on PR #316's branch which was never merged. The diff against
main therefore shows `+1` new SVG and `0` deletions, not `+1/-4`. This
is consistent with PR #316 having been abandoned (per PR #318's own
"PR #316 can be closed in favor of this one"), but means the PR-body
description of "removed 4" is in PR #316-relative terms, not
main-relative terms. Not flagged as alarming — formal scope analysis
follows in Step 6.
