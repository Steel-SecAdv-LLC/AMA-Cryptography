# Phase 0 — preflight reconciliation (2026-08-31)

Audit target: PR #394, head `steel/systempqc-maint1` @ `32c3e0de27b7c21ceb8067c3e79fdaad1c4565d4`,
base `main` @ `2dcef5c6ccf7aa95a00a460e525dfb500f59ea87` (base == merge-base; clean linear range).
Ledger rows `0.*` in `ledger.csv` carry the commands, exit codes, and log hashes.

## Stated figures vs measured

| Figure | Stated | Measured | Drift | Disposition |
|---|---|---|---|---|
| Diff additions | 83,074 | 82,900 (`git diff --numstat`, sum; identical with `--no-renames`) | GitHub API +174, additions only | git is ground truth for this audit; deletions (7,481) and file count (1,063) match exactly, so the +174 is a GitHub-side accounting artefact, not missing content |
| Diff deletions | 7,481 | 7,481 | none | — |
| Changed files | (implied) | 1,063 | none | `changed-files.txt` is the inventory checklist |
| Commits | 347 | 347 (`git rev-list --count`) | none | — |
| Test census | 4,769 | **6,676 collected** (`pytest --collect-only -q`) | **+1,907** | directive figure is stale; PR body's "6,125 passed / 49 skipped" (at `7432e0d`) and "6,016 passed / 96 skipped" (at `f8873ae`) bracket the current head. Baseline full-suite run to follow. |
| Binary files in diff | — | 678 (corpus seeds, PNGs; zero line contribution) | — | — |

## Silicon (item 17 precondition) — **FAIL, scope reduction flagged now**

`lscpu`: Intel Xeon @ 2.80GHz (Cascade Lake-class virtualized), 4 cores, no SMT.
Present: `avx512f avx512dq avx512cd avx512bw avx512vl avx512_vnni aes pclmulqdq avx2`.
**Absent: `vaes`, `vpclmulqdq`.**

Consequence: item 17's "AVX-512 + VAES" lane cannot be measured on this host.
What CAN run here: AVX-512F/VL kernels (Keccak 4-way etc.), AES-NI, PCLMULQDQ,
AVX2 — dudect + CT harness will cover every lane this silicon exposes, and the
VAES/VPCLMULQDQ lane is reported as environment-impossible (matches PR body's
release-prerequisite 3, which already calls for Sapphire Rapids / Zen 4 hardware).

## Environment

- Python 3.11.15, gcc 13.3.0, clang 18.1.3, cmake 3.28.3 (C tree needs only ≥3.15;
  the pip path pulls cmake≥4.4.0 into the isolated build env), valgrind present.
- 4 CPUs, 15 GiB RAM, ~30 GiB free disk.
- Docker: daemon was NOT running at session start. First probe wrongly reported
  success because the probe's own `echo` swallowed the exit code — corrected;
  ledger row 0.4a (first) records the honest FAIL, second 0.4a row records the
  working state after starting `dockerd --iptables=false --bridge=none`
  in-session (sandbox lacks iptables; containers run with `--network=host`).
- Egress: rekor.sigstore.dev, tuf-repo-cdn.sigstore.dev, pypi.org,
  registry-1.docker.io, storage.googleapis.com, freetsa.org all reachable.
- Constraint: direct `api.github.com` is proxy-blocked; GitHub API access goes
  through the session's GitHub MCP tools only. Artifact downloads for item 1
  use that path.

## Artifact availability (item 1 precondition) — retained

All 9 artifacts of run 33338946996 exist, `expired=false`, and are bound to the
current PR head SHA `32c3e0d`. **The SLSA provenance
(`ama-cryptography.intoto.jsonl`) expires 2026-09-04T22:34Z — 4 days out**;
item 1 runs early. Digests in `logs/phase0-artifacts-mcp.log`.

## Branch note

The session harness had created `claude/pr-394-v5-audit-klt6x8` from `main`
(no PR content). Per the operator directive's hard constraint 1 — which is the
explicit permission the harness rule requires — all audit work happens on
`steel/systempqc-maint1` and nothing else is pushed.

## Immediate flags (directive: "flagged here, immediately")

1. **Item 17 VAES/VPCLMULQDQ lane: environment-impossible on this host** (above).
2. Directive's test figure (4,769) is stale by +1,907; not silently adopted.
3. GitHub's +174 additions figure is not reproducible from git; git ground
   truth adopted.
4. Effort floors vs hardware: 15 fuzz targets × ≥2 h = ≥30 CPU-hours on
   4 cores, plus TSan/Helgrind ≥2 h each, Valgrind full C suite, ≥60 min
   refleak soak, mutation testing. These are sequenced for maximal completion;
   anything not complete at report time is labeled partial (forcing the
   DO-NOT-MERGE default) rather than floor-lowered.
