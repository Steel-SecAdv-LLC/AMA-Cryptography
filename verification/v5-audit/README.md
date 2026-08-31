# v5.0 pre-merge audit — verification ledger

Evidence directory for the PR #394 pre-merge audit (operator directive of
2026-08-31).  Everything here is append-only: corrections are new rows and
new files, never edits to committed history.

## Layout

- `ledger.csv` — one row per verification run.  Columns:
  `item,command,exit_code,threshold,verdict,log_path,log_sha256,runtime_s,utc_timestamp`.
  `verdict` is mechanical: `PASS` iff `exit_code == 0`.  Items whose pass
  criterion is not "exit 0" are wrapped in a checker script that exits
  nonzero on violation, so the verdict never rests on judgment words.
- `run.sh` — the recording runner that produces ledger rows.
- `logs/` — full captured stdout+stderr per run, named as in `log_path`.
  Logs too large to commit are committed as `<name>.log.sha256` +
  `<name>.log.tail` and flagged in the ledger row's threshold field.
- `phase0.md` — preflight reconciliation of the directive's stated figures
  against measured reality, with drift called out.
- `dismissals.csv` — every finding dismissed as flaky/environmental/false
  positive, with its ≥3 logged reproduction attempts and external-cause
  evidence.  Empty file means no dismissals were made.
- `memos/` — per-subsystem adversarial-review memos (item 15) and other
  narrative evidence artefacts.

## Item numbering

Items `0.x` are Phase 0 preflight.  Items `1`–`21` follow the operator
checklist: 1 signature verification, 2 reproducible build, 3 hostile
install matrix, 4 tamper drill, 5 OSS-Fuzz onboarding, 6 Valgrind/LSan,
7 refleak/RSS soak, 8 post-free scrub, 9 history secret scan, 10 core-dump
hygiene, 11 fuzz soak, 12 differential fuzzing, 13 API-misuse fuzzing,
14 mutation testing, 15 adversarial review, 16 CodeQL, 17 dudect/CT +
perf, 18 TSan/Helgrind, 19 offline drills, 20 demo surface, 21 Scorecard.
Suffix `nc` marks a negative-control run (the harness shown failing on a
seeded defect before its clean run counts).
