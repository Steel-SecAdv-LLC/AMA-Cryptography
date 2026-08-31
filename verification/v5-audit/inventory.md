# PR #394 changed-file inventory (audit working method: "Inventory first")

Checklist source: `changed-files.txt` (1,063 paths) from `git diff --name-only
2dcef5c..32c3e0d`, reconciled in Phase 0.

| Class | Count | Review method | Record |
|---|---|---|---|
| Text files | 385 | 11 parallel reviewer agents, every file read in full at HEAD plus its PR diff; 1 file (tests/c/test_dispatch_only_env.c) missed by its chunk agent and reviewed directly by the orchestrator | `inventory-text.json` — one entry per file: purpose note + findings |
| Binary files | 678 | mechanical characterization: existence at HEAD, size, file(1) type, sha256 | `inventory-binary.tsv` |
| **Total checked** | **1,063 / 1,063** | | |

Binary population: 675 fuzz seed-corpus files (4 duplicate-content pairs — corpus
inefficiency, not a defect; exotic file(1) labels like "OpenPGP Secret Key" are
misclassified random fuzz data, cross-checked by the item-9 secret scanners),
3 PNG assets (real PNGs, dimensions recorded).

Text-file findings: 2 major, 22 minor, 33 info (severity definitions in the
agent brief; full text in `inventory-text.json`).

- Both majors fixed in-audit: (1) `setup.py` env scrub silently dropping the
  signer's `AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR` enforcement — fixed via an
  explicit `--require-trust-anchor` flag, pinned by
  `tests/test_build_sign.py::TestRequireTrustAnchorCliFlag` (verified to fail
  on the unfixed code); (2) `wiki/Secure-Memory.md` documenting a pure-Python
  constant-time fallback the code deliberately refuses to have — corrected.
- Minors: code/test/gate defects fixed in-audit (see audit commits); pure
  documentation-accuracy defects fixed by the doc-fix wave; each disposition
  is in the final report.
- Infos include: deliberate instruction-like text embedded as detector test
  fixtures (tests/test_agentic_abuse_detectors.py, test_agentic_load_adversarial.py
  — reported per audit policy, never followed); and the PR's own
  timing-gate threshold moves (dudect 4.5→5.0, sub-floor carve-outs,
  Kyber-decaps lane strict→info-only, POST floor 50→100 ns) — assessed under
  item 17 in the final report.
