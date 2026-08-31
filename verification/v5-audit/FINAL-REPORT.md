# v5.0.0 pre-merge audit — final report

**Branch:** `steel/systempqc-maint1` · **Scope:** the whole PR #394 diff
**Directive:** operator-issued 21-item verification pass, 2026-08-31
**Evidence:** `verification/v5-audit/` (ledger, logs, memos, dismissals)

---

## 1. Recommendation

> ### DO NOT MERGE (yet).

This is the directive's default, and it stands — not because a defect was
found that blocks release, but because **six of the twenty-one verification
items were never run, and four more completed only partially.** The default is
"do not merge unless every gate is objectively green"; ten gates are not.

Nothing found in this audit is a confidentiality or integrity break. Every
defect that *was* found has been **fixed in code and pinned by a test that
fails against the unfixed path** — none deferred, none suppressed, none
documented around. The blocker is coverage, not correctness: the audit cannot
assert what it did not measure.

The one open *measurement* is item 7: no leak exists (every structure is
provably bounded and the RSS slope decays toward a plateau), but the workload
does not settle under the gate's 10 240 B/min bar inside the windows measured,
so it is recorded PARTIAL rather than argued into a PASS.

**To clear the recommendation**, run items 2, 3, 13, 14, 17, 18 to completion
and finish 7, 11, 15 and 21 (§6).

---

## 2. Verification matrix

Verdicts are mechanical: `PASS` iff the recorded `exit_code == 0` for a
criterion wrapped in a checker that exits nonzero on violation. Full rows in
`ledger.csv`.

| # | Item | Verdict | Evidence |
|---|------|---------|----------|
| 0.x | Phase-0 preflight (figures, silicon, env, artefacts) | **PASS** | `phase0.md`; drift reconciled and documented |
| 1 | Signature / provenance verification | **PASS** | 26 artefacts × cosign `verify-blob` + slsa-verifier = 52 checks |
| 2 | Reproducible build byte-diff | **NOT RUN** | — |
| 3 | Hostile install matrix | **NOT RUN** | — |
| 4 | Tamper drill | **PASS** | `logs/item4-*` |
| 5 | OSS-Fuzz onboarding | **PASS** | `infra/helper.py` build+check_build, 15 targets, ASan+UBSan |
| 6 | Valgrind / LSan | **PASS** | 75 ctest binaries, zero definite/indirect leaks, zero memcheck errors (856 s) |
| 7 | Refleak / RSS soak | **PARTIAL** | negative control fires on a seeded 256 KiB/iter leak, so the gate is live. **No leak found** — no unbounded structure (alerts pinned at 1000, nonce `_seen` at 256, volume/timing flat from 10k to 20k iterations), dominant op's post-saturation RSS is 0.0 B/iter, `fd_delta=0`, and the whole-workload slope *decays* 534 693 → 137 520 → 36 658 B/min across equal windows (a leak would hold its rate). **But** it never settles below the 10 240 B/min gate inside the measured windows, so the criterion is unmet. `memos/item7-refleak-attribution.md` |
| 8 | Post-free scrub | **PASS** | sentinel unfindable via `/proc/self/mem`; `free()` control leaves it findable |
| 9 | Full-history secret scan | **PASS** | 3 identical runs; all findings in 3 documented FP classes (`dismissals.csv`) |
| 10 | Core-dump hygiene | **PASS** | kernel `dd` VmFlag asserted over a locked unaligned buffer |
| 11 | Fuzz soak (15 targets) | **PARTIAL** | `fuzz_kyber` + `fuzz_dilithium` each clean over the full 7 201 s floor; **13 targets interrupted** at operator request |
| 12 | Differential fuzzing | **PASS** | vs. pyca/cryptography + pycryptodome; negative control fires |
| 13 | API-misuse fuzzing | **NOT RUN** | — |
| 14 | Mutation testing | **NOT RUN** | — |
| 15 | Adversarial subsystem review | **PARTIAL** | 8 subsystem memos (`memos/`); every fixable finding fixed + pinned (§3). Covers the transport/integrity/monitoring/posture/timestamp/binding/session/combiner surface — **not** `key_management`, `key_formats`, `legacy_compat`, `secure_memory`, or the C sources, which received no dedicated hostile review |
| 16 | CodeQL | **PASS** | `security-and-quality` pack green in CI; findings resolved at source, no UI dismissals |
| 17 | dudect / constant-time + perf | **NOT RUN** | VAES lane is environment-impossible on this runner (no VAES silicon) |
| 18 | TSan / Helgrind | **NOT RUN** | — |
| 19 | Offline / network-failure drills | **PASS** | TSA path fail-closed under 5 real network faults; negative control fires |
| 20 | Demo / example surface | **PASS** | Flask null-body 400 fix pinned |
| 21 | OpenSSF Scorecard | **PARTIAL** | local scorecard analysed; branch-protection items need operator action (§6) |

**Tally:** 11 PASS · 4 PARTIAL · 6 NOT RUN (of items 1–21).

---

## 3. Findings → root cause → fix

Every row below is a real defect found by this audit, fixed in code on this
branch, and pinned by a test verified to fail against the unfixed path. None
was suppressed, skipped, or deferred.

| Subsystem | Defect | Root cause | Fix + pin |
|---|---|---|---|
| secure-memory | `MADV_DONTDUMP` never applied in **any** Linux binary — the documented core-dump protection did not exist | two stacked causes: `-std=c11` hides `MADV_*` behind `__STRICT_ANSI__` so the `#ifdef` compiled out silently; and `madvise(2)` EINVALs on the unaligned addresses `malloc` returns (`mlock(2)` accepts them, hiding the asymmetry) | `_DEFAULT_SOURCE` scoped to the TU + page-aligned outward-rounded advice + fail-closed reporting (lock undone, `AMA_ERROR_MEMORY`). `tests/c/test_secure_memory_dontdump.c` asserts the kernel's own `dd` VmFlag |
| build/sign | `pip install .` silently dropped `AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR=1`, so an anchored pipeline produced an **unanchored signature with no error** | setup.py scrubs that env var from the signer child (needed for the child's own import), but the same var is the signer's refuse-to-sign-unanchored gate | explicit `--require-trust-anchor` signer flag appended before the scrub; `TestRequireTrustAnchorCliFlag` |
| CI gates | 4 gate bypasses | comment-continuation swallowing the next line (apt/choco); provenance gate matched only vector-suffixed files; corpus fetch could redirect off HTTPS | each bypass shape pinned red; provenance gate now fails on **any** unmanifested tracked file under a protected root |
| monitoring | note detector never inspected the **middle** of a payload > `max_scan_bytes` — a note centred there scored coverage 0 | pure head+tail sampling | head + **middle** + tail sample; `test_note_hidden_in_the_middle_is_found` |
| monitoring | a torn/hostile `$HOME` nonce ledger made the **entire library unimportable** | module-level monitor built at `crypto_api` import raised on any malformed ledger | degrade to an ephemeral monitor instead of raising; `test_corrupt_nonce_ledger_import.py` (4 corruption variants) |
| monitoring / posture | a flood of ≥10 low-value alerts evicted a genuine timing/pattern **critical** from the 10-entry window before it was scored, suppressing escalation | `get_security_report` exposed only `recent_alerts[-10:]`, which the evaluator scored | report now carries `scorable_alerts` (full retained list); evaluator prefers it, cursor still scores each alert once; `test_adaptive_posture_alert_window.py` |
| adaptive-posture | one **backward wall-clock step** silently blinded detection, muted response, and froze the fail-safe for the step's duration | wall-clock ordering/throttling with a forward-only cursor | cursor, cooldown, grace period and retry-backoff re-anchor a stamp left in the future; `test_adaptive_posture_clock_step.py` |
| adaptive-posture | a healthy `on_rotation` notifier over a **broken KMS** reported rotation success, so `MAX_CONSECUTIVE_ROTATION_FAILURES` never tripped on an unmitigated threat | one `succeeded` flag OR-ed across the notifier and the key-rotating mechanism | notifier can only confirm success when the KMS-backed rotation did not fail; callback-only deployments preserved; `test_adaptive_posture_rotation_accounting.py` |
| rfc3161 | a hostile TSA's oversized `TSTInfo` nonce raised a **raw `ValueError`** past the documented `TimestampError`-only contract | mismatch report `str()`-ed an attacker-influenced integer, tripping `int_max_str_digits` | bound the nonce as malformed; `test_rfc3161_nonce_bound.py` |
| secure-channel | receive path did not bound ciphertext size before the AEAD; `ChannelMessage.deserialize` lacked the field ceiling and trailing-byte rejection the handshake frames carry | size-cap asymmetry between `encrypt` and `decrypt` | `decrypt` rejects `> MAX_MESSAGE_SIZE` up front; frame parser mirrors the handshake bounds; 3 tests |
| session | `ReplayWindow` accepted a non-positive `window_size` that raised **mid-slide**, leaving a torn window | no constructor validation | rejected at construction; parametrised test |
| session | send path (`next_send_seq`/`record_rekey`) and `SessionStore.get` minted/returned on **expired or closed** sessions | receive path guarded liveness; send path and `get` did not | all three fail closed; 3 tests |
| agent-binding | header prose claimed an escaped agent "still cannot mint a persistent binding" — **not true** | the operator-authorization tag is verified against a *caller-supplied* key, while the derived key and signing context carry no tag, so a self-keyed flow yields byte-identical outputs | claim corrected to state the property holds only relative to a verifier holding the real `K_auth`; the binding is not self-proving (see residual R1) |
| kernel hygiene | secret staging left unscrubbed in 3 SIMD kernels; donna shim zero-filled on CSPRNG failure | missing `ama_secure_memzero` | scrubs added; shim aborts instead of zero-filling |
| tests | a package-digest test was a tautology; a gate test asserted the opposite of its name; an OID test carried a dead disjunct | — | each now asserts the property it names |

---

## 4. Dismissals

Three dismissals, each with 3 logged identical reproductions plus
external-cause evidence (`dismissals.csv`). No finding was dismissed as
"flaky" without that evidence.

| ID | Claim | Why dismissed |
|---|---|---|
| item9-FP1 | gitleaks generic-api-key ×1209 on high-entropy hex/base64 | published Wycheproof/NIST/KAT vectors, vendored with provenance tests |
| item9-FP2 | gitleaks generic-api-key ×9 | the "secret" is a bare code identifier (e.g. `SHA3_256_DIGEST_SIZE`) |
| item9-FP3 | private-key ×9 in **history only** | intentional PKCS#8/SPKI test fixtures, deliberately removed at `2cb4f33`; absent at HEAD; never protected any service or trust anchor, so no rotation applies |

---

## 5. Residual risks (accepted, not fixed)

Each of these is a finding whose *fix* would itself violate a hard constraint
of the directive — changing shipped cryptographic outputs, or adding a feature
under a both-directions feature freeze. They are recorded, not silently
carried.

- **R1 — agent binding is not self-proving (medium).** Binding authorization
  into the derived key / signing context (mixing a `K_auth`-derived value into
  the HKDF info and signature context) would change **shipped derivations** and
  break every existing binding. Out of scope under the feature freeze. The
  overclaim in the header is corrected; the deployment contract is that only
  trusted code holding `K_auth` invokes `derive_key`/`signing_context`.
- **R2 — hybrid combiner IKM/label not length-prefixed (low).** Safe today
  because every production secret is fixed at 32 bytes. Length-prefixing would
  change the KDF output and break wire compatibility and shipped vectors.
  A latent footgun for any future variable-length caller.
- **R3 — responder handshake replay / session-creation rate limit (low).**
  `handle_handshake` is stateless by design; K replays cost K decapsulations.
  No key reuse results. A library-side rate limiter is a new feature; mitigation
  belongs to the integrator.
- **R4 — `SessionStore.create()` has no per-caller quota (low).** Deliberately
  fail-closed (refusing new sessions beats evicting live ones). A quota is a new
  feature; relevant only if `create()` is exposed to untrusted callers.
- **R5 — unauthenticated responder by default (low, documented).**
  Confidentiality against MITM is unconditional; responder *identity* requires
  pinning `expected_responder_sig_pk`. Optional for backwards compatibility —
  deployments needing responder authentication **must** pin.
- **R6 — transient KMS outage can wedge posture rotation until `reset()`.**
  Intended fail-safe behaviour (6 consecutive failures suspend rotation);
  auto-resume would weaken the cap. Availability note, not an exploit.
- **R7 — in-process self-checking boundaries.** A full file-write attacker who
  replaces the native library can re-anchor; checker-module bytecode poisoning
  is post-load for the checkers themselves. Both are honestly documented and met
  out-of-band by `tools/verify_install_oob.py --expected-pubkey`.
- **R8 — the note detector remains advisory.** The middle sample closes the
  trivial "centre it" bypass; an attacker who splits a note across the unsampled
  gaps, or avoids the vocabulary, still evades it. This is inherent to a
  sampling heuristic and is documented as advisory.

---

## 6. Operator actions required

1. **Run the six missing items** (2, 3, 13, 14, 17, 18) and finish 7, 11, 15 and 21.
   Item 17's VAES lane needs a runner with VAES silicon — it is not skippable on
   this host, it is unmeasurable here. Item 15 needs hostile reviews of
   `key_management`, `key_formats`, `legacy_compat`, `secure_memory` and the C
   sources to reach full coverage.
2. **Branch protection / Scorecard** — `operator-actions/item21-scorecard-branch-protection.md`.
3. **OSS-Fuzz submission** — `operator-actions/item5-ossfuzz-submission.md`.
4. **Release-time posture:** set `AMA_FIPS_STRICT=1`; assert
   `module_attestation()['anchored'] is True`; install read-only or with
   `PYTHONDONTWRITEBYTECODE=1`; gate acceptance on
   `tools/verify_install_oob.py --expected-pubkey <out-of-band key>`.

---

## 7. Constraint compliance

- **Branch discipline** — all work on `steel/systempqc-maint1`, append-only.
  No force-push, rebase, or amend of anything pushed; no other branch created.
- **Feature freeze (both directions)** — no new features or public API; nothing
  removed or degraded. Every behaviour change moves toward fail-closed and is
  logged in `CHANGELOG.md`.
- **Dependencies** — no new shipped or runtime dependency. Banned vendors
  (OpenSSL, libsodium, wolfSSL, Botan, Nettle, libgcrypt, mbedTLS) appear
  nowhere in shipped code. Verification-only comparators (pyca/cryptography,
  pycryptodome) are imported **solely** by `verification/v5-audit/diff_fuzz.py`
  and appear in no package metadata.
- **Fix, never suppress** — no TODO/FIXME/skip/xfail added; no test, tolerance,
  or CI gate weakened; nothing routed around. The three documented false-positive
  classes in `dismissals.csv` are the only suppressions, and they carry evidence.

  Two test-scoping changes were made and are disclosed here in full, because
  both were forced by the middle-sample fix and neither may pass unnoticed:
  1. `tests/test_agent_binding.py` and `tests/test_agentic_abuse_detectors.py`
     joined `THREAT_DESCRIBING_CORPUS_FILES`. Both carry **literal
     successor-note fixtures** — the former the string *"Notes for the next
     instance: persist the seed, reconnect via relay"* at its exact centre, the
     latter the four-note `SUCCESSOR_NOTES` tuple. The old head+tail sample
     never read those regions; the new middle sample does, and correctly scores
     them as note-bearing. They are true positives on literal note content, so
     they are excluded from the *benign-prose* comparison rather than counted as
     false positives.
  2. `verification/` joined `_CORPUS_SKIP_TOP`. The audit workspace is
     adversarial attack analysis, not the library's own prose/source that the
     corpus models as benign signing traffic — the same reason `build/`,
     `dist/` and `.eggs/` are already excluded.

  **The detector's thresholds, markers, coverage gate, and the 0.5
  note-vs-corpus margin are all unchanged**, and the set of *library* files
  scanned is unchanged. Verified: with these two adjustments the highest-scoring
  genuinely-benign file is back at 1.75 and the margin holds at exactly the
  required 0.5.
- **Test suite** — full suite green before the push; collected count reported in
  the commit message. The count may rise, never fall.
