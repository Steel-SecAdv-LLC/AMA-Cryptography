# Adversarial Security Review — `session` subsystem

**Target:** `ama_cryptography/session.py` (branch `steel/systempqc-maint1`)
**Scope:** `ReplayWindow` (replay window, `REPLAY_WINDOW_SIZE`), `SessionState` TTL/expiry, session-id generation, `SessionStore` `MAX_SESSIONS`.
**Method:** READ-ONLY, hostile, line-level. No file/process was modified.

---

## 1. Threat model

**Assets**
1. Integrity of the anti-replay decision (a replayed seq must never be accepted).
2. Unpredictability + uniqueness of the 32-byte session-id bearer token.
3. Availability of the store (bounded memory; legit peers can open sessions).
4. Correct TTL expiry (a stale session cannot be revived).

**Trust boundaries**
- `session.py` is a **standalone module**. It is *not* imported by any non-test package module — `secure_channel.py` carries its **own** structurally-identical replay window and never uses `SessionStore`/`ReplayWindow`/`SessionState`. Only `tests/test_exception_hierarchy.py` imports a symbol (`SessionError`). The boundary is therefore the **API contract with an external caller**.
- The module does **no** authentication and **no** AEAD. It assumes the caller passes `seq` to `accept_recv_seq()`/`check_and_accept()` **only after** the frame is authenticated (which is exactly how `secure_channel.py`'s own copy orders it: the replay set is mutated only *after* `native_aes256_gcm_decrypt` succeeds).
- Session-ids are minted internally; TTL is a monotonic-clock measurement.

**Adversary capabilities.** Read access to source; controls every value the module does not itself generate — `seq`, `ttl_seconds`, `metadata`, lookup ids, `window_size` on a directly-built `ReplayWindow`, and the volume/timing of `create()` calls; may drive the module into the FIPS ERROR state. Cannot choose the minted id, cannot move the monotonic clock backward, and (per contract) presents `seq` only post-authentication.

---

## 2. Attacks attempted

### DEFENDED (with evidence)

| # | Attack | Location | Evidence |
|---|--------|----------|----------|
| A1 | Replay **inside** window | `session.py:106-107` | `if seq in self._seen: raise ReplayDetectedError("already received")`; every accepted seq is added at :109 before the next check. |
| A2 | Replay **outside/below** window | `:104-105` + slide `:114-118` | `if seq < self.base: raise ...("too old")`. Slide always discards the **min** and sets `base = evicted_min + 1`, so every evicted seq ends `< base`. Invariant "all `_seen` ≥ `base`" holds inductively; `base` is monotonic non-decreasing ⇒ **no false-negative replay, window never reopens.** |
| A3 | Session-id prediction | `:293` | `secure_token_bytes(32)` = 256-bit CSPRNG + continuous RNG health test. Not caller-derived. Logs expose only a 64-bit hex prefix. |
| A4 | Session fixation | `:257-311` | No caller-supplied id; no insert-by-id path. |
| A5 | Collision silently replaces a live session | `:294-303` | Duplicate draw **fails closed** (raises) instead of overwriting. |
| A6 | Clock-rollback expiry bypass | `:156-158` | `time.monotonic()`; TTL from `created_at`, not `last_activity`. |
| A7 | FIPS error-state token mint | `:279` + `:293` | `check_crypto_permitted()` then `secure_token_bytes` (which re-checks). Pinned by `test_post_failclosed`. |
| A8 | `_seen` memory exhaustion | `:114-118` | Bounded to `window_size` (+1) regardless of gap; slide is O(evicted), not O(gap). Pinned by large-gap tests. |
| A9 | Unbounded store growth | `:284-285` | `MAX_SESSIONS` (1024) enforced after `_cleanup_expired()`. |
| A10 | TOCTOU on check-and-insert / limit | `:280-309` | All under `self._lock`; atomic. Pinned by `TestSessionStoreThreadSafety`. |
| A11 | Seq/counter integer wrap | `:178-184`, `:95-118` | Python bigints; no fixed-width wrap. |
| A12 | Lookup timing oracle | `:327` | Dict get on a 256-bit secret key; not feasibly exploitable. |

### FINDINGS (all low severity)

**F1 — Resource STARVATION DoS (availability, low).** `create()` enforces a memory cap but has **no per-caller quota, rate limit, or idle/LRU eviction**; a slot frees only on expiry or `close()` (`:284-285`, `:373-380`). An attacker able to reach `create()` (default TTL 3600 s) pins all 1024 slots and starves legitimate `create()` for up to an hour. Deliberately fail-closed (refusing new sessions is safer than evicting live ones); exploitability depends on whether the integrator exposes `create()` to untrusted callers. No confidentiality/integrity impact.

**F2 — Send path skips expiry/closed checks (low).** `accept_recv_seq()` guards `is_expired`/`_closed` (`:196-199`); `next_send_seq()`/`record_rekey()` (`:178-184`, `:205-208`) guard neither. An expired or `close()`d `SessionState` keeps minting send sequence numbers and updating `last_activity`. Bookkeeping only — this module holds **no key material** — but a caller that trusts `next_send_seq()` to reflect liveness would be misled. `get()` also checks `is_expired` but not `is_closed`.

**F3 — `reset()` footgun (low).** `ReplayWindow.reset()` (`:120-123`) sets `base=0` and clears `_seen`, which *would* re-admit old seqs. Verified `record_rekey()` does **not** call it and nothing internal calls it — so a rekey does **not** reopen the window (correct). Flagged because an integrator who wires `rekey → reset()` while keeping the same recv key reintroduces a replay hole.

**F4 — No `window_size` validation (low).** Negative `window_size` raises `ValueError` via `min(empty)` in the slide; `0` degenerates. Not reachable through `SessionStore`/`SessionState` (fixed default 256 at `:147`); only via a directly-built `ReplayWindow`. Recommend `window_size >= 1` validation.

**F5 — Count-bounded, not range-bounded window (low/info).** The window bounds the *count* of tracked seqs (≤256), not the numeric range; `base` creeps +1/msg. Proven to introduce **no replay hole**; only an availability corner (a huge authenticated seq jump can later cause genuinely in-flight low seqs to be rejected). Requires authenticated frames.

**F6 — Unbounded `metadata` (info).** `create(metadata=...)` stored verbatim, no size cap; total bounded by `MAX_SESSIONS`. A hardening note only when metadata is attacker-sourced.

---

## 3. Verdict

The **core anti-replay engine, id generation, fixation resistance, monotonic-clock expiry, FIPS gating, and lock discipline are all correct** — no critical or high finding was substantiated, and the sliding-window eviction was formally traced to confirm no replayed sequence number (inside or outside the window) can be accepted and that the window cannot reopen in normal operation. Residual issues are low-severity availability/robustness and caller-contract gaps. Recommended hardening: validate `window_size ≥ 1`; gate the send path on `is_active`; document that `seq` must be authenticated before `accept_recv_seq`, and that `reset()` must never run without a fresh recv key; add a per-caller `create()` quota / idle-eviction if `create()` is exposed to untrusted callers. None block merge on confidentiality/integrity grounds.