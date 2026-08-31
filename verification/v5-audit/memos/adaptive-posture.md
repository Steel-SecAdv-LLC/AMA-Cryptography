＃ Adversarial Security Review — adaptive-posture

**File:** `ama_cryptography/adaptive_posture.py` (v5.0.0)
**Branch:** `steel/systempqc-maint1`
**Scope:** `PostureEvaluator` (threat scoring/classification) and `CryptoPostureController` (rotation triggers, algorithm-strength ranking, the unrankable-algorithm raise, rotation cooldown/backoff/cap, confirmation mode).
**Question:** can crafted event sequences force a downgrade, suppress an escalation, wedge rotation, or drive the controller to a weaker posture than the threat warrants?

## 1. Threat model

**Assets.** Accuracy of the threat level that gates rotation and algorithm upgrades; the escalation path (a real threat must reach and hold HIGH/CRITICAL) and the de-escalation path (must not relax below the score); availability of the response machinery (rotation must not wedge); INVARIANT-35 (no escalation may swap in a weaker or cross-purpose algorithm).

**Trust boundary.** The only external input is `monitor_report = AmaCryptographyMonitor.get_security_report()` (`monitoring.py:4041`). Alert dicts are `{type, anomaly, timestamp}`; **every timestamp is the monitor's own `time.time()`** (`monitoring.py:3818,3853,3939,3988`), and stored deviation/z-score magnitudes are `abs()` values emitted only above a positive threshold. The attacker does not author report fields; the monitor does. What the attacker shapes is the observable behaviour that makes the monitor emit alerts (rate, severity, clustering, going quiet) and — if on-host or able to induce an NTP/VM/container clock event — the wall clock the monitor stamps and the controller throttles against. `current_algorithm`, the pending queue, confirm/reject and `reset()` are a same-process API, not a remote surface. The module reads no env vars or files.

**Adversary.** Source access; can induce/suppress timing and pattern anomalies and choose their timing; can move the wall clock (on-host); cannot forge negative/sub-threshold deviations; cannot make a caller-supplied KMS fail on demand.

## 2. Attacks attempted

### VULNERABLE — Backward wall-clock step blinds *and* mutes the engine (MEDIUM)
The subsystem orders alerts and throttles every action on `time.time()` and never `time.monotonic()` (`grep`: 917, 1021, 1193, 1292, 1298, 1334), and the alert cursor advances forward-only (`_advance_alert_cursor:370`, `if newest > self._last_processed_alert_ts`). A single backward wall-clock jump (NTP step on a large offset, manual `date`, VM snapshot restore, container clock reset) has three simultaneous effects for a window equal to the step size:
- **Detection blinded:** new monitor alerts carry `ts < cursor`, so `_alerts_not_yet_scored` (337-346) appends nothing (neither the `>` nor the `==` branch matches); timing/pattern/Lyapunov all score 0; `effective_score` decays; the posture **de-escalates to NOMINAL during an active attack**.
- **Response muted:** `evaluate_and_respond:918` computes `(now − _last_rotation_time)` as **negative**, so `cooldown_active` is `True` and the destructive-action block (926) never runs.
- **Fail-safe frozen:** `_process_expired_pending_actions:1026` sees `(now − pa.timestamp)` negative, so queued actions never auto-execute.

Silent (no log/metric); the only recovery is `reset()`. Tests drive time solely through a monotonic `_FakeClock` (`test_adaptive_posture.py:715-733`), so this is unpinned. **Fix:** use a monotonic clock for the cursor and all throttles, or detect a timestamp/`now` regression and re-baseline.

### VULNERABLE — `on_rotation` success masks a failing KMS, defeating the failure cap (LOW)
In `_trigger_rotation`, `succeeded` is one OR flag across mechanisms. If `register_key`/`initiate_rotation` raise (KMS down, 1259-1270) but a configured `on_rotation()` returns normally (1272-1278), `succeeded=True`, so line 1291 arms `_last_rotation_time`, clears `_rotation_failure_streak`, and returns `True` — **while no key was rotated.** The streak never accumulates, `MAX_CONSECUTIVE_ROTATION_FAILURES` is never reached, and `get_posture_summary()` reports `rotation_suspended=False` with a climbing `rotation_count`. The docstring frames `on_rotation` as a notifier ("Callback invoked when key rotation is triggered"), so "notifier healthy, KMS broken" is a realistic config in which the engine reports success on an unmitigated threat. **Fix:** success must require the mechanism that actually performs the rotation, not any callback.

### inconclusive — Transient outage permanently wedges rotation (LOW)
Six attempted-and-failed rotations trip the cap; the guard (`_trigger_rotation:1195-1204`) then returns *before* touching the mechanism, and the streak is only cleared downstream (1293), so a recovered KMS cannot self-resume — `reset()` is the sole exit (pinned, `test_adaptive_posture.py:1011-1033`). At sustained CRITICAL the served backoff (~290 s) means a ~5 min backend blip can disable posture rotation until a human intervenes. Intended and documented, and the failures are not attacker-controlled, so not a direct exploit — but a genuine availability wedge for the residual-risk list.

### defended — Tie-counting under-scores a burst when tied alerts slide out (LOW)
When alerts share a clock tick, `_scored_at_cursor_ts` counts them off in arrival order (342-345). If a scored tied alert drops off the front of the 10-item window (`monitoring.py:4069`) and a new same-timestamp alert slides in, the newcomer's `tie_index` stays `< _scored_at_cursor_ts` and it is silently unscored — the code owns this as "fails towards skipping" (331-333). Bounded to one clock tick (≈15.6 ms Windows; Linux `time.time()` sub-µs makes ties rare), so a multi-second attack still advances the clock and escalates. Accepted conservatism.

### defended — Sub-threshold / negative-deviation dilution
`robust_score` is `abs(...)` (`monitoring.py:760`) and pattern `z_score` is `abs(...)` (`monitoring.py:2341,2364`); alerts fire only above a positive threshold. No alert reaching the scorers can carry a negative magnitude to subtract from the composite, and the attacker cannot author report fields. Path closed.

### defended — Low-and-slow sawtooth escalation suppression
`_classify` applies the hysteresis band on the **escalation** side (622): once a level is counting, its floor is `threshold − band`, so a peak-hold sawtooth stays above the floor across `escalation_count` cycles and the counter fills; escalation then selects the highest satisfied counter regardless of the instantaneous candidate (631-641). Pinned (`test_adaptive_posture_decay_and_escalation.py:119-157`).

### defended — Stale-alert / Lyapunov-floor permanent escalation (the 5.0 target)
Peak-hold `max(score, acc*decay)` is bounded in [0,1] and decays (290); each alert is scored once via the shared cursor (243); the Lyapunov deque drains one sample per quiet cycle and clears its baseline when empty (508-512), removing the permanent floor. Pinned by three regression tests.

### defended — Unrankable / cross-family downgrade (INVARIANT-35)
Construction raises on an off-ladder name (809-817); `UNRANKED_STRENGTH = −1` makes the downgrade alarm always fire (900) and makes `_trigger_algorithm_switch` refuse rather than take the weakest rung (1371-1379); escalation walks only the constructed family's ladder (819, 847-849), so no KEM↔signature swap is possible. Pinned by `TestAlgorithmFamilies` / `TestAnUnrankableAlgorithmCannotProduceADowngrade`.

### inconclusive — `inf` deviation disables the Lyapunov term (LOW)
`robust_score` can return `math.inf` on a scale-0 window (`monitoring.py:758-759`). If `inf` seeds `_lyapunov_baseline` (533), subsequent `V_dot = finite − inf ≤ 0` keeps the baseline `inf` and `instability` stuck at 0 (543-552). No NaN reaches the threshold comparison. Only zeroes one 15% signal; the other 85% still escalate. Robustness note.

### defended — Forced downgrade via de-escalation
De-escalation fires only when `score < current_threshold − hysteresis_band` (645) and drops to the score-derived candidate. The attacker can lower the score only by genuinely reducing observed anomalies; there is no path below what the score supports.

## 3. Verdict
No CRITICAL. The bespoke posture logic defends every in-scope manipulation that maps to a documented 5.0 fix, each pinned by tests. Two real residual weaknesses, both from design choices rather than the fixes: **(1)** wall-clock (`time.time()`) ordering and throttling with a forward-only cursor lets one backward clock step silently blind detection, mute response, and freeze the fail-safe (MEDIUM); **(2)** OR-across-mechanisms success accounting lets a notifier callback mask a failing KMS and prevent the failure cap from ever tripping (LOW). Plus an availability note: a transient outage can wedge rotation until a manual `reset()`. Recommend moving the cursor and all throttles to a monotonic source (or regression-detecting), and requiring rotation success from the mechanism that actually rotates.