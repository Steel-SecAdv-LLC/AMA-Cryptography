# Item 7 — refleak / RSS soak: attribution analysis

**Verdict: PARTIAL.** No leak was demonstrated, and no unbounded structure
exists — but the workload does not settle below the mechanical gate
(10 240 B/min) inside the windows measured here, so the criterion is not met and
item 7 must not be recorded as PASS.

## 1. What the gate says

`refleak_soak.py` fails when the least-squares RSS slope over post-warmup
samples is >= 10 240 B/min. Two clean runs:

| run | window | warmup | iterations | fd_delta | slope | gate |
|---|---|---|---|---|---|---|
| `item7-soak-clean.log` | 12 min | 12 000/op | 20 873 | 0 | **61 460 B/min** | FAIL |
| `item7-soak-v2.log` | 65 min | default | 63 125 | 0 | 22 474 B/min | FAIL (confounded — see §4) |

The harness itself is sound: the negative control (`item7-negative-control.log`,
ledger row `7nc`) seeds a 256 KiB/iter leak and the gate fires. A silent gate
was ruled out before any of this was interpreted.

## 2. Per-op attribution

Each of the 20 ops run in isolation, warmed then measured
(`scratchpad/perop_probe.py`; 400 warm / 1200 measured):

| op | RSS B/iter | traced B/iter |
|---|---|---|
| `monitoring.create_record_report` | 692.9 | 583.0 |
| `package.create_verify` | 194.6 | 214.1 |
| *the other 18 ops* | 0.0 | 0.8 – 1.3 (tracemalloc noise floor) |

Only two ops move at all. Both drive the same shared monitor.

## 3. Are those two a leak, or bounded fill?

The monitor's structures are bounded by design (alert retention, `maxlen`
deques, a capped fingerprint set), so a measurement taken below saturation
reports legitimate fill as if it were growth. Re-measured with 14 000 warmup
iterations — past every cap — in two consecutive windows:

| op | pre-saturation | post-sat w1 | post-sat w2 |
|---|---|---|---|
| `monitoring.create_record_report` | 567 B/iter RSS / 417 traced | **0.0 RSS** / 347 traced | **0.0 RSS** / 348 traced |
| `package.create_verify` | 258 / 231 | 20.5 / 17.8 | 22.5 / 35.5 |

**RSS per iteration falls to zero** for the dominant op once its structures are
saturated. The residual `traced` figure is churn — the alert ring buffer
replacing entries — not retention, which the direct structure census confirms:

```
after  2 000 iters : alerts=1000 (cap 1000)  nonce _seen=256  _counters=1  volume.*=1  timing.profiles=14
after 10 000 iters : alerts=1000             nonce _seen=256  _counters=1  volume.*=1  timing.profiles=14
after 20 000 iters : alerts=1000             nonce _seen=256  _counters=1  volume.*=1  timing.profiles=14
```

Every structure is flat between 10 000 and 20 000 iterations. There is no
unbounded container. `fd_delta = 0` across every run rules out descriptor leaks.

## 4. Why the whole-workload slope is still non-zero

A constant-rate leak holds its slope across equal consecutive windows. This
workload's slope *decays* (`item7-twowindow.log`, 20-op round robin, 180 s
warmup then two 240 s windows):

```
warmup  : slope = 534 693 B/min   (RSS 53 816 -> 55 672 KiB)
window 1: slope = 137 520 B/min   (RSS 55 672 -> 56 140 KiB)
window 2: slope =  36 658 B/min   (RSS 56 140 -> 56 312 KiB)
```

Roughly a 15x decay from warmup to window 2, and 3.75x between two *equal*
consecutive windows. That is the signature of allocator-arena high-water
growth under 20 heterogeneous allocation-size profiles plus bounded-structure
fill — not of a leak, which would hold ~137 000 B/min in window 2.

The 65-minute `item7-soak-v2` run (22 474 B/min) is consistent with the same
decay over a longer window, but it is **not** counted as evidence: during it
the `integrity.verify_module` op raised on every iteration because package
sources were being edited concurrently, so both the workload and the
exception-formatting allocations were unrepresentative. It is recorded and
discounted rather than quietly dropped.

## 5. Conclusion

- **No leak found.** No unbounded structure; per-op steady-state RSS is 0.0
  B/iter for the dominant op; the slope decays toward zero rather than holding.
- **The gate is nevertheless not met.** Window 2 sits at 36 658 B/min, above the
  10 240 B/min bar. On this evidence the plateau has not yet crossed below the
  threshold inside a measured window.
- **Therefore PARTIAL, not PASS.** Closing it requires a long-window run (the
  soak's own 65-minute default, uncontaminated this time) demonstrating the
  slope settling under 10 240 B/min — or, if it does not settle, a further
  bisection of `package.create_verify`, the one op still showing ~20 B/iter RSS
  after saturation.

Nothing here is dismissed as flaky. The finding stands as an open, bounded
measurement gap, and it is one of the reasons the audit's recommendation is
DO NOT MERGE.
