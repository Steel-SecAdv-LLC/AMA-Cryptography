#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — scalar AES-GCM instruction-count invariance (INVARIANT-6)
============================================================================

Asserts that the **scalar** AES-256-GCM path retires the same number of
instructions regardless of the key, and therefore regardless of the GHASH
subkey ``H = E_K(0^128)`` derived from it.

Why this exists
---------------
``src/c/ama_aes_gcm.c`` accumulates GHASH with a branch-free mask::

    mask = 0 - bit_of(Z)          # 0x00 or 0xFF
    for k in 0..15: out[k] ^= V[k] & mask

That is constant-time in the C abstract machine only.  An optimizer may
prove the mask is all-zero-or-all-ones, recognise the masked accumulate as the
identity in the all-zero case, and emit a branch over it — putting a branch back on a
bit of the running accumulator, which is a function of the secret ``H`` from
the second block onward.  clang 18 at ``-O2``/``-O3`` did exactly that; gcc
13 did not.  Both builds pass every functional test, because the *results*
are identical.  Only the emitted control flow differs, so only a check that
looks at execution rather than at output can see it.

The source-level defence is ``ama_ct_value_barrier_u64`` (see
``src/c/internal/ama_ct_barrier.h``); ``ghash_mul`` accumulates on 64-bit
words, so the word-width form is the one it uses.  This gate is what stops the
defence from being silently removed, or from being defeated by a compiler
nobody has tried yet.

Method
------
Retired-instruction counts under ``valgrind --tool=callgrind``, not wall
time.  Callgrind counts are deterministic to within a handful of
instructions, so this needs no statistics, no repetitions for significance,
and no quiet machine — it is a functional check that happens to be about
timing, and it gives the same verdict on a loaded CI runner as on idle
hardware.

Three measurements:

* **Floor** — the same key twice.  Whatever this differs by is process-level
  noise (loader, glibc), and it bounds the resolution of the comparison.
* **Signal** — distinct key classes against each other.
* **Verdict** — fail if any cross-key delta exceeds ``--threshold``.

Calibration, measured on the reference build (x86-64, 8 encryptions of 512 B
with 64 B AAD, scalar path forced):

===================================  ==================
build                                cross-key delta
===================================  ==================
clang -O3 without the value barrier  3,226 instructions
clang -O3 with the value barrier             12
same key, two runs (noise floor)       up to 25
===================================  ==================

Per-target limits are set from measurement, not from headroom: all FOURTEEN
targets measure a cross-class delta of exactly zero under both gcc 13 and
clang 18 at -O3, with a same-class floor of exactly zero, and every limit is
0.  `ecdsa` was the last holdout — it carried a limit of 64 for the DER
length term — and reached zero the way `nistp-ecdsa` did, by signing through
the fixed-width `ama_secp256k1_ecdsa_sign_raw` entry point so the encoder is
outside the measurement rather than inside it with an allowance.  The full
measurement table and the reasoning are at ``THRESHOLDS`` below.

Exit status
-----------
``0`` invariant holds, ``1`` a key-dependent instruction count was measured,
``2`` the check could not run (missing valgrind, compiler, or library, or a
noise floor so high the comparison would be meaningless).  As elsewhere in
``tools/``, an unrunnable check is never reported as a passing one.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, Sequence

#: Fallback limit for a target with no entry in :data:`THRESHOLDS`.  Zero,
#: because that is what a deterministic instrument measures on code with no
#: benign variable-time step; a new target that genuinely has one states its
#: own limit and the measurement behind it.
DEFAULT_THRESHOLD = 0

#: Key classes to compare.  Single characters so the driver's argument
#: handling costs the same for each — a multi-character argument would make
#: strtoul-style parsing itself key-dependent and pollute the measurement.
#:
#: Eight rather than four.  This is a *sampling* check: it detects a
#: secret-dependent path only if two of the keys it happens to try land on
#: different sides of the predicate.  With four keys the secp256k1 carry-fold
#: and low-s leaks showed a 288-instruction spread, against 576 over twenty —
#: i.e. four keys saw half the effect available, and a smaller leak could sit
#: entirely inside one class.  Each additional class costs ~0.4 s on the ecdsa
#: target and ~5 s on ghash, which buys detection power cheaply.
#:
#: Printable ASCII only: the value reaches the driver as `argv[1][0]`, and a
#: non-ASCII character would be UTF-8 encoded by the caller into two bytes,
#: so the driver would silently see the lead byte and two "different" classes
#: could collide.
KEY_CLASSES = ("A", "Z", "m", "q", "0", "~", "!", "5")

#: Per-target instruction-count threshold.
#:
#: ghash: the scalar AES-GCM path is deterministic end to end, so anything
#: above process noise is a defect.  Calibration in the module docstring.
#:
#: ecdsa: secp256k1 signing HAD one *legitimate* variable-time step — DER
#: encoding of r and s, whose leading-zero handling depends on the signature
#: values.  Those are public (the verifier receives them), which is why a
#: non-zero limit was defensible.  It is history now, not the current
#: rationale: this target signs through `ama_secp256k1_ecdsa_sign_raw`, a
#: fixed-width 64-octet entry point, so the encoder is not in the measurement
#: at all and the limit is 0 like every other target.  The paragraphs below
#: record how that limit came down, because the numbers in them are the
#: evidence for the value it came down to.
#:
#: This threshold was 3,000, calibrated against the Montgomery
#: extra-reduction leak (33,354 instructions) and an apparent benign spread
#: of 728.  Both halves of that calibration were wrong in the same direction.
#: The 728 was not benign — most of it was two *further* live leaks in the
#: same file, sc_add's carry fold and sc_is_high's short-circuited memcmp,
#: which this gate was passing over.  And ~9 instructions per byte of the
#: remainder came from the driver consuming `siglen` bytes rather than a
#: fixed count, which is measurement noise the gate itself created.
#:
#: Re-measured on the configuration CI actually runs — the AMA_TESTING_MODE
#: static archive, LTO off, 8 key classes, driver consuming a fixed byte
#: count:
#:
#: ==========================================  ==================
#: build                                       cross-key delta
#: ==========================================  ==================
#: pre-fix secp256k1 (git-reverted control)    2,952 instructions
#: fixed (shipped), at the time                   80
#: fixed (shipped), re-measured                   24  (gcc 13 -O3)
#:                                                16  (clang 18 -O3)
#: ==========================================  ==================
#:
#: The 80 predates the driver consuming a fixed byte count rather than
#: iterating to `siglen`; that change removed the ~9 instructions per byte of
#: noise the driver was creating itself, and what is left is the library's own
#: DER encoding. Both re-measurements are on the archive build the workflow
#: configures (Release, LTO off), which is the configuration the limit has to
#: be safe for.
#:
#: The old threshold of 3,000 therefore sat **48 instructions above the
#: defect it was measuring**.  It was never going to fire.  Its replacement,
#: a flat 200, then sat 2.5x above the benign floor — and 8 signatures of
#: amplification made that 25 instructions per signature of real divergence
#: this target would still have passed.  The limit is now 64; see the
#: measurement table below.
#:
#: (On a shared-library build the same comparison reads 576 against 24; the
#: absolute numbers move with linkage and codegen, the ratio does not.  Quote
#: the archive numbers, because that is what the workflow builds.)
#:
#: The general lesson is recorded because it will recur: a threshold set
#: between one known defect and one *assumed* noise floor is only as good as
#: the assumption. The noise floor has to be measured on a build believed
#: clean, and "believed clean" has to be earned by looking, not by the
#: absence of a red gate.
#:
#: consttime: ama_consttime_memcmp is a fixed-count XOR accumulator over
#: volatile pointers, so its retired count is invariant by construction —
#: measured byte-identical (37,157,290) across all eight classes, covering the
#: equal case and a first-difference at eight positions spread through a 4 KiB
#: buffer. There is no benign spread to accommodate, which is why its limit
#: is 0 rather than a shared allowance.
#:
#: This target exists because the dudect lane for the same function is a
#: *wall-clock* statistical test on a shared CI runner, and it flakes: it
#: failed at |t| = 5.21 against a 4.5 threshold in 2 of 3 rounds on a commit
#: that did not touch src/c/ama_consttime.c, on a function whose instruction
#: count does not move at all. This module's own docstring already makes the
#: argument — callgrind counts "give the same verdict on a loaded CI runner as
#: on idle hardware" — so the durable answer to a flaky timing lane over a
#: deterministic function is to also measure it deterministically. dudect stays
#: as the wall-clock cross-check; this is what a real regression trips.
#: THE LIMITS BELOW ARE MEASURED, NOT ROUNDED
#: ------------------------------------------
#: Every target used to share a flat 200, chosen for `ecdsa` and applied to
#: the rest as "pure headroom".  Headroom in a deterministic instrument is not
#: free: what it buys is the right to pass a real divergence.  A target's
#: sensitivity is its limit divided by its amplification — the number of
#: operations its driver runs — so a flat 200 meant:
#:
#: =============  =============  =====================================
#: target         operations     per-operation divergence that PASSED
#: =============  =============  =====================================
#: nistp-ecdsa          4              50 instructions per signature
#: ghash                8              25 per encryption
#: ecdsa                8              25 per signature
#: x25519               8              25 per scalar multiplication
#: kyber-decaps        60               3 per decapsulation
#: ed25519-sign       200               1 per signature
#: aead-verify        500               0 (1 per call amplifies to 500)
#: consttime         2000               0
#: ascon-hash        2000               0
#: ascon-encrypt     2000               0
#: agent-binding     2000               0
#: sha3-256          2000               0
#: =============  =============  =====================================
#:
#: `ed25519-sign` is the sharpest: 200 operations against a limit of 200, and
#: the verdict is `>` — so a one-instruction-per-signature key-dependent
#: divergence, which is what a conditional branch on a secret bit looks like
#: after the optimizer gets to it, passed this gate exactly.  The nistp leak
#: this file already records was 313 instructions per signature; the same gate
#: would not have seen it at 50.
#:
#: That is not an argument from arithmetic.  It was measured, by putting the
#: defect back: one branch on `private_key[0] & 1`, executed once per
#: signature, at the top of `ama_nistp_ecdsa_sign_raw` in src/c/ama_nistp.c,
#: on the archive build the workflow configures.  The cross-key delta is 12
#: retired instructions and 8 data references — and at a limit of 200 this
#: tool printed
#:
#:     NISTP-ECDSA CONSTANT-TIME CHECK PASSED — instruction count, data
#:     references and cache misses are all key-independent
#:
#: over code with a live branch on the private key, exit 0.  At the limits
#: below it fails, exit 1, naming both metrics.  The mutation was reverted;
#: what it establishes is that the old margin was not headroom, it was a
#: blind spot of a size real defects come in.
#:
#: So each limit is now what the measurement supports.  Measured on this tree
#: with the AMA_TESTING_MODE static archive, LTO off, 8 key classes, at -O3
#: under both compilers CI uses:
#:
#: ===============  =================  ===================  ===============
#: target           gcc 13  (I / D)    clang 18  (I / D)    same-class floor
#: ===============  =================  ===================  ===============
#: ghash                 0 / 0               0 / 0                0
#: consttime             0 / 0               0 / 0                0
#: aead-verify           0 / 0               0 / 0                0
#: ascon-hash            0 / 0               0 / 0                0
#: ascon-encrypt         0 / 0               0 / 0                0
#: agent-binding         0 / 0               0 / 0                0
#: kyber-decaps          0 / 0               0 / 0                0
#: sha3-256              0 / 0               0 / 0                0
#: ed25519-sign          0 / 0               0 / 0                0
#: x25519                0 / 0               0 / 0                0
#: x25519-batch          0 / 0               0 / 0                0
#: nistp-ecdsa           0 / 0               0 / 0                0
#: ecdsa                 0 / 0               0 / 0                0
#: ===============  =================  ===================  ===============
#:
#: All thirteen are exactly zero, on both compilers, with a same-class floor of
#: exactly zero — which is what "deterministic instrument" has to mean.  Their
#: limit is 0.  A single retired instruction of cross-class
#: difference in any of them falsifies the property the target states, and
#: there is nothing left for a threshold to be headroom FOR: the floor check
#: already reports INCONCLUSIVE (exit 2) rather than passing if the
#: environment cannot reproduce itself, so a host with real measurement noise
#: is diagnosed instead of silently absorbed.
#:
#: `nistp-ecdsa` reached zero by construction rather than by luck: its driver
#: now signs with `ama_nistp_ecdsa_sign_raw`, identical arithmetic to the DER
#: entry point with a fixed-width 64-octet result, so the DER encoder's
#: length variance — a public-value term, but a key-dependent one — is no
#: longer inside the measurement at all.
#:
#: `ecdsa` was the last holdout and is now closed the same way.  secp256k1
#: used to expose only the DER form, so the leading-zero handling of r and s
#: stayed in the count — 24 instructions over 8 signatures under gcc, 16 under
#: clang — and the target carried a limit of 64.  That was a tolerance of 8
#: instructions per signature, and a secret-dependent divergence smaller than
#: that was below what the target could resolve.
#:
#: `ama_secp256k1_ecdsa_sign_raw` emits a constant 64 octets from identical
#: arithmetic, so the encoder is no longer inside the measurement.  Measured
#: on this tree, all eight key classes are byte-identical under both
#: compilers:
#:
#:     gcc 13    11,645,734 I refs   2,082,049 D refs   1,706 D1   1,456 LLd
#:     clang 18  11,948,072 I refs   3,202,907 D refs   1,713 D1   1,464 LLd
#:
#: with a same-class floor of zero.  The limit is 0.  The two entry points are
#: not assumed equivalent: tests/c/test_secp256k1.c decodes the DER signature
#: back to (r, s) and compares it against r||s over 512 keys, and asserts the
#: comparison saw at least one short DER signature so it cannot pass over
#: full-length cases alone.
#:
#: `x25519-batch` is the thirteenth, and it exists because a lane can be
#: informational only where something else blocks.  `tests/c/test_dudect.c`
#: registers eight info-only wall-clock lanes, and each one that names a reason
#: names a deterministic counterpart: `Kyber-1024 decaps` cites `kyber-decaps`,
#: `secp256k1 ECDSA sign` cites `ecdsa`.  Two had none — `ML-DSA-65 sign` and
#: `SLH-DSA-SHA2-256f sign`, both of which drive a rejection loop whose
#: iteration count is a function of the secret, so a zero-delta instruction
#: count is not merely absent but impossible (see CONSTANT_TIME_VERIFICATION.md,
#: "Rejection sampling and what these gates cannot cover") — and a third,
#: `X25519 scalarmult batch x4`, had none for no reason at all: the property is
#: the same one `x25519` states, over a DIFFERENT entry point.
#:
#: `ama_x25519_scalarmult_batch` carries its own four-lane chunker, the AVX2
#: 4-way kernel behind `AMA_DISPATCH_USE_X25519_AVX2`, a scalar tail, and an
#: aggregated low-order rejection that must zero every output when any lane
#: rejects.  The `x25519` target reaches none of that; it measures the
#: single-shot entry point.  Measured on this tree at count = 4 (the smallest
#: batch that takes the full-chunk path), all eight key classes byte-identical
#: on all four metrics, on BOTH dispatch wirings:
#:
#:     gcc 13    scalar 4x sequential   34,562,888 I   6,818,496 D  2,034/1,622
#:     gcc 13    SIMD (AVX2 4-way)      10,118,790 I   6,212,344 D  2,205/1,710
#:     clang 18  scalar 4x sequential   17,213,720 I   3,222,067 D  2,197/1,738
#:     clang 18  SIMD (AVX2 4-way)      10,036,821 I   3,603,683 D  2,320/1,772
#:
#: The AVX2 4-way kernel had never been measured by a deterministic instrument
#: before; its only coverage was the info-only wall-clock lane.  The gate is
#: verified to FAIL rather than assumed to work: a branch on
#: `scalars[0][0] & 1` planted at the top of the batch entry point makes it
#: report a 1,744-instruction / 1,024-data-reference cross-class delta and exit
#: 1.  The mutation was reverted.
THRESHOLDS = {
    # Every one of the thirteen is invariant by construction and measures
    # exactly zero on both compilers; see the table above.  `ecdsa` was the
    # last holdout at 64, for the DER length term, and reached zero the way
    # `nistp-ecdsa` did: by signing through a fixed-width entry point.
    "ecdsa": 0,
    "ghash": 0,
    "consttime": 0,
    "aead-verify": 0,
    "ascon-hash": 0,
    "ascon-encrypt": 0,
    "agent-binding": 0,
    "kyber-decaps": 0,
    "sha3-256": 0,
    "ed25519-sign": 0,
    "nistp-ecdsa": 0,
    "x25519": 0,
    # `ama_x25519_scalarmult_batch` — a separate entry point with its own
    # chunker, AVX2 4-way kernel and aggregated low-order rejection, none of
    # which the `x25519` target reaches.  Measured 0/0 on both compilers with
    # a same-class floor of 0, like the other twelve.
    "x25519-batch": 0,
    # `ama_secp256k1_point_mul` — the Montgomery ladder the info-only
    # `secp256k1 scalar multiplication` dudect lane exercises, which had no
    # blocking counterpart while its own source comment claimed one.  The two
    # classes are a Hamming-weight contrast (k = 1 against a scalar just under
    # n), so every ladder step takes the opposite cswap branch between them.
    "secp256k1-scalarmult": 0,
}

#: Where to look first when a target fails.  Kept per-target so the message
#: names the code that is actually implicated rather than a generic pointer.
_REMEDY = {
    "secp256k1-scalarmult": (
        "The ladder in src/c/ama_secp256k1.c must select with\n"
        "ama_consttime_swap, not with a branch on a scalar bit. Disassemble\n"
        "the ladder loop in the built object and look for a conditional branch\n"
        "whose predicate is a bit of the scalar; see\n"
        "src/c/internal/ama_ct_barrier.h. If only the cache-miss columns\n"
        "moved, check that the driver stages its scalar into one aligned\n"
        "buffer rather than pointing at one of two constants."
    ),
    "ghash": (
        "The usual cause is an optimizer turning the masked GHASH accumulation\n"
        "back into a branch on the secret subkey. Disassemble ghash_mul in the\n"
        "built object and look for a conditional branch that skips the masked\n"
        "XOR; see src/c/internal/ama_ct_barrier.h."
    ),
    "ecdsa": (
        "The usual cause is a branch on a secret in the scalar arithmetic of\n"
        "src/c/ama_secp256k1.c. Three sites have had this defect and all three\n"
        "must stay masked rather than branched: the Montgomery extra-reduction\n"
        "predicate in sc_mont_mul, the carry fold in sc_add, and the low-s\n"
        "normalisation (sc_is_high must not short-circuit, and the negation is\n"
        "selected via sc_cond_negate). Disassemble each and look for a\n"
        "conditional jump. Do NOT discount any part of the delta as DER\n"
        "encoding: this target signs through ama_secp256k1_ecdsa_sign_raw, so\n"
        "the encoder is outside the measurement entirely and there is no\n"
        "benign component left to subtract. Any non-zero delta here is a\n"
        "defect."
    ),
    "ascon-hash": (
        "ama_ascon_hash256 in src/c/ama_ascon.c must absorb and permute over a\n"
        "fixed schedule with no input-dependent branch and no table lookup. A\n"
        "delta here means the implementation itself became input-dependent, and\n"
        "the wall-clock dudect lane's finding is AMA's rather than the CPU's.\n"
        "No delta means the opposite: see the driver comment and the PSTATE.DIT\n"
        "/ DOITM discussion, because the remediation is then a deployment mode\n"
        "rather than a code change."
    ),
    "ascon-encrypt": (
        "ama_ascon_aead128_encrypt in src/c/ama_ascon.c must absorb, permute and\n"
        "squeeze over a schedule fixed by the LENGTHS, with no key-dependent\n"
        "branch and no table lookup. A delta here means the implementation became\n"
        "key-dependent, and the wall-clock dudect lane's sub-nanosecond finding is\n"
        "AMA's rather than the CPU's. No delta means the opposite: see the driver\n"
        "comment and the PSTATE.DIT / DOITM discussion, because the remediation is\n"
        "then a deployment mode rather than a code change."
    ),
    "agent-binding": (
        "ama_agent_binding_check in src/c/ama_agent_binding.c must compare the\n"
        "authorization in constant time and return a MASKED verdict, so accepting\n"
        "and rejecting retire the same instructions. A delta here is a verdict\n"
        "oracle: an early return on the first mismatched byte, or a branch on the\n"
        "comparison result before the return. Look for a conditional that skips\n"
        "work on the reject path; see src/c/internal/ama_ct_barrier.h and the\n"
        "masked-return pattern in ama_chacha20poly1305.c."
    ),
    "kyber-decaps": (
        "kyber_decapsulate_internal in src/c/ama_kyber.c must compute BOTH the\n"
        "real shared secret and the implicit-rejection value H(z||ct), then select\n"
        "between them with ama_consttime_copy on the ama_consttime_memcmp result.\n"
        "A delta here is a plaintext-checking oracle: an attacker who can tell\n"
        "rejection from success recovers the message the FO transform exists to\n"
        "protect. Look for a branch on the ciphertext comparison, or for the\n"
        "rejection value being computed only when it is needed."
    ),
    "sha3-256": (
        "ama_sha3_256 in src/c/ama_sha3.c must absorb and permute over a fixed\n"
        "schedule with no input-dependent branch and no table lookup. A delta\n"
        "here means the implementation itself became input-dependent, and the\n"
        "wall-clock dudect lane's finding is AMA's rather than the CPU's. No\n"
        "delta means the opposite: the remediation is then a deployment mode\n"
        "(DOITM / PSTATE.DIT) rather than a code change. Check first for an\n"
        "optimizer-introduced branch in the absorb loop's partial-block tail."
    ),
    "ed25519-sign": (
        "ama_ed25519_sign in src/c/ama_ed25519.c must not branch on the secret\n"
        "key or the derived nonce. A delta here is the most serious result this\n"
        "tool can produce: the class variable is the long-term signing key, so\n"
        "an input-dependent instruction stream is a key-recovery surface rather\n"
        "than a nuisance. Look at the scalar-multiplication comb (a conditional\n"
        "point add or a data-dependent window index), sc25519 reduction, and\n"
        "any early exit in the SHA-512 core. No delta puts the wall-clock\n"
        "reading on the CPU's data-operand-dependent execution instead."
    ),
    "nistp-ecdsa": (
        "The usual cause is the optimizer branching on a mask that\n"
        "src/c/ama_nistp.c built to be branch-free. Every mask in that file\n"
        "comes from nistp_mask64(), which launders it through\n"
        "ama_ct_value_barrier_u64 for exactly this reason; check that the\n"
        "barrier is still there before looking anywhere else. The predicates\n"
        "it protects are the Montgomery extra-reduction carry in\n"
        "nistp_cond_sub_mod, the exceptional-case flags in nistp_jac_add, and\n"
        "the comb digit — the last two of which are functions of the RFC 6979\n"
        "nonce. Disassemble nistp_mont_mul and nistp_jac_add and look for a\n"
        "conditional jump. Do NOT discount any part of the delta as DER\n"
        "encoding: this target signs through ama_nistp_ecdsa_sign_raw, so the\n"
        "encoder is outside the measurement entirely and there is no benign\n"
        "component left to subtract. Any non-zero delta here is a defect."
    ),
    "x25519-batch": (
        "The batch entry point adds code above the ladder that the `x25519`\n"
        "target does not reach: the four-lane chunker and scalar tail in\n"
        "ama_x25519_scalarmult_batch (src/c/ama_x25519.c), the AVX2 4-way\n"
        "kernel behind AMA_DISPATCH_USE_X25519_AVX2, and the aggregated\n"
        "low-order rejection that must zero EVERY output when ANY lane\n"
        "rejects. Check that the rejection aggregation is a mask over all\n"
        "lanes rather than an early return, that the tail loop count is a\n"
        "function of `count` and not of any scalar, and that the 4-way\n"
        "kernel's conditional swap is a mask. If `x25519` also fails, fix\n"
        "that first: the fault is in the shared ladder, not in the batching."
    ),
    "x25519": (
        "The Montgomery ladder in src/c/ama_x25519.c must swap with a mask, not\n"
        "a branch: the predicate is one bit of the secret scalar per step, so a\n"
        "branch there leaks the key directly. Check the conditional swap first,\n"
        "then the field paths it uses (src/c/fe64.h, src/c/fe51.h and the\n"
        "MULX+ADX kernel in src/c/internal/ama_x25519_fe64_mulx.c) for a\n"
        "carry-fold or canonicalisation written as an `if`. Which field path\n"
        "ran is reported by ama_x25519_field_path(); a delta that appears on\n"
        "one path and not another is still a defect on the path it appears on."
    ),
    "consttime": (
        "ama_consttime_memcmp in src/c/ama_consttime.c must accumulate over the\n"
        "whole buffer with no early exit. Any delta here means the loop gained a\n"
        "break, a comparison, or an optimizer-introduced branch on the running\n"
        "difference — disassemble it and confirm the only jump is the loop\n"
        "counter. This count is invariant by construction, so unlike the other\n"
        "targets there is no benign spread to discount."
    ),
    "aead-verify": (
        "The AEAD decrypt accept/reject pair at ct_len == 0 must retire the\n"
        "same instruction count: everything after the Poly1305/GHASH recompute\n"
        "— the constant-time tag compare, the shared scrub, the masked\n"
        "zero-length decrypt, and the MASKED return-code selection — is one\n"
        "instruction sequence for both outcomes. The usual cause of a delta is\n"
        "the return selection regressing to a ternary/branch: gcc 13 on\n"
        "aarch64 compiled `tag_match ? AMA_SUCCESS : AMA_ERROR_VERIFY_FAILED`\n"
        "in ama_chacha20poly1305.c into a cbnz whose reject arm was one\n"
        "instruction longer, which the chacha20-neon dudect sweep slot\n"
        "measured at |t| = 8.08. Disassemble the tail of\n"
        "ama_chacha20poly1305_decrypt and ama_aes256_gcm_decrypt and confirm\n"
        "the return value is produced by mask arithmetic, not selected by a\n"
        "conditional branch. The accept/reject outcome itself is public via\n"
        "the return code — this pins measurement symmetry, not secrecy."
    ),
}


_DRIVER = r"""
/* Generated by tools/check_ghash_constant_time.py — do not edit. */
#include <stdint.h>
#include <string.h>
#include "ama_cryptography.h"

/* AMA_TESTING_MODE hook from src/c/dispatch/ama_dispatch.c.  Forcing the
 * scalar path is the entire point: on any host with PCLMULQDQ/VAES (every
 * x86-64 CI runner) the dispatcher would otherwise route to the SIMD kernel
 * and this check would measure code the gate is not about. */
void ama_test_force_aes_gcm_scalar(void);

int main(int argc, char **argv) {
    uint8_t key[32], nonce[12], pt[512], aad[64], ct[512], tag[16];
    unsigned fill = (argc > 1) ? (unsigned)(unsigned char)argv[1][0] : 0u;

    /* Spread the class byte across the key rather than `memset`-ing it.
     * A repeated-byte key is a degenerate sample: it makes the whole key
     * schedule, and every H-derived value, highly structured, and it caps the
     * reachable key space at 256 values. The expansion is deterministic, so
     * the count stays reproducible to the instruction. */
    for (unsigned i = 0; i < sizeof key; i++)
        key[i] = (uint8_t)(fill * 31u + i * 167u + i * i * 13u);
    memset(nonce, 0, sizeof nonce);
    memset(pt, 0, sizeof pt);
    memset(aad, 0, sizeof aad);

    ama_test_force_aes_gcm_scalar();

    /* The return value is checked so that a failed encryption cannot be
     * measured as if it were a successful one.  Eight early returns are
     * every bit as key-independent as eight encryptions, and would read as a
     * pass; the exit status is what lets the caller tell the two apart. */
    for (int i = 0; i < 8; i++) {
        if (ama_aes256_gcm_encrypt(key, nonce, pt, sizeof pt,
                                   aad, sizeof aad, ct, tag) != AMA_SUCCESS) return 1;
    }

    /* Consume the tag without letting its value reach control flow or
     * output.  A data-dependent printf would differ between key classes on
     * its own and would be indistinguishable from the defect. */
    static volatile uint8_t sink;
    for (int i = 0; i < 16; i++) sink = (uint8_t)(sink ^ tag[i]);
    return 0;
}
"""

_ECDSA_DRIVER = r"""
/* Generated by tools/check_ghash_constant_time.py — do not edit. */
#include <stdint.h>
#include <string.h>
#include "ama_cryptography.h"

/* secp256k1 ECDSA signing, fixed message, key varied by class.
 *
 * The property under test is every secret-dependent step of signing: the
 * Montgomery extra reduction in sc_mont_mul, the carry fold in sc_add, and
 * the low-s normalisation.  Written with a branch, each leaks the long-term
 * key and — worse — the per-signature nonce.  RFC 6979 makes signing
 * deterministic, so with a fixed message the only input that moves is the
 * key and the count is reproducible to the instruction. */
int main(int argc, char **argv) {
    uint8_t sk[32], pk[33], sig[AMA_SECP256K1_ECDSA_RAW_SIG_LEN], msg[32];
    unsigned fill = (argc > 1) ? (unsigned)(unsigned char)argv[1][0] : 0x41u;

    /* Spread the class byte across the key — see the ghash driver.  A
     * repeated-byte scalar is a poor sample of the private-key space, and
     * this check's whole power comes from two classes landing on opposite
     * sides of a secret-dependent predicate. */
    for (unsigned i = 0; i < sizeof sk; i++)
        sk[i] = (uint8_t)(fill * 31u + i * 167u + i * i * 13u);
    memset(msg, 0x11, sizeof msg);
    if (ama_secp256k1_pubkey_from_privkey(sk, pk) != AMA_SUCCESS) return 1;

    static volatile uint8_t sink;
    for (int i = 0; i < 8; i++) {
        memset(sig, 0, sizeof sig);
        /* The FIXED-WIDTH entry point, not the DER one.
         *
         * DER omits the leading zero octets of r and s, so a DER signature
         * is 8 to 72 octets and its length is a function of the key.  The
         * length is public, but it is key-correlated and it lands inside a
         * count taken over the whole call, which is why this target had to
         * sit at a threshold of 64 while the other eleven sat at 0 — a
         * tolerance of 8 instructions per signature with room for a real
         * leak underneath.  ama_secp256k1_ecdsa_sign_raw runs identical
         * arithmetic and emits a constant 64 octets, so the encoder is
         * outside the measurement and the threshold is 0.
         *
         * Equivalence is not assumed: tests/c/test_secp256k1.c decodes the
         * DER signature back to (r, s) and compares it against r||s over 512
         * keys, and asserts it saw at least one short DER signature so the
         * comparison cannot pass over full-length cases alone. */
        if (ama_secp256k1_ecdsa_sign_raw(sig, msg, sk) != AMA_SUCCESS) return 1;
        for (size_t j = 0; j < sizeof sig; j++) sink = (uint8_t)(sink ^ sig[j]);
    }
    return 0;
}
"""

_CONSTTIME_DRIVER = r"""
/* Generated by tools/check_ghash_constant_time.py — do not edit. */
#include <stdint.h>
#include <string.h>
#include "ama_cryptography.h"

/* ama_consttime_memcmp over a 4 KiB buffer. The class byte selects where the
 * first differing byte sits; class 'A' makes the buffers equal.
 *
 * The harness deliberately has NO class-dependent branch of its own: the
 * mutation is always performed, with an XOR mask of 0 for the equal class.
 * Written the obvious way — `if (cls > 0) { ...mutate... }` — the harness
 * contributes ~11 instructions of its own and the measurement stops being a
 * statement about the library. A driver for a constant-time check has to be
 * constant-time itself. */
int main(int argc, char **argv) {
    enum { N = 4096 };
    static uint8_t a[N], b[N];
    unsigned cls = (argc > 1) ? (unsigned)(unsigned char)argv[1][0] : 0x41u;
    size_t pos = (size_t)((cls * 37u) % N);
    uint8_t mask = (uint8_t)((cls == 0x41u) ? 0x00u : 0xffu);

    memset(a, 0x5a, sizeof a);
    memset(b, 0x5a, sizeof b);
    b[pos] = (uint8_t)(b[pos] ^ mask);

    static volatile int sink;
    for (int i = 0; i < 2000; i++)
        sink = sink ^ ama_consttime_memcmp(a, b, sizeof a);
    return 0;
}
"""

_AEAD_VERIFY_DRIVER = r"""
/* Generated by tools/check_ghash_constant_time.py — do not edit. */
#include <stdint.h>
#include <string.h>
#include "ama_cryptography.h"

/* AMA_TESTING_MODE hook — force the scalar AES-GCM path so this measures
 * the same code on every host (see the ghash driver's rationale). */
void ama_test_force_aes_gcm_scalar(void);

/* ChaCha20-Poly1305 and AES-256-GCM decrypt at ct_len == 0: the
 * accept/reject pair.  The class byte's LOW BIT selects the tag —
 * bit 0 = valid tag (accept, AMA_SUCCESS), bit 1 = flipped tag
 * (reject, AMA_ERROR_VERIFY_FAILED) — so the standard eight key
 * classes sample both outcomes and every cross-class delta that
 * matters is an accept-vs-reject pair.
 *
 * The property under test is the one the dudect tag-verify lanes time
 * statistically: at ct_len == 0 the Poly1305/GHASH recompute, the
 * constant-time tag compare, the shared scrub, the masked zero-length
 * decrypt, AND the masked return-code selection are a single
 * instruction sequence for both outcomes.  gcc 13 on aarch64 compiled
 * the previous ternary return in ama_chacha20poly1305.c into a branch
 * whose reject arm was one instruction longer; amplified over the
 * iteration count below, that regression is a ~ITERS-instruction
 * cross-class delta, two orders of magnitude above the threshold.
 *
 * The driver itself must be class-symmetric: the tag pointer is
 * selected with mask arithmetic, and the per-call return codes are
 * folded into an accumulator (compared against the class's expected
 * code, itself derived by mask arithmetic) so verifying correctness
 * adds no class-dependent branch inside the measured loops.
 *
 * 500 iterations: a one-instruction-per-call regression amplifies to a
 * 500-instruction cross-class delta, far above the measured same-class
 * floor, while keeping the 10-run check inside the ARM job's budget under
 * valgrind.  The amplification is no longer what carries the sensitivity —
 * this target's limit is 0, so a single retired instruction of cross-class
 * difference fails it — but it still separates a real per-call divergence
 * from anything that could enter the count once, outside the loops. */
enum { ITERS = 500 };

int main(int argc, char **argv) {
    uint8_t key[32], nonce[12], aad[32], tag_good[16], tag_bad[16];
    unsigned cls = (argc > 1) ? (unsigned)(unsigned char)argv[1][0] : 0x41u;
    uintptr_t bit = (uintptr_t)(cls & 1u);
    uintptr_t sel = (uintptr_t)0 - bit;
    /* AMA_SUCCESS == 0, so expected = VERIFY_FAILED iff bit is set. */
    unsigned expected = (unsigned)AMA_ERROR_VERIFY_FAILED & (unsigned)(0 - (int)bit);
    unsigned acc = 0;

    for (unsigned i = 0; i < sizeof key; i++)
        key[i] = (uint8_t)(0x5Eu * 31u + i * 167u + i * i * 13u);
    memset(nonce, 0x24, sizeof nonce);
    memset(aad, 0x7Bu, sizeof aad);

    ama_test_force_aes_gcm_scalar();

    /* --- ChaCha20-Poly1305 --- */
    if (ama_chacha20poly1305_encrypt(key, nonce, NULL, 0,
                                     aad, sizeof aad, NULL, tag_good) != AMA_SUCCESS)
        return 1;
    memcpy(tag_bad, tag_good, sizeof tag_bad);
    tag_bad[0] ^= 0x01;
    {
        const uint8_t *tag_use = (const uint8_t *)(
            ((uintptr_t)tag_good & ~sel) | ((uintptr_t)tag_bad & sel));
        for (int i = 0; i < ITERS; i++) {
            ama_error_t rc = ama_chacha20poly1305_decrypt(
                key, nonce, NULL, 0, aad, sizeof aad, tag_use, NULL);
            acc |= (unsigned)rc ^ expected;
        }
    }

    /* --- AES-256-GCM (scalar path forced above) --- */
    if (ama_aes256_gcm_encrypt(key, nonce, NULL, 0,
                               aad, sizeof aad, NULL, tag_good) != AMA_SUCCESS)
        return 1;
    memcpy(tag_bad, tag_good, sizeof tag_bad);
    tag_bad[0] ^= 0x01;
    {
        const uint8_t *tag_use = (const uint8_t *)(
            ((uintptr_t)tag_good & ~sel) | ((uintptr_t)tag_bad & sel));
        for (int i = 0; i < ITERS; i++) {
            ama_error_t rc = ama_aes256_gcm_decrypt(
                key, nonce, NULL, 0, aad, sizeof aad, tag_use, NULL);
            acc |= (unsigned)rc ^ expected;
        }
    }

    /* One check, after all measured loops: a wrong return code on any
     * iteration makes the run non-zero, so a driver that measured the
     * wrong thing cannot be reported as a pass. */
    return acc != 0;
}
"""

_ASCON_HASH_DRIVER = r"""
/* Generated by tools/check_ghash_constant_time.py — do not edit. */
#include <stdint.h>
#include <string.h>
#include "ama_cryptography.h"

/* Ascon-Hash256 (NIST SP 800-232) over a fixed 64-byte input, with the class
 * byte spread across that input.
 *
 * Why this target exists.  The wall-clock lane in
 * tools/constant_time/dudect_crypto.c reported |t| = 19.0 for Ascon-Hash256
 * in 5 of 5 rounds, consistently signed, on a CI runner — while the SAME
 * binary is a null on other hardware (t = +2.16 / -1.57 / -1.18 at 50,000 /
 * 200,000 / 800,000 iterations: no sqrt(n) growth, sign flipping).  That
 * lane's construction is already symmetric — both inputs built before the
 * loop, branchless pointer select, nothing class-dependent before the timer
 * — so the disagreement is between two machines, not two harnesses.
 *
 * Retired instruction counts settle which half of that is AMA's.  They are
 * deterministic and immune to the microarchitecture, so if the count is
 * input-independent then the implementation is data-independent and the
 * wall-clock difference belongs to the CPU (the data-operand-dependent
 * execution that Intel's DOITM and ARM's PSTATE.DIT exist to control) rather
 * than to src/c/ama_ascon.c.  That is the same method that settled
 * ama_consttime_memcmp: delta 0 across all eight classes, noise floor 0.
 *
 * Which specific inputs the classes carry does not matter for THIS question:
 * any two distinct inputs expose a data-dependent path in the instruction
 * stream.  The dudect lane deliberately uses the 0x00 / 0xFF extremes because
 * maximal Hamming contrast is where an operand-dependent HARDWARE effect is
 * most visible, which is a different question and not one callgrind can
 * answer.
 *
 * No class-dependent branch in the driver itself — see the consttime driver:
 * a driver for a constant-time check has to be constant-time too. */
int main(int argc, char **argv) {
    enum { N = 64 };
    static uint8_t input[N];
    uint8_t digest[32];
    unsigned fill = (argc > 1) ? (unsigned)(unsigned char)argv[1][0] : 0x41u;

    /* Spread the class byte, as the ecdsa driver does: a repeated-byte input
     * is a poor sample, and the check's power comes from classes landing on
     * different sides of any input-dependent predicate. */
    for (unsigned i = 0; i < (unsigned)N; i++)
        input[i] = (uint8_t)(fill * 31u + i * 167u + i * i * 13u);

    static volatile uint8_t sink;
    for (int i = 0; i < 2000; i++) {
        if (ama_ascon_hash256(input, sizeof input, digest) != AMA_SUCCESS) return 1;
        sink = (uint8_t)(sink ^ digest[0]);
    }
    return 0;
}
"""

_ASCON_ENCRYPT_DRIVER = r"""
/* Generated by tools/check_ghash_constant_time.py — do not edit. */
#include <stdint.h>
#include <string.h>
#include "ama_cryptography.h"

/* Ascon-AEAD128 encryption (NIST SP 800-232 Algorithm 3) over a fixed 64-byte
 * plaintext, with the class byte spread across the KEY.  The key is the secret
 * here, so it is the key that has to be varied — the Ascon-Hash256 target above
 * varies the message because for a hash the message is the input under test.
 *
 * Why this target exists.  The wall-clock lane
 * `Ascon-AEAD128 encrypt (key-independent)` in tests/c/test_dudect.c crossed
 * the threshold on shared runners with a per-class difference of about
 * +0.6 ns — under a quarter of the effect-size floor — and, across two runs of
 * the SAME binary at the SAME measurement count, it was consistently signed in
 * one (3/3, +0.596 ns) and direction-inconsistent in the other (2+/1-,
 * +0.607 ns).  A quantity whose SIGN is not reproducible between two machines
 * executing identical instructions is not a property of the code.
 *
 * That is exactly the range dudect's verdict rule declines to adjudicate, on
 * the stated grounds that the deterministic instruction-count gates own it.
 * For Ascon-AEAD128 ENCRYPT that was not true: `ascon-hash` covers
 * Ascon-Hash256 and `aead-verify` covers the AEAD accept/reject pair, and
 * neither covers this call.  The sub-floor exemption was making a claim about
 * coverage that did not exist, so the coverage is added rather than the claim
 * softened.
 *
 * Retired instruction counts settle it deterministically: if the count does not
 * depend on the key then the implementation is key-independent, and a residual
 * wall-clock difference belongs to the CPU's data-operand-dependent execution
 * (what Intel's DOITM and ARM's PSTATE.DIT exist to control) rather than to
 * src/c/ama_ascon.c.  Same method, same standard as ghash / ecdsa /
 * ed25519-sign / aead-verify: cross-class delta 0, noise floor 0.
 *
 * No class-dependent branch in the driver itself — a driver for a
 * constant-time check has to be constant-time too. */
int main(int argc, char **argv) {
    uint8_t key[AMA_ASCON_AEAD128_KEY_LEN];
    uint8_t nonce[AMA_ASCON_AEAD128_NONCE_LEN];
    uint8_t pt[64], ct[64], tag[AMA_ASCON_AEAD128_TAG_LEN];
    unsigned fill = (argc > 1) ? (unsigned)(unsigned char)argv[1][0] : 0x41u;

    /* Spread the class byte across the key, as the ecdsa and ascon-hash
     * drivers do: a repeated-byte key is a poor sample, and the check's power
     * comes from classes landing on different sides of any key-dependent
     * predicate. */
    for (unsigned i = 0; i < (unsigned)sizeof key; i++)
        key[i] = (uint8_t)(fill * 31u + i * 167u + i * i * 13u);

    /* Nonce and plaintext are FIXED across classes: the question is whether
     * the KEY changes the instruction stream, so everything else must be held
     * constant or a delta would not localise to the key. */
    memset(nonce, 0x5A, sizeof nonce);
    memset(pt, 0xA5, sizeof pt);

    static volatile uint8_t sink;
    for (int i = 0; i < 2000; i++) {
        if (ama_ascon_aead128_encrypt(key, nonce, pt, sizeof pt,
                                      NULL, 0, ct, tag) != AMA_SUCCESS) return 1;
        sink = (uint8_t)(sink ^ ct[0] ^ tag[0]);
    }
    return 0;
}
"""

_AGENT_BINDING_DRIVER = r"""
/* Generated by tools/check_ghash_constant_time.py — do not edit. */
#include <stdint.h>
#include <string.h>
#include "ama_cryptography.h"

/* ama_agent_binding_check on an ACCEPTING and a REJECTING binding.
 *
 * Unlike every other target here the two classes are not two secrets, they are
 * two VERDICTS: class 'A' checks an authorization that verifies, every other
 * class checks one whose first authorization byte has been flipped.  A verdict
 * oracle is the leak that matters for this call — if rejecting costs fewer
 * instructions than accepting, an attacker learns whether a forged
 * authorization was close, which is the same defect the AEAD accept/reject
 * target (`aead-verify`) exists to pin for the ciphers.
 *
 * Why this target exists.  The wall-clock lane `agent binding check
 * (verdict-independent)` in tests/c/test_dudect.c crossed the threshold on a
 * shared runner in 3 of 3 rounds at |t| = 41.72 with a per-class difference of
 * -1.141 ns — under the effect-size floor, in the range where a wall-clock
 * t-test on shared hardware cannot separate a source-level leak from the CPU's
 * data-operand-dependent execution.  dudect declines to adjudicate there on
 * the grounds that the deterministic instruction-count gates own the range;
 * for this call nothing did, so the exemption rested on coverage that did not
 * exist.  This is that coverage.
 *
 * Both classes must reach the same code path length for the count to be
 * comparable, so the driver checks the return value only against a sink and
 * never branches on it — a driver for a constant-time check has to be
 * constant-time too. */
int main(int argc, char **argv) {
    ama_agent_binding_t good, bad;
    uint8_t instance_id[AMA_AGENT_INSTANCE_ID_BYTES];
    uint8_t profile[AMA_ETHICAL_PROFILE_BYTES];
    uint8_t authority_key[32];
    unsigned fill = (argc > 1) ? (unsigned)(unsigned char)argv[1][0] : 0x41u;

    /* Fixed across classes: the question is whether the VERDICT changes the
     * instruction stream, so the binding's contents must be held constant. */
    for (unsigned i = 0; i < (unsigned)sizeof instance_id; i++)
        instance_id[i] = (uint8_t)(0x5Au + i * 167u);
    for (unsigned i = 0; i < (unsigned)sizeof profile; i++)
        profile[i] = (uint8_t)(0xA5u + i * 13u);
    for (unsigned i = 0; i < (unsigned)sizeof authority_key; i++)
        authority_key[i] = (uint8_t)(0x11u + i * 31u);

    if (ama_agent_binding_init(&good, AMA_AGENT_LIFETIME_PERSISTENT,
                               (uint8_t)(AMA_AGENT_CAP_DATA_SIGN |
                                         AMA_AGENT_CAP_PERSISTENCE |
                                         AMA_AGENT_CAP_SELF_REPLICATE),
                               instance_id, profile) != AMA_SUCCESS) return 1;
    if (ama_agent_binding_authorize(&good, authority_key,
                                    sizeof authority_key) != AMA_SUCCESS) return 1;

    memcpy(&bad, &good, sizeof bad);
    bad.authorization[0] = (uint8_t)(bad.authorization[0] ^ 0x01u);

    /* Class 'A' is the accepting binding; every other class is the rejecting
     * one.  The selection is a branchless pointer choice made ONCE, outside
     * the measured loop, so the driver contributes no per-class instructions
     * of its own. */
    const ama_agent_binding_t *b = (fill == 0x41u) ? &good : &bad;

    static volatile unsigned sink;
    for (int i = 0; i < 2000; i++) {
        ama_error_t rc = ama_agent_binding_check(b, authority_key,
                                                 sizeof authority_key);
        sink = sink ^ (unsigned)rc;
    }
    return 0;
}
"""

_KYBER_DECAPS_DRIVER = r"""
/* Generated by tools/check_ghash_constant_time.py — do not edit. */
#include <stdint.h>
#include <string.h>
#include "ama_cryptography.h"

/* ML-KEM-1024 decapsulation, with the class deciding the FO VERDICT.
 *
 * Class 'A' decapsulates a ciphertext whose re-encryption matches; every other
 * class decapsulates one whose first byte has been flipped, taking the FIPS 203
 * Sec 6.3 implicit-rejection path.  Like `aead-verify` and `agent-binding`, the
 * two classes here are two OUTCOMES rather than two secrets: a decapsulator
 * that is measurably faster on rejection hands an attacker the plaintext-checking
 * oracle the Fujisaki-Okamoto transform exists to deny, which is the whole
 * IND-CCA2 argument for the scheme.
 *
 * Why this target exists.  The wall-clock lane `Kyber-1024 decaps (CT reject)`
 * in tests/c/test_dudect.c crossed the threshold on a shared runner in 3 of 3
 * rounds at |t| = 11.81 with a per-class difference of +5.630 ns — ABOVE the
 * 2 ns effect-size floor, so the verdict rule correctly refused to excuse it and
 * failed the build.  A difference in that range is exactly what a mispredicted
 * branch (7-10 ns) looks like, so it could not be waved away as measurement
 * noise; it needed a deterministic answer.
 *
 * The deterministic answer, measured over 60 decapsulations per class on the
 * Release (-O3) library the wheel ships: retired instructions, data
 * references, D1 misses and LLd misses are all four byte-identical between
 * the valid and the rejected ciphertext, under gcc 13 and clang 18 alike.
 * Instructions rule out a branch or any skipped computation; the
 * data-reference and miss figures rule out a secret-dependent memory access,
 * which an instruction count alone cannot see.  (The absolute figures for the
 * measuring commit are in CHANGELOG.md; the zero deltas are the invariant.
 * An earlier revision of this comment quoted counts taken on an unoptimized
 * build and argued the 5.630 ns was "one part in 90,000" of a decapsulation —
 * withdrawn: a mispredicted branch costs a fixed 5-20 ns whatever surrounds
 * it, so the ratio excludes nothing.  The identity above is the argument.)
 * The residual wall-clock difference needs no exotic explanation and an
 * earlier revision's appeal to data-operand-dependent latency (Intel DOITM,
 * ARM PSTATE.DIT) is withdrawn.  The lane that produced it selected its
 * ciphertext with `class_idx ? ct_bad : ct`, a branch perfectly correlated
 * with the class sitting between the class draw and the opening timer.  Run
 * as a null experiment — byte-identical ciphertexts in both classes, true
 * effect exactly zero, 200,000 measurements, 5 runs — that construction is
 * over threshold in 3 of 5 runs at worst |t| = 6.99, every excursion one
 * sign; the masked-merge staging the lane now uses is 0 of 5.  The excursion
 * was the instrument's, not the primitive's.
 *
 * THE STAGING BELOW IS LOAD-BEARING.  Handing the timed call `ct` for one class
 * and `ct_bad` for the other confounds the class with the ciphertext's ADDRESS:
 * measured that way at -O3 this same driver reports a reproducible ~175-miss
 * D1 delta with the instruction count unchanged — a "finding" that belongs
 * entirely to the driver.  Copying the selected ciphertext into one aligned
 * buffer first collapses it to zero.  This is the same defect
 * tools/check_dudect_class_staging.py enforces against in the wall-clock
 * harnesses; a driver for a constant-time check has to be constant-time
 * too — and since the miss metrics landed, an unstaged driver FAILS this
 * gate rather than merely misleading its reader. */
int main(int argc, char **argv) {
    static uint8_t pk[AMA_KYBER_1024_PUBLIC_KEY_BYTES];
    static uint8_t sk[AMA_KYBER_1024_SECRET_KEY_BYTES];
    static uint8_t ct[AMA_KYBER_1024_CIPHERTEXT_BYTES];
    static uint8_t ct_bad[AMA_KYBER_1024_CIPHERTEXT_BYTES];
    static _Alignas(64) uint8_t stage[AMA_KYBER_1024_CIPHERTEXT_BYTES];
    uint8_t ss[AMA_KYBER_1024_SHARED_SECRET_BYTES];
    uint8_t d[32], z[32];
    size_t ct_len = sizeof ct;
    unsigned fill = (argc > 1) ? (unsigned)(unsigned char)argv[1][0] : 0x41u;

    /* A seeded keypair, so the secret key is identical across every class and a
     * delta can only be the verdict. */
    for (unsigned i = 0; i < 32; i++) {
        d[i] = (uint8_t)(0x11u + i);
        z[i] = (uint8_t)(0x77u + i);
    }
    if (ama_kyber_keypair_from_seed(d, z, pk, sk) != AMA_SUCCESS) return 1;
    if (ama_kyber_encapsulate(pk, sizeof pk, ct, &ct_len, ss, sizeof ss) != AMA_SUCCESS) return 1;

    memcpy(ct_bad, ct, sizeof ct_bad);
    ct_bad[0] = (uint8_t)(ct_bad[0] ^ 0xFFu);

    /* Select ONCE, outside the measured loop, and stage into one buffer. */
    memcpy(stage, (fill == 0x41u) ? ct : ct_bad, sizeof stage);

    static volatile unsigned sink;
    for (int i = 0; i < 60; i++) {
        /* Implicit rejection returns AMA_SUCCESS for BOTH classes by design —
         * an rc divergence would itself be the oracle — so this check is a
         * genuine error path, not a class-dependent branch. */
        if (ama_kyber_decapsulate(stage, ct_len, sk, sizeof sk, ss, sizeof ss)
                != AMA_SUCCESS) return 1;
        sink = sink ^ (unsigned)ss[0];
    }
    return 0;
}
"""

_SHA3_256_DRIVER = r"""
/* Generated by tools/check_ghash_constant_time.py — do not edit. */
#include <stdint.h>
#include <string.h>
#include "ama_cryptography.h"

/* SHA3-256 (FIPS 202) over one full 136-byte rate block, class byte spread
 * across the input.
 *
 * Why this target exists.  The wall-clock lane in
 * tools/constant_time/dudect_crypto.c reported |t| = 12.05 for SHA3-256 in 3
 * of 5 rounds, consistently signed, on a CI runner — while the same commit's
 * previous run on the same runner class was a null (+2.42, and the harness
 * only escalates past round 1 when something trips).  Two commits apart, with
 * no C change between them: 09b2e51 changed Python and documentation only.
 *
 * The lane's own construction is not the suspect.  It builds both inputs
 * before the loop and selects between them with a branchless pointer select
 * outside the timer — the very defect it used to have, documented in that
 * file, and fixed.  So the disagreement is again between two machines rather
 * than between two harnesses, and the same instrument settles it.
 *
 * Retired instruction counts are deterministic and immune to the
 * microarchitecture.  Keccak-f[1600] has no lookup table and no
 * data-dependent branch (src/c/ama_sha3.c), so an input-independent count
 * means the implementation is data-independent and the wall-clock reading
 * belongs to the CPU's data-operand-dependent execution (what Intel's DOITM
 * and ARM's PSTATE.DIT exist to control).  A nonzero delta would mean the
 * opposite, and would make the dudect lane's finding AMA's.
 *
 * The dudect lane deliberately uses the 0x00 / 0xFF extremes because maximal
 * Hamming contrast is where an operand-dependent HARDWARE effect shows up.
 * That is a different question from this one and callgrind cannot answer it;
 * this driver spreads the class byte instead, which is the stronger probe for
 * an input-dependent instruction stream.
 *
 * No class-dependent branch in the driver itself — a driver for a
 * constant-time check has to be constant-time too. */
int main(int argc, char **argv) {
    enum { N = 136 };  /* one full SHA3-256 rate block, as the dudect lane uses */
    static uint8_t input[N];
    uint8_t digest[32];
    unsigned fill = (argc > 1) ? (unsigned)(unsigned char)argv[1][0] : 0x41u;

    for (unsigned i = 0; i < (unsigned)N; i++)
        input[i] = (uint8_t)(fill * 31u + i * 167u + i * i * 13u);

    static volatile uint8_t sink;
    for (int i = 0; i < 2000; i++) {
        if (ama_sha3_256(input, sizeof input, digest) != AMA_SUCCESS) return 1;
        sink = (uint8_t)(sink ^ digest[0]);
    }
    return 0;
}
"""

_ED25519_SIGN_DRIVER = r"""
/* Generated by tools/check_ghash_constant_time.py — do not edit. */
#include <stdint.h>
#include <string.h>
#include "ama_cryptography.h"

/* Ed25519 signing with the SECRET KEY as the class variable.
 *
 * Why this target exists.  The wall-clock lane in
 * tools/constant_time/dudect_crypto.c reported t = -6.71 for Ed25519 sign in
 * 4 of 5 rounds, consistently signed, on the same CI run that flagged
 * SHA3-256 — and passed (-2.40) on the immediately preceding commit, which
 * differed by no C code at all.
 *
 * This is the lane that matters most of the three, because unlike a hash the
 * class variable here IS the long-term secret: a real input-dependence would
 * be a key-recovery surface, not a nuisance.  So it gets the deterministic
 * instrument rather than an argument from the wall clock.
 *
 * Ed25519 signing is deterministic (RFC 8032 §5.1.6 derives the nonce from
 * the key and message), so for a fixed message the retired-instruction count
 * is a pure function of the secret key.  Constant-time signing means that
 * function is constant.  The scalar multiplication is a fixed-window comb
 * over the base point and the SHA-512 core is branchless, so an
 * input-independent count is the expected result and a delta localises the
 * defect to src/c/ama_ed25519.c.
 *
 * The class byte becomes the 32-byte seed, mirroring the dudect lane's
 * all-zero vs all-0xFF seeds but spreading the byte so the classes land on
 * different sides of any secret-dependent predicate rather than only on the
 * two Hamming extremes.  The message is FIXED: varying it would make the
 * count vary for a legitimate reason (message length feeds the SHA-512 block
 * count) and mask the property under test. */
int main(int argc, char **argv) {
    uint8_t public_key[32];
    uint8_t secret_key[64];
    uint8_t signature[64];
    /* Fixed message — see above.  64 bytes, the width the dudect lane signs. */
    static const uint8_t message[64] = {
        0x41, 0x4d, 0x41, 0x20, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72,
        0x61, 0x70, 0x68, 0x79, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39,
        0x20, 0x69, 0x6e, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e,
        0x2d, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x20, 0x69, 0x6e, 0x76, 0x61, 0x72,
        0x69, 0x61, 0x6e, 0x63, 0x65, 0x20, 0x64, 0x72, 0x69, 0x76, 0x65, 0x72,
        0x2e, 0x00, 0x00, 0x00,
    };
    unsigned fill = (argc > 1) ? (unsigned)(unsigned char)argv[1][0] : 0x41u;

    /* The seed occupies secret_key[0..31]; ama_ed25519_keypair writes the
     * public key into [32..63].  See the contract in ama_cryptography.h. */
    for (unsigned i = 0; i < 32u; i++)
        secret_key[i] = (uint8_t)(fill * 31u + i * 167u + i * i * 13u);
    if (ama_ed25519_keypair(public_key, secret_key) != AMA_SUCCESS) return 1;

    static volatile uint8_t sink;
    for (int i = 0; i < 200; i++) {
        if (ama_ed25519_sign(signature, message, sizeof message, secret_key) != AMA_SUCCESS)
            return 1;
        sink = (uint8_t)(sink ^ signature[0]);
    }
    return 0;
}
"""

_NISTP_ECDSA_DRIVER = r"""
/* Generated by tools/check_ghash_constant_time.py — do not edit. */
#include <stdint.h>
#include <string.h>
#include "ama_cryptography.h"

/* NIST P-256 ECDSA signing, fixed digest, key varied by class.
 *
 * The `ecdsa` target above measures the secp256k1 scalar arithmetic.  The
 * NIST P-curves are a SEPARATE implementation — src/c/ama_nistp.c has its own
 * limb layout, its own Montgomery multiply and its own group law — and nothing
 * measured it.  That gap was not theoretical: with the library built at -O3
 * (which CI did not do until the same change that added this target), clang 18
 * made `nistp_mont_mul` key-dependent by 1,251 retired instructions over four
 * signatures, by branching on the Montgomery extra-reduction predicate that
 * `nistp_mask64` exists to keep branch-free.  P-256, P-384 and P-521 share
 * that arithmetic, so one target covers the family's scalar core.
 *
 * P-256 rather than P-521: it is the widely deployed one, it is the fastest to
 * measure, and the limb code under test is shared.  RFC 6979 makes signing
 * deterministic, so with a fixed digest the only moving input is the key.
 *
 * `ama_nistp_ecdsa_sign_raw`, NOT `ama_nistp_ecdsa_sign`.  The two run
 * identical arithmetic and differ only in how they encode the result, and
 * DER is length-variable on the leading-zero bytes of r and s — public
 * values, but the encoder's cost tracks them, so the DER form put a
 * key-dependent term into the count that the gate then had to tolerate:
 * measured 32 retired instructions over four signatures under gcc 13 -O3
 * and 16 under clang 18.  Tolerating it meant a limit no tighter than the
 * benign term, and with only four signatures of amplification that limit
 * admitted tens of instructions per signature of REAL divergence.  The raw
 * form writes a fixed 64 octets, so the encoding contributes nothing and the
 * limit for this target is 0. */
int main(int argc, char **argv) {
    uint8_t sk[32], pk[65], sig[64], digest[32];
    unsigned fill = (argc > 1) ? (unsigned)(unsigned char)argv[1][0] : 0x41u;

    /* Spread the class byte across the key — see the ghash driver. */
    for (unsigned i = 0; i < sizeof sk; i++)
        sk[i] = (uint8_t)(fill * 31u + i * 167u + i * i * 13u);
    memset(digest, 0x11, sizeof digest);
    if (ama_nistp_pubkey_from_privkey(AMA_NIST_CURVE_P256, sk, pk) != AMA_SUCCESS) return 1;

    static volatile uint8_t sink;
    for (int i = 0; i < 4; i++) {
        memset(sig, 0, sizeof sig);
        if (ama_nistp_ecdsa_sign_raw(AMA_NIST_CURVE_P256, digest, sizeof digest,
                                     sk, sig) != AMA_SUCCESS) return 1;
        /* Fixed count over a fixed-width signature: the consumption is
         * identical for every class. */
        for (size_t j = 0; j < sizeof sig; j++) sink = (uint8_t)(sink ^ sig[j]);
    }
    return 0;
}
"""

_X25519_DRIVER = r"""
/* Generated by tools/check_ghash_constant_time.py — do not edit. */
#include <stdint.h>
#include <string.h>
#include "ama_cryptography.h"

/* X25519, secret scalar varied by class against a FIXED peer point.
 *
 * The Montgomery ladder's conditional swap is the canonical place a
 * branch-free select gets compiled back into a branch, and the predicate is a
 * bit of the secret scalar — one bit per ladder step, 255 steps, which is the
 * whole key.  The dudect lane for this primitive is a wall-clock test on a
 * shared runner; this is its deterministic counterpart, the same pairing
 * `ecdsa` has with `secp256k1 ECDSA sign`.
 *
 * The peer point is fixed so the only moving input is the secret.  The scalar
 * is clamped by the implementation, so every class still yields a distinct
 * valid scalar.  Both the fe64 and fe51 field paths reach this entry point;
 * which one runs is a build-time choice reported by ama_x25519_field_path(),
 * and the wiring line in this tool's report records the dispatch state the
 * counts were taken under. */
int main(int argc, char **argv) {
    uint8_t sk[32], peer[32], out[32];
    unsigned fill = (argc > 1) ? (unsigned)(unsigned char)argv[1][0] : 0x41u;

    for (unsigned i = 0; i < sizeof sk; i++)
        sk[i] = (uint8_t)(fill * 31u + i * 167u + i * i * 13u);
    /* A fixed, valid peer public key. */
    for (unsigned i = 0; i < sizeof peer; i++)
        peer[i] = (uint8_t)(0x09u + i);

    static volatile uint8_t sink;
    for (int i = 0; i < 8; i++) {
        /* A non-SUCCESS return would be a contributory-behaviour rejection,
         * i.e. a different amount of work — the exit status keeps that from
         * being measured as if it were a completed exchange. */
        if (ama_x25519_key_exchange(sk, peer, out) != AMA_SUCCESS) return 1;
        for (int j = 0; j < 32; j++) sink = (uint8_t)(sink ^ out[j]);
    }
    return 0;
}
"""


_X25519_BATCH_DRIVER = r"""
/* Generated by tools/check_ghash_constant_time.py — do not edit. */
#include <stdint.h>
#include <string.h>
#include "ama_cryptography.h"

/* Batched X25519, four secret scalars varied by class against FIXED peer
 * points.
 *
 * `ama_x25519_scalarmult_batch` is a separate public entry point from
 * `ama_x25519_key_exchange`, with its own code above the ladder: a
 * four-lane chunker, an AVX2 4-way kernel behind
 * AMA_DISPATCH_USE_X25519_AVX2, a scalar tail, and an aggregated
 * low-order rejection that zeroes EVERY output if ANY lane rejects.  None
 * of that is reached by the `x25519` target, which measures the
 * single-shot path.
 *
 * Its dudect lane (`X25519 scalarmult batch x4`) is info-only, and until
 * this target existed it was one of two info-only lanes with no blocking
 * deterministic counterpart at all — the pairing every other info-only
 * lane in that file cites as the reason it may be informational.  The
 * scalars ARE the secret here (255 conditional swaps each, one per bit),
 * so the property is exactly the one the `x25519` target states, over
 * different code.
 *
 * count = 4: the smallest batch that takes the full-chunk path rather than
 * the scalar fallback the header documents for N of 1, 2 and 3.  The four
 * scalars are distinct within a class so no lane can be a copy of another,
 * and the peer points are fixed so the only moving input is secret. */
int main(int argc, char **argv) {
    uint8_t sk[4][32], peer[4][32], out[4][32];
    unsigned fill = (argc > 1) ? (unsigned)(unsigned char)argv[1][0] : 0x41u;

    for (unsigned lane = 0; lane < 4; lane++) {
        for (unsigned i = 0; i < 32; i++) {
            sk[lane][i] = (uint8_t)(fill * 31u + i * 167u + i * i * 13u + lane * 97u);
            /* Fixed, valid peer public keys — distinct per lane, class-independent. */
            peer[lane][i] = (uint8_t)(0x09u + i + lane * 5u);
        }
    }

    static volatile uint8_t sink;
    for (int r = 0; r < 8; r++) {
        /* A non-SUCCESS return is a low-order rejection, i.e. a different
         * amount of work — the exit status keeps that from being measured
         * as though it were a completed batch. */
        if (ama_x25519_scalarmult_batch(out, (const uint8_t (*)[32])sk,
                                        (const uint8_t (*)[32])peer, 4) != AMA_SUCCESS)
            return 1;
        for (int lane = 0; lane < 4; lane++)
            for (int j = 0; j < 32; j++) sink = (uint8_t)(sink ^ out[lane][j]);
    }
    return 0;
}
"""


_SECP256K1_SCALARMULT_DRIVER = r"""
/* Generated by tools/check_ghash_constant_time.py — do not edit. */
#include <stdint.h>
#include <string.h>
#include "ama_cryptography.h"

/* secp256k1 Montgomery ladder, secret scalar varied by class against a FIXED
 * point (the generator).
 *
 * This target exists because `secp256k1 scalar multiplication`
 * (tests/c/test_dudect.c) was an info-only wall-clock lane with no blocking
 * counterpart, while its own in-source comment claimed one: "fail-loud
 * variants of this lane are intentionally surfaced separately via
 * tests/c/test_consttime.c".  That file contains no secp256k1 scalar-
 * multiplication case, so the claim was false and the primitive's
 * constant-time property rested on a lane that cannot fail CI.
 *
 * `ecdsa` does not cover it.  That target signs through
 * `ama_secp256k1_ecdsa_sign_raw`, whose ladder input is the RFC 6979 nonce
 * derived from a FIXED digest and the class key — so the ladder runs, but the
 * scalar it runs on is a hash output, not a controlled bit pattern, and the
 * lane's whole subject (a conditional swap whose predicate is a scalar bit)
 * is measured only incidentally.  Here the two classes are chosen for their
 * Hamming weight, the same contrast the dudect lane uses: every ladder step
 * takes the opposite cswap branch between classes.
 *
 * The point is fixed so the only moving input is the scalar.  Both scalars are
 * valid — in [1, n-1] — so neither class short-circuits on a range rejection,
 * which would be a different amount of work rather than a timing signal. */
int main(int argc, char **argv) {
    /* secp256k1 generator G, big-endian. */
    static const uint8_t Gx[32] = {
        0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,0x0B,0x07,
        0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,0x17,0x98
    };
    static const uint8_t Gy[32] = {
        0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,0x5D,0xA4,0xFB,0xFC,0x0E,0x11,0x08,0xA8,
        0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,0x9C,0x47,0xD0,0x8F,0xFB,0x10,0xD4,0xB8
    };
    /* Low Hamming weight: k = 1. */
    static const uint8_t k_low[32] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1
    };
    /* High Hamming weight, just under the curve order n. */
    static const uint8_t k_high[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
        0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40,
        0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE
    };
    unsigned cls = (argc > 1) ? (unsigned)(unsigned char)argv[1][0] : 0x41u;

    /* STAGE the scalar into one aligned buffer with a branchless select.
     *
     * `const uint8_t *k = (cls & 1u) ? k_high : k_low;` measured a real,
     * class-correlated delta: I refs and D refs were byte-identical across all
     * eight classes (16,020,312 / 3,835,717), and the D1/LL miss counts split
     * exactly along the odd/even classes at 1,661 vs 1,660.  That is not the
     * library — it is this driver handing the ladder a different ADDRESS per
     * class, so the two constants sit in different cache lines.  Selecting the
     * bytes into a single aligned destination is the same staging
     * `dudect_stage_select` performs in tests/c/test_dudect.c, and for the same
     * reason: the measurement must vary the secret, not where the secret
     * lives. */
    _Alignas(64) uint8_t k[32];
    const uint8_t mask = (uint8_t)-(uint8_t)(cls & 1u);
    for (unsigned i = 0; i < sizeof k; i++)
        k[i] = (uint8_t)((k_high[i] & mask) | (k_low[i] & (uint8_t)~mask));

    uint8_t out_x[32], out_y[32];
    static volatile uint8_t sink;
    for (int i = 0; i < 4; i++) {
        if (ama_secp256k1_point_mul(k, Gx, Gy, out_x, out_y) != AMA_SUCCESS) return 1;
        for (int j = 0; j < 32; j++) sink = (uint8_t)(sink ^ out_x[j] ^ out_y[j]);
    }
    return 0;
}
"""


_DRIVERS = {
    "ghash": _DRIVER,
    "ecdsa": _ECDSA_DRIVER,
    "consttime": _CONSTTIME_DRIVER,
    "aead-verify": _AEAD_VERIFY_DRIVER,
    "ascon-hash": _ASCON_HASH_DRIVER,
    "ascon-encrypt": _ASCON_ENCRYPT_DRIVER,
    "agent-binding": _AGENT_BINDING_DRIVER,
    "kyber-decaps": _KYBER_DECAPS_DRIVER,
    "sha3-256": _SHA3_256_DRIVER,
    "ed25519-sign": _ED25519_SIGN_DRIVER,
    "nistp-ecdsa": _NISTP_ECDSA_DRIVER,
    "x25519": _X25519_DRIVER,
    "x25519-batch": _X25519_BATCH_DRIVER,
    "secp256k1-scalarmult": _SECP256K1_SCALARMULT_DRIVER,
}


#: Standalone program that asks the library under test whether it was compiled
#: with optimization.  Kept separate from the measurement drivers so every
#: target gets the guard without ten copies of the same declaration.
_OPT_PROBE = r"""
/* Generated by tools/check_ghash_constant_time.py — do not edit. */
#include <stdio.h>

/* AMA_TESTING_MODE export from src/c/ama_consttime.c; declared in
 * src/c/internal/ama_testing_exports.h, which is not on this driver's
 * include path.  Same convention as ama_test_force_aes_gcm_scalar above. */
int ama_build_optimization_probe(void);

int main(void) {
    printf("%d\n", ama_build_optimization_probe());
    return 0;
}
"""


#: The four callgrind figures this tool compares across classes.
#:
#: Instruction counts alone cannot see a secret-dependent *memory access*: a
#: table lookup indexed by a secret retires exactly the same instructions
#: whichever entry it touches, and that is the AES S-box leak in its classic
#: form.  The data-reference count catches a differing NUMBER of accesses; the
#: two miss counts catch differing ADDRESSES, because a different address
#: stream through a fixed cache produces a different miss count.  All four are
#: simulated, so all four are deterministic — no statistics, no quiet machine.
_METRICS = {
    "I refs": re.compile(r"I\s+refs:\s+([\d,]+)"),
    "D refs": re.compile(r"D\s+refs:\s+([\d,]+)"),
    "D1 misses": re.compile(r"D1\s+misses:\s+([\d,]+)"),
    "LLd misses": re.compile(r"LLd\s+misses:\s+([\d,]+)"),
}

#: Metrics counted in operations, which a legitimately public-data-dependent
#: step can move (DER encoding of r and s in the ecdsa target).  They share the
#: per-target threshold.
_COUNT_METRICS = ("I refs", "D refs")

#: Cache geometry, PINNED.  Callgrind otherwise reads the host's cache
#: configuration out of CPUID, which makes every miss figure a property of the
#: runner rather than of the code — and a number quoted as evidence that only
#: reproduces on one CPU model is not evidence.  Pinning a plain 32 KiB 8-way
#: L1 / 8 MiB 16-way LL makes the miss counts reproducible anywhere the tool
#: runs.  The verdict never depended on the geometry (a delta between two
#: classes on one host is a delta whatever the cache), but the published
#: numbers do, and those are what a reader checks.
_CACHE_GEOMETRY = ("--I1=32768,8,64", "--D1=32768,8,64", "--LL=8388608,16,64")


def _limit_for(metric: str, count_threshold: int) -> int:
    """The limit that applies to one metric: the per-target count threshold
    for instruction and data-reference counts, MISS_THRESHOLD for the two
    cache-miss metrics.  Factored out because the sweep, the confirmation
    sweep and the report must all apply the SAME rule; three transcriptions of
    a threshold is how a gate ends up enforcing three different things."""
    return count_threshold if metric in _COUNT_METRICS else MISS_THRESHOLD


#: Miss-count threshold.  Zero, and that is measured rather than aspirational:
#: across all fourteen targets at gcc 13 -O3 and clang 18 -O3, every
#: cross-class miss delta and every same-class noise floor is exactly 0.  (An
#: earlier revision of this note said "all ten targets" and cited ecdsa as
#: "the one target with a legitimate public-data spread ... 24 instructions
#: and 8 data references".  Both were stale: the inventory is thirteen, and
#: ecdsa's spread went to zero when the target moved to
#: `ama_secp256k1_ecdsa_sign_raw`.)  A non-zero delta here means the two
#: classes walked different addresses, which is the finding this metric exists
#: to make — so there is no benign band to reserve.
MISS_THRESHOLD = 0


def _dispatch_wiring(driver: Path) -> list[str]:
    """The kernel wiring these counts were taken against, as the library reports it.

    A count is only evidence about the code it actually executed.  Because the
    dispatch table picks between a SIMD and a scalar kernel for the same slot,
    a report that does not name the wiring leaves the reader unable to tell
    which of the two the delta covers — and before `AMA_DISPATCH_NO_AUTOTUNE`
    was set above, that choice was made by a wall-clock benchmark of whatever
    machine happened to run the gate.  So the wiring is printed beside the
    counts rather than assumed.

    Run UNDER VALGRIND, which is not incidental.  Valgrind emulates CPUID and
    reports only the ISA extensions it implements, so a capability the host has
    and Valgrind does not is invisible to the dispatcher inside the
    measurement.  Measured on an AVX-512 host: natively the library reports
    ``AVX2=1 AVX-512F=1 AVX-512-Keccak=1``, and under callgrind the same binary
    reports ``AVX2=1 AVX-512F=0 AVX-512-Keccak=0``.  This function used to run
    the driver natively and print that first line beside counts taken with the
    second, i.e. it named a wiring the numbers did not cover — the exact defect
    its own docstring says it exists to prevent.

    The consequence is worth stating rather than hiding, because it bounds what
    this gate can claim: with ``-DAMA_ENABLE_AVX512=ON`` the library wires
    ``keccak_f1600_x4`` to the AVX-512 kernel on capable silicon, and no run of
    this tool can execute that kernel.  The report now says so in the wiring
    line instead of leaving the reader to assume otherwise.  (In the shipped
    configuration the question is moot: ``AMA_ENABLE_AVX512`` defaults OFF and
    ``setup.py`` never sets it, so wheels carry the AVX2 4-way kernel that the
    measurement does cover.)

    Best-effort: a driver that cannot report its wiring still produces a valid
    measurement, so a failure here returns nothing rather than failing the
    check.  The counts themselves are what the verdict rests on.
    """
    env = dict(os.environ)
    env["AMA_DISPATCH_NO_AUTOTUNE"] = "1"
    env["AMA_DISPATCH_VERBOSE"] = "1"
    try:
        proc = subprocess.run(
            # --tool=none: the cheapest tool that still runs under Valgrind's
            # CPUID emulation, which is the property that matters here.
            ["valgrind", "--tool=none", str(driver), KEY_CLASSES[0]],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
    except OSError:
        return []
    return [
        line.strip()
        # Valgrind prefixes its own output with "==PID==", so the dispatch
        # lines no longer start the line; match on the tag itself.
        for line in proc.stderr.splitlines()
        if "[AMA Dispatch]" in line and "Auto-tune" not in line
    ]


def _library_is_optimized(lib: Path, cc: str, include: Path, workdir: Path) -> Optional[int]:
    """Whether the library under test was compiled with optimization.

    1 = yes, 0 = no, None = the probe could not be built or run (which
    includes an older library that does not export it).

    This is the guard that makes the whole instrument honest about its
    subject.  Everything these targets look for is a transformation the
    OPTIMIZER performs — see the module docstring, and
    src/c/internal/ama_ct_barrier.h.  At -O0 no such transformation exists to
    find, so every target reports PASS over code that is not the code that
    ships, and the report reads exactly as it would over a clean optimized
    build.  Asking the library removes the assumption from the caller.
    """
    source = workdir / "optprobe.c"
    source.write_text(_OPT_PROBE, encoding="utf-8")
    binary = workdir / "optprobe"
    compile_cmd = [
        cc,
        "-O2",
        str(source),
        f"-I{include}",
        "-o",
        str(binary),
        str(lib),
        "-lpthread",
        "-lm",
    ]
    if ".so" in lib.name or lib.suffix in (".dylib", ".so"):
        compile_cmd.append(f"-Wl,-rpath,{lib.resolve().parent}")
    built = subprocess.run(compile_cmd, capture_output=True, text=True, check=False)
    if built.returncode != 0:
        return None
    proc = subprocess.run([str(binary)], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return None
    try:
        return int(proc.stdout.strip())
    except ValueError:
        return None


def _measure(driver: Path, key_class: str, workdir: Path) -> Optional[dict[str, int]]:
    """The four :data:`_METRICS` for one *successful* run of the driver, else None.

    The exit-status check is load-bearing, not defensive tidiness.  Callgrind
    prints an ``I refs:`` line for any process it supervises, including one
    that never reached ``main`` — and this tool used to accept that line as a
    measurement.  Handing ``--lib`` a shared object rather than the static
    archive produced exactly that: the driver linked, failed at load with
    ``cannot open shared object file``, and every key class returned the same
    ~109,000 instructions of dynamic-loader work.  All four agreed, so the
    delta was zero, and the gate printed ``PASSED — count is key-independent``
    over a program that had not performed a single cryptographic operation.
    It gave that verdict identically for a build carrying two live
    secret-dependent branches and for one with none.

    ``main`` returns 0 only after every crypto call has succeeded and the
    measured loop has run to completion, so the exit status is a precise
    witness that the thing under measurement actually executed.  No arbitrary
    instruction floor is needed on top of it.

    ``AMA_DISPATCH_NO_AUTOTUNE=1`` is not a convenience, and it fixes two
    separate defects in this instrument.

    On its first call into the dispatch table the library runs the SIMD-vs-
    scalar auto-tune: a best-of-N **wall-clock** benchmark of the Keccak,
    Kyber-NTT and Dilithium-NTT kernels.

    First, it destroys the baseline.  Measured here, the auto-tune costs
    6,950,175,736 retired instructions against the 319,561 the same program
    retires with it off — 21,700x — and because its loop counts are driven by
    a clock it is not reproducible: two runs of one driver on one identical
    input differed by 9 instructions, and eight runs of identical inputs spread
    over 27.  That is a wall-clock measurement smuggled into the baseline of a
    check whose whole premise is that it needs neither statistics nor a quiet
    machine, and on a loaded runner it could consume the per-target threshold
    on its own.  With the auto-tune off the count is bit-identical run to run.

    Second, and worse, it chooses the SUBJECT.  On the host this was measured
    on the auto-tune found the SIMD Keccak slower than the scalar one
    (simd=12,724,814 ns vs generic=1,063,456 ns) and reverted the slot — so the
    gate measured ``keccak_f1600 -> scalar (BMI1/BMI2)`` at 19,416 instructions
    per SHA3-256 call.  With the auto-tune off the same program dispatches
    ``keccak_f1600 -> SIMD`` at 146,748.  Which kernel any given run of this
    gate actually tested was therefore decided by a timing measurement on
    whatever machine happened to run it, and was recorded nowhere.

    Disabling the auto-tune pins the subject to the library's default SIMD
    wiring — a fixed, named target rather than a host-dependent one — and the
    report below prints that wiring so the evidence says what it covers.  This
    is a deliberate narrowing: the scalar fallback is NOT covered by these
    counts and must not be claimed as such; ``AMA_DISPATCH_ONLY`` pins
    individual slots for that, and the scalar AES-GCM invariance job in
    dudect.yml covers that path directly.
    """
    env = dict(os.environ)
    env["AMA_DISPATCH_NO_AUTOTUNE"] = "1"
    proc = subprocess.run(
        [
            "valgrind",
            "--tool=callgrind",
            "--cache-sim=yes",
            *_CACHE_GEOMETRY,
            f"--callgrind-out-file={workdir / 'callgrind.out'}",
            str(driver),
            key_class,
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    if proc.returncode != 0:
        print(
            f"  driver exited {proc.returncode} for key class {key_class!r} — "
            "the measured workload did not run to completion.\n"
            f"  {proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else ''}",
            file=sys.stderr,
        )
        return None
    measured: dict[str, int] = {}
    for name, pattern in _METRICS.items():
        match = pattern.search(proc.stderr)
        if match is None:
            # A missing figure is a broken measurement, not a zero.
            return None
        measured[name] = int(match.group(1).replace(",", ""))
    return measured


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--lib",
        required=True,
        type=Path,
        help="Path to libama_cryptography_test.a (the AMA_TESTING_MODE static "
        "library, which exports ama_test_force_aes_gcm_scalar).",
    )
    parser.add_argument(
        "--include",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "include",
        help="Path to the public header directory.",
    )
    parser.add_argument("--cc", default="cc", help="Compiler for the driver.")
    parser.add_argument(
        "--target",
        choices=sorted(_DRIVERS),
        default="ghash",
        help="Which constant-time property to measure.",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=None,
        help="Override the per-target default in THRESHOLDS.",
    )
    args = parser.parse_args(argv)
    if args.threshold is None:
        args.threshold = THRESHOLDS[args.target]

    for tool in ("valgrind", args.cc):
        if shutil.which(tool) is None:
            print(
                f"CONSTANT-TIME CHECK INCONCLUSIVE — {tool!r} is not installed.",
                file=sys.stderr,
            )
            return 2
    if not args.lib.is_file():
        print(
            f"CONSTANT-TIME CHECK INCONCLUSIVE — {args.lib} does not exist.\n"
            "Build it with: cmake -B build -DAMA_USE_NATIVE_PQC=ON -DAMA_BUILD_TESTS=ON",
            file=sys.stderr,
        )
        return 2

    with tempfile.TemporaryDirectory(prefix="ama-ghash-ct-") as tmp:
        workdir = Path(tmp)
        source = workdir / "driver.c"
        source.write_text(_DRIVERS[args.target], encoding="utf-8")
        driver = workdir / "driver"

        compile_cmd = [
            args.cc,
            "-O2",
            str(source),
            f"-I{args.include}",
            "-o",
            str(driver),
            str(args.lib),
            "-lpthread",
            "-lm",
        ]
        # A shared library named on the command line links fine but is not
        # found at load time without an rpath, which is how this check came to
        # report PASS over a driver that never started.  The exit-status check
        # in _measure() now catches that; embedding the rpath means
        # the caller does not hit it in the first place.  CI passes the static
        # archive, for which this is a no-op.
        if ".so" in args.lib.name or args.lib.suffix in (".dylib", ".so"):
            compile_cmd.append(f"-Wl,-rpath,{args.lib.resolve().parent}")
        compiled = subprocess.run(compile_cmd, capture_output=True, text=True, check=False)
        if compiled.returncode != 0:
            print(
                "CONSTANT-TIME CHECK INCONCLUSIVE — the driver did not build.\n"
                f"{' '.join(compile_cmd)}\n{compiled.stderr}",
                file=sys.stderr,
            )
            return 2

        # Refuse to measure an unoptimized library.  This runs BEFORE any
        # measurement, because a verdict from an -O0 build is worse than no
        # verdict: it is indistinguishable, in its own output, from a verdict
        # over the code that ships.
        optimized = _library_is_optimized(args.lib, args.cc, args.include, workdir)
        if optimized != 1:
            reason = {
                0: (
                    "the library was compiled WITHOUT optimization "
                    "(`__OPTIMIZE__` is not defined in it)."
                ),
                None: (
                    "the library does not export ama_build_optimization_probe(), "
                    "so its optimization level could not be established. Rebuild "
                    "the AMA_TESTING_MODE archive from this tree."
                ),
                -1: (
                    "the compiler that built the library does not report an "
                    "optimization level, so it could not be established."
                ),
            }[optimized]
            print(
                f"CONSTANT-TIME CHECK INCONCLUSIVE — {reason}\n"
                "Every target here looks for a transformation the OPTIMIZER "
                "makes; at -O0 there is none to find and a PASS would mean "
                "nothing. Configure with an optimizing build type, e.g.\n"
                "  cmake -B build -DCMAKE_BUILD_TYPE=Release "
                "-DAMA_USE_NATIVE_PQC=ON -DAMA_BUILD_TESTS=ON -DAMA_ENABLE_LTO=OFF\n"
                "(this project sets no default CMAKE_BUILD_TYPE for a bare "
                "configure, so omitting it yields no -O flag at all).",
                file=sys.stderr,
            )
            return 2

        # The wiring these counts will be taken against, captured while the
        # driver still exists — the report below runs after this temporary
        # directory is gone.
        wiring = _dispatch_wiring(driver)

        # Noise floor first: the same key twice.  If the environment cannot
        # even reproduce itself to within the threshold, no verdict about a
        # smaller effect would mean anything.
        floor_a = _measure(driver, KEY_CLASSES[0], workdir)
        floor_b = _measure(driver, KEY_CLASSES[0], workdir)
        if floor_a is None or floor_b is None:
            print(
                "CONSTANT-TIME CHECK INCONCLUSIVE — callgrind produced no measurement.",
                file=sys.stderr,
            )
            return 2
        floors = {name: abs(floor_a[name] - floor_b[name]) for name in _METRICS}
        for name, value in floors.items():
            limit = args.threshold if name in _COUNT_METRICS else MISS_THRESHOLD
            if value > limit:
                print(
                    f"CONSTANT-TIME CHECK INCONCLUSIVE — the same key twice "
                    f"differed by {value} in {name!r}, above the {limit} "
                    f"threshold. The measurement cannot resolve the effect it "
                    f"is looking for.",
                    file=sys.stderr,
                )
                return 2

        measured: dict[str, dict[str, int]] = {KEY_CLASSES[0]: floor_a}
        for key_class in KEY_CLASSES[1:]:
            one = _measure(driver, key_class, workdir)
            if one is None:
                print(
                    "CONSTANT-TIME CHECK INCONCLUSIVE — callgrind produced "
                    f"no measurement for key class {key_class!r}.",
                    file=sys.stderr,
                )
                return 2
            measured[key_class] = one

        # Close the floor at the END of the sweep as well as the start.
        #
        # The floor above establishes that the instrument could reproduce
        # itself at the moment the sweep began.  It says nothing about the
        # moment it ended, and the sweep is one process per class in strict
        # order — so any one-time cost that falls away after the first few
        # processes (a cache directory created on first use, a page-cache warm
        # up, an ASLR layout that changes the simulated cache sets) lands
        # entirely on the classes measured first and reads as a cross-class
        # delta.  That is not hypothetical: on this tree, with every threshold
        # at 0, a run of `--target aead-verify` reported 456 I refs of
        # "key-dependent measurement" whose split followed the ORDER of
        # measurement (the first three high, the last six low) and not the
        # accept/reject split the driver actually varies — 1 false FAIL in 6
        # runs, on a tree whose driver, compiled standalone and run 24 times,
        # showed zero variance.
        #
        # Re-measuring class 0 last turns that from an invisible bias into a
        # visible number: `drift` is the same-class difference across the whole
        # sweep, printed in the report next to `floor`.
        floor_c = _measure(driver, KEY_CLASSES[0], workdir)
        if floor_c is None:
            print(
                "CONSTANT-TIME CHECK INCONCLUSIVE — callgrind produced no "
                "closing floor measurement.",
                file=sys.stderr,
            )
            return 2
        drift = {name: abs(floor_c[name] - floor_a[name]) for name in _METRICS}

        # Decide provisionally, then CONFIRM before failing.
        #
        # A real leak is deterministic under callgrind: the same driver, the
        # same inputs and the same simulated cache produce the same counts, so
        # it reproduces in any order.  An artefact of measurement order does
        # not.  Only a breach pays for the second sweep, so a green run costs
        # exactly what it did before.
        baseline_1 = measured[KEY_CLASSES[0]]
        worst_1 = {
            name: max(abs(values[name] - baseline_1[name]) for values in measured.values())
            for name in _METRICS
        }
        breached_1 = [name for name in _METRICS if worst_1[name] > _limit_for(name, args.threshold)]

        confirm: Optional[dict[str, dict[str, int]]] = None
        breached_2: list[str] = []
        if breached_1:
            confirm = {}
            for key_class in reversed(KEY_CLASSES):
                one = _measure(driver, key_class, workdir)
                if one is None:
                    print(
                        "CONSTANT-TIME CHECK INCONCLUSIVE — callgrind produced "
                        f"no confirmation measurement for key class {key_class!r}.",
                        file=sys.stderr,
                    )
                    return 2
                confirm[key_class] = one
            baseline_2 = confirm[KEY_CLASSES[0]]
            worst_2 = {
                name: max(abs(values[name] - baseline_2[name]) for values in confirm.values())
                for name in _METRICS
            }
            breached_2 = [
                name for name in _METRICS if worst_2[name] > _limit_for(name, args.threshold)
            ]

    print(f"[{args.target}] deterministic measurements by key class:")
    for line in wiring:
        print(f"  wiring: {line}")
    if not wiring:
        print("  wiring: no dispatch table involved (scalar-only implementation)")
    print("  cache geometry: " + " ".join(flag.lstrip("-") for flag in _CACHE_GEOMETRY))
    header = "  key    " + "".join(f"{name:>16s}" for name in _METRICS)
    print(header)
    for key_class, values in measured.items():
        row = "".join(f"{values[name]:>16,d}" for name in _METRICS)
        print(f"  0x{ord(key_class):02x}   {row}")

    worst = worst_1
    print("  floor  " + "".join(f"{floors[name]:>16,d}" for name in _METRICS))
    print("  drift  " + "".join(f"{drift[name]:>16,d}" for name in _METRICS))
    print("  worst  " + "".join(f"{worst[name]:>16,d}" for name in _METRICS))
    print("  limit  " + "".join(f"{_limit_for(name, args.threshold):>16,d}" for name in _METRICS))

    if confirm is not None:
        print("\n  confirmation sweep (classes measured in reverse order):")
        for key_class in KEY_CLASSES:
            row = "".join(f"{confirm[key_class][name]:>16,d}" for name in _METRICS)
            print(f"  0x{ord(key_class):02x}   {row}")

    breached = breached_1
    if breached and sorted(breached_2) != sorted(breached_1):
        # The two sweeps disagree about WHICH metrics carry a key-dependent
        # delta.  A leak is deterministic under callgrind, so it cannot appear
        # in one ordering and vanish in the other; a measurement-order artefact
        # can and does.  Classify rather than collapse — the same rule the
        # dudect verdict logic applies to a sign-flipping t-statistic.  Both
        # outcomes still stop the run; what changes is the diagnosis, and that
        # a clean tree is no longer told it has a leak.
        print(
            f"\n{args.target.upper()} CONSTANT-TIME CHECK INCONCLUSIVE — the two "
            f"sweeps disagree.\n"
            f"  forward sweep breached: {', '.join(breached_1) or 'nothing'}\n"
            f"  reverse sweep breached: {', '.join(breached_2) or 'nothing'}\n"
            f"  same-class drift across the sweep: "
            + ", ".join(f"{name}={drift[name]:,}" for name in _METRICS)
            + "\n"
            "A key-dependent measurement is deterministic under callgrind and "
            "reproduces in either order; a delta that follows the ORDER of "
            "measurement does not. Re-run on a quiet host. If it persists, the "
            "instrument — not the library — is what to fix.",
            file=sys.stderr,
        )
        return 2

    if breached:
        detail = ", ".join(f"{name} by {worst[name]:,}" for name in breached)
        print(
            f"\n{args.target.upper()} CONSTANT-TIME CHECK FAILED — a key-dependent "
            f"measurement was taken ({detail}), reproduced in a second sweep with "
            f"the classes in reverse order.\n"
            + (
                "A data-reference or cache-miss delta with an unchanged instruction "
                "count is a secret-dependent memory ACCESS rather than a branch: "
                "look for an index derived from the secret, not for a jump.\n"
                if "I refs" not in breached
                else ""
            )
            + _REMEDY[args.target],
            file=sys.stderr,
        )
        return 1

    print(
        f"\n{args.target.upper()} CONSTANT-TIME CHECK PASSED — instruction count, "
        "data references and cache misses are all key-independent."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
