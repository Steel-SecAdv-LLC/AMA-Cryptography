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

The default threshold of 200 sits an order of magnitude above the noise and
an order of magnitude below the defect, so it is not tuned to either.

Exit status
-----------
``0`` invariant holds, ``1`` a key-dependent instruction count was measured,
``2`` the check could not run (missing valgrind, compiler, or library, or a
noise floor so high the comparison would be meaningless).  As elsewhere in
``tools/``, an unrunnable check is never reported as a passing one.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, Sequence

#: Instruction-count delta above which a key-dependent path is reported.
DEFAULT_THRESHOLD = 200

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
#: ecdsa: secp256k1 signing has one *legitimate* variable-time step — DER
#: encoding of r and s, whose leading-zero handling depends on the signature
#: values.  Those are public: the verifier receives them.
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
#: fixed (shipped)                                80
#: ==========================================  ==================
#:
#: The old threshold of 3,000 therefore sat **48 instructions above the
#: defect it was measuring**.  It was never going to fire.  200 sits 2.5x
#: above the benign floor and ~15x below the defect.
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
#: buffer. There is no benign spread to accommodate, so the shared 200 is pure
#: headroom.
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
THRESHOLDS = {
    "ghash": 200,
    "ecdsa": 200,
    "consttime": 200,
    "aead-verify": 200,
    # Ascon has no lookup table and no data-dependent branch (ama_ascon.c),
    # so like `consttime` this count is invariant by construction and there is
    # no benign spread to discount.
    "ascon-hash": 200,
    # Keccak-f[1600] is table-free and branch-free (ama_sha3.c); like
    # `consttime` and `ascon-hash` the count is invariant by construction.
    "sha3-256": 200,
    # Ed25519 signing is a fixed-window comb over the base point plus a
    # branchless SHA-512; for a fixed message the count is a pure function of
    # the key, and constant-time signing means that function is constant.
    "ed25519-sign": 200,
}

#: Where to look first when a target fails.  Kept per-target so the message
#: names the code that is actually implicated rather than a generic pointer.
_REMEDY = {
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
        "conditional jump. DER encoding of r and s is legitimately variable on\n"
        "public data, but with the driver consuming a fixed byte count that\n"
        "accounts for only ~24 instructions — not hundreds."
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
    uint8_t sk[32], pk[33], sig[80], msg[32];
    size_t siglen;
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
        /* Clear the whole buffer so the bytes past the signature are
         * deterministic, then consume a FIXED count below. */
        memset(sig, 0, sizeof sig);
        siglen = sizeof sig;
        if (ama_secp256k1_ecdsa_sign(sig, &siglen, msg, sk) != AMA_SUCCESS) return 1;
        /* Iterating to `siglen` would make the *driver* variable-time on the
         * DER length.  That length is public, but it put ~9 instructions per
         * byte of avoidable variance into the measurement, and a threshold
         * padded to tolerate it is a threshold with room for a real leak
         * underneath.  Consuming a fixed 80 bytes removes the term entirely
         * and leaves only der_encode_signature's own public-data-dependent
         * work, which is what drops the benign spread to single digits. */
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
 * 500-instruction cross-class delta — 2.5x the 200 threshold and ~25x
 * the measured same-class floor — while keeping the 10-run check
 * inside the ARM job's budget under valgrind. */
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

_DRIVERS = {
    "ghash": _DRIVER,
    "ecdsa": _ECDSA_DRIVER,
    "consttime": _CONSTTIME_DRIVER,
    "aead-verify": _AEAD_VERIFY_DRIVER,
    "ascon-hash": _ASCON_HASH_DRIVER,
    "sha3-256": _SHA3_256_DRIVER,
    "ed25519-sign": _ED25519_SIGN_DRIVER,
}


_IREFS = re.compile(r"I\s+refs:\s+([\d,]+)")


def _instruction_count(driver: Path, key_class: str, workdir: Path) -> Optional[int]:
    """Retired instructions for one *successful* run of the driver, else None.

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
    """
    proc = subprocess.run(
        [
            "valgrind",
            "--tool=callgrind",
            f"--callgrind-out-file={workdir / 'callgrind.out'}",
            str(driver),
            key_class,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        print(
            f"  driver exited {proc.returncode} for key class {key_class!r} — "
            "the measured workload did not run to completion.\n"
            f"  {proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else ''}",
            file=sys.stderr,
        )
        return None
    match = _IREFS.search(proc.stderr)
    if match is None:
        return None
    return int(match.group(1).replace(",", ""))


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
        # in _instruction_count() now catches that; embedding the rpath means
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

        # Noise floor first: the same key twice.  If the environment cannot
        # even reproduce itself to within the threshold, no verdict about a
        # smaller effect would mean anything.
        floor_a = _instruction_count(driver, KEY_CLASSES[0], workdir)
        floor_b = _instruction_count(driver, KEY_CLASSES[0], workdir)
        if floor_a is None or floor_b is None:
            print(
                "CONSTANT-TIME CHECK INCONCLUSIVE — callgrind produced no " "instruction count.",
                file=sys.stderr,
            )
            return 2
        floor = abs(floor_a - floor_b)
        if floor > args.threshold:
            print(
                f"CONSTANT-TIME CHECK INCONCLUSIVE — the same key twice "
                f"differed by {floor} instructions, at or above the "
                f"{args.threshold}-instruction threshold. The measurement cannot "
                f"resolve the effect it is looking for.",
                file=sys.stderr,
            )
            return 2

        counts: dict[str, int] = {KEY_CLASSES[0]: floor_a}
        for key_class in KEY_CLASSES[1:]:
            count = _instruction_count(driver, key_class, workdir)
            if count is None:
                print(
                    "CONSTANT-TIME CHECK INCONCLUSIVE — callgrind produced "
                    f"no instruction count for key class {key_class!r}.",
                    file=sys.stderr,
                )
                return 2
            counts[key_class] = count

    print(f"[{args.target}] retired-instruction counts by key class:")
    for key_class, count in counts.items():
        print(f"  key=0x{ord(key_class):02x}  {count:,}")
    print(f"  noise floor (same key, two runs): {floor} instruction(s)")

    baseline = counts[KEY_CLASSES[0]]
    worst = max(abs(count - baseline) for count in counts.values())
    print(f"  worst cross-key delta:            {worst} instruction(s)")
    print(f"  threshold:                        {args.threshold} instruction(s)")

    if worst > args.threshold:
        print(
            f"\n{args.target.upper()} CONSTANT-TIME CHECK FAILED — a key-dependent "
            f"instruction count was measured.\n{_REMEDY[args.target]}",
            file=sys.stderr,
        )
        return 1

    print(f"\n{args.target.upper()} CONSTANT-TIME CHECK PASSED — count is key-independent.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
