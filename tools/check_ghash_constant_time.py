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
import os
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
    # Ascon-AEAD128 encryption is the same permutation over a fixed schedule,
    # keyed: no table, no key-dependent branch (ama_ascon.c), so the count is
    # invariant by construction and there is no benign spread to discount.
    "ascon-encrypt": 200,
    # ama_agent_binding_check compares the authorization with
    # ama_consttime_memcmp and returns a masked verdict; accept and reject
    # therefore execute the same instructions, and any spread is a real
    # verdict oracle rather than a benign one.
    "agent-binding": 200,
    # ML-KEM decapsulation computes both the real and the rejection shared
    # secret and selects between them with ama_consttime_copy, so the two FO
    # outcomes execute the same instructions; there is no benign spread.
    "kyber-decaps": 200,
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
 * The deterministic answer, measured over 60 decapsulations per class:
 *
 *     retired instructions   323,766,461   identical, valid vs rejected
 *     data memory accesses   168,506,025   identical
 *     L1 data cache misses         2,651   identical
 *
 * All three are byte-identical across the two classes and reproducible across
 * runs.  Retired instructions rule out a branch or any skipped computation; the
 * cache figures rule out a secret-dependent memory access, which an instruction
 * count alone cannot see.  A decapsulation here is about 5.4 million
 * instructions, so the 5.630 ns wall-clock difference is roughly one part in
 * 90,000 — accumulated data-operand-dependent latency across millions of
 * multiplies, which is what Intel's DOITM and ARM's PSTATE.DIT exist to control,
 * and not a property of src/c/ama_kyber.c.
 *
 * THE STAGING BELOW IS LOAD-BEARING.  Handing the timed call `ct` for one class
 * and `ct_bad` for the other confounds the class with the ciphertext's ADDRESS:
 * measured that way this same driver reported 3,516 L1 misses for the valid
 * class against 3,870 for the rejected one, perfectly reproducibly — a 354-miss
 * "finding" that belongs entirely to the driver.  Copying the selected
 * ciphertext into one aligned buffer first collapses it to zero.  This is the
 * same defect tools/check_dudect_class_staging.py enforces against in the
 * wall-clock harnesses; a driver for a constant-time check has to be constant-time
 * too. */
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
}


_IREFS = re.compile(r"I\s+refs:\s+([\d,]+)")


def _dispatch_wiring(driver: Path) -> list[str]:
    """The kernel wiring these counts were taken against, as the library reports it.

    A count is only evidence about the code it actually executed.  Because the
    dispatch table picks between a SIMD and a scalar kernel for the same slot,
    a report that does not name the wiring leaves the reader unable to tell
    which of the two the delta covers — and before `AMA_DISPATCH_NO_AUTOTUNE`
    was set above, that choice was made by a wall-clock benchmark of whatever
    machine happened to run the gate.  So the wiring is printed beside the
    counts rather than assumed.

    Best-effort: a driver that cannot report its wiring still produces a valid
    measurement, so a failure here returns nothing rather than failing the
    check.  The counts themselves are what the verdict rests on.
    """
    env = dict(os.environ)
    env["AMA_DISPATCH_NO_AUTOTUNE"] = "1"
    env["AMA_DISPATCH_VERBOSE"] = "1"
    try:
        proc = subprocess.run(
            [str(driver), KEY_CLASSES[0]],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
    except OSError:
        return []
    return [
        line.strip()
        for line in proc.stderr.splitlines()
        if line.startswith("[AMA Dispatch]") and "Auto-tune" not in line
    ]


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

        # The wiring these counts will be taken against, captured while the
        # driver still exists — the report below runs after this temporary
        # directory is gone.
        wiring = _dispatch_wiring(driver)

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
    for line in wiring:
        print(f"  wiring: {line}")
    if not wiring:
        print("  wiring: no dispatch table involved (scalar-only implementation)")
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
