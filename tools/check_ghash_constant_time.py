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
prove the mask is ``0x00``-or-``0xFF``, recognise the loop as the identity
in the ``0x00`` case, and emit a branch over it — putting a branch back on a
bit of the running accumulator, which is a function of the secret ``H`` from
the second block onward.  clang 18 at ``-O2``/``-O3`` did exactly that; gcc
13 did not.  Both builds pass every functional test, because the *results*
are identical.  Only the emitted control flow differs, so only a check that
looks at execution rather than at output can see it.

The source-level defence is ``ama_ct_value_barrier_u8`` (see
``src/c/internal/ama_ct_barrier.h``).  This gate is what stops the defence
from being silently removed, or from being defeated by a compiler nobody has
tried yet.

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
KEY_CLASSES = ("A", "Z", "m", "q")

#: Per-target instruction-count threshold.
#:
#: ghash: the scalar AES-GCM path is deterministic end to end, so anything
#: above process noise is a defect.  Calibration in the module docstring.
#:
#: ecdsa: secp256k1 signing has one *legitimate* variable-time step — DER
#: encoding of r and s, whose leading-zero handling depends on the signature
#: values.  Those are public: the verifier receives them.  Measured over eight
#: keys the benign spread is 728 instructions and falls into exactly four
#: discrete levels (2x2: r and s each needing a leading 0x00 pad or not),
#: which is what confirms the attribution.  The Montgomery extra-reduction
#: leak this gate exists to catch measured 33,354.  3,000 sits 4x above the
#: benign spread and 11x below the defect, so it is tuned to neither.
THRESHOLDS = {"ghash": 200, "ecdsa": 3000}

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
        "The usual cause is a branch on a secret in the scalar field arithmetic\n"
        "of src/c/ama_secp256k1.c — classically the Montgomery extra-reduction\n"
        "predicate in sc_mont_mul, which must stay masked rather than branched.\n"
        "Disassemble sc_mont_mul and look for a conditional jump. Note that DER\n"
        "encoding of r and s is legitimately variable-time on public data and\n"
        "accounts for a benign spread of a few hundred instructions."
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

    memset(key, (int)fill, sizeof key);
    memset(nonce, 0, sizeof nonce);
    memset(pt, 0, sizeof pt);
    memset(aad, 0, sizeof aad);

    ama_test_force_aes_gcm_scalar();

    for (int i = 0; i < 8; i++) {
        ama_aes256_gcm_encrypt(key, nonce, pt, sizeof pt,
                               aad, sizeof aad, ct, tag);
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
 * The property under test is the Montgomery multiplication in the scalar
 * field: written with a branch on the extra-reduction predicate it leaks
 * both the long-term key and, worse, the per-signature nonce.  RFC 6979
 * makes signing deterministic, so with a fixed message the only input that
 * moves is the key and the count is reproducible to the instruction. */
int main(int argc, char **argv) {
    uint8_t sk[32], pk[33], sig[80], msg[32];
    size_t siglen;
    unsigned fill = (argc > 1) ? (unsigned)(unsigned char)argv[1][0] : 0x41u;

    memset(sk, (int)fill, sizeof sk);
    memset(msg, 0x11, sizeof msg);
    if (ama_secp256k1_pubkey_from_privkey(sk, pk) != AMA_SUCCESS) return 1;

    static volatile uint8_t sink;
    for (int i = 0; i < 8; i++) {
        siglen = sizeof sig;
        if (ama_secp256k1_ecdsa_sign(sig, &siglen, msg, sk) != AMA_SUCCESS) return 1;
        for (size_t j = 0; j < siglen; j++) sink = (uint8_t)(sink ^ sig[j]);
    }
    return 0;
}
"""

_DRIVERS = {"ghash": _DRIVER, "ecdsa": _ECDSA_DRIVER}


_IREFS = re.compile(r"I\s+refs:\s+([\d,]+)")


def _instruction_count(driver: Path, key_class: str, workdir: Path) -> Optional[int]:
    """Retired instructions for one run of the driver, or None on failure."""
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
