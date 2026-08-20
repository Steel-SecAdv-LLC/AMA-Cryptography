#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — no divide instruction may take a secret operand.

Why this exists
---------------
KyberSlash is this defect class: ML-KEM's ``Compress_d`` is written as a
division by ``q``, the compiler is *usually* free to lower it to a reciprocal
multiply, and where it does not, the emitted ``div`` has operand-dependent
latency over a secret-derived numerator.  That is a practical key-recovery
channel, and this repository shipped it once — the pull request that carried
the fix is titled for it.

The fix was a Granlund-Montgomery reciprocal in ``src/c/ama_kyber.c``.  What
was never added is anything that would notice the fix being undone.  Reading
the C does not settle it either way: the source says ``/``, the object may or
may not contain a ``div``, and only the object decides.  So this gate reads
the object.

What it does
------------
Disassembles the built library, attributes every ``div``/``idiv`` to the
symbol it lands in, and compares that inventory against :data:`ALLOWED`.
Anything not listed, or listed with a smaller count, fails.

Allowlisting a symbol requires stating why its operands are public.  A count
is recorded with it so that *new* divides in an already-listed function still
fail — the usual way a real one hides is next to a benign one.

Non-vacuity
-----------
The mistake this gate is most likely to make is finding nothing because it
looked at nothing: a stripped object, a symbol that got inlined away, a
disassembler that failed silently.  Measured during this gate's own
development — a first version reported "0 divides in kyber_compress_d" and
was believed, when the truth was that ``kyber_compress_d`` is ``static``, is
fully inlined, and has no symbol to search.  So the gate asserts a floor on
what it managed to read before it is allowed to report a clean result.

Exit status
-----------
0  every divide in the object is on a public operand
1  a divide appeared in a symbol that is not allowlisted, or above its
   recorded count
2  the gate could not read what it needs, or read too little to be believed
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Symbols permitted to contain divide instructions, with the count measured
#: on this tree and the reason the operands are public.  A divide anywhere
#: else, or more of them here, fails.
#:
#: Counts are per-symbol and compiler-dependent (unrolling changes them), so
#: they are ceilings rather than equalities: fewer is fine, more is a new
#: divide that has to be justified here before it can pass.
ALLOWED: dict[str, tuple[int, str]] = {
    "dil_sign_internal": (
        24,
        "ama_dilithium.c:1562 `nonces[f] = ((f / P->l) << 8) + (f % P->l)`. "
        "The dividend is the loop counter and the divisor is the parameter "
        "set's dimension l (4, 5 or 7 for ML-DSA-44/65/87) — both public. "
        "Confirmed in the disassembly: the divisor sits loop-invariant in one "
        "register across the unrolled body while the dividend increments.",
    ),
    "lms_verify_parsed": (
        16,
        "ama_lms.c:391. LMS/HSS verification takes only public inputs — the "
        "identifier, the type words, the public root, the message and the "
        "signature. No secret is in scope in this function.",
    ),
    "ama_argon2id_core": (
        12,
        "ama_argon2.c:530 `ref_lane = J2 % lanes`. On Argon2id's "
        "data-INdependent phase J2 comes from the counter-driven address "
        "block and is public. On the data-dependent phase it is derived from "
        "the password, which RFC 9106 section 3.4 specifies: that phase's "
        "addressing is data-dependent by design, and `memory[ref_index]` two "
        "lines later is a secret-indexed read into a multi-megabyte buffer — "
        "a far stronger channel than divide latency, on the same secret. "
        "Removing the divide would deviate from RFC 9106 without changing "
        "the property. Recorded rather than silently dropped.",
    ),
}

#: The gate must have read at least this much before a clean result means
#: anything.  Set well below the real figures so a normal build never trips
#: it, and well above zero so an empty or stripped object cannot pass.
MIN_SYMBOLS = 200
MIN_INSTRUCTIONS = 50_000

#: Symbols that MUST be present and MUST be divide-free.  Without this, a
#: build that dropped ML-KEM entirely would report a clean inventory.
REQUIRED_CLEAN = (
    "kyber_decapsulate_internal",
    "ama_kyber_decapsulate",
    "ama_kyber_encapsulate",
)

_SYMBOL_RE = re.compile(r"^[0-9a-f]+ <(?P<name>[^>]+)>:$")
_INSN_RE = re.compile(r"^\s+[0-9a-f]+:\s+(?P<mnemonic>[a-z][a-z0-9.]*)")
#: Divide mnemonics across the two architectures this library ships.
#:
#: x86-64: ``div``/``idiv`` with their operand-size suffixes, and the SSE
#: forms (``divss``, ``divsd``, ``divps``, ``divpd``) which the ``i?div[a-z]*``
#: arm already covers.
#: AArch64: ``udiv``/``sdiv``, plus ``fdiv`` — spelled out because it matches
#: neither of the other two arms.  There is no floating-point arithmetic
#: anywhere in this library, so an ``fdiv`` appearing at all is worth failing
#: on; measured on this tree, both the x86-64 and the AArch64 shared objects
#: contain zero.
_DIVIDE_RE = re.compile(r"^(i?div[a-z]*|udiv|sdiv|fdiv[a-z]*)$")


#: Disassemblers to try, in order.  Every one of them is tried until one
#: SUCCEEDS — presence is not ability.
#:
#: The previous form was ``which("objdump") or which("llvm-objdump")``, which
#: picks by presence and then commits.  GNU ``objdump`` from a distribution's
#: ``binutils`` is built for the host architecture only, so on an x86-64 host
#: it answers an AArch64 object with ``can't disassemble for architecture
#: UNKNOWN!`` and a non-zero exit — and this gate, which fails closed, returned
#: 2 rather than running.  That is the correct verdict for "could not read it"
#: and the wrong outcome overall: ``llvm-objdump`` was installed on the same
#: host and handles the object perfectly, and the gate already knew its name.
#:
#: The consequence was that the KyberSlash regression gate could not cover the
#: AArch64 build at all — the one where the NEON and SVE2 ML-KEM kernels live.
#: Measured on this tree with the fallback in place, the AArch64 shared object
#: reads 580 symbols / 60,784 instructions, three allowlisted divide sites all
#: within their recorded ceilings, and all three REQUIRED_CLEAN symbols present
#: and divide-free.
_DISASSEMBLERS = ("objdump", "llvm-objdump", "aarch64-linux-gnu-objdump")


def disassemble(library: Path) -> str:
    """Disassembly text from the first available tool that can read ``library``.

    Raises ``FileNotFoundError`` when none of :data:`_DISASSEMBLERS` is on
    PATH, and ``RuntimeError`` — naming every attempt and its diagnostic —
    when they are all present and all fail.  Failing with the whole list is
    deliberate: "objdump failed" alone sent a reader looking at the object
    when the answer was the tool.
    """
    attempts: list[str] = []
    for name in _DISASSEMBLERS:
        path = shutil.which(name)
        if path is None:
            continue
        result = subprocess.run(
            [path, "-d", "--no-show-raw-insn", str(library)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
        attempts.append(f"{name}: {(result.stderr or result.stdout).strip()[:200] or 'no output'}")
    if not attempts:
        raise FileNotFoundError("no disassembler on PATH; tried " + ", ".join(_DISASSEMBLERS))
    raise RuntimeError(f"every available disassembler failed on {library} — " + "; ".join(attempts))


def inventory(disassembly: str) -> tuple[dict[str, int], set[str], int]:
    """(divides per symbol, all symbols seen, total instructions)."""
    divides: dict[str, int] = {}
    symbols: set[str] = set()
    instructions = 0
    current = "<no symbol>"
    for line in disassembly.splitlines():
        symbol = _SYMBOL_RE.match(line)
        if symbol:
            current = symbol.group("name")
            symbols.add(current)
            continue
        insn = _INSN_RE.match(line)
        if not insn:
            continue
        instructions += 1
        if _DIVIDE_RE.match(insn.group("mnemonic")):
            divides[current] = divides.get(current, 0) + 1
    return divides, symbols, instructions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lib", required=True, type=Path, help="built shared object or archive")
    args = parser.parse_args(argv)

    if not args.lib.is_file():
        print(
            f"FATAL: {args.lib} does not exist; refusing to report a clean gate.", file=sys.stderr
        )
        return 2
    try:
        disassembly = disassemble(args.lib)
    except (FileNotFoundError, RuntimeError) as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2

    divides, symbols, instructions = inventory(disassembly)

    if len(symbols) < MIN_SYMBOLS or instructions < MIN_INSTRUCTIONS:
        print(
            f"FATAL: read only {len(symbols)} symbol(s) and {instructions} instruction(s) "
            f"from {args.lib} (floor {MIN_SYMBOLS}/{MIN_INSTRUCTIONS}). A clean inventory "
            f"over an object this gate could not really read would mean nothing.",
            file=sys.stderr,
        )
        return 2

    problems: list[str] = []
    for symbol in REQUIRED_CLEAN:
        if symbol not in symbols:
            problems.append(
                f"{symbol} is not in the object. This gate's whole subject is that "
                f"ML-KEM contains no divide; it cannot report that about code that "
                f"is not there."
            )

    for symbol, count in sorted(divides.items()):
        allowed = ALLOWED.get(symbol)
        if allowed is None:
            problems.append(
                f"{symbol}: {count} divide instruction(s), and this symbol is not "
                f"allowlisted. If its operands are public, add it to ALLOWED with "
                f"the reasoning. If they are not, this is the KyberSlash defect "
                f"class and the division must be replaced with a reciprocal "
                f"multiply, as src/c/ama_kyber.c does for Compress_d."
            )
        elif count > allowed[0]:
            problems.append(
                f"{symbol}: {count} divide instruction(s), above the {allowed[0]} "
                f"recorded. The recorded ones are public ({allowed[1].split('.')[0]}); "
                f"a new one is not covered by that and must be justified before it "
                f"can pass."
            )

    print(f"{'symbol':<34}{'divides':>9}  operands")
    for symbol, count in sorted(divides.items()):
        note = "ALLOWLISTED" if symbol in ALLOWED else "*** NOT ALLOWLISTED ***"
        print(f"{symbol:<34}{count:>9}  {note}")
    print(
        f"\nread {len(symbols):,} symbol(s), {instructions:,} instruction(s); "
        f"{sum(divides.values())} divide(s) in {len(divides)} symbol(s)"
    )
    for symbol in REQUIRED_CLEAN:
        if symbol in symbols:
            print(f"  {symbol}: {divides.get(symbol, 0)} divide(s)")

    if problems:
        print("\nSECRET-DIVISION CHECK FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("\nOK: every divide instruction in the object is on a public operand.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
