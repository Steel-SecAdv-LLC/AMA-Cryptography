#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""AVX2/AVX-512 vector instructions must stay inside their dedicated kernels.

Why this gate exists
--------------------
Audit M3.  Of the three principal findings in the SIMD-scoping work, two shipped
with a regression gate and one did not.  KyberSlash got ``check_secret_division.py``,
which disassembles the built object.  The SVE2 kernels got the ``arm-qemu-sve2``
lane.  The AVX2-scoping fix -- confining ``-mavx2`` to the ``src/c/avx2``
translation units instead of applying it library-wide -- got a CMake comment.

That fix is real and load-bearing: with a global ``-mavx2`` the compiler
auto-vectorises the *entire* library with 256-bit YMM instructions, so a build
selects AVX2 code at run time on a CPU that may not have it -- the #UD-on-a-
non-AVX2-host failure mode the per-file scoping exists to prevent.  Reintroducing
global ``-mavx2`` builds clean and passes the functional suite; nothing kept the
property holding.  This gate does.

What it enforces
----------------
It disassembles the built object, records every symbol whose body contains a
YMM or ZMM register operand, and fails on any such symbol that is not
AVX2/AVX-512 kernel code.  A symbol is kernel code when

  * its name carries the ``_avx2`` / ``_avx512`` marker every kernel entry in
    ``src/c/avx2`` and ``src/c/avx512`` uses (including the ``.part`` /
    ``.constprop`` / ``.isra`` fragments the compiler splits them into), or
  * it is one of the file-local helpers in :data:`ALLOWED_NON_SUFFIXED`, each
    of which is defined in one of those directories but not named for it.

A YMM/ZMM operand anywhere else is the global-``-mavx2`` regression: a symbol
that is not a kernel has been given 256/512-bit vector code, so the object now
runs AVX2 on paths the dispatcher never gated on a CPUID check.

Exit status
-----------
0  every YMM/ZMM operand lives in AVX2/AVX-512 kernel code
1  a non-kernel symbol carries a YMM/ZMM operand, OR a required kernel symbol
   is missing or carries none (the AVX2 build this gate exists to check did not
   actually happen)
2  the object could not be read (missing, no disassembler, or below the
   non-vacuity floor) -- a clean result over an object nothing disassembled
   would be a false pass
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Make the `tools` package importable when this file is run as a script
# (`python3 tools/check_avx_scoping.py`, the way CI invokes the sibling gate):
# the script's own directory is on sys.path then, not the repository root, so
# the sibling import below would fail.  Under pytest the root is already on the
# path and this is a no-op.  Same pattern as tools/build_post_kats.py.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# The audit's instruction is to wire this "beside check_secret_division.py,
# which already reads the same object".  Reusing its disassembler keeps the two
# gates reading the object identically -- the multi-disassembler fallback that
# lets the KyberSlash gate cover the AArch64 build applies here unchanged.
from tools.check_secret_division import disassemble  # noqa: E402

#: The gate must have read at least this much before a clean result means
#: anything -- a stripped or truncated object could otherwise pass with zero
#: findings.  Set well below the real figures (a normal x86-64 build reads
#: hundreds of symbols and tens of thousands of instructions) and well above
#: zero.
MIN_SYMBOLS = 200
MIN_INSTRUCTIONS = 50_000

#: Kernel symbols that MUST be present AND MUST carry a vector operand.  Without
#: this the gate would report "no leaks" over a build in which AVX2 was disabled,
#: dropped, or never linked -- the same false pass an empty inventory gives the
#: KyberSlash gate.  These three are the NTTs at the heart of the ML-KEM and
#: ML-DSA AVX2 kernels and the 4-way Keccak permutation; a build with the AVX2
#: path compiled in cannot lack them.
REQUIRED_VECTOR_SYMBOLS = (
    "ama_kyber_ntt_avx2",
    "ama_dilithium_ntt_avx2",
    "ama_keccak_f1600_x4_avx2",
)

#: File-local helpers that carry YMM but are not named for their kernel, each
#: defined in a src/c/avx2 or src/c/avx512 translation unit (grep the name to
#: confirm).  Allowlisting a symbol here is the statement "this vector code is
#: in a scoped kernel TU even though its name does not say so"; a new bare name
#: fails the gate until it is either renamed to the marker or justified here.
ALLOWED_NON_SUFFIXED = {
    "fe_mul_x4": "4-way field multiply, static in src/c/avx2/ama_x25519_avx2.c",
    "fe25519_10_contract": "field contraction, static in src/c/avx2/ama_x25519_avx2.c",
}

#: Kernel-name marker.  Matches ``ama_kyber_ntt_avx2`` and the compiler's
#: ``ama_sphincs_wots_chain_avx2.part.0`` / ``...avx512.constprop.0`` splits: the
#: marker is followed by end-of-string or a ``.`` fragment suffix.
_KERNEL_MARKER_RE = re.compile(r"_avx(?:2|512)(?:\.|$)")

_SYMBOL_RE = re.compile(r"^[0-9a-f]+ <(?P<name>[^>]+)>:$")
_INSN_RE = re.compile(r"^\s+[0-9a-f]+:\s+(?P<body>.*)$")
#: A YMM or ZMM register operand, in either objdump's AT&T (``%ymm3``) or an
#: Intel-syntax (``ymm3``) rendering -- the ``\b`` before the register class
#: matches after the ``%`` (a non-word character) and at a bare word start
#: alike.  XMM is deliberately excluded: 128-bit SSE/AES-NI is baseline x86-64,
#: enabled everywhere, and is not what per-file ``-mavx2`` scopes.
_VECTOR_OPERAND_RE = re.compile(r"\b[yz]mm\d")


def is_kernel_symbol(name: str) -> bool:
    """True when ``name`` is AVX2/AVX-512 kernel code allowed to carry YMM/ZMM."""
    return bool(_KERNEL_MARKER_RE.search(name)) or name in ALLOWED_NON_SUFFIXED


def inventory(disassembly: str) -> tuple[dict[str, int], set[str], int]:
    """``(vector-ops per symbol, all symbols seen, total instructions)``."""
    vector_ops: dict[str, int] = {}
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
        if _VECTOR_OPERAND_RE.search(insn.group("body")):
            vector_ops[current] = vector_ops.get(current, 0) + 1
    return vector_ops, symbols, instructions


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

    vector_ops, symbols, instructions = inventory(disassembly)

    if len(symbols) < MIN_SYMBOLS or instructions < MIN_INSTRUCTIONS:
        print(
            f"FATAL: read only {len(symbols)} symbol(s) and {instructions} instruction(s) "
            f"from {args.lib} (floor {MIN_SYMBOLS}/{MIN_INSTRUCTIONS}). A clean scoping "
            f"result over an object this gate could not really read would mean nothing.",
            file=sys.stderr,
        )
        return 2

    problems: list[str] = []

    # Non-vacuity: the AVX2 build this gate checks must actually be present.
    for symbol in REQUIRED_VECTOR_SYMBOLS:
        if symbol not in symbols:
            problems.append(
                f"{symbol} is not in the object. This gate verifies that YMM/ZMM code "
                f"stays inside the AVX2/AVX-512 kernels; it cannot do that over a build "
                f"whose kernels are absent. Point --lib at a build with AVX2 enabled."
            )
        elif vector_ops.get(symbol, 0) == 0:
            problems.append(
                f"{symbol} is present but carries no YMM/ZMM operand. It is an AVX2 NTT/"
                f"Keccak kernel and must; a vector-free one means the disassembly was not "
                f"read correctly, and a clean result over it would be meaningless."
            )

    # The finding itself: vector code outside a kernel.
    leaks = {sym: n for sym, n in vector_ops.items() if not is_kernel_symbol(sym)}
    for symbol, count in sorted(leaks.items()):
        problems.append(
            f"{symbol}: {count} YMM/ZMM operand(s) in a non-kernel symbol. AVX2/AVX-512 "
            f"code must live in src/c/avx2 or src/c/avx512, compiled under per-file "
            f"-mavx2/-mavx512. Vector code here means the scoping regressed (a library-wide "
            f"-mavx2, or a direct call that let a kernel inline out of its TU): the object "
            f"now runs AVX2 on a path the dispatcher never gated on a CPUID check. If this "
            f"symbol really is a scoped kernel helper, rename it to the _avx2/_avx512 marker "
            f"or add it to ALLOWED_NON_SUFFIXED with the TU it lives in."
        )

    print(f"{'symbol':<40}{'ymm/zmm':>9}  scope")
    for symbol, count in sorted(vector_ops.items()):
        note = "kernel" if is_kernel_symbol(symbol) else "*** NON-KERNEL ***"
        print(f"{symbol:<40}{count:>9}  {note}")
    print(
        f"\nread {len(symbols):,} symbol(s), {instructions:,} instruction(s); "
        f"{sum(vector_ops.values())} YMM/ZMM operand(s) in {len(vector_ops)} symbol(s), "
        f"{len(leaks)} outside a kernel"
    )

    if problems:
        print("\nAVX SCOPING CHECK FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("\nOK: every YMM/ZMM operand in the object is inside an AVX2/AVX-512 kernel.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
