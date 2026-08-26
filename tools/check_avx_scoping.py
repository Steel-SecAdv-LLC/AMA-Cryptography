#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""CPUID-gated instructions must stay inside their dedicated kernels.

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

AVX2 was not the only per-file ISA flag
--------------------------------------
The gate was written for ``-mavx2`` because that is where the audit found the
defect, and it checked YMM/ZMM operands only.  But ``CMakeLists.txt`` scopes
**six** families of CPUID-gated instructions per file, not one:

  ===================================  ============================================
  per-file flags                       translation units
  ===================================  ============================================
  ``-mavx2``                           ``src/c/avx2/*``
  ``-mavx512f -mavx512vl``             ``src/c/avx512/*``
  ``-maes -mpclmul``                   ``src/c/avx2/ama_aes_gcm{,_vaes}_avx2.c``
  ``-mvaes -mvpclmulqdq``              ``src/c/avx2/ama_aes_gcm_vaes_avx2.c``
  ``-msha -mssse3 -msse4.1``           ``src/c/ama_sha256_ni.c``
  ``-mbmi -mbmi2``, ``-mbmi2 -madx``   ``src/c/x86/*``, ``src/c/internal/*_mulx.c``
  ===================================  ============================================

Every one of those raises the same hazard in the same way: make the flag global
and the compiler is free to emit that ISA anywhere, including in the portable
fallback the runtime dispatcher selects **because** the CPU lacks the feature —
and the result is a #UD on a host the wheel claims to support.  A gate that
covers one sixth of the surface leaves the other five to a CMake comment, which
is precisely the state the audit found ``-mavx2`` in.

What it enforces
----------------
It disassembles the built object and, for each ISA family in
:data:`ISA_FAMILIES`, records every symbol whose body contains an instruction
from that family and fails on any such symbol that is not a kernel for it.  A
symbol is kernel code for a family when

  * its name carries one of that family's markers -- ``_avx2`` / ``_avx512``
    for vector code, ``_shani`` for the SHA extensions, ``_bmi`` / ``_mulx``
    for the general-purpose ones -- including the ``.part`` / ``.constprop`` /
    ``.isra`` fragments the compiler splits them into, or
  * it is one of the file-local helpers in that family's allowlist, each
    defined in a scoped translation unit but not named for it.

An occurrence anywhere else is the global-flag regression: a symbol that is not
a kernel has been given instructions the dispatcher never gated on a CPUID
check.

Deliberately NOT checked
------------------------
``tzcnt``, ``lzcnt`` and ``popcnt``.  ``tzcnt`` is encoded as ``rep bsf`` and
executes as ``bsf`` on a CPU without BMI1 -- wrong for a zero input, but never
a fault -- so flagging it would report a portability hazard that does not
exist.  ``lzcnt``/``popcnt`` sit behind ABM/POPCNT rather than behind any flag
this build scopes per file.  XMM operands are likewise excluded: 128-bit SSE2
is baseline x86-64.  The SSSE3 and SSE4.1 families ARE checked, because
``-mssse3``/``-msse4.1`` are per-file flags here and neither is baseline
(``-march=x86-64`` is SSE2).

Exit status
-----------
0  every CPUID-gated instruction lives in a kernel scoped for its ISA
1  a non-kernel symbol carries one, OR a required kernel symbol is missing or
   carries none (the build this gate exists to check did not actually happen)
2  the object could not be read (missing, no disassembler, or below the
   non-vacuity floor) -- a clean result over an object nothing disassembled
   would be a false pass
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import NamedTuple

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
from tools.check_secret_division import disassemble  # noqa: E402 -- after sys.path setup (AVX-001)

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


#: A named family of CPUID-gated instructions, the kernels allowed to contain
#: them, and the symbols whose presence proves the gate really read a build in
#: which that family exists.
#:
#: ``pattern`` is matched against the MNEMONIC COLUMN of the disassembly, not
#: the whole line: objdump prints the raw encoding bytes before the mnemonic,
#: and a two-hex-digit byte can never match a multi-letter mnemonic, but the
#: operand and comment columns can contain symbol names that do.  Splitting on
#: the tab keeps ``call <ama_aes256_gcm_encrypt_avx2>`` from being read as an
#: AES-NI instruction at its call site.
class IsaFamily(NamedTuple):
    name: str
    flags: str
    pattern: re.Pattern[str]
    markers: tuple[re.Pattern[str], ...]
    allowed: dict[str, str]
    required: tuple[str, ...]
    remedy: str

    def owns(self, symbol: str) -> bool:
        """True when ``symbol`` is a kernel this family's instructions may live in."""
        return any(m.search(symbol) for m in self.markers) or symbol in self.allowed


_AVX_MARKER = re.compile(r"_avx(?:2|512)(?:\.|$)")
_SHANI_MARKER = re.compile(r"_shani(?:\.|$)")
_GPR_ISA_MARKER = re.compile(r"_(?:bmi|mulx)(?:\.|$)")

ISA_FAMILIES: tuple[IsaFamily, ...] = (
    IsaFamily(
        name="AVX/AVX2/AVX-512 (YMM/ZMM)",
        flags="-mavx2, -mavx512f -mavx512vl",
        # Either objdump's AT&T (``%ymm3``) or an Intel-syntax (``ymm3``)
        # rendering -- the ``\b`` matches after the ``%`` and at a bare word
        # start alike.  XMM is excluded: 128-bit SSE2 is baseline x86-64.
        pattern=re.compile(r"\b[yz]mm\d"),
        markers=(_AVX_MARKER,),
        allowed=ALLOWED_NON_SUFFIXED,
        required=REQUIRED_VECTOR_SYMBOLS,
        remedy=(
            "AVX2/AVX-512 code must live in src/c/avx2 or src/c/avx512, compiled under "
            "per-file -mavx2/-mavx512"
        ),
    ),
    IsaFamily(
        name="AES-NI",
        flags="-maes (and -mvaes for the VAES kernel)",
        pattern=re.compile(
            r"\b(?:v?aesenc|v?aesenclast|v?aesdec|v?aesdeclast|v?aeskeygenassist|v?aesimc)\b"
        ),
        markers=(_AVX_MARKER,),
        allowed={},
        # The AES-NI GCM kernel. Its absence means the object was built without
        # the AES-NI path, and a clean AES-NI result over it would mean nothing.
        required=("ama_aes256_gcm_encrypt_avx2",),
        remedy=(
            "AES-NI must stay in src/c/avx2/ama_aes_gcm{,_vaes}_avx2.c, the only TUs given "
            "-maes/-mvaes. src/c/ama_aes_bitsliced.c is deliberately excluded: it is the "
            "constant-time fallback FOR CPUs without AES-NI, so an AES-NI opcode there "
            "faults on exactly the hosts it exists to serve"
        ),
    ),
    IsaFamily(
        name="PCLMULQDQ",
        flags="-mpclmul (and -mvpclmulqdq for the VAES kernel)",
        pattern=re.compile(r"\b(?:v?pclmul(?:l|h)q(?:l|h)qdq|v?pclmulqdq)\b"),
        markers=(_AVX_MARKER,),
        allowed={},
        required=("ama_aes256_gcm_encrypt_avx2",),
        remedy=(
            "carry-less multiply must stay in the GHASH kernels under per-file -mpclmul; "
            "the portable GHASH in src/c/ama_aes_gcm.c must remain baseline"
        ),
    ),
    IsaFamily(
        name="SHA-NI (Intel SHA Extensions)",
        flags="-msha",
        pattern=re.compile(
            r"\b(?:sha256rnds2|sha256msg1|sha256msg2|sha1rnds4|sha1msg1|sha1msg2|sha1nexte)\b"
        ),
        markers=(_SHANI_MARKER,),
        allowed={},
        required=("ama_sha256_compress_x86_shani",),
        remedy=(
            "SHA-NI must stay in src/c/ama_sha256_ni.c, the only TU given -msha; the "
            "whole-library scalar SHA-256 stays baseline so the binary runs on CPUs "
            "without the extension, with ama_cpuid.c selecting at run time"
        ),
    ),
    IsaFamily(
        name="BMI1/BMI2/ADX",
        flags="-mbmi -mbmi2, -mbmi2 -madx",
        # tzcnt/lzcnt/popcnt deliberately absent -- see the module docstring.
        pattern=re.compile(
            r"\b(?:mulx|pdep|pext|bzhi|blsr|blsi|blsmsk|andn|sarx|shlx|shrx|rorx|adcx|adox)\b"
        ),
        markers=(_GPR_ISA_MARKER,),
        allowed={},
        # Built on every x86 GCC/Clang target regardless of AMA_ENABLE_SIMD
        # (CMakeLists.txt: "BMI1 and BMI2 are general-purpose ISA extensions,
        # not SIMD"), so its absence is a gate-scope failure, not a config.
        required=("ama_keccak_f1600_bmi",),
        remedy=(
            "BMI/ADX must stay in src/c/x86/*.c and src/c/internal/*_mulx.c, the only TUs "
            "given -mbmi/-mbmi2/-madx, each gated at run time by ama_cpuid.c"
        ),
    ),
    IsaFamily(
        name="SSSE3",
        flags="-mssse3",
        pattern=re.compile(
            r"\b(?:pshufb|palignr|phaddw|phaddd|phaddsw|phsubw|phsubd|phsubsw|pmaddubsw"
            r"|pabsb|pabsw|pabsd|psignb|psignw|psignd|pmulhrsw)\b"
        ),
        markers=(_AVX_MARKER, _SHANI_MARKER),
        allowed={},
        required=("ama_sha256_compress_x86_shani",),
        remedy=(
            "SSSE3 is not baseline x86-64 (-march=x86-64 is SSE2) and is applied per file "
            "beside -msha/-maes; it must stay in those TUs"
        ),
    ),
    IsaFamily(
        name="SSE4.1",
        flags="-msse4.1",
        pattern=re.compile(
            r"\b(?:pblendvb|pblendw|blendvps|blendvpd|pextrd|pextrq|pinsrd|pinsrq|pmulld"
            r"|pmuldq|ptest|pcmpeqq|packusdw|roundps|roundpd|roundss|roundsd"
            r"|pmovzx[bwd][wdq]|pmovsx[bwd][wdq]|pminu[dw]|pmaxu[dw]|pminsb|pmaxsb"
            r"|pminsd|pmaxsd)\b"
        ),
        markers=(_AVX_MARKER, _SHANI_MARKER),
        allowed={},
        # No required symbol: the compiler's use of SSE4.1 in the scoped TUs is
        # incidental (3 occurrences in the reference build), so pinning one
        # would break on a compiler that chose otherwise.  The global symbol
        # and instruction floors, and the five families above that DO carry
        # required symbols, are what establish the gate read a real object.
        required=(),
        remedy=(
            "SSE4.1 is not baseline x86-64 and is applied per file beside -msha/-maes; "
            "it must stay in those TUs"
        ),
    ),
)


def is_kernel_symbol(name: str) -> bool:
    """True when ``name`` is AVX2/AVX-512 kernel code allowed to carry YMM/ZMM.

    Retained as the AVX-family predicate that ``inventory()`` pairs with; the
    per-family question is :meth:`IsaFamily.owns`.
    """
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


def _mnemonic(body: str) -> str:
    """The mnemonic+operand column of an objdump instruction line.

    objdump prints ``<address>:\t<encoding bytes>\t<mnemonic> <operands>``.
    Matching a family pattern against the whole line would let the encoding
    bytes and, more importantly, a branch target like
    ``call ... <ama_aes256_gcm_encrypt_avx2>`` register as an occurrence at
    every CALL SITE of a kernel -- turning every caller into a false leak.
    """
    return body.split("\t")[-1] if "\t" in body else body


def scan_families(disassembly: str) -> tuple[dict[str, dict[str, int]], set[str], int]:
    """``(per-family {symbol: count}, all symbols seen, total instructions)``.

    One pass over the disassembly for every family in :data:`ISA_FAMILIES`, so
    a large object is walked once rather than seven times.
    """
    per_family: dict[str, dict[str, int]] = {f.name: {} for f in ISA_FAMILIES}
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
        mnemonic = _mnemonic(insn.group("body"))
        for family in ISA_FAMILIES:
            if family.pattern.search(mnemonic):
                counts = per_family[family.name]
                counts[current] = counts.get(current, 0) + 1
    return per_family, symbols, instructions


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

    per_family, symbols, instructions = scan_families(disassembly)

    if len(symbols) < MIN_SYMBOLS or instructions < MIN_INSTRUCTIONS:
        print(
            f"FATAL: read only {len(symbols)} symbol(s) and {instructions} instruction(s) "
            f"from {args.lib} (floor {MIN_SYMBOLS}/{MIN_INSTRUCTIONS}). A clean scoping "
            f"result over an object this gate could not really read would mean nothing.",
            file=sys.stderr,
        )
        return 2

    problems: list[str] = []
    total_leaks = 0
    total_ops = 0

    for family in ISA_FAMILIES:
        counts = per_family[family.name]
        total_ops += sum(counts.values())

        # Non-vacuity: the build this family is checked against must exist.
        for symbol in family.required:
            if symbol not in symbols:
                problems.append(
                    f"[{family.name}] {symbol} is not in the object. This gate verifies "
                    f"that {family.name} instructions stay inside the kernels compiled "
                    f"under {family.flags}; it cannot do that over a build whose kernels "
                    f"are absent. Point --lib at a full x86-64 build."
                )
            elif counts.get(symbol, 0) == 0:
                problems.append(
                    f"[{family.name}] {symbol} is present but carries no {family.name} "
                    f"instruction, though it is that family's kernel. A family-free one "
                    f"means the disassembly was not read correctly, and a clean result "
                    f"over it would be meaningless."
                )

        leaks = {sym: n for sym, n in counts.items() if not family.owns(sym)}
        total_leaks += len(leaks)
        for symbol, count in sorted(leaks.items()):
            problems.append(
                f"[{family.name}] {symbol}: {count} occurrence(s) in a non-kernel symbol. "
                f"{family.remedy}. An occurrence here means the per-file scoping regressed "
                f"(a library-wide {family.flags.split(',')[0].strip()}, or a direct call "
                f"that let a kernel inline out of its TU): the object now executes "
                f"{family.name} on a path the dispatcher never gated on a CPUID check, so "
                f"it faults on a host that lacks the feature. If this symbol really is a "
                f"scoped kernel helper, rename it to carry the family's marker or add it "
                f"to that family's allowlist with the TU it lives in."
            )

        print(f"--- {family.name}  ({family.flags}) ---")
        if not counts:
            print("    (none in this object)")
        for symbol, count in sorted(counts.items()):
            note = "kernel" if family.owns(symbol) else "*** NON-KERNEL ***"
            print(f"    {symbol:<44}{count:>7}  {note}")

    print(
        f"\nread {len(symbols):,} symbol(s), {instructions:,} instruction(s); "
        f"{total_ops} CPUID-gated instruction(s) across {len(ISA_FAMILIES)} ISA "
        f"famil(ies), {total_leaks} symbol(s) outside a kernel"
    )

    if problems:
        print("\nISA SCOPING CHECK FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(
        "\nOK: every CPUID-gated instruction in the object is inside a kernel scoped "
        "for its ISA."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
