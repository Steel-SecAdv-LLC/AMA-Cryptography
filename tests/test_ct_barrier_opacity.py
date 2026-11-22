# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The optimizer barrier hides a mask's range from the compilers CI uses.

``ama_ct_value_barrier_u64`` / ``_u32`` (``src/c/internal/ama_ct_barrier.h``)
exist so the optimizer cannot prove a select mask is 0 or ~0 and turn the
masked select back into a branch on the secret.  Whether they do that is a
property of the compiler, not of the source, so it is measured here: a probe
asks the compiler the exact question the barrier must leave unanswerable --
"is this mask 0 or all-ones?" -- under each compiler and each optimization
level CI builds with (``-O2``, ``-O3``, and ``-O3 -flto`` linked).

* The CONTROL, the same function without the barrier, must fold to a constant
  ``return 1``.  That proves the probe is sensitive on that compiler: if it
  did not fold, a pass of the probe below would mean nothing.
* The PROBE, through the barrier, must not fold.

If the barrier were weakened to a plain ``return v`` (or a compiler learned to
see through an empty ``asm`` with a register operand), the probe would fold
like the control and this test fails.  ``tools/check_ct_markers.py`` pins
where the barrier is used; this pins what it does.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
INTERNAL = REPO_ROOT / "src" / "c" / "internal"

PROBE = r"""
#include <stdint.h>
#include "ama_ct_barrier.h"
__attribute__((noinline, used)) int ctl_u64(uint64_t b) {
    uint64_t m = (uint64_t)0 - (b & 1u);
    return (m == 0) | (m == ~(uint64_t)0);
}
__attribute__((noinline, used)) int probe_u64(uint64_t b) {
    uint64_t m = ama_ct_value_barrier_u64((uint64_t)0 - (b & 1u));
    return (m == 0) | (m == ~(uint64_t)0);
}
__attribute__((noinline, used)) int ctl_u32(uint32_t b) {
    uint32_t m = 0u - (b & 1u);
    return (m == 0) | (m == ~0u);
}
__attribute__((noinline, used)) int probe_u32(uint32_t b) {
    uint32_t m = ama_ct_value_barrier_u32(0u - (b & 1u));
    return (m == 0) | (m == ~0u);
}
/* Called through volatile pointers so that interprocedural optimization --
 * which LTO enables -- cannot replace a call with the constant it proved and
 * then drop the function: each body must survive to be disassembled. */
int (*volatile f64[2])(uint64_t) = {ctl_u64, probe_u64};
int (*volatile f32[2])(uint32_t) = {ctl_u32, probe_u32};
int main(int argc, char **argv) {
    (void)argv;
    return f64[0]((uint64_t)argc) + f64[1]((uint64_t)argc) + f32[0]((uint32_t)argc) +
           f32[1]((uint32_t)argc) - 4;
}
"""

FLAG_SETS = (("-O2",), ("-O3",), ("-O3", "-flto"))
FUNCTIONS = ("ctl_u64", "probe_u64", "ctl_u32", "probe_u32")
_NOT_A_BODY = ("nop", "endbr", "bti", "paciasp", "autiasp", "hint")


def _compilers() -> list[str]:
    return [cc for cc in ("gcc", "clang") if shutil.which(cc)]


def _objdump() -> str | None:
    return shutil.which("objdump")


#: Frame-pointer setup and teardown, matched by operand so that no other
#: move or push is discarded.  x86-64 macOS keeps a frame pointer by default,
#: which wraps a folded ``movl $1, %eax; ret`` in ``push %rbp; mov %rsp,
#: %rbp`` ... ``pop %rbp`` -- five instructions that are still a constant.
_FRAME = re.compile(
    r"^(?:push[lq]?\s+%[re]bp|pop[lq]?\s+%[re]bp|mov[lq]?\s+%[re]sp,\s*%[re]bp"
    r"|stp\s+x29,\s*x30\b|ldp\s+x29,\s*x30\b|mov\s+x29,\s*sp)$"
)


def _until_return(instructions: list[str]) -> list[str]:
    """Mnemonics of the body up to its first return, frame bookkeeping and
    padding removed; what follows the return is alignment padding."""
    body = []
    for text in instructions:
        norm = " ".join(text.replace(", ", ",").split()).lower()
        mnemonic = norm.split()[0]
        if mnemonic.startswith(_NOT_A_BODY) or _FRAME.match(norm.replace(",", ", ")):
            continue
        body.append(mnemonic)
        if mnemonic.startswith("ret"):
            break
    return body


def _instructions_from_assembly(assembly: str, function: str) -> list[str]:
    """Mnemonics of ``function`` in ``cc -S`` output.

    The compiler's own assembly is read rather than a disassembly, because it
    names the function the same way on every object format -- ``f:`` on ELF
    and COFF, ``_f:`` on Mach-O -- and needs neither a symbol table (an
    executable linked for the MSVC target has none) nor a disassembler that
    understands the host's format.  Directives, labels and comments are not
    instructions.
    """
    lines = assembly.splitlines()
    label = re.compile(rf"^_?{re.escape(function)}:")
    start = next((i for i, ln in enumerate(lines) if label.match(ln)), None)
    assert start is not None, f"{function} not found in the assembly"
    out = []
    for line in lines[start + 1 :]:
        text = line.split("#")[0].split("//")[0].split(";")[0].strip()
        if not text or text.startswith(".") or text.endswith(":"):
            continue
        out.append(text)
        if text.split()[0].lower().startswith("ret"):
            break
    return _until_return(out)


def _instructions_from_disassembly(disassembly: str, function: str) -> list[str]:
    """Mnemonics of ``function`` in an ``objdump -d`` listing (``_f`` on Mach-O)."""
    match = re.search(
        rf"^[0-9a-f]+ <_?{re.escape(function)}>:\n(.*?)(?:\n\n|\Z)", disassembly, re.M | re.S
    )
    assert match, f"{function} not found in the disassembly"
    out = []
    for line in match.group(1).splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2 and parts[0].strip().endswith(":") and parts[1].strip():
            out.append(parts[1].strip())
    return _until_return(out)


def _folds_to_constant(mnemonics: list[str]) -> bool:
    """``mov $1, ret`` (x86-64) or ``mov w0, #1; ret`` (AArch64)."""
    return bool(mnemonics) and len(mnemonics) <= 2 and mnemonics[-1].startswith("ret")


def _cells() -> list[tuple[str, tuple[str, ...]]]:
    """Every (compiler, flags) cell this host can build.

    One cell is left out by construction, not skipped at run time: clang on
    Windows targets MSVC, whose linker writes an executable with no symbol
    table, so there is nothing to find the LTO-optimised functions by.  The
    Windows wheels are built by MSVC, which compiles the barrier's
    ``volatile`` branch rather than the ``asm`` this probe measures, so that
    cell is not a configuration the project ships.  Its -O2/-O3 cells, which
    read the compiler's assembly, still run.
    """
    return [
        (cc, flags)
        for cc in _compilers()
        for flags in FLAG_SETS
        if not (sys.platform == "win32" and cc == "clang" and "-flto" in flags)
    ]


pytestmark = pytest.mark.skipif(
    not _compilers(),
    reason="no gcc or clang on this host",
)


def test_every_ci_host_has_a_compiler() -> None:
    """On the hosts CI runs this module on, the probe must not silently skip."""
    if sys.platform.startswith("linux") or sys.platform == "darwin":
        assert _compilers(), "neither gcc nor clang is on PATH"
        assert _objdump() is not None, "objdump is not on PATH"


def _build(cc: str, flags: tuple[str, ...], tmp_path: Path) -> list[str]:
    src = tmp_path / "probe.c"
    src.write_text(PROBE, encoding="utf-8")
    base = [cc, "-std=c11", *flags, "-I", str(INTERNAL), str(src)]
    if "-flto" not in flags:
        asm = tmp_path / "probe.s"
        proc = subprocess.run(
            [*base, "-S", "-o", str(asm)], capture_output=True, text=True, check=False
        )
        assert proc.returncode == 0, proc.stderr
        text = asm.read_text(encoding="utf-8", errors="replace")
        return [" ".join(_instructions_from_assembly(text, f)) for f in FUNCTIONS]
    exe = tmp_path / ("probe.exe" if sys.platform == "win32" else "probe")
    proc = subprocess.run([*base, "-o", str(exe)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    run = subprocess.run([str(exe)], capture_output=True, check=False)
    assert run.returncode == 0, "the probe computed a wrong answer"
    objdump = _objdump()
    assert objdump is not None, "objdump is not on PATH"
    dis = subprocess.run(
        [objdump, "-d", "--no-show-raw-insn", str(exe)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [" ".join(_instructions_from_disassembly(dis, f)) for f in FUNCTIONS]


@pytest.mark.parametrize(
    ("cc", "flags"), _cells(), ids=lambda v: v if isinstance(v, str) else " ".join(v)
)
def test_the_barrier_hides_the_mask_range(cc: str, flags: tuple[str, ...], tmp_path: Path) -> None:
    found = dict(zip(FUNCTIONS, (body.split() for body in _build(cc, flags, tmp_path))))
    for width in ("u64", "u32"):
        assert _folds_to_constant(found[f"ctl_{width}"]), (
            f"{cc} {' '.join(flags)} did not fold the barrier-free control "
            f"({found[f'ctl_{width}']}); the probe cannot tell anything on this compiler"
        )
        assert not _folds_to_constant(found[f"probe_{width}"]), (
            f"{cc} {' '.join(flags)} folded the mask through ama_ct_value_barrier_{width} "
            f"({found[f'probe_{width}']}): the barrier no longer hides its range"
        )
