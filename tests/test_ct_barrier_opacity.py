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


def _compilers() -> list[str]:
    return [cc for cc in ("gcc", "clang") if shutil.which(cc)]


def _objdump() -> str | None:
    return shutil.which("objdump")


def _instructions(disassembly: str, function: str) -> list[str]:
    """Mnemonics of ``function`` in an ``objdump -d`` listing."""
    match = re.search(rf"^[0-9a-f]+ <{function}>:\n(.*?)(?:\n\n|\Z)", disassembly, re.M | re.S)
    assert match, f"{function} not found in the disassembly"
    out = []
    for line in match.group(1).splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2 and parts[0].strip().endswith(":") and parts[1].strip():
            out.append(parts[1].split()[0])
    body = [m for m in out if not m.startswith(("nop", "endbr", "bti", "paciasp", "autiasp"))]
    # Up to the first return: what follows is alignment padding.
    for i, mnemonic in enumerate(body):
        if mnemonic.startswith("ret"):
            return body[: i + 1]
    return body


def _folds_to_constant(mnemonics: list[str]) -> bool:
    """``mov $1, ret`` (x86-64) or ``mov w0, #1; ret`` (AArch64)."""
    return len(mnemonics) <= 2 and mnemonics[-1].startswith("ret")


pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux") and not _compilers(),
    reason="no gcc or clang on this host; the Linux CI lanes run it",
)


def test_linux_has_a_compiler() -> None:
    """On Linux, where CI builds, the probe must not silently skip."""
    if sys.platform.startswith("linux"):
        assert _compilers(), "neither gcc nor clang is on PATH"
        assert _objdump() is not None, "objdump is not on PATH"


@pytest.mark.parametrize("flags", FLAG_SETS, ids=lambda f: " ".join(f))
@pytest.mark.parametrize("cc", _compilers() or ["none"])
def test_the_barrier_hides_the_mask_range(cc: str, flags: tuple[str, ...], tmp_path: Path) -> None:
    objdump = _objdump()
    if cc == "none" or objdump is None:
        pytest.skip("no compiler/objdump on this host")
    src = tmp_path / "probe.c"
    src.write_text(PROBE, encoding="utf-8")
    exe = tmp_path / "probe"
    proc = subprocess.run(
        [cc, "-std=c11", *flags, "-I", str(INTERNAL), str(src), "-o", str(exe)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 and "-flto" in flags and "LLVMgold" in proc.stderr:
        pytest.skip(f"{cc} cannot link with -flto here: {proc.stderr.strip()[:120]}")
    assert proc.returncode == 0, proc.stderr
    run = subprocess.run([str(exe)], capture_output=True, check=False)
    assert run.returncode == 0, "the probe computed a wrong answer"
    dis = subprocess.run(
        [objdump, "-d", "--no-show-raw-insn", str(exe)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    found = {f: _instructions(dis, f) for f in FUNCTIONS}
    for width in ("u64", "u32"):
        assert _folds_to_constant(found[f"ctl_{width}"]), (
            f"{cc} {' '.join(flags)} did not fold the barrier-free control "
            f"({found[f'ctl_{width}']}); the probe cannot tell anything on this compiler"
        )
        assert not _folds_to_constant(found[f"probe_{width}"]), (
            f"{cc} {' '.join(flags)} folded the mask through ama_ct_value_barrier_{width} "
            f"({found[f'probe_{width}']}): the barrier no longer hides its range"
        )
