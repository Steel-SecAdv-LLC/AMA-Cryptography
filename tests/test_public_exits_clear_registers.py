#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""No exported function leaves by a tail call (INVARIANT-6).

``AMA_API`` carries ``zero_call_used_regs("all")`` (``include/ama_cryptography.h``):
the compiler clears every call-clobbered register at the exported function's
own return. A function that ends in a tail call never executes that return.
It jumps to its callee, and the callee, an internal function without the
attribute, returns straight to the caller with whatever it left in registers.

Measured 2026-11-08: before ``-fno-optimize-sibling-calls`` (``CMakeLists.txt``),
32 of the 199 exports left by a tail call under gcc 13.3 on x86-64, 47 under
aarch64 gcc 13.3 with LTO, and 41 under clang 18 with LTO. Among them were
``ama_ml_kem_decapsulate`` -> ``kyber_decapsulate_internal`` and
``ama_ml_dsa_keypair`` -> ``dil_keygen_internal``, and under clang
``ama_kyber_encapsulate`` returned a word of the shared secret in x10
(``tests/c/test_register_residue.c``). The register rows cover a sample of the
API. This test reads every export of the built image.

A direct jump from an exported function to any other function is a
violation. The exception is the function's own ``.cold`` partition, which
GCC splits off and which is part of the same function. Indirect jumps are not
read: a switch's jump table is one, and the flag removes indirect tail calls
together with direct ones.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.test_no_libc_string_calls import _built_libraries, _target
from tools import check_vendor_isolation as gate

_LABEL = re.compile(r"^\s*(?:0x)?[0-9a-f]+ <(?P<name>[^>]+)>:\s*$")
#: x86-64 ``jmp``/``jmpq`` and AArch64 ``b`` to a named target, in GNU or
#: LLVM objdump syntax (``jmp 4f120 <x>`` / ``b 0x4f120 <x>``).
_DIRECT_JUMP = re.compile(r"\s(?:jmpq?|b)\s+(?:0x)?[0-9a-f]+ <(?P<target>[^>]+)>")


def _objdump() -> str | None:
    return shutil.which("objdump") or shutil.which("llvm-objdump")


def _exported_functions(image: Path) -> set[str]:
    info = gate.parse_binary(image)
    return {name for name in info.defined_symbols if name.lstrip("_").startswith("ama_")}


def _bare(name: str, macho: bool) -> str:
    """A symbol as C spells it: Mach-O prefixes one underscore."""
    return name[1:] if macho and name.startswith("_") else name


def tail_calls(image: Path, objdump: str) -> dict[str, set[str]]:
    """Each exported function that jumps to another function, and where to,
    by C name (Mach-O's leading underscore removed; measured on CI's
    macos-latest, where the control's names came back as
    ``_ama_control_export``)."""
    macho = gate.parse_binary(image).fmt == "Mach-O"
    exported = _exported_functions(image)
    listing = subprocess.run(
        [objdump, "-d", "--no-show-raw-insn", str(image)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    found: dict[str, set[str]] = {}
    current: str | None = None
    for line in listing.splitlines():
        label = _LABEL.match(line)
        if label:
            current = label.group("name")
            continue
        if current not in exported:
            continue
        jump = _DIRECT_JUMP.search(line)
        if jump is None:
            continue
        target = jump.group("target").split("+", 1)[0]
        if target == current or target.startswith(current + ".cold"):
            continue
        found.setdefault(_bare(current, macho), set()).add(_bare(target, macho))
    return found


def test_no_exported_function_leaves_by_a_tail_call() -> None:
    images = [image for image in _built_libraries() if _target(image) is not None]
    if not images:
        pytest.skip("no x86-64 or AArch64 library image built in this tree")
    objdump = _objdump()
    if objdump is None:
        pytest.skip("neither objdump nor llvm-objdump is on PATH")
    offending = {str(image): tail_calls(image, objdump) for image in images}
    offending = {image: calls for image, calls in offending.items() if calls}
    assert not offending, (
        f"{offending}: these exports end in a jump to a function without "
        "AMA_API's register clearing, which then returns to the caller with "
        "its registers uncleared. Build with -fno-optimize-sibling-calls "
        "(CMakeLists.txt)."
    )


@pytest.mark.parametrize("sibling_calls", [True, False])
def test_the_scan_sees_a_tail_call(tmp_path: Path, sibling_calls: bool) -> None:
    """Non-vacuity: a tail call from an exported function is reported, and
    the flag this tree builds with removes it."""
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    objdump = _objdump()
    if cc is None or objdump is None:
        pytest.skip("no C compiler or objdump on PATH to build the control object")
    src = tmp_path / "control.c"
    src.write_text(
        "__attribute__((noinline)) static int ama_control_internal(int x) {\n"
        '    __asm__ volatile("" : "+r"(x));\n'
        "    return x * 3 + 1;\n"
        "}\n"
        "int ama_control_export(int x) { return ama_control_internal(x + 1); }\n",
        encoding="ascii",
    )
    so = tmp_path / "libcontrol.so"
    flags = ["-O2", "-shared", "-fPIC"]
    if not sibling_calls:
        flags.append("-fno-optimize-sibling-calls")
    proc = subprocess.run(
        [cc, *flags, str(src), "-o", str(so)], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0 or _target(so) is None:
        pytest.skip(f"the control object could not be built here: {proc.stderr[-300:]}")
    calls = tail_calls(so, objdump)
    if sibling_calls:
        assert "ama_control_internal" in calls.get("ama_control_export", set()), calls
    else:
        assert "ama_control_export" not in calls, calls
