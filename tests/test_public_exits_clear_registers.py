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
aarch64 gcc 13.3 with LTO, and 41 under clang 18 with LTO, counted by the
first version of this scan, which also counted a forward to another export.
Re-measured on a sibling-call build of the tree as of the refined rules below
(x86-64 gcc 13.3, Release with LTO): 30 exports left by a direct jump, 20 of
them to a function without the clearing, the other 10 to another export.
Among the 20 were ``ama_ml_kem_decapsulate`` -> ``kyber_decapsulate_internal``
and ``ama_ml_dsa_keypair`` -> ``dil_keygen_internal``, and under clang
``ama_kyber_encapsulate`` returned a word of the shared secret in x10
(``tests/c/test_register_residue.c``). The register rows cover a sample of the
API. This test reads every export of the built image.

What is read, per export:

* The instructions inside the export's own symbol size, and inside its GCC
  cold partition (``name.cold``, a symbol of its own). GCC splits an
  unlikely path into that partition, and the partition is the same
  function: the tail call it ends in leaves the export with its registers
  uncleared (measured 2026-11-08, gcc 13.3 and 14.2: a cold-attributed
  callee is reached by ``jmp`` from inside ``ama_control_export.cold``).
  The first version of this scan read the hot part only, and Copilot's
  review pointed at the gap. Any other suffixed symbol (``.part.N``,
  ``.constprop.N``, clang's outlined ``.cold.N``) is a separate function,
  so a jump to it is a tail call.
* Attribution is by symbol size, not by the nearest label. objdump labels
  every byte after a function with that function's name until the next
  symbol, and the AArch64 linker places erratum-843419 stubs there (a moved
  load and a branch back, under a ``$x`` mapping symbol only). Read by
  label, ``ama_chacha20poly1305_decrypt`` appeared to jump to
  ``nistp_jac_double.constprop.0``: that branch was the stub's, 0x290 bytes
  into a 0x290-byte function. Mach-O carries no symbol sizes, so there the
  next label bounds the function; Mach-O has no such stubs.
* A direct jump (``jmp``/``b``) to any function other than the export, its
  partition and another export is a violation. A jump to another export's
  entry is not: that export carries ``AMA_API`` and clears at its own
  return (gcc's identical-code folding makes ``ama_shake256_inc_absorb`` a
  two-instruction forwarder to ``ama_sha3_update`` in the AVX-512 build).
  A jump into the middle of another export is a violation. An
  erratum-843419 veneer (``e843419@...``) branches back into the function
  that entered it, so a jump to one is internal; a long-branch veneer
  (``__name_veneer``) stands for ``name``.
* An indirect jump in the shape of a GOT tail call is a violation: x86-64
  ``jmp *disp(%rip)`` and AArch64 ``ldr xN, [xN, #imm]`` followed by
  ``br xN`` (both measured from ``-fno-plt`` builds of a ``memcpy``
  forwarder, gcc 13.3 and clang 18). A register-indirect jump of any other
  shape is a switch's jump table (``notrack jmp *%rax``; AArch64 loads the
  table entry into a different register than it branches through) and is
  not a violation. A register-indirect tail call of some other shape is the
  one form this scan does not read; ``-fno-optimize-sibling-calls`` removes
  it together with every form it does read.

Each rule has a control below that fails without it (AGENTS section 6.2).
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
#: x86-64 RIP-relative indirect jump: the GOT form of a tail call
#: (``-fno-plt``), with the symbol objdump resolves the slot to when it can.
_GOT_JUMP_X86 = re.compile(
    r"\s(?:notrack\s+)?jmpq?\s+\*(?:0x)?[0-9a-f]+\(%rip\)"
    r"(?:\s+#+\s*(?:0x)?[0-9a-f]+\s+<(?P<target>[^>]+)>)?"
)
#: AArch64 GOT form: the register branched through was loaded through itself
#: on the instruction before (``ldr x16, [x16, #4032]`` then ``br x16``).
_GOT_LOAD_A64 = re.compile(r"\sldr\s+(?P<reg>x\d+), \[(?P=reg)(?:, #-?\d+)?\]")
_GOT_JUMP_A64 = re.compile(r"\sbr\s+(?P<reg>x\d+)\b")
#: GCC's cold partition of a function: the same function, split.
_PARTITION = re.compile(r"^(?P<owner>.+)\.cold$")
#: The AArch64 linker's erratum-843419 veneer, which branches back into the
#: function that entered it, and its long-branch veneer, which stands for
#: the function it is named after.
_ERRATUM_VENEER = re.compile(r"^e843419@")
_BRANCH_VENEER = re.compile(r"^__(?P<name>.+)_veneer$")
#: The address a listing line disassembles.
_INSN_ADDRESS = re.compile(r"^\s*(?P<addr>[0-9a-f]+):")
#: A symbol-table row of ``objdump -t`` / ``llvm-objdump -t``: the address
#: first and the name last; ELF rows carry a size column between them (16
#: hex digits), Mach-O rows carry none.
_HEX_COLUMN = re.compile(r"^[0-9a-f]{8,16}$")


def _objdump() -> str | None:
    return shutil.which("objdump") or shutil.which("llvm-objdump")


def _exported_functions(image: Path) -> set[str]:
    info = gate.parse_binary(image)
    return {name for name in info.defined_symbols if name.lstrip("_").startswith("ama_")}


def _bare(name: str, macho: bool) -> str:
    """A symbol as C spells it: Mach-O prefixes one underscore."""
    return name[1:] if macho and name.startswith("_") else name


def _owner(label: str) -> str:
    """The function a listing label belongs to: itself, or the export whose
    ``.cold`` partition it is."""
    partition = _PARTITION.match(label)
    return partition.group("owner") if partition else label


def _listing(image: Path, objdump: str) -> str:
    return subprocess.run(
        [objdump, "-d", "--no-show-raw-insn", str(image)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def _symbol_ranges(image: Path, objdump: str) -> dict[str, tuple[int, int]]:
    """``name -> (address, size)`` for every sized symbol the image's table
    lists; empty for a format without sizes (Mach-O)."""
    table = subprocess.run(
        [objdump, "-t", str(image)], capture_output=True, text=True, check=True
    ).stdout
    ranges: dict[str, tuple[int, int]] = {}
    for line in table.splitlines():
        tokens = line.split()
        if len(tokens) < 4 or not _HEX_COLUMN.match(tokens[0]):
            continue
        sizes = [tok for tok in tokens[1:-1] if _HEX_COLUMN.match(tok)]
        if not sizes:
            continue
        size = int(sizes[0], 16)
        if size:
            ranges[tokens[-1]] = (int(tokens[0], 16), size)
    return ranges


def _owner_at(address: int, bodies: list[tuple[int, int, str]]) -> str | None:
    for start, size, owner in bodies:
        if start <= address < start + size:
            return owner
    return None


def _resolve_direct(label: str) -> str | None:
    """The function a direct jump's target label stands for, or None for a
    label the jump never leaves its function through (an erratum veneer
    branches back into it)."""
    if _ERRATUM_VENEER.match(label):
        return None
    veneer = _BRANCH_VENEER.match(label)
    name = veneer.group("name") if veneer else label
    # A PLT entry stands for the function it resolves to (``memcpy@plt``).
    return name.split("@", 1)[0]


def _leaves_to(line: str, previous: str, owner: str, exported: set[str]) -> str | None:
    """The function this instruction of ``owner`` leaves to without
    AMA_API's clearing, or None."""
    direct = _DIRECT_JUMP.search(line)
    if direct:
        name, _, offset = direct.group("target").partition("+")
        resolved = _resolve_direct(name)
        if resolved is None or _owner(resolved) == owner:
            return None
        # Another export's entry clears at its own return; its middle does not.
        return direct.group("target") if resolved not in exported or offset else None
    got_x86 = _GOT_JUMP_X86.search(line)
    if got_x86:
        slot = got_x86.group("target")
        if slot is None:
            return "*(%rip) (GOT slot)"
        return None if slot.split("@", 1)[0] in exported else slot
    got_a64 = _GOT_JUMP_A64.search(line)
    if got_a64:
        load = _GOT_LOAD_A64.search(previous)
        if load and load.group("reg") == got_a64.group("reg"):
            return f"*{got_a64.group('reg')} (GOT slot)"
    return None


def tail_calls(image: Path, objdump: str) -> dict[str, set[str]]:
    """Each exported function that leaves by a jump to a function without
    AMA_API's clearing, and where to, by C name (Mach-O's leading underscore
    removed; measured on CI's macos-latest, where the control's names came
    back as ``_ama_control_export``)."""
    macho = gate.parse_binary(image).fmt == "Mach-O"
    exported = _exported_functions(image)
    # Every export's body, and its partition's, by address; empty on Mach-O,
    # where the next label bounds a function instead.
    bodies = [
        (start, size, _owner(name))
        for name, (start, size) in _symbol_ranges(image, objdump).items()
        if _owner(name) in exported
    ]
    found: dict[str, set[str]] = {}
    owner: str | None = None
    previous = ""
    for line in _listing(image, objdump).splitlines():
        label = _LABEL.match(line)
        if label:
            if not bodies:
                owner = _owner(label.group("name"))
            previous = ""
            continue
        if bodies:
            insn = _INSN_ADDRESS.match(line)
            owner = _owner_at(int(insn.group("addr"), 16), bodies) if insn else None
        if owner in exported:
            target = _leaves_to(line, previous, owner, exported)
            if target is not None:
                found.setdefault(_bare(owner, macho), set()).add(_bare(target, macho))
        previous = line
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


# --- controls: each rule of the scan, exercised with and without the flag ---

_CONTROL_DIRECT = (
    "__attribute__((noinline)) static int ama_control_internal(int x) {\n"
    '    __asm__ volatile("" : "+r"(x));\n'
    "    return x * 3 + 1;\n"
    "}\n"
    "int ama_control_export(int x) { return ama_control_internal(x + 1); }\n"
)

#: A cold-attributed callee on an unlikely path: GCC moves the path into
#: ``ama_control_export.cold`` and, with sibling calls on, ends it in a jump.
_CONTROL_COLD = (
    "__attribute__((cold, noinline)) static int ama_cold_internal(int x) {\n"
    '    __asm__ volatile("" : "+r"(x));\n'
    "    return x * 7 + 3;\n"
    "}\n"
    "__attribute__((noinline)) static int ama_hot_internal(int x) {\n"
    '    __asm__ volatile("" : "+r"(x));\n'
    "    return x + 1;\n"
    "}\n"
    "int ama_control_export(int x) {\n"
    "    if (__builtin_expect(x == 0x7f3a9c1, 0)) {\n"
    "        return ama_cold_internal(x);\n"
    "    }\n"
    "    return ama_hot_internal(x) * 2;\n"
    "}\n"
)

#: A forwarder from one export to another: the callee carries AMA_API too,
#: so this jump is not a violation (gcc's identical-code folding emits the
#: same shape).
_CONTROL_FORWARD = (
    "__attribute__((noinline)) int ama_target_export(int x) {\n"
    '    __asm__ volatile("" : "+r"(x));\n'
    "    return x * 5 + 2;\n"
    "}\n"
    "int ama_forward_export(int x) { return ama_target_export(x); }\n"
)

#: A forwarder to libc under ``-fno-plt``: the tail call goes through the
#: GOT slot, an indirect jump.
_CONTROL_GOT = (
    "#include <string.h>\n"
    "void *ama_got_export(void *d, const void *s, unsigned long n) {\n"
    "    return memcpy(d, s, n);\n"
    "}\n"
)


def _build_control(
    tmp_path: Path, source: str, extra_flags: list[str], sibling_calls: bool
) -> tuple[Path, str] | None:
    """The control shared object and the objdump to read it with, or None
    with the skip already raised."""
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    objdump = _objdump()
    if cc is None or objdump is None:
        pytest.skip("no C compiler or objdump on PATH to build the control object")
    src = tmp_path / "control.c"
    src.write_text(source, encoding="ascii")
    so = tmp_path / "libcontrol.so"
    flags = ["-O2", "-shared", "-fPIC", *extra_flags]
    if not sibling_calls:
        flags.append("-fno-optimize-sibling-calls")
    proc = subprocess.run(
        [cc, *flags, str(src), "-o", str(so)], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0 or _target(so) is None:
        pytest.skip(f"the control object could not be built here: {proc.stderr[-300:]}")
    return so, objdump


@pytest.mark.parametrize("sibling_calls", [True, False])
def test_the_scan_sees_a_tail_call(tmp_path: Path, sibling_calls: bool) -> None:
    """Non-vacuity: a direct tail call from an exported function is reported,
    and the flag this tree builds with removes it."""
    built = _build_control(tmp_path, _CONTROL_DIRECT, [], sibling_calls)
    assert built is not None
    calls = tail_calls(*built)
    if sibling_calls:
        assert "ama_control_internal" in calls.get("ama_control_export", set()), calls
    else:
        assert "ama_control_export" not in calls, calls


@pytest.mark.parametrize("sibling_calls", [True, False])
def test_the_scan_reads_the_cold_partition(tmp_path: Path, sibling_calls: bool) -> None:
    """A tail call GCC places inside ``ama_control_export.cold`` is charged to
    the export (reverting ``_owner`` to the identity passes the sibling-calls
    case vacuously: measured, the scan then returns ``{}``)."""
    built = _build_control(tmp_path, _CONTROL_COLD, [], sibling_calls)
    assert built is not None
    so, objdump = built
    if "<ama_control_export.cold>:" not in _listing(so, objdump):
        pytest.skip("this compiler did not split a cold partition off the control")
    calls = tail_calls(so, objdump)
    if sibling_calls:
        targets = calls.get("ama_control_export", set())
        assert any(t.startswith("ama_cold_internal") for t in targets), calls
    else:
        assert "ama_control_export" not in calls, calls


def test_a_jump_to_another_export_is_not_a_violation(tmp_path: Path) -> None:
    """The target export clears at its own return. Removing the export
    exemption reports ``ama_forward_export -> ama_target_export``."""
    built = _build_control(tmp_path, _CONTROL_FORWARD, [], sibling_calls=True)
    assert built is not None
    so, objdump = built
    body = _listing(so, objdump).split("ama_forward_export>:", 1)[-1].split("\n\n", 1)[0]
    if not re.search(r"\sjmpq?\s+(?:0x)?[0-9a-f]+ <_?ama_target_export", body):
        pytest.skip("this compiler did not emit the forwarder as a tail call")
    assert tail_calls(so, objdump) == {}


#: An export of one instruction, then a jump the linker could have placed
#: after it (an AArch64 erratum stub has this shape): outside the export's
#: ``.size``, so not the export's.  GNU assembler, ELF only.
_CONTROL_ORPHAN = {
    "x86_64": (
        "    .text\n"
        "    .globl ama_orphan_export\n"
        "    .type ama_orphan_export, @function\n"
        "ama_orphan_export:\n"
        "    ret\n"
        "    .size ama_orphan_export, . - ama_orphan_export\n"
        "    nop\n"
        "    jmp orphan_internal\n"
        "    .type orphan_internal, @function\n"
        "orphan_internal:\n"
        "    ret\n"
        "    .size orphan_internal, . - orphan_internal\n"
        '    .section .note.GNU-stack,"",@progbits\n'
    ),
    "aarch64": (
        "    .text\n"
        "    .globl ama_orphan_export\n"
        "    .type ama_orphan_export, %function\n"
        "ama_orphan_export:\n"
        "    ret\n"
        "    .size ama_orphan_export, . - ama_orphan_export\n"
        "    nop\n"
        "    b orphan_internal\n"
        "    .type orphan_internal, %function\n"
        "orphan_internal:\n"
        "    ret\n"
        "    .size orphan_internal, . - orphan_internal\n"
        '    .section .note.GNU-stack,"",%progbits\n'
    ),
}


def test_code_after_the_exports_size_is_not_the_exports(tmp_path: Path) -> None:
    """objdump labels the orphan ``jmp`` as ``ama_orphan_export+0x1``; the
    scan, bounding the export by its symbol size, does not charge it
    (measured on the AArch64 images: erratum-843419 stubs after
    ``ama_chacha20poly1305_decrypt`` and ``ama_sha384``).  Reading by label
    instead reports ``ama_orphan_export -> orphan_internal``."""
    import platform

    source = _CONTROL_ORPHAN.get(platform.machine().lower().replace("arm64", "aarch64"))
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    objdump = _objdump()
    if source is None or cc is None or objdump is None:
        pytest.skip("no assembler control for this host")
    src = tmp_path / "orphan.s"
    src.write_text(source, encoding="ascii")
    so = tmp_path / "liborphan.so"
    proc = subprocess.run(
        [cc, "-shared", "-nostdlib", "-fPIC", str(src), "-o", str(so)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 or _target(so) is None:
        pytest.skip(f"the assembler control could not be built here: {proc.stderr[-300:]}")
    if gate.parse_binary(so).fmt != "ELF":
        pytest.skip("symbol sizes are an ELF property")
    assert "ama_orphan_export" in _exported_functions(so)
    assert "<orphan_internal>" in _listing(so, objdump), "the orphan jump was not assembled"
    assert tail_calls(so, objdump) == {}


def test_attribution_is_by_symbol_size(tmp_path: Path) -> None:
    """On ELF the export's body is bounded by its symbol size, so code the
    linker places after it (AArch64 erratum stubs) is not read as the
    export's. The control's table carries a nonzero size for the export."""
    built = _build_control(tmp_path, _CONTROL_DIRECT, [], sibling_calls=True)
    assert built is not None
    so, objdump = built
    ranges = _symbol_ranges(so, objdump)
    if gate.parse_binary(so).fmt == "Mach-O":
        assert ranges == {}, "Mach-O carries no symbol sizes"
        return
    export = next(name for name in ranges if name.lstrip("_") == "ama_control_export")
    start, size = ranges[export]
    assert size > 0
    bodies = [(start, size, export)]
    assert _owner_at(start, bodies) == export
    assert _owner_at(start + size - 1, bodies) == export
    assert _owner_at(start + size, bodies) is None


@pytest.mark.parametrize("sibling_calls", [True, False])
def test_the_scan_sees_a_got_indirect_tail_call(tmp_path: Path, sibling_calls: bool) -> None:
    """Under ``-fno-plt`` the tail call to libc is an indirect jump through
    the GOT, on x86-64 (``jmp *disp(%rip)``) and AArch64 (``ldr``/``br``
    through one register); both are reported, and the flag removes them."""
    built = _build_control(tmp_path, _CONTROL_GOT, ["-fno-plt"], sibling_calls)
    assert built is not None
    so, objdump = built
    calls = tail_calls(so, objdump)
    if sibling_calls:
        targets = calls.get("ama_got_export", set())
        assert targets, calls
        if _target(so) == "x86-64":
            assert any("memcpy" in t or "GOT slot" in t for t in targets), calls
    else:
        assert "ama_got_export" not in calls, calls
