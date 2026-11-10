# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Both directions for ``tools/check_ct_operand.py`` and its Valgrind tool.

The gate decides leakage class (c) of INVARIANT-12 — a secret-derived operand
reaching an instruction whose latency may depend on it — and it can be wrong
in four distinct places, each pinned here:

1. **The vendor lists.**  ``tools/ct_operand/allowlists.json`` must stay the
   transcription it claims to be: its sources named, its sizes those of the
   cross-checked extractions, and none of the variable-latency classes the
   documentation says the vendors exclude smuggled back in.
2. **Mnemonic normalisation.**  objdump spells some listed instructions
   differently from the vendor (string moves, REP, the SSE ``movsd`` that is
   NOT the listed string ``MOVSD``); a wrong rule passes or fails the wrong
   instruction.
3. **The verdict.**  A division, floating-point or square-root class on a
   tainted operand fails; so does an unlisted mnemonic (``--inventory`` only
   reports it); a branch-only site passes only when a bit-exact Memcheck run
   of the same driver reports nothing; an unresolvable site, an empty run or
   an unadjudicated branch is inconclusive, never a pass.
4. **The instrument itself.**  The Valgrind tool is built and run on a small
   program that feeds a secret to a divide, a double multiply, a square root
   and a multiply, and the same operations a public value: the report must
   carry exactly the right class on exactly the secret sites.
"""

from __future__ import annotations

import ast
import dataclasses
import importlib.util
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "check_ct_operand.py"
ALLOWLISTS = REPO_ROOT / "tools" / "ct_operand" / "allowlists.json"
DUDECT = REPO_ROOT / ".github" / "workflows" / "dudect.yml"


@pytest.fixture(scope="module")
def gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_ct_operand", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_ct_operand"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def ghash() -> ModuleType:
    path = REPO_ROOT / "tools" / "check_ghash_constant_time.py"
    spec = importlib.util.spec_from_file_location("check_ghash_constant_time", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# 1. The vendor lists
# ---------------------------------------------------------------------------


class TestAllowlists:
    data = json.loads(ALLOWLISTS.read_text(encoding="utf-8"))

    def test_each_list_names_its_source_and_how_it_was_read(self) -> None:
        for isa in ("x86_64", "aarch64"):
            source = self.data[isa]["source"]
            for key in ("publisher", "title", "url", "retrieved", "extraction"):
                assert source.get(key), f"{isa}: source.{key} missing"

    def test_the_lists_are_the_size_of_the_cross_checked_extractions(self) -> None:
        # 594: Intel Table 1, two independent reads agreeing exactly.
        # 651: Arm DIT (non-SME), first read, its four disputed entries
        # confirmed by a third read.
        assert len(self.data["x86_64"]["mnemonics"]) == 594
        assert len(self.data["aarch64"]["mnemonics"]) == 651
        for isa in ("x86_64", "aarch64"):
            names = self.data[isa]["mnemonics"]
            assert len(names) == len(set(names)), f"{isa}: duplicate entries"

    @pytest.mark.parametrize(
        ("isa", "absent"),
        [
            (
                "x86_64",
                [
                    "DIV",
                    "IDIV",
                    "DIVSD",
                    "DIVPS",
                    "VDIVPD",
                    "SQRTSD",
                    "SQRTPS",
                    "VSQRTPD",
                    "MULSD",
                    "ADDSD",
                    "CVTSI2SD",
                    "CVTTSD2SI",
                ],
            ),
            (
                "aarch64",
                ["SDIV", "UDIV", "FDIV", "FSQRT", "FMUL", "FADD", "FMADD", "SCVTF", "FCVTZS"],
            ),
        ],
    )
    def test_no_variable_latency_class_is_listed(self, isa: str, absent: list[str]) -> None:
        """The documentation says the vendors list no divide, no FP arithmetic
        and no square root; if an edit ever adds one, that sentence is false."""
        listed = set(self.data[isa]["mnemonics"])
        assert not listed & set(absent), sorted(listed & set(absent))

    def test_multiply_is_admitted_and_the_documentation_says_so(self) -> None:
        assert {"MUL", "IMUL", "MULX", "PMULUDQ"} <= set(self.data["x86_64"]["mnemonics"])
        assert {"MADD", "UMULH", "SMULH", "UMADDL"} <= set(self.data["aarch64"]["mnemonics"])
        assert "multiply" in self.data["variable_latency_classes"]

    def test_the_listed_movsd_is_the_string_move(self) -> None:
        assert "A5" in self.data["x86_64"]["opcode_notes"]["MOVSD"]
        assert "MOVSD" in self.data["x86_64"]["mnemonics"]

    def test_rep_entries_carry_the_count_footnote(self) -> None:
        for name in ("REP_MOVSB", "REP_STOSB"):
            assert name in self.data["x86_64"]["mnemonics"]
            assert "CX" in self.data["x86_64"]["footnotes"][name]


# ---------------------------------------------------------------------------
# 2. Mnemonic normalisation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("rep movs QWORD PTR es:[rdi],QWORD PTR ds:[rsi]", "REP_MOVSQ"),
        ("rep stos BYTE PTR es:[rdi],al", "REP_STOSB"),
        ("movs BYTE PTR es:[rdi],BYTE PTR ds:[rsi]", "MOVSB"),
        ("movs DWORD PTR es:[rdi],DWORD PTR ds:[rsi]", "MOVSD"),
        ("movsd  xmm0,QWORD PTR [rsp+0x8]", "MOVSD(SSE)"),
        ("lock add DWORD PTR [rip+0x10],0x1", "ADD"),
        ("notrack jmp rax", "JMP"),
        ("div    rcx", "DIV"),
        ("vpmuludq ymm0,ymm1,ymm2", "VPMULUDQ"),
        # objdump's selector-immediate aliases of PCLMULQDQ are one instruction.
        ("pclmullqlqdq xmm1,xmm2", "PCLMULQDQ"),
        ("pclmulhqhqdq xmm1,xmm2", "PCLMULQDQ"),
        ("pclmullqhqdq xmm1,xmm2", "PCLMULQDQ"),
        ("vpclmulhqlqdq ymm0,ymm1,ymm2", "VPCLMULQDQ"),
    ],
)
def test_x86_canonical(gate: ModuleType, text: str, expected: str) -> None:
    assert gate.x86_canonical(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("orr\tx0, xzr, x1", "ORR"),
        ("b.eq\t1234 <f+0x10>", "B"),
        ("cmphi\tp0.s, p1/z, z0.s, z1.s", "CMP"),
        ("udiv\tw0, w1, w2", "UDIV"),
    ],
)
def test_aarch64_canonical(gate: ModuleType, text: str, expected: str) -> None:
    assert gate.aarch64_canonical(text) == expected


@pytest.mark.skipif(
    platform.machine().lower() not in ("x86_64", "amd64") or not shutil.which("as"),
    reason="the spelling probes assemble x86-64 with GNU as",
)
def test_condition_code_synonyms_are_learned_from_the_assembler(
    gate: ModuleType, tmp_path: Path
) -> None:
    allowed, _ = gate.load_allowlist("x86_64")
    spellings = gate.derive_x86_spellings(allowed, tmp_path)
    # objdump prints the Z/E and NB/AE synonyms one way; whichever it is, it
    # must map back to a listed name, and MOV-with-imm64 prints as movabs.
    assert spellings.get("MOVABS") == "MOV"
    assert "CMOVZ" in spellings.values() and "SETNB" in spellings.values()
    assert all(listed in allowed for listed in spellings.values())


#: The shape GNU objdump prints for a MinGW (COFF) probe object: .text is
#: padded to its alignment, so `nop`s follow the last probe's instruction.
#: Pairing probes with lines by position read 39 lines for 33 probes on every
#: Windows pytest lane (2026-11-07); this fixture is that shape, so the rule is
#: held on every host, not only on one with an assembler.
_COFF_PROBE_DUMP = """
probe.o:     file format pe-x86-64

Disassembly of section .text:

0000000000000000 <ctprobe_0>:
   0:\tcmove  rax,rbx

0000000000000004 <ctprobe_1>:
   4:\tsete   al
   7:\tnop
   8:\tnop
   9:\tnop
"""


class TestProbeTexts:
    def test_section_padding_after_the_last_probe_is_ignored(self, gate: ModuleType) -> None:
        assert gate.probe_texts(_COFF_PROBE_DUMP, 2) == ["cmove  rax,rbx", "sete   al"]

    def test_a_missing_probe_is_refused(self, gate: ModuleType) -> None:
        with pytest.raises(RuntimeError, match=r"probe\(s\) \[2\]"):
            gate.probe_texts(_COFF_PROBE_DUMP, 3)

    def test_a_probe_that_is_not_one_instruction_is_refused(self, gate: ModuleType) -> None:
        dump = _COFF_PROBE_DUMP.replace(
            "   0:\tcmove  rax,rbx\n", "   0:\tcmove  rax,rbx\n   3:\tnop\n"
        )
        with pytest.raises(RuntimeError, match="exactly one instruction"):
            gate.probe_texts(dump, 2)

    def test_lines_under_another_symbol_are_not_read_as_a_probe(self, gate: ModuleType) -> None:
        # Between two probes, where it would otherwise count as a second
        # instruction of probe 0 and fail the one-instruction rule.
        dump = _COFF_PROBE_DUMP.replace(
            "\n0000000000000004 <ctprobe_1>:",
            "\n0000000000000003 <other>:\n   3:\tud2\n\n0000000000000004 <ctprobe_1>:",
        )
        assert gate.probe_texts(dump, 2) == ["cmove  rax,rbx", "sete   al"]


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX ownership and modes")
class TestToolCache:
    """The staged tool is executed, so its cache must be private to the caller."""

    def test_the_default_is_per_user_not_the_shared_temporary_directory(
        self, gate: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        assert gate.default_cache() == tmp_path / "xdg" / "ama-ctoperand"
        monkeypatch.delenv("XDG_CACHE_HOME")
        assert gate.default_cache() == Path.home() / ".cache" / "ama-ctoperand"
        assert Path(tempfile.gettempdir()) not in gate.default_cache().parents

    def test_a_new_cache_is_created_private(self, gate: ModuleType, tmp_path: Path) -> None:
        cache = tmp_path / "new" / "cache"
        gate._require_private_dir(cache)
        assert stat.S_IMODE(cache.stat().st_mode) & 0o077 == 0

    @pytest.mark.parametrize("where", ["cache", "stage"])
    def test_a_group_or_world_writable_directory_is_refused(
        self, gate: ModuleType, tmp_path: Path, where: str
    ) -> None:
        cache = tmp_path / "cache"
        stage = cache / "vglib-amd64-linux"
        stage.mkdir(parents=True, mode=0o700)
        cache.chmod(0o700)
        (cache if where == "cache" else stage).chmod(0o777)
        # Refused before Valgrind is looked up or anything staged is trusted.
        with pytest.raises(ValueError, match="writable by group or others"):
            gate.build_tool("x86_64", cache)

    def test_a_symlinked_stage_is_refused(self, gate: ModuleType, tmp_path: Path) -> None:
        cache = tmp_path / "cache"
        cache.mkdir(mode=0o700)
        elsewhere = tmp_path / "planted"
        elsewhere.mkdir(mode=0o700)
        (cache / "vglib-amd64-linux").symlink_to(elsewhere)
        with pytest.raises(ValueError, match="not a plain directory"):
            gate.build_tool("x86_64", cache)

    def test_another_users_directory_is_refused(
        self, gate: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache = tmp_path / "cache"
        cache.mkdir(mode=0o700)
        owner = cache.stat().st_uid
        monkeypatch.setattr(gate.os, "getuid", lambda: owner + 1)
        with pytest.raises(ValueError, match="owned by uid"):
            gate.build_tool("x86_64", cache)


_STATIC_PROBE = """
        .intel_syntax noprefix
        .text
        .globl static_probe
static_probe:
        endbr64
        vpxor   ymm0, ymm1, ymm2
        vpshufb ymm3, ymm4, ymm5
        test    rdi, rdi
        jne     1f
        nop
        xchg    ax, ax
        vmovaps ymm0, YMMWORD PTR [rsp]
1:      ret
"""


@pytest.mark.skipif(
    platform.machine().lower() not in ("x86_64", "amd64") or not shutil.which("as"),
    reason="assembles an x86-64 probe with GNU as",
)
class TestStaticListing:
    """The AVX-512/VAES lane: no taint, every instruction held to the list."""

    def test_only_the_unlisted_data_instruction_is_reported(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        src = tmp_path / "probe.s"
        obj = tmp_path / "probe.o"
        src.write_text(_STATIC_PROBE, encoding="utf-8")
        subprocess.run(["as", "-o", str(obj), str(src)], check=True)
        allowed, _ = gate.load_allowlist("x86_64")
        spell_dir = tmp_path / "spellings"
        spell_dir.mkdir()
        counts, bad = gate.static_listing(
            [obj], allowed, gate.derive_x86_spellings(allowed, spell_dir)
        )
        # The listed SIMD logic, the control transfers and the padding pass;
        # the FP-domain move clang emitted for a stack copy of round keys
        # (src/c/avx2/ama_aes_gcm_vaes_avx2.c) does not.
        assert [name for _, name, _ in bad] == ["VMOVAPS"], bad
        assert {"VPXOR", "VPSHUFB", "JNE", "RET", "NOP", "ENDBR64"} <= set(counts)

    def test_a_missing_member_is_inconclusive(self, gate: ModuleType, tmp_path: Path) -> None:
        archive = tmp_path / "lib.a"
        obj = tmp_path / "probe.o"
        src = tmp_path / "probe.s"
        src.write_text(_STATIC_PROBE, encoding="utf-8")
        subprocess.run(["as", "-o", str(obj), str(src)], check=True)
        subprocess.run(["ar", "rcs", str(archive), str(obj)], check=True)
        status = gate.main(
            ["--static", "--lib", str(archive), "--member", "ama_sha3_x4_avx512.c.o"]
        )
        assert status == 2


# ---------------------------------------------------------------------------
# 3. IR classes and the verdict
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("Iop_DivModU128to64", "DIV"),
        ("Iop_DivU64", "DIV"),
        ("Iop_Div64Fx2", "DIV"),
        ("Iop_SqrtF64", "SQRT"),
        ("Iop_RSqrtEst32Fx4", "SQRT"),
        ("Iop_MulF64", "FP"),
        ("Iop_Add32Fx4", "FP"),
        ("Iop_I64StoF64", "FP"),
        ("Iop_F32toI32Sx4_RZ", "FP"),
        ("Iop_RoundF64toIntE", "FP"),
        # Width-less conversions out of FP: not spelled this way by any VEX
        # release through 3.26, but the table follows the installed header.
        ("Iop_FtoI32Sx4_RZ", "FP"),
        ("Iop_FtoI32Ux4_RZ", "FP"),
        ("Iop_QFtoI32Sx4_RZ", "FP"),
        ("Iop_ReinterpF64asI64", None),
        ("Iop_CmpORD32U", None),
        ("Iop_MullU64", None),
        ("Iop_Add64", None),
        ("Iop_Perm8x16", None),
    ],
)
def test_op_class(gate: ModuleType, name: str, expected: str | None) -> None:
    assert gate.op_class(name) == expected


@pytest.mark.requires_memcheck
def test_the_generated_class_table_is_nonempty_for_the_installed_vex(gate: ModuleType) -> None:
    header = Path("/usr/include/valgrind/libvex_ir.h")
    if not header.is_file():
        pytest.skip("Valgrind tool headers are not installed")
    text, counts = gate.generate_opclass_header(header)
    assert all(counts[c] > 0 for c in gate.BLOCKING_CLASSES), counts
    assert "case Iop_DivModU128to64:" in text and "case Iop_MullU64:" not in text


def _report(sites: list[str]) -> str:
    body = "\n".join(sites)
    count = sum(1 for line in sites if line.startswith("site "))
    return (
        "ctoperand 3\ntainted_bytes 32\ntaint_requests 1\ndeclassified_bytes 0\n"
        f"consumptions 10\nsuperblocks 5\nsites {count}\n{body}\nend\n"
    )


def _classify(gate: ModuleType, text: str, table: dict[int, str]) -> Any:
    report = gate.parse_report(text)
    for site in report.sites:
        site.file_offset = site.ip  # identity mapping for the synthetic object
    return gate.classify(
        report, "x86_64", {"MOV", "DIV", "IMUL"}, {}, set(), disassembly={"obj": table}
    )


@pytest.mark.parametrize(
    ("bits", "expected"),
    [
        (["BRANCH"], True),
        (["BRANCH", "OTHER"], False),
        (["OTHER"], False),
        ([], False),
        (["BRANCH", "DIV"], True),
    ],
)
def test_only_a_pure_branch_is_labelled_class_a(
    gate: ModuleType, bits: list[str], expected: bool
) -> None:
    """An unlisted instruction whose result also reaches a register or memory
    keeps an operand-latency question; only a pure branch defers to Memcheck."""
    value = sum(gate.CLASS_BITS[b] for b in bits)
    assert gate.is_branch_only(value) is expected


class TestVerdict:
    def test_a_report_must_be_complete(self, gate: ModuleType) -> None:
        with pytest.raises(ValueError):
            gate.parse_report("ctoperand 3\ntainted_bytes 1\n")
        with pytest.raises(ValueError):
            gate.parse_report("ctoperand 1\nend\n")
        with pytest.raises(ValueError):
            gate.parse_report(_report([]).replace("sites 0", "sites 3"))

    def test_a_division_class_blocks(
        self, gate: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(gate, "load_segments", lambda obj: [(0, 0, 1 << 20)])
        verdict = _classify(
            gate,
            _report(["site 0x10 4 0x10 0x1 obj", "  at f"]),
            {0x10: "f+0x0\tdiv    rcx"},
        )
        assert [name for _, name, _ in verdict.class_violations] == ["DIV"]

    def test_an_unlisted_mnemonic_is_inventoried_not_blocking(
        self, gate: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(gate, "load_segments", lambda obj: [(0, 0, 1 << 20)])
        verdict = _classify(
            gate,
            _report(["site 0x20 1 0x20 0x0 obj", "  at f"]),
            {0x20: "f+0x0\tcwde"},
        )
        assert not verdict.class_violations
        assert [name for _, name, _ in verdict.unlisted] == ["CWDE"]

    def test_a_listed_multiply_is_neither(
        self, gate: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(gate, "load_segments", lambda obj: [(0, 0, 1 << 20)])
        verdict = _classify(
            gate,
            _report(["site 0x30 1 0x30 0x0 obj", "  at f"]),
            {0x30: "f+0x0\timul   rax,rbx"},
        )
        assert not verdict.class_violations and not verdict.unlisted

    def test_a_site_that_cannot_be_disassembled_is_unresolved(
        self, gate: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(gate, "load_segments", lambda obj: [(0, 0, 1 << 20)])
        verdict = _classify(gate, _report(["site 0x40 1 0x40 0x0 obj", "  at f"]), {})
        assert len(verdict.unresolved) == 1

    def test_the_outcome_rule(self, gate: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(gate, "load_segments", lambda obj: [(0, 0, 1 << 20)])
        bits = gate.CLASS_BITS

        def verdict(mnemonic: str, classes: int) -> Any:
            return _classify(
                gate,
                _report([f"site 0x50 1 0x50 {classes:#x} obj", "  at f"]),
                {0x50: f"f+0x0\t{mnemonic}"},
            )

        listed = verdict("imul   rax,rbx", bits["OTHER"])
        unlisted = verdict("cwde", bits["OTHER"])
        branch = verdict("je     10 <f>", bits["BRANCH"])
        division = verdict("div    rcx", bits["DIV"] | bits["OTHER"])
        assert gate.outcome(listed, None, False)[0] == 0
        assert gate.outcome(division, None, True)[0] == 1
        # An unlisted mnemonic blocks; --inventory reports it and passes.
        assert gate.outcome(unlisted, None, False)[0] == 1
        assert gate.outcome(unlisted, None, True)[0] == 0
        # A branch-only site is decided by Memcheck, never by its label.
        assert gate.outcome(branch, None, False)[0] == 2
        assert gate.outcome(branch, 0, False)[0] == 0
        assert gate.outcome(branch, 3, False)[0] == 1
        assert gate.outcome(branch, 3, True)[0] == 1

    def test_a_missing_library_is_inconclusive(self, gate: ModuleType, tmp_path: Path) -> None:
        assert gate.main(["--lib", str(tmp_path / "absent.a"), "--target", "x25519"]) == 2

    def test_deny_may_only_narrow_the_list(self, gate: ModuleType, tmp_path: Path) -> None:
        lib = tmp_path / "lib.a"
        lib.write_bytes(b"")
        assert gate.main(["--lib", str(lib), "--target", "x25519", "--deny", "NOTAMNEMONIC"]) == 2


_A64_STATIC_PROBE = """
        .arch armv9-a+sve2
        .text
        .globl admitted
        .type admitted, %function
admitted:
        bti     c
        add     x0, x1, x2
        ld1h    z0.h, p0/z, [x1]
        add     z0.h, z0.h, z1.h
        ptrue   p0.h
        pfalse  p1.b
        cnth    x3
        rdvl    x4, #1
        adrp    x5, admitted
        movz    w9, #0x2001
        movz    w3, #0x1
        movk    w9, #0x380, lsl #16
        movn    x10, #0x0
        movk    x10, #0x380, lsl #48
        cbz     x0, 1f
        subs    x0, x0, #1
        b.ne    1f
1:      ret
        .size admitted, .-admitted

        .globl refused
        .type refused, %function
refused:
        movk    w9, #0x1
        udiv    w0, w1, w2
        whilelt p0.h, x1, x2
        cntp    x0, p0, p0.h
        fmov    w0, s0
        movz    w9, #0x1
        add     w9, w9, w1
        movk    w9, #0x2, lsl #16
        movz    w11, #0x1
        bl      admitted
        movk    w11, #0x2, lsl #16
        movz    w12, #0x1
2:      movk    w12, #0x2, lsl #16
        subs    x0, x0, #1
        b.ne    2b
        movz    w13, #0x1
        orr     x14, xzr, x13
        movk    x13, #0x2, lsl #16
        ret
        .size refused, .-refused
"""


def _aarch64_cc() -> str | None:
    """A compiler that targets AArch64 ELF: the native one or the cross one."""
    if sys.platform.startswith("linux") and platform.machine().lower() in ("aarch64", "arm64"):
        return shutil.which("cc") or shutil.which("gcc")
    return shutil.which("aarch64-linux-gnu-gcc")


@pytest.mark.requires_aarch64_toolchain
class TestStaticListingAArch64:
    """The SVE2 lane: Valgrind cannot execute SVE, so the kernels are held to
    Arm's DIT list by reading them.

    The rule is the x86-64 one with two additions an AArch64 listing needs,
    and each is held here from both sides.  Instructions that read no register
    (an immediate, a page address, a constant predicate, the vector length)
    have no row on the list and are admitted by name.  MOVK reads the register
    it completes, and is admitted only where that register still holds the
    immediate a MOVZ or MOVN wrote: refused with no such instruction before
    it, after one whose register has since been named, across a call, at a
    branch target, and after its register was read under its other width.
    """

    def _listing(self, gate: ModuleType, tmp_path: Path) -> tuple[dict[str, int], list[str]]:
        compiler = _aarch64_cc()
        objdump = gate.objdump_for("aarch64")
        if compiler is None or objdump is None:
            pytest.skip("no AArch64 compiler and disassembler on this host")
        src = tmp_path / "probe.s"
        obj = tmp_path / "probe.o"
        src.write_text(_A64_STATIC_PROBE, encoding="utf-8")
        subprocess.run([compiler, "-c", "-o", str(obj), str(src)], check=True)
        assert gate.object_isa(obj) == "aarch64"
        allowed, _ = gate.load_allowlist("aarch64")
        counts, bad = gate.static_listing([obj], allowed, {}, "aarch64", objdump)
        return counts, [text.split()[0] + " " + text.split()[1] for _, _, text in bad]

    def test_what_is_admitted_and_what_is_refused(self, gate: ModuleType, tmp_path: Path) -> None:
        counts, bad = self._listing(gate, tmp_path)
        # Nothing in `admitted`; in `refused`, the five instructions that take
        # register data and are not listed, and every MOVK whose register is
        # not known to hold an immediate, in source order.
        assert bad == [
            "movk w9,",
            "udiv w0,",
            "whilelt p0.h,",
            "cntp x0,",
            "fmov w0,",
            "movk w9,",
            "movk w11,",
            "movk w12,",
            "movk x13,",
        ], bad
        assert {"HINT", "PTRUE", "PFALSE", "CNTH", "RDVL", "ADRP", "MOVZ", "MOVN"} <= set(counts)
        assert counts["MOVK"] == 7

    def test_the_archive_is_listed_against_its_own_architecture(
        self, gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """--static reads the ISA from the members, not from the host: the
        same command lists an AArch64 archive on an x86-64 host that has the
        cross binutils, and refuses rather than guess where it cannot."""
        compiler = _aarch64_cc()
        if compiler is None or gate.objdump_for("aarch64") is None:
            pytest.skip("no AArch64 compiler and disassembler on this host")
        src = tmp_path / "probe.s"
        obj = tmp_path / "probe.o"
        archive = tmp_path / "lib.a"
        src.write_text(_A64_STATIC_PROBE, encoding="utf-8")
        subprocess.run([compiler, "-c", "-o", str(obj), str(src)], check=True)
        subprocess.run(["ar", "rcs", str(archive), str(obj)], check=True)
        assert gate.main(["--static", "--lib", str(archive), "--member", "probe.o"]) == 1
        out = capsys.readouterr().out
        assert "(aarch64)" in out and "9 instruction(s) are neither" in out
        junk = tmp_path / "junk.o"
        junk.write_bytes(b"not an object")
        subprocess.run(["ar", "rcs", str(tmp_path / "junk.a"), str(junk)], check=True)
        assert gate.main(["--static", "--lib", str(tmp_path / "junk.a"), "--member", "junk.o"]) == 2


# ---------------------------------------------------------------------------
# 4. The instrument itself
# ---------------------------------------------------------------------------

_PROBE = r"""
#include <stdint.h>
#include <valgrind/memcheck.h>
__attribute__((noinline)) uint64_t f_div(uint64_t a, uint64_t b) { return a / b; }
__attribute__((noinline)) double f_fp(int64_t a, double s) { return (double)a * s; }
__attribute__((noinline)) double f_sqrt(double a) { return __builtin_sqrt(a); }
__attribute__((noinline)) uint64_t f_mul(uint64_t a, uint64_t b) { return a * b; }
__attribute__((noinline)) uint64_t g_div(uint64_t a, uint64_t b) { return a / b; }
__attribute__((noinline)) int h_branch(uint64_t a, uint64_t b) {
    int r;
    __asm__ volatile("cmp %1, %2\n\tje 1f\n\tjbe 1f\n\tmov $0, %0\n\tjmp 2f\n"
                     "1: mov $1, %0\n2:\n" : "=r"(r) : "r"(a), "r"(b) : "cc");
    return r;
}
/* rax holds the secret, then `or $-1` makes it a constant: the divide that
 * follows has public operands only (gcc 14 builds UINT64_MAX this way before
 * dividing by a public modulus in src/c/ama_argon2.c). */
__attribute__((noinline)) uint64_t k_ones_div(uint64_t a, uint64_t d) {
    uint64_t q;
    __asm__ volatile("mov %1, %%rax\n\tor $-1, %%rax\n\txor %%edx, %%edx\n\tdiv %2\n\tmov %%rax, %0"
                     : "=r"(q) : "r"(a), "r"(d) : "rax", "rdx", "cc");
    return q;
}
int main(void) {
    volatile uint64_t seed = 12345, seven = 7;
    volatile double scale = 1.5;
    uint64_t secret = seed, declassified = seed;
    VALGRIND_MAKE_MEM_UNDEFINED(&secret, sizeof secret);
    VALGRIND_MAKE_MEM_UNDEFINED(&declassified, sizeof declassified);
    VALGRIND_MAKE_MEM_DEFINED(&declassified, sizeof declassified);
    volatile uint64_t r1 = f_div(secret, seven);
    volatile double r2 = f_fp((int64_t)secret, scale);
    volatile double r3 = f_sqrt(r2);
    volatile uint64_t r4 = f_mul(secret, seven);
    volatile uint64_t r5 = g_div(declassified, seven);
    volatile int r6 = h_branch(secret, seven);
    volatile uint64_t r7 = k_ones_div(secret, seven);
    (void)r1; (void)r2; (void)r3; (void)r4; (void)r5; (void)r6; (void)r7;
    return 0;
}
"""


_ENCODINGS = {"sse": ["-mno-avx"], "vex": ["-mavx"]}


@pytest.mark.requires_memcheck
@pytest.mark.requires_host_isa("x86-64")
@pytest.mark.skipif(
    platform.machine().lower() not in ("x86_64", "amd64"),
    reason="the probe is written for the x86-64 lifting",
)
def test_a_reported_site_is_explained_by_its_own_ir(gate: ModuleType, tmp_path: Path) -> None:
    """`--ct-dump-ir-at` prints the statements under the reported instruction's
    IMark, and only that instruction's: what a reviewer needs when a site's
    mnemonic takes no data operand (the first AArch64 run reported an `mrs` of
    DCZID_EL0, which VEX lifts to a constant PUT).  The site's own IMark opens
    the dump and the dump stops at the next one."""
    if (
        not shutil.which("valgrind")
        or not Path("/usr/include/valgrind/pub_tool_tooliface.h").is_file()
    ):
        pytest.skip("valgrind or its tool headers are not installed")
    stage = gate.build_tool("x86_64", tmp_path / "cache")
    src = tmp_path / "probe.c"
    exe = tmp_path / "probe"
    src.write_text(_PROBE, encoding="utf-8")
    subprocess.run(["gcc", "-O2", "-g", "-mno-avx", str(src), "-o", str(exe), "-lm"], check=True)
    text = gate.run_tool(stage, exe, {"PATH": "/usr/bin:/bin"}, tmp_path)
    assert text is not None
    report = gate.parse_report(text)
    allowed, _ = gate.load_allowlist("x86_64")
    gate.classify(report, "x86_64", allowed, gate.derive_x86_spellings(allowed, tmp_path), set())
    site = next(
        s
        for s in report.sites
        if s.symbol.startswith("f_div+") and "DIV" in gate.class_names(s.classes)
    )
    lines = gate.explain_sites(stage, exe, {"PATH": "/usr/bin:/bin"}, tmp_path, [site.ip])
    assert lines, "the explainer printed nothing for a reported site"
    assert lines[0] == f"ctoperand-ir-begin 0x{site.ip:x}"
    marks = [line for line in lines if "IMark(" in line]
    assert int(marks[0].split("IMark(")[1].split(",")[0], 16) == site.ip
    assert len(marks) == 2, "the dump runs past the next instruction's IMark"
    # ... and nothing of the next instruction is printed after its IMark.
    assert "IMark(" in lines[-2], "the dump continued past the next instruction's IMark"
    assert any("DivMod" in line or "Div" in line for line in lines), lines
    assert lines[-1] == "ctoperand-ir-end"


@pytest.mark.requires_memcheck
@pytest.mark.requires_host_isa("x86-64")
@pytest.mark.skipif(
    platform.machine().lower() not in ("x86_64", "amd64"),
    reason="the probe's expectations are written for the x86-64 lifting",
)
@pytest.mark.parametrize("encoding", sorted(_ENCODINGS))
def test_the_tool_reports_each_class_on_the_secret_sites_only(
    gate: ModuleType, tmp_path: Path, encoding: str
) -> None:
    if (
        not shutil.which("valgrind")
        or not Path("/usr/include/valgrind/pub_tool_tooliface.h").is_file()
    ):
        pytest.skip("valgrind or its tool headers are not installed")
    stage = gate.build_tool("x86_64", tmp_path / "cache")
    src = tmp_path / "probe.c"
    exe = tmp_path / "probe"
    src.write_text(_PROBE, encoding="utf-8")
    # Both encodings on every host, each selected explicitly: CI's Ubuntu 26.04
    # gcc emits the VEX forms (vmulsd, vsqrtsd ...) with no flag at all, so an
    # empty flag list would make both cases VEX and leave SSE lifting untested.
    subprocess.run(
        ["gcc", "-O2", "-g", *_ENCODINGS[encoding], str(src), "-o", str(exe), "-lm"], check=True
    )
    text = gate.run_tool(stage, exe, {"PATH": "/usr/bin:/bin"}, tmp_path)
    assert text is not None
    report = gate.parse_report(text)
    allowed, _ = gate.load_allowlist("x86_64")
    verdict = gate.classify(
        report, "x86_64", allowed, gate.derive_x86_spellings(allowed, tmp_path), set()
    )

    def classes_in(function: str) -> set[str]:
        found: set[str] = set()
        for site in report.sites:
            if site.symbol.startswith(function + "+"):
                found.update(gate.class_names(site.classes))
        return found

    assert report.header["tainted_bytes"] == 16
    assert "DIV" in classes_in("f_div")
    assert "FP" in classes_in("f_fp")
    assert "SQRT" in classes_in("f_sqrt")
    # Admitted by the vendor list: consumed, but in no blocking class.
    assert any(s.symbol.startswith("f_mul+") for s in report.sites)
    assert not classes_in("f_mul") & {"DIV", "FP", "SQRT"}
    # A declassified value is public again: its divide is not recorded at all.
    assert not any(s.symbol.startswith("g_div+") for s in report.sites)
    # A conditional jump on the secret is BRANCH and nothing else; the `cmp`
    # feeding it writes the flags, which is a non-branch use (OTHER).
    jumps = [
        s
        for s in report.sites
        if s.symbol.startswith("h_branch+") and s.classes & gate.CLASS_BITS["BRANCH"]
    ]
    assert len(jumps) == 2 and all(gate.is_branch_only(s.classes) for s in jumps), [
        (s.symbol, gate.class_names(s.classes)) for s in jumps
    ]
    compare = [
        s
        for s in report.sites
        if s.symbol.startswith("h_branch+") and not s.classes & gate.CLASS_BITS["BRANCH"]
    ]
    assert compare and all(s.classes & gate.CLASS_BITS["OTHER"] for s in compare)
    # The verdict, by function and class rather than by mnemonic: which
    # encoding carries the operation (SSE `mulsd` or VEX `vmulsd`) is the
    # compiler's choice -- CI's Ubuntu 26.04 toolchain emits the VEX forms --
    # and the gate's blocking rule is the IR class, so that is what is held.
    blocking: dict[str, set[str]] = {}
    for site, _, _ in verdict.class_violations:
        function = site.symbol.split("+", 1)[0]
        blocking.setdefault(function, set()).update(
            c for c in gate.class_names(site.classes) if c in gate.BLOCKING_CLASSES
        )
    assert "DIV" in blocking.get("f_div", set()), blocking
    assert "FP" in blocking.get("f_fp", set()), blocking
    assert "SQRT" in blocking.get("f_sqrt", set()), blocking
    # k_ones_div divides only after `or $-1` replaced the secret in rax.
    assert not {"f_mul", "g_div", "h_branch", "k_ones_div"} & set(blocking), blocking
    # Each case ran the encoding it is named for -- held against the NAME, not
    # the flags, so a wrong flag fails here: every blocking FP or SQRT
    # instruction is VEX (V-prefixed) in "vex" and none is in "sse".
    fp_mnemonics = {
        mnemonic
        for site, mnemonic, _ in verdict.class_violations
        if site.symbol.split("+", 1)[0] in ("f_fp", "f_sqrt")
    }
    assert fp_mnemonics, verdict.class_violations
    vex = {m for m in fp_mnemonics if m.startswith("V")}
    assert vex == (fp_mnemonics if encoding == "vex" else set()), fp_mnemonics


_PACKED_PROBE = r"""
#include <stdint.h>
#include <valgrind/memcheck.h>
#if defined(__AVX__)
#define V "v"
#else
#define V ""
#endif
/* One instruction per function, named in the source: which conversion the
 * compiler would have chosen is not what is being measured. */
#define PACKED(name, insn)                                                          \
    __attribute__((noinline)) void name(const void *in, void *out) {               \
        __asm__ volatile(V "movdqu (%0), %%xmm0\n\t" V insn " %%xmm0, %%xmm1\n\t"  \
                         V "movdqu %%xmm1, (%1)"                                   \
                         : : "r"(in), "r"(out) : "xmm0", "xmm1", "memory");        \
    }
PACKED(p_cvttps2dq, "cvttps2dq")
PACKED(p_cvtps2dq, "cvtps2dq")
PACKED(p_cvtdq2ps, "cvtdq2ps")
PACKED(p_cvttpd2dq, "cvttpd2dq")
PACKED(p_cvtpd2dq, "cvtpd2dq")
PACKED(p_cvtdq2pd, "cvtdq2pd")
PACKED(p_cvtps2pd, "cvtps2pd")
PACKED(p_cvtpd2ps, "cvtpd2ps")
PACKED(q_public, "cvttps2dq")
int main(void) {
    static float fsec[4] = { 1.5f, 2.5f, -3.5f, 4.0f }, fpub[4] = { 1.0f, 2.0f, 3.0f, 4.0f };
    static double dsec[2] = { 1.5, -2.5 };
    static int32_t isec[4] = { 1, -2, 3, 4 };
    static uint8_t out[9][16];
    VALGRIND_MAKE_MEM_UNDEFINED(fsec, sizeof fsec);
    VALGRIND_MAKE_MEM_UNDEFINED(dsec, sizeof dsec);
    VALGRIND_MAKE_MEM_UNDEFINED(isec, sizeof isec);
    p_cvttps2dq(fsec, out[0]);
    p_cvtps2dq(fsec, out[1]);
    p_cvtdq2ps(isec, out[2]);
    p_cvttpd2dq(dsec, out[3]);
    p_cvtpd2dq(dsec, out[4]);
    p_cvtdq2pd(isec, out[5]);
    p_cvtps2pd(fsec, out[6]);
    p_cvtpd2ps(dsec, out[7]);
    q_public(fpub, out[8]);
    return 0;
}
"""

_PACKED_CONVERSIONS = (
    "cvttps2dq",
    "cvtps2dq",
    "cvtdq2ps",
    "cvttpd2dq",
    "cvtpd2dq",
    "cvtdq2pd",
    "cvtps2pd",
    "cvtpd2ps",
)


@pytest.mark.requires_memcheck
@pytest.mark.requires_host_isa("x86-64")
@pytest.mark.skipif(
    platform.machine().lower() not in ("x86_64", "amd64"),
    reason="the probe's expectations are written for the x86-64 lifting",
)
@pytest.mark.parametrize("encoding", sorted(_ENCODINGS))
def test_a_packed_conversion_of_a_secret_is_a_blocking_fp_site(
    gate: ModuleType, tmp_path: Path, encoding: str
) -> None:
    """Every packed float/integer conversion on a secret is reported FP, and
    blocks; the same instruction on a public value is not recorded.

    ``test_op_class`` holds the NAME rule to the packed spellings.  This is
    the instrument end of the same question: the instruction is executed, VEX
    lifts it to whichever operations the installed release uses (3.22:
    ``F32toI32Sx4`` and ``I32StoF32x4`` for the single-precision pairs, the
    scalar ``F64toI32S``, ``I32StoF64``, ``F32toF64`` and ``F64toF32`` lane by
    lane for the rest), and the site must come out FP whatever they are.
    ``_PROBE`` cannot stand in for it: its one conversion, ``cvtsi2sd``, sits
    in a function that multiplies as well, so that function is FP with or
    without the conversion's class.  Mutation, 2026-11-10: with ``op_class``
    made to return ``None`` for the conversion operations, this test fails in
    both encodings and ``test_the_tool_reports_each_class_on_the_secret_sites
    _only`` still passes.
    """
    if (
        not shutil.which("valgrind")
        or not Path("/usr/include/valgrind/pub_tool_tooliface.h").is_file()
    ):
        pytest.skip("valgrind or its tool headers are not installed")
    stage = gate.build_tool("x86_64", tmp_path / "cache")
    src = tmp_path / "packed.c"
    exe = tmp_path / "packed"
    src.write_text(_PACKED_PROBE, encoding="utf-8")
    subprocess.run(
        ["gcc", "-O2", "-g", *_ENCODINGS[encoding], str(src), "-o", str(exe)], check=True
    )
    text = gate.run_tool(stage, exe, {"PATH": "/usr/bin:/bin"}, tmp_path)
    assert text is not None
    report = gate.parse_report(text)
    allowed, _ = gate.load_allowlist("x86_64")
    verdict = gate.classify(
        report, "x86_64", allowed, gate.derive_x86_spellings(allowed, tmp_path), set()
    )
    assert report.header["tainted_bytes"] == 48
    blocking: dict[str, set[tuple[str, str]]] = {}
    for site, mnemonic, _ in verdict.class_violations:
        blocking.setdefault(site.symbol.split("+", 1)[0], set()).update(
            (mnemonic, c) for c in gate.class_names(site.classes) if c in gate.BLOCKING_CLASSES
        )
    # The conversion itself is what blocks, in the encoding the case names,
    # and for the class FP alone; the loads and stores around it do not.
    prefix = "V" if encoding == "vex" else ""
    assert blocking == {
        f"p_{name}": {(prefix + name.upper(), "FP")} for name in _PACKED_CONVERSIONS
    }, blocking
    assert not any(s.symbol.startswith("q_public+") for s in report.sites)


@pytest.mark.requires_memcheck
@pytest.mark.requires_host_isa("x86-64")
@pytest.mark.skipif(
    platform.machine().lower() not in ("x86_64", "amd64"),
    reason="the probe's expectations are written for the x86-64 lifting",
)
def test_a_secret_branch_fails_through_the_memcheck_adjudication(
    gate: ModuleType, ghash: ModuleType, tmp_path: Path
) -> None:
    """The probe's h_branch jumps on the secret.  The operand tool labels the
    two jumps branch-only; the gate must not pass them on that label: the
    bit-exact Memcheck run of the same program reports the jump, and the
    outcome is a failure."""
    if not shutil.which("valgrind") or not Path("/usr/include/valgrind/memcheck.h").is_file():
        pytest.skip("valgrind or its headers are not installed")
    stage = gate.build_tool("x86_64", tmp_path / "cache")
    src = tmp_path / "probe.c"
    exe = tmp_path / "probe"
    src.write_text(_PROBE, encoding="utf-8")
    subprocess.run(["gcc", "-O2", "-g", str(src), "-o", str(exe), "-lm"], check=True)
    text = gate.run_tool(stage, exe, {"PATH": "/usr/bin:/bin"}, tmp_path)
    assert text is not None
    allowed, _ = gate.load_allowlist("x86_64")
    verdict = gate.classify(
        gate.parse_report(text),
        "x86_64",
        allowed,
        gate.derive_x86_spellings(allowed, tmp_path),
        {"DIV", "IMUL"} & allowed,
    )
    branch_only = [v for v in verdict.unlisted if gate.is_branch_only(v[0].classes)]
    # h_branch's two jumps -- and gcc's errno check in the inlined sqrt of
    # f_sqrt (UCOMISD; JA), which branches on the same secret.
    assert "h_branch" in {v[0].symbol.split("+", 1)[0] for v in branch_only}, branch_only
    memcheck = ghash._run_taint(exe, tmp_path)
    assert memcheck is not None and memcheck[0] > 0, memcheck
    # The probe also divides by the secret, which fails first; drop those
    # sites so what is held is the branch rule on the probe's real sites.
    branches_alone = dataclasses.replace(verdict, class_violations=[])
    status, reason = gate.outcome(branches_alone, memcheck[0], inventory=False)
    assert status == 1 and "Memcheck" in reason, reason
    assert gate.outcome(branches_alone, None, inventory=False)[0] == 2


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------


def _job(name: str = "secret-operand-check") -> dict[str, Any]:
    workflow = yaml.safe_load(DUDECT.read_text(encoding="utf-8"))
    job: dict[str, Any] = workflow["jobs"][name]
    return job


def _archive_loops(job: dict[str, Any]) -> list[set[str]]:
    """The target set of every `for target in ...` loop over the test archive."""
    loops = []
    for step in job["steps"]:
        run = step.get("run", "")
        if "libama_cryptography_test.a" not in run or "check_ct_operand" not in run:
            continue
        match = re.search(r"for target in (.*?); do", run.replace("\\\n", " "), re.S)
        if match:
            loops.append(set(match.group(1).split()))
    return loops


def test_the_dudect_workflow_runs_every_taint_driver_through_the_gate(
    gate: ModuleType, ghash: ModuleType
) -> None:
    """Every taint driver and every operand-only driver, under gcc AND clang.

    Two archive loops: the gcc build, and the clang build -- clang's
    execution-domain pass picks encodings gcc does not, and the macOS wheels
    are clang-built, so a target measured only under gcc is half measured."""
    every = set(ghash._TAINT_DRIVERS) | set(gate._OPERAND_ONLY_DRIVERS)
    loops = _archive_loops(_job())
    assert len(loops) == 2, f"expected a gcc and a clang archive loop, found {len(loops)}"
    for looped in loops:
        missing = sorted(every - looped)
        assert not missing, f"drivers an x86-64 archive loop never runs: {missing}"
    text = "\n".join(step.get("run", "") for step in _job()["steps"])
    assert "--cc clang" in text
    assert "--dispatch-only aes-gcm-aesni" in text, "the AES-NI GCM tier is never pinned"


def test_the_aarch64_job_runs_every_driver_against_the_dit_list(
    gate: ModuleType, ghash: ModuleType
) -> None:
    """The AArch64 lane, natively on ubuntu-24.04-arm.  ed25519-sign-sse2fold
    is the one driver it does not run: it forces the x86 SSE2 niels-select
    fold, which an AArch64 build does not contain, so there it would measure
    ed25519-sign a second time."""
    job = _job("secret-operand-check-arm64")
    assert job["runs-on"] == "ubuntu-24.04-arm"
    loops = _archive_loops(job)
    assert len(loops) == 1
    missing = sorted(
        (set(ghash._TAINT_DRIVERS) | set(gate._OPERAND_ONLY_DRIVERS))
        - {"ed25519-sign-sse2fold"}
        - loops[0]
    )
    assert not missing, f"drivers the AArch64 lane never runs: {missing}"


def test_the_avx512_and_vaes_kernels_get_the_static_listing() -> None:
    runs = "\n".join(step.get("run", "") for step in _job()["steps"])
    assert "--static" in runs and "-DAMA_ENABLE_AVX512=ON" in runs
    for member in ("ama_sha3_x4_avx512.c.o", "ama_aes_gcm_vaes_avx2.c.o"):
        assert f"--member {member}" in runs, member
    assert "for cc in gcc clang" in runs


def test_the_sve2_kernels_get_the_static_listing() -> None:
    """Valgrind executes no SVE, so the AArch64 job reads the SVE2 objects
    instead: every file of ``src/c/sve2`` is a member of the listing, under
    both compilers, from an archive built with the kernels in it and without
    LTO (an LTO object holds no machine code to read)."""
    runs = "\n".join(step.get("run", "") for step in _job("secret-operand-check-arm64")["steps"])
    listing = next(
        block for block in runs.split("set -euo pipefail") if "-DAMA_ENABLE_SVE2=ON" in block
    )
    assert "--static" in listing and "-DAMA_ENABLE_LTO=OFF" in listing
    assert "for cc in gcc clang" in listing
    sources = sorted(path.name for path in (REPO_ROOT / "src" / "c" / "sve2").glob("*.c"))
    assert len(sources) == 8, sources
    assert sorted(re.findall(r"--member (\S+)\.o\b", listing)) == sources
    cmake = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    flags = cmake.split("set_source_files_properties(${AMA_SVE2_SOURCES} PROPERTIES", 1)[1]
    assert "-fno-tree-vectorize -fno-tree-slp-vectorize" in flags.split(")", 1)[0]


def test_the_gate_also_measures_the_shipped_shared_object() -> None:
    runs = [step.get("run", "") for step in _job()["steps"]]
    assert any("libama_cryptography.so" in r and "check_ct_operand" in r for r in runs)


@pytest.mark.parametrize("name", ["secret-operand-check", "secret-operand-check-arm64"])
def test_the_job_is_fail_closed_and_aggregated(name: str) -> None:
    workflow = yaml.safe_load(DUDECT.read_text(encoding="utf-8"))
    job = workflow["jobs"][name]
    assert "continue-on-error" not in job
    assert all("continue-on-error" not in step for step in job["steps"])
    assert all("--inventory" not in step.get("run", "") for step in job["steps"])
    assert name in workflow["jobs"]["dudect-gate"]["needs"]
    gate_script = "\n".join(s.get("run", "") for s in workflow["jobs"]["dudect-gate"]["steps"])
    assert f"check {name} " in gate_script


def test_the_bulk_aead_workload_reaches_the_kernels_it_names(
    gate: ModuleType, ghash: ModuleType
) -> None:
    """chacha20_xor enters the x8 kernel only for 512 bytes or more, and the
    aead-bulk drivers once ran 256: the ChaCha20 kernels the target names
    never executed (Copilot review, 2026-11-08).  Both drivers carry a message
    above that size, and every lane refuses a run that did not reach the
    kernel its target and pin name: one table, in
    ``check_ghash_constant_time``, read by the count and taint lanes there
    and by the operand gate here (``tests/test_ghash_constant_time_gate.py``
    holds the two lanes; this holds the third to the same table)."""
    for driver in (ghash._TAINT_DRIVERS["aead-bulk"], ghash._DRIVERS["aead-bulk"]):
        sizes = [int(n) for n in re.findall(r"\bpt\[(\d+)\]", driver)]
        assert sizes and min(sizes) > 512, sizes
    assert ghash.required_kernels("aead-bulk", None, "x86_64") == ("ama_chacha20_block_x8_avx2",)
    # The NEON x8 entry point only calls the x4 kernel twice; the x4 kernel
    # is where the secret is consumed.
    assert ghash.required_kernels("aead-bulk", None, "aarch64") == ("ama_chacha20_block_x4_neon",)
    # Pinned, the kernel is the pinned tier's; every other slot is scalar.
    assert ghash.required_kernels("aead-bulk", "aes-gcm-aesni", "x86_64") == (
        "ama_aes256_gcm_encrypt_avx2",
        "ama_aes256_gcm_decrypt_avx2",
    )
    source = TOOL_PATH.read_text(encoding="utf-8")
    assert "ghash.required_kernels(args.target, args.dispatch_only, isa)" in source
    assert not hasattr(gate, "_REQUIRED_KERNELS"), "a second table would drift from the first"


def test_the_hkdf_drivers_key_every_hmac_with_a_long_secret(ghash: ModuleType) -> None:
    """In HKDF the IKM is HMAC's message; the keys are the salt and the
    digest-sized PRK, so a long IKM never reached HMAC's key-hash path.  Each
    HMAC is called directly with the 300-byte buffer as its key, in the taint
    and the count driver alike (block sizes 64, 128 and 136 bytes)."""
    for driver in (ghash._TAINT_DRIVERS["hkdf"], ghash._DRIVERS["hkdf"]):
        assert "static uint8_t big[300];" in driver
        for hmac in ("ama_hmac_sha256", "ama_hmac_sha3_256", "ama_hmac_sha384", "ama_hmac_sha512"):
            assert f"{hmac}(big, sizeof big," in driver, hmac


def test_assume_adx_is_trusted_only_when_the_library_confirms_it(
    ghash: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--assume-adx` sets AMA_TESTING_ASSUME_ADX=1 and the run is trusted only
    on the library's own confirmation line: a refusal, or no line at all (a
    non-testing archive, a target that never read CPUID), is a reason."""
    monkeypatch.setattr(ghash, "_ASSUME_ADX", True)
    monkeypatch.setattr(ghash, "_DISPATCH_ONLY", None)
    assert ghash._driver_env()["AMA_TESTING_ASSUME_ADX"] == "1"
    honoured = "==1== [AMA Dispatch] AMA_TESTING_ASSUME_ADX=1 honored: ADX assumed present"
    refused = "==1== [AMA Dispatch] AMA_TESTING_ASSUME_ADX=1 refused: CPUID reports no BMI2"
    assert ghash._dispatch_pin_was_honoured([honoured]) is None
    assert ghash._dispatch_pin_was_honoured([refused]) == refused
    assert ghash._dispatch_pin_was_honoured([]) is not None
    assert ghash._dispatch_pin_was_honoured(["[AMA Dispatch] AVX2=1"]) is not None
    monkeypatch.setattr(ghash, "_ASSUME_ADX", False)
    assert "AMA_TESTING_ASSUME_ADX" not in ghash._driver_env()
    assert ghash._dispatch_pin_was_honoured([]) is None


def test_the_mulx_adx_kernels_are_measured_by_every_x86_lane() -> None:
    """Valgrind's CPUID hides ADX, so without --assume-adx no lane selected the
    X25519 MULX ladder or the P-curve MULX multiply production runs on every
    ADX-capable CPU.  On it the gate found gcc's vectorised fe64_cswap
    (MOVHLPS x4, 510 times per scalar multiplication) that no other run saw.
    Operand gate under gcc and clang, taint, and both count steps."""
    runs = {s["name"]: s.get("run", "") for s in _job()["steps"]}
    gcc = runs["Every secret operand reaches only a vendor-listed instruction (gcc)"]
    clang = runs["Every secret operand reaches only a vendor-listed instruction (clang)"]
    for text in (gcc, clang):
        assert re.search(
            r"for target in x25519 nistp-ecdsa; do\s+python tools/check_ct_operand"
            r"\.py[^\n]*--assume-adx",
            text,
        ), text
    workflow = yaml.safe_load(DUDECT.read_text(encoding="utf-8"))
    steps = [s for job in workflow["jobs"].values() for s in job.get("steps", [])]
    taint = next(
        s["run"] for s in steps if s.get("name", "").startswith("Secret-taint - no control")
    )
    loop = taint.split("for target in x25519 nistp-ecdsa; do", 1)
    assert len(loop) == 2, "the taint step has no MULX+ADX loop"
    body = loop[1].split("\ndone", 1)[0]
    assert "--taint" in body and "--assume-adx" in body, body
    for target in ("x25519", "nistp-ecdsa"):
        assert any(
            f"--target {target} --assume-adx" in s.get("run", "")
            and "check_ghash_constant_time.py" in s.get("run", "")
            for s in steps
        ), f"no count step measures {target} on the MULX+ADX kernel"


def test_aarch64_portable_sources_are_built_without_simd_registers() -> None:
    """The AArch64 cure is a build property, so it is pinned where it lives.

    gcc 13 moved the portable C's secret words through SIMD registers with
    FMOV, which Arm's DIT list does not name (514 sites, first AArch64 run).
    CMakeLists.txt compiles every library source except the NEON and SVE2
    kernels with -mgeneral-regs-only on AArch64 GCC/Clang, fails configure
    if the compiler refuses it, and builds the NEON kernels without the
    auto-vectoriser.  The behavioural pin is the blocking AArch64 lane; this
    holds the mechanism in place between its runs."""
    cmake = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    block = cmake.split('if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64" AND\n', 1)
    assert len(block) == 2, "the AArch64 general-registers block is gone"
    body = block[1].split("\nendif()\n\nfind_package(Threads REQUIRED)", 1)[0]
    assert "set(_ama_general_regs_sources ${AMA_SOURCES})" in body
    assert "list(REMOVE_ITEM _ama_general_regs_sources ${AMA_NEON_SOURCES})" in body
    assert "APPEND PROPERTY COMPILE_OPTIONS -mgeneral-regs-only" in body
    assert "FATAL_ERROR" in body
    assert "-fno-tree-vectorize -fno-tree-slp-vectorize" in body
    assert cmake.index("set(AMA_SOURCES") < cmake.index("_ama_general_regs_sources")


@pytest.mark.parametrize("name", ["secret-operand-check", "secret-operand-check-arm64"])
def test_every_target_runs_and_any_failure_fails_the_step(name: str) -> None:
    """A step runs every target and then fails if any failed.

    Under `set -e` the first failing target ended the step, so one CI run
    reported one finding: the gcc 15.2 run on dba6bf4 stopped at x25519 and
    said nothing about the 23 targets after it.  Each gate call now records
    its target in `failed` and the step exits 1 at the end when that is
    non-empty; an inconclusive run (exit 2) counts as a failure too, since
    `||` fires on any non-zero status."""
    for step in _job(name)["steps"]:
        run = step.get("run", "")
        if "check_ct_operand.py" not in run:
            continue
        calls = run.replace("\\\n", " ").count("python tools/check_ct_operand.py")
        assert run.count('|| failed="$failed') == calls, step["name"]
        assert 'failed=""' in run.split("check_ct_operand.py")[0], step["name"]
        verdict = run.rstrip().splitlines()[-4:]
        assert verdict[0].strip() == 'if [ -n "$failed" ]; then', step["name"]
        assert verdict[2].strip() == "exit 1" and verdict[3].strip() == "fi", step["name"]


def test_the_instrument_tests_run_where_valgrind_is_provisioned() -> None:
    """The tests that build and run the tool skip without valgrind's tool
    headers, and no ordinary pytest lane installs them.  Two jobs do, one per
    architecture, and each runs ``-m requires_memcheck`` on this module with
    AMA_CI_REQUIRE_MEMCHECK set, which turns a skip into a failure
    (INVARIANT-47): ci.yml's security-checks on x86-64, and dudect.yml's
    secret-operand-check-arm64 on AArch64, where the guarded-write and
    store-conditional probes are the only place those two paths of the tool
    are executed at all.  A tool test must carry the marker, or it pins
    nothing in CI; and one written for a single architecture must name it
    with ``requires_host_isa``, or the other architecture's job fails on its
    skip."""
    ci = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    lanes = (ci["jobs"]["security-checks"]["steps"], _job("secret-operand-check-arm64")["steps"])
    for steps in lanes:
        step = next(s for s in steps if "-m requires_memcheck" in str(s.get("run", "")))
        assert "tests/test_ct_operand_gate.py" in step["run"]
        assert str((step.get("env") or {}).get("AMA_CI_REQUIRE_MEMCHECK")) == "1"
    arm = [str(s.get("run", "")) for s in lanes[1]]
    tests_at = next(i for i, run in enumerate(arm) if "-m requires_memcheck" in run)
    gate_at = next(i for i, run in enumerate(arm) if "check_ct_operand.py" in run)
    assert tests_at < gate_at, "the instrument is used before its own tests have run"
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    decorators = {
        node.name: [ast.unparse(d) for d in node.decorator_list]
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }
    marked = {
        name for name, found in decorators.items() if any("requires_memcheck" in d for d in found)
    }
    assert {
        "test_the_tool_reports_each_class_on_the_secret_sites_only",
        "test_the_generated_class_table_is_nonempty_for_the_installed_vex",
        "test_a_packed_conversion_of_a_secret_is_a_blocking_fp_site",
        "test_a_failed_exchange_keeps_the_taint_of_the_word_it_left",
        "test_a_failed_store_conditional_keeps_the_taint_of_the_word_it_left",
        "test_a_guarded_write_does_not_charge_the_register_it_left_unchanged",
    } <= marked, marked
    for name in sorted(marked):
        found = decorators[name]
        guard = next((d for d in found if "skipif" in d and "platform.machine" in d), None)
        named = [d for d in found if "requires_host_isa" in d]
        if guard is None:
            assert not named, f"{name} names an instruction set it does not skip on"
            continue
        isa = "aarch64" if "aarch64" in guard else "x86-64"
        assert named == [f"pytest.mark.requires_host_isa('{isa}')"], (name, named)


def test_the_gate_scripts_are_in_both_path_filters() -> None:
    text = DUDECT.read_text(encoding="utf-8")
    for path in ("tools/check_ct_operand.py", "tools/ct_operand/**"):
        assert f"- '{path}'" in text, f"push filter omits {path}"
        assert f"            {path}\n" in text, f"WATCHED_PATHS omits {path}"


_GUARDED_PROBE = r"""
#include <stdint.h>
#include <valgrind/memcheck.h>
/* x5 holds the secret; a public test branches around `mrs x5, dczid_el0`,
 * which writes a constant and reads no data operand. */
__attribute__((noinline)) uint64_t guarded(uint64_t s, uint64_t p) {
    uint64_t r;
    __asm__ volatile("mov x5, %1\n\tcbz %2, 1f\n\tmrs x5, dczid_el0\n1:\n\tmov %0, x5"
                     : "=r"(r) : "r"(s), "r"(p) : "x5");
    return r;
}
int main(void) {
    volatile uint64_t seed = 12345, one = 1;
    uint64_t secret = seed;
    VALGRIND_MAKE_MEM_UNDEFINED(&secret, sizeof secret);
    volatile uint64_t r = guarded(secret, one);
    (void)r;
    return 0;
}
"""


def _tool_present() -> bool:
    return bool(shutil.which("valgrind")) and (
        Path("/usr/include/valgrind/pub_tool_tooliface.h").is_file()
    )


def _run_probe(gate: ModuleType, isa: str, stage: Path, exe: Path, workdir: Path) -> Any:
    """The report of ``exe`` under the tool staged at ``stage``, with every
    site resolved to its symbol and static address."""
    workdir.mkdir(exist_ok=True)
    text = gate.run_tool(stage, exe, {"PATH": "/usr/bin:/bin"}, workdir)
    assert text is not None
    report = gate.parse_report(text)
    allowed, _ = gate.load_allowlist(isa)
    spellings = gate.derive_x86_spellings(allowed, workdir) if isa == "x86_64" else {}
    gate.classify(report, isa, allowed, spellings, set())
    return report


def _mutant_tool(gate: ModuleType, isa: str, cache: Path, old: str, new: str) -> Path:
    """The tool built from its source with one replacement: the form a probe
    must be able to tell from the real one, or the probe pins nothing."""
    source = gate.TOOL_SOURCE.read_text(encoding="utf-8")
    assert source.count(old) == 1, f"mutation anchor drifted: {old!r}"
    cache.mkdir()
    mutated = cache / "ctoperand.c"
    mutated.write_text(source.replace(old, new), encoding="utf-8")
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(gate, "TOOL_SOURCE", mutated)
        stage: Path = gate.build_tool(isa, cache / "stage")
    return stage


def _divides(gate: ModuleType, report: Any) -> set[str]:
    """The functions in which a secret reached a division, by source name: a
    compiler's clone of one (``name.constprop.0``) is that function."""
    return {
        site.symbol.split("+", 1)[0].split(".", 1)[0]
        for site in report.sites
        if site.classes & gate.CLASS_BITS["DIV"]
    }


@pytest.mark.requires_memcheck
@pytest.mark.requires_host_isa("aarch64")
@pytest.mark.skipif(
    platform.machine().lower() not in ("aarch64", "arm64"),
    reason="VEX chases conditional branches into guarded writes on its arm64 front end only",
)
def test_a_guarded_write_does_not_charge_the_register_it_left_unchanged(
    gate: ModuleType, tmp_path: Path
) -> None:
    """VEX lifts an instruction reached by speculatively chasing a conditional
    branch as ``PUT(r) = ITE(guard, new, GET(r))``.  The unchanged arm is not an
    operand of the instruction: charging it reported glibc memset's
    ``mrs x5, dczid_el0`` -- a constant -- because x5 still held a secret
    (CI, fbefa4c).  The probe recreates that, and first requires the IR to
    show the guarded write, so a VEX that stopped chasing skips rather than
    passing vacuously.

    Corrected 2026-11-10 (AGENTS.md section 6.6).  As first written this test
    could not fail, and no lane ran it to show that: it matched sites by a
    symbol only :func:`classify` assigns, which it never called, so every
    site's symbol was ``?``; and it compared, and dumped the IR at, the
    address objdump prints, where a site carries the address the instruction
    was loaded at.  Sites are now resolved, matched on their static address,
    and the dump is asked for at the loaded one; and the probe function must
    show a site of its own, so an empty report is a failure and not a pass.
    """
    if not _tool_present():
        pytest.skip("valgrind or its tool headers are not installed")
    stage = gate.build_tool("aarch64", tmp_path / "cache")
    src = tmp_path / "probe.c"
    exe = tmp_path / "probe"
    src.write_text(_GUARDED_PROBE, encoding="utf-8")
    subprocess.run(["gcc", "-O2", "-g", str(src), "-o", str(exe)], check=True)
    dump = subprocess.run(
        ["objdump", "-d", "--no-show-raw-insn", str(exe)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    mrs = [
        int(line.split(":")[0], 16)
        for line in dump.splitlines()
        if "mrs" in line and "dczid_el0" in line and ":" in line
    ]
    assert len(mrs) == 1, mrs
    report = _run_probe(gate, "aarch64", stage, exe, tmp_path / "run")
    own = [s for s in report.sites if s.symbol.startswith("guarded+")]
    assert own, "the secret was consumed nowhere in the probe function"
    loaded_at = mrs[0] + (own[0].ip - own[0].svma)
    ir = gate.explain_sites(stage, exe, {"PATH": "/usr/bin:/bin"}, tmp_path, [loaded_at])
    if not any("ITE(" in line for line in ir):
        pytest.skip("this VEX did not chase the branch; there is no guarded write to judge")
    charged = [s for s in report.sites if s.svma == mrs[0]]
    assert not charged, "the mrs was charged for the register value it left unchanged"


_EXCHANGE_MAIN = r"""
__attribute__((noinline)) uint64_t d_failed(const uint64_t *w, uint64_t n) { return n / *w; }
__attribute__((noinline)) uint64_t d_stored(const uint64_t *w, uint64_t n) { return n / *w; }
__attribute__((noinline)) uint64_t d_public(const uint64_t *w, uint64_t n) { return n / *w; }
int main(void) {
    volatile uint64_t seed = 12345, big = 1000003;
    static uint64_t failed_word, stored_word, public_word;
    uint64_t secret = seed | 1;
    failed_word = seed | 1;
    stored_word = 7;
    public_word = 7;
    VALGRIND_MAKE_MEM_UNDEFINED(&failed_word, sizeof failed_word);
    VALGRIND_MAKE_MEM_UNDEFINED(&secret, sizeof secret);
    /* A public store that does not happen: the word still holds its secret. */
    if (store_fails(&failed_word, 9) != 0)
        return 3;
    /* A secret stored: the word now holds it. */
    if (store_succeeds(&stored_word, 7, secret) != 0)
        return 4;
    /* A public store to a public word: nothing secret anywhere. */
    if (store_succeeds(&public_word, 7, 9) != 0)
        return 5;
    volatile uint64_t r1 = d_failed(&failed_word, big);
    volatile uint64_t r2 = d_stored(&stored_word, big);
    volatile uint64_t r3 = d_public(&public_word, big);
    (void)r1; (void)r2; (void)r3;
    return failed_word == 9 ? 6 : 0;
}
"""

_CAS_PROBE = r"""
#include <stdint.h>
#include <valgrind/memcheck.h>
/* lock cmpxchg stores `desired` only if the word equals `expected`. */
__attribute__((noinline)) static int exchange(uint64_t *word, uint64_t expected, uint64_t desired) {
    uint64_t old = expected;
    unsigned char stored;
    __asm__ volatile("lock cmpxchg %3, (%2)\n\tsete %1"
                     : "+a"(old), "=q"(stored) : "r"(word), "r"(desired) : "cc", "memory");
    return stored;
}
/* Expects 1, which the word is not: 0 when the store did not happen. */
static int store_fails(uint64_t *word, uint64_t desired) { return exchange(word, 1, desired); }
static int store_succeeds(uint64_t *word, uint64_t expected, uint64_t desired) {
    return !exchange(word, expected, desired);
}
""" + _EXCHANGE_MAIN

_LLSC_PROBE = r"""
#include <stdint.h>
#include <valgrind/memcheck.h>
/* A store-conditional with no exclusive access open: it fails and writes
 * nothing.  0 when the store did not happen. */
__attribute__((noinline)) static int store_fails(uint64_t *word, uint64_t desired) {
    uint32_t status;
    __asm__ volatile("clrex\n\tstxr %w0, %2, [%1]"
                     : "=&r"(status) : "r"(word), "r"(desired) : "memory");
    return status == 0;
}
/* Load-exclusive, store-conditional, until the store happens. */
__attribute__((noinline)) static int store_succeeds(uint64_t *word, uint64_t expected,
                                                    uint64_t desired) {
    uint64_t old;
    uint32_t status;
    __asm__ volatile("1:\tldxr %1, [%2]\n\tstxr %w0, %3, [%2]\n\tcbnz %w0, 1b"
                     : "=&r"(status), "=&r"(old) : "r"(word), "r"(desired) : "memory");
    return old != expected;
}
""" + _EXCHANGE_MAIN


@pytest.mark.requires_memcheck
@pytest.mark.requires_host_isa("x86-64")
@pytest.mark.skipif(
    platform.machine().lower() not in ("x86_64", "amd64"),
    reason="the probe is a lock cmpxchg",
)
def test_a_failed_exchange_keeps_the_taint_of_the_word_it_left(
    gate: ModuleType, tmp_path: Path
) -> None:
    """A compare-and-swap that does not store leaves the word, and so must
    leave its taint.

    The tool's shadow store for ``Ist_CAS`` is unconditional, and safe only
    because it writes the union of what was loaded and what was offered: it
    can add taint and never clear it.  The probe holds that property rather
    than taking it from the source.  A secret word survives a public exchange
    that fails and is still a secret when it divides (``d_failed``); a secret
    offered and stored makes its word one (``d_stored``); a public exchange on
    a public word makes nothing (``d_public``).  The mutant stores the taint
    of the operands alone, which is what an ordinary store does, and must
    lose ``d_failed``: if it does not, the probe cannot tell the two and holds
    nothing.
    """
    if not _tool_present():
        pytest.skip("valgrind or its tool headers are not installed")
    src = tmp_path / "exchange.c"
    exe = tmp_path / "exchange"
    src.write_text(_CAS_PROBE, encoding="utf-8")
    subprocess.run(["gcc", "-O2", "-g", str(src), "-o", str(exe)], check=True)
    stage = gate.build_tool("x86_64", tmp_path / "cache")
    report = _run_probe(gate, "x86_64", stage, exe, tmp_path / "run")
    assert report.header["tainted_bytes"] == 16
    assert _divides(gate, report) == {"d_failed", "d_stored"}
    mutant = _mutant_tool(
        gate,
        "x86_64",
        tmp_path / "mutant",
        "call_st(&e, c->addr, total, or1(&e, ls, in_t), NULL);",
        "call_st(&e, c->addr, total, in_t, NULL);",
    )
    assert _divides(gate, _run_probe(gate, "x86_64", mutant, exe, tmp_path / "mutant-run")) == {
        "d_stored"
    }


@pytest.mark.requires_memcheck
@pytest.mark.requires_host_isa("aarch64")
@pytest.mark.skipif(
    platform.machine().lower() not in ("aarch64", "arm64"),
    reason="the probe is a load-exclusive / store-conditional pair",
)
def test_a_failed_store_conditional_keeps_the_taint_of_the_word_it_left(
    gate: ModuleType, tmp_path: Path
) -> None:
    """A store-conditional that fails writes nothing, so its shadow store must
    not happen either.

    The shadow store for ``Ist_LLSC`` is guarded by the statement's own
    result, 1 only if the store happened.  Unguarded, a public store attempt
    on a word that still holds a secret clears the word's taint, and the
    secret's next use is not seen.  ``clrex`` then ``stxr`` fails on every
    core: the probe returns non-zero, and the run fails, if it ever does not.
    The mutant is the tool with the guard removed, and it must lose
    ``d_failed``.  That is also what makes the test fail, instead of pass for
    nothing, on a host where Valgrind lifts exclusives to its fallback and
    there is no ``Ist_LLSC`` to guard: there the mutant and the tool agree.
    """
    if not _tool_present():
        pytest.skip("valgrind or its tool headers are not installed")
    src = tmp_path / "exclusive.c"
    exe = tmp_path / "exclusive"
    src.write_text(_LLSC_PROBE, encoding="utf-8")
    subprocess.run(["gcc", "-O2", "-g", str(src), "-o", str(exe)], check=True)
    stage = gate.build_tool("aarch64", tmp_path / "cache")
    report = _run_probe(gate, "aarch64", stage, exe, tmp_path / "run")
    assert report.header["tainted_bytes"] == 16
    assert _divides(gate, report) == {"d_failed", "d_stored"}
    mutant = _mutant_tool(
        gate,
        "aarch64",
        tmp_path / "mutant",
        "IRExpr_RdTmp(st->Ist.LLSC.result));",
        "NULL);",
    )
    assert _divides(gate, _run_probe(gate, "aarch64", mutant, exe, tmp_path / "mutant-run")) == {
        "d_stored"
    }
