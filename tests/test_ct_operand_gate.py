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
   tainted operand fails; an unlisted mnemonic is inventoried and does not;
   an unresolvable site or an empty run is inconclusive, never a pass.
4. **The instrument itself.**  The Valgrind tool is built and run on a small
   program that feeds a secret to a divide, a double multiply, a square root
   and a multiply, and the same operations a public value: the report must
   carry exactly the right class on exactly the secret sites.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import platform
import re
import shutil
import subprocess
import sys
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

    def test_a_missing_library_is_inconclusive(self, gate: ModuleType, tmp_path: Path) -> None:
        assert gate.main(["--lib", str(tmp_path / "absent.a"), "--target", "x25519"]) == 2

    def test_deny_may_only_narrow_the_list(self, gate: ModuleType, tmp_path: Path) -> None:
        lib = tmp_path / "lib.a"
        lib.write_bytes(b"")
        assert gate.main(["--lib", str(lib), "--target", "x25519", "--deny", "NOTAMNEMONIC"]) == 2


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
    (void)r1; (void)r2; (void)r3; (void)r4; (void)r5; (void)r6;
    return 0;
}
"""


@pytest.mark.requires_memcheck
@pytest.mark.skipif(
    platform.machine().lower() not in ("x86_64", "amd64"),
    reason="the probe's expectations are written for the x86-64 lifting",
)
@pytest.mark.parametrize("encoding", [[], ["-mavx"]], ids=["sse", "vex"])
def test_the_tool_reports_each_class_on_the_secret_sites_only(
    gate: ModuleType, tmp_path: Path, encoding: list[str]
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
    # Both encodings on every host: `-mavx` makes gcc emit the VEX forms
    # (vdivsd, vmulsd, vsqrtsd ...) a newer default target produces anyway.
    subprocess.run(["gcc", "-O2", "-g", *encoding, str(src), "-o", str(exe), "-lm"], check=True)
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
    assert not {"f_mul", "g_div", "h_branch"} & set(blocking), blocking


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------


def _job() -> dict[str, Any]:
    workflow = yaml.safe_load(DUDECT.read_text(encoding="utf-8"))
    job: dict[str, Any] = workflow["jobs"]["secret-operand-check"]
    return job


def test_the_dudect_workflow_runs_every_taint_driver_through_the_gate(ghash: ModuleType) -> None:
    text = "\n".join(step.get("run", "") for step in _job()["steps"])
    assert "tools/check_ct_operand.py" in text
    archive_loop = next(
        step["run"]
        for step in _job()["steps"]
        if "libama_cryptography_test.a" in step.get("run", "")
        and "check_ct_operand" in step.get("run", "")
    )
    match = re.search(r"for target in (.*?); do", archive_loop.replace("\\\n", " "), re.S)
    assert match, "the archive step has no `for target in ...; do` loop"
    looped = set(match.group(1).split())
    missing = sorted(set(ghash._TAINT_DRIVERS) - looped)
    assert not missing, f"taint drivers the secret-operand gate never runs: {missing}"


def test_the_gate_also_measures_the_shipped_shared_object() -> None:
    runs = [step.get("run", "") for step in _job()["steps"]]
    assert any("libama_cryptography.so" in r and "check_ct_operand" in r for r in runs)


def test_the_job_is_fail_closed_and_aggregated() -> None:
    workflow = yaml.safe_load(DUDECT.read_text(encoding="utf-8"))
    job = workflow["jobs"]["secret-operand-check"]
    assert "continue-on-error" not in job
    assert all("continue-on-error" not in step for step in job["steps"])
    assert "secret-operand-check" in workflow["jobs"]["dudect-gate"]["needs"]
    gate_script = "\n".join(s.get("run", "") for s in workflow["jobs"]["dudect-gate"]["steps"])
    assert "check secret-operand-check" in gate_script


def test_the_instrument_tests_run_where_valgrind_is_provisioned() -> None:
    """The tests that build and run the tool skip without valgrind's tool
    headers, and no ordinary pytest lane installs them.  ci.yml's
    security-checks job does, and runs ``-m requires_memcheck`` with
    AMA_CI_REQUIRE_MEMCHECK set, which turns a skip into a failure
    (INVARIANT-47): this module must be in that step and its tool tests must
    carry the marker, or they pin nothing in CI."""
    ci = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    steps = ci["jobs"]["security-checks"]["steps"]
    step = next(s for s in steps if "-m requires_memcheck" in str(s.get("run", "")))
    assert "tests/test_ct_operand_gate.py" in step["run"]
    assert str((step.get("env") or {}).get("AMA_CI_REQUIRE_MEMCHECK")) == "1"
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    marked = {
        node.name
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and any("requires_memcheck" in ast.unparse(d) for d in node.decorator_list)
    }
    assert {
        "test_the_tool_reports_each_class_on_the_secret_sites_only",
        "test_the_generated_class_table_is_nonempty_for_the_installed_vex",
    } <= marked, marked


def test_the_gate_scripts_are_in_both_path_filters() -> None:
    text = DUDECT.read_text(encoding="utf-8")
    for path in ("tools/check_ct_operand.py", "tools/ct_operand/**"):
        assert f"- '{path}'" in text, f"push filter omits {path}"
        assert f"            {path}\n" in text, f"WATCHED_PATHS omits {path}"
