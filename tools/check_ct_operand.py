#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — no secret may reach an instruction outside the vendor
data-independent-timing lists (INVARIANT-12).

Leakage model
-------------
A violation is a secret-derived value that reaches (a) a conditional branch,
(b) a memory address, or (c) an instruction whose latency may depend on its
operands on a supported target (x86-64 and AArch64, with the SIMD tiers the
dispatcher selects).  (a) and (b) are the Memcheck taint lane
(``tools/check_ghash_constant_time.py --taint``).  This gate is (c).

"May depend on its operands" is decided by the vendors, not by this file:
an instruction is admitted only if Intel's Data Operand Independent Timing
list (x86-64) or Arm's DIT list (AArch64) names it.  The lists, their
sources, retrieval dates and extraction method are in
``tools/ct_operand/allowlists.json``.  Everything else that consumes a
secret-derived operand is reported, whatever it is — a divide, a
floating-point operation, a square root, or an instruction the vendor simply
does not vouch for.

Method
------
``tools/ct_operand/ctoperand.c`` is a Valgrind tool built on VEX IR.  It
honours Memcheck's client requests, so the taint drivers in
``check_ghash_constant_time._TAINT_DRIVERS`` and every ``AMA_CT_DECLASSIFY``
site in ``src/c`` work unchanged; it propagates a byte-granular taint shadow
through memory, registers and IR temporaries, and records every guest
instruction that reads a tainted value.  Guest IR is not optimised before
instrumentation (``--vex-iropt-level=0``), so each instruction's own
computation stays attached to its own address.  This script disassembles
every recorded address with objdump, normalises the mnemonic, and fails on
any that is not on the list.

Why not static relational analysis or a DBI framework: a Valgrind tool is
the only one of the three that runs the existing drivers (and their
declassification points) without modification, on the same libraries the
Memcheck lane already runs, with no dependency this repository does not
already install in ``dudect.yml``.

What it does not establish
--------------------------
It checks operand flow on the paths the drivers execute, on the build it is
given, on the ISA the host runs.  It says nothing about power,
electromagnetic, acoustic or fault attacks, speculative execution, or
frequency scaling (Hertzbleed); Intel's list itself says a listed instruction
is not thereby resistant to power, thermal or frequency channels.  And it
assumes the vendor timing mode is in force: Intel's guarantee holds in DOIT
mode, Arm's only while PSTATE.DIT is set (see ``ama_ct_hw_mode_status``).

Exit status
-----------
``0`` no secret reaches an unlisted instruction; ``1`` one does (each site
is printed with its mnemonic, function, source line and call chain); ``2``
the check could not run, or ran and observed too little to mean anything.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Optional, Sequence

TOOLS = Path(__file__).resolve().parent
REPO_ROOT = TOOLS.parent
TOOL_SOURCE = TOOLS / "ct_operand" / "ctoperand.c"
ALLOWLISTS = TOOLS / "ct_operand" / "allowlists.json"

#: Before a clean result means anything the run must have tainted something
#: and seen instructions consume it.  The smallest figures measured on this
#: tree (2026-11-07) are 19 distinct instructions for clang's
#: ``ama_consttime_memcmp`` loop and 39 for gcc's; an earlier revision of this
#: comment said "in the hundreds" and set the floor at 20, which made the clang
#: ``consttime`` run inconclusive on a correct measurement (section 6.6).  A
#: driver whose taint request was lost, or a tool that stopped recording,
#: reads 0, which is what the floor exists to refuse.
MIN_CONSUMING_SITES = 8

#: x86 instruction prefixes objdump prints as separate words.
_X86_PREFIXES = {
    "rep",
    "repz",
    "repe",
    "repnz",
    "repne",
    "lock",
    "bnd",
    "notrack",
    "data16",
    "addr32",
    "cs",
    "ds",
    "ss",
    "es",
    "fs",
    "gs",
    "rex",
    "rex.w",
    "rex.b",
    "rex.x",
    "rex.r",
    "xacquire",
    "xrelease",
}
_X86_STRING_OPS = {"movs", "stos", "lods", "scas", "cmps", "ins", "outs"}
_X86_SIZE = {"BYTE": "B", "WORD": "W", "DWORD": "D", "QWORD": "Q"}

#: Probe instructions, written with Intel's spelling, used to learn how
#: objdump spells the same encoding.  The equivalence is MEASURED by
#: assembling the probe and disassembling the result, never asserted here.
#: Only spellings that objdump is known to rewrite need a probe; every other
#: listed mnemonic is compared by name.
_X86_PROBES = {
    "MOV": ["mov rax, 0x1122334455667788"],
}


def _load_sibling(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load tools/{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def host_isa() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    if machine in ("aarch64", "arm64"):
        return "aarch64"
    return machine


def load_allowlist(isa: str) -> tuple[set[str], dict[str, str]]:
    """The vendor list for ``isa`` as upper-case mnemonics, and its footnotes."""
    data = json.loads(ALLOWLISTS.read_text(encoding="utf-8"))
    entry = data.get(isa)
    if entry is None or not entry.get("mnemonics"):
        raise ValueError(f"no allowlist for {isa!r} in {ALLOWLISTS}")
    return {m.upper() for m in entry["mnemonics"]}, dict(entry.get("footnotes", {}))


# --------------------------------------------------------------------------
# IR operation classes (generated from the installed VEX header)
# --------------------------------------------------------------------------

#: Bits the tool reports per site.  DIV, FP and SQRT are the variable-latency
#: classes both vendor lists exclude (no divide, no floating-point arithmetic,
#: no square root is on Intel's DOIT list or on Arm's DIT list; Arm lists only
#: FCSEL of scalar floating point).  BRANCH marks taint reaching a block exit
#: or an indirect target: leakage class (a), which the Memcheck lane
#: adjudicates bit-exactly and this gate only labels.
CLASS_BITS = {"DIV": 1, "FP": 2, "SQRT": 4, "BRANCH": 8}
BLOCKING_CLASSES = ("DIV", "FP", "SQRT")

_IROP = re.compile(r"\b(Iop_[A-Za-z0-9_]+)\b")
_FP_NAME = re.compile(r"F(?:16|32|64|128)|Fx\d|F0x\d|(?<![A-Z])D(?:32|64|128)")


def op_class(name: str) -> Optional[str]:
    """Class of one VEX ``IROp`` by its name, or None for integer/data ops.

    VEX names every operation by what it computes, so the families are read
    from the name: a ``Div`` (integer, floating or decimal), a ``Sqrt``
    (including the reciprocal estimates), or any operation over an F16/F32/
    F64/F128 or decimal value or an FP vector lane (``Fx4``, ``F0x2``).
    ``Reinterp`` ops are bit casts with no arithmetic and are excluded.
    """
    body = name[len("Iop_") :]
    if "Reinterp" in body:
        return None
    if "Div" in body:
        return "DIV"
    if "Sqrt" in body:
        return "SQRT"
    if _FP_NAME.search(body):
        return "FP"
    return None


def generate_opclass_header(vex_header: Path) -> tuple[str, dict[str, int]]:
    """C source of ``ct_op_class`` for this VEX version, and per-class counts."""
    seen: list[str] = []
    for name in _IROP.findall(vex_header.read_text(encoding="utf-8", errors="replace")):
        if name not in seen and name not in ("Iop_INVALID", "Iop_LAST"):
            seen.append(name)
    by_class: dict[str, list[str]] = {c: [] for c in BLOCKING_CLASSES}
    for name in seen:
        cls = op_class(name)
        if cls is not None:
            by_class[cls].append(name)
    if not all(by_class.values()):
        raise RuntimeError(f"{vex_header}: a class came out empty: {by_class}")
    lines = [
        "/* Generated by tools/check_ct_operand.py from " + vex_header.name + " -- do not edit. */",
        "#define CT_CLASS_DIV 1u",
        "#define CT_CLASS_FP 2u",
        "#define CT_CLASS_SQRT 4u",
        "#define CT_CLASS_BRANCH 8u",
        "static UInt ct_op_class(IROp op)",
        "{",
        "    switch (op) {",
    ]
    for cls in BLOCKING_CLASSES:
        lines.extend(f"    case {name}:" for name in by_class[cls])
        lines.append(f"        return CT_CLASS_{cls};")
    lines += ["    default:", "        return 0;", "    }", "}", ""]
    return "\n".join(lines), {c: len(v) for c, v in by_class.items()}


def class_names(bits: int) -> list[str]:
    return [name for name, bit in CLASS_BITS.items() if bits & bit]


# --------------------------------------------------------------------------
# Mnemonic normalisation
# --------------------------------------------------------------------------


def x86_canonical(text: str) -> str:
    """Intel-list spelling of one objdump ``-M intel`` instruction text.

    Prefixes are stripped except REP, which the list spells as part of the
    name (``REP_MOVSB``).  String instructions take their operand-size
    letter from the first operand, because objdump prints ``movs BYTE PTR
    es:[rdi],...`` where the list says ``MOVSB``.  The SSE scalar move
    objdump also spells ``movsd`` is returned as ``MOVSD(SSE)``: the list's
    ``MOVSD`` row is opcode A5, the string move, so the two must not merge.
    """
    words = text.split()
    rep = False
    while words and words[0].lower() in _X86_PREFIXES:
        if words[0].lower() in ("rep", "repz", "repe", "repnz", "repne"):
            rep = True
        words.pop(0)
    if not words:
        return ""
    mnemonic = words[0].lower()
    operands = " ".join(words[1:])
    if mnemonic in _X86_STRING_OPS:
        size = next(
            (_X86_SIZE[w] for w in operands.replace(",", " ").split() if w in _X86_SIZE), ""
        )
        name = mnemonic.upper() + size
        return f"REP_{name}" if rep else name
    if mnemonic == "movsd" and "xmm" in operands:
        return "MOVSD(SSE)"
    return mnemonic.upper()


def aarch64_canonical(text: str) -> str:
    """List spelling of one ``objdump -M no-aliases`` AArch64 instruction.

    With aliases off objdump prints the architectural mnemonic the DIT list
    uses (``orr`` rather than ``mov``, ``subs`` rather than ``cmp``,
    ``madd`` rather than ``mul``), so no alias table is needed.  A
    conditional branch's ``.cond`` suffix is dropped; an SVE integer compare
    (``cmpeq``, ``cmphi`` ...) is the list's ``CMP<cc>`` row.
    """
    words = text.split()
    if not words:
        return ""
    mnemonic = words[0].lower().split(".")[0]
    if re.fullmatch(r"cmp(eq|ne|ge|gt|le|lt|hi|hs|lo|ls)", mnemonic):
        return "CMP"
    return mnemonic.upper()


def derive_x86_spellings(allowed: set[str], workdir: Path) -> dict[str, str]:
    """``{objdump spelling: list spelling}`` for listed mnemonics objdump renames.

    Condition-code mnemonics have synonyms (CMOVZ/CMOVE, SETNB/SETAE ...) and
    objdump prints one of them; MOV with a 64-bit immediate prints as
    ``movabs``.  Each listed CMOVcc/SETcc and each probe is assembled with
    GNU as and disassembled, and whatever objdump prints is mapped back to
    the listed name — so the equivalence is the assembler's, not this file's.
    """
    probes: list[tuple[str, str]] = []
    for name in sorted(allowed):
        if name.startswith("CMOV"):
            probes.append((name, f"{name.lower()} rax, rbx"))
        elif name.startswith("SET"):
            probes.append((name, f"{name.lower()} al"))
    for name, lines in _X86_PROBES.items():
        probes.extend((name, line) for line in lines)
    asm = workdir / "probe.s"
    obj = workdir / "probe.o"
    asm.write_text(
        ".intel_syntax noprefix\n.text\n" + "".join(f"{line}\n" for _, line in probes),
        encoding="utf-8",
    )
    subprocess.run(["as", "-o", str(obj), str(asm)], check=True, capture_output=True)
    dump = subprocess.run(
        ["objdump", "-d", "-M", "intel", "--no-show-raw-insn", str(obj)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    texts = [m.group(1) for m in re.finditer(r"^\s+[0-9a-f]+:\s+(.+)$", dump, re.MULTILINE)]
    if len(texts) != len(probes):
        raise RuntimeError(
            f"probe disassembly returned {len(texts)} lines for {len(probes)} probes"
        )
    spellings: dict[str, str] = {}
    for (name, _), text in zip(probes, texts):
        spellings[x86_canonical(text)] = name
    return spellings


# --------------------------------------------------------------------------
# Report parsing and disassembly
# --------------------------------------------------------------------------


@dataclass
class Site:
    ip: int
    count: int
    file_offset: int
    classes: int
    obj: str
    at: str
    frames: list[str] = field(default_factory=list)
    symbol: str = "?"

    #: Link-time address, filled in by :func:`classify` from the program headers.
    svma: int = -1


@dataclass
class Report:
    header: dict[str, int]
    sites: list[Site]


def parse_report(text: str) -> Report:
    lines = text.splitlines()
    if not lines or lines[0] != "ctoperand 3" or lines[-1] != "end":
        raise ValueError("ctoperand report is missing, truncated or of an unknown version")
    header: dict[str, int] = {}
    sites: list[Site] = []
    for line in lines[1:-1]:
        if line.startswith("site "):
            _, ip, count, offset, classes, obj = line.split(" ", 5)
            sites.append(Site(int(ip, 16), int(count), int(offset, 16), int(classes, 16), obj, ""))
        elif line.startswith("  at "):
            sites[-1].at = line[5:]
        elif line.startswith("  frame "):
            sites[-1].frames.append(line.split(" ", 4)[4])
        else:
            key, value = line.split(" ", 1)
            header[key] = int(value)
    if header.get("sites") != len(sites):
        raise ValueError("ctoperand report site count does not match its body")
    return Report(header, sites)


_DISASM_LINE = re.compile(r"^\s*([0-9a-f]+):\s+(.+?)\s*$")
_DISASM_SYMBOL = re.compile(r"^([0-9a-f]+) <([^>]+)>:$")


def disassemble(obj: str, isa: str) -> dict[int, str]:
    """``{address: "symbol+0xoff\tinstruction text"}`` for every instruction in ``obj``.

    The enclosing symbol and offset are carried with the text so a report
    names the exact instruction in the machine code even where the object has
    no line tables (the Release archive CI measures has none).
    """
    options = ["-M", "intel"] if isa == "x86_64" else ["-M", "no-aliases"]
    proc = subprocess.run(
        ["objdump", "-d", *options, "--no-show-raw-insn", obj],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise RuntimeError(f"objdump could not disassemble {obj}: {proc.stderr.strip()[:300]}")
    table: dict[int, str] = {}
    symbol, base = "?", 0
    for line in proc.stdout.splitlines():
        head = _DISASM_SYMBOL.match(line)
        if head:
            symbol, base = head.group(2), int(head.group(1), 16)
            continue
        match = _DISASM_LINE.match(line)
        if match and not match.group(2).startswith("<"):
            address = int(match.group(1), 16)
            table[address] = f"{symbol}+0x{address - base:x}\t{match.group(2)}"
    return table


_LOAD = re.compile(
    r"^\s*LOAD\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x[0-9a-f]+\s+0x([0-9a-f]+)", re.MULTILINE
)


def load_segments(obj: str) -> list[tuple[int, int, int]]:
    """``[(p_offset, p_vaddr, p_filesz)]`` of every PT_LOAD in ``obj`` (readelf -lW)."""
    proc = subprocess.run(["readelf", "-lW", obj], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"readelf could not read {obj}: {proc.stderr.strip()[:200]}")
    return [(int(o, 16), int(v, 16), int(z, 16)) for o, v, z in _LOAD.findall(proc.stdout)]


def offset_to_vaddr(segments: list[tuple[int, int, int]], offset: int) -> Optional[int]:
    for p_offset, p_vaddr, p_filesz in segments:
        if p_offset <= offset < p_offset + p_filesz:
            return offset - p_offset + p_vaddr
    return None


@dataclass
class Verdict:
    by_mnemonic: dict[str, int]
    #: BLOCKING: a secret reached a division, FP or square-root operation.
    class_violations: list[tuple[Site, str, str]]
    #: INVENTORY: a secret reached a mnemonic the vendor list does not name.
    unlisted: list[tuple[Site, str, str]]
    unresolved: list[Site]

    @property
    def violations(self) -> list[tuple[Site, str, str]]:
        return self.class_violations


def classify(
    report: Report,
    isa: str,
    allowed: set[str],
    spellings: dict[str, str],
    deny: set[str],
    disassembly: Optional[dict[str, dict[int, str]]] = None,
) -> Verdict:
    """Map every consuming site to its mnemonic and split by the allowlist."""
    canonical = x86_canonical if isa == "x86_64" else aarch64_canonical
    tables: dict[str, dict[int, str]] = dict(disassembly or {})
    by_mnemonic: dict[str, int] = {}
    class_violations: list[tuple[Site, str, str]] = []
    unlisted: list[tuple[Site, str, str]] = []
    unresolved: list[Site] = []
    blocking_bits = sum(CLASS_BITS[c] for c in BLOCKING_CLASSES)
    segments: dict[str, list[tuple[int, int, int]]] = {}
    for site in report.sites:
        if site.obj not in tables:
            try:
                tables[site.obj] = disassemble(site.obj, isa)
            except (OSError, RuntimeError):
                tables[site.obj] = {}
        if site.obj not in segments:
            try:
                segments[site.obj] = load_segments(site.obj)
            except (OSError, RuntimeError):
                segments[site.obj] = []
        vaddr = offset_to_vaddr(segments[site.obj], site.file_offset)
        site.svma = -1 if vaddr is None else vaddr
        entry = tables[site.obj].get(site.svma)
        if entry is None:
            unresolved.append(site)
            continue
        where, _, text = entry.partition("\t")
        if not text:
            where, text = "?", entry
        site.symbol = where
        name = canonical(text)
        name = spellings.get(name, name)
        by_mnemonic[name] = by_mnemonic.get(name, 0) + 1
        if site.classes & blocking_bits:
            class_violations.append((site, name, text))
        if name not in allowed or name in deny:
            unlisted.append((site, name, text))
    return Verdict(by_mnemonic, class_violations, unlisted, unresolved)


# --------------------------------------------------------------------------
# Building and running the tool
# --------------------------------------------------------------------------


def _valgrind_platform(isa: str) -> tuple[str, str]:
    if isa == "x86_64":
        return "amd64-linux", "-DVGA_amd64=1 -DVGP_amd64_linux=1 -DVGPV_amd64_linux_vanilla=1"
    if isa == "aarch64":
        return "arm64-linux", "-DVGA_arm64=1 -DVGP_arm64_linux=1 -DVGPV_arm64_linux_vanilla=1"
    raise ValueError(f"no Valgrind platform for {isa!r}")


def _find_valgrind_dirs(plat: str) -> tuple[Path, Path, Path]:
    """(installed tool directory, archive directory, header directory)."""
    candidates = [Path("/usr/libexec/valgrind"), Path("/usr/lib/valgrind")]
    libexec = next((p for p in candidates if (p / f"memcheck-{plat}").is_file()), None)
    if libexec is None:
        raise FileNotFoundError(f"no installed Valgrind tools for {plat}")
    archive_dirs = [libexec, *Path("/usr/lib").glob("*-linux-gnu/valgrind")]
    archives = next(
        (p for p in archive_dirs if (p / f"libcoregrind-{plat}.a").is_file()),
        None,
    )
    if archives is None:
        raise FileNotFoundError(f"libcoregrind-{plat}.a not found (install valgrind)")
    include = Path("/usr/include/valgrind")
    if not (include / "pub_tool_tooliface.h").is_file():
        raise FileNotFoundError("Valgrind tool headers not found under /usr/include/valgrind")
    return libexec, archives, include


def build_tool(isa: str, cache: Path) -> Path:
    """Build ctoperand and stage a VALGRIND_LIB directory; return that directory.

    Cached per cache directory and rebuilt whenever the tool source or the
    generated operation-class table differs from the staged copy.
    """
    plat, defines = _valgrind_platform(isa)
    libexec, archives, include = _find_valgrind_dirs(plat)
    header_text, _ = generate_opclass_header(include / "libvex_ir.h")
    # Reused only when the staged copy of the inputs is byte-identical to the
    # current ones: an edited tool or a different VEX header always rebuilds.
    inputs = TOOL_SOURCE.read_bytes() + b"\0" + header_text.encode("utf-8")
    stage = cache / f"vglib-{plat}"
    tool = stage / f"ctoperand-{plat}"
    stamp = stage / "inputs"
    if tool.is_file() and stamp.is_file() and stamp.read_bytes() == inputs:
        return stage
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    (stage / "ct_opclass.h").write_text(header_text, encoding="utf-8")
    obj = stage / "ctoperand.o"
    cflags = [
        # -Wall -Wextra without -Werror: the tool is warning-clean against
        # Valgrind 3.22's headers, and a warning a newer header introduces on a
        # CI image is not a measurement failure, so it must not become one.
        "-std=gnu11",
        "-O2",
        "-g",
        "-Wall",
        "-Wextra",
        "-Wno-unused-parameter",
        "-fno-stack-protector",
        "-fno-builtin",
        "-fno-strict-aliasing",
        "-fno-pie",
        "-fno-omit-frame-pointer",
        "-DVGO_linux=1",
        *defines.split(),
        f"-I{include}",
        f"-I{stage}",
    ]
    subprocess.run(["gcc", *cflags, "-c", str(TOOL_SOURCE), "-o", str(obj)], check=True)
    link = [
        "gcc",
        "-o",
        str(tool),
        str(obj),
        "-static",
        "-nodefaultlibs",
        "-nostartfiles",
        "-u",
        "_start",
        "-Wl,--build-id=none",
        "-Wl,-Ttext-segment=0x58000000",
        str(archives / f"libcoregrind-{plat}.a"),
        str(archives / f"libvex-{plat}.a"),
        "-lgcc",
        str(archives / f"libgcc-sup-{plat}.a"),
    ]
    subprocess.run(link, check=True)
    for entry in libexec.iterdir():
        target = stage / entry.name
        if not target.exists():
            target.symlink_to(entry)
    stamp.write_bytes(inputs)
    return stage


def run_tool(stage: Path, driver: Path, env: dict[str, str], workdir: Path) -> Optional[str]:
    out = workdir / "ctoperand.report"
    log = workdir / "ctoperand.log"
    run_env = dict(env)
    run_env["VALGRIND_LIB"] = str(stage)
    proc = subprocess.run(
        [
            "valgrind",
            "--tool=ctoperand",
            "-q",
            "--vex-iropt-level=0",
            "--num-callers=12",
            f"--log-file={log}",
            f"--ct-out={out}",
            str(driver),
        ],
        capture_output=True,
        text=True,
        check=False,
        env=run_env,
    )
    if proc.returncode != 0 or not out.is_file():
        tail = log.read_text(encoding="utf-8", errors="replace")[-2000:] if log.is_file() else ""
        print(
            f"  ctoperand run exited {proc.returncode}\n{tail}{proc.stderr[-1000:]}",
            file=sys.stderr,
        )
        return None
    return out.read_text(encoding="utf-8", errors="replace")


def main(argv: Optional[Sequence[str]] = None) -> int:
    ghash = _load_sibling("check_ghash_constant_time")
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--lib", required=True, type=Path)
    parser.add_argument("--include", type=Path, default=REPO_ROOT / "include")
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--target", required=True, choices=sorted(ghash._TAINT_DRIVERS))
    parser.add_argument("--dispatch-only", default=None, metavar="SLOT")
    parser.add_argument("--optimized-witness", type=Path, default=None)
    parser.add_argument(
        "--deny",
        default="",
        help="Comma-separated listed mnemonics to treat as NOT listed for this run. "
        "Only ever narrows the allowlist; used to show the instrument sees a "
        "secret reaching an instruction class the vendor list admits (multiply).",
    )
    parser.add_argument(
        "--require-listed",
        action="store_true",
        help="Also FAIL on any consuming mnemonic outside the vendor list (the "
        "inventory). Off by default: see the module docstring for why that half "
        "is a measurement and not a blocking check.",
    )
    parser.add_argument("--cache", type=Path, default=Path(tempfile.gettempdir()) / "ama-ctoperand")
    args = parser.parse_args(argv)
    # The sibling gate reads its tier pin from a module global; set it there so
    # the wiring probe and the driver environment see the same pin.
    vars(ghash)["_DISPATCH_ONLY"] = args.dispatch_only

    isa = host_isa()
    try:
        allowed, footnotes = load_allowlist(isa)
    except (OSError, ValueError) as exc:
        print(f"CT-OPERAND CHECK INCONCLUSIVE — {exc}", file=sys.stderr)
        return 2
    deny = {m.strip().upper() for m in args.deny.split(",") if m.strip()}
    if not deny <= allowed:
        print(
            "CT-OPERAND CHECK INCONCLUSIVE — --deny names unlisted mnemonics "
            f"{sorted(deny - allowed)}",
            file=sys.stderr,
        )
        return 2
    for tool in ("valgrind", "objdump", "readelf", "gcc", args.cc) + (
        ("as",) if isa == "x86_64" else ()
    ):
        if shutil.which(tool) is None:
            print(f"CT-OPERAND CHECK INCONCLUSIVE — {tool!r} is not installed.", file=sys.stderr)
            return 2
    if not args.lib.is_file():
        print(f"CT-OPERAND CHECK INCONCLUSIVE — {args.lib} does not exist.", file=sys.stderr)
        return 2

    try:
        stage = build_tool(isa, args.cache)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(
            f"CT-OPERAND CHECK INCONCLUSIVE — could not build the Valgrind tool: {exc}",
            file=sys.stderr,
        )
        return 2

    with tempfile.TemporaryDirectory(prefix="ama-ctoperand-") as tmp:
        workdir = Path(tmp)
        spellings = derive_x86_spellings(allowed, workdir) if isa == "x86_64" else {}
        driver, why = ghash.build_driver(
            ghash._TAINT_DRIVERS[args.target], args.lib, args.include, args.cc, workdir
        )
        if driver is None:
            print(
                f"CT-OPERAND CHECK INCONCLUSIVE — the driver did not build.\n{why}", file=sys.stderr
            )
            return 2
        optimized = ghash._library_is_optimized(args.lib, args.cc, args.include, workdir)
        witness = ""
        if optimized is None and args.optimized_witness is not None:
            build_type = ghash._cmake_build_type(args.optimized_witness)
            if build_type in ("Release", "RelWithDebInfo", "MinSizeRel"):
                optimized = 1
                witness = (
                    f"optimization witness: {args.optimized_witness} "
                    f"(CMAKE_BUILD_TYPE={build_type})"
                )
        if optimized != 1:
            print(
                "CT-OPERAND CHECK INCONCLUSIVE — the library's optimization level is not "
                "established (see check_ghash_constant_time.py: an -O0 build is not the "
                "code that ships).",
                file=sys.stderr,
            )
            return 2
        wiring = ghash._dispatch_wiring(driver)
        refusal = ghash._dispatch_pin_was_honoured(wiring)
        if refusal is not None:
            print(f"CT-OPERAND CHECK INCONCLUSIVE — {refusal}", file=sys.stderr)
            return 2
        text = run_tool(stage, driver, ghash._driver_env(), workdir)
        if text is None:
            print(
                "CT-OPERAND CHECK INCONCLUSIVE — the driver did not run to completion.",
                file=sys.stderr,
            )
            return 2
        try:
            report = parse_report(text)
        except ValueError as exc:
            print(f"CT-OPERAND CHECK INCONCLUSIVE — {exc}", file=sys.stderr)
            return 2
        verdict = classify(report, isa, allowed, spellings, deny)

    head = report.header
    print(f"[{args.target}] secret-operand analysis ({isa}, vendor list: {ALLOWLISTS.name}):")
    for line in wiring:
        print(f"  wiring: {line}")
    if witness:
        print(f"  {witness}")
    print(
        f"  tainted {head.get('tainted_bytes', 0):,} byte(s) in {head.get('taint_requests', 0)} "
        f"request(s); {len(report.sites):,} distinct instruction(s) consumed taint "
        f"{head.get('consumptions', 0):,} time(s)"
    )
    print(
        "  consuming mnemonics: "
        + ", ".join(f"{name} x{count}" for name, count in sorted(verdict.by_mnemonic.items()))
    )
    for name in sorted(verdict.by_mnemonic):
        if name in footnotes:
            print(f"  note: {name} {footnotes[name]}")

    if verdict.unresolved:
        print(
            f"\n{args.target.upper()} CT-OPERAND CHECK INCONCLUSIVE — {len(verdict.unresolved)} "
            "recorded instruction(s) could not be disassembled:",
            file=sys.stderr,
        )
        for site in verdict.unresolved[:20]:
            print(f"  {site.obj} +0x{site.svma:x}: {site.at}", file=sys.stderr)
        return 2
    if head.get("tainted_bytes", 0) == 0 or len(report.sites) < MIN_CONSUMING_SITES:
        print(
            f"\n{args.target.upper()} CT-OPERAND CHECK INCONCLUSIVE — the run tainted "
            f"{head.get('tainted_bytes', 0)} byte(s) and saw {len(report.sites)} consuming "
            f"instruction(s), below the floor of {MIN_CONSUMING_SITES}. An instrument that "
            "observed nothing has cleared nothing.",
            file=sys.stderr,
        )
        return 2
    if verdict.unlisted:
        print(
            f"\n  INVENTORY — {len(verdict.unlisted)} consuming instruction(s) whose mnemonic "
            "the vendor list does not name (reported, not blocking; see "
            "docs/constant-time-testing.md for the reviewed classification):"
        )
        for site, name, text in sorted(verdict.unlisted, key=lambda v: (v[1], v[0].obj, v[0].svma)):
            label = (
                "class (a) branch: adjudicated by the Memcheck lane; "
                if site.classes & CLASS_BITS["BRANCH"]
                else ""
            )
            print(f"  - {name}: `{text}`  [{label}{_where(site)}]")
    if verdict.class_violations:
        print(
            f"\n  {len(verdict.class_violations)} instruction(s) feed a secret-derived operand "
            "to a division, floating-point or square-root operation:"
        )
        for site, name, text in sorted(
            verdict.class_violations, key=lambda v: (v[0].obj, v[0].svma)
        ):
            classes = "/".join(c for c in class_names(site.classes) if c in BLOCKING_CLASSES)
            print(
                f"  - class {classes}, mnemonic {name}: `{text}` at {site.symbol} "
                f"({Path(site.obj).name} +0x{site.svma:x}, executed {site.count}x)"
            )
            print(f"      at {site.at}")
            # Frames Valgrind could not resolve (an object without unwind
            # tables walks into garbage) are noise, not a call chain.
            for frame in [f for f in site.frames[1:] if "(in " in f or "(" in f][:5]:
                print(f"         {frame}")
        print(
            f"\n{args.target.upper()} CT-OPERAND CHECK FAILED — a secret-derived operand reaches "
            "an instruction class no vendor data-independent-timing list admits "
            "(division, floating point, square root)."
        )
        return 1
    if args.require_listed and verdict.unlisted:
        print(
            f"\n{args.target.upper()} CT-OPERAND CHECK FAILED (--require-listed) — "
            f"{len(verdict.unlisted)} consuming instruction(s) are not on the vendor list."
        )
        return 1
    print(
        f"\n{args.target.upper()} CT-OPERAND CHECK PASSED — no secret-derived operand reaches a "
        "division, floating-point or square-root operation"
        + (
            f"; {len(verdict.unlisted)} unlisted consuming instruction(s) inventoried above."
            if verdict.unlisted
            else "; every consuming instruction is on the vendor list."
        )
    )
    return 0


def _where(site: Site) -> str:
    return f"{site.symbol}, {Path(site.obj).name} +0x{site.svma:x}, {site.count}x"


if __name__ == "__main__":
    sys.exit(main())
