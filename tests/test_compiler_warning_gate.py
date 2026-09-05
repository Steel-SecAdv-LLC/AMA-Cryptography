# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Tests for ``tools/check_compiler_warnings.py``.

The gate this covers replaced a chain of ``grep -v`` inside one workflow step.
That chain had already broken once in this branch's history — its allowlist
matched ASCII apostrophes while ``LANG=C.UTF-8`` makes GCC quote identifiers
with U+2018/U+2019, so the step failed on the exact class it exists to permit —
and it passed vacuously when its log was missing, because ``grep``'s exit 2
flattened into "no warnings found".

So both directions are pinned here, not just the happy path: every exemption is
shown to admit its own class in *both* quote spellings, a real out-of-allowlist
diagnostic is shown to fail, and a missing or empty log is shown to be fatal
rather than clean.  The out-of-allowlist samples are verbatim lines from real
builds of this tree, not invented text.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "tools" / "check_compiler_warnings.py"

# Verbatim from a Release build of this tree before the benchmark harness was
# fixed (gcc 13, -O3 -D_FORTIFY_SOURCE=2).  This is the class the unoptimized
# gate configuration could not emit at all.
STRINGOP_TRUNCATION = (
    "/home/user/AMA-Cryptography/benchmarks/benchmark_c_raw.c:245:5: warning: "
    "'__builtin_strncpy' output may be truncated copying 63 bytes from a "
    "string of length 63 [-Wstringop-truncation]"
)

# Verbatim from an AArch64 cross build of this tree before the NEON kernels
# were given a header.  This is the class the x86-64-only gate could not see.
MISSING_PROTOTYPE = (
    "/home/user/AMA-Cryptography/src/c/neon/ama_kyber_neon.c:133:6: warning: "
    "no previous prototype for 'ama_kyber_ntt_neon' [-Wmissing-prototypes]"
)

# The two documented extension classes, in both quote spellings GCC uses.
INT128_ASCII = (
    "/home/user/AMA-Cryptography/src/c/fe51.h:188:22: warning: ISO C does not "
    "support '__int128' types [-Wpedantic]"
)
INT128_UTF8 = (
    "/home/user/AMA-Cryptography/src/c/fe51.h:188:22: warning: ISO C does not "
    "support ‘__int128’ types [-Wpedantic]"
)
OVERLENGTH_LITERAL = (
    "/home/user/AMA-Cryptography/src/c/x86/ama_nistp_mont_mulx.c:120:9: "
    "warning: string literal of length 9001 exceeds maximum length 4095 that "
    "ISO C99 compilers are required to support [-Woverlength-strings]"
)
VENDORED = (
    "/home/user/AMA-Cryptography/src/c/vendor/ed25519-donna/"
    "modm-donna-64bit.h:13:35: warning: a label can only be part of a "
    "statement and a declaration is not a statement [-Wpedantic]"
)


def run_gate(*logs: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(GATE), *[str(p) for p in logs]],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


def write_log(tmp_path: Path, name: str, *lines: str) -> Path:
    path = tmp_path / name
    body = "\n".join(("[ 42%] Building C object foo.c.o", *lines, "[100%] Built target ama")) + "\n"
    path.write_text(body, encoding="utf-8")
    return path


class TestAllowlistAdmitsItsOwnClasses:
    """Each exemption must admit its class — in either quote spelling."""

    @pytest.mark.parametrize(
        "line",
        [INT128_ASCII, INT128_UTF8, OVERLENGTH_LITERAL, VENDORED],
        ids=["int128-ascii", "int128-utf8", "overlength-literal", "vendored"],
    )
    def test_exempt_line_passes(self, tmp_path: Path, line: str) -> None:
        log = write_log(tmp_path, "build.log", line)
        result = run_gate(log)
        assert result.returncode == 0, result.stderr

    def test_clean_log_passes(self, tmp_path: Path) -> None:
        log = write_log(tmp_path, "build.log")
        result = run_gate(log)
        assert result.returncode == 0, result.stderr
        assert "no compiler warnings outside the frozen allowlist" in result.stdout

    def test_counts_are_reported_so_a_dead_exemption_is_visible(self, tmp_path: Path) -> None:
        log = write_log(tmp_path, "build.log", INT128_ASCII, INT128_UTF8)
        result = run_gate(log)
        assert result.returncode == 0, result.stderr
        assert "allowlisted [int128-extension]: 2" in result.stdout
        assert "allowlisted [overlength-asm-literal]: 0" in result.stdout


class TestAllowlistRejectsEverythingElse:
    @pytest.mark.parametrize(
        "line",
        [STRINGOP_TRUNCATION, MISSING_PROTOTYPE],
        ids=["optimizer-dependent", "architecture-dependent"],
    )
    def test_real_warning_fails(self, tmp_path: Path, line: str) -> None:
        log = write_log(tmp_path, "build.log", line)
        result = run_gate(log)
        assert result.returncode == 1
        assert "outside the frozen allowlist" in result.stderr
        assert line in result.stderr

    def test_int128_outside_the_named_headers_is_not_exempt(self, tmp_path: Path) -> None:
        """The exemption is scoped to fe51.h / fe64.h, not to the text."""
        line = INT128_ASCII.replace("fe51.h", "ama_kyber.c")
        log = write_log(tmp_path, "build.log", line)
        result = run_gate(log)
        assert result.returncode == 1
        assert "ama_kyber.c" in result.stderr

    def test_one_bad_log_among_several_fails(self, tmp_path: Path) -> None:
        clean = write_log(tmp_path, "clean.log", INT128_ASCII)
        dirty = write_log(tmp_path, "dirty.log", MISSING_PROTOTYPE)
        result = run_gate(clean, dirty)
        assert result.returncode == 1
        assert "dirty.log" in result.stderr


class TestFailsClosedOnAbsentEvidence:
    """A gate that passes having examined nothing is the defect being removed."""

    def test_missing_log_is_fatal(self, tmp_path: Path) -> None:
        result = run_gate(tmp_path / "never-written.log")
        assert result.returncode == 1
        assert "does not exist" in result.stderr

    def test_empty_log_is_fatal(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.log"
        empty.write_text("", encoding="utf-8")
        result = run_gate(empty)
        assert result.returncode == 1
        assert "is empty" in result.stderr

    def test_missing_log_beside_a_clean_one_is_still_fatal(self, tmp_path: Path) -> None:
        clean = write_log(tmp_path, "clean.log", INT128_ASCII)
        result = run_gate(clean, tmp_path / "never-written.log")
        assert result.returncode == 1

    def test_no_arguments_is_a_usage_error(self) -> None:
        result = subprocess.run(
            [sys.executable, str(GATE)],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        assert result.returncode == 2


class TestDecodingCannotMaskContent:
    def test_undecodable_bytes_do_not_hide_a_warning(self, tmp_path: Path) -> None:
        """A build log can carry any bytes a diagnostic quotes back.

        The gate must fail on the warning it contains, not on the decode.
        """
        log = tmp_path / "build.log"
        log.write_bytes(
            b"quoted source: \xff\xfe not utf-8\n" + MISSING_PROTOTYPE.encode("utf-8") + b"\n"
        )
        result = run_gate(log)
        assert result.returncode == 1
        assert "ama_kyber_ntt_neon" in result.stderr


class TestWiredIntoTheWorkflow:
    """The script only enforces anything if the workflow actually calls it."""

    def test_static_analysis_workflow_invokes_the_gate(self) -> None:
        workflow = (REPO_ROOT / ".github" / "workflows" / "static-analysis.yml").read_text(
            encoding="utf-8"
        )
        assert "tools/check_compiler_warnings.py" in workflow

    def test_every_produced_log_is_checked(self) -> None:
        """Every `tee`d warning log must be passed to the gate.

        A build step that writes a log nobody reads is the same silent gap as
        a missing gate, and it is one edit away at any time.
        """
        workflow = (REPO_ROOT / ".github" / "workflows" / "static-analysis.yml").read_text(
            encoding="utf-8"
        )
        produced = {
            token
            for token in workflow.replace("|", " ").split()
            if token.startswith("build-warnings") and token.endswith(".log")
        }
        assert produced, "no warning logs are produced by the workflow at all"
        checked_section = workflow.split("tools/check_compiler_warnings.py")
        assert len(checked_section) >= 2
        checked_text = "".join(checked_section[1:])
        for log in sorted(produced):
            assert log in checked_text, f"{log} is written but never checked"


class TestClangFormatConfigLoads:
    """``.clang-format`` must be loadable by the toolchain this project pins.

    Placed beside the warning-gate tests because it is the same class of
    defect: a toolchain configuration file that silently does not apply.

    ``Language: C`` was rejected by every clang-format before LLVM 20 —
    including the clang-18 in CI and in the container images — with
    ``unknown enumerated scalar`` followed by
    ``Error reading .clang-format: Invalid argument``.  The whole file was
    then ignored, so an editor with format-on-save fell back to LLVM defaults
    (2-space indent, 80 columns): the exact opposite of what the file
    specifies.
    """

    CONFIG = REPO_ROOT / ".clang-format"

    def test_language_is_the_universally_valid_spelling(self) -> None:
        text = self.CONFIG.read_text(encoding="utf-8")
        language_lines = [
            line.strip() for line in text.splitlines() if line.strip().startswith("Language:")
        ]
        assert language_lines == ["Language: Cpp"], (
            "Language must be 'Cpp' — the kind clang-format uses for C in every "
            "version.  'C' is a parse error before LLVM 20, which silently "
            f"disables the entire file.  Found: {language_lines}"
        )

    def test_clang_format_actually_parses_it(self) -> None:
        import shutil
        import subprocess

        clang_format = shutil.which("clang-format")
        if clang_format is None:
            pytest.skip("clang-format not installed")
        result = subprocess.run(
            [clang_format, "--dump-config"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        assert (
            result.returncode == 0
        ), f"clang-format could not read .clang-format: {result.stderr.strip()}"
        # The dumped config must carry this file's settings, not LLVM defaults
        # — a file that failed to load still dumps a config, just the wrong one.
        assert "IndentWidth:     4" in result.stdout
        assert "ColumnLimit:     100" in result.stdout


class TestClangSummaryLineIsNotADiagnostic:
    """``1 warning generated.`` is clang's bookkeeping, not a finding.

    An earlier form of the line matcher (``\\bwarning[ :]``) matched it, so
    every clang build reported one bogus finding per translation unit that
    emitted any warning — including warnings the allowlist had already
    excused.  GCC prints no such line, so it survived until the gate was first
    run over a clang log.  A gate that fires on its own bookkeeping is as
    useless as one that cannot fire.
    """

    @pytest.mark.parametrize(
        "line",
        [
            "1 warning generated.",
            "2 warnings generated.",
            "17 warnings generated.",
        ],
    )
    def test_summary_lines_are_ignored(self, tmp_path: Path, line: str) -> None:
        log = write_log(tmp_path, "build.log", line)
        result = run_gate(log)
        assert result.returncode == 0, result.stderr

    def test_a_summary_line_does_not_mask_a_real_warning(self, tmp_path: Path) -> None:
        log = write_log(tmp_path, "build.log", MISSING_PROTOTYPE, "1 warning generated.")
        result = run_gate(log)
        assert result.returncode == 1
        assert "ama_kyber_ntt_neon" in result.stderr
        assert "1 warning generated." not in result.stderr

    def test_msvc_spelling_is_still_a_diagnostic(self, tmp_path: Path) -> None:
        """MSVC writes ``warning Cxxxx:`` — the colon is what both forms share."""
        line = r"C:\src\ama_kyber.c(42): warning C4244: conversion, possible loss of data"
        log = write_log(tmp_path, "build.log", line)
        result = run_gate(log)
        assert result.returncode == 1
        assert "C4244" in result.stderr


class TestInterleavedParallelOutput:
    """`make -j N` can merge two compilers' stderr inside one line.

    Two processes share one pipe, so a single line can carry both
    diagnostics character-interleaved.  Observed verbatim in a clean parallel
    build of this tree: two identical -Woverlength-strings warnings from the
    shared and static targets merged into one line.  A position-exact
    allowlist pattern stops matching such a line, so an *allowlisted* warning
    is reported as a violation and the gate goes red for a reason that has
    nothing to do with the code.

    The build steps pass `-Otarget` so Make serialises per-target output;
    these cases pin the defence in depth that keeps the allowlist working if
    a generator ever does not.
    """

    #: Verbatim from a clean `make -j` build of this tree.
    INTERLEAVED_OVERLENGTH = (
        "/home/user/AMA-Cryptography/src/c/x86/ama_nistp_mont_mulx.c"
        "/home/user/AMA-Cryptography/src/c/x86/ama_nistp_mont_mulx.c::161161::99::"
        "  warning: warning: string literal of length 4266 exceeds maximum length "
        "4095 that ISO C99 compilers are required to support [-Woverlength-strings]"
        "string literal of length 4266 exceeds maximum length 4095 that ISO C99 "
        "compilers are required to support [-Woverlength-strings]"
    )

    def test_interleaved_allowlisted_warning_is_still_allowlisted(self, tmp_path: Path) -> None:
        log = write_log(tmp_path, "build.log", self.INTERLEAVED_OVERLENGTH)
        result = run_gate(log)
        assert result.returncode == 0, result.stderr

    def test_interleaved_int128_is_still_allowlisted(self, tmp_path: Path) -> None:
        merged = (
            "/src/c/fe51.h/src/c/fe51.h::188188::2222::  warning: warning: "
            "ISO C does not support '__int128' types [-Wpedantic]"
            "ISO C does not support '__int128' types [-Wpedantic]"
        )
        log = write_log(tmp_path, "build.log", merged)
        result = run_gate(log)
        assert result.returncode == 0, result.stderr

    def test_tolerance_does_not_admit_a_different_warning(self, tmp_path: Path) -> None:
        """The relaxation is `.*` between name and text, not `name ⇒ exempt`.

        A line naming an allowlisted file but carrying a DIFFERENT diagnostic
        must still fail — otherwise the exemption would become a per-file
        blanket.
        """
        line = (
            "/home/user/AMA-Cryptography/src/c/x86/ama_nistp_mont_mulx.c:12:3: "
            "warning: variable 'tmp' set but not used [-Wunused-but-set-variable]"
        )
        log = write_log(tmp_path, "build.log", line)
        result = run_gate(log)
        assert result.returncode == 1
        assert "unused-but-set-variable" in result.stderr

    def test_every_parallel_strict_build_serialises_its_output(self) -> None:
        """Make needs ``-Otarget``; Ninja already buffers per edge.

        The assertion is per build directory, not per line: the two generators
        need different things, and demanding one flag for both would either
        miss the Make lanes or require a flag Ninja rejects.
        """
        workflow = (REPO_ROOT / ".github" / "workflows" / "static-analysis.yml").read_text(
            encoding="utf-8"
        )
        ninja_dirs = set(re.findall(r"-B (\S+) -G Ninja", workflow))
        builds = [
            line
            for line in workflow.splitlines()
            if "cmake --build build-strict" in line and "tee" in line
        ]
        assert builds, "no strict build step pipes through tee"
        for line in builds:
            build_dir = line.split("cmake --build ", 1)[1].split()[0]
            if build_dir in ninja_dirs:
                assert (
                    "-Otarget" not in line
                ), f"{build_dir} is a Ninja build; -Otarget is a Make flag: {line.strip()}"
                continue
            assert "-Otarget" in line, f"unsynchronised parallel Make build: {line.strip()}"
