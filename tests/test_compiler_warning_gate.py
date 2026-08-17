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
