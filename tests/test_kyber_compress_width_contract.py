# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""A Compress_d width outside FIPS 203's [1, 11] must not compile.

WHY THIS TEST EXISTS

``kyber_compress_d_impl`` in ``src/c/ama_kyber.c`` computes FIPS 203
Compress_d with a reciprocal multiply that is exact only for d <= 18, and FIPS
203 defines Compress_d only for d < 12.  Its run-time guard refuses d = 0 and
d > 18 by returning ``AMA_KYBER_COMPRESS_REFUSED`` -- which is 0, a valid
coefficient, inside [0, 2^d), and one no caller range-checks.  The comment
beside it said a refused width "yields a value the callers' own range checks
reject".  No such check existed: ``poly_compress`` masked the 0 into the
ciphertext, so a mistyped width would have packed a silently wrong ciphertext
that fails only at the peer's decapsulation.  A mistyped d = 12 was worse
still: inside the reciprocal's exact interval, so not refused at all.

The fix is a compile-time contract at every call site.  ``kyber_compress_d()``
is now a macro whose operand declares a bit-field of width
``((d) >= 1u && (d) <= 11u) ? 1 : -1``.  A bit-field width must be a
non-negative integer constant expression (C11 6.7.2.1p4), so an out-of-range
literal, and a width that is not a compile-time constant at all, are both
compile errors.

WHAT IT ENFORCES

* PIN -- the contract rejects: the real translation unit, compiled with one
  added probe that calls ``kyber_compress_d`` with 0, 12, 18 or 19, or with a
  run-time width, fails to compile, and the diagnostic comes from the width
  check.  Mutation (``AMA_KYBER_COMPRESS_WIDTH_CHECK`` removed from the
  ``kyber_compress_d`` macro): every one of those probes compiles and this test
  fails.
* Non-vacuity -- the same harness compiles the same translation unit with a
  probe at each width ML-KEM actually uses, so a rejection above is the width
  and not a harness that cannot compile the file.
* PIN -- every call is checked: in the preprocessed production translation
  unit, every call of ``kyber_compress_d_impl`` is the tail of the width check.
  Mutation (one call site rewritten to call ``kyber_compress_d_impl``
  directly): this test fails.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
KYBER_C = REPO_ROOT / "src" / "c" / "ama_kyber.c"

#: Widths FIPS 203 ML-KEM actually compresses to (du/dv for the three parameter
#: sets, and 1 for the message).  The contract must admit every one of them.
FIPS203_WIDTHS = (1, 4, 5, 10, 11)

#: Literal widths the contract must refuse: 0 (degenerate), 12 (the first width
#: FIPS 203 does not define, and one the reciprocal still computes exactly --
#: so the run-time guard does NOT refuse it), 18 (the last width the reciprocal
#: is exact for) and 19 (the first it is not).
REFUSED_WIDTHS = (0, 12, 18, 19)

#: The bit-field the width check declares.  A rejection must be attributable to
#: it, not to some unrelated error in the probe.
CHECK_MEMBER = "compress_width_not_a_fips203_constant_in_1_to_11"
CHECK_MACRO = "AMA_KYBER_COMPRESS_WIDTH_CHECK"

#: The defines that compile every call site in: the native PQC paths and the
#: diagnostics block, but NOT AMA_TESTING_MODE, whose one export calls the
#: function directly on purpose (its width is a run-time sweep).
#:
#: AMA_BUILDING_STATIC is the static-library build's own definition
#: (CMakeLists.txt sets it on ``ama_cryptography_static``).  It is what makes
#: ``AMA_API`` empty on Windows; without it the header falls through to
#: ``__declspec(dllimport)``, and a translation unit that DEFINES the
#: exported functions then fails to compile before the width probe is ever
#: reached ("dllimport cannot be applied to non-inline function definition",
#: fifteen times, on every windows-latest lane, 2026-09-24).  A non-vacuity
#: probe that cannot compile the real TU proves nothing, so the harness
#: compiles it the way the library itself is compiled.  On every other
#: platform ``AMA_API`` is empty regardless and the define is inert.
PRODUCTION_DEFINES = (
    "-DAMA_USE_NATIVE_PQC",
    "-DAMA_KYBER_BUILD_DIAGNOSTICS",
    "-DAMA_BUILDING_STATIC",
)


def _compilers() -> list[str]:
    """Every distinct C compiler on PATH; both GCC and Clang where present."""
    found: list[str] = []
    seen: set[str] = set()
    for name in ("cc", "gcc", "clang"):
        path = shutil.which(name)
        if path is None:
            continue
        real = os.path.realpath(path)
        if real in seen:
            continue
        seen.add(real)
        found.append(path)
    return found


COMPILERS = _compilers()


def _base_command(cc: str) -> list[str]:
    return [
        cc,
        "-std=c11",
        "-I",
        str(REPO_ROOT / "include"),
        "-I",
        str(REPO_ROOT / "src" / "c"),
        *PRODUCTION_DEFINES,
    ]


def _compile_probe(cc: str, call: str) -> subprocess.CompletedProcess[str]:
    """Compile ama_kyber.c with one added function returning ``call``."""
    source = (
        '#include "ama_kyber.c"\n'
        "uint32_t ama_width_probe(uint32_t x, unsigned w);\n"
        "uint32_t ama_width_probe(uint32_t x, unsigned w) {\n"
        "    (void)w;\n"
        f"    return {call};\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        probe = Path(tmp) / "width_probe.c"
        probe.write_text(source, encoding="utf-8")
        return subprocess.run(
            [*_base_command(cc), "-fsyntax-only", str(probe)],
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )


def _needs_compiler(cc: str | None) -> str:
    if cc is None:
        pytest.skip("no C compiler on PATH")
    return cc


@pytest.mark.parametrize("cc", COMPILERS or [None])
def test_every_fips203_width_compiles(cc: str | None) -> None:
    """Non-vacuity: the harness compiles the real TU at every ML-KEM width."""
    compiler = _needs_compiler(cc)
    for width in FIPS203_WIDTHS:
        proc = _compile_probe(compiler, f"kyber_compress_d(x, {width})")
        assert proc.returncode == 0, (
            f"{compiler}: src/c/ama_kyber.c with a probe at FIPS 203 width "
            f"{width} does not compile, so the rejections below would prove "
            f"nothing:\n{proc.stderr}"
        )


@pytest.mark.parametrize("cc", COMPILERS or [None])
@pytest.mark.parametrize("width", REFUSED_WIDTHS)
def test_an_out_of_range_literal_width_does_not_compile(cc: str | None, width: int) -> None:
    compiler = _needs_compiler(cc)
    proc = _compile_probe(compiler, f"kyber_compress_d(x, {width})")
    assert proc.returncode != 0, (
        f"{compiler}: kyber_compress_d(x, {width}) compiled.  FIPS 203 defines "
        f"Compress_d only for 1 <= d <= 11; a width outside that interval must "
        f"be a build error, because at run time the only refusal available is "
        f"the coefficient 0, which the ciphertext packer accepts silently."
    )
    assert CHECK_MEMBER in proc.stderr or CHECK_MACRO in proc.stderr, (
        f"{compiler}: kyber_compress_d(x, {width}) failed, but not in the width "
        f"check:\n{proc.stderr}"
    )


@pytest.mark.parametrize("cc", COMPILERS or [None])
def test_a_run_time_width_does_not_compile(cc: str | None) -> None:
    """A width read from a variable or a parameter block cannot be checked, so
    it must not compile either."""
    compiler = _needs_compiler(cc)
    proc = _compile_probe(compiler, "kyber_compress_d(x, w)")
    assert proc.returncode != 0, (
        f"{compiler}: kyber_compress_d(x, w) with a run-time w compiled; the "
        f"width contract only holds if every width is a checked constant."
    )
    assert (
        CHECK_MEMBER in proc.stderr or CHECK_MACRO in proc.stderr
    ), f"{compiler}: kyber_compress_d(x, w) failed, but not in the width check:\n{proc.stderr}"


_IMPL_CALL = re.compile(r"\bkyber_compress_d_impl\s*\((?!\s*uint32_t\s+x_normalized\b)")
_CHECKED_CALL = re.compile(
    re.escape(CHECK_MEMBER) + r"[^;]*;\s*\}\s*\)\s*\)\s*,\s*kyber_compress_d_impl\s*\("
)


@pytest.mark.parametrize("cc", COMPILERS or [None])
def test_every_production_call_goes_through_the_width_check(cc: str | None) -> None:
    compiler = _needs_compiler(cc)
    proc = subprocess.run(
        [*_base_command(compiler), "-E", "-P", str(KYBER_C)],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert proc.returncode == 0, f"{compiler}: could not preprocess ama_kyber.c:\n{proc.stderr}"
    calls = _IMPL_CALL.findall(proc.stdout)
    checked = _CHECKED_CALL.findall(proc.stdout)
    # Nine call sites: five Compress_1 message encodes (decapsulation and the
    # diagnostics block) and poly_compress's four widths.
    assert len(calls) >= 9, (
        f"{compiler}: only {len(calls)} calls of kyber_compress_d_impl in the "
        f"preprocessed translation unit; the pattern has stopped seeing them"
    )
    assert len(checked) == len(calls), (
        f"{compiler}: {len(calls) - len(checked)} of the {len(calls)} calls of "
        f"kyber_compress_d_impl in the production translation unit bypass "
        f"{CHECK_MACRO}.  Call kyber_compress_d(), not the function."
    )
