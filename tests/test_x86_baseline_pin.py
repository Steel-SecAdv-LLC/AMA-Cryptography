# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The x86-64 ISA baseline is pinned in CMake, not inherited from the compiler.

Every ISA extension the library uses is enabled per translation unit and
entered only through the CPUID-gated dispatch; everything else is the portable
path a host without the extension executes.  ``tools/check_avx_scoping.py``
measures that property on the built object.  It held only while the
compiler's default target was baseline x86-64, which is the distribution's to
change: Ubuntu 26.04's amd64v3 build of GCC 15 defaults to x86-64-v3, and on
that image (dudect.yml run 42242159624, 2026-11-06) the default build carried
AVX2, VEX-encoded and BMI1/BMI2 instructions in 449 non-kernel symbols --
#UD on any pre-AVX2 host in exactly the code the dispatcher selects because
the host lacks AVX2.

``CMakeLists.txt`` now states the baseline (``-march=x86-64 -mtune=generic``)
for every x86-64 GCC/Clang build, after a probe that records whether the
compiler would have been baseline on its own.  Measured: on gcc 13.3 (baseline
default) the pin leaves ``libama_cryptography.so`` disassembly-identical; with
``CFLAGS=-march=x86-64-v3`` in the environment the scoping gate fails without
the pin and passes with it.  That object-level evidence is the behavioural
gate; this module pins the CMake text so the line cannot quietly go.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CMAKELISTS = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")

PIN = 'set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=x86-64 -mtune=generic")'
GUARD = 'if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")'
PROBE = "AMA_COMPILER_DEFAULT_IS_BASELINE_X86_64"


def _line_of(needle: str) -> int:
    index = CMAKELISTS.index(needle)
    return CMAKELISTS.count("\n", 0, index) + 1


class TestTheBaselineIsPinned:
    def test_the_pin_is_present_exactly_once(self) -> None:
        assert CMAKELISTS.count(PIN) == 1

    def test_the_pin_sits_inside_the_x86_64_guard(self) -> None:
        """The nearest enclosing ``if(`` above the pin is the x86-64 match.

        An aarch64 cross build or a NEON/SVE2 lane must never see an x86
        ``-march``; the guard, not a comment, keeps it off them.
        """
        pin_at = CMAKELISTS.index(PIN)
        opening = CMAKELISTS.rfind("\n    if(", 0, pin_at)
        assert opening != -1
        guard_line = CMAKELISTS[opening + 1 : CMAKELISTS.index("\n", opening + 1)]
        assert guard_line.strip() == GUARD, guard_line
        closing = CMAKELISTS.index("\n    endif()", pin_at)
        assert CMAKELISTS.find("\n    if(", pin_at, closing) == -1

    def test_the_pin_is_in_the_gcc_clang_branch_not_msvc(self) -> None:
        """``-march`` is a GCC/Clang spelling; MSVC's /arch default is SSE2."""
        msvc_if = _line_of("if(MSVC)")
        gcc_else = msvc_if + CMAKELISTS.split("\n")[msvc_if - 1 :].index("else()")
        assert msvc_if < gcc_else < _line_of(PIN)

    def test_the_probe_records_what_the_compiler_would_have_done(self) -> None:
        """A CI log must show which case the runner was.

        The probe fails to compile when the default target defines any
        above-baseline feature macro, and the two status lines name the
        outcome; without them a runner whose default moved again would be
        found only by the objdump gate, after the build.
        """
        assert "check_c_source_compiles(" in CMAKELISTS
        probe_at = CMAKELISTS.index(PROBE)
        assert probe_at < CMAKELISTS.index(PIN)
        probe_src = CMAKELISTS[
            CMAKELISTS.rindex("check_c_source_compiles(", 0, probe_at) : probe_at
        ]
        for macro in ("__AVX__", "__AVX2__", "__BMI__", "__BMI2__", "__SSSE3__", "__SSE4_1__"):
            assert f"defined({macro})" in probe_src, macro
        assert "#error" in probe_src
        assert "compiler default is baseline" in CMAKELISTS
        assert "compiler default is ABOVE baseline" in CMAKELISTS

    def test_no_other_global_march_reaches_cmake_c_flags(self) -> None:
        """The only global ``-march`` on CMAKE_C_FLAGS is the baseline pin.

        ``-march=native`` lives on CMAKE_C_FLAGS_RELEASE behind
        AMA_ENABLE_NATIVE_ARCH (benchmark builds only) and the ARM
        ``-march=armv9-a+sve2`` is a per-file flag; neither may migrate here.
        """
        global_march = re.findall(
            r'set\(CMAKE_C_FLAGS\s+"\$\{CMAKE_C_FLAGS\}[^"]*-march=([^\s"]+)', CMAKELISTS
        )
        assert global_march == ["x86-64"], global_march
