#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Hardware AES-GCM must not depend on the AVX2 build option.

``CMakeLists.txt``'s AES-NI block has always carried this claim::

    # NOTE: Independent of AMA_ENABLE_SIMD — AES-NI is a distinct ISA extension
    # from AVX2/SSE. Disabling SIMD should not disable hardware AES acceleration.

and it was inverted.  The only x86 AES-NI kernel in the tree,
``src/c/avx2/ama_aes_gcm_avx2.c``, sat in ``AMA_AVX2_SOURCES``, compiled only
inside ``if(AMA_ENABLE_SIMD AND AMA_ENABLE_AVX2)``; the dispatcher installed it
only when ``dispatch_info.aes_gcm >= AMA_IMPL_AVX2``; and the one flag the
block actually set went to ``src/c/ama_aes_gcm.c``, which contains no SIMD
intrinsic at all, so it emitted nothing while a STATUS line announced hardware
AES was enabled.

Measured by building the library three ways and asking
``ama_aes_gcm_active_backend()`` what is installed:

===================  =====================  ====================
configuration        before                 after
===================  =====================  ====================
SIMD on, AVX2 on     ``aes-ni-pclmul``      ``aes-ni-pclmul``
SIMD on, AVX2 off    ``bitsliced-software`` ``aes-ni-pclmul``
SIMD off             ``bitsliced-software`` ``aes-ni-pclmul``
===================  =====================  ====================

That is real work lost on every x86 CPU with AES-NI but without AVX2
(Westmere through Ivy Bridge, and any VM masking the AVX2 bit) and in every
build that turns the option off — silently, because the fallback is correct,
just slower.

``TestTheBackendAcrossBuildConfigurations`` re-runs exactly that measurement:
it configures and builds the static library three ways and links a probe that
calls ``ama_aes_gcm_active_backend()``.  It is marked ``slow`` and skips when
no compiler or CMake is present, but it is the test that actually enforces the
property — the structural checks below can only catch the one route by which
the coupling was reintroduced, and a behaviour has to be checked by running it.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import NamedTuple

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CMAKELISTS = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
DISPATCH = (REPO_ROOT / "src" / "c" / "dispatch" / "ama_dispatch.c").read_text(encoding="utf-8")
AESNI_KERNEL = REPO_ROOT / "src" / "c" / "avx2" / "ama_aes_gcm_avx2.c"
VAES_KERNEL = REPO_ROOT / "src" / "c" / "avx2" / "ama_aes_gcm_vaes_avx2.c"
PORTABLE_AES = REPO_ROOT / "src" / "c" / "ama_aes_gcm.c"


def _strip_c_comments(text: str) -> str:
    """Remove ``/* ... */`` and ``// ...`` so a prose mention is not a match."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", " ", text)


def _block(name: str) -> str:
    """The text of a ``set(<name> ...)`` assignment that lists sources."""
    match = re.search(rf"set\({re.escape(name)}\s*\n(.*?)\n\s*\)", CMAKELISTS, re.DOTALL)
    assert match is not None, f"no multi-line set({name} ...) in CMakeLists.txt"
    return match.group(1)


class TestTheKernelNeedsNoAvx2:
    """The premise of the whole change, read from the kernel itself."""

    def test_the_aesni_kernel_uses_no_256_bit_intrinsic(self) -> None:
        text = AESNI_KERNEL.read_text(encoding="utf-8")
        wide = sorted(set(re.findall(r"_mm256_[a-z0-9_]+", text)))
        assert wide == [], (
            f"{AESNI_KERNEL.name} uses AVX2 intrinsics {wide}, so gating it on "
            "AVX2 would be correct after all — this test and the CMake split "
            "both need revisiting"
        )

    def test_the_aesni_kernel_does_use_aes_ni_and_pclmul(self) -> None:
        """Non-vacuity: it must be the hardware kernel, not an empty file."""
        text = AESNI_KERNEL.read_text(encoding="utf-8")
        assert "_mm_aesenc_si128" in text
        assert "_mm_clmulepi64_si128" in text

    def test_the_vaes_kernel_does_need_avx2(self) -> None:
        """The other half: the VAES kernel is correctly AVX2-gated."""
        text = VAES_KERNEL.read_text(encoding="utf-8")
        assert re.search(r"_mm256_aesenc_epi128", text), "expected VAES YMM intrinsics"

    def test_the_portable_implementation_has_no_intrinsics(self) -> None:
        """Why ``-maes -mpclmul`` on this file emitted nothing."""
        text = PORTABLE_AES.read_text(encoding="utf-8")
        assert not re.search(r"_mm_|_mm256_|__m128i|__m256i", text)


class TestTheBuildGatingMatchesThat:
    def test_the_aesni_kernel_is_not_in_the_avx2_source_list(self) -> None:
        assert "ama_aes_gcm_avx2.c" not in _block("AMA_AVX2_SOURCES")

    def test_the_vaes_kernel_still_is(self) -> None:
        assert "ama_aes_gcm_vaes_avx2.c" in _block("AMA_AVX2_SOURCES")

    def test_the_aesni_kernel_is_gated_on_the_architecture_alone(self) -> None:
        """It must be assigned inside the x86 block, not the SIMD/AVX2 one.

        Bounded by the block's own ``endif()``.  This used to split on the
        opening line and assert against ``[1]`` — everything from there to the
        END OF FILE — so the assertions held for any occurrence anywhere below,
        inside the block or not.  The third window-reaches-past-its-subject
        defect in this file; they are all bounded now.
        """
        opening = 'if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64|x86")'
        assert CMAKELISTS.count(opening) == 1, "the architecture-only block moved or was renamed"
        block = _cmake_block(CMAKELISTS, opening)
        assert "set(AMA_X86_AESNI_SOURCES src/c/avx2/ama_aes_gcm_avx2.c)" in block
        assert "add_compile_definitions(AMA_HAVE_X86_AESNI_IMPL)" in block

    def test_the_aesni_kernel_is_64_bit_only(self) -> None:
        """Narrower than the block it sits in, because its kernel is narrower.

        The enclosing ``if(CMAKE_SYSTEM_PROCESSOR MATCHES ...)`` includes a
        bare ``x86`` because ``ama_sha256_ni.c`` guards its body on
        ``__x86_64__ || _M_X64 || __i386__ || _M_IX86`` and genuinely builds
        32-bit.  ``ama_aes_gcm_avx2.c`` guards on ``__x86_64__ || _M_X64``
        only, so defining ``AMA_HAVE_X86_AESNI_IMPL`` on a 32-bit target hands
        the dispatcher a macro over an EMPTY translation unit and the
        ``ama_aes256_gcm_encrypt_avx2`` reference it then compiles has nothing
        to link against.  ``x86`` is what CMAKE_SYSTEM_PROCESSOR reports for a
        32-bit MSVC target.

        Measured with a toolchain file setting ``CMAKE_SYSTEM_PROCESSOR x86``:
        before the fix the configure applied the AES-NI per-file flags and
        defined the macro; after it, it reports the kernel as not compiled.
        """
        source = CMAKELISTS
        anchor = "set(AMA_X86_AESNI_SOURCES src/c/avx2/ama_aes_gcm_avx2.c)"
        assert source.count(anchor) == 1, "the AES-NI source assignment moved"
        head = source[: source.index(anchor)]
        # The nearest enclosing architecture test must exclude 32-bit x86.
        guard = head.rfind("CMAKE_SYSTEM_PROCESSOR MATCHES")
        assert guard != -1, "no architecture guard precedes the AES-NI source list"
        line_end = head.index(")", guard)
        condition = head[guard:line_end]
        assert "x86_64" in condition, condition
        assert not re.search(r"\|x86(?![_0-9])", condition), (
            f"the AES-NI kernel is gated on {condition!r}, which matches 32-bit "
            f"x86 — but the kernel's own body is #if-guarded to 64-bit, so the "
            f"macro would be defined over an empty translation unit"
        )

    def test_sha_ni_flags_do_not_depend_on_the_aesni_kernel(self) -> None:
        """SHA-NI builds 32-bit; its flags must not ride on the 64-bit gate.

        A first version of the fix nested the SHA-NI ``set_source_files_properties``
        inside ``if(AMA_X86_AESNI_SOURCES)``, which would have dropped ``-msha``
        on exactly the 32-bit targets the enclosing ``x86`` alternative exists
        to serve.
        """
        source = CMAKELISTS
        anchor = "set_source_files_properties(src/c/ama_sha256_ni.c PROPERTIES"
        assert source.count(anchor) == 1
        head = source[: source.index(anchor)]
        # Walk back to the nearest unclosed `if(`; it must not be the AES-NI one.
        assert "if(AMA_X86_AESNI_SOURCES)" not in head.rsplit("if(NOT MSVC)", 1)[-1], (
            "the SHA-NI per-file flags are inside if(AMA_X86_AESNI_SOURCES), so a "
            "32-bit x86 build would lose -msha"
        )

    def test_the_new_source_list_reaches_the_library_target(self) -> None:
        assert "${AMA_X86_AESNI_SOURCES}" in CMAKELISTS.split("set(AMA_X86_AESNI_SOURCES")[-1]

    def test_the_dead_flag_is_gone_from_the_portable_translation_unit(self) -> None:
        assert "set_source_files_properties(src/c/ama_aes_gcm.c" not in CMAKELISTS


def _cmake_block(source: str, opening: str) -> str:
    """The body of one CMake ``if(...)`` block, by ``endif()`` matching.

    Nesting-aware, so an inner ``if()`` does not close the outer one.  Same
    reason as :func:`_preprocessor_block`: "everything after the opening line"
    is not a block, and an assertion scoped that way passes on text the block
    does not contain.
    """
    start = source.index(opening) + len(opening)
    depth = 1
    out: list[str] = []
    for line in source[start:].splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("if("):
            depth += 1
        elif stripped.startswith("endif("):
            depth -= 1
            if depth == 0:
                return "".join(out)
        out.append(line)
    raise AssertionError(f"no endif() closes {opening!r}")


def _preprocessor_block(source: str, opening: str) -> str:
    """The text between ``opening`` and the ``#endif`` that closes it.

    Nesting-aware: any ``#if``/``#ifdef``/``#ifndef`` inside increments the
    depth, so an inner conditional does not terminate the block.  Written
    because the alternative — a fixed character window, or a split on the
    first ``#endif`` with a slack term bolted on — is what let an assertion
    about "inside this block" pass on text outside it.
    """
    start = source.index(opening) + len(opening)
    depth = 1
    out: list[str] = []
    for line in source[start:].splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith(("#if", "#ifdef", "#ifndef")):
            depth += 1
        elif stripped.startswith("#endif"):
            depth -= 1
            if depth == 0:
                return "".join(out)
        out.append(line)
    raise AssertionError(f"no #endif closes {opening!r}")


def _function_body(source: str, signature: str) -> str:
    """The braced body of one C function, by brace matching.

    A fixed character window past the signature is not a body: it runs into
    whatever follows, so an assertion that the function CALLS something passes
    on a call made by the next function down.  Measured — a first version of
    ``test_the_public_accessor_and_the_report_share_one_answer`` used
    ``reporter[:6000]`` and did not fail when the reporter's call was replaced
    with a hardcoded label.

    Comments must already be stripped; braces inside string literals would
    break this, and there are none in the two functions it is used on.
    """
    start = source.index(signature)
    open_brace = source.index("{", start)
    depth = 0
    for i in range(open_brace, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[open_brace : i + 1]
    raise AssertionError(f"unbalanced braces after {signature!r}")


class TestTheDispatchGatingMatchesThat:
    def test_the_install_is_under_the_aesni_macro(self) -> None:
        """Inside the ``#ifdef``, bounded by its own ``#endif``.

        This asserted ``symbol in block.split("#endif")[0] + block[:4000]``.
        The second term defeats the first: the symbol only has to appear
        somewhere in the next four thousand characters, inside the block or
        well past it, so the assertion could not fail for the thing it names.
        Same shape as the ``reporter[:6000]`` window fixed in
        ``test_the_public_accessor_and_the_report_share_one_answer`` — a fixed
        character window is not a region.

        ``_preprocessor_block`` tracks nesting, so the VAES arm's inner
        ``#ifdef AMA_HAVE_AVX2_IMPL`` does not end the search early.
        """
        assert "#ifdef AMA_HAVE_X86_AESNI_IMPL" in DISPATCH
        block = _preprocessor_block(DISPATCH, "#ifdef AMA_HAVE_X86_AESNI_IMPL")
        assert "ama_aes256_gcm_encrypt_avx2" in block, (
            "the AES-NI kernel is not installed inside the " "AMA_HAVE_X86_AESNI_IMPL block"
        )

    def test_the_install_does_not_require_the_avx2_tier(self) -> None:
        """``dispatch_info.aes_gcm >= AMA_IMPL_AVX2`` was the runtime half.

        Comments are stripped first: the code that removed this condition
        explains it in prose right above, and a substring search over the raw
        file would match its own changelog.
        """
        assert "dispatch_info.aes_gcm >= AMA_IMPL_AVX2" not in _strip_c_comments(DISPATCH)

    def test_the_active_backend_reporter_can_see_it_without_avx2(self) -> None:
        """The AES-NI arm of the backend reporter is under its OWN macro.

        Anchored on ``return "bitsliced-software"`` — the reporter's terminal
        fallback, and the one landmark in it that cannot move without the
        reporter ceasing to be a reporter — rather than on the name of the
        enclosing function.

        That distinction is not hypothetical: this assertion used to split on
        ``const char *ama_aes_gcm_active_backend(void)``, and it broke when the
        pointer comparisons were factored into a static helper so
        ``ama_print_dispatch_info`` could share them.  Nothing about the
        property changed; the test was pinned to where the code happened to
        live.  ``TestTheBackendAcrossBuildConfigurations`` measures the same
        property by building three configurations and probing the result, but
        it skips off x86 and where no compiler or CMake is available, so this
        structural check is the coverage everywhere else — which is why it is
        repaired rather than deleted.  It no longer skips on an x86 host
        WITHOUT AES-NI: the probe reports the CPU's own answer and the test
        asserts the software backend there instead.
        """
        terminal = 'return "bitsliced-software"'
        assert DISPATCH.count(terminal) == 1, (
            "expected exactly one terminal software-fallback return in the "
            "dispatcher; the anchor this test locates the reporter by has moved"
        )
        head = DISPATCH[: DISPATCH.index(terminal)]

        aesni_section = head.split("#ifdef AMA_HAVE_X86_AESNI_IMPL")
        assert len(aesni_section) >= 2, "the AES-NI arm is not under its own macro"
        assert 'return "aes-ni-pclmul"' in aesni_section[-1], (
            "the AES-NI label is not returned from inside the "
            "AMA_HAVE_X86_AESNI_IMPL arm that precedes the software fallback"
        )

        # ...and it is NOT nested inside the AVX2 arm, which is the whole
        # finding.  The VAES label legitimately is; the AES-NI one must not be.
        aesni_arm = aesni_section[-1]
        aesni_return = aesni_arm.index('return "aes-ni-pclmul"')
        assert "#ifdef AMA_HAVE_AVX2_IMPL" not in aesni_arm[:aesni_return], (
            "the AES-NI label sits inside an AMA_HAVE_AVX2_IMPL block — the "
            "exact coupling this finding removed"
        )

    def test_the_public_accessor_and_the_report_share_one_answer(self) -> None:
        """Two callers, one pointer comparison.

        ``ama_aes_gcm_active_backend()`` is the public accessor and
        ``ama_print_dispatch_info()`` prints the wired backend on its own row.
        If those ever grew separate comparison ladders they could disagree,
        and the report is the one an operator reads.
        """
        stripped = _strip_c_comments(DISPATCH)
        # Exactly one definition, called from both places.
        assert stripped.count("static const char *aes_gcm_installed_backend(void) {") == 1

        accessor = _function_body(stripped, "const char *ama_aes_gcm_active_backend(void)")
        assert "return aes_gcm_installed_backend();" in accessor

        reporter = _function_body(stripped, "void ama_print_dispatch_info(void)")
        assert "aes_gcm_installed_backend()" in reporter, (
            "ama_print_dispatch_info no longer asks aes_gcm_installed_backend() "
            "for the wired-backend row; a second comparison ladder, or a "
            "hardcoded label, can disagree with the public accessor"
        )

    def test_the_vaes_upgrade_is_still_avx2_gated(self) -> None:
        """It genuinely needs AVX2; decoupling it would be a real bug."""
        block = DISPATCH.split("#ifdef AMA_HAVE_X86_AESNI_IMPL")[1][:4000]
        vaes_index = block.index("ama_aes256_gcm_encrypt_vaes_avx2")
        assert "#ifdef AMA_HAVE_AVX2_IMPL" in block[:vaes_index]


# ---------------------------------------------------------------------------
# The property itself, measured
# ---------------------------------------------------------------------------
_PROBE_C = """
#include <stdio.h>
#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif
#include "ama_dispatch.h"

/* Whether THIS CPU has both AES-NI and PCLMULQDQ, asked of the CPU itself.
 *
 * This used to be `" aes" in /proc/cpuinfo and "pclmulqdq" in /proc/cpuinfo`,
 * read from Python.  That file exists only on Linux, so the read raised
 * OSError anywhere else, the helper answered "no AES-NI", and the backend
 * assertion below was skipped on a host that has the ISA.  Measured on the
 * ten windows-latest jobs, which are x86-64 with AES-NI and reported "host
 * has no AES-NI/PCLMULQDQ"; the macOS runners never reached it because
 * macos-latest is aarch64 and took the `not _x86_host()` branch instead.  An
 * Intel Mac or any other non-Linux x86 host has the same hole.  CPUID leaf 1
 * answers the question wherever the probe compiles at all, and the probe
 * already needs a C compiler. */
static int host_has_aes_ni(void) {
#if defined(__x86_64__) || defined(__i386__)
    unsigned int eax, ebx, ecx, edx;
    if (!__get_cpuid(1u, &eax, &ebx, &ecx, &edx)) {
        return 0;
    }
    return ((ecx & (1u << 25)) != 0u) && ((ecx & (1u << 1)) != 0u);
#else
    return 0;
#endif
}

int main(void) {
    ama_dispatch_init();
    printf("HOST_AES_NI=%d\\n", host_has_aes_ni());
    printf("BACKEND=%s\\n", ama_aes_gcm_active_backend());
    return 0;
}
"""

#: (label, extra CMake options).  The second and third are the configurations
#: that silently lost hardware AES: measured as ``bitsliced-software`` before
#: the split and ``aes-ni-pclmul`` after it.
_CONFIGURATIONS = (
    ("simd-on", ["-DAMA_ENABLE_SIMD=ON", "-DAMA_ENABLE_AVX2=ON"]),
    ("avx2-off", ["-DAMA_ENABLE_SIMD=ON", "-DAMA_ENABLE_AVX2=OFF"]),
    ("simd-off", ["-DAMA_ENABLE_SIMD=OFF"]),
)

#: Backends that mean a hardware AES-GCM kernel is installed.  ``vaes-avx2`` is
#: only reachable in the AVX2 configuration and only on a VAES host, so the
#: assertion accepts either rather than pinning the host's feature set.
_HARDWARE_BACKENDS = frozenset({"aes-ni-pclmul", "vaes-avx2"})


class _Probe(NamedTuple):
    """What one built-and-run probe binary reported."""

    host_has_aes_ni: bool
    backend: str


#: Static-library file names, across toolchains.  GCC-family toolchains emit
#: `libNAME.a`; MSVC emits `NAME.lib`.  The probe can only link the former, but
#: both are searched so the diagnostic can say WHICH one it found when the
#: generator and the compiler disagree.
_STATIC_LIB_NAMES = frozenset({"libama_cryptography_static.a", "ama_cryptography_static.lib"})


def _single_config_generator(os_name: str | None = None) -> list[str] | None:
    """CMake generator flags that honour ``CMAKE_BUILD_TYPE``, or ``None``.

    ``os_name`` defaults to ``os.name`` and exists so a test can exercise the
    Windows branch without patching ``os.name`` globally.  That patch is not
    harmless: ``pathlib`` picks ``WindowsPath`` vs ``PosixPath`` from
    ``os.name`` at instantiation, so anything constructing a ``Path`` while it
    is patched — pytest's own cache provider, for one — gets a flavour this
    interpreter cannot use.  Found by mutation-testing this very function: the
    run died in ``pytest_sessionfinish`` with "cannot instantiate 'WindowsPath'
    on your system" rather than reporting the assertion.

    Returned as the argv fragment to splice in, so "use the platform default"
    is the empty list rather than a sentinel the caller has to decode.

    On POSIX the default generator (Unix Makefiles) is already single-config,
    so nothing needs forcing.  On Windows the default is Visual Studio, which
    is multi-config AND incompatible with the GCC-family compiler this probe
    links with, so a generator must be named explicitly or the measurement
    cannot be made at all.
    """
    import shutil

    if shutil.which("ninja"):
        return ["-G", "Ninja"]
    if (os.name if os_name is None else os_name) != "nt":
        return []
    if shutil.which("mingw32-make"):
        return ["-G", "MinGW Makefiles"]
    return None


def _find_static_library(build_dir: Path) -> Path | None:
    """The built static library, wherever the generator put it.

    Single-config generators write ``lib/libNAME.a``; multi-config generators
    interpose a per-configuration directory (``lib/Release/NAME.lib``).  The
    hardcoded single-config POSIX path is what all ten windows-latest jobs
    failed on, so the layout is discovered rather than assumed.
    """
    for candidate in sorted(build_dir.rglob("*")):
        if candidate.is_file() and candidate.name in _STATIC_LIB_NAMES:
            return candidate
    return None


def _x86_host() -> bool:
    import platform

    return platform.machine().lower() in {"x86_64", "amd64", "i386", "i686"}


class TestTheBuildProbeIsPlatformCorrect:
    """The build helper's platform logic, checked where the build cannot run.

    ``TestTheBackendAcrossBuildConfigurations`` below only reaches this code on
    an x86 host with a compiler, so on every other runner the logic went
    unexercised — and when it finally did run on windows-latest it asserted a
    POSIX artefact path against a Visual Studio layout and failed all ten jobs.
    These run everywhere and need no toolchain.
    """

    def test_the_generator_is_single_config_or_absent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A multi-config generator ignores CMAKE_BUILD_TYPE; never return one.

        The platform is passed in rather than patched onto ``os``: see
        ``_single_config_generator``'s docstring for what patching it breaks.
        """
        import shutil as _shutil

        monkeypatch.setattr(
            _shutil, "which", lambda n, *a, **k: "/usr/bin/ninja" if n == "ninja" else None
        )
        assert _single_config_generator(os_name="posix") == ["-G", "Ninja"]
        assert _single_config_generator(os_name="nt") == ["-G", "Ninja"]

        # No ninja on POSIX: the platform default (Unix Makefiles) is already
        # single-config, so nothing needs forcing.
        monkeypatch.setattr(_shutil, "which", lambda n, *a, **k: None)
        assert _single_config_generator(os_name="posix") == []

        # Windows with neither: the only default is Visual Studio, which is
        # multi-config AND cannot drive a GCC-family compiler.  Refusing is
        # right; naming a generator that is not installed is not.
        assert _single_config_generator(os_name="nt") is None

        monkeypatch.setattr(
            _shutil,
            "which",
            lambda n, *a, **k: "C:/mingw64/bin/mingw32-make.exe" if n == "mingw32-make" else None,
        )
        assert _single_config_generator(os_name="nt") == ["-G", "MinGW Makefiles"]

    def test_the_artefact_is_found_in_either_layout(self, tmp_path: Path) -> None:
        """Single-config writes lib/libNAME.a; multi-config writes lib/CONFIG/NAME.lib."""
        posix = tmp_path / "posix" / "lib"
        posix.mkdir(parents=True)
        (posix / "libama_cryptography_static.a").write_bytes(b"stub")
        found = _find_static_library(tmp_path / "posix")
        assert found is not None and found.name == "libama_cryptography_static.a"

        # The exact shape windows-latest produced, and the one the hardcoded
        # path could not see.
        msvc = tmp_path / "msvc" / "lib" / "Debug"
        msvc.mkdir(parents=True)
        (msvc / "ama_cryptography_static.lib").write_bytes(b"stub")
        found = _find_static_library(tmp_path / "msvc")
        assert found is not None and found.parent.name == "Debug"

    def test_nothing_built_is_reported_as_nothing(self, tmp_path: Path) -> None:
        """Must not invent a path: a missing library has to read as missing."""
        (tmp_path / "lib").mkdir()
        (tmp_path / "lib" / "unrelated.a").write_bytes(b"stub")
        assert _find_static_library(tmp_path) is None


@pytest.mark.slow
@pytest.mark.requires_host_isa("x86")
class TestTheBackendAcrossBuildConfigurations:
    """Build the library three ways and ask which AES-GCM kernel is installed.

    This is the measurement the finding rests on, run rather than described.
    Before the split the last two rows answered ``bitsliced-software``.
    """

    @staticmethod
    def _build_and_probe(tmp_path: Path, label: str, options: list[str]) -> tuple[_Probe, Path]:
        import shutil
        import subprocess

        cmake = shutil.which("cmake")
        compiler = shutil.which("cc") or shutil.which("gcc")
        if cmake is None or compiler is None:
            pytest.skip("cmake or a C compiler is unavailable")

        # The library must be built by the SAME compiler the probe links with,
        # and into a predictable layout.  Neither was true on Windows, and the
        # test never reached the build there until this pass removed the
        # /proc/cpuinfo skip that had been masking it:
        #
        #  * CMake's default Windows generator is Visual Studio, which is
        #    MULTI-config.  It ignores CMAKE_BUILD_TYPE and writes
        #    `lib/Debug/ama_cryptography_static.lib` — so the hardcoded
        #    `lib/libama_cryptography_static.a` was simply absent, which is the
        #    assertion all ten windows-latest jobs failed on.
        #  * even found, an MSVC `.lib` is not linkable by the MinGW `cc` the
        #    probe uses.  Building with `-DCMAKE_C_COMPILER` set to the probe's
        #    own compiler is what makes the two halves agree.
        #
        # A GCC-family compiler and the Visual Studio generator are mutually
        # exclusive, so an explicit single-config generator is required
        # wherever the default is multi-config.
        generator = _single_config_generator()
        if generator is None:
            pytest.skip(
                "no single-config CMake generator (ninja / mingw32-make) is "
                "available for the probe compiler; the multi-config default "
                "would ignore CMAKE_BUILD_TYPE and emit a library this probe "
                "cannot link"
            )

        build_dir = tmp_path / f"build-{label}"
        configure = subprocess.run(
            [
                cmake,
                "-S",
                str(REPO_ROOT),
                "-B",
                str(build_dir),
                *generator,
                f"-DCMAKE_C_COMPILER={compiler}",
                "-DCMAKE_BUILD_TYPE=Release",
                # LTO off, so `nm` can read the archive on every runner rather
                # than only where the toolchain registers its plugin.  With
                # -flto GCC emits slim objects whose symbol table lives in
                # GIMPLE; GNU nm recovers it only by auto-loading
                # liblto_plugin.so from a bfd-plugins directory.  Debian
                # registers one, so this passed locally; the MinGW-w64
                # distribution on windows-latest does not, and `nm` there
                # reported 1,300-odd `.gnu.lto_.decls.*` section names instead
                # of any function — which the symbol assertion below then
                # reported as "the AES-NI kernel is not in the library at all".
                # What those assertions actually ask is which translation units
                # the configuration compiles in, and CMake's source lists decide
                # that identically with LTO on or off.
                "-DAMA_ENABLE_LTO=OFF",
                "-DAMA_USE_NATIVE_PQC=ON",
                "-DAMA_BUILD_TESTS=OFF",
                "-DAMA_BUILD_EXAMPLES=OFF",
                *options,
            ],
            capture_output=True,
            text=True,
            timeout=900,
        )
        assert configure.returncode == 0, configure.stderr[-2000:]
        build = subprocess.run(
            [cmake, "--build", str(build_dir), "--target", "ama_cryptography_static", "-j", "4"],
            capture_output=True,
            text=True,
            timeout=3600,
        )
        assert build.returncode == 0, build.stderr[-2000:]

        static_lib = _find_static_library(build_dir)
        if static_lib is None:
            present = sorted(
                str(q.relative_to(build_dir))
                for q in build_dir.rglob("*")
                if q.is_file() and q.suffix in {".a", ".lib"}
            )
            raise AssertionError(
                f"no static library under {build_dir}; searched for "
                f"{sorted(_STATIC_LIB_NAMES)}, found {present}"
            )

        probe_c = tmp_path / f"probe-{label}.c"
        probe_c.write_text(_PROBE_C, encoding="utf-8")
        probe_bin = tmp_path / f"probe-{label}"
        # -DAMA_BUILDING_STATIC is not optional on Windows and is a no-op
        # everywhere else.  `AMA_API` in include/ama_cryptography.h expands to
        # __declspec(dllimport) for a Windows consumer that has not said it is
        # linking the STATIC library, so without it every entry point resolves
        # to `__imp_<name>` and the probe fails to link — measured, against a
        # MinGW-w64 cross-build of this tree.  On POSIX `AMA_API` is empty, so
        # passing it unconditionally keeps one code path instead of two.
        #
        # The library list is platform-split for the same reason CMakeLists.txt
        # splits it: Windows needs bcrypt for BCryptGenRandom (ama_platform_rand
        # gets it from `#pragma comment(lib, ...)` under MSVC, which MinGW
        # ignores with a warning), and it must NOT be asked for -lpthread, whose
        # only use was the once-primitive that now resolves to Win32
        # InitOnceExecuteOnce.
        platform_libs = ["-lbcrypt"] if os.name == "nt" else ["-lm", "-lpthread"]
        link = subprocess.run(
            [
                compiler,
                "-O2",
                "-std=c11",
                "-DAMA_BUILDING_STATIC",
                f"-I{REPO_ROOT / 'include'}",
                str(probe_c),
                "-o",
                str(probe_bin),
                str(static_lib),
                *platform_libs,
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        assert link.returncode == 0, link.stderr[-2000:]
        # MinGW's gcc appends `.exe` when `-o` names a file without one, so the
        # path handed to `-o` is not necessarily the path that now exists.
        produced = probe_bin if probe_bin.is_file() else probe_bin.with_suffix(".exe")
        assert (
            produced.is_file()
        ), f"the probe linked but produced neither {probe_bin} nor {produced}"
        run = subprocess.run([str(produced)], capture_output=True, text=True, timeout=300)
        assert run.returncode == 0, run.stderr[-2000:]
        fields = dict(line.split("=", 1) for line in run.stdout.splitlines() if "=" in line)
        assert set(fields) == {"HOST_AES_NI", "BACKEND"}, run.stdout
        return _Probe(host_has_aes_ni=fields["HOST_AES_NI"] == "1", backend=fields["BACKEND"]), (
            static_lib
        )

    @staticmethod
    def _defined_symbols(static_lib: Path) -> set[str]:
        import shutil
        import subprocess

        nm = shutil.which("nm")
        if nm is None:
            pytest.skip("nm is unavailable")
        out = subprocess.run(
            [nm, "--defined-only", str(static_lib)], capture_output=True, text=True, timeout=300
        )
        assert out.returncode == 0, out.stderr[-1000:]
        symbols = {line.split()[-1] for line in out.stdout.splitlines() if line.strip()}
        # Diagnose the environment before the caller misreads it.  Without the
        # LTO plugin `nm` lists GIMPLE section names rather than functions, and
        # every symbol assertion downstream then fails as though the kernel had
        # not been compiled in.  A wrong diagnosis is worse than a failure: this
        # one cost a full windows-latest round trip.
        lto_sections = sum(1 for name in symbols if name.startswith(".gnu.lto_"))
        assert lto_sections == 0, (
            f"{static_lib} still holds LTO bytecode: nm reported {lto_sections} "
            f".gnu.lto_* section name(s) and no usable symbol table, so this "
            f"says nothing about which kernels were compiled in. The probe "
            f"configures -DAMA_ENABLE_LTO=OFF precisely to avoid depending on "
            f"whether this toolchain registers liblto_plugin.so in a "
            f"bfd-plugins directory; if you are seeing this, that flag stopped "
            f"taking effect."
        )
        return symbols

    @pytest.mark.parametrize("label,options", _CONFIGURATIONS, ids=[c[0] for c in _CONFIGURATIONS])
    def test_hardware_aes_survives_every_simd_configuration(
        self, tmp_path: Path, label: str, options: list[str]
    ) -> None:
        if not _x86_host():
            # Declared on the class as `requires_host_isa("x86")`, so the CI
            # backend-skip escalation in tests/conftest.py leaves this alone
            # instead of reporting "build the C library" on an aarch64 runner.
            pytest.skip("AES-NI gating is an x86 property")
        probe, static_lib = self._build_and_probe(tmp_path, label, options)
        if probe.host_has_aes_ni:
            assert probe.backend in _HARDWARE_BACKENDS, (
                f"with {' '.join(options)} the active AES-GCM backend is "
                f"{probe.backend!r}. Hardware AES must not depend on the SIMD or "
                "AVX2 build options — CMakeLists.txt has said so since before it "
                "was true."
            )
        else:
            # Not a skip: "no hardware kernel may install on a CPU without the
            # ISA" is a property of the dispatcher too, and it is checkable
            # here.  The former code skipped the whole parametrisation on such
            # a host and lost the symbol-level assertions below with it.
            assert probe.backend not in _HARDWARE_BACKENDS, (
                f"the host reports no AES-NI/PCLMULQDQ, yet the dispatcher wired "
                f"{probe.backend!r} — a hardware kernel on a CPU that cannot run it"
            )

        # Non-vacuity, at the symbol level, and the build-time half of the
        # finding: the AES-NI kernel must be LINKED in every configuration, and
        # the AVX2-only kernels must genuinely be absent from the two that turn
        # AVX2 off.  This does not depend on the host's CPU at all — which is
        # why it now runs on every x86 host rather than only those with AES-NI.
        # Without it the three parameter sets could be building the same library
        # and the test would pass on a coincidence.
        symbols = self._defined_symbols(static_lib)
        assert (
            "ama_aes256_gcm_encrypt_avx2" in symbols
        ), f"{label}: the AES-NI kernel is not in the library at all"
        avx2_only = {"ama_kyber_ntt_avx2", "ama_dilithium_ntt_avx2"}
        if label == "simd-on":
            assert avx2_only <= symbols, (
                f"{label}: the AVX2 kernels are missing, so this configuration "
                "is not the one it claims to be"
            )
        else:
            assert not (avx2_only & symbols), (
                f"{label}: AVX2 kernels {sorted(avx2_only & symbols)} are linked, "
                "so AVX2 was not actually disabled and the test proves nothing"
            )
