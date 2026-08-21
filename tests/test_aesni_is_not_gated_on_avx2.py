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

import re
from pathlib import Path

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
        """It must be assigned inside the x86 block, not the SIMD/AVX2 one."""
        arch_block = CMAKELISTS.split('if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64|x86")')
        assert len(arch_block) >= 2, "the architecture-only block moved or was renamed"
        assert "set(AMA_X86_AESNI_SOURCES src/c/avx2/ama_aes_gcm_avx2.c)" in arch_block[1]
        assert "add_compile_definitions(AMA_HAVE_X86_AESNI_IMPL)" in arch_block[1]

    def test_the_new_source_list_reaches_the_library_target(self) -> None:
        assert "${AMA_X86_AESNI_SOURCES}" in CMAKELISTS.split("set(AMA_X86_AESNI_SOURCES")[-1]

    def test_the_dead_flag_is_gone_from_the_portable_translation_unit(self) -> None:
        assert "set_source_files_properties(src/c/ama_aes_gcm.c" not in CMAKELISTS


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
        assert "#ifdef AMA_HAVE_X86_AESNI_IMPL" in DISPATCH
        block = DISPATCH.split("#ifdef AMA_HAVE_X86_AESNI_IMPL")[1]
        assert "ama_aes256_gcm_encrypt_avx2" in block.split("#endif")[0] + block[:4000]

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
        it skips off x86 and on hosts without AES-NI, so this structural check
        is the coverage everywhere else — which is why it is repaired rather
        than deleted.
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
#include "ama_dispatch.h"
int main(void) {
    ama_dispatch_init();
    printf("%s\\n", ama_aes_gcm_active_backend());
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


def _x86_host() -> bool:
    import platform

    return platform.machine().lower() in {"x86_64", "amd64", "i386", "i686"}


def _has_aes_ni() -> bool:
    """AES-NI and PCLMULQDQ, from the host's own CPU flags."""
    try:
        flags = Path("/proc/cpuinfo").read_text(encoding="utf-8")
    except OSError:
        return False
    return " aes" in flags and "pclmulqdq" in flags


@pytest.mark.slow
class TestTheBackendAcrossBuildConfigurations:
    """Build the library three ways and ask which AES-GCM kernel is installed.

    This is the measurement the finding rests on, run rather than described.
    Before the split the last two rows answered ``bitsliced-software``.
    """

    @staticmethod
    def _build_and_probe(tmp_path: Path, label: str, options: list[str]) -> tuple[str, Path]:
        import shutil
        import subprocess

        cmake = shutil.which("cmake")
        compiler = shutil.which("cc") or shutil.which("gcc")
        if cmake is None or compiler is None:
            pytest.skip("cmake or a C compiler is unavailable")

        build_dir = tmp_path / f"build-{label}"
        configure = subprocess.run(
            [
                cmake,
                "-S",
                str(REPO_ROOT),
                "-B",
                str(build_dir),
                "-DCMAKE_BUILD_TYPE=Release",
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

        static_lib = build_dir / "lib" / "libama_cryptography_static.a"
        assert static_lib.is_file(), f"no static library at {static_lib}"

        probe_c = tmp_path / f"probe-{label}.c"
        probe_c.write_text(_PROBE_C, encoding="utf-8")
        probe_bin = tmp_path / f"probe-{label}"
        link = subprocess.run(
            [
                compiler,
                "-O2",
                "-std=c11",
                f"-I{REPO_ROOT / 'include'}",
                str(probe_c),
                "-o",
                str(probe_bin),
                str(static_lib),
                "-lm",
                "-lpthread",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        assert link.returncode == 0, link.stderr[-2000:]
        run = subprocess.run([str(probe_bin)], capture_output=True, text=True, timeout=300)
        assert run.returncode == 0, run.stderr[-2000:]
        return run.stdout.strip(), static_lib

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
        return {line.split()[-1] for line in out.stdout.splitlines() if line.strip()}

    @pytest.mark.parametrize("label,options", _CONFIGURATIONS, ids=[c[0] for c in _CONFIGURATIONS])
    def test_hardware_aes_survives_every_simd_configuration(
        self, tmp_path: Path, label: str, options: list[str]
    ) -> None:
        if not _x86_host():
            pytest.skip("AES-NI gating is an x86 property")
        if not _has_aes_ni():
            pytest.skip("host has no AES-NI/PCLMULQDQ, so no hardware path can install")
        backend, static_lib = self._build_and_probe(tmp_path, label, options)
        assert backend in _HARDWARE_BACKENDS, (
            f"with {' '.join(options)} the active AES-GCM backend is {backend!r}. "
            "Hardware AES must not depend on the SIMD or AVX2 build options — "
            "CMakeLists.txt has said so since before it was true."
        )

        # Non-vacuity, at the symbol level: the AES-NI kernel must be LINKED in
        # every configuration, and the AVX2-only kernels must genuinely be
        # absent from the two that turn AVX2 off.  Without this the three
        # parameter sets could be building the same library and the test would
        # pass on a coincidence.
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
