# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The Cython binding extensions must be hardened like the library.

BSA-2.  ``CMakeLists.txt`` gives the library ``-fcf-protection=full`` on
x86-64 and ``-mbranch-protection=standard`` on AArch64, explicitly because a
toolchain without a distribution patch "produces the same sources with no CET
at all, and nothing here would have noticed".  ``setup.py`` gave the binding
extensions ``-fstack-protector-strong``, ``_FORTIFY_SOURCE`` and the ``-z``
link flags -- but not those two.  The extensions marshal keys and plaintexts
across the C boundary, and the manylinux ``gcc-toolset`` used by the release
and reproducible-build jobs is exactly the unpatched kind, so the shipped
wheels' most exposed objects had the least hardening.

Two halves, because either alone is defeatable: the flag must be selected
(here), and the built object must actually carry the marking
(``tools/wheel_smoke_test.py::check_control_flow_integrity``).
"""

from __future__ import annotations

import pathlib
import platform
import subprocess
import sys
from typing import ClassVar

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SETUP_PY = REPO_ROOT / "setup.py"


def _setup_namespace() -> dict[str, object]:
    """Exec just the flag helpers from setup.py, without running setup()."""
    import os
    import sysconfig
    import tempfile

    source = SETUP_PY.read_text(encoding="utf-8")
    start = source.index("def _compiler_accepts(")
    end = source.index("def get_extension_modules(")
    namespace: dict[str, object] = {
        "os": os,
        "platform": platform,
        "subprocess": subprocess,
        "sysconfig": sysconfig,
        "tempfile": tempfile,
        "DEBUG": False,
        "COVERAGE": False,
    }

    # flag logic without running setup(); importing the module would execute
    # the whole build preflight.
    exec(  # noqa: S102 -- running this repository's own setup.py logic (BSA-002)
        compile(source[start:end], str(SETUP_PY), "exec"), namespace
    )
    return namespace


class TestTheProbeIsReal:
    def test_it_accepts_a_flag_the_compiler_supports(self) -> None:
        assert _setup_namespace()["_compiler_accepts"]("-O2") is True  # type: ignore[operator]  # exec'd namespace: mypy cannot type the callable (BSA-002)

    def test_it_rejects_a_flag_the_compiler_does_not(self) -> None:
        # Non-vacuity: a probe that always returned True would add the flag on
        # a toolchain that then fails the build.
        accepts = _setup_namespace()["_compiler_accepts"]
        assert accepts("-fthis-flag-does-not-exist-xyz") is False  # type: ignore[operator]  # exec'd namespace: mypy cannot type the callable (BSA-002)


class TestTheProbeTargetsWhatTheBuildTargets:
    """The probe must ask the question the build will ask.

    A probe that omits the build's ``-arch`` flags answers for the host, not
    for the target.  That is exactly how ``-fcf-protection=full`` reached a
    universal2 macOS compile: it probed clean against the native x86_64 target
    on an Intel runner and then failed the arm64 slice outright, taking every
    ``macos-15-intel`` lane down.
    """

    def test_arch_flags_are_read_from_archflags(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ARCHFLAGS", "-arch arm64 -arch x86_64")
        arches = _setup_namespace()["_target_arches"]()  # type: ignore[operator]  # exec'd namespace: mypy cannot type the callable (BSA-002)
        assert arches == ["arm64", "x86_64"]

    def test_a_single_architecture_build_reports_no_arch_flags(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ARCHFLAGS", "")
        assert _setup_namespace()["_target_arches"]() == []  # type: ignore[operator]  # exec'd namespace: mypy cannot type the callable (BSA-002)

    def test_the_probe_carries_the_arch_flags(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Non-vacuity for the fix itself: with a target this host cannot build
        # for, even a universally-supported flag must probe False -- which is
        # only possible if the -arch flags reached the probe command.
        monkeypatch.setenv("ARCHFLAGS", "-arch this-arch-does-not-exist-xyz")
        accepts = _setup_namespace()["_compiler_accepts"]
        assert accepts("-O2") is False  # type: ignore[operator]  # exec'd namespace: mypy cannot type the callable (BSA-002)


class TestAUniversalBuildGetsPerSliceFlags:
    """Neither slice may receive the other's flag.

    Host-independent: it asserts the *shape* of the emitted flags, so it pins
    the regression on Linux CI as well as on macOS.
    """

    @staticmethod
    def _universal_flags(monkeypatch: pytest.MonkeyPatch) -> list[str]:
        """``get_compiler_flags()`` as a universal2 macOS build would see it.

        ``_compiler_accepts`` is stubbed to accept, which is what makes this
        assert anything at all on a Linux CI host: the real probe now carries
        ``-arch arm64 -arch x86_64``, which no Linux toolchain accepts, so it
        refuses every candidate and the shape assertions below would hold
        vacuously for correct and incorrect selection logic alike.  Stubbing
        it tests the SELECTION, which is the part that was wrong.
        """
        monkeypatch.setenv("ARCHFLAGS", "-arch arm64 -arch x86_64")
        namespace = _setup_namespace()
        namespace["_compiler_accepts"] = lambda flag: True
        flags, _ = namespace["get_compiler_flags"]()  # type: ignore[operator]  # exec'd namespace: mypy cannot type the callable (BSA-002)
        return list(flags)

    def test_no_bare_cfi_flag_survives_a_multi_arch_build(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        flags = self._universal_flags(monkeypatch)
        for index, flag in enumerate(flags):
            if flag in ("-fcf-protection=full", "-mbranch-protection=standard"):
                assert index > 0 and flags[index - 1].startswith("-Xarch_"), (
                    f"{flag} is applied to every slice of a universal build; "
                    f"clang rejects it for the slice it does not belong to "
                    f"(flags: {flags})"
                )

    @pytest.mark.parametrize(
        ("arch", "expected"),
        [
            ("arm64", "-mbranch-protection=standard"),
            ("x86_64", "-fcf-protection=full"),
        ],
    )
    def test_each_slice_gets_its_own_flag(
        self, monkeypatch: pytest.MonkeyPatch, arch: str, expected: str
    ) -> None:
        # The positive half: dropping CFI from both slices would satisfy the
        # negative test above, and is not the fix.
        flags = self._universal_flags(monkeypatch)
        marker = f"-Xarch_{arch}"
        assert flags.count(marker) == 1, f"{marker} not emitted exactly once ({flags})"
        assert flags[flags.index(marker) + 1] == expected, (
            f"{marker} must be immediately followed by {expected}; -Xarch_ "
            f"applies to the next argument only (flags: {flags})"
        )


class TestTheFlagIsSelected:
    #: The CFI flag each supported machine must carry, keyed by
    #: ``platform.machine().lower()``.
    #:
    #: A table rather than an ``if``/``elif`` chain ending in ``pytest.skip()``.
    #: The chain bound ``expected`` on every path that reached the assertion,
    #: but only because ``pytest.skip()`` raises — an interprocedural fact
    #: about pytest that a static analyser cannot see, so CodeQL read
    #: ``expected`` as possibly-unbound at the assert
    #: (``py/uninitialized-local-variable``). The lookup binds it on every
    #: reaching path in the source itself, and adding an architecture is now a
    #: row rather than a branch.
    _CFI_FLAG_BY_MACHINE: ClassVar[dict[str, str]] = {
        "x86_64": "-fcf-protection=full",
        "amd64": "-fcf-protection=full",
        "aarch64": "-mbranch-protection=standard",
        "arm64": "-mbranch-protection=standard",
    }

    @pytest.mark.skipif(sys.platform == "win32", reason="MSVC branch uses /guard:cf")
    def test_the_architectures_cfi_flag_is_in_the_compile_flags(self) -> None:
        flags, _ = _setup_namespace()["get_compiler_flags"]()  # type: ignore[operator]  # exec'd namespace: mypy cannot type the callable (BSA-002)
        machine = platform.machine().lower()
        expected = self._CFI_FLAG_BY_MACHINE.get(machine)
        if expected is None:
            pytest.skip(f"no CFI flag defined for {machine}")
        assert expected in flags, (
            f"setup.py does not give the binding extensions {expected}; on a "
            f"toolchain that does not default it on, they ship with no CFI "
            f"while the library has it"
        )

    def test_windows_keeps_its_own_control_flow_guard(self) -> None:
        """The MSVC branch must not have been disturbed."""
        source = SETUP_PY.read_text(encoding="utf-8")
        assert "/guard:cf" in source


class TestTheSmokeTestChecksTheBuiltObject:
    """A selected flag that the toolchain drops is still no hardening."""

    def test_the_release_smoke_test_reads_the_gnu_property_note(self) -> None:
        source = (REPO_ROOT / "tools" / "wheel_smoke_test.py").read_text(encoding="utf-8")
        assert "check_control_flow_integrity" in source
        assert "readelf" in source
        assert "SHSTK" in source and "BTI" in source

    def test_the_check_is_registered_in_the_run(self) -> None:
        # A check function nobody calls is not a gate.
        source = (REPO_ROOT / "tools" / "wheel_smoke_test.py").read_text(encoding="utf-8")
        body = source[source.index("def main() -> int:") :]
        assert "check_control_flow_integrity," in body
