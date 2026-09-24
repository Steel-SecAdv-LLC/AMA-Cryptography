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

import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import sysconfig
import types
from collections.abc import Callable
from typing import ClassVar, cast

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SETUP_PY = REPO_ROOT / "setup.py"


def _setup_namespace(platform_module: object = platform) -> dict[str, object]:
    """Exec just the flag helpers from setup.py, without running setup().

    ``platform_module`` stands in for the ``platform`` module those helpers
    consult, so a test can ask what a build for another machine selects.
    """
    import tempfile

    source = SETUP_PY.read_text(encoding="utf-8")
    start = source.index("def _compiler_accepts(")
    end = source.index("def get_extension_modules(")
    namespace: dict[str, object] = {
        "os": os,
        "platform": platform_module,
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="MSVC branch returns /guard:cf and never reaches the per-slice selection",
)
class TestAUniversalBuildGetsPerSliceFlags:
    """Neither slice may receive the other's flag.

    Host-independent across every toolchain that can produce a universal
    binary: it asserts the *shape* of the emitted flags, so it pins the
    regression on Linux CI as well as on macOS.  Windows is the one exception
    -- ``get_compiler_flags()`` takes the MSVC branch there and returns
    ``/guard:cf`` without consulting the target architectures at all, so the
    property under test does not exist rather than being violated.
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


_FlagsFn = Callable[[], tuple[list[str], list[str]]]

#: GCC's AArch64 outline-atomics helpers (libgcc/config/aarch64/lse.S) and the
#: constructor-initialised flag they dispatch on (lse-init.c).  All of them are
#: defined in libgcc.a only, so a reference to any one of them is a libgcc.a
#: member joining the link.
_OUTLINE_ATOMIC_SYMBOL = re.compile(
    r"\b__aarch64_(?:(?:cas|swp|ldadd|ldclr|ldeor|ldset)\d+_\w+|have_lse_atomics)\b"
)

#: The read-modify-writes Cython emits for a typed memoryview's acquisition
#: count (``__pyx_atomic_incr_relaxed`` / ``__pyx_atomic_decr_acq_rel`` over an
#: ``atomic_int``), which is what put libgcc.a into math_engine's link.
_ATOMIC_RMW_PROBE = """\
#include <stdatomic.h>
atomic_int ama_probe_count;
int ama_probe_acquire(void) {
    return atomic_fetch_add_explicit(&ama_probe_count, 1, memory_order_relaxed);
}
int ama_probe_release(void) {
    return atomic_fetch_sub_explicit(&ama_probe_count, 1, memory_order_acq_rel);
}
"""

_ON_AARCH64_LINUX = sys.platform.startswith("linux") and platform.machine().lower() in (
    "aarch64",
    "arm64",
)


def _aarch64_linux() -> types.SimpleNamespace:
    """A stand-in ``platform`` module reporting an AArch64 Linux build host."""
    return types.SimpleNamespace(machine=lambda: "aarch64", system=lambda: "Linux")


def _flags_fn(namespace: dict[str, object]) -> _FlagsFn:
    """``get_compiler_flags`` from an exec'd setup.py namespace, typed."""
    return cast(_FlagsFn, namespace["get_compiler_flags"])


def _aarch64_compiler() -> str | None:
    """A C compiler that targets AArch64 Linux, if this host has one.

    The native compiler on an AArch64 Linux host -- which is every
    ``ubuntu-24.04-arm`` lane of ci.yml -- resolved the way setup.py's own
    probe resolves it; otherwise a cross compiler on PATH.
    """
    if _ON_AARCH64_LINUX:
        compiler = os.environ.get("CC") or sysconfig.get_config_var("CC") or "cc"
        return str(compiler).split()[0]
    return shutil.which("aarch64-linux-gnu-gcc")


def _outline_atomic_symbols(readelf: str, obj: pathlib.Path) -> list[str]:
    """Every outline-atomics helper named in ``obj``'s symbol tables.

    In a relocatable object these are the undefined references the link will
    satisfy from libgcc.a; in a linked object they are the helpers it pulled
    in.  ``readelf`` reads any ELF machine, so this works on a cross build.
    """
    out = subprocess.run(
        [readelf, "-sW", str(obj)], capture_output=True, text=True, check=True, timeout=120
    ).stdout
    return sorted(set(_OUTLINE_ATOMIC_SYMBOL.findall(out)))


class TestLibgccCannotClearTheBtiProperty:
    """No binding extension may need a libgcc.a member on AArch64.

    ``GNU_PROPERTY_AARCH64_FEATURE_1_AND`` is an AND over every relocatable
    input to the link, and libgcc.a is one: none of the 398 members of the
    manylinux_2_28 aarch64 gcc-toolset-14 (14.2.1) libgcc.a carries a GNU
    property note.  GCC >= 10 defaults to ``-moutline-atomics`` on AArch64, so
    an atomic read-modify-write compiles to a call into libgcc.a, the link
    pulls ``ldadd_4_*.o`` and ``lse-init.o``, and the property is cleared for
    the whole extension.  Release dry run 35296160649 refused math_engine --
    the one extension with such atomics -- for exactly that reason.

    Each test fails on the CALL, not on the property note, because whether the
    note survives depends on whose libgcc.a is linked: Ubuntu's members are
    marked, so a native ``ubuntu-24.04-arm`` build kept the property and only
    the manylinux wheel lost it.  Three layers, since any one alone is
    defeatable: the selection (host-independent), the flag's effect on a real
    AArch64 compiler, and the built extensions on an AArch64 host.
    """

    def test_an_aarch64_linux_build_selects_inline_atomics(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # _compiler_accepts is stubbed so this asserts the SELECTION on any
        # host; the next test lets a real AArch64 compiler answer instead.
        monkeypatch.setenv("ARCHFLAGS", "")
        namespace = _setup_namespace(_aarch64_linux())
        namespace["_compiler_accepts"] = lambda flag: True
        flags, link_flags = _flags_fn(namespace)()
        assert "-mno-outline-atomics" in flags, (
            f"an AArch64 Linux build of the binding extensions does not get "
            f"-mno-outline-atomics, so an atomic read-modify-write calls into "
            f"libgcc.a and the unmarked member clears the BTI property of the "
            f"extension (compile flags: {flags})"
        )
        # The other unmarked input the same AND sees: the C runtime's
        # crti.o/crtn.o.  Pinned here because both halves are needed.
        assert "-nostartfiles" in link_flags, (
            f"an AArch64 Linux build of the binding extensions links the C "
            f"runtime's unmarked crti.o/crtn.o (link flags: {link_flags})"
        )

    @pytest.mark.parametrize(("machine", "system"), [("x86_64", "Linux"), ("arm64", "Darwin")])
    def test_no_other_target_is_given_the_flag(
        self, monkeypatch: pytest.MonkeyPatch, machine: str, system: str
    ) -> None:
        # x86 compilers reject the flag outright (gcc: "unrecognized
        # command-line option"), and a Mach-O object carries no GNU property
        # for libgcc.a to clear.
        monkeypatch.setenv("ARCHFLAGS", "")
        host = types.SimpleNamespace(machine=lambda: machine, system=lambda: system)
        namespace = _setup_namespace(host)
        namespace["_compiler_accepts"] = lambda flag: True
        flags, link_flags = _flags_fn(namespace)()
        assert "-mno-outline-atomics" not in flags + link_flags

    def test_the_selected_flags_compile_atomics_without_a_libgcc_call(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
    ) -> None:
        compiler = _aarch64_compiler()
        if compiler is None:
            pytest.skip(
                "no AArch64 C compiler on this host (runs natively on ci.yml's "
                "ubuntu-24.04-arm lanes, or anywhere aarch64-linux-gnu-gcc is on PATH)"
            )
        readelf = shutil.which("readelf") or shutil.which("llvm-readelf")
        if readelf is None:
            pytest.skip("no readelf on PATH")
        monkeypatch.setenv("ARCHFLAGS", "")
        monkeypatch.setenv("CC", compiler)
        namespace = _setup_namespace(_aarch64_linux())
        flags, _ = _flags_fn(namespace)()
        source = tmp_path / "probe.c"
        source.write_text(_ATOMIC_RMW_PROBE, encoding="utf-8")
        obj = tmp_path / "probe.o"

        def libgcc_calls(extra: list[str]) -> list[str]:
            subprocess.run(
                [compiler, *flags, *extra, "-fPIC", "-c", str(source), "-o", str(obj)],
                capture_output=True,
                check=True,
                timeout=120,
            )
            return _outline_atomic_symbols(readelf, obj)

        # Non-vacuity: this compiler really does route the probe through
        # libgcc.a when outline atomics are on.  Otherwise an empty answer below
        # would hold whatever setup.py selected.
        accepts = cast(Callable[[str], bool], namespace["_compiler_accepts"])
        if not accepts("-moutline-atomics"):
            pytest.skip(f"{compiler} has no outline atomics, so there is no libgcc call to avoid")
        assert libgcc_calls(["-moutline-atomics"]), (
            f"{compiler} compiled the atomic probe with -moutline-atomics and "
            f"emitted no libgcc helper call; this test cannot tell a correct "
            f"selection from a missing one"
        )

        calls = libgcc_calls([])
        assert calls == [], (
            f"with the flags setup.py selects for AArch64 ({flags}), an atomic "
            f"read-modify-write still calls {calls} in libgcc.a; linking that "
            f"member clears the extension's BTI property on every manylinux base"
        )

    @pytest.mark.skipif(
        not _ON_AARCH64_LINUX,
        reason="the in-tree extensions are AArch64 ELF objects only on an AArch64 Linux host",
    )
    def test_no_built_extension_links_a_libgcc_atomic_helper(self) -> None:
        readelf = shutil.which("readelf") or shutil.which("llvm-readelf")
        if readelf is None:
            pytest.skip("no readelf on PATH")
        suffix = str(sysconfig.get_config_var("EXT_SUFFIX") or ".so")
        built = sorted(
            path for path in (REPO_ROOT / "ama_cryptography").glob(f"*{suffix}") if path.is_file()
        )
        if not any(path.name.startswith("math_engine") for path in built):
            pytest.skip("math_engine is not built in this tree (Cython unavailable)")
        linked: dict[str, list[str]] = {}
        for ext in built:
            sections = subprocess.run(
                [readelf, "-SW", str(ext)], capture_output=True, text=True, check=True, timeout=120
            ).stdout
            # A stripped object has no .symtab, and then "no helper found"
            # would be a statement about the strip rather than the link.
            assert ".symtab" in sections, f"{ext.name} is stripped; its link cannot be inspected"
            helpers = _outline_atomic_symbols(readelf, ext)
            if helpers:
                linked[ext.name] = helpers
        assert not linked, (
            f"binding extensions linked libgcc.a's outline-atomics helpers: "
            f"{linked}.  The manylinux libgcc.a members carry no BTI property, "
            f"so the release wheel ships these objects with BTI cleared."
        )


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
