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


class TestTheFlagIsSelected:
    @pytest.mark.skipif(sys.platform == "win32", reason="MSVC branch uses /guard:cf")
    def test_the_architectures_cfi_flag_is_in_the_compile_flags(self) -> None:
        flags, _ = _setup_namespace()["get_compiler_flags"]()  # type: ignore[operator]  # exec'd namespace: mypy cannot type the callable (BSA-002)
        machine = platform.machine().lower()
        if machine in ("x86_64", "amd64"):
            expected = "-fcf-protection=full"
        elif machine in ("aarch64", "arm64"):
            expected = "-mbranch-protection=standard"
        else:
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
