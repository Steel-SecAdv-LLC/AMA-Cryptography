# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The generated ama_cryptography.pc must name the directories the library is
installed to, whether GNUInstallDirs was given them relative or absolute.

WHY THIS TEST EXISTS

``include(GNUInstallDirs)`` went in so the generated ``.pc`` would follow the
host's library layout instead of a hardcoded ``lib`` a packager would have to
patch.  GNUInstallDirs accepts ``CMAKE_INSTALL_LIBDIR`` and
``CMAKE_INSTALL_INCLUDEDIR`` as absolute paths -- Nix's CMake setup hook passes
them that way -- and ``ama_cryptography.pc.in`` prefixed both unconditionally:

    libdir=${exec_prefix}/@CMAKE_INSTALL_LIBDIR@

Measured at the parent commit, configured with ``CMAKE_INSTALL_PREFIX=/opt/out``
and ``CMAKE_INSTALL_LIBDIR=/nix/store/abc-lib/lib``: the ``.pc`` read
``libdir=${exec_prefix}//nix/store/abc-lib/lib`` and ``pkg-config --libs``
emitted ``-L/opt/out/nix/store/abc-lib/lib`` -- a directory that does not exist,
so every downstream link failed.  That is the packager case the change was made
for.

WHAT IT ENFORCES

The real top-level CMakeLists.txt is configured twice, each time with one of
the two directories absolute and the other relative, and the generated ``.pc``
is resolved the way pkg-config resolves it.  An absolute directory must come
out verbatim; a relative one must keep the relocatable ``${exec_prefix}/`` or
``${prefix}/`` form.  PIN: reverting either template line to the unconditional
prefix fails the configure that makes that directory absolute.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(shutil.which("cmake") is None, reason="cmake is not on PATH")

_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _configure(build: Path, prefix: Path, libdir: str, includedir: str) -> dict[str, str]:
    """Configure the project and return the .pc's variables, raw."""
    cmake = shutil.which("cmake")
    assert cmake is not None
    proc = subprocess.run(
        [
            cmake,
            "-S",
            str(REPO_ROOT),
            "-B",
            str(build),
            f"-DCMAKE_INSTALL_PREFIX={prefix.as_posix()}",
            f"-DCMAKE_INSTALL_LIBDIR={libdir}",
            f"-DCMAKE_INSTALL_INCLUDEDIR={includedir}",
            "-DAMA_BUILD_TESTS=OFF",
            "-DAMA_BUILD_EXAMPLES=OFF",
            # This test is about the .pc, not the compiler; an unlisted
            # toolchain must not stop the configure before the file is written.
            "-DAMA_ALLOW_UNVERIFIED_TOOLCHAIN=ON",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )
    assert proc.returncode == 0, f"configure failed:\n{proc.stdout}\n{proc.stderr}"
    pc = build / "ama_cryptography.pc"
    assert pc.is_file(), f"configure wrote no {pc.name}"
    variables: dict[str, str] = {}
    for line in pc.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if m:
            variables[m.group(1)] = m.group(2)
    for name in ("prefix", "exec_prefix", "libdir", "includedir"):
        assert name in variables, f"{pc.name} defines no {name}"
    return variables


def _resolve(variables: dict[str, str], name: str) -> str:
    """Expand ${var} references the way pkg-config does."""
    value = variables[name]
    for _ in range(len(variables) + 1):
        expanded = _VAR.sub(lambda m: variables[m.group(1)], value)
        if expanded == value:
            return value
        value = expanded
    raise AssertionError(f"{name} does not resolve: {variables[name]!r}")


def test_an_absolute_libdir_is_written_as_given(tmp_path: Path) -> None:
    prefix = tmp_path / "prefix"
    libdir = (tmp_path / "separate-lib-output" / "lib").as_posix()
    variables = _configure(tmp_path / "build", prefix, libdir, "include")

    assert _resolve(variables, "libdir") == libdir, (
        f"CMAKE_INSTALL_LIBDIR={libdir} is absolute, but the .pc resolves libdir "
        f"to {_resolve(variables, 'libdir')!r}: pkg-config --libs would emit a -L "
        f"directory the library was never installed to"
    )
    # The relative one, in the same file, stays relocatable.
    assert variables["includedir"] == "${prefix}/include"
    assert _resolve(variables, "includedir") == f"{prefix.as_posix()}/include"


def test_an_absolute_includedir_is_written_as_given(tmp_path: Path) -> None:
    prefix = tmp_path / "prefix"
    includedir = (tmp_path / "separate-dev-output" / "include").as_posix()
    variables = _configure(tmp_path / "build", prefix, "lib64", includedir)

    assert _resolve(variables, "includedir") == includedir, (
        f"CMAKE_INSTALL_INCLUDEDIR={includedir} is absolute, but the .pc resolves "
        f"includedir to {_resolve(variables, 'includedir')!r}: pkg-config --cflags "
        f"would emit an -I directory the headers were never installed to"
    )
    # The relative one, in the same file, stays relocatable.
    assert variables["libdir"] == "${exec_prefix}/lib64"
    assert _resolve(variables, "libdir") == f"{prefix.as_posix()}/lib64"
