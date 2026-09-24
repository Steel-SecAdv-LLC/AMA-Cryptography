# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Every production-library switch combination must configure a test tree that links.

``-DAMA_BUILD_STATIC=OFF`` and ``-DAMA_BUILD_SHARED=OFF`` are documented
switches, and ``AMA_BUILD_TESTS`` defaults to ON.  ``tests/c/CMakeLists.txt``
linked ``test_dispatch_seal`` against ``ama_cryptography_static``
unconditionally.  With the static library switched off that name is not a
target, so CMake handed it to the linker as a plain library name and the build
of the test tree failed:

    /usr/bin/ld: cannot find -lama_cryptography_static

Nothing noticed, because every CI lane configures both libraries ON.

These tests configure the tree (configure only -- nothing is compiled) under
each non-default combination and read the generated link commands.  Every AMA
library a target links must be a target of THAT configuration, which the
generator writes as a path to the file it builds; a bare
``-lama_cryptography*`` is a name the linker would have to find on its own,
and in this tree it never can.  The seal test itself must stay registered
whenever either production library exists: the fix is a fallback to the shared
library (also a non-testing build, so the seal is still exercised), not a
quiet deregistration.

The examples tree had the same defect: ``examples/c/CMakeLists.txt`` linked
``ama_cryptography_static`` whenever ``AMA_BUILD_SHARED`` was OFF, whether or
not the static library existed.  It now links whichever production library is
a target and registers no example when neither is, so every configuration here
is configured with the examples ON and their link commands are scanned too.
"""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

#: A library name the linker is asked to find by itself.  CMake writes a
#: target it builds as a path (``lib/libama_cryptography_static.a``), so this
#: form appears only for a name that is not a target of the configuration.
_BARE_AMA_LIBRARY = re.compile(r"(?<![\w/.-])-lama_cryptography\w*")

#: ``add_test`` as CMake writes it into CTestTestfile.cmake, in both the
#: bracket-quoted form (CMake >= 3.20) and the plain one.
_SEAL_TEST_REGISTERED = re.compile(r"add_test\(\s*(?:\[=\[)?test_dispatch_seal(?:\]=\])?\s")


def _single_config_generator() -> str | None:
    """A generator whose link commands land in files this test can read."""
    if shutil.which("ninja"):
        return "Ninja"
    if platform.system() != "Windows" and shutil.which("make"):
        return "Unix Makefiles"
    return None


def _configure(tmp_path: Path, static: bool, shared: bool) -> Path:
    cmake = shutil.which("cmake")
    compiler = shutil.which("cc") or shutil.which("gcc")
    if cmake is None or compiler is None:
        pytest.skip("cmake and a C compiler are required to configure the tree")
    generator = _single_config_generator()
    if generator is None:
        pytest.skip(
            "no single-config CMake generator (ninja / make) is available, and "
            "a multi-config generator writes link items where this test does "
            "not read them"
        )
    build_dir = tmp_path / "build"
    result = subprocess.run(
        [
            cmake,
            "-S",
            str(REPO_ROOT),
            "-B",
            str(build_dir),
            "-G",
            generator,
            f"-DCMAKE_C_COMPILER={compiler}",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DAMA_BUILD_TESTS=ON",
            f"-DAMA_BUILD_STATIC={'ON' if static else 'OFF'}",
            f"-DAMA_BUILD_SHARED={'ON' if shared else 'OFF'}",
            "-DAMA_BUILD_EXAMPLES=ON",
        ],
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert result.returncode == 0, (
        f"configure failed with AMA_BUILD_STATIC={static} AMA_BUILD_SHARED={shared}:\n"
        f"{result.stdout[-4000:]}\n{result.stderr[-4000:]}"
    )
    return build_dir


def _link_command_files(build_dir: Path) -> list[Path]:
    files = [p for p in (build_dir / "build.ninja",) if p.is_file()]
    files += sorted(build_dir.rglob("link.txt"))
    return files


@pytest.mark.slow
@pytest.mark.parametrize(
    ("static", "shared"),
    [(False, True), (True, False), (False, False)],
    ids=["static-off", "shared-off", "both-off"],
)
def test_every_linked_ama_library_is_a_target(tmp_path: Path, static: bool, shared: bool) -> None:
    build_dir = _configure(tmp_path, static, shared)
    files = _link_command_files(build_dir)
    assert files, f"the generator wrote no link commands under {build_dir}"
    offenders = []
    for path in files:
        for match in sorted(set(_BARE_AMA_LIBRARY.findall(path.read_text(errors="replace")))):
            offenders.append(f"{path.relative_to(build_dir)}: {match}")
    assert not offenders, (
        "a target links an AMA library that this configuration does not build; "
        "the linker is left to find it by name and cannot:\n  " + "\n  ".join(offenders)
    )

    example_link = build_dir / "examples" / "c" / "CMakeFiles" / "simple_example.dir" / "link.txt"
    ninja = build_dir / "build.ninja"
    example_built = example_link.is_file() or (
        ninja.is_file() and "simple_example" in ninja.read_text(errors="replace")
    )
    assert example_built == (static or shared), (
        f"examples registered={example_built} with AMA_BUILD_STATIC={static} "
        f"AMA_BUILD_SHARED={shared}: they link whichever production library "
        "exists, and are registered only when one does"
    )

    ctest_file = build_dir / "tests" / "c" / "CTestTestfile.cmake"
    registered = bool(_SEAL_TEST_REGISTERED.search(ctest_file.read_text(errors="replace")))
    assert registered == (static or shared), (
        f"test_dispatch_seal registered={registered} with AMA_BUILD_STATIC={static} "
        f"AMA_BUILD_SHARED={shared}: it must run against whichever production "
        "library exists, and only when neither does is there nothing to seal-test"
    )
