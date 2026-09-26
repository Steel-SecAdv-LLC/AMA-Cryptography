# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Every Makefile target is a command, and each one says what it does.

Three defects, all of them silent.

**``make docs`` did nothing.**  ``docs`` has no prerequisites and ``docs/`` is a
tracked directory, so GNU make treated the target as an up-to-date FILE and
skipped the recipe.  Measured on the Makefile as it stood::

    make -n docs
    -> make: 'docs' is up to date.

``docker`` and ``fuzz`` shadow directories the same way.  The recipe had just
been rewritten to route sphinx through ``$(RUN)``, under a comment asserting
"-W --keep-going turns every Sphinx warning into an error" — of a recipe that
never executed.

**``make security-audit`` ran the unscoped pip-audit** that the same commit
documents as broken two targets below: "a bare `pip-audit` reports CVEs in
packages this project does not ship (pip, urllib3 and whatever else the host
image carries), so the target went red for reasons nothing in this repository
can fix."

**``make c-api`` advertised a static library that is never produced.**
``CMakeLists.txt`` sets ``OUTPUT_NAME "ama_cryptography_static"``, so the
artefact is ``libama_cryptography_static.a``.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
MAKEFILE = REPO_ROOT / "Makefile"

#: `^name:` at column 0, excluding pattern rules and variable assignments.
_TARGET_RE = re.compile(r"^([a-z][a-z0-9_-]*):(?!=)", re.MULTILINE)


def _targets() -> list[str]:
    return _TARGET_RE.findall(MAKEFILE.read_text(encoding="utf-8"))


def _phony() -> set[str]:
    text = MAKEFILE.read_text(encoding="utf-8")
    match = re.search(r"^\.PHONY:((?:[^\n\\]*\\\n)*[^\n]*)", text, re.MULTILINE)
    assert match, ".PHONY is missing from the Makefile"
    return set(match.group(1).replace("\\\n", " ").split())


def test_the_sweep_finds_the_targets() -> None:
    """Non-vacuity: every assertion below iterates this list."""
    found = _targets()
    assert len(found) >= 20, found
    for expected in ("docs", "lint", "c-api", "security-audit"):
        assert expected in found, found


def test_every_target_is_phony() -> None:
    missing = sorted(set(_targets()) - _phony())
    assert not missing, (
        "Makefile targets that are not .PHONY — a directory of the same name "
        f"silently disables them: {missing}"
    )


@pytest.mark.parametrize("name", ["docs", "docker", "fuzz"])
def test_the_targets_that_shadow_a_directory_still_run(name: str) -> None:
    """The three that actually collide today, driven through make itself."""
    assert (REPO_ROOT / name).is_dir(), f"{name}/ is no longer a directory; drop this case"
    result = subprocess.run(
        ["make", "-n", name],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert "is up to date" not in result.stdout + result.stderr, (
        f"`make {name}` is a no-op: make resolved the target to the directory. "
        f"{result.stdout}{result.stderr}"
    )


def test_every_pip_audit_invocation_is_scoped() -> None:
    """An unscoped pip-audit reports CVEs in packages this project does not ship.

    Both spellings are matched: the Makefile invokes the module form
    (``pip_audit``) today, but the tool's common CLI name is ``pip-audit``,
    and a future edit switching spellings would otherwise carry an unscoped
    invocation straight past a filter keyed to one substring.
    """
    unscoped = [
        line.strip()
        for line in MAKEFILE.read_text(encoding="utf-8").splitlines()
        if re.search(r"pip[-_]audit", line) and "--requirement" not in line
        # Prose is not an invocation: echo lines and comments name the tool
        # without running it.
        and not re.match(r"\s*@?(#|echo\b)", line)
    ]
    assert not unscoped, unscoped


def test_the_c_api_target_names_the_library_the_build_produces() -> None:
    makefile = MAKEFILE.read_text(encoding="utf-8")
    cmake = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    assert (
        'OUTPUT_NAME "ama_cryptography_static"' in cmake
    ), "the static target's OUTPUT_NAME moved; this test's premise needs rechecking"
    assert "build/lib/libama_cryptography_static.a" in makefile
    assert (
        "build/lib/libama_cryptography.a" not in makefile
    ), "`make c-api` advertises a static library path the build never produces"


class TestTheDudectHarnessMakefileBuildsWhatItSaysItBuilds:
    """``tools/constant_time/Makefile`` claims lockstep it did not deliver.

    Its ``CRYPTO_SRCS`` comment says linking ``ama_kyber.c`` and
    ``ama_dilithium.c`` "keep[s] the harness binary in lockstep with what
    ``cmake -DAMA_USE_NATIVE_PQC=ON`` produces for the production build".
    Linking those translation units WITHOUT defining the macro does not:
    both compile their ``#else`` arms, so every ML-KEM and ML-DSA entry point
    in the harness binary returned ``AMA_ERROR_NOT_IMPLEMENTED``, and the
    dispatch auto-tune in ``ama_dispatch.c`` microbenched its NTT kernels
    inside a binary whose PQC was stubbed out.

    It also left 15 ``-Wall -Wextra`` warnings standing — fourteen ``defined
    but not used`` statics whose only callers live inside the native arms, and
    one unused parameter — which is how a real warning in this build goes
    unnoticed.  Measured: ``make clean && make all`` emitted 15 before, 0 after.

    The two halves are pinned together because each breaks the other: without
    ``ama_slhdsa.c`` the macro makes the link fail on ``ama_sphincs_keypair``
    / ``_sign`` / ``_verify`` (``ama_core.c`` references them under the macro),
    and without the macro the extra source is dead weight and the comment is
    false again.
    """

    HARNESS_MAKEFILE = REPO_ROOT / "tools" / "constant_time" / "Makefile"

    def _assignment(self, name: str) -> str:
        """The value of a (possibly ``\\``-continued) make variable, comments out.

        Read from the ASSIGNMENT rather than by searching the file, because the
        comment block above ``CFLAGS`` explains the flag by naming it — so a
        whole-file ``in`` test passes with the flag deleted from the recipe,
        which is what the first version of this class did.  A vacuous assertion
        in a test written to close vacuous assertions is worth the extra parse.
        """
        lines = self.HARNESS_MAKEFILE.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if not line.startswith(f"{name} ") and not line.startswith(f"{name}="):
                continue
            value = line.split("=", 1)[1]
            while value.rstrip().endswith("\\"):
                i += 1
                value = value.rstrip().rstrip("\\") + " " + lines[i]
            # Continuation lines may carry their own trailing comments.
            return " ".join(part.split("#", 1)[0] for part in value.splitlines())
        raise AssertionError(f"{name} is not assigned in {self.HARNESS_MAKEFILE}")

    def test_native_pqc_is_defined(self) -> None:
        cflags = self._assignment("CFLAGS")
        assert "-DAMA_USE_NATIVE_PQC" in cflags, (
            "tools/constant_time/Makefile links the PQC translation units but does "
            "not define AMA_USE_NATIVE_PQC in CFLAGS, so their entry points compile "
            "to AMA_ERROR_NOT_IMPLEMENTED and the lockstep the CRYPTO_SRCS comment "
            f"claims does not hold.  CFLAGS = {cflags!r}"
        )

    def test_the_slhdsa_source_the_macro_requires_is_linked(self) -> None:
        srcs = self._assignment("CRYPTO_SRCS")
        assert "ama_slhdsa.c" in srcs, (
            "AMA_USE_NATIVE_PQC makes ama_core.c reference ama_sphincs_keypair / "
            "_sign / _verify; without $(SRC_DIR)/ama_slhdsa.c in CRYPTO_SRCS the "
            f"harness fails to link.  CRYPTO_SRCS = {srcs!r}"
        )

    def test_the_pqc_translation_units_the_comment_names_are_linked(self) -> None:
        srcs = self._assignment("CRYPTO_SRCS")
        for src in ("ama_kyber.c", "ama_dilithium.c"):
            assert src in srcs, f"{src} left CRYPTO_SRCS; the lockstep claim needs it"

    def test_the_constant_time_aes_flag_is_still_there(self) -> None:
        """The control: the flag this line already carried must not be lost."""
        assert "-DAMA_AES_CONSTTIME=ON" in self._assignment("CFLAGS")

    def test_the_optimization_level_matches_the_release_build(self) -> None:
        """The lockstep claim extends to codegen, not just feature macros.

        The harness compiled at plain ``-O2`` with no NDEBUG while its own
        comment claimed the flags exist "so the timing measurements
        faithfully reflect what end users get" from the canonical Release
        build (``-O3 -DNDEBUG -fomit-frame-pointer -funroll-loops``).  The
        optimization level is load-bearing for exactly this class of
        measurement: rebuilding an instruction-count constant-time target at
        a different level immediately measured a 9,424-instruction
        key-dependent spread in the secp256k1 scalar arithmetic (recorded in
        check_workflow_commands.check_cmake_build_type).  A timing harness
        measuring different codegen than the shipped library measures the
        wrong artefact.
        """
        cflags = self._assignment("CFLAGS")
        for flag in ("-O3", "-DNDEBUG", "-fomit-frame-pointer", "-funroll-loops"):
            assert flag in cflags, (
                f"{flag} left tools/constant_time/Makefile CFLAGS; the harness no "
                f"longer compiles the codegen the canonical Release library ships, "
                f"so its timing measurements describe a different binary.  "
                f"CFLAGS = {cflags!r}"
            )
        for stale in ("-O0", "-O1", "-O2"):
            assert stale not in cflags.split(), (
                f"{stale} in CFLAGS overrides the Release optimization level "
                f"(last -O wins with gcc).  CFLAGS = {cflags!r}"
            )


class TestTheBenchmarksMakefileBuildsWithoutAPrebuiltLibrary:
    """``make -C benchmarks benchmark_c_raw`` on a tree with no ``build/``.

    The recipe advertised a no-library fallback -- "No pre-built library
    found. Compiling from sources..." -- that compiled
    ``$(wildcard src/c/ama_*.c)`` with the harness and could never produce a
    binary.  Measured on a fresh worktree: the compile stops in
    ``ama_sha256_ni.c`` (``_mm_sha256rnds2_epu32``: target specific option
    mismatch), because the glob carries none of the per-file ISA flags CMake
    applies; with ``-march=native`` added to get past that, the link fails on
    ``ama_get_dispatch_table``, which lives in ``src/c/dispatch/`` where the
    glob does not look.  It also defined neither ``AMA_USE_NATIVE_PQC`` nor
    ``AMA_AES_CONSTTIME``.  The fallback now builds the static archive through
    CMake, the one complete description of the library, and links that.

    Driven through make itself with recording stand-ins for ``cmake`` and the
    compiler, in a scratch tree whose ``src/`` and ``include/`` are the real
    ones -- so the old recipe, which globs them, is exercised as it was.
    """

    def test_the_fallback_builds_the_archive_with_cmake_and_links_it(self, tmp_path: Path) -> None:
        if sys.platform == "win32" or shutil.which("make") is None:
            pytest.skip("benchmarks/Makefile is a POSIX make recipe")
        root = tmp_path / "tree"
        (root / "benchmarks").mkdir(parents=True)
        for name in ("Makefile", "benchmark_c_raw.c"):
            shutil.copy(REPO_ROOT / "benchmarks" / name, root / "benchmarks" / name)
        for name in ("src", "include"):
            (root / name).symlink_to(REPO_ROOT / name, target_is_directory=True)

        log = tmp_path / "calls.log"
        stubs = tmp_path / "bin"
        stubs.mkdir()
        cmake = stubs / "cmake"
        cmake.write_text(
            "#!/bin/sh\n"
            f'echo "cmake $*" >> "{log}"\n'
            'prev=""\n'
            "for arg; do\n"
            '  if [ "$prev" = "--build" ]; then\n'
            '    mkdir -p "$arg/lib" && : > "$arg/lib/libama_cryptography_static.a"\n'
            "  fi\n"
            '  prev="$arg"\n'
            "done\n",
            encoding="utf-8",
        )
        cc = stubs / "cc"
        cc.write_text(
            "#!/bin/sh\n"
            f'echo "cc $*" >> "{log}"\n'
            'prev=""\n'
            'for arg; do [ "$prev" = "-o" ] && : > "$arg"; prev="$arg"; done\n',
            encoding="utf-8",
        )
        cmake.chmod(0o755)
        cc.chmod(0o755)

        result = subprocess.run(
            [
                "make",
                "-C",
                str(root / "benchmarks"),
                "benchmark_c_raw",
                f"CC={cc}",
                f"CMAKE={cmake}",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        calls = log.read_text(encoding="utf-8").splitlines()
        configure = [c for c in calls if c.startswith("cmake ") and " -S " in c]
        build = [c for c in calls if c.startswith("cmake ") and " --build " in c]
        compiles = [c for c in calls if c.startswith("cc ")]

        assert len(configure) == 1, calls
        for flag in (f"-S {root}", f"-B {root}/build", "-DCMAKE_BUILD_TYPE=Release"):
            assert flag in configure[0], configure[0]
        assert "-DAMA_USE_NATIVE_PQC=ON" in configure[0], configure[0]
        assert "AMA_AES_CONSTTIME=OFF" not in configure[0], configure[0]
        assert len(build) == 1 and "--target ama_cryptography_static" in build[0], calls
        assert len(compiles) == 1, calls
        assert f"{root}/build/lib/libama_cryptography_static.a" in compiles[0], compiles[0]
        assert not re.search(r"/src/c/\S+\.c\b", compiles[0]), (
            "the fallback compiles library sources itself instead of linking the "
            f"archive CMake built: {compiles[0]}"
        )
        assert (root / "benchmarks" / "benchmark_c_raw").is_file()
