#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography Setup Script
============================

Multi-language build system with C extensions and Cython optimizations.

Build modes:
    python setup.py build         # Build C extensions and Cython modules
    python setup.py build_ext     # Build extensions only
    python setup.py install       # Install package
    python setup.py develop       # Development install
    python setup.py sdist         # Source distribution
    python setup.py bdist_wheel   # Binary wheel distribution

Environment variables:
    AMA_NO_CYTHON=1              # Disable Cython compilation (use pure Python)
    AMA_NO_C_EXTENSIONS=1        # Disable C extensions
    AMA_DEBUG=1                  # Enable debug symbols
    AMA_COVERAGE=1               # Enable coverage instrumentation
"""

import glob
import os
import platform
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Callable, Optional

# D-9: Preflight version checks for every build-time dependency listed in
# pyproject.toml's [build-system].requires.  Each floor here is kept IDENTICAL
# to the version pinned there, so the guard enforces exactly what an isolated
# PEP 517 build installs — the comment "enforced by setup.py's preflight check"
# is factually accurate (Copilot review #5 / D-9-extended).
#
#   * setuptools >= 83.0.0:  Debian's patched setuptools 68.x raises
#     AttributeError(install_layout) deep inside pip's bdist_wheel subprocess.
#     70.0.0 closes GHSA-cx63-2mw6-8hw5 and 78.1.1 closes PYSEC-2025-49; the
#     floor is pinned at 83.0.0 to match pyproject.toml's [build-system].
#   * wheel >= 0.47.0:        closes GHSA-8rrh-rw8j-w5fx.
#   * cmake >= 4.4.0:         supply-chain floor (matches pyproject.toml's
#     [build-system].requires).  CMakeLists.txt's cmake_minimum_required is
#     3.15, but this higher floor is enforced for supply-chain security.
#   * Cython >= 3.2.8:        floor for the math_engine extension's
#     `cimport numpy` typed-memoryview surface.
#   * numpy >= 1.24.0:        provides the `numpy.pxd` headers the Cython
#     extension absorbs at C-compile time.
#
# Failing fast with a single FATAL message is far better than the opaque
# downstream errors users would otherwise see (AttributeError deep inside
# pip's wheel-build subprocess; "numpy.pxd not found" inside Cython's
# cythonize call; cmake_minimum_required abort; etc.).
#
# Version comparison goes through packaging.version.Version when available
# (handles PEP 440 + Debian-style local/build suffixes like "70.0.0+deb"
# and "70.0.0-1" — Copilot review #6).  When packaging is unavailable
# (very old build environments), we pad the digit-only tuple to length 3
# so 70.0+ still satisfies (70, 0, 0).
_BUILD_REQS = {
    "setuptools": ((83, 0, 0), "AttributeError(install_layout) on bdist_wheel"),
    "wheel": ((0, 47, 0), "GHSA-8rrh-rw8j-w5fx"),
    "cmake": (
        (4, 4, 0),
        "Dependabot supply-chain floor (pyproject.toml [build-system].requires);"
        " CMakeLists.txt cmake_minimum_required is 3.15 but this higher"
        " floor is enforced for supply-chain security",
    ),
    "Cython": ((3, 2, 8), "math_engine cimport numpy stability floor"),
    "numpy": ((1, 24, 0), "numpy.pxd headers required by math_engine"),
}


def _pad3(parts: Sequence[int]) -> tuple[int, int, int]:
    """Exactly three components, so ``(70, 0)`` compares as ``(70, 0, 0)``.

    Indexed rather than concatenated with a padding tuple: ``tuple(x) + (0,) *
    n`` has type ``tuple[int, ...]``, which says nothing about the arity the
    comparisons below depend on.
    """
    padded = list(parts[:3]) + [0, 0, 0]
    return (padded[0], padded[1], padded[2])


def _parse_version(raw: str) -> tuple[int, int, int]:
    """Best-effort PEP 440 parse → 3-tuple of ints.

    Falls back to a tolerant digit-only split when ``packaging`` is not
    importable.  Local / build suffixes (``+deb``, ``-1``) are stripped
    so a Debian-packaged ``70.0.0+deb`` does not get rejected as
    ``(70, 0)`` by a naive ``split('.')`` (Copilot review #6).
    """
    try:
        from packaging.version import Version

        v = Version(raw)
        return _pad3(v.release)
    except Exception:  # pragma: no cover - packaging is in modern setuptools
        # Strip local/build segments and any pre/post markers; keep only
        # the leading dotted-numeric release portion.
        head = raw.split("+", 1)[0].split("-", 1)[0]
        digits = [int(x) for x in head.split(".") if x.isdigit()]
        return _pad3(digits)


_REMEDY = (
    "  python3 -m pip install --upgrade "
    "'setuptools>=83.0.0' 'wheel>=0.47.0' 'cmake>=4.4.0' "
    "'Cython>=3.2.8' 'numpy>=1.24.0'\n"
)


def _check_build_dependency(import_name: str, attr: str = "__version__") -> None:
    floor, reason = _BUILD_REQS[import_name]
    try:
        mod = __import__(import_name)
    except ImportError:
        # The module is enforced by [build-system].requires; absent it,
        # the build cannot proceed regardless.  Surface the same FATAL
        # path so the user sees one consolidated remedy.
        sys.stderr.write(
            f"FATAL: {import_name} is required at build time (>= "
            f"{'.'.join(str(x) for x in floor)}, reason: {reason}). "
            f"Install with:\n{_REMEDY}"
        )
        sys.exit(1)
    raw = getattr(mod, attr, None)
    if raw is None:
        # Older releases without a __version__ attribute — let the build
        # try to proceed.  pyproject.toml's PEP 517 isolation pulls in
        # versions that DO carry __version__, so this branch is mostly
        # defensive against weird vendored installs.
        return
    parsed = _parse_version(str(raw))
    if parsed < floor:
        sys.stderr.write(
            f"FATAL: {import_name} >= {'.'.join(str(x) for x in floor)} "
            f"required (found {raw}; reason: {reason}). Upgrade with:\n{_REMEDY}"
        )
        sys.exit(1)


def _check_cmake_version() -> None:
    """Dual-path cmake floor check.

    cmake is fundamentally a CLI tool, not a Python module — but
    pyproject.toml's [build-system].requires installs the ``cmake`` PyPI
    shim (which carries ``cmake.__version__``) into PEP 517 isolated
    build envs.  Direct ``python setup.py`` invocations instead rely on
    the system cmake CLI (apt / brew / dnf / cmake.org installer).
    Probe both paths so neither fails spuriously: prefer the PyPI shim
    when present, otherwise parse ``cmake --version`` from the CLI on
    PATH.  Either way, enforce the same floor as ``_BUILD_REQS["cmake"]``
    and ``pyproject.toml`` so the audit trail stays consistent across
    all four pin sites (Copilot review @ setup.py:150 + Devin review
    @ setup.py:63).
    """
    floor, reason = _BUILD_REQS["cmake"]
    raw: Optional[str] = None
    # Path A: PyPI cmake shim (PEP 517 isolated build env).
    try:
        import cmake as _cmake

        raw = getattr(_cmake, "__version__", None)
    except ImportError:
        pass  # PyPI cmake shim not installed; fall through to CLI probe
    # Path B: system cmake CLI.
    if raw is None:
        try:
            result = subprocess.run(
                ["cmake", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0 and result.stdout:
                first_line = result.stdout.splitlines()[0]
                parts = first_line.split()
                # Expected: "cmake version X.Y.Z"
                if len(parts) >= 3 and parts[0] == "cmake" and parts[1] == "version":
                    raw = parts[2]
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass  # cmake CLI not on PATH or timed out; fall through to FATAL
    if raw is None:
        sys.stderr.write(
            f"FATAL: cmake is required at build time (>= "
            f"{'.'.join(str(x) for x in floor)}, reason: {reason}). "
            f"Install via your system package manager (apt install cmake / "
            f"brew install cmake / dnf install cmake) or:\n{_REMEDY}"
        )
        sys.exit(1)
    parsed = _parse_version(str(raw))
    if parsed < floor:
        sys.stderr.write(
            f"FATAL: cmake >= {'.'.join(str(x) for x in floor)} "
            f"required (found {raw}; reason: {reason}). Upgrade with:\n{_REMEDY}"
        )
        sys.exit(1)


# Run the preflight before any setuptools imports below — the Debian
# install_layout regression fires inside setuptools' own __init__ paths
# during bdist_wheel, so a check that runs after `from setuptools import
# Extension` would race the very failure mode it is meant to prevent.
# setuptools and wheel are checked unconditionally — they are required
# for any setup.py invocation regardless of whether Cython is enabled.
# Cython and numpy are only required when the math_engine Cython
# extension is being built; the documented ``AMA_NO_CYTHON=1`` opt-out
# (and its companion ``AMA_NO_C_EXTENSIONS=1``, which empties the Cython
# extension list — the native library itself is built via CMake in every
# configuration) must therefore skip those preflight checks.  Copilot reviews #12/#15/#22 and Devin review #13
# observed that the previous form ran every floor unconditionally,
# turning a documented opt-out into an unconditional FATAL when the
# environment lacked Cython/numpy (e.g. minimal embedded builders or
# ``pip install --no-build-isolation`` against a host without
# Cython/numpy).  pyproject.toml's [build-system].requires comment
# already reads "FATAL unless AMA_NO_CYTHON=1"; this brings the runtime
# behaviour in line with the documented contract.
for _name in ("setuptools", "wheel"):
    _check_build_dependency(_name)

# cmake is needed for the C-side build (CMakeBuild → cmake_minimum_required
# in CMakeLists.txt) — UNCONDITIONALLY.  This used to be skipped under
# AMA_NO_C_EXTENSIONS=1 on the premise that the flag opts out of "the entire
# native build"; that premise stopped holding when NativeDistribution made
# has_ext_modules() return True in every configuration: `build` always
# schedules build_ext, CMakeBuild.run() calls _build_cmake() before it ever
# looks at self.extensions, and the native library is built for every wheel.
# So the env var was silently bypassing the supply-chain version floor while
# cmake was still invoked — the flag now selects only whether the CYTHON
# binding extensions are built (see USE_C_EXTENSIONS below), never whether
# cmake runs.  Copilot review @ setup.py:150 + Devin review @ setup.py:63
# caught the original drift where pyproject.toml [build-system].requires was
# bumped to cmake>=4.3.2 but setup.py's preflight hadn't matched.
_check_cmake_version()

_SKIP_CYTHON_PREFLIGHT = bool(os.getenv("AMA_NO_CYTHON")) or bool(os.getenv("AMA_NO_C_EXTENSIONS"))
if not _SKIP_CYTHON_PREFLIGHT:
    for _name in ("Cython", "numpy"):
        _check_build_dependency(_name)
else:
    sys.stderr.write(
        "AMA_NO_CYTHON / AMA_NO_C_EXTENSIONS set: skipping Cython/numpy "
        "preflight (the math_engine accelerator will not be built).\n"
    )

from setuptools import Extension, find_packages, setup  # noqa: E402 -- follows preflight (SU-001)
from setuptools.command.build_ext import build_ext  # noqa: E402 -- follows preflight (SU-001)
from setuptools.dist import Distribution  # noqa: E402 -- follows preflight (SU-001)

# Check for Cython availability at the call-site level (the preflight
# above only proves a minimum version; AMA_NO_CYTHON=1 still gates
# whether Cython is actually invoked).
# Declared before the import so the except branch can bind None: without the
# declaration the name takes the imported function's type and `= None` is an
# incompatible assignment.
cythonize: Any
try:
    from Cython.Build import cythonize as _cythonize

    cythonize = _cythonize
    CYTHON_AVAILABLE = True
except ImportError:  # pragma: no cover - preflight should have caught this
    # CodeQL flagged this as an empty except without explanation
    # (https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/security/code-scanning/503).
    # The preflight at the top of this module already validates Cython is
    # importable and at the required version floor; a second ImportError
    # here means the user opted out (AMA_NO_CYTHON=1) or is running an
    # exotic embedded interpreter where the preflight short-circuited.
    # Either way the right behaviour is to fall through to the pure-C
    # extension build path; the wheel will still be functional, just
    # without the math_engine accelerator.
    CYTHON_AVAILABLE = False
    cythonize = None

# Check for NumPy availability (needed for C API headers)
np: Any
try:
    import numpy as _np

    np = _np
    NUMPY_AVAILABLE = True
except ImportError:  # pragma: no cover - preflight should have caught this
    # Same rationale as the Cython block above: the preflight enforces
    # numpy>=1.24.0; a second ImportError here means an opt-out path
    # (AMA_NO_CYTHON=1 short-circuits the math_engine build, which is
    # the only consumer of numpy headers) and the build can proceed.
    NUMPY_AVAILABLE = False
    np = None

# Configuration
VERSION = "5.0.0"
USE_CYTHON = CYTHON_AVAILABLE and not os.getenv("AMA_NO_CYTHON")
USE_C_EXTENSIONS = not os.getenv("AMA_NO_C_EXTENSIONS")
DEBUG = bool(os.getenv("AMA_DEBUG"))
COVERAGE = bool(os.getenv("AMA_COVERAGE"))

# D-3: setup.py drives CMake into an isolated subdirectory so it does not
# collide with a hand-driven `make c` (which uses ./build/).  Running the two
# concurrently against a shared build dir corrupts the CMakeFiles/ compiler
# probe and produces opaque "configure_file: No such file or directory"
# failures (audit reproduced this).  Keeping the two paths separate makes the
# two build systems composable.
PY_CMAKE_BUILD_DIR = Path("build") / "python-cmake"

# Read long description
long_description = (Path(__file__).resolve().parent / "README.md").read_text(encoding="utf-8")


def get_compiler_flags() -> tuple[list[str], list[str]]:
    """Get compiler flags based on platform and configuration."""
    flags = []
    link_flags = []

    if platform.system() == "Windows":
        # /guard:cf matches what CMakeLists.txt gives the MSVC library targets;
        # without it the binding extensions — which marshal keys and plaintexts
        # across the C boundary — were the least hardened artefacts in the wheel.
        flags.extend(["/O2", "/W3", "/guard:cf"])
        link_flags.extend(["/guard:cf", "/DYNAMICBASE", "/NXCOMPAT"])
    else:
        # Linux/macOS
        flags.extend(
            [
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Wformat=2",
                "-fstack-protector-strong",
            ]
        )

        if DEBUG:
            flags.extend(["-O0", "-g3", "-DDEBUG"])
        else:
            # Note: -march=native removed for portability across CI environments
            # _FORTIFY_SOURCE mirrors the CMake Release flags; it is inert
            # without optimisation, hence the non-DEBUG branch only.  The
            # published wheels are built in manylinux containers whose GCC does
            # not enable it by default, so these extensions shipped without the
            # fortified string/memory checks the C library has had all along.
            flags.extend(["-O3", "-DNDEBUG", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=2"])

        # ELF link hardening, matching the library (see CMakeLists.txt): full
        # RELRO closes GOT-overwrite, and an explicit non-executable stack does
        # not depend on every linked object carrying .note.GNU-stack.  macOS's
        # ld does not accept -z options, so this is Linux-only.
        if platform.system() == "Linux":
            link_flags.extend(["-Wl,-z,relro", "-Wl,-z,now", "-Wl,-z,noexecstack"])

        if COVERAGE:
            flags.extend(["--coverage"])
            link_flags.extend(["--coverage"])

    return flags, link_flags


def get_extension_modules() -> list[Extension]:
    """Build list of extension modules."""
    extensions: list[Extension] = []
    compiler_flags, linker_flags = get_compiler_flags()

    if not USE_C_EXTENSIONS:
        return extensions

    # Note: The native C library (ama_core.c, ama_consttime.c, etc.) is built
    # by CMake in CMakeBuild.run(), NOT as a Python extension module.
    # Those files lack PyInit_* functions required for Python C extensions.

    # Cython mathematical engine (if Cython available)
    if USE_CYTHON:
        # Build include dirs for math engine
        math_include_dirs = ["include"]
        if NUMPY_AVAILABLE:
            # Add NumPy C API headers for numpy/arrayobject.h
            math_include_dirs.append(np.get_include())

        math_ext = Extension(
            name="ama_cryptography.math_engine",
            sources=["src/cython/math_engine.pyx"],
            include_dirs=math_include_dirs,
            extra_compile_args=compiler_flags,
            extra_link_args=linker_flags,
            language="c",
        )
        extensions.append(math_ext)

        # Platform-conditional rpath: $ORIGIN is ELF/Linux, @loader_path is Mach-O/macOS.
        #
        # D-1: $ORIGIN (the directory containing the binding .so itself) is
        # listed FIRST so pip-installed wheels resolve libama_cryptography.so
        # from the bundled package directory.  The legacy ../build/lib entries
        # are kept as fallbacks for in-tree development, where the binding
        # extensions are built `--inplace` next to the source layout and the
        # native library still lives under ./build/lib.
        rpath = []
        if sys.platform.startswith("linux"):
            rpath = ["$ORIGIN", "$ORIGIN/../build/lib", "$ORIGIN/../../build/lib"]
        elif sys.platform == "darwin":
            rpath = [
                "@loader_path",
                "@loader_path/../build/lib",
                "@loader_path/../../build/lib",
            ]

        # Cython HMAC-SHA3-256 binding (calls ama_hmac_sha3_256 in libama_cryptography)
        hmac_ext = Extension(
            name="ama_cryptography.hmac_binding",
            sources=["src/cython/hmac_binding.pyx"],
            include_dirs=["include"],
            library_dirs=["build/lib"],
            libraries=["ama_cryptography"],
            runtime_library_dirs=rpath,
            extra_compile_args=compiler_flags,
            extra_link_args=linker_flags,
            language="c",
        )
        extensions.append(hmac_ext)

        # Cython SHA3-256 binding (calls ama_sha3_256 in libama_cryptography)
        sha3_ext = Extension(
            name="ama_cryptography.sha3_binding",
            sources=["src/cython/sha3_binding.pyx"],
            include_dirs=["include"],
            library_dirs=["build/lib"],
            libraries=["ama_cryptography"],
            runtime_library_dirs=rpath,
            extra_compile_args=compiler_flags,
            extra_link_args=linker_flags,
            language="c",
        )
        extensions.append(sha3_ext)

        # Cython Ed25519 binding (calls ama_ed25519_* in libama_cryptography)
        ed25519_ext = Extension(
            name="ama_cryptography.ed25519_binding",
            sources=["src/cython/ed25519_binding.pyx"],
            include_dirs=["include"],
            library_dirs=["build/lib"],
            libraries=["ama_cryptography"],
            runtime_library_dirs=rpath,
            extra_compile_args=compiler_flags,
            extra_link_args=linker_flags,
            language="c",
        )
        extensions.append(ed25519_ext)

        # Cython Dilithium binding (calls ama_dilithium_* in libama_cryptography)
        dilithium_ext = Extension(
            name="ama_cryptography.dilithium_binding",
            sources=["src/cython/dilithium_binding.pyx"],
            include_dirs=["include"],
            library_dirs=["build/lib"],
            libraries=["ama_cryptography"],
            runtime_library_dirs=rpath,
            extra_compile_args=compiler_flags,
            extra_link_args=linker_flags,
            language="c",
        )
        extensions.append(dilithium_ext)

        # Cython HKDF binding (calls ama_hkdf in libama_cryptography)
        hkdf_ext = Extension(
            name="ama_cryptography.hkdf_binding",
            sources=["src/cython/hkdf_binding.pyx"],
            include_dirs=["include"],
            library_dirs=["build/lib"],
            libraries=["ama_cryptography"],
            runtime_library_dirs=rpath,
            extra_compile_args=compiler_flags,
            extra_link_args=linker_flags,
            language="c",
        )
        extensions.append(hkdf_ext)

    return extensions


def get_cythonized_extensions() -> list[Extension]:
    """Apply Cython to extensions if available."""
    extensions = get_extension_modules()

    if USE_CYTHON and extensions:
        # Cythonize with compiler directives
        compiler_directives = {
            "language_level": "3",
            "embedsignature": True,
            "boundscheck": DEBUG,
            "wraparound": DEBUG,
            "cdivision": not DEBUG,
            "initializedcheck": DEBUG,
            "profile": COVERAGE,
            "linetrace": COVERAGE,
        }

        # list(): cythonize is untyped third-party, so its result is Any, and
        # returning Any from a function declared to return list[Extension]
        # silently erases the annotation for every caller.
        cythonized: list[Extension] = list(
            cythonize(
                extensions,
                compiler_directives=compiler_directives,
                annotate=DEBUG,  # Generate HTML annotation files in debug mode
            )
        )
        return cythonized

    return extensions


class NativeDistribution(Distribution):
    """Declares this distribution native, whether or not it has ext_modules.

    Two things read ``Distribution.has_ext_modules()``, and both were wrong
    for this package whenever ``ext_modules`` came back empty:

    1. ``build.sub_commands`` gates ``build_ext`` on it.  Every one of the six
       binding Extensions is declared inside ``if USE_CYTHON:`` in
       ``get_extension_modules()``, so ``AMA_NO_CYTHON=1`` (and
       ``AMA_NO_C_EXTENSIONS=1``) empties the list, setuptools skips
       ``build_ext`` entirely, and ``CMakeBuild.run`` — the ONLY caller of
       ``_build_cmake`` and ``_copy_native_library_into_package`` — never
       runs.  The resulting wheel contained no ``libama_cryptography.so`` at
       all, so the install imported straight into
       ``CryptoModuleError: no native library found in any of 17 searched
       directories``.  Measured on 3baf6c3 and on ``origin/main`` before it:
       ``AMA_NO_CYTHON=1 pip install .`` exits 0 and produces an install that
       cannot import.  README, ENHANCED_FEATURES.md and IMPLEMENTATION_GUIDE
       all list the variable as a supported "pure Python" mode, and setup.py
       itself prints ``AMA_NO_CYTHON=1 pip install .`` as the escape from a
       fatal Cython error — an escape into a broken install.
    2. ``bdist_wheel.root_is_pure`` derives from it, so that same build was
       tagged ``py3-none-any``.  A pure tag on a distribution whose only
       working form ships a platform-specific shared object is a wheel that
       installs anywhere and works nowhere.  With this class it is tagged
       ``cp3XX-cp3XX-<platform>``, which is over-specific rather than wrong:
       without binding extensions the package would in fact run on any
       CPython >= 3.10, but a native artefact must never carry ``any``.

    There is no configuration in which this package is pure.  INVARIANT-7
    forbids operating without the native backend, and POST enforces it at
    import, so "pure Python AMA Cryptography" is not a degraded mode — it is
    a module that refuses to initialise.  The Cython switches select whether
    the optional Python BINDINGS are built; they never selected whether the
    library itself is.
    """

    def has_ext_modules(self) -> bool:
        return True


class CMakeBuild(build_ext):
    """Custom build_ext command that builds CMake projects.

    Responsibilities (in order):
      1. Build the native C library (libama_cryptography) via CMake into an
         isolated subdirectory (D-3) so this command does not race with a
         user-driven `make c` against ./build/.
      2. Copy the produced libama_cryptography.so* into the in-tree
         ama_cryptography/ package directory (D-1) so the resulting wheel
         contains everything required to import the package — no
         LD_LIBRARY_PATH or `sudo make install` step needed.
      3. Build the Cython binding extensions.  When a user has both Cython
         and numpy installed (the documented dev path), failures here are
         FATAL (D-4): a silent fallthrough produced builds advertising
         optimised primitives that did not actually exist.  Genuine pure-
         Python builds opt out with AMA_NO_CYTHON=1.
    """

    def run(self) -> None:
        self._build_cmake()
        self._copy_native_library_into_package()

        if self.extensions:
            # D-4: Cython failures are now fatal unless the user explicitly opted
            # out of Cython entirely (AMA_NO_CYTHON=1) or asked to skip C
            # extensions altogether (AMA_NO_C_EXTENSIONS=1).  Previously the
            # exception was caught and downgraded to a warning, which produced
            # broken installs that quietly advertised "Cython available: False"
            # while having no extension .so files at all (audit D-4).
            if not USE_CYTHON:
                self._run_integrity_signer()
                return
            if not NUMPY_AVAILABLE:
                raise RuntimeError(
                    "FATAL: numpy is required to build the Cython math_engine extension "
                    "(src/cython/math_engine.pyx uses `cimport numpy`).\n"
                    "Install with:\n"
                    "  pip install 'numpy>=1.24'\n"
                    "Or skip Cython extensions entirely:\n"
                    "  AMA_NO_CYTHON=1 pip install ."
                )
            super().run()

        # Ed25519 signed-integrity hook.  Runs on EVERY build.
        self._run_integrity_signer()

    def _run_integrity_signer(self) -> None:
        """Sign and bind this build's artefact.  Runs on every build.

        The signer reads:
          - AMA_INTEGRITY_SIGNING_SEED_HEX         (release-CI deterministic seed)
          - AMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX  (env-var trust anchor; optional
              when the native library was compiled with a CMake anchor)
          - AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR     (fail closed if no anchor)
        and writes the signed-integrity artefact into BOTH the source tree
        copy of the package and the staging build_lib copy so the wheel
        builder picks it up exactly the way it picks up _integrity_digest.txt.
        AMA_BUILD_PIPELINE=1 is set on the child below unconditionally: it is
        _build_sign's own "a build, not a user re-blessing an installed tree"
        gate, and this IS the build.

        This used to return early unless the caller had already exported
        AMA_BUILD_PIPELINE=1, on the stated ground that "plain `pip install .`
        from a source checkout is unaffected — those users get the digest-only
        fallback (logged WARNING at import time)".  Measured, that fallback is
        not a warning-shaped inconvenience.  A plain `pip install .` shipped
        six binding extensions with ``INTEGRITY_BINDING_DIGESTS_HEX = {}``,
        which produced, per interpreter start: twelve "present but not covered
        by the signed artefact" lines, a POST verdict of "1 of 13 tests were
        SKIPPED — this module is NOT fully verified", and — because
        _check_binding_extensions treats uncovered inventory as a hard failure
        on any build carrying a trust anchor — a CryptoModuleError under
        AMA_FIPS_STRICT=1, the variable SECURITY.md tells release deployments
        to set.  README names `pip install .` the primary install channel and
        it is the only one that works while PyPI is unpublished, so the
        default path produced the loudest possible unverified state.

        The native library is built unconditionally a few lines above (a
        missing CMake is already FATAL), so there is no build that reaches
        here without something to sign.  A signer failure therefore fails the
        build rather than downgrading it: an artefact that cannot be produced
        is a broken install, not a developer convenience.
        """
        src_pkg_dir = Path(__file__).resolve().parent / "ama_cryptography"
        staged_pkg_dir = Path(self.build_lib) / "ama_cryptography" if self.build_lib else None

        # The signer's v3 artefact binds every compiled binding extension by
        # digest, enumerated from the SOURCE package dir — but build_ext
        # compiles the extensions into build_lib, so on a fresh checkout the
        # source dir has none at signing time and the artefact binds an empty
        # map while the wheel ships six unlisted bindings: POST then fails
        # every install with "present but not covered" (caught by the
        # wheel-install CI lane the first time a fresh tree built).  Sync the
        # source dir's extension set to EXACTLY the staged set before
        # signing: copy what the wheel will ship, and remove stale extension
        # files the wheel will not (a leftover from a previous interpreter's
        # build in the same tree — cibuildwheel builds every Python version
        # sequentially from one /project — would otherwise be signed into an
        # artefact whose wheel does not contain it, failing POST as
        # "missing on disk").  The native library is excluded: it is synced
        # by _copy_native_library_into_package and bound separately.
        # Prune the staging dir to exactly the extensions THIS build declares,
        # before the source dir is synced from it.
        #
        # setuptools' build_lib persists across invocations in one tree, and
        # nothing empties it.  So a tree previously built with Cython, rebuilt
        # with AMA_NO_CYTHON=1, still has the six binding extensions sitting
        # in build_lib: _sync_binding_extensions_into_source faithfully copies
        # them back into the source dir, _compute_binding_digests signs them,
        # and the wheel ships six binding extensions from a build that
        # declared none.  Reproduced here — the same command produced a
        # 3,124,336-byte wheel with `bindings = 6` in a dirty tree and a
        # 1,788,629-byte wheel with `bindings = 0` in a clean one.  The
        # extensions themselves were valid, which is what makes it worth
        # closing: the artefact signs a set the build did not choose, so
        # "signed" stops meaning "produced by this build".
        #
        # _sync_binding_extensions_into_source already enforces
        # source-set == staged-set; this makes staged-set == declared-set, so
        # the chain reaches declared-set end to end.
        self._prune_staged_extensions_not_declared(staged_pkg_dir)
        self._sync_binding_extensions_into_source(src_pkg_dir, staged_pkg_dir)

        # Delete the artefact this run is about to replace, BEFORE the signer
        # process starts — the same delete-then-sign order
        # tools/resign_wheel.py uses, and the one the package's own
        # pre-import refusal prints as the remedy.
        #
        # `python -m ama_cryptography._build_sign` imports the package before
        # _build_sign runs a line, and __init__'s
        # _refuse_tampered_bindings_before_import compares every binding
        # extension on disk against the artefact still sitting in the tree.
        # A rebuild always changes those bytes, so a second build in a tree
        # that already carries an artefact refuses the import with "digest
        # MISMATCH", the signer exits 1, and the build fails.  That is not
        # hypothetical: it is what cibuildwheel does — one /project, every
        # Python version built sequentially — and it is what the three-way
        # install check reproduced here the moment signing stopped being
        # conditional.  The pre-import gate is right to refuse; what was
        # wrong was asking it to adjudicate a tree mid-rebuild.
        #
        # Moved ASIDE, not deleted.  `_integrity_signature.py` is a git-TRACKED
        # file, and an earlier form of this block unlinked it outright: any
        # signer failure then left the developer's checkout with the artefact
        # gone, a state `git checkout` is the only recovery from and which the
        # RuntimeError below does not mention.  The rename is restored on every
        # non-zero exit and on every exception, so a failed build leaves the
        # tree exactly as it found it.  __pycache__ goes too, so a compiled
        # copy cannot shadow the move.
        #
        # Removing it for the duration is safe and is not a downgrade: with no
        # artefact, nothing is signed, so nothing reads as tampering; the .py
        # digest is unaffected because the artefact is excluded from it by
        # construction; and the signer writes a fresh one moments later or the
        # build fails and the original comes back.
        _stashed: list[tuple[Path, Path]] = []
        for _pkg_dir in (src_pkg_dir, staged_pkg_dir):
            if _pkg_dir is None or not _pkg_dir.is_dir():
                continue
            _artefact = _pkg_dir / "_integrity_signature.py"
            if _artefact.is_file():
                _aside = _pkg_dir / "_integrity_signature.py.pre-sign"
                _aside.unlink(missing_ok=True)
                _artefact.rename(_aside)
                _stashed.append((_artefact, _aside))
            shutil.rmtree(_pkg_dir / "__pycache__", ignore_errors=True)

        def _restore_stashed_artefacts() -> None:
            for _artefact, _aside in _stashed:
                if _aside.is_file() and not _artefact.is_file():
                    _aside.rename(_artefact)
                else:
                    _aside.unlink(missing_ok=True)

        # _build_sign loads the native library via _find_native_library,
        # which searches the in-tree package dir first.  We already copied
        # libama_cryptography.so* into BOTH the source and staging dirs
        # in _copy_native_library_into_package, so the loader can resolve
        # it without an LD_LIBRARY_PATH override.
        cmd = [
            sys.executable,
            "-m",
            "ama_cryptography._build_sign",
            "--package-dir",
            str(src_pkg_dir),
            # Bind the just-synced binding extensions into the signed
            # artefact.  BOTH callers pass this now — this one and the repair
            # flow (`integrity --update --sign`), which sets the same argv.
            # The flag stays explicit rather than becoming the default so
            # `--digest-only` and genuinely extension-free trees remain
            # reachable; see _build_sign's --bind-extensions help.
            #
            # This comment used to say the repair flow "deliberately omits
            # this — ... why a source-tree artefact must bind none", which was
            # true of the revision it was written for and was inverted by the
            # change that made the repair flow bind too.  It pointed the reader
            # at a help text that says the opposite.
            "--bind-extensions",
        ]
        env = os.environ.copy()
        env["AMA_BUILD_PIPELINE"] = "1"
        # Scrubbed from the CHILD's environment only.  Both describe how the
        # INSTALLED module must behave, not how the signer's own import must:
        # the signer necessarily imports a tree whose artefact has just been
        # moved aside, so POST records the integrity stage at `digest-only`
        # strength.  AMA_FIPS_STRICT=1 escalates that SKIP to a hard failure,
        # and AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR=1 fails the stage outright on
        # an unanchored build.  Neither is a FAILED-and-repairable stage, so
        # __init__'s signer carve-out cannot cover them — it keys on
        # `_all_failures_repairable`, and a SKIP produces no failed row at all.
        # An operator who exports either variable in their shell (the
        # documented way to run a strict build) could not `pip install .`.
        #
        # AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR is dual-use, though: besides the
        # import-time POST policy above, _build_sign reads the SAME variable
        # as its own refuse-to-sign-unanchored gate.  Scrubbing it therefore
        # silently dropped the operator's demanded anchor enforcement from
        # the very signing step it was exported to constrain.  The intent is
        # re-carried explicitly: when the installing environment had the
        # variable enabled, the signer gets --require-trust-anchor on its
        # command line, so the child imports leniently but still refuses to
        # produce an unanchored signature.  (2026-08 v5 audit, item 15.)
        _true_env_values = {"1", "true", "yes", "on"}  # mirrors _build_sign
        if (
            os.environ.get("AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR", "").strip().lower()
            in _true_env_values
        ):
            cmd.append("--require-trust-anchor")
        for _child_only in ("AMA_FIPS_STRICT", "AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR"):
            env.pop(_child_only, None)
        try:
            subprocess.check_call(cmd, env=env)
        except BaseException as e:
            _restore_stashed_artefacts()
            if isinstance(e, subprocess.CalledProcessError):
                raise RuntimeError(
                    f"FATAL: integrity signer failed (exit {e.returncode}). "
                    "Every build must produce a signed integrity artefact that "
                    "covers the binding extensions it ships; an unsigned or "
                    "partially-covered build imports with POST reporting itself "
                    "NOT fully verified and fails outright under "
                    "AMA_FIPS_STRICT=1.  Refusing to produce one.  The tree's "
                    "previous artefact has been restored."
                ) from e
            raise
        else:
            for _artefact, _aside in _stashed:
                _aside.unlink(missing_ok=True)

        # Mirror the freshly-written artefact into the staging dir so the
        # wheel builder packages it.  The signer ran against src_pkg_dir.
        if staged_pkg_dir is not None and staged_pkg_dir.is_dir():
            for name in ("_integrity_signature.py", "_integrity_digest.txt"):
                src_file = src_pkg_dir / name
                if src_file.is_file():
                    shutil.copy2(src_file, staged_pkg_dir / name)

    # Mirrors _build_sign's enumeration criteria (and _self_test's): every
    # file with one of these suffixes in the package dir, except the native
    # library, is a binding extension the artefact must bind.
    _EXTENSION_SUFFIXES = (".so", ".pyd", ".dylib")
    _NATIVE_LIB_PREFIXES = ("libama_cryptography", "ama_cryptography.dll")

    def _iter_extension_files(self, pkg_dir: Optional[Path]) -> list[Path]:
        out: list[Path] = []
        if pkg_dir is None or not pkg_dir.is_dir():
            return out
        for path in sorted(pkg_dir.iterdir()):
            if not path.is_file() or path.suffix not in self._EXTENSION_SUFFIXES:
                continue
            if path.name.startswith(self._NATIVE_LIB_PREFIXES):
                continue
            out.append(path)
        return out

    def _declared_extension_filenames(self) -> set[str]:
        """Basenames of the binding extensions this build declares.

        Empty when ``ext_modules`` is empty — which is the case the pruning
        exists for, and why this is derived from ``self.extensions`` rather
        than from whatever happens to be on disk.
        """
        names: set[str] = set()
        for ext in self.extensions or []:
            # setuptools' build_ext.get_ext_filename / get_ext_fullname are
            # untyped in the installed stubs, so a direct call is "call to
            # untyped function in typed context" under mypy --strict.  Both go
            # through a locally-typed alias rather than a suppression:
            # INVARIANT-13 wants the code fixed, not the report silenced, and
            # the alias states the type the stub omits instead of asserting a
            # stronger one.
            ext_fullname: Callable[[str], str] = self.get_ext_fullname
            ext_filename: Callable[[str], str] = self.get_ext_filename
            filename = ext_filename(ext_fullname(ext.name))
            names.add(Path(filename).name)
        return names

    def _prune_staged_extensions_not_declared(self, staged_pkg_dir: Optional[Path]) -> None:
        """Delete staged binding extensions no Extension in this build names.

        See the call site.  A missing staging dir is a no-op for the same
        reason it is in _sync_binding_extensions_into_source.
        """
        if staged_pkg_dir is None or not staged_pkg_dir.is_dir():
            return
        declared = self._declared_extension_filenames()
        for path in self._iter_extension_files(staged_pkg_dir):
            if path.name not in declared:
                print(
                    "Removing staged binding extension left by an earlier build "
                    f"in this tree (not declared by this one): {path.name}"
                )
                path.unlink()

    def _sync_binding_extensions_into_source(
        self, src_pkg_dir: Path, staged_pkg_dir: Optional[Path]
    ) -> None:
        """Make the source dir's binding-extension set exactly the staged set.

        See the call site for why both directions matter.  A missing staging
        dir (an ``--inplace`` build, or ``AMA_NO_CYTHON=1`` before any
        staging exists) is a no-op: the source dir already IS the build
        output in those flows, so the signer's enumeration of it is correct.
        """
        if staged_pkg_dir is None or not staged_pkg_dir.is_dir():
            return
        staged = {path.name: path for path in self._iter_extension_files(staged_pkg_dir)}
        for stale in self._iter_extension_files(src_pkg_dir):
            if stale.name not in staged:
                print(f"Removing stale binding extension not in this build: {stale.name}")
                stale.unlink()
        for name, path in staged.items():
            print(f"Syncing binding extension into source package for signing: {name}")
            shutil.copy2(path, src_pkg_dir / name)

    def _build_cmake(self) -> None:
        """Build libama_cryptography via CMake."""
        # Check if CMake is available
        try:
            subprocess.check_output(["cmake", "--version"])
        except OSError as e:
            raise RuntimeError(
                "FATAL: CMake not found. The native C library is required for "
                "cryptographic operations. Install CMake before building:\n"
                "  Ubuntu/Debian: sudo apt-get install cmake\n"
                "  macOS:         brew install cmake\n"
                "  Windows:       choco install cmake"
            ) from e

        # D-3: drive CMake into ./build/python-cmake/, leaving ./build/ for the
        # user-driven `make c` flow.
        build_directory = PY_CMAKE_BUILD_DIR.absolute()
        build_directory.mkdir(parents=True, exist_ok=True)

        cmake_args = [
            f"-DCMAKE_BUILD_TYPE={'Debug' if DEBUG else 'Release'}",
            "-DAMA_BUILD_SHARED=ON",
            "-DAMA_BUILD_STATIC=ON",
            "-DAMA_BUILD_TESTS=OFF",  # Tests are run separately
            "-DAMA_BUILD_EXAMPLES=OFF",
            "-DAMA_USE_NATIVE_PQC=ON",
        ]

        # Forward the integrity trust anchor into the native build.
        #
        # This is load-bearing, not a convenience: at runtime
        # ``_self_test._load_integrity_trust_anchor()`` reads the anchor
        # ONLY from the compiled library (via
        # ``ama_integrity_trust_anchor_pubkey_hex()``).  An anchor supplied
        # solely through the environment is consulted at *build* time by
        # ``_build_sign`` and then forgotten, so without this forwarding a
        # release could set the anchor variable and still ship a wheel whose
        # import-time check accepts any public key placed in
        # ``_integrity_signature.py``.  CMakeLists.txt validates the value
        # (empty or exactly 64 hex characters) and fails the build otherwise,
        # so a malformed anchor surfaces here rather than at import.
        # Passed UNCONDITIONALLY, including when empty.  CMakeLists.txt
        # declares the option as a CACHE STRING, so a value written into
        # CMakeCache.txt by an earlier configure survives every later
        # configure that does not overwrite it.  Appending the flag only when
        # the variable was set therefore made anchoring sticky: build once
        # with an anchor, unset the variable, rebuild in the same tree, and
        # the "unanchored" artefact still carried the old anchor — silently,
        # since nothing re-reads the environment to notice.  That is the wrong
        # direction for an artefact whose whole purpose is to say who signed
        # it, and it makes a build non-reproducible from its inputs.  Passing
        # the empty string explicitly resets the cache entry; CMakeLists.txt
        # validates "empty or exactly 64 hex characters", so empty is a
        # first-class value and not a malformed one.
        _anchor = os.environ.get("AMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX", "").strip()
        cmake_args.append(f"-DAMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX={_anchor}")

        build_args = ["--config", "Debug" if DEBUG else "Release"]

        if platform.system() == "Windows":
            cmake_args.extend(
                [
                    f"-DCMAKE_LIBRARY_OUTPUT_DIRECTORY_{('Debug' if DEBUG else 'Release').upper()}={build_directory}",
                    f"-DCMAKE_RUNTIME_OUTPUT_DIRECTORY_{('Debug' if DEBUG else 'Release').upper()}={build_directory}",
                ]
            )
            build_args.extend(["--", "/m"])
        else:
            cmake_args.append(f"-DCMAKE_INSTALL_PREFIX={build_directory}")
            # Parallel build
            import multiprocessing

            build_args.extend(["--", f"-j{multiprocessing.cpu_count()}"])

        # Run CMake with error handling
        try:
            subprocess.check_call(["cmake", str(Path.cwd())] + cmake_args, cwd=str(build_directory))

            # Build
            subprocess.check_call(["cmake", "--build", "."] + build_args, cwd=str(build_directory))
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"FATAL: CMake build failed: {e}\n"
                "The native C library is required for cryptographic operations. "
                "A Python-only install would have no PQC crypto and no clear indication."
            ) from e

        # Update Cython binding `library_dirs` to point at our isolated
        # CMake build dir so the in-place build can link against the
        # libraries we just produced (D-3).  Mirror the same multi-layout
        # candidate set that _copy_native_library_into_package uses so
        # the link step doesn't fail on Windows multi-config generators
        # whose import library lands under a Release/ or Debug/ subdir
        # rather than the conventional lib/ (Copilot review #3).
        link_candidates = [
            str(build_directory / "lib"),
            str(build_directory),
        ]
        for cfg_subdir in ("Release", "Debug", "RelWithDebInfo", "MinSizeRel"):
            link_candidates.extend(
                [
                    str(build_directory / cfg_subdir / "lib"),
                    str(build_directory / cfg_subdir),
                    str(build_directory / "lib" / cfg_subdir),
                ]
            )
        for ext in self.extensions or []:
            if "ama_cryptography" in ext.libraries:
                ext.library_dirs = link_candidates + [
                    d for d in ext.library_dirs if d not in link_candidates and d != "build/lib"
                ]

    def _copy_native_library_into_package(self) -> None:
        """Bundle libama_cryptography.so* (and Windows DLL) into the package.

        D-1 — without this step the produced wheel ships only the Cython
        binding `.so` files; they NEEDED-link against the library's current
        SONAME (`libama_cryptography.so.<major>`, `.so.5` at this release —
        CMake derives SOVERSION from the project major, so this tracks the
        version rather than being a fixed name), which is not present anywhere
        on a fresh install, so any
        `python -m ama_cryptography` invocation outside the source tree dies
        with `RuntimeError: AMA native C library required`.

        We copy into TWO locations on every invocation:

          (1) the in-tree source dir (./ama_cryptography/) — required for
              `python setup.py build_ext --inplace` so an editable / source
              checkout can `import ama_cryptography` directly;
          (2) the staging dir <build_lib>/ama_cryptography/ — required for
              `pip install` / `python -m build` flows, because setuptools'
              wheel-builder collects package files from the staging dir,
              not from the source tree.  Putting them ONLY in the source
              tree was the original D-1 root cause: the wheel never
              picked them up and the install ended in a broken state.

        We preserve the SONAME chain
            libama_cryptography.so -> .so.<major> -> .so.<major>.<minor>.<patch>
        (`.so.5` -> `.so.5.0.0` at this release; CMake derives SOVERSION from
        the project major, so the chain tracks the version rather than being a
        fixed name) so the dynamic loader resolves the binding extensions'
        NEEDED entry correctly via DT_RUNPATH=$ORIGIN.
        """
        is_windows = platform.system() == "Windows"
        cmake_root = PY_CMAKE_BUILD_DIR.absolute()
        cmake_lib_dir = cmake_root / "lib"
        cmake_bin_dir = cmake_root / "bin"

        # Where CMake actually puts the artifacts varies by generator and
        # build type.  CMakeLists.txt lines 130-132 set the default
        # output dirs to <BIN>/lib and <BIN>/bin, but on Windows
        # multi-config generators (Visual Studio) those settings are
        # ignored unless _RELEASE / _DEBUG-suffixed forms are also set,
        # AND outputs land in <root>/Release/<lib_or_bin>/ rather than
        # <root>/lib or <root>/bin.  setup.py's CMake invocation does
        # set the suffixed forms but points them at the build root,
        # which sidesteps the per-config subdir but means the artifacts
        # land in the build root itself.  Older / single-config
        # generators put them in <root>/lib + <root>/bin.  This
        # discovery code therefore scans every reasonable layout —
        # search ROOT first to handle the override path, then the
        # single-config defaults, then per-config subdirs as a final
        # fallback.  Copilot review #3 reproduction.
        candidate_dirs = [cmake_root, cmake_lib_dir, cmake_bin_dir]
        for cfg_subdir in ("Release", "Debug", "RelWithDebInfo", "MinSizeRel"):
            candidate_dirs.extend(
                [
                    cmake_root / cfg_subdir,
                    cmake_root / cfg_subdir / "lib",
                    cmake_root / cfg_subdir / "bin",
                    cmake_root / "lib" / cfg_subdir,
                    cmake_root / "bin" / cfg_subdir,
                ]
            )

        shared_globs: tuple[str, ...]
        archive_globs: tuple[str, ...]
        if is_windows:
            shared_globs = ("ama_cryptography*.dll", "libama_cryptography*.dll")
            archive_globs = ("ama_cryptography*.lib", "libama_cryptography*.lib")
        elif sys.platform == "darwin":
            shared_globs = ("libama_cryptography*.dylib",)
            archive_globs = ()
        else:
            shared_globs = ("libama_cryptography.so*",)
            archive_globs = ()

        patterns: list[str] = []
        for d in candidate_dirs:
            for g in shared_globs + archive_globs:
                patterns.append(str(d / g))

        # Compute both destination directories.  build_lib is set by
        # setuptools before build_ext.run() runs.
        destinations = []
        in_tree_dir = Path("ama_cryptography").absolute()
        if in_tree_dir.is_dir():
            destinations.append(in_tree_dir)
        if getattr(self, "build_lib", None):
            staging_dir = Path(self.build_lib).absolute() / "ama_cryptography"
            staging_dir.mkdir(parents=True, exist_ok=True)
            destinations.append(staging_dir)

        # Track filenames already copied so a glob hit in two candidate
        # dirs (e.g., one populated by single-config CMake, one by a
        # leftover Visual Studio Release/ dir) doesn't overwrite the
        # newer artifact with an older one.
        seen_basenames: set[str] = set()
        copied = []
        for pat in patterns:
            for src in sorted(glob.glob(pat)):
                src_path = Path(src)
                if src_path.name in seen_basenames:
                    continue
                seen_basenames.add(src_path.name)
                for dst_dir in destinations:
                    dst_path = dst_dir / src_path.name
                    if dst_path.is_symlink() or dst_path.exists():
                        dst_path.unlink()
                    if src_path.is_symlink() and not is_windows:
                        # Preserve symlink so the SONAME chain stays intact
                        # (libama_cryptography.so -> .so.<major> ->
                        #  .so.<major>.<minor>.<patch>; `.so.5` at this
                        #  release).
                        target = os.readlink(src)
                        os.symlink(target, dst_path)
                    else:
                        shutil.copy2(src, dst_path, follow_symlinks=True)
                    copied.append(str(dst_path))

        if not copied:
            searched = "\n  ".join(str(d) for d in candidate_dirs)
            raise RuntimeError(
                "FATAL: CMake reported success but no libama_cryptography "
                "shared library was found.  Searched (in order):\n  "
                f"{searched}\n"
                "The wheel would be unusable; aborting."
            )


# Package configuration
setup(
    name="ama-cryptography",
    version=VERSION,
    description="Quantum-resistant cryptographic protection system for helical mathematical Omni-Codes",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Andrew E. A.",
    author_email="steel.sa.llc@gmail.com",
    maintainer="Steel Security Advisors LLC",
    maintainer_email="steel.sa.llc@gmail.com",
    url="https://github.com/Steel-SecAdv-LLC/AMA-Cryptography",
    project_urls={
        "Documentation": "https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/blob/main/README.md",
        "Source": "https://github.com/Steel-SecAdv-LLC/AMA-Cryptography",
        "Issues": "https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/issues",
    },
    license="Apache-2.0",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: C",
        "Programming Language :: Cython",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Typing :: Typed",
    ],
    keywords=[
        "cryptography",
        "quantum-resistant",
        "post-quantum-cryptography",
        "dilithium",
        "ml-dsa",
        "kyber",
        "ml-kem",
        "sphincs",
        "ed25519",
        "aes-gcm",
        "sha3",
        "hmac",
        "pqc",
        "security",
        "integrity-protection",
        "digital-signatures",
    ],
    python_requires=">=3.10",
    packages=find_packages(
        include=["ama_cryptography", "ama_cryptography.*"],
        exclude=["tests", "tests.*", "examples", "examples.*", "src", "src.*"],
    ),
    py_modules=["ama_cryptography_monitor"],
    # Dependency metadata (install_requires / extras_require) is declared
    # **only** in pyproject.toml. Setuptools merges the two automatically; any
    # second copy here would be a silent source of drift (see audit 2c).
    ext_modules=get_cythonized_extensions(),
    cmdclass={"build_ext": CMakeBuild},
    # See NativeDistribution: the native library is required in every
    # configuration, including the ones that build no Python extensions.
    distclass=NativeDistribution,
    include_package_data=True,
    # D-1: ship the native shared library alongside the Cython bindings so
    # the dynamic loader can resolve libama_cryptography via DT_RUNPATH=$ORIGIN.
    # Both Linux/macOS (.so/.dylib) and Windows (.dll) are covered; missing
    # patterns on a given platform are simply no-ops at install time.
    package_data={
        "ama_cryptography": [
            "_integrity_digest.txt",
            "py.typed",
            "*.pyi",
            # Pinned NIST ACVP-Server vectors consumed by the FIPS 140-3 POST
            # known-answer tests.  Listed here as well as in pyproject.toml's
            # [tool.setuptools.package-data] because a setup.py package_data
            # kwarg overrides the pyproject table under setuptools — omitting it
            # here would silently drop the vectors from the wheel and make the
            # PQC KATs fail at import with "pinned vector missing".
            "_post_kats/*.json",
            "libama_cryptography.so*",
            "libama_cryptography.dylib",
            "libama_cryptography*.dylib",
            "ama_cryptography*.dll",
            "ama_cryptography*.lib",
        ],
    },
    zip_safe=False,
)

# Print build configuration
if __name__ == "__main__":
    print("=" * 70)
    print("AMA Cryptography Build Configuration")
    print("=" * 70)
    print(f"Version:          {VERSION}")
    print(f"Python:           {sys.version.split()[0]}")
    print(f"Platform:         {platform.system()} {platform.machine()}")
    print(f"Cython available: {CYTHON_AVAILABLE}")
    print(f"Use Cython:       {USE_CYTHON}")
    print(f"Use C ext:        {USE_C_EXTENSIONS}")
    print(f"Debug mode:       {DEBUG}")
    print(f"Coverage:         {COVERAGE}")
    print("=" * 70)
