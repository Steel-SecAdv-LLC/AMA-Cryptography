#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

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
from pathlib import Path
from typing import Optional

# D-9: Preflight version checks for every build-time dependency listed in
# pyproject.toml's [build-system].requires.  Each floor matches the version
# pinned there, so the comment "enforced by setup.py's preflight check" is
# now factually accurate (Copilot review #5 / D-9-extended).
#
#   * setuptools >= 70.0.0:  Debian's patched setuptools 68.x raises
#     AttributeError(install_layout) deep inside pip's bdist_wheel subprocess.
#     70.0.0 also closes GHSA-cx63-2mw6-8hw5; we float to 78.1.1 in
#     pyproject.toml to also pick up PYSEC-2025-49.
#   * wheel >= 0.47.0:        closes GHSA-8rrh-rw8j-w5fx.
#   * cmake >= 4.3.2:         Dependabot supply-chain floor (matches
#     pyproject.toml's [build-system].requires).  CMakeLists.txt's
#     cmake_minimum_required is 3.15, but this higher floor is enforced
#     for supply-chain security.
#   * Cython >= 3.2.4:        floor for the math_engine extension's
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
    "setuptools": ((70, 0, 0), "AttributeError(install_layout) on bdist_wheel"),
    "wheel": ((0, 47, 0), "GHSA-8rrh-rw8j-w5fx"),
    "cmake": (
        (4, 3, 2),
        "Dependabot supply-chain floor (pyproject.toml [build-system].requires);"
        " CMakeLists.txt cmake_minimum_required is 3.15 but this higher"
        " floor is enforced for supply-chain security",
    ),
    "Cython": ((3, 2, 4), "math_engine cimport numpy stability floor"),
    "numpy": ((1, 24, 0), "numpy.pxd headers required by math_engine"),
}


def _parse_version(raw: str) -> tuple:
    """Best-effort PEP 440 parse → 3-tuple of ints.

    Falls back to a tolerant digit-only split when ``packaging`` is not
    importable.  Local / build suffixes (``+deb``, ``-1``) are stripped
    so a Debian-packaged ``70.0.0+deb`` does not get rejected as
    ``(70, 0)`` by a naive ``split('.')`` (Copilot review #6).
    """
    try:
        from packaging.version import Version  # type: ignore[import-not-found]

        v = Version(raw)
        release = v.release
        # Pad to exactly three components so ``(70, 0)`` compares the same
        # as ``(70, 0, 0)``.
        return tuple(release) + (0,) * max(0, 3 - len(release))
    except Exception:  # pragma: no cover - packaging is in modern setuptools
        # Strip local/build segments and any pre/post markers; keep only
        # the leading dotted-numeric release portion.
        head = raw.split("+", 1)[0].split("-", 1)[0]
        digits = [int(x) for x in head.split(".") if x.isdigit()]
        return tuple(digits[:3]) + (0,) * max(0, 3 - len(digits[:3]))


_REMEDY = (
    "  python3 -m pip install --upgrade "
    "'setuptools>=78.1.1' 'wheel>=0.47.0' 'cmake>=4.3.2' "
    "'Cython>=3.2.4' 'numpy>=1.24.0'\n"
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
        import cmake as _cmake  # type: ignore[import-not-found]

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
# (and its companion ``AMA_NO_C_EXTENSIONS=1``, which short-circuits all
# native build paths including the Cython one) must therefore skip those
# preflight checks.  Copilot reviews #12/#15/#22 and Devin review #13
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
# in CMakeLists.txt).  Skip only when the entire native build is opted out
# (AMA_NO_C_EXTENSIONS=1); AMA_NO_CYTHON=1 alone still builds C extensions
# that go through cmake.  Copilot review @ setup.py:150 + Devin review
# @ setup.py:63 caught the drift where pyproject.toml [build-system].requires
# was bumped to cmake>=4.3.2 but setup.py's preflight hadn't matched —
# documented "kept in lockstep" only became true when this check landed.
_SKIP_C_PREFLIGHT = bool(os.getenv("AMA_NO_C_EXTENSIONS"))
if not _SKIP_C_PREFLIGHT:
    _check_cmake_version()

_SKIP_CYTHON_PREFLIGHT = bool(os.getenv("AMA_NO_CYTHON")) or _SKIP_C_PREFLIGHT
if not _SKIP_CYTHON_PREFLIGHT:
    for _name in ("Cython", "numpy"):
        _check_build_dependency(_name)
else:
    sys.stderr.write(
        "AMA_NO_CYTHON / AMA_NO_C_EXTENSIONS set: skipping Cython/numpy "
        "preflight (the math_engine accelerator will not be built).\n"
    )

from setuptools import Extension, find_packages, setup  # noqa: E402
from setuptools.command.build_ext import build_ext  # noqa: E402

# Check for Cython availability at the call-site level (the preflight
# above only proves a minimum version; AMA_NO_CYTHON=1 still gates
# whether Cython is actually invoked).
try:
    from Cython.Build import cythonize

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
try:
    import numpy as np

    NUMPY_AVAILABLE = True
except ImportError:  # pragma: no cover - preflight should have caught this
    # Same rationale as the Cython block above: the preflight enforces
    # numpy>=1.24.0; a second ImportError here means an opt-out path
    # (AMA_NO_CYTHON=1 short-circuits the math_engine build, which is
    # the only consumer of numpy headers) and the build can proceed.
    NUMPY_AVAILABLE = False
    np = None

# Configuration
VERSION = "3.0.0"
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


def get_compiler_flags():
    """Get compiler flags based on platform and configuration."""
    flags = []
    link_flags = []

    if platform.system() == "Windows":
        flags.extend(["/O2", "/W3"])
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
            flags.extend(["-O3", "-DNDEBUG"])

        if COVERAGE:
            flags.extend(["--coverage"])
            link_flags.extend(["--coverage"])

    return flags, link_flags


def get_extension_modules():
    """Build list of extension modules."""
    extensions = []
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


def get_cythonized_extensions():
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

        return cythonize(
            extensions,
            compiler_directives=compiler_directives,
            annotate=DEBUG,  # Generate HTML annotation files in debug mode
        )

    return extensions


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

    def run(self):
        self._build_cmake()
        self._copy_native_library_into_package()

        if not self.extensions:
            return

        # D-4: Cython failures are now fatal unless the user explicitly opted
        # out of Cython entirely (AMA_NO_CYTHON=1) or asked to skip C
        # extensions altogether (AMA_NO_C_EXTENSIONS=1).  Previously the
        # exception was caught and downgraded to a warning, which produced
        # broken installs that quietly advertised "Cython available: False"
        # while having no extension .so files at all (audit D-4).
        if not USE_CYTHON:
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

    def _build_cmake(self):
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

    def _copy_native_library_into_package(self):
        """Bundle libama_cryptography.so* (and Windows DLL) into the package.

        D-1 — without this step the produced wheel ships only the Cython
        binding `.so` files; they NEEDED-link against `libama_cryptography.so.3`
        which is not present anywhere on a fresh install, so any
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
            libama_cryptography.so -> .so.3 -> .so.3.0.0
        so the dynamic loader resolves the binding extensions' NEEDED entry
        correctly via DT_RUNPATH=$ORIGIN.
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
        seen_basenames: set = set()
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
                        # Preserve symlink so SONAME chain stays intact
                        # (libama_cryptography.so -> .so.3 -> .so.3.0.0).
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
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
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
    python_requires=">=3.9",
    packages=find_packages(exclude=["tests", "tests.*", "examples", "examples.*", "src", "src.*"]),
    py_modules=["ama_cryptography_monitor"],
    # Dependency metadata (install_requires / extras_require) is declared
    # **only** in pyproject.toml. Setuptools merges the two automatically; any
    # second copy here would be a silent source of drift (see audit 2c).
    ext_modules=get_cythonized_extensions(),
    cmdclass={"build_ext": CMakeBuild},
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
