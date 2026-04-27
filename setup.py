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

# D-9: Preflight setuptools version check.  Debian's setuptools 68.x ships a
# downstream patch (install_lib.set_undefined_options('install','install_layout'))
# that raises AttributeError on bdist_wheel because the install command isn't
# constructed in that flow.  Modern setuptools (>=70) removed install_layout
# from the path and is the supported floor here.  Failing fast with a clear
# remedy is far better than the opaque AttributeError users would otherwise
# see deep inside pip's wheel build subprocess.
_SETUPTOOLS_MIN = (70, 0, 0)
try:
    import setuptools as _setuptools_preflight

    _v = tuple(int(x) for x in _setuptools_preflight.__version__.split(".")[:3] if x.isdigit())
    if _v and _v < _SETUPTOOLS_MIN:
        sys.stderr.write(
            "FATAL: setuptools >= {req} required (found {got}).\n"
            "Older setuptools (notably Debian's patched 68.x) breaks 'pip wheel'\n"
            "with AttributeError: install_layout. Upgrade with:\n"
            "  python3 -m pip install --upgrade 'setuptools>=70' 'wheel>=0.46.2'\n".format(
                req=".".join(str(x) for x in _SETUPTOOLS_MIN),
                got=_setuptools_preflight.__version__,
            )
        )
        sys.exit(1)
except ImportError:
    pass

from setuptools import Extension, find_packages, setup  # noqa: E402
from setuptools.command.build_ext import build_ext  # noqa: E402

# Check for Cython availability
try:
    from Cython.Build import cythonize

    CYTHON_AVAILABLE = True
except ImportError:
    CYTHON_AVAILABLE = False
    cythonize = None

# Check for NumPy availability (needed for C API headers)
try:
    import numpy as np

    NUMPY_AVAILABLE = True
except ImportError:
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
        # libraries we just produced (D-3).
        for ext in self.extensions or []:
            if "ama_cryptography" in ext.libraries:
                ext.library_dirs = [str(build_directory / "lib")] + [
                    d for d in ext.library_dirs if d != "build/lib"
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
        cmake_lib_dir = (PY_CMAKE_BUILD_DIR / "lib").absolute()
        cmake_bin_dir = (PY_CMAKE_BUILD_DIR / "bin").absolute()

        if is_windows:
            patterns = [
                str(cmake_bin_dir / "ama_cryptography*.dll"),
                str(cmake_lib_dir / "ama_cryptography*.lib"),
            ]
        elif sys.platform == "darwin":
            patterns = [str(cmake_lib_dir / "libama_cryptography*.dylib")]
        else:
            patterns = [str(cmake_lib_dir / "libama_cryptography.so*")]

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

        copied = []
        for pat in patterns:
            for src in glob.glob(pat):
                src_path = Path(src)
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
            raise RuntimeError(
                "FATAL: CMake reported success but no libama_cryptography "
                "shared library was found under "
                f"{cmake_lib_dir}. The wheel would be unusable; aborting."
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
