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

import os
import platform
import subprocess
import sys
from pathlib import Path

from setuptools import Extension, find_packages, setup
from setuptools.command.build_ext import build_ext

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
VERSION = "2.1.2"
USE_CYTHON = CYTHON_AVAILABLE and not os.getenv("AMA_NO_CYTHON")
USE_C_EXTENSIONS = not os.getenv("AMA_NO_C_EXTENSIONS")
DEBUG = bool(os.getenv("AMA_DEBUG"))
COVERAGE = bool(os.getenv("AMA_COVERAGE"))

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

        # Platform-conditional rpath: $ORIGIN is ELF/Linux, @loader_path is Mach-O/macOS
        rpath = []
        if sys.platform.startswith("linux"):
            rpath = ["$ORIGIN/../build/lib", "$ORIGIN/../../build/lib"]
        elif sys.platform == "darwin":
            rpath = ["@loader_path/../build/lib", "@loader_path/../../build/lib"]

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
    """Custom build_ext command that builds CMake projects."""

    def run(self):
        # Always run CMake to build the native C library, even when there
        # are no Cython extensions.  The native C library is the primary
        # cryptographic backend (INVARIANT-7) and must be built for the
        # package to function.  Cython extensions are optional.

        self._build_cmake()

        # Build Cython extensions if present.  CMake is already invoked
        # above; super().run() handles only the Cython/setuptools pieces.
        if self.extensions:
            try:
                super().run()
            except Exception as e:
                import logging

                logging.getLogger(__name__).warning(
                    "Cython extension build failed: %s. "
                    "Native C library was built successfully by CMake — "
                    "Cython math extensions are optional.",
                    e,
                )

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

        # Build C library with CMake
        build_directory = Path("build").absolute()
        build_directory.mkdir(exist_ok=True)

        cmake_args = [
            f"-DCMAKE_BUILD_TYPE={'Debug' if DEBUG else 'Release'}",
            "-DAMA_BUILD_SHARED=ON",
            "-DAMA_BUILD_STATIC=ON",
            "-DAMA_BUILD_TESTS=OFF",  # Tests are run separately
            "-DAMA_BUILD_EXAMPLES=OFF",
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

        # Cython extension build is handled by run() after _build_cmake()
        # returns — do NOT call super().run() here to avoid double-building.


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
    # Note: pyproject.toml is the authoritative source for dependencies.
    # This section is kept in sync for compatibility with older tools.
    install_requires=[],
    extras_require={
        # numpy/scipy: optional, used by equations/double_helix and 3R monitor
        # when available. Core cryptographic operations work without them.
        "monitoring": [
            "numpy>=1.24.0,<3.0.0",
            "scipy>=1.7.0",
        ],
        # PyCA cryptography — only needed as fallback when native C library is not available
        "legacy": ["cryptography>=41.0.7"],
        # PKCS#11 support for hardware security modules
        "hsm": ["PyKCS11>=1.5.0"],
        # PyNaCl reserved for future libsodium integration; not currently used
        "secure-memory": ["pynacl>=1.6.2"],
        # NOTE: pyproject.toml [project.optional-dependencies.dev] is authoritative.
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-timeout>=2.1.0",
            "pytest-benchmark>=4.0.0",
            "pytest-xdist>=3.0.0",
            "hypothesis>=6.0.0",
            "black==24.10.0; python_version=='3.9'",
            "black>=26.3.1; python_version>='3.10'",
            "ruff>=0.4.0",
            "mypy>=1.9.0",
            "bandit>=1.7.0",
            "safety>=2.3.0",
            "Cython>=3.2.4",
            "numpy>=1.24.0",
            "scipy>=1.11.0",
        ],
        "docs": [
            "sphinx>=7.4.7",
            "sphinx-rtd-theme>=1.2.0",
            "sphinx-autodoc-typehints>=2.3.0",
        ],
        "all": [
            "pynacl>=1.6.2",
            "PyKCS11>=1.5.0",
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-timeout>=2.1.0",
            "pytest-benchmark>=4.0.0",
            "pytest-xdist>=3.0.0",
            "hypothesis>=6.0.0",
            "black==24.10.0; python_version=='3.9'",
            "black>=26.3.1; python_version>='3.10'",
            "ruff>=0.4.0",
            "mypy>=1.9.0",
            "bandit>=1.7.0",
            "safety>=2.3.0",
            "Cython>=3.2.4",
            "sphinx>=7.4.7",
            "sphinx-rtd-theme>=1.2.0",
            "sphinx-autodoc-typehints>=2.3.0",
            "numpy>=1.24.0",
            "scipy>=1.11.0",
        ],
    },
    ext_modules=get_cythonized_extensions(),
    cmdclass={"build_ext": CMakeBuild},
    include_package_data=True,
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
