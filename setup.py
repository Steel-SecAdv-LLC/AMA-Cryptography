#!/usr/bin/env python3
# Copyright 2025 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Ava Guardian ♱ Setup Script
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
    AVA_NO_CYTHON=1              # Disable Cython compilation (use pure Python)
    AVA_NO_C_EXTENSIONS=1        # Disable C extensions
    AVA_DEBUG=1                  # Enable debug symbols
    AVA_COVERAGE=1               # Enable coverage instrumentation
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
VERSION = "1.3"
USE_CYTHON = CYTHON_AVAILABLE and not os.getenv("AVA_NO_CYTHON")
USE_C_EXTENSIONS = not os.getenv("AVA_NO_C_EXTENSIONS")
DEBUG = bool(os.getenv("AVA_DEBUG"))
COVERAGE = bool(os.getenv("AVA_COVERAGE"))

# Read long description
long_description = Path("README.md").read_text(encoding="utf-8")


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

    # C library sources
    c_sources = [
        "src/c/ava_core.c",
        "src/c/ava_consttime.c",
    ]

    # Core C extension
    core_ext = Extension(
        name="ava_guardian._core",
        sources=c_sources,
        include_dirs=["include"],
        extra_compile_args=compiler_flags,
        extra_link_args=linker_flags,
        libraries=["crypto"] if platform.system() != "Windows" else [],
    )
    extensions.append(core_ext)

    # Cython mathematical engine (if Cython available)
    if USE_CYTHON:
        # Build include dirs for math engine
        math_include_dirs = ["include"]
        if NUMPY_AVAILABLE:
            # Add NumPy C API headers for numpy/arrayobject.h
            math_include_dirs.append(np.get_include())

        math_ext = Extension(
            name="ava_guardian.math_engine",
            sources=["src/cython/math_engine.pyx"],
            include_dirs=math_include_dirs,
            extra_compile_args=compiler_flags,
            extra_link_args=linker_flags,
            language="c",
        )
        extensions.append(math_ext)

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
        # Skip if no extensions to build
        if not self.extensions:
            return

        # Check if CMake is available
        try:
            subprocess.check_output(["cmake", "--version"])
        except OSError:
            print("WARNING: CMake not found. C library will not be built.")
            print("         Python-only mode will be used.")
            return

        # Build C library with CMake
        build_directory = Path("build").absolute()
        build_directory.mkdir(exist_ok=True)

        cmake_args = [
            f"-DCMAKE_BUILD_TYPE={'Debug' if DEBUG else 'Release'}",
            "-DAVA_BUILD_SHARED=ON",
            "-DAVA_BUILD_STATIC=ON",
            "-DAVA_BUILD_TESTS=OFF",  # Tests are run separately
            "-DAVA_BUILD_EXAMPLES=OFF",
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
            print(f"WARNING: CMake build failed: {e}")
            print("         Continuing with Python-only installation.")
            print("         C extensions will not be available.")
            # Don't re-raise - allow installation to continue
            return

        # Continue with Python extension build
        super().run()


# Package configuration
setup(
    name="ava-guardian",
    version=VERSION,
    description="Quantum-Resistant Cryptographic Protection System",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Andrew E. A.",
    author_email="steel.sa.llc@gmail.com",
    maintainer="Steel Security Advisors LLC",
    maintainer_email="steel.sa.llc@gmail.com",
    url="https://github.com/Steel-SecAdv-LLC/Ava-Guardian",
    project_urls={
        "Documentation": "https://github.com/Steel-SecAdv-LLC/Ava-Guardian/blob/main/README.md",
        "Source": "https://github.com/Steel-SecAdv-LLC/Ava-Guardian",
        "Issues": "https://github.com/Steel-SecAdv-LLC/Ava-Guardian/issues",
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
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Typing :: Typed",
    ],
    keywords=[
        "cryptography",
        "quantum-resistant",
        "post-quantum-cryptography",
        "dilithium",
        "kyber",
        "sphincs",
        "ml-dsa",
        "pqc",
        "security",
    ],
    python_requires=">=3.8",
    packages=find_packages(exclude=["tests", "tests.*", "examples", "examples.*", "src", "src.*"]),
    # Note: pyproject.toml is the authoritative source for dependencies.
    # This section is kept in sync for compatibility with older tools.
    install_requires=[
        "cryptography>=41.0.0",
        "numpy>=1.24.0,<3.0.0",
        "scipy>=1.7.0",
    ],
    extras_require={
        # Note: The PyPI package is 'liboqs-python' which provides the 'oqs' module
        "quantum": ["liboqs-python>=0.10.0,<0.11.0"],
        "quantum-alt": ["pqcrypto>=0.1.3,<0.2.0"],
        # PyNaCl for enhanced secure memory operations (libsodium bindings)
        "secure-memory": ["pynacl>=1.5.0"],
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-benchmark>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "isort>=5.12.0",
            "Cython>=3.0.0",
        ],
        "docs": [
            "sphinx>=6.0.0",
            "sphinx-rtd-theme>=1.2.0",
            "sphinx-autodoc-typehints>=1.22.0",
        ],
        "all": [
            "liboqs-python>=0.10.0,<0.11.0",
            "pynacl>=1.5.0",
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-benchmark>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "isort>=5.12.0",
            "Cython>=3.0.0",
            "sphinx>=6.0.0",
            "sphinx-rtd-theme>=1.2.0",
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
    print("Ava Guardian Build Configuration")
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
