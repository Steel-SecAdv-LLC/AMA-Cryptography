# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
#
# Multi-stage Docker build for AMA Cryptography
# Optimized for production deployment with minimal attack surface

# Stage 1: Builder
FROM ubuntu:22.04 AS builder

# Install build dependencies
# INVARIANT-1: no external cryptographic libraries are linked. libssl-dev is
# NOT installed — AMA's C sources implement ML-KEM / ML-DSA / SPHINCS+ / AES /
# SHA-3 / ChaCha20-Poly1305 natively and never call OpenSSL at runtime.
#
# gcc-12 / g++-12 are installed alongside the default gcc-11 because
# CMakeLists.txt enforces INVARIANT-8 (GCC >= 12 required for reliable
# constant-time codegen + full SIMD intrinsic support) and ubuntu:22.04
# defaults to gcc-11.
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    gcc-12 \
    g++-12 \
    git \
    python3-dev \
    python3-pip \
    python3-venv \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Make gcc-12 the system default `gcc` / `g++` via update-alternatives.
# We can't just set CC/CXX env vars here: `python3 -m build --wheel`
# below runs in a PEP 517 isolated build environment whose subprocess
# may not propagate the parent env reliably to setuptools' CMakeBuild
# subshell. Rewriting the alternatives makes every gcc/g++ invocation
# in the stage resolve to v12, which guarantees CMakeLists.txt:103's
# INVARIANT-8 toolchain check passes regardless of which sub-shell
# does the cmake call.
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-12 100 && \
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-12 100 && \
    update-alternatives --set gcc /usr/bin/gcc-12 && \
    update-alternatives --set g++ /usr/bin/g++-12

# Install Python dependencies
COPY requirements.txt requirements-dev.txt /tmp/
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt -r /tmp/requirements-dev.txt

# Copy source code
WORKDIR /build
COPY . .

# Build C library. The stage's default `gcc` / `g++` now resolve to
# gcc-12 / g++-12 via update-alternatives, which satisfies the
# INVARIANT-8 toolchain check in CMakeLists.txt:103 — see the compiler
# setup block above for the reasoning. AMA_USE_NATIVE_PQC=ON is set
# explicitly to lock in the native PQC sources (ML-KEM / ML-DSA /
# SPHINCS+) for this image; the flag controls only which PQC sources
# are compiled, NOT any OpenSSL link dependency. The image omits
# libssl-dev because AMA's C sources do not link against OpenSSL at
# all (INVARIANT-1) — CMake discovers OpenSSL `QUIET` for downstream
# consumers but AMA itself never references it.
RUN mkdir -p build && cd build && \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DAMA_USE_NATIVE_PQC=ON \
        -DAMA_BUILD_SHARED=ON \
        -DAMA_BUILD_STATIC=OFF \
        -DAMA_BUILD_TESTS=OFF \
        -DAMA_BUILD_EXAMPLES=OFF \
        -DAMA_ENABLE_AVX2=OFF \
        -DAMA_ENABLE_LTO=ON && \
    cmake --build . --config Release -j$(nproc)

# Build Python package (modern PEP 517 build)
RUN pip3 install --no-cache-dir build && \
    python3 -m build --wheel

# Stage 2: Runtime
FROM ubuntu:22.04

LABEL maintainer="Steel Security Advisors LLC <steel.sa.llc@gmail.com>"
LABEL description="AMA Cryptography - Quantum-Resistant Cryptographic Protection System"
LABEL version="3.0.0"

# Install runtime dependencies only
# INVARIANT-1: libssl3 is NOT installed — AMA's native C primitives do not
# dynamically load libcrypto/libssl. Keeping it out shrinks the container
# attack surface (one fewer CVE-prone library on disk).
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 ama && \
    mkdir -p /app /data && \
    chown -R ama:ama /app /data

# Copy built artifacts from builder
COPY --from=builder /build/build/lib/*.so* /usr/local/lib/
COPY --from=builder /build/dist/*.whl /tmp/
COPY --from=builder /build/requirements.txt /tmp/

# Install Python package and runtime dependencies
# The core library has zero runtime dependencies. numpy is installed only because
# ama_cryptography_monitor_demo.py uses it to simulate CPU-intensive workloads.
RUN pip3 install --no-cache-dir /tmp/*.whl && \
    pip3 install --no-cache-dir -r /tmp/requirements.txt && \
    pip3 install --no-cache-dir numpy && \
    rm -rf /tmp/*.whl /tmp/requirements.txt && \
    ldconfig

# Switch to non-root user
USER ama

# Prevent .pyc file creation and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Copy examples and documentation
COPY --chown=ama:ama examples/ /app/examples/
COPY --chown=ama:ama README.md LICENSE /app/
# Copy monitor and benchmark scripts to /app for docker-compose services
COPY --chown=ama:ama ama_cryptography_monitor_demo.py benchmark_suite.py /app/

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import ama_cryptography; print('OK')" || exit 1

# Default command
CMD ["python3", "-c", "import ama_cryptography; print(f'AMA Cryptography v{ama_cryptography.__version__} ready')"]
