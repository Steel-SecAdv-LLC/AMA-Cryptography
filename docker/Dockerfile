# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
#
# Multi-stage Docker build for AMA Cryptography
# Optimized for production deployment with minimal attack surface

# Stage 1: Builder
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    python3-dev \
    python3-pip \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt requirements-dev.txt /tmp/
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt -r /tmp/requirements-dev.txt

# Copy source code
WORKDIR /build
COPY . .

# Build C library
RUN mkdir -p build && cd build && \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
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
LABEL version="2.1.5"

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libssl3 \
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
