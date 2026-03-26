# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
#
# OSS-Fuzz Dockerfile for AMA-Cryptography
# https://google.github.io/oss-fuzz/getting-started/new-project-guide/

FROM gcr.io/oss-fuzz-base/base-builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    make \
    pkg-config \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Clone the repository
RUN git clone --depth 1 https://github.com/Steel-SecAdv-LLC/AMA-Cryptography.git /src/ama-cryptography

WORKDIR /src/ama-cryptography

COPY build.sh $SRC/
