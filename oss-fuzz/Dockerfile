# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
#
# OSS-Fuzz Dockerfile for AMA-Cryptography
# https://google.github.io/oss-fuzz/getting-started/new-project-guide/
#
# This base is deliberately NOT digest-pinned, unlike the images under
# docker/. OSS-Fuzz builds this file inside its own infrastructure against
# the base-builder image it currently ships, and rebuilds every project
# against new bases as its toolchain moves; pinning a digest here would
# either be ignored or break the project's builds on the next base refresh.
# The pin belongs to OSS-Fuzz, not to this repository.
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
