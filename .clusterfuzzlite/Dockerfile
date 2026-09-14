# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
#
# ClusterFuzzLite build image for AMA-Cryptography.
#
# This base is deliberately NOT digest-pinned, for the same reason as
# oss-fuzz/Dockerfile: ClusterFuzzLite builds it inside OSS-Fuzz's own
# infrastructure against the base-builder image its actions currently ship,
# and moves every project forward with its toolchain.  The pin belongs to
# OSS-Fuzz, not to this repository.
FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y \
    cmake \
    make \
    pkg-config \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# ClusterFuzzLite builds the checkout that triggered the workflow, so the
# source is COPIED rather than cloned (oss-fuzz/Dockerfile clones, as an
# OSS-Fuzz submission must).
COPY . $SRC/ama-cryptography
COPY .clusterfuzzlite/build.sh $SRC/
WORKDIR $SRC/ama-cryptography
