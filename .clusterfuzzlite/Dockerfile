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

# apt retries three times with a pause because stalled Ubuntu mirrors are a
# measured failure mode, not a hypothesis: the OSS-Fuzz lane died twice on
# 2026-10-07 (runs 37665893658 and 37672010498) fetching archive.ubuntu.com
# inside this build, identically on the re-run — the same class the
# workflows' apt-install.sh already retries (INVARIANT: apt-retry gate).
RUN for attempt in 1 2 3; do \
        apt-get update && apt-get install -y cmake make pkg-config python3 && break; \
        if [ "$attempt" = 3 ]; then exit 100; fi; \
        sleep 20; \
        done && rm -rf /var/lib/apt/lists/*

# ClusterFuzzLite builds the checkout that triggered the workflow, so the
# source is COPIED rather than cloned (oss-fuzz/Dockerfile clones, as an
# OSS-Fuzz submission must).
COPY . $SRC/ama-cryptography
COPY .clusterfuzzlite/build.sh $SRC/
WORKDIR $SRC/ama-cryptography
