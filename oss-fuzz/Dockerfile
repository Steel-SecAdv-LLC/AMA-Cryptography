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

# Clone the repository.
#
# AMA_REF selects what is cloned.  It defaults to the default branch, which is
# what OSS-Fuzz itself wants.  A local or CI check of a specific tree does not
# go through this ARG at all: tools/test_oss_fuzz_build.sh passes the checkout
# to `helper.py build_fuzzers` as its source path, which mounts it over the
# WORKDIR below and so over this clone.  (An earlier revision of this comment
# said the script set AMA_REF; it never did, and a build-arg would in any case
# only reach a commit that had already been pushed.)  The ARG stays for a
# manual `docker build --build-arg AMA_REF=<ref>` of a pushed ref.
ARG AMA_REF=""
RUN git clone --depth 1 https://github.com/Steel-SecAdv-LLC/AMA-Cryptography.git /src/ama-cryptography \
    && if [ -n "$AMA_REF" ]; then \
         cd /src/ama-cryptography \
         && git fetch --depth 1 origin "$AMA_REF" \
         && git checkout FETCH_HEAD; \
       fi

WORKDIR /src/ama-cryptography

COPY build.sh $SRC/
