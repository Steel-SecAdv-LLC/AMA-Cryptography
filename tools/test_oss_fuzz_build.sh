#!/bin/bash
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
#
# Build THIS checkout's fuzzers the way OSS-Fuzz builds them, then run
# OSS-Fuzz's own bad-build check over the result.
#
# What runs
# ---------
#   1. google/oss-fuzz is fetched at OSS_FUZZ_REF (a pinned commit, so the
#      driver is the same on every run) unless a checkout is given.
#   2. oss-fuzz/{project.yaml,Dockerfile,build.sh} are copied into
#      projects/ama-cryptography of that checkout — exactly the submission.
#   3. `infra/helper.py build_fuzzers ama-cryptography <this repo>` builds the
#      image from oss-fuzz/Dockerfile (FROM gcr.io/oss-fuzz-base/base-builder)
#      and runs OSS-Fuzz's `compile` driver with this repository MOUNTED over
#      the Dockerfile's clone, so the tree that is built is the one you are
#      standing in, not whatever the default branch holds.  (An earlier
#      revision of this script said that too and did not do it: it passed no
#      source path, so it built the clone.)
#   4. `infra/helper.py check_build ama-cryptography` runs every fuzzer inside
#      base-runner: it must start, be linked against the requested engine and
#      sanitizer, and survive its seed corpus.  That is the check OSS-Fuzz
#      applies to every project on every build.
#
# Prerequisites: Docker running, python3, git.  Network for the base images
# and the infra checkout.  Roughly ten minutes on a hosted runner.
#
# Usage:
#   tools/test_oss_fuzz_build.sh [path-to-oss-fuzz-checkout]
#   OSS_FUZZ_REF=<commit>  tools/test_oss_fuzz_build.sh
#   SANITIZER=undefined    tools/test_oss_fuzz_build.sh
#
# .github/workflows/fuzzing.yml runs this on every push and pull request.

set -euo pipefail

OSS_FUZZ_DIR="${1:-${RUNNER_TEMP:-/tmp}/oss-fuzz}"
OSS_FUZZ_REF="${OSS_FUZZ_REF:-4e65aea32254fe988ac4b84dbb088d2d08d789e7}"
SANITIZER="${SANITIZER:-address}"
ENGINE="${ENGINE:-libfuzzer}"
PROJECT_NAME="ama-cryptography"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: Docker is required but not installed." >&2
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker daemon is not running." >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required (OSS-Fuzz's helper.py)." >&2
    exit 1
fi

if [ ! -f "$OSS_FUZZ_DIR/infra/helper.py" ]; then
    echo "Fetching google/oss-fuzz at $OSS_FUZZ_REF into $OSS_FUZZ_DIR..."
    mkdir -p "$OSS_FUZZ_DIR"
    git -C "$OSS_FUZZ_DIR" init -q
    git -C "$OSS_FUZZ_DIR" remote add origin https://github.com/google/oss-fuzz.git
    git -C "$OSS_FUZZ_DIR" fetch -q --depth 1 origin "$OSS_FUZZ_REF"
    git -C "$OSS_FUZZ_DIR" checkout -q FETCH_HEAD
else
    echo "Using the OSS-Fuzz checkout at $OSS_FUZZ_DIR" \
         "($(git -C "$OSS_FUZZ_DIR" rev-parse --short HEAD 2>/dev/null || echo 'not a git checkout'))"
fi

PROJECT_DIR="$OSS_FUZZ_DIR/projects/$PROJECT_NAME"
mkdir -p "$PROJECT_DIR"
echo "Copying the submission files into projects/$PROJECT_NAME..."
cp "$REPO_ROOT/oss-fuzz/project.yaml" "$PROJECT_DIR/"
cp "$REPO_ROOT/oss-fuzz/Dockerfile" "$PROJECT_DIR/"
cp "$REPO_ROOT/oss-fuzz/build.sh" "$PROJECT_DIR/"

cd "$OSS_FUZZ_DIR"

echo ""
echo "=== Step 1: build the fuzzers inside base-builder (engine=$ENGINE sanitizer=$SANITIZER) ==="
# The trailing path is helper.py's `source_path`: it is mounted over the
# Dockerfile's WORKDIR (/src/ama-cryptography), so the build compiles this
# checkout.  oss-fuzz/build.sh builds into $WORK, never into the mounted tree.
python3 infra/helper.py build_fuzzers \
    --engine "$ENGINE" --sanitizer "$SANITIZER" \
    "$PROJECT_NAME" "$REPO_ROOT"

echo ""
echo "=== Step 2: OSS-Fuzz's bad-build check over every fuzzer ==="
python3 infra/helper.py check_build \
    --engine "$ENGINE" --sanitizer "$SANITIZER" \
    "$PROJECT_NAME"

echo ""
echo "=== OSS-Fuzz build and check passed for this checkout ==="
echo "Fuzzers are in $OSS_FUZZ_DIR/build/out/$PROJECT_NAME/."
echo "To submit: fork https://github.com/google/oss-fuzz, copy oss-fuzz/ to"
echo "projects/$PROJECT_NAME/, and open the pull request (docs/oss-fuzz-onboarding.md)."
