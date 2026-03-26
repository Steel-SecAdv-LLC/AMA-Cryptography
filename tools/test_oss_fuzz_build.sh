#!/bin/bash
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
#
# Local OSS-Fuzz build verification script
#
# This script uses OSS-Fuzz's infrastructure to test the build locally
# before submitting a PR to google/oss-fuzz.
#
# Prerequisites:
#   - Docker installed and running
#   - google/oss-fuzz repository cloned locally
#
# Usage:
#   ./tools/test_oss_fuzz_build.sh [path-to-oss-fuzz-checkout]
#
# If no path is given, the script clones oss-fuzz into /tmp/oss-fuzz.

set -euo pipefail

OSS_FUZZ_DIR="${1:-/tmp/oss-fuzz}"
PROJECT_NAME="ama-cryptography"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# Check prerequisites
if ! command -v docker &>/dev/null; then
    echo "ERROR: Docker is required but not installed."
    echo "Install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! docker info &>/dev/null; then
    echo "ERROR: Docker daemon is not running."
    exit 1
fi

# Clone or update OSS-Fuzz
if [ ! -d "$OSS_FUZZ_DIR" ]; then
    echo "Cloning google/oss-fuzz into $OSS_FUZZ_DIR..."
    git clone --depth 1 https://github.com/google/oss-fuzz.git "$OSS_FUZZ_DIR"
else
    echo "Using existing OSS-Fuzz checkout at $OSS_FUZZ_DIR"
fi

# Create project directory in OSS-Fuzz checkout
PROJECT_DIR="$OSS_FUZZ_DIR/projects/$PROJECT_NAME"
mkdir -p "$PROJECT_DIR"

# Copy OSS-Fuzz configuration files
echo "Copying OSS-Fuzz configuration files..."
cp "$REPO_ROOT/oss-fuzz/project.yaml" "$PROJECT_DIR/"
cp "$REPO_ROOT/oss-fuzz/Dockerfile" "$PROJECT_DIR/"
cp "$REPO_ROOT/oss-fuzz/build.sh" "$PROJECT_DIR/"

echo ""
echo "=== Step 1: Building Docker image ==="
python3 "$OSS_FUZZ_DIR/infra/helper.py" build_image "$PROJECT_NAME"

echo ""
echo "=== Step 2: Building fuzz targets ==="
python3 "$OSS_FUZZ_DIR/infra/helper.py" build_fuzzers "$PROJECT_NAME"

echo ""
echo "=== Step 3: Checking build ==="
python3 "$OSS_FUZZ_DIR/infra/helper.py" check_build "$PROJECT_NAME"

echo ""
echo "=== All checks passed! ==="
echo "The OSS-Fuzz build is working correctly."
echo ""
echo "Next steps:"
echo "  1. Fork https://github.com/google/oss-fuzz"
echo "  2. Copy oss-fuzz/ files to projects/$PROJECT_NAME/"
echo "  3. Submit a PR to google/oss-fuzz"
echo "  See docs/oss-fuzz-onboarding.md for full instructions."
