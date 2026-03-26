#!/bin/bash
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
#
# dudect Constant-Time Verification Runner
#
# Builds and runs all dudect tests, collecting results into a summary.
#
# Usage:
#   ./tools/run_dudect.sh [--measurements N] [--timeout S] [--build-only]
#
# Options:
#   --measurements N   Number of measurements per test (default: 1000000)
#   --timeout S        Per-test timeout in seconds (default: 300)
#   --build-only       Only build, don't run tests
#   --pqc              Enable PQC tests (Kyber, Dilithium)
#   --help             Show this help message

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$REPO_ROOT/build-dudect"

MEASUREMENTS=1000000
TIMEOUT=300
BUILD_ONLY=0
PQC=1  # Enabled by default

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --measurements N   Measurements per test (default: $MEASUREMENTS)"
    echo "  --timeout S        Per-test timeout in seconds (default: $TIMEOUT)"
    echo "  --build-only       Only build, don't run"
    echo "  --no-pqc           Disable PQC tests"
    echo "  --help             Show this help"
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --measurements) MEASUREMENTS="$2"; shift 2 ;;
        --timeout)      TIMEOUT="$2"; shift 2 ;;
        --build-only)   BUILD_ONLY=1; shift ;;
        --no-pqc)       PQC=0; shift ;;
        --help)         usage ;;
        *)              echo "Unknown option: $1"; usage ;;
    esac
done

echo "======================================================="
echo "dudect Constant-Time Verification Runner"
echo "======================================================="
echo ""
echo "Configuration:"
echo "  Measurements: $MEASUREMENTS"
echo "  Timeout:      ${TIMEOUT}s"
echo "  PQC tests:    $([ $PQC -eq 1 ] && echo 'enabled' || echo 'disabled')"
echo ""

# Build
echo "=== Building dudect tests ==="
cmake -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DAMA_ENABLE_DUDECT=ON \
    -DAMA_USE_NATIVE_PQC=$([ $PQC -eq 1 ] && echo 'ON' || echo 'OFF') \
    -DAMA_AES_CONSTTIME=ON \
    -DAMA_ENABLE_LTO=OFF \
    -DAMA_BUILD_EXAMPLES=OFF \
    "$REPO_ROOT" 2>&1 | tail -5

cmake --build "$BUILD_DIR" -j"$(nproc)" 2>&1 | tail -5
echo "Build complete."
echo ""

if [ $BUILD_ONLY -eq 1 ]; then
    echo "Build-only mode. Skipping test execution."
    exit 0
fi

# Run dudect test suite
echo "=== Running dudect test suite ==="
echo ""

DUDECT_BIN="$BUILD_DIR/bin/test_dudect"
if [ ! -f "$DUDECT_BIN" ]; then
    echo "ERROR: test_dudect binary not found at $DUDECT_BIN"
    exit 1
fi

# Try to pin to single core for less noise (non-fatal if taskset unavailable)
TASKSET=""
if command -v taskset &>/dev/null; then
    TASKSET="taskset -c 0"
fi

EXIT_CODE=0
$TASKSET "$DUDECT_BIN" --measurements "$MEASUREMENTS" --timeout "$TIMEOUT" || EXIT_CODE=$?

echo ""

# Also run legacy harnesses if they exist
echo "=== Running legacy dudect harnesses ==="
LEGACY_DIR="$REPO_ROOT/tools/constant_time"
if [ -f "$LEGACY_DIR/Makefile" ]; then
    (cd "$LEGACY_DIR" && make -s all 2>/dev/null)

    if [ -f "$LEGACY_DIR/dudect_harness" ]; then
        echo "--- Utility function harness ---"
        $TASKSET "$LEGACY_DIR/dudect_harness" 50000 || true
    fi

    if [ -f "$LEGACY_DIR/dudect_crypto" ]; then
        echo "--- Crypto primitive harness ---"
        $TASKSET "$LEGACY_DIR/dudect_crypto" 50000 || true
    fi
else
    echo "Legacy harnesses not found, skipping."
fi

echo ""
echo "======================================================="
if [ $EXIT_CODE -eq 0 ]; then
    echo "All dudect tests PASSED."
else
    echo "Some dudect tests FAILED (exit code: $EXIT_CODE)."
    echo ""
    echo "If this is a CI environment, timing noise may cause"
    echo "false positives. Reproduce locally on quiet hardware:"
    echo "  taskset -c 0 nice -n -20 $DUDECT_BIN --measurements 10000000"
fi
echo "======================================================="

exit $EXIT_CODE
