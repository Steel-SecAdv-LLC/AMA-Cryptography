# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
# AMA Cryptography — Benchmarks Build
# ====================================
#
# Build the raw C benchmark binary:
#   make benchmark_c_raw
#
# Run:
#   ./benchmark_c_raw            # Human-readable table
#   ./benchmark_c_raw --csv      # CSV output
#   ./benchmark_c_raw --json     # JSON output
#
# Library:
#   Links build/lib/libama_cryptography.so, else build/lib/
#   libama_cryptography_static.a.  When neither exists, the recipe builds the
#   static archive with CMake first -- the same configuration as
#     cmake -B ../build -DAMA_USE_NATIVE_PQC=ON -DCMAKE_BUILD_TYPE=Release
#     cmake --build ../build --target ama_cryptography_static

ROOT_DIR     := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
INCLUDE_DIR  := $(ROOT_DIR)/include
BUILD_DIR    := $(ROOT_DIR)/build

UNAME_S      := $(shell uname -s)
CC           ?= gcc
CFLAGS       := -O3 -Wall -Wextra -std=c11 -I$(INCLUDE_DIR)
# -pthread: the static archive's dispatcher initialises through
# pthread_once (INVARIANT-15), and CMake records Threads::Threads as a link
# dependency of that archive rather than folding it in.
LDFLAGS      := -lm -pthread
ifeq ($(UNAME_S),Linux)
LDFLAGS      += -lrt
endif

# Link the shared library if it exists, else the static archive; when neither
# exists, build the static archive with CMake and link that.
LIB_SO       := $(BUILD_DIR)/lib/libama_cryptography.so
LIB_A        := $(BUILD_DIR)/lib/libama_cryptography_static.a

# The no-library fallback goes through CMake because CMakeLists.txt is the
# only complete description of the library.  This recipe used to compile
# $(wildcard src/c/ama_*.c) itself, and that could never produce a binary:
# the glob misses src/c/dispatch/ (ama_get_dispatch_table, which the harness
# calls), src/c/internal/ and src/c/x86/, and carries none of the per-file ISA
# flags (ama_sha256_ni.c stops the compile at the first SHA-NI intrinsic).
# It also defined neither AMA_USE_NATIVE_PQC nor AMA_AES_CONSTTIME, so had it
# linked it would have benchmarked PQC stubs and the table S-box that CMake
# refuses to build without an explicit INVARIANT-20 acknowledgement.
CMAKE        ?= cmake
CMAKE_FLAGS  := -DCMAKE_BUILD_TYPE=Release -DAMA_USE_NATIVE_PQC=ON -DAMA_BUILD_STATIC=ON

.PHONY: all clean help

all: benchmark_c_raw

benchmark_c_raw: benchmark_c_raw.c
	@echo "=== Building Raw C Benchmark Harness ==="
	@if [ -f "$(LIB_SO)" ]; then \
		echo "Linking against shared library: $(LIB_SO)"; \
		$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR)/lib -lama_cryptography $(LDFLAGS) \
			-Wl,-rpath,$(BUILD_DIR)/lib; \
	elif [ -f "$(LIB_A)" ]; then \
		echo "Linking against static library: $(LIB_A)"; \
		$(CC) $(CFLAGS) -o $@ $< $(LIB_A) $(LDFLAGS); \
	else \
		echo "No pre-built library found. Building $(LIB_A) with CMake..."; \
		$(CMAKE) -S $(ROOT_DIR) -B $(BUILD_DIR) $(CMAKE_FLAGS) && \
		$(CMAKE) --build $(BUILD_DIR) --target ama_cryptography_static && \
		$(CC) $(CFLAGS) -o $@ $< $(LIB_A) $(LDFLAGS); \
	fi
	@echo "=== Build complete: ./benchmark_c_raw ==="

clean:
	rm -f benchmark_c_raw

help:
	@echo "Targets:"
	@echo "  benchmark_c_raw  Build the raw C benchmark binary"
	@echo "  clean            Remove built binaries"
	@echo ""
	@echo "Usage:"
	@echo "  ./benchmark_c_raw          Human-readable table output"
	@echo "  ./benchmark_c_raw --csv    CSV output (machine-parseable)"
	@echo "  ./benchmark_c_raw --json   JSON output (machine-parseable)"
