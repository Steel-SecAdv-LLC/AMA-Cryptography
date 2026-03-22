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
# Prerequisites:
#   The AMA C library must be built first:
#     cmake -B ../build -DAMA_USE_NATIVE_PQC=ON -DCMAKE_BUILD_TYPE=Release
#     cmake --build ../build

ROOT_DIR     := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
INCLUDE_DIR  := $(ROOT_DIR)/include
SRC_DIR      := $(ROOT_DIR)/src/c
BUILD_DIR    := $(ROOT_DIR)/build

UNAME_S      := $(shell uname -s)
CC           ?= gcc
CFLAGS       := -O3 -Wall -Wextra -std=c11 -I$(INCLUDE_DIR)
LDFLAGS      := -lm
ifeq ($(UNAME_S),Linux)
LDFLAGS      += -lrt
endif

# If the shared library exists, link against it; otherwise compile sources directly
LIB_SO       := $(BUILD_DIR)/lib/libama_cryptography.so
LIB_A        := $(BUILD_DIR)/lib/libama_cryptography.a

# C source files needed when linking statically
C_SOURCES    := $(wildcard $(SRC_DIR)/ama_*.c) $(SRC_DIR)/ed25519_donna_shim.c

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
		echo "No pre-built library found. Compiling from sources..."; \
		$(CC) $(CFLAGS) -I$(SRC_DIR) -I$(SRC_DIR)/internal \
			-I$(SRC_DIR)/vendor/ed25519-donna \
			-DAMA_BUILDING_STATIC \
			-o $@ $< $(C_SOURCES) $(LDFLAGS); \
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
