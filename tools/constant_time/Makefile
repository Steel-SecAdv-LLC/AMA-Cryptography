# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
#
# Makefile for Constant-Time Verification Tools

CC = gcc
# D-5: build the harness AGAINST THE PRODUCTION-DEFAULT constant-time AES path
# (-DAMA_AES_CONSTTIME=ON), so the timing measurements faithfully reflect
# what end users get from `cmake -DAMA_USE_NATIVE_PQC=ON` (the canonical
# build).  Without this flag the harness silently exercised the table-based
# S-box reference path and produced misleading "[KNOWN - table-based]"
# attribution for failures actually unrelated to the S-box.
CFLAGS = -O2 -Wall -Wextra -I../../include -DAMA_AES_CONSTTIME=ON
LDFLAGS = -lm -lpthread

# Source directories
SRC_DIR = ../../src/c
INCLUDE_DIR = ../../include

# Targets
DUDECT_HARNESS = dudect_harness
DUDECT_CRYPTO  = dudect_crypto

# Source files needed by each harness
CONSTTIME_SRC = $(SRC_DIR)/ama_consttime.c

# All sources needed for the crypto-primitive harness.  ama_aes_bitsliced.c
# provides the constant-time S-box that ama_aes_gcm.c uses when
# AMA_AES_CONSTTIME is defined; without it the link fails with an undefined
# reference to ama_aes256_key_expansion_consttime.
DISPATCH_DIR = ../../src/c/dispatch
CRYPTO_SRCS = $(SRC_DIR)/ama_consttime.c \
              $(SRC_DIR)/ama_core.c \
              $(SRC_DIR)/ama_sha3.c \
              $(SRC_DIR)/ama_ed25519.c \
              $(SRC_DIR)/ama_aes_gcm.c \
              $(SRC_DIR)/ama_aes_bitsliced.c \
              $(SRC_DIR)/ama_hkdf.c \
              $(SRC_DIR)/ama_cpuid.c \
              $(DISPATCH_DIR)/ama_dispatch.c

.PHONY: all clean test test-full test-crypto test-crypto-full help

all: $(DUDECT_HARNESS) $(DUDECT_CRYPTO)

$(DUDECT_HARNESS): dudect_harness.c $(CONSTTIME_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(CONSTTIME_SRC) $(LDFLAGS)

$(DUDECT_CRYPTO): dudect_crypto.c $(CRYPTO_SRCS)
	$(CC) $(CFLAGS) -o $@ $< $(CRYPTO_SRCS) $(LDFLAGS)

test: $(DUDECT_HARNESS)
	@echo "Running dudect-style timing analysis (utility functions)..."
	@echo "This may take a few minutes..."
	./$(DUDECT_HARNESS) 100000

test-full: $(DUDECT_HARNESS)
	@echo "Running full dudect-style timing analysis (1M iterations)..."
	@echo "This may take 5-10 minutes..."
	./$(DUDECT_HARNESS) 1000000

test-crypto: $(DUDECT_CRYPTO)
	@echo "Running dudect-style timing analysis (crypto primitives)..."
	@echo "Tests: Ed25519 sign, AES-GCM encrypt/verify, HKDF, SHA3-256"
	./$(DUDECT_CRYPTO) 100000

test-crypto-full: $(DUDECT_CRYPTO)
	@echo "Running full crypto primitive timing analysis (1M iterations)..."
	@echo "This may take 10-15 minutes..."
	./$(DUDECT_CRYPTO) 1000000

# Run both harnesses
test-all: test test-crypto

clean:
	rm -f $(DUDECT_HARNESS) $(DUDECT_CRYPTO)

help:
	@echo "Constant-Time Verification Tools"
	@echo "================================="
	@echo ""
	@echo "Targets:"
	@echo "  all              - Build all dudect harnesses"
	@echo "  test             - Run utility function timing analysis (100K)"
	@echo "  test-full        - Run full utility timing analysis (1M)"
	@echo "  test-crypto      - Run crypto primitive timing analysis (100K)"
	@echo "  test-crypto-full - Run full crypto primitive timing analysis (1M)"
	@echo "  test-all         - Run both harnesses (100K)"
	@echo "  clean            - Remove built files"
	@echo "  help             - Show this help message"
