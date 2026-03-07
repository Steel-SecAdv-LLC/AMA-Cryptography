# Copyright 2025 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
#
# Makefile for Constant-Time Verification Tools

CC = gcc
CFLAGS = -O2 -Wall -Wextra -I../../include
LDFLAGS = -lm

# Source directories
SRC_DIR = ../../src/c
INCLUDE_DIR = ../../include

# Targets
DUDECT_HARNESS = dudect_harness

# Source files
CONSTTIME_SRC = $(SRC_DIR)/ama_consttime.c

.PHONY: all clean test help

all: $(DUDECT_HARNESS)

$(DUDECT_HARNESS): dudect_harness.c $(CONSTTIME_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(CONSTTIME_SRC) $(LDFLAGS)

test: $(DUDECT_HARNESS)
	@echo "Running dudect-style timing analysis..."
	@echo "This may take a few minutes..."
	./$(DUDECT_HARNESS) 100000

test-full: $(DUDECT_HARNESS)
	@echo "Running full dudect-style timing analysis (1M iterations)..."
	@echo "This may take 5-10 minutes..."
	./$(DUDECT_HARNESS) 1000000

clean:
	rm -f $(DUDECT_HARNESS)

help:
	@echo "Constant-Time Verification Tools"
	@echo "================================="
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build the dudect harness"
	@echo "  test       - Run quick timing analysis (100K iterations)"
	@echo "  test-full  - Run full timing analysis (1M iterations)"
	@echo "  clean      - Remove built files"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make           # Build the harness"
	@echo "  make test      # Run quick test"
	@echo "  make test-full # Run comprehensive test"
