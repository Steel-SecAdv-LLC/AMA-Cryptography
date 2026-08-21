# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
#
# Makefile for AMA Cryptography
#
# Quick build targets:
#   make all        - Build everything (C library + Python extensions)
#   make c          - Build C library only
#   make python     - Build Python package
#   make test       - Run all tests
#   make clean      - Clean build artifacts
#   make install    - Install library system-wide
#   make docker     - Build Docker image

.PHONY: all c python test clean install docker help c-api constant-time-check security-scan fuzz fuzz-run

# Default target
all: c python

# Build C library with CMake
c:
	@echo "Building C library (native PQC + all crypto primitives)..."
	@mkdir -p build
	@# CMAKE_BUILD_TYPE=Release is explicit, not decorative: an empty build type
	@# applies NONE of the per-config flags, so this target used to produce an
	@# unoptimised library with no _FORTIFY_SOURCE (which is inert without -O)
	@# and no LTO — and `make install` below then installs exactly that build
	@# system-wide.  Every document that quotes performance or hardening for
	@# this project describes the Release configuration.
	@cd build && cmake .. -DCMAKE_BUILD_TYPE=Release -DAMA_USE_NATIVE_PQC=ON && $(MAKE)
	@echo "✓ C library built successfully"

# Build Python package with extensions
python:
	@echo "Building Python package..."
	@python3 setup.py build_ext --inplace
	@echo "✓ Python package built successfully"

# Run tests
test: test-c test-python test-examples

test-c: c
	@echo "Running C tests..."
	@cd build && ctest --output-on-failure
	@echo "✓ C tests passed"

test-python: python
	@echo "Running Python tests..."
	@$(RUN) pytest tests/ -v --cov=ama_cryptography --cov-report=term-missing
	@echo "✓ Python tests passed"

# Execute the shipped Python examples.
#
# examples/python/ is documentation that runs, and until this target existed
# nothing ran it: basic_usage.py Examples 3 and 4 called the package API with
# keyword names it does not have, and complete_demo.py handed converge() a
# numpy.ndarray it did not accept.  Both scripts failed for every user who
# tried them, and every test in the suite passed.
#
# Depends on `c` and not on `python`: the examples exercise the native
# backend, and the Cython extensions are optional to them.
test-examples: c
	@echo "Running shipped Python examples..."
	@$(RUN) pytest tests/test_python_examples.py -v
	@echo "✓ Python examples ran to completion"

# Run benchmarks
benchmark: python
	@echo "Running benchmarks..."
	@python3 benchmarks/benchmark_suite.py
	@$(RUN) pytest tests/ --benchmark-only

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf build/
	@rm -rf lib/
	@rm -rf *.so *.egg-info dist/ .eggs/
	@find . -type d -name __pycache__ -exec rm -rf {} + || true
	@find . -type f -name "*.pyc" -delete
	@find . -type f -name "*.pyo" -delete
	@find . -type f -name "*.c" -path "*/src/cython/*" -delete
	# In-place Cython extensions land under ama_cryptography/ (and under
	# build/ when PEP 517 build was used). Without the two lines below,
	# `make clean` leaves *.cpython-*.so and Windows *.pyd files behind —
	# subsequent `make python` then silently re-links against stale
	# objects (audit 5b).
	@find ama_cryptography -type f -name "*.so" -delete
	@find ama_cryptography -type f -name "*.pyd" -delete
	# The native library is bundled into the package by setup.py as a SONAME
	# chain — libama_cryptography.so -> .so.5 -> .so.5.0.0 — and the two rules
	# above miss every link in it: the first two are symlinks, which `-type f`
	# excludes, and the third does not match `*.so`. So the whole chain
	# survived `make clean`, and pqc_backends._get_search_dirs() searches this
	# directory FIRST, ahead of build/ and the system paths. A stale library
	# therefore shadowed every later build indefinitely, with the loaded path
	# appearing nowhere in the logs — a rebuilt .so could sit in build/lib
	# while the process kept running last month's code. Matched by prefix
	# rather than by extension, and without -type, so symlinks go too.
	@find ama_cryptography -maxdepth 1 -name "libama_cryptography*" -delete
	@find ama_cryptography -maxdepth 1 -name "ama_cryptography*.dll" -delete
	@echo "✓ Cleaned"

# Install system-wide
install: all
	@echo "Installing AMA Cryptography..."
	@cd build && sudo $(MAKE) install
	@$(RUN) pip install -e .
	@echo "✓ Installed successfully"

# Development install
dev-install:
	@echo "Installing development dependencies..."
	@$(RUN) pip install -e ".[dev,all]"
	@echo "✓ Development environment ready"

# The interpreter's own tools, never the bare console scripts.
#
# `mypy` on PATH here was 1.19.1 from a stale ~/.local install while the pinned
# toolchain (requirements-lock.txt, both CI images, .pre-commit-config.yaml) is
# 2.3.0 — and [tool.mypy] sets python_version = "3.10", which mypy 1.x accepts
# with different semantics. `make lint` therefore reported 40 errors that CI
# does not have and would not report ones it does. Same hazard for black and
# ruff, whose formatting differs across versions.
PYTHON ?= python3
RUN := $(PYTHON) -m

# Format code
format:
	@echo "Formatting code..."
	@$(RUN) black .
	@$(RUN) ruff check --select I --fix .
	@echo "✓ Code formatted"

# Lint code
# The scope and the flags CI uses, so a green `make lint` means something.
# This target ran `ruff check ama_cryptography/ tests/` and `mypy
# ama_cryptography/ --ignore-missing-imports`, which is neither:
# --ignore-missing-imports silences the missing-stub errors the pyproject
# overrides answer file by file, and one directory is a third of the Python in
# the tree.
lint:
	@echo "Linting code..."
	@$(RUN) ruff check .
	@MYPYPATH=. $(RUN) mypy --strict --explicit-package-bases \
	  ama_cryptography/ tests/ tools/ benchmarks/ examples/ \
	  fuzz/python/ nist_vectors/ schemas/ wycheproof_vectors/ \
	  docs/conf.py setup.py ama_cryptography_monitor.py
	@echo "✓ Lint passed"

# Generate documentation
# Requires: sphinx from requirements-dev.txt (pip install -r requirements-dev.txt)
#
# AMA_SPHINX_BUILD=1 lifts the INVARIANT-7 import guards in crypto_api.py /
# key_management.py / legacy_compat.py so autodoc can introspect the modules
# without a native C backend.  Every call-time path still enforces
# INVARIANT-7 — this affects imports only.
#
# -W --keep-going turns every Sphinx warning into an error while still
# collecting the full list, so docstring regressions fail the build.
docs:
	@echo "Generating documentation..."
	@cd build && doxygen ../docs/Doxyfile
	@AMA_SPHINX_BUILD=1 sphinx-build -W --keep-going -b html docs docs/_build/html
	@echo "✓ Documentation generated"
	@echo "  C API docs:      build/docs/html/index.html"
	@echo "  Python API docs: docs/_build/html/index.html"

# Build Docker image
docker:
	@echo "Building Docker image..."
	@docker build -t ama-cryptography:latest -f docker/Dockerfile .
	@echo "✓ Docker image built"

# Create release distribution
dist: clean
	@echo "Creating distribution packages..."
	@python3 -m build
	@echo "✓ Distribution packages created in dist/"

# Security audit (basic)
security-audit:
	@echo "Running security audit..."
	@pip-audit
	@$(RUN) bandit -r ama_cryptography/ -ll
	@echo "✓ Security audit complete"

# Comprehensive security scan (bandit + semgrep + dependency scanning)
security-scan:
	@echo "Running comprehensive security scan..."
	@echo "[1/3] Running bandit for Python security issues..."
	@# Produce the JSON, then apply the SAME severity gate CI uses. The `|| true`
	@# is only on the report-writing bandit run (bandit exits non-zero when it
	@# finds anything at the -ll floor); the gate below is what actually decides
	@# pass/fail, fail-closed on a missing/erroring report.
	@$(RUN) bandit -r ama_cryptography/ -ll -f json -o bandit-report.json || true
	@python3 tools/check_bandit_severity.py bandit-report.json
	@echo "[2/3] Running semgrep for cryptographic rules..."
	@# semgrep scan exits 0 regardless of findings; the gate reads the JSON and
	@# fails on ERROR-severity findings or a scan that did not run. No `|| echo`
	@# swallowing a failure into a success line.
	@semgrep --config .semgrep.yml ama_cryptography/ --json -o semgrep-report.json
	@python3 tools/check_semgrep_severity.py semgrep-report.json
	@echo "[3/3] Running pip-audit for dependency vulnerabilities..."
	@# pip-audit exits non-zero when a known-vulnerable dependency is present;
	@# let that propagate rather than masking it with `|| echo completed`.
	@# Scoped to the lock file, not the ambient interpreter: a bare `pip-audit`
	@# reports CVEs in packages this project does not ship (pip, urllib3 and
	@# whatever else the host image carries), so the target went red for reasons
	@# nothing in this repository can fix. Same scoping ci.yml and security.yml
	@# already use.
	@pip-audit --strict --desc --requirement requirements-lock.txt
	@echo "✓ Comprehensive security scan complete (bandit + semgrep + pip-audit all passed)"

# Constant-time verification (dudect-style timing analysis)
constant-time-check:
	@echo "Running constant-time verification..."
	@echo "Building dudect harness..."
	@cd tools/constant_time && $(MAKE) clean && $(MAKE)
	@echo "Running timing analysis (100K iterations)..."
	@cd tools/constant_time && $(MAKE) test
	@echo "✓ Constant-time verification complete"

# Full constant-time verification (1M iterations, recommended for production)
constant-time-check-full:
	@echo "Running full constant-time verification (1M iterations)..."
	@echo "This may take 5-10 minutes..."
	@cd tools/constant_time && $(MAKE) clean && $(MAKE)
	@cd tools/constant_time && $(MAKE) test-full
	@echo "✓ Full constant-time verification complete"

# Build fuzzing harnesses (requires clang)
fuzz:
	@echo "Building fuzzing harnesses (libFuzzer + ASan)..."
	@mkdir -p build-fuzz
	@cd build-fuzz && cmake .. \
		-DCMAKE_C_COMPILER=clang \
		-DCMAKE_BUILD_TYPE=Debug \
		-DAMA_BUILD_FUZZ=ON \
		-DAMA_BUILD_TESTS=OFF \
		-DAMA_BUILD_EXAMPLES=OFF \
		-DAMA_ENABLE_LTO=OFF \
		-DAMA_USE_NATIVE_PQC=ON && $(MAKE)
	@echo "✓ Fuzz harnesses built in build-fuzz/bin/"

# Run a quick fuzzing smoke test (10 seconds per target)
fuzz-run: fuzz
	@echo "Running fuzzing smoke tests (10 seconds each)..."
	@# libFuzzer exits non-zero on a crash/leak/timeout.  Piping to `tail`
	@# previously discarded that exit code (the pipeline returned tail's status),
	@# so a discovered crash printed its last lines and the target still reported
	@# "✓ complete".  Write output to a log and branch on the fuzzer's OWN exit
	@# status (no pipe in the tested command), so a crash fails the target and
	@# names the offender.  Portable across /bin/sh and bash.
	@for target in fuzz_sha3 fuzz_ed25519 fuzz_aes_gcm fuzz_hkdf fuzz_consttime; do \
		echo "  Fuzzing $$target..."; \
		if ./build-fuzz/bin/$$target -max_total_time=10 -max_len=4096 \
				build-fuzz/corpus/$$target/ > fuzz-$$target.log 2>&1; then \
			tail -3 fuzz-$$target.log; \
		else \
			status=$$?; \
			echo "✗ $$target FAILED (libFuzzer exit $$status) — crash/leak/timeout:"; \
			tail -20 fuzz-$$target.log; \
			exit "$$status"; \
		fi; \
	done
	@echo "✓ Fuzzing smoke tests complete (no crashes/leaks/timeouts)"

# Build C API with native PQC
c-api:
	@echo "Building C API library with native PQC..."
	@mkdir -p build
	@cd build && cmake .. -DCMAKE_BUILD_TYPE=Release \
		-DAMA_BUILD_SHARED=ON -DAMA_BUILD_STATIC=ON \
		-DAMA_USE_NATIVE_PQC=ON && $(MAKE)
	@echo "✓ C API built successfully"
	@echo "  Shared library: build/lib/libama_cryptography.so"
	@echo "  Static library: build/lib/libama_cryptography.a"
	@echo "  Headers: include/ama_cryptography.h"
	@echo "  PQC: NATIVE (ML-DSA-65, Kyber-1024, SPHINCS+-256f)"

# Build C API Docker image for reproducible builds
docker-c-api:
	@echo "Building C API Docker image..."
	@docker build -t ama-cryptography-c-api:latest -f docker/Dockerfile.c-api .
	@echo "✓ C API Docker image built"
	@echo "  Usage: docker run -v \$$(pwd)/output:/output ama-cryptography-c-api:latest"

# Performance profiling
profile: python
	@echo "Profiling performance..."
	@python3 -m cProfile -o profile.stats benchmarks/benchmark_suite.py
	@python3 -c "import pstats; p = pstats.Stats('profile.stats'); p.sort_stats('cumulative'); p.print_stats(30)"

# Help
help:
	@echo "AMA Cryptography Build System"
	@echo "============================"
	@echo ""
	@echo "Main targets:"
	@echo "  make all            - Build C library and Python extensions"
	@echo "  make c              - Build C library only"
	@echo "  make c-api          - Build C API with native PQC"
	@echo "  make python         - Build Python package"
	@echo "  make test           - Run all tests (C, Python, shipped examples)"
	@echo "  make test-examples  - Run the shipped Python examples end to end"
	@echo "  make benchmark      - Run performance benchmarks"
	@echo "  make clean          - Remove build artifacts"
	@echo "  make install        - Install system-wide"
	@echo "  make dev-install    - Install development environment"
	@echo ""
	@echo "Security targets:"
	@echo "  make security-audit       - Run basic security checks (bandit + pip-audit)"
	@echo "  make security-scan        - Run comprehensive security scan (bandit + semgrep + pip-audit)"
	@echo "  make constant-time-check  - Run constant-time verification (100K iterations)"
	@echo "  make constant-time-check-full - Run full constant-time verification (1M iterations)"
	@echo "  make fuzz                 - Build libFuzzer harnesses (requires clang)"
	@echo "  make fuzz-run             - Run 10-second fuzzing smoke tests"
	@echo ""
	@echo "Development targets:"
	@echo "  make format         - Format code with black/ruff"
	@echo "  make lint           - Lint code with ruff/mypy"
	@echo "  make docs           - Generate API documentation"
	@echo "  make profile        - Profile performance"
	@echo ""
	@echo "Deployment targets:"
	@echo "  make docker         - Build Docker image"
	@echo "  make docker-c-api   - Build C API Docker image"
	@echo "  make dist           - Create release distributions"
	@echo ""
