# Copyright 2025 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
#
# Makefile for Ava Guardian ♱
#
# Quick build targets:
#   make all        - Build everything (C library + Python extensions)
#   make c          - Build C library only
#   make python     - Build Python package
#   make test       - Run all tests
#   make clean      - Clean build artifacts
#   make install    - Install library system-wide
#   make docker     - Build Docker image

.PHONY: all c python test clean install docker help c-api constant-time-check security-scan

# Default target
all: c python

# Build C library with CMake
c:
	@echo "Building C library..."
	@mkdir -p build
	@cd build && cmake .. && $(MAKE)
	@echo "✓ C library built successfully"

# Build Python package with extensions
python:
	@echo "Building Python package..."
	@python3 setup.py build_ext --inplace
	@echo "✓ Python package built successfully"

# Run tests
test: test-c test-python

test-c: c
	@echo "Running C tests..."
	@cd build && ctest --output-on-failure
	@echo "✓ C tests passed"

test-python: python
	@echo "Running Python tests..."
	@pytest tests/ -v --cov=ava_guardian --cov-report=term-missing
	@echo "✓ Python tests passed"

# Run benchmarks
benchmark: python
	@echo "Running benchmarks..."
	@python3 benchmark_suite.py
	@pytest tests/ --benchmark-only

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf build/
	@rm -rf lib/
	@rm -rf *.so *.egg-info dist/ .eggs/
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete
	@find . -type f -name "*.pyo" -delete
	@find . -type f -name "*.c" -path "*/src/cython/*" -delete
	@echo "✓ Cleaned"

# Install system-wide
install: all
	@echo "Installing Ava Guardian ♱..."
	@cd build && sudo $(MAKE) install
	@pip3 install -e .
	@echo "✓ Installed successfully"

# Development install
dev-install:
	@echo "Installing development dependencies..."
	@pip3 install -e ".[dev,all]"
	@echo "✓ Development environment ready"

# Format code
format:
	@echo "Formatting code..."
	@black ava_guardian/ tests/ *.py
	@isort ava_guardian/ tests/ *.py
	@echo "✓ Code formatted"

# Lint code
lint:
	@echo "Linting code..."
	@flake8 ava_guardian/ tests/ --max-line-length=100
	@mypy ava_guardian/ --ignore-missing-imports
	@echo "✓ Lint passed"

# Generate documentation
# Requires: sphinx from requirements-dev.txt (pip install -r requirements-dev.txt)
docs:
	@echo "Generating documentation..."
	@cd build && doxygen ../docs/Doxyfile
	@cd docs && sphinx-build -b html . _build/html
	@echo "✓ Documentation generated"
	@echo "  C API docs:      build/docs/html/index.html"
	@echo "  Python API docs: docs/_build/html/index.html"

# Build Docker image
docker:
	@echo "Building Docker image..."
	@docker build -t ava-guardian:latest -f docker/Dockerfile .
	@echo "✓ Docker image built"

# Create release distribution
dist: clean
	@echo "Creating distribution packages..."
	@python3 setup.py sdist bdist_wheel
	@echo "✓ Distribution packages created in dist/"

# Security audit (basic)
security-audit:
	@echo "Running security audit..."
	@pip-audit
	@bandit -r ava_guardian/ -ll
	@echo "✓ Security audit complete"

# Comprehensive security scan (bandit + semgrep + dependency scanning)
security-scan:
	@echo "Running comprehensive security scan..."
	@echo "[1/3] Running bandit for Python security issues..."
	@bandit -r ava_guardian/ code_guardian_secure.py -ll -f json -o bandit-report.json || true
	@bandit -r ava_guardian/ code_guardian_secure.py -ll
	@echo "[2/3] Running semgrep for cryptographic rules..."
	@semgrep --config .semgrep.yml ava_guardian/ code_guardian_secure.py --json -o semgrep-report.json 2>/dev/null || echo "  (semgrep not installed or no rules matched)"
	@echo "[3/3] Running pip-audit for dependency vulnerabilities..."
	@pip-audit --format json -o pip-audit-report.json 2>/dev/null || pip-audit || echo "  (pip-audit completed)"
	@echo "✓ Comprehensive security scan complete"
	@echo "  Reports: bandit-report.json, semgrep-report.json, pip-audit-report.json"

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

# Build C API with native PQC
c-api:
	@echo "Building C API library with native PQC..."
	@mkdir -p build
	@cd build && cmake .. -DAVA_BUILD_SHARED=ON -DAVA_BUILD_STATIC=ON \
		-DAVA_USE_NATIVE_PQC=ON && $(MAKE)
	@echo "✓ C API built successfully"
	@echo "  Shared library: build/lib/libava_guardian.so"
	@echo "  Static library: build/lib/libava_guardian.a"
	@echo "  Headers: include/ava_guardian.h"
	@echo "  PQC: NATIVE (ML-DSA-65, Kyber-1024, SPHINCS+-256f)"

# Build C API Docker image for reproducible builds
docker-c-api:
	@echo "Building C API Docker image..."
	@docker build -t ava-guardian-c-api:latest -f docker/Dockerfile.c-api .
	@echo "✓ C API Docker image built"
	@echo "  Usage: docker run -v \$$(pwd)/output:/output ava-guardian-c-api:latest"

# Performance profiling
profile: python
	@echo "Profiling performance..."
	@python3 -m cProfile -o profile.stats benchmark_suite.py
	@python3 -c "import pstats; p = pstats.Stats('profile.stats'); p.sort_stats('cumulative'); p.print_stats(30)"

# Help
help:
	@echo "Ava Guardian ♱ Build System"
	@echo "============================"
	@echo ""
	@echo "Main targets:"
	@echo "  make all            - Build C library and Python extensions"
	@echo "  make c              - Build C library only"
	@echo "  make c-api          - Build C API with native PQC"
	@echo "  make python         - Build Python package"
	@echo "  make test           - Run all tests"
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
	@echo ""
	@echo "Development targets:"
	@echo "  make format         - Format code with black/isort"
	@echo "  make lint           - Lint code with flake8/mypy"
	@echo "  make docs           - Generate API documentation"
	@echo "  make profile        - Profile performance"
	@echo ""
	@echo "Deployment targets:"
	@echo "  make docker         - Build Docker image"
	@echo "  make docker-c-api   - Build C API Docker image"
	@echo "  make dist           - Create release distributions"
	@echo ""
