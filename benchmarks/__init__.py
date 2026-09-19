# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Benchmark harnesses and regression-floor tooling.

A real package (not an implicit namespace one) so that ``mypy --strict`` maps
``benchmarks/benchmark_runner.py`` to the same ``benchmarks.benchmark_runner``
module name the test tree imports it under — with only a namespace package,
one invocation sees the file under two module names and refuses to check it.
``setup.py``'s ``find_packages(include=["ama_cryptography", ...])`` cannot
pick this package up, so nothing here ships in the wheel.
"""
