#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""Canonical package-namespace entry point for the 3R Runtime Anomaly Monitor.

This module re-exports every public symbol from the historical top-level
``ama_cryptography_monitor`` module so that new code can write the
package-consistent import::

    from ama_cryptography.monitor import AmaCryptographyMonitor, create_monitor

while existing code that still writes::

    from ama_cryptography_monitor import AmaCryptographyMonitor

continues to work against the same module object. Every symbol exposed
here is ``is``-identical to the object bound to the same name on the
top-level module — no wrapper class is introduced, so ``isinstance()``
checks written against either path remain interchangeable.

The top-level file remains the source of truth for now so that the
declared ``py_modules=['ama_cryptography_monitor']`` packaging contract
and the pre-existing test suite that imports from the historical name
continue to work unchanged.
"""

from ama_cryptography_monitor import (
    AmaCryptographyMonitor,
    EWMAStats,
    ImportHijackViolation,
    IncrementalStats,
    IntegrityViolation,
    NonceTracker,
    PatternAnomaly,
    RecursionPatternMonitor,
    RefactoringAnalyzer,
    ResonanceTimingMonitor,
    TimingAnomaly,
    create_monitor,
    high_resolution_timer,
)

__all__ = [
    "AmaCryptographyMonitor",
    "EWMAStats",
    "ImportHijackViolation",
    "IncrementalStats",
    "IntegrityViolation",
    "NonceTracker",
    "PatternAnomaly",
    "RecursionPatternMonitor",
    "RefactoringAnalyzer",
    "ResonanceTimingMonitor",
    "TimingAnomaly",
    "create_monitor",
    "high_resolution_timer",
]
