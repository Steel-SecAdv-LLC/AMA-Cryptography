#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Canonical package-namespace entry point for the 3R Runtime Anomaly Monitor.

This module re-exports every public symbol from the historical top-level
``ama_cryptography_monitor`` module so that new code can write the
package-consistent import::

    from ama_cryptography.monitor import AmaCryptographyMonitor, create_monitor

while existing code that still writes::

    from ama_cryptography_monitor import AmaCryptographyMonitor

continues to work against the same module object.  See audit 2e
(``INVARIANTS.md`` / the v2.1.5 scaffolding review) for the migration plan
toward a single in-package source of truth.

The top-level file remains the source of truth for now so that we do not
break the declared ``py_modules=['ama_cryptography_monitor']`` packaging
contract and the many tests that still import from the historical name.
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
