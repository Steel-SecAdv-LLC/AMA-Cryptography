#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Package-namespace alias for the 3R Runtime Anomaly Monitor.

The implementation lives in ``ama_cryptography.monitoring``.  Both this
module and the historical top-level ``ama_cryptography_monitor`` module are
aliases of it: this one re-exports its public symbols so new code can write
the package-consistent import::

    from ama_cryptography.monitor import AmaCryptographyMonitor, create_monitor

while existing code that still writes::

    from ama_cryptography_monitor import AmaCryptographyMonitor

continues to work against the same module object (the top-level shim
delegates here via ``sys.modules``, and this module registers the
historical name below).  Both aliases are kept for the declared
``py_modules=['ama_cryptography_monitor']`` packaging contract and the
tests that still import from the historical name.
"""

import sys

from ama_cryptography import monitoring as _monitor_module
from ama_cryptography.monitoring import (
    AmaCryptographyMonitor,
    EWMAStats,
    ImportHijackViolation,
    IncrementalStats,
    IntegrityViolation,
    NonceTracker,
    NoteArtifactDetector,
    NoteArtifactSignal,
    PatternAnomaly,
    RecursionPatternMonitor,
    RefactoringAnalyzer,
    ResonanceTimingMonitor,
    TimingAnomaly,
    VolumeSpike,
    VolumeSpikeDetector,
    create_monitor,
    high_resolution_timer,
)

sys.modules.setdefault("ama_cryptography_monitor", _monitor_module)

__all__ = [
    "AmaCryptographyMonitor",
    "EWMAStats",
    "ImportHijackViolation",
    "IncrementalStats",
    "IntegrityViolation",
    "NonceTracker",
    "NoteArtifactDetector",
    "NoteArtifactSignal",
    "PatternAnomaly",
    "RecursionPatternMonitor",
    "RefactoringAnalyzer",
    "ResonanceTimingMonitor",
    "TimingAnomaly",
    "VolumeSpike",
    "VolumeSpikeDetector",
    "create_monitor",
    "high_resolution_timer",
]
