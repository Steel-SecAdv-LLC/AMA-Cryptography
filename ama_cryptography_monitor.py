#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
import sys

from ama_cryptography import monitoring as _monitor_module
from ama_cryptography.monitoring import (
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

sys.modules[__name__] = _monitor_module

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
