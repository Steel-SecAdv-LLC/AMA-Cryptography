#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

import sys
from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tools.monitoring.ama_cryptography_monitor import (
        AmaCryptographyMonitor as AmaCryptographyMonitor,
    )
    from tools.monitoring.ama_cryptography_monitor import (
        EWMAStats as EWMAStats,
    )
    from tools.monitoring.ama_cryptography_monitor import (
        ImportHijackViolation as ImportHijackViolation,
    )
    from tools.monitoring.ama_cryptography_monitor import (
        IncrementalStats as IncrementalStats,
    )
    from tools.monitoring.ama_cryptography_monitor import (
        IntegrityViolation as IntegrityViolation,
    )
    from tools.monitoring.ama_cryptography_monitor import (
        NonceTracker as NonceTracker,
    )
    from tools.monitoring.ama_cryptography_monitor import (
        PatternAnomaly as PatternAnomaly,
    )
    from tools.monitoring.ama_cryptography_monitor import (
        RecursionPatternMonitor as RecursionPatternMonitor,
    )
    from tools.monitoring.ama_cryptography_monitor import (
        RefactoringAnalyzer as RefactoringAnalyzer,
    )
    from tools.monitoring.ama_cryptography_monitor import (
        ResonanceTimingMonitor as ResonanceTimingMonitor,
    )
    from tools.monitoring.ama_cryptography_monitor import (
        TimingAnomaly as TimingAnomaly,
    )
    from tools.monitoring.ama_cryptography_monitor import (
        create_monitor as create_monitor,
    )
    from tools.monitoring.ama_cryptography_monitor import (
        high_resolution_timer as high_resolution_timer,
    )
else:
    _monitor_module = import_module("tools.monitoring.ama_cryptography_monitor")
    sys.modules[__name__] = _monitor_module
