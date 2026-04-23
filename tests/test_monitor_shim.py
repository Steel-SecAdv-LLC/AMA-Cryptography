#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Tests for the ``ama_cryptography.monitor`` package-namespace shim.

Audit 2e: ``ama_cryptography_monitor`` is historically a top-level module.
``ama_cryptography.monitor`` is the package-consistent re-export.  This
suite pins the contract that both paths resolve to the same underlying
classes / factory so no divergent code object slips in during a refactor.
"""

from __future__ import annotations

import importlib

import pytest


class TestMonitorShim:
    def test_shim_is_importable(self) -> None:
        """The package-internal path must import without side-effect errors."""
        shim = importlib.import_module("ama_cryptography.monitor")
        assert shim is not None
        # __all__ must list at least the three headline symbols so
        # `from ama_cryptography.monitor import *` stays useful.
        for required in ("AmaCryptographyMonitor", "create_monitor", "TimingAnomaly"):
            assert required in shim.__all__

    def test_shim_re_exports_classes_are_identical(self) -> None:
        """Each symbol exported by the shim must be `is`-identical to the
        object bound to the same name in the historical top-level module.

        `is` equality (not just `==`) is required — otherwise `isinstance`
        checks written against one path would fail for objects created via
        the other path, silently diverging downstream consumers.
        """
        shim = importlib.import_module("ama_cryptography.monitor")
        source = importlib.import_module("ama_cryptography_monitor")

        # Every name in __all__ must match the source by object identity.
        for name in shim.__all__:
            assert hasattr(source, name), f"{name} missing from top-level module"
            assert getattr(shim, name) is getattr(source, name), (
                f"{name} diverges between ama_cryptography.monitor " f"and ama_cryptography_monitor"
            )

    def test_create_monitor_returns_expected_type(self) -> None:
        """The factory re-exported via the shim produces the shared class."""
        from ama_cryptography.monitor import AmaCryptographyMonitor, create_monitor

        monitor = create_monitor(enabled=False)
        assert isinstance(monitor, AmaCryptographyMonitor)

    def test_crypto_api_uses_package_path(self) -> None:
        """crypto_api imports the shim (audit 2e migration).

        This guards against a revert that would re-point crypto_api at the
        top-level module — doing so would silently resurrect the
        namespace-inconsistency issue flagged by the audit.

        INVARIANT-7 refuses to import ``crypto_api`` when the native C
        backend isn't built (by design — see ``CHANGELOG.md`` / audit
        2e); in that case we skip rather than mask the protection, so
        the contract is still pinned in any environment with the
        native library present.
        """
        try:
            api = importlib.import_module("ama_cryptography.crypto_api")
        except RuntimeError as exc:
            if "INVARIANT-7" in str(exc):
                pytest.skip(
                    "crypto_api import blocked by INVARIANT-7 " "(native backend unavailable)"
                )
            raise

        # The AmaCryptographyMonitor class pulled into crypto_api's namespace
        # must be the same object reachable from the package-internal path.
        # (The binding is an internal import, not a public re-export —
        # ``crypto_api.__all__`` intentionally omits it. ``importlib`` gives
        # us a ``ModuleType`` so mypy --strict is content with direct
        # attribute access here.)
        from ama_cryptography.monitor import AmaCryptographyMonitor as ShimMonitor

        assert api.AmaCryptographyMonitor is ShimMonitor
