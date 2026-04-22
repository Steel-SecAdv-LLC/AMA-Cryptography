#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""Tests for the ``ama_cryptography.monitor`` package-namespace shim.

``ama_cryptography_monitor`` is historically a top-level module.
``ama_cryptography.monitor`` is the package-consistent re-export. This
suite pins the contract that both paths resolve to the same underlying
classes / factory so no divergent code object slips in during a refactor.
"""

from __future__ import annotations


class TestMonitorShim:
    def test_shim_is_importable(self) -> None:
        """The package-internal path must import without side-effect errors."""
        import importlib

        shim = importlib.import_module("ama_cryptography.monitor")
        assert shim is not None
        # __all__ must list at least the three headline symbols so
        # `from ama_cryptography.monitor import *` stays useful.
        for required in ("AmaCryptographyMonitor", "create_monitor", "TimingAnomaly"):
            assert required in shim.__all__, (
                f"{required!r} missing from ama_cryptography.monitor.__all__"
            )

    def test_shim_re_exports_are_identical(self) -> None:
        """Each symbol exported by the shim must be ``is``-identical to the
        object bound to the same name in the top-level module.

        ``is`` equality (not just ``==``) is required — otherwise
        ``isinstance`` checks written against one path would fail for
        objects created via the other path, silently diverging
        downstream consumers.
        """
        import ama_cryptography.monitor as shim
        import ama_cryptography_monitor as source

        for name in shim.__all__:
            assert hasattr(source, name), (
                f"{name} missing from top-level ama_cryptography_monitor"
            )
            assert getattr(shim, name) is getattr(source, name), (
                f"{name} diverges between ama_cryptography.monitor "
                f"and ama_cryptography_monitor"
            )

    def test_create_monitor_returns_expected_type(self) -> None:
        """The factory re-exported via the shim produces the shared class."""
        from ama_cryptography.monitor import AmaCryptographyMonitor, create_monitor

        monitor = create_monitor(enabled=False)
        assert isinstance(monitor, AmaCryptographyMonitor)

    def test_crypto_api_uses_package_path(self) -> None:
        """crypto_api imports the shim's class object (audit 2e migration).

        This guards against a revert that would re-point crypto_api at
        the top-level module under a different object identity — doing
        so would silently resurrect the namespace-inconsistency issue
        flagged by the audit.  Because the shim re-exports the same
        object, ``crypto_api.AmaCryptographyMonitor`` must equal
        ``ama_cryptography.monitor.AmaCryptographyMonitor`` by ``is``.
        """
        import ama_cryptography.crypto_api as api
        from ama_cryptography.monitor import AmaCryptographyMonitor as ShimMonitor

        assert api.AmaCryptographyMonitor is ShimMonitor
