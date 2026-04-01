#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Pytest Configuration and Shared Fixtures
=========================================

Centralized test fixtures for the AMA Cryptography test suite.
Provides reusable components for cryptographic testing.

This file consolidates fixtures from across the test suite to:
- Reduce code duplication
- Ensure consistent test setup
- Improve test maintainability
"""

from __future__ import annotations

import os
import secrets
import tempfile
from collections.abc import Generator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

# =============================================================================
# CI ENFORCEMENT: Crypto backend skip → failure in CI
# =============================================================================
# When AMA_CI_REQUIRE_BACKENDS=1 is set (by our ci.yml after building the
# C library), all cryptographic backends MUST be available. Tests that skip
# due to missing backends become hard failures. This env var is NOT set by
# other CI workflows that may not build the native library, so their
# legitimate skips are preserved.

_CI = os.environ.get("AMA_CI_REQUIRE_BACKENDS", "").lower() in ("true", "1", "yes")
_BACKEND_SKIP_REASONS = (
    "dilithium",
    "kyber",
    "sphincs",
    "backend",
    "native",
    "aes",
    "ed25519",
    "x25519",
    "argon2",
)


def _is_backend_skip(marker: Any) -> bool:
    """Check if a skipif marker is about a missing crypto backend."""
    reason = ""
    if hasattr(marker, "kwargs"):
        reason = marker.kwargs.get("reason", "")
    if hasattr(marker, "args") and len(marker.args) > 1 and not reason:
        reason = str(marker.args[1])
    return any(kw in reason.lower() for kw in _BACKEND_SKIP_REASONS)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: Any, call: Any) -> Any:
    """In CI, convert any backend-related skip into a hard failure."""
    outcome = yield
    if not _CI:
        return
    rep = outcome.get_result()
    if rep.skipped:
        for marker in item.iter_markers("skipif"):
            if _is_backend_skip(marker):
                reason = marker.kwargs.get("reason", "backend unavailable")
                rep.outcome = "failed"
                rep.longrepr = (
                    f"CI FAILURE: {reason} — "
                    "all cryptographic backends must be available in CI. "
                    "The C library must be built before running tests."
                )
                break


# =============================================================================
# TEMPORARY DIRECTORY FIXTURES
# =============================================================================


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provide a temporary directory that is cleaned up after the test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def temp_storage_path(temp_dir: Path) -> Path:
    """Provide a temporary path for key storage tests."""
    storage_path = temp_dir / "key_storage"
    storage_path.mkdir(parents=True, exist_ok=True)
    return storage_path


# =============================================================================
# KEY MANAGEMENT FIXTURES
# =============================================================================


@pytest.fixture
def master_seed() -> bytes:
    """Provide a deterministic master seed for reproducible HD key tests."""
    # Fixed seed for reproducible tests
    return bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f"
    )


@pytest.fixture
def random_seed() -> bytes:
    """Provide a random 64-byte seed for tests requiring entropy."""
    return secrets.token_bytes(64)


@pytest.fixture
def test_key_material() -> bytes:
    """Provide standard 32-byte key material for storage tests."""
    return b"test-key-material-32-bytes-long!"


@pytest.fixture
def test_password() -> str:
    """Provide a standard test password."""
    return "test-password-secure-123"  # nosec B105 — test-only fixture password, not used in production (TC-001)


# =============================================================================
# HD KEY DERIVATION FIXTURES
# =============================================================================


@pytest.fixture
def hd_derivation(master_seed: bytes) -> Any:
    """Provide an HDKeyDerivation instance with deterministic seed."""
    from ama_cryptography.key_management import HDKeyDerivation

    return HDKeyDerivation(seed=master_seed)


# =============================================================================
# KEY ROTATION FIXTURES
# =============================================================================


@pytest.fixture
def rotation_manager() -> Any:
    """Provide a KeyRotationManager with default settings."""
    from ama_cryptography.key_management import KeyRotationManager

    return KeyRotationManager()


@pytest.fixture
def rotation_manager_short_period() -> Any:
    """Provide a KeyRotationManager with very short rotation period."""
    from ama_cryptography.key_management import KeyRotationManager

    return KeyRotationManager(rotation_period=timedelta(seconds=0))


@pytest.fixture
def rotation_manager_long_period() -> Any:
    """Provide a KeyRotationManager with long rotation period."""
    from ama_cryptography.key_management import KeyRotationManager

    return KeyRotationManager(rotation_period=timedelta(days=365))


# =============================================================================
# SECURE STORAGE FIXTURES
# =============================================================================


@pytest.fixture
def secure_storage(temp_storage_path: Path, test_password: str) -> Any:
    """Provide a SecureKeyStorage instance with password-derived key."""
    from ama_cryptography.key_management import SecureKeyStorage

    return SecureKeyStorage(temp_storage_path, master_password=test_password)


# =============================================================================
# CRYPTOGRAPHIC API FIXTURES
# =============================================================================


# =============================================================================
# PQC BACKEND FIXTURES
# =============================================================================


@pytest.fixture
def pqc_backend_info() -> Any:
    """Provide current PQC backend availability info."""
    from ama_cryptography.pqc_backends import get_pqc_backend_info

    return get_pqc_backend_info()


@pytest.fixture
def dilithium_available() -> Any:
    """Check if Dilithium is available."""
    from ama_cryptography.pqc_backends import DILITHIUM_AVAILABLE

    return DILITHIUM_AVAILABLE


@pytest.fixture
def kyber_available() -> Any:
    """Check if Kyber is available."""
    from ama_cryptography.pqc_backends import KYBER_AVAILABLE

    return KYBER_AVAILABLE


@pytest.fixture
def sphincs_available() -> Any:
    """Check if SPHINCS+ is available."""
    from ama_cryptography.pqc_backends import SPHINCS_AVAILABLE

    return SPHINCS_AVAILABLE


# =============================================================================
# EQUATION ENGINE FIXTURES
# =============================================================================


@pytest.fixture
def equation_engine() -> Any:
    """Provide an AmaEquationEngine instance."""
    from ama_cryptography.double_helix_engine import AmaEquationEngine

    return AmaEquationEngine()


@pytest.fixture
def initial_state() -> Any:
    """Provide an initial state vector for equation tests."""
    from ama_cryptography._numeric import array

    return array([1.0, 0.5, 0.25, 0.125, 0.0625])


# =============================================================================
# MONITOR FIXTURES
# =============================================================================


# =============================================================================
# PYTEST CONFIGURATION
# =============================================================================


def pytest_configure(config: Any) -> None:
    """Configure custom pytest markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "quantum: marks tests that require quantum-resistant libraries"
    )
    config.addinivalue_line("markers", "integration: marks integration tests")
    config.addinivalue_line("markers", "security: marks security-related tests")
    config.addinivalue_line("markers", "performance: marks performance-related tests")
