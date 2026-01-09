#!/usr/bin/env python3
# Copyright 2025 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Pytest Configuration and Shared Fixtures
=========================================

Centralized test fixtures for the Ava Guardian ♱ test suite.
Provides reusable components for cryptographic testing.

This file consolidates fixtures from across the test suite to:
- Reduce code duplication
- Ensure consistent test setup
- Improve test maintainability
"""

import secrets
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import Generator, Tuple

import pytest

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
    return "test-password-secure-123"  # nosec B105


# =============================================================================
# HD KEY DERIVATION FIXTURES
# =============================================================================


@pytest.fixture
def hd_derivation(master_seed: bytes):
    """Provide an HDKeyDerivation instance with deterministic seed."""
    from ava_guardian.key_management import HDKeyDerivation

    return HDKeyDerivation(seed=master_seed)


@pytest.fixture
def hd_derivation_random():
    """Provide an HDKeyDerivation instance with random seed."""
    from ava_guardian.key_management import HDKeyDerivation

    return HDKeyDerivation()


# =============================================================================
# KEY ROTATION FIXTURES
# =============================================================================


@pytest.fixture
def rotation_manager():
    """Provide a KeyRotationManager with default settings."""
    from ava_guardian.key_management import KeyRotationManager

    return KeyRotationManager()


@pytest.fixture
def rotation_manager_short_period():
    """Provide a KeyRotationManager with very short rotation period."""
    from ava_guardian.key_management import KeyRotationManager

    return KeyRotationManager(rotation_period=timedelta(seconds=0))


@pytest.fixture
def rotation_manager_long_period():
    """Provide a KeyRotationManager with long rotation period."""
    from ava_guardian.key_management import KeyRotationManager

    return KeyRotationManager(rotation_period=timedelta(days=365))


# =============================================================================
# SECURE STORAGE FIXTURES
# =============================================================================


@pytest.fixture
def secure_storage(temp_storage_path: Path, test_password: str):
    """Provide a SecureKeyStorage instance with password-derived key."""
    from ava_guardian.key_management import SecureKeyStorage

    return SecureKeyStorage(temp_storage_path, master_password=test_password)


@pytest.fixture
def secure_storage_no_password(temp_storage_path: Path):
    """Provide a SecureKeyStorage instance with random encryption key."""
    from ava_guardian.key_management import SecureKeyStorage

    return SecureKeyStorage(temp_storage_path)


# =============================================================================
# CRYPTOGRAPHIC API FIXTURES
# =============================================================================


@pytest.fixture
def crypto_ed25519():
    """Provide an AvaGuardianCrypto instance for Ed25519."""
    from ava_guardian.crypto_api import AlgorithmType, AvaGuardianCrypto

    return AvaGuardianCrypto(algorithm=AlgorithmType.ED25519)


@pytest.fixture
def crypto_hybrid():
    """Provide an AvaGuardianCrypto instance for hybrid signatures."""
    from ava_guardian.crypto_api import AlgorithmType, AvaGuardianCrypto

    return AvaGuardianCrypto(algorithm=AlgorithmType.HYBRID_SIG)


@pytest.fixture
def ed25519_keypair(crypto_ed25519) -> Tuple[bytes, bytes]:
    """Generate and return an Ed25519 keypair (public_key, secret_key)."""
    keypair = crypto_ed25519.generate_keypair()
    return keypair.public_key, keypair.secret_key


@pytest.fixture
def test_message() -> bytes:
    """Provide a standard test message for signature tests."""
    return b"Test message for Ava Guardian cryptographic operations."


@pytest.fixture
def test_message_large() -> bytes:
    """Provide a large test message for performance-related tests."""
    return secrets.token_bytes(1024 * 100)  # 100 KB


# =============================================================================
# PQC BACKEND FIXTURES
# =============================================================================


@pytest.fixture
def pqc_backend_info():
    """Provide current PQC backend availability info."""
    from ava_guardian.pqc_backends import get_pqc_backend_info

    return get_pqc_backend_info()


@pytest.fixture
def dilithium_available():
    """Check if Dilithium is available."""
    from ava_guardian.pqc_backends import DILITHIUM_AVAILABLE

    return DILITHIUM_AVAILABLE


@pytest.fixture
def kyber_available():
    """Check if Kyber is available."""
    from ava_guardian.pqc_backends import KYBER_AVAILABLE

    return KYBER_AVAILABLE


@pytest.fixture
def sphincs_available():
    """Check if SPHINCS+ is available."""
    from ava_guardian.pqc_backends import SPHINCS_AVAILABLE

    return SPHINCS_AVAILABLE


# =============================================================================
# EQUATION ENGINE FIXTURES
# =============================================================================


@pytest.fixture
def equation_engine():
    """Provide an AvaEquationEngine instance."""
    from ava_guardian.double_helix_engine import AvaEquationEngine

    return AvaEquationEngine()


@pytest.fixture
def initial_state():
    """Provide an initial state vector for equation tests."""
    import numpy as np

    return np.array([1.0, 0.5, 0.25, 0.125, 0.0625])


# =============================================================================
# MONITOR FIXTURES
# =============================================================================


@pytest.fixture
def guardian_monitor():
    """Provide an AvaGuardianMonitor instance."""
    try:
        from ava_guardian_monitor import AvaGuardianMonitor

        return AvaGuardianMonitor(enabled=True)
    except ImportError:
        pytest.skip("ava_guardian_monitor not available")


@pytest.fixture
def guardian_monitor_disabled():
    """Provide a disabled AvaGuardianMonitor instance."""
    try:
        from ava_guardian_monitor import AvaGuardianMonitor

        return AvaGuardianMonitor(enabled=False)
    except ImportError:
        pytest.skip("ava_guardian_monitor not available")


# =============================================================================
# TEST DATA FIXTURES
# =============================================================================


@pytest.fixture
def sample_omni_code() -> dict:
    """Provide a sample Omni-Code structure for package tests."""
    return {
        "sequence_id": "test-sequence-001",
        "data": {
            "type": "test",
            "content": "Sample Omni-Code for testing",
            "metadata": {
                "created_by": "test_suite",
                "version": "1.1",
            },
        },
    }


@pytest.fixture
def binary_data_small() -> bytes:
    """Provide small binary data for quick tests."""
    return secrets.token_bytes(32)


@pytest.fixture
def binary_data_medium() -> bytes:
    """Provide medium binary data for standard tests."""
    return secrets.token_bytes(1024)


@pytest.fixture
def binary_data_large() -> bytes:
    """Provide large binary data for stress tests."""
    return secrets.token_bytes(1024 * 1024)  # 1 MB


# =============================================================================
# SKIP MARKERS
# =============================================================================


@pytest.fixture
def skip_if_no_pqc(pqc_backend_info):
    """Skip test if no PQC backend is available."""
    if pqc_backend_info["status"] == "UNAVAILABLE":
        pytest.skip("No PQC backend available")


@pytest.fixture
def skip_if_no_dilithium(dilithium_available):
    """Skip test if Dilithium is not available."""
    if not dilithium_available:
        pytest.skip("Dilithium backend not available")


@pytest.fixture
def skip_if_no_kyber(kyber_available):
    """Skip test if Kyber is not available."""
    if not kyber_available:
        pytest.skip("Kyber backend not available")


@pytest.fixture
def skip_if_no_sphincs(sphincs_available):
    """Skip test if SPHINCS+ is not available."""
    if not sphincs_available:
        pytest.skip("SPHINCS+ backend not available")


# =============================================================================
# PYTEST CONFIGURATION
# =============================================================================


def pytest_configure(config):
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
