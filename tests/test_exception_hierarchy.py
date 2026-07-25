#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Tests for the unified AmaCryptographyError root of the exception hierarchy.

Every library error — including the module-specific ones defined outside
exceptions.py — must be catchable via a single ``except AmaCryptographyError``,
while classes that historically subclassed ``RuntimeError`` keep that ancestry
for backward compatibility.
"""

from __future__ import annotations

from ama_cryptography.exceptions import (
    AmaCryptographyError,
    AmaHSMUnavailableError,
    CryptoConfigError,
    CryptoModuleError,
    IntegrityError,
    KeyManagementError,
    PQCUnavailableError,
    QuantumSignatureRequiredError,
    QuantumSignatureUnavailableError,
    SecurityWarning,
    SignatureVerificationError,
)
from ama_cryptography.pqc_backends import KyberUnavailableError, SphincsUnavailableError
from ama_cryptography.rfc3161_timestamp import TimestampError, TimestampUnavailableError
from ama_cryptography.secure_channel import ChannelError
from ama_cryptography.secure_memory import SecureMemoryError
from ama_cryptography.session import SessionError

ALL_ERRORS = [
    PQCUnavailableError,
    QuantumSignatureUnavailableError,
    QuantumSignatureRequiredError,
    CryptoConfigError,
    KeyManagementError,
    SignatureVerificationError,
    IntegrityError,
    CryptoModuleError,
    AmaHSMUnavailableError,
    KyberUnavailableError,
    SphincsUnavailableError,
    TimestampError,
    TimestampUnavailableError,
    ChannelError,
    SecureMemoryError,
    SessionError,
]


def test_all_errors_under_root() -> None:
    for cls in ALL_ERRORS:
        assert issubclass(cls, AmaCryptographyError), f"{cls.__name__} not under root"


def test_runtimeerror_ancestry_preserved() -> None:
    # Backward compatibility: these were RuntimeError subclasses before the root
    # was introduced and must still be catchable as RuntimeError.
    for cls in (PQCUnavailableError, CryptoModuleError, AmaHSMUnavailableError):
        assert issubclass(cls, RuntimeError), f"{cls.__name__} lost RuntimeError"


def test_security_warning_is_not_an_error() -> None:
    # SecurityWarning is a warning, not an error — it must stay a UserWarning
    # and stay OUT of the error hierarchy.
    assert issubclass(SecurityWarning, UserWarning)
    assert not issubclass(SecurityWarning, AmaCryptographyError)


def test_catch_all_via_root() -> None:
    # Every library error must be catchable at runtime via a single
    # ``except AmaCryptographyError`` root (not merely a subclass relation).
    # A boolean flag set inside ``except`` and asserted afterwards keeps the
    # post-``try`` statement reachable via the catch path, so there is no
    # unreachable branch (CodeQL alerts #538/#539).
    for cls in ALL_ERRORS:
        caught = False
        try:
            raise cls("boom")
        except AmaCryptographyError:
            caught = True
        assert caught, f"{cls.__name__} not caught by AmaCryptographyError root"


def test_root_exported_at_top_level() -> None:
    import ama_cryptography

    assert ama_cryptography.AmaCryptographyError is AmaCryptographyError
    assert "AmaCryptographyError" in ama_cryptography.__all__
