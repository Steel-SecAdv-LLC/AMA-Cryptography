#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Tests for ama_cryptography.exceptions
======================================

Covers:
  - Every exception and warning class in the module
  - Inheritance hierarchy (correct base classes)
  - Raise/catch semantics
  - Message preservation
  - __all__ exports
"""

from __future__ import annotations

import warnings

import pytest

from ama_cryptography.exceptions import (
    CryptoConfigError,
    CryptoModuleError,
    IntegrityError,
    KeyManagementError,
    PQCUnavailableError,
    QuantumSignatureUnavailableError,
    SecurityWarning,
    SignatureVerificationError,
)

# ---------------------------------------------------------------------------
# Inheritance hierarchy
# ---------------------------------------------------------------------------


class TestInheritanceHierarchy:
    """Verify that each exception extends the correct base class."""

    def test_security_warning_is_user_warning(self) -> None:
        assert issubclass(SecurityWarning, UserWarning)
        assert issubclass(SecurityWarning, Warning)

    def test_pqc_unavailable_is_runtime_error(self) -> None:
        assert issubclass(PQCUnavailableError, RuntimeError)

    def test_quantum_signature_unavailable_extends_pqc(self) -> None:
        assert issubclass(QuantumSignatureUnavailableError, PQCUnavailableError)
        assert issubclass(QuantumSignatureUnavailableError, RuntimeError)

    def test_crypto_config_is_exception(self) -> None:
        assert issubclass(CryptoConfigError, Exception)

    def test_key_management_is_exception(self) -> None:
        assert issubclass(KeyManagementError, Exception)

    def test_signature_verification_is_exception(self) -> None:
        assert issubclass(SignatureVerificationError, Exception)

    def test_integrity_is_exception(self) -> None:
        assert issubclass(IntegrityError, Exception)

    def test_crypto_module_is_runtime_error(self) -> None:
        assert issubclass(CryptoModuleError, RuntimeError)


# ---------------------------------------------------------------------------
# Raise / catch semantics
# ---------------------------------------------------------------------------


class TestRaiseCatch:
    """Each exception can be raised, caught, and carries its message."""

    @pytest.mark.parametrize(
        "exc_cls",
        [
            PQCUnavailableError,
            QuantumSignatureUnavailableError,
            CryptoConfigError,
            KeyManagementError,
            SignatureVerificationError,
            IntegrityError,
            CryptoModuleError,
        ],
    )
    def test_raise_and_catch(self, exc_cls: type) -> None:
        msg = f"test message for {exc_cls.__name__}"
        with pytest.raises(exc_cls, match="test message"):
            raise exc_cls(msg)

    @pytest.mark.parametrize(
        "exc_cls",
        [
            PQCUnavailableError,
            QuantumSignatureUnavailableError,
            CryptoConfigError,
            KeyManagementError,
            SignatureVerificationError,
            IntegrityError,
            CryptoModuleError,
        ],
    )
    def test_message_preserved(self, exc_cls: type) -> None:
        msg = "precise error text"
        err = exc_cls(msg)
        assert str(err) == msg

    def test_quantum_sig_caught_by_pqc(self) -> None:
        """QuantumSignatureUnavailableError should be catchable as PQCUnavailableError."""
        with pytest.raises(PQCUnavailableError):
            raise QuantumSignatureUnavailableError("no native backend")

    def test_pqc_caught_by_runtime_error(self) -> None:
        """PQCUnavailableError should be catchable as RuntimeError."""
        with pytest.raises(RuntimeError):
            raise PQCUnavailableError("missing backend")

    def test_crypto_module_caught_by_runtime_error(self) -> None:
        with pytest.raises(RuntimeError):
            raise CryptoModuleError("FIPS error state")


# ---------------------------------------------------------------------------
# SecurityWarning
# ---------------------------------------------------------------------------


class TestSecurityWarning:
    """SecurityWarning must behave as a proper Warning subclass."""

    def test_warn_and_catch(self) -> None:
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            warnings.warn("non-constant-time op", SecurityWarning, stacklevel=1)
            assert len(w) == 1
            assert issubclass(w[0].category, SecurityWarning)
            assert "non-constant-time" in str(w[0].message)

    def test_filterable_as_user_warning(self) -> None:
        """SecurityWarning can be filtered via the UserWarning category."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always", UserWarning)
            warnings.warn("test", SecurityWarning, stacklevel=1)
            assert len(w) == 1


# ---------------------------------------------------------------------------
# Fail-closed semantics (no silent degradation)
# ---------------------------------------------------------------------------


class TestFailClosedSemantics:
    """Verify exceptions enforce fail-closed behaviour — no silent fallbacks."""

    def test_no_default_empty_constructor_hides_errors(self) -> None:
        """Every exception should carry a meaningful message in practice.
        Verify they at least accept a message and store it."""
        for cls in [
            PQCUnavailableError,
            QuantumSignatureUnavailableError,
            CryptoConfigError,
            KeyManagementError,
            SignatureVerificationError,
            IntegrityError,
            CryptoModuleError,
        ]:
            err = cls("detail here")
            assert len(str(err)) > 0

    def test_chained_exception_preserves_cause(self) -> None:
        """Exceptions raised with 'from' should preserve the cause chain."""
        original = ValueError("root cause")
        try:
            try:
                raise original
            except ValueError as e:
                raise CryptoConfigError("wrapper") from e
        except CryptoConfigError as exc:
            assert exc.__cause__ is original


# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------


class TestModuleExports:
    """Verify __all__ is complete and accurate."""

    def test_all_exports(self) -> None:
        from ama_cryptography import exceptions as mod

        expected = {
            "SecurityWarning",
            "PQCUnavailableError",
            "QuantumSignatureUnavailableError",
            "CryptoConfigError",
            "KeyManagementError",
            "SignatureVerificationError",
            "IntegrityError",
            "CryptoModuleError",
        }
        assert set(mod.__all__) == expected

    def test_all_exports_are_classes(self) -> None:
        from ama_cryptography import exceptions as mod

        for name in mod.__all__:
            obj = getattr(mod, name)
            assert isinstance(obj, type), f"{name} is not a class"
