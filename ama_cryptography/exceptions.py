#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
AMA Cryptography Exception Classes
=================================

Centralized exception and warning classes for the AMA Cryptography package.
All modules should import exceptions from this module to ensure consistency.

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Date: 2026-04-06
Version: 2.1.2
"""


class SecurityWarning(UserWarning):
    """
    Warning for security-related issues in cryptographic configurations.

    Used to alert users about potentially unsafe or suboptimal security
    configurations without raising an exception. Examples include:
    - Using non-constant-time implementations
    - Legacy encryption formats
    - Missing recommended security features
    """

    pass


class PQCUnavailableError(RuntimeError):
    """
    Raised when post-quantum cryptography is required but unavailable.

    This exception indicates that a PQC operation was requested but the
    native C backend is not available.

    Inherits from RuntimeError to maintain backward compatibility with
    existing tests and code that expects this exception hierarchy.

    To resolve, build the native C library:
        cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build
    """

    pass


class QuantumSignatureUnavailableError(PQCUnavailableError):
    """
    Raised when quantum-resistant signature operations are requested but
    the native C backend is not available.

    This exception ensures fail-closed behavior for quantum signatures,
    preventing the system from silently degrading to insecure placeholders.

    Inherits from PQCUnavailableError for catch-all handling.
    """

    pass


class QuantumSignatureRequiredError(Exception):
    """Raised when quantum-resistant signatures are required by policy but
    Dilithium is not available or the package lacks quantum signatures."""

    pass


class CryptoConfigError(Exception):
    """
    Raised when cryptographic configuration is invalid.

    This includes invalid algorithm selections, incompatible parameters,
    or missing required configuration values.
    """

    pass


class KeyManagementError(Exception):
    """
    Base exception for key management operations.

    Raised for errors in key derivation, rotation, storage, or retrieval.
    """

    pass


class SignatureVerificationError(Exception):
    """
    Raised when signature verification fails.

    This indicates the signature is invalid, the data was tampered with,
    or the wrong public key was used for verification.
    """

    pass


class IntegrityError(Exception):
    """
    Raised when data integrity verification fails.

    This includes HMAC verification failures, hash mismatches, or
    other integrity check failures.
    """

    pass


class CryptoModuleError(RuntimeError):
    """
    Raised when the cryptographic module is in a FIPS 140-3 error state.

    All cryptographic operations are refused until the module is reset
    via reset_module().
    """

    pass


__all__ = [
    "SecurityWarning",
    "PQCUnavailableError",
    "QuantumSignatureUnavailableError",
    "QuantumSignatureRequiredError",
    "CryptoConfigError",
    "KeyManagementError",
    "SignatureVerificationError",
    "IntegrityError",
    "CryptoModuleError",
]
