#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography Exception Classes
==================================

Centralized exception and warning classes for the AMA Cryptography package.
All modules should import exceptions from this module to ensure consistency.

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Date: 2026-04-17
Version: 5.0.0
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


class AmaCryptographyError(Exception):
    """
    Root of the AMA Cryptography exception hierarchy.

    Every error raised by the library derives (directly or transitively) from
    this class, so a single ``except AmaCryptographyError`` catches all of
    them — including the module-specific errors (TimestampError, SessionError,
    ChannelError, SecureMemoryError) defined outside this module.

    ``SecurityWarning`` is intentionally NOT a subclass: it is a ``UserWarning``,
    not an error.  Classes that historically subclass ``RuntimeError`` (e.g.
    ``PQCUnavailableError``, ``CryptoModuleError``) additionally inherit from
    ``RuntimeError`` so existing ``except RuntimeError`` sites keep working.
    """

    pass


class NativeBackendUnavailableError(AmaCryptographyError, RuntimeError):
    """
    Raised when an operation needs the native C backend and it is not present.

    This is INVARIANT-7's failure mode expressed as a type: the library refuses
    to operate rather than substituting anything. It is not specific to
    post-quantum work — the NIST prime curves, secp256k1 and the classical
    primitives raise it for the same reason.

    ``PQCUnavailableError`` is a subclass, so existing ``except
    PQCUnavailableError`` sites keep working and ``except RuntimeError``
    continues to catch every case. Catch this class when the question is
    "is the native library present", and the subclass when the answer needs
    to distinguish which family was asked for.

    To resolve, build the native C library:
        cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build
    """

    pass


class PQCUnavailableError(NativeBackendUnavailableError):
    """
    Raised when post-quantum cryptography is required but unavailable.

    This exception indicates that a PQC operation was requested but the
    native C backend is not available.

    Inherits from NativeBackendUnavailableError (and transitively from
    AmaCryptographyError and RuntimeError), so every pre-existing handler
    shape keeps working unchanged.

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


class QuantumSignatureRequiredError(AmaCryptographyError):
    """Raised when quantum-resistant signatures are required by policy but
    Dilithium is not available or the package lacks quantum signatures."""

    pass


class CryptoConfigError(AmaCryptographyError):
    """
    Raised when cryptographic configuration is invalid.

    This includes invalid algorithm selections, incompatible parameters,
    or missing required configuration values.
    """

    pass


class KeyManagementError(AmaCryptographyError):
    """
    Base exception for key management operations.

    Raised for errors in key derivation, rotation, storage, or retrieval.
    """

    pass


class SignatureVerificationError(AmaCryptographyError):
    """
    Raised when signature verification fails.

    This indicates the signature is invalid, the data was tampered with,
    or the wrong public key was used for verification.
    """

    pass


class IntegrityError(AmaCryptographyError):
    """
    Raised when data integrity verification fails.

    This includes HMAC verification failures, hash mismatches, or
    other integrity check failures.
    """

    pass


class CryptoModuleError(AmaCryptographyError, RuntimeError):
    """
    Raised when the cryptographic module is in a FIPS 140-3 error state.

    All cryptographic operations are refused until the module is reset
    via reset_module().
    """

    pass


class KeyFormatError(AmaCryptographyError, ValueError):
    """
    Raised when an interoperability key encoding cannot be parsed or produced.

    Covers PKCS#8, SPKI, PEM, JWK and COSE_Key handling in
    ``ama_cryptography.key_formats``: malformed or non-minimal DER,
    non-deterministic CBOR, a truncated or over-long key, a structure whose
    declared algorithm does not match its contents, a JWK whose ``crv`` and
    coordinate widths disagree, and so on.

    Inherits from ``ValueError`` as well as the AMA root because a bad encoding
    *is* a bad value, and callers parsing untrusted key material routinely
    already guard with ``except ValueError``. A parse failure must never be
    absorbed: it means the caller does not have the key it thinks it has.
    """

    pass


class UnsupportedKeyFormatError(KeyFormatError):
    """
    Raised when an encoding is well-formed but names an algorithm, curve or
    representation this library deliberately does not implement.

    Distinct from ``KeyFormatError`` on purpose. "I cannot parse this" and "I
    parsed this and will not pretend to support it" are different facts, and
    conflating them is how a library ends up quietly emitting a non-standard
    encoding for an algorithm whose standard is unfinished — which is exactly
    why ML-DSA and ML-KEM raise this for JWK and COSE. See the limitations
    table in ``ama_cryptography.key_formats``.
    """

    pass


class AmaHSMUnavailableError(AmaCryptographyError, RuntimeError):
    """Raised when an HSM operation is requested but PyKCS11 is not installed.

    PyKCS11 is an optional dependency for hardware security module support.
    Install it with: pip install ama-cryptography[hsm]

    Note: This exception class lives in ``ama_cryptography.exceptions`` so
    that it is always importable, even in environments where the native C
    library or PyKCS11 is absent.
    """

    pass


__all__ = [
    "AmaCryptographyError",
    "SecurityWarning",
    "NativeBackendUnavailableError",
    "PQCUnavailableError",
    "QuantumSignatureUnavailableError",
    "QuantumSignatureRequiredError",
    "CryptoConfigError",
    "KeyManagementError",
    "SignatureVerificationError",
    "IntegrityError",
    "CryptoModuleError",
    "KeyFormatError",
    "UnsupportedKeyFormatError",
    "AmaHSMUnavailableError",
]
