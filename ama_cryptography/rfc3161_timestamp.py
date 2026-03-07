#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
RFC 3161 Timestamp Protocol Implementation
===========================================

Provides Time-Stamp Protocol (TSP) client for obtaining cryptographic timestamps
from RFC 3161 compliant Time-Stamp Authorities (TSAs).

Standard: RFC 3161 - Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)
Reference: https://www.rfc-editor.org/rfc/rfc3161

Security Properties:
--------------------
1. Non-repudiation: Proves data existed at a specific time
2. Third-party attestation: Independent verification by TSA
3. Cryptographic binding: Timestamp is cryptographically bound to data hash
4. Long-term validity: Uses long-term signature algorithms (e.g., SPHINCS+)

Use Cases:
----------
- Legal documents requiring proof of existence
- Code signing with verifiable creation time
- Audit logs with tamper-evident timestamps
- Long-term archival with time attestation
"""

import hashlib
import warnings
from dataclasses import dataclass
from typing import Optional

# Try to import rfc3161ng for RFC 3161 timestamp support
try:
    from rfc3161ng import RemoteTimestamper

    RFC3161_AVAILABLE = True
except ImportError:
    RFC3161_AVAILABLE = False
    RemoteTimestamper = None


class TimestampUnavailableError(Exception):
    """Raised when RFC 3161 timestamping is requested but not available."""

    pass


class TimestampError(Exception):
    """Raised when timestamp request fails."""

    pass


@dataclass
class TimestampResult:
    """
    Result from get_timestamp() containing the timestamp token.

    Attributes:
        token: RFC 3161 timestamp token (ASN.1 DER encoded)
        tsa_url: URL of the Time-Stamp Authority used
        hash_algorithm: Hash algorithm used (e.g., 'sha256', 'sha3-256')
        data_hash: Hash of the timestamped data
    """

    token: bytes
    tsa_url: str
    hash_algorithm: str
    data_hash: bytes


def get_timestamp(
    data: bytes,
    tsa_url: Optional[str] = None,
    hash_algorithm: str = "sha3-256",
    certificate_file: Optional[str] = None,
) -> TimestampResult:
    """
    Obtain RFC 3161 timestamp for data from a Time-Stamp Authority.

    Process:
    --------
    1. Compute hash of data using specified algorithm
    2. Create RFC 3161 TimeStampReq with hash
    3. Send request to TSA server via HTTP POST
    4. Receive and validate TimeStampResp
    5. Extract timestamp token from response

    Args:
        data: Data to timestamp (will be hashed)
        tsa_url: URL of RFC 3161 Time-Stamp Authority
                 Default: FreeTSA.org public service
        hash_algorithm: Hash algorithm to use ('sha256', 'sha3-256', 'sha512')
                       Default: 'sha3-256' (consistent with AMA Cryptography)
        certificate_file: Optional path to TSA certificate for verification

    Returns:
        TimestampResult with timestamp token and metadata

    Raises:
        TimestampUnavailableError: If rfc3161ng library not installed
        TimestampError: If timestamp request fails
        ValueError: If hash_algorithm is not supported

    Example:
        >>> result = get_timestamp(b"Important document")
        >>> print(f"Timestamp token: {len(result.token)} bytes")
        >>> # Save token for later verification
        >>> with open("document.tsr", "wb") as f:
        ...     f.write(result.token)

    Public TSA Services:
    --------------------
    - FreeTSA: http://freetsa.org/tsr (free, no registration)
    - DigiCert: http://timestamp.digicert.com (free, no registration)
    - GlobalSign: http://timestamp.globalsign.com/tsa/tsa (free)

    Note: For production use, consider running your own TSA server or
          using a commercial service with SLA guarantees.
    """
    if not RFC3161_AVAILABLE:
        raise TimestampUnavailableError(
            "RFC3161_UNAVAILABLE: rfc3161ng library not installed. "
            "Install with: pip install rfc3161ng"
        )

    # Use FreeTSA as default public TSA
    if tsa_url is None:
        tsa_url = "http://freetsa.org/tsr"
        warnings.warn(
            f"No TSA URL specified, using public service: {tsa_url}. "
            "For production use, specify a reliable TSA server.",
            category=UserWarning,
        )

    # Compute hash based on specified algorithm
    if hash_algorithm == "sha256":
        data_hash = hashlib.sha256(data).digest()
    elif hash_algorithm == "sha3-256":
        data_hash = hashlib.sha3_256(data).digest()
    elif hash_algorithm == "sha512":
        data_hash = hashlib.sha512(data).digest()
    elif hash_algorithm == "sha3-512":
        data_hash = hashlib.sha3_512(data).digest()
    else:
        raise ValueError(
            f"Unsupported hash algorithm: {hash_algorithm}. "
            "Supported: sha256, sha3-256, sha512, sha3-512"
        )

    # Create timestamper and request timestamp
    try:
        timestamper = RemoteTimestamper(
            tsa_url,
            certificate=certificate_file,
            hashname=hash_algorithm.replace("-", ""),  # 'sha3256' format
        )

        # Request timestamp token
        timestamp_token = timestamper(data=data)

        if timestamp_token is None:
            raise TimestampError(
                f"Failed to obtain timestamp from {tsa_url}. "
                "TSA server may be unavailable or rejected the request."
            )

        return TimestampResult(
            token=timestamp_token,
            tsa_url=tsa_url,
            hash_algorithm=hash_algorithm,
            data_hash=data_hash,
        )

    except Exception as e:
        if isinstance(e, (TimestampUnavailableError, TimestampError, ValueError)):
            raise
        raise TimestampError(f"Timestamp request failed: {str(e)}") from e


def verify_timestamp(
    data: bytes,
    timestamp_result: TimestampResult,
    certificate_file: Optional[str] = None,
) -> bool:
    """
    Verify RFC 3161 timestamp token against data.

    Verification Process:
    ---------------------
    1. Recompute hash of data using specified algorithm
    2. Parse timestamp token (ASN.1 DER)
    3. Verify timestamp signature
    4. Check hash in token matches computed hash
    5. Validate TSA certificate chain (if certificate_file provided)

    Args:
        data: Original data that was timestamped
        timestamp_result: TimestampResult from get_timestamp()
        certificate_file: Optional path to TSA certificate for chain validation

    Returns:
        True if timestamp is valid, False otherwise

    Example:
        >>> # Load timestamp from file
        >>> with open("document.tsr", "rb") as f:
        ...     token = f.read()
        >>> result = TimestampResult(
        ...     token=token,
        ...     tsa_url="http://freetsa.org/tsr",
        ...     hash_algorithm='sha3-256',
        ...     data_hash=b'...'
        ... )
        >>> is_valid = verify_timestamp(b"Important document", result)
        >>> print(f"Timestamp valid: {is_valid}")
    """
    if not RFC3161_AVAILABLE:
        raise TimestampUnavailableError(
            "RFC3161_UNAVAILABLE: rfc3161ng library not installed. "
            "Install with: pip install rfc3161ng"
        )

    try:
        # Recompute hash
        if timestamp_result.hash_algorithm == "sha256":
            computed_hash = hashlib.sha256(data).digest()
        elif timestamp_result.hash_algorithm == "sha3-256":
            computed_hash = hashlib.sha3_256(data).digest()
        elif timestamp_result.hash_algorithm == "sha512":
            computed_hash = hashlib.sha512(data).digest()
        elif timestamp_result.hash_algorithm == "sha3-512":
            computed_hash = hashlib.sha3_512(data).digest()
        else:
            return False

        # Verify hash matches
        if computed_hash != timestamp_result.data_hash:
            return False

        # Create timestamper for verification
        timestamper = RemoteTimestamper(
            timestamp_result.tsa_url,
            certificate=certificate_file,
            hashname=timestamp_result.hash_algorithm.replace("-", ""),
        )

        # Verify timestamp token
        # Note: rfc3161ng's check() method validates the token structure
        is_valid = timestamper.check(
            timestamp_result.token,
            data=data,
        )

        return bool(is_valid)

    except Exception:
        return False


# Public API
__all__ = [
    "get_timestamp",
    "verify_timestamp",
    "TimestampResult",
    "TimestampUnavailableError",
    "TimestampError",
    "RFC3161_AVAILABLE",
]
