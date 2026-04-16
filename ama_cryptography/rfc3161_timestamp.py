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
import logging
import os as _os_mod
import struct
import threading
import time
import warnings
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Dict, Generator, Optional

_logger = logging.getLogger(__name__)

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
        token: RFC 3161 timestamp token (ASN.1 DER encoded, or mock token bytes)
        tsa_url: URL of the Time-Stamp Authority used (or "mock" / "disabled")
        hash_algorithm: Hash algorithm used (e.g., 'sha256', 'sha3-256')
        data_hash: Hash of the timestamped data
    """

    token: bytes
    tsa_url: str
    hash_algorithm: str
    data_hash: bytes


# ---------------------------------------------------------------------------
# Mock TSA for offline / testing use
# ---------------------------------------------------------------------------

# 16-byte magic header that identifies a mock timestamp token.
_MOCK_MAGIC = b"AMA_MOCK_TSA\x00\x01\x00\x00"


# S3 fix: Guard flag — MockTSA is only available in testing contexts.
# Set this to True in test fixtures / conftest.py before using MockTSA.
# Thread-local storage so concurrent threads don't leak the allowed state.
_MOCK_TSA_ALLOWED: bool = False
_MOCK_TSA_LOCK = threading.Lock()
_mock_tsa_local = threading.local()


@contextmanager
def allow_mock_tsa() -> Generator[None, None, None]:
    """Context manager that enables MockTSA for the calling thread.

    SECURITY FIX (audit finding C8): Replaces bare try/finally flag
    manipulation with a context manager that guarantees atomic
    enable/disable semantics.  The thread-local flag is set on entry
    and unconditionally cleared on exit, eliminating the TOCTOU race
    where a concurrent finalizer or signal handler could observe the
    flag in an inconsistent state.

    Usage::

        with allow_mock_tsa():
            token = MockTSA.timestamp(data_hash, "sha256")
            assert MockTSA.verify(token, data_hash)
    """
    previous = getattr(_mock_tsa_local, "allowed", False)
    _mock_tsa_local.allowed = True
    try:
        yield
    finally:
        _mock_tsa_local.allowed = previous


def _hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """RFC 2104 HMAC-SHA-256 without importing stdlib hmac (INVARIANT-1).

    Uses hashlib.sha256 directly.  Block size for SHA-256 is 64 bytes.
    """
    block_size = 64
    if len(key) > block_size:
        key = hashlib.sha256(key).digest()
    key = key.ljust(block_size, b"\x00")
    o_key_pad = bytes(k ^ 0x5C for k in key)
    i_key_pad = bytes(k ^ 0x36 for k in key)
    return hashlib.sha256(o_key_pad + hashlib.sha256(i_key_pad + msg).digest()).digest()


class MockTSA:
    """
    Self-signed mock Time-Stamp Authority for testing purposes.

    .. warning:: **Testing only.**  MockTSA will raise ``RuntimeError`` if
       ``_MOCK_TSA_ALLOWED`` is not set to ``True``.  Set it in your test
       fixtures or via the ``allow_mock_tsa`` context manager.

    The token format (all big-endian) is:
        16 bytes  - magic header (_MOCK_MAGIC)
         4 bytes  - hash algorithm name length (N)
         N bytes  - hash algorithm name (utf-8)
         8 bytes  - Unix timestamp (double, seconds since epoch)
        32 bytes  - HMAC-SHA256(key=nonce, msg=payload)  [S3: uses HMAC,
                    not raw SHA-256 concatenation, to avoid length-extension]
        32 bytes  - the random nonce used for the HMAC

    The HMAC lets ``verify_timestamp`` confirm that the token has not been
    tampered with, even though the key is embedded in the token (the security
    goal is integrity, not authenticity -- this is a *mock*).
    """

    @staticmethod
    def _check_allowed() -> None:
        """Raise if MockTSA is used outside a testing context.

        Checks thread-local flag first (set by get_timestamp mock-mode),
        then falls back to the module-level global (set by test fixtures).
        The global read is guarded by ``_MOCK_TSA_LOCK`` so that a
        concurrent ``_MOCK_TSA_ALLOWED = True`` assignment in another
        thread is observed atomically.
        """
        if getattr(_mock_tsa_local, "allowed", False):
            return
        with _MOCK_TSA_LOCK:
            allowed = _MOCK_TSA_ALLOWED
        if not allowed:
            raise RuntimeError(
                "MockTSA is only available in testing contexts. "
                "Set ama_cryptography.rfc3161_timestamp._MOCK_TSA_ALLOWED = True "
                "in your test fixture before using MockTSA."
            )

    @staticmethod
    def timestamp(data_hash: bytes, hash_algorithm: str) -> bytes:
        """Create a mock timestamp token from *data_hash*."""
        MockTSA._check_allowed()

        algo_bytes = hash_algorithm.encode("utf-8")
        algo_len = struct.pack(">I", len(algo_bytes))
        ts = struct.pack(">d", time.time())
        nonce = _os_mod.urandom(32)

        payload = _MOCK_MAGIC + algo_len + algo_bytes + ts + data_hash
        # S3 fix: Use HMAC instead of raw SHA-256(nonce || payload) to
        # prevent length-extension attacks on the integrity tag.
        mac = _hmac_sha256(nonce, payload)

        return payload + mac + nonce

    @staticmethod
    def verify(token: bytes, data_hash: bytes) -> bool:
        """Verify a mock timestamp token against *data_hash*."""
        try:
            if not token.startswith(_MOCK_MAGIC):
                return False

            offset = len(_MOCK_MAGIC)
            algo_len = struct.unpack_from(">I", token, offset)[0]
            offset += 4
            # skip algo bytes
            offset += algo_len
            # skip timestamp (8 bytes)
            offset += 8

            # The remaining bytes up to this point form the payload.
            payload_end = offset
            # payload = _MOCK_MAGIC + algo_len(4) + algo(N) + ts(8) + data_hash
            # mac(32) + nonce(32) at the tail.
            mac = token[-(32 + 32) : -32]
            nonce = token[-32:]
            payload = token[: -(32 + 32)]

            # S3 fix: Verify HMAC (not raw hash concatenation).
            # Use constant-time comparison to be consistent with the
            # project's security posture (CONTRIBUTING.md / INVARIANT-1).
            from ama_cryptography.secure_memory import constant_time_compare

            expected_mac = _hmac_sha256(nonce, payload)
            if not constant_time_compare(mac, expected_mac):
                return False

            # Extract embedded data_hash from the payload and compare.
            # SECURITY FIX: Use constant-time comparison to prevent
            # timing oracle attacks on hash values (audit finding S3b).
            embedded_hash = payload[payload_end:]
            return constant_time_compare(embedded_hash, data_hash)
        except Exception as exc:
            _logger.error("MockTSA.verify failed: %s", exc)
            return False


def _is_mock_token(token: bytes) -> bool:
    """Return True if *token* was produced by :class:`MockTSA`."""
    return token[:16] == _MOCK_MAGIC


def get_timestamp(
    data: bytes,
    tsa_url: Optional[str] = None,
    hash_algorithm: str = "sha3-256",
    certificate_file: Optional[str] = None,
    tsa_mode: str = "online",
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
        tsa_mode: Operating mode for timestamping:
                  - "online" (default): contact a real TSA server
                  - "mock": use MockTSA for offline / testing purposes
                  - "disabled": skip timestamping; returns a TimestampResult
                    with tsa_url='disabled' and an empty token

    Returns:
        TimestampResult with timestamp token and metadata.  When tsa_mode
        is ``"disabled"``, returns a TimestampResult with ``tsa_url='disabled'``
        and ``token=b""``.  Never returns ``None``.

    Raises:
        TimestampUnavailableError: If rfc3161ng library not installed (online mode)
        TimestampError: If timestamp request fails
        ValueError: If hash_algorithm or tsa_mode is not supported

    Example:
        >>> result = get_timestamp(b"Important document")
        >>> print(f"Timestamp token: {len(result.token)} bytes")
        >>> # Save token for later verification
        >>> with open("document.tsr", "wb") as f:
        ...     f.write(result.token)

    Public TSA Services:
    --------------------
    - FreeTSA: https://freetsa.org/tsr (free, no registration)
    - DigiCert: http://timestamp.digicert.com (free, no registration)
    - GlobalSign: http://timestamp.globalsign.com/tsa/tsa (free)

    Note: For production use, consider running your own TSA server or
          using a commercial service with SLA guarantees.
    """
    if tsa_mode not in ("online", "mock", "disabled"):
        raise ValueError(
            f"Unsupported tsa_mode: {tsa_mode!r}. Supported: 'online', 'mock', 'disabled'"
        )

    # ---- Compute data hash (needed for all modes) ----
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

    # ---- Disabled mode: return immediately with empty token ----
    if tsa_mode == "disabled":
        return TimestampResult(
            token=b"",
            tsa_url="disabled",
            hash_algorithm=hash_algorithm,
            data_hash=data_hash,
        )

    # ---- Mock mode: generate a self-signed mock token ----
    if tsa_mode == "mock":
        # SECURITY FIX (audit finding C8): Use the allow_mock_tsa()
        # context manager instead of bare flag manipulation to guarantee
        # atomic enable/disable semantics.
        with allow_mock_tsa():
            token = MockTSA.timestamp(data_hash, hash_algorithm)
        return TimestampResult(
            token=token,
            tsa_url="mock",
            hash_algorithm=hash_algorithm,
            data_hash=data_hash,
        )

    # ---- Online mode ----
    if not RFC3161_AVAILABLE:
        raise TimestampUnavailableError(
            "RFC3161_UNAVAILABLE: rfc3161ng library not installed. "
            "Install with: pip install rfc3161ng"
        )

    # Use FreeTSA as default public TSA
    if tsa_url is None:
        tsa_url = "https://freetsa.org/tsr"
        warnings.warn(
            f"No TSA URL specified, using public service: {tsa_url}. "
            "For production use, specify a reliable TSA server.",
            category=UserWarning,
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


def _compute_data_hash(data: bytes, algorithm: str) -> Optional[bytes]:
    """Compute a hash of *data* using the named *algorithm*.

    Returns the digest bytes, or ``None`` if the algorithm is not supported.
    """
    _hash_funcs: Dict[str, Callable[[bytes], hashlib._Hash]] = {
        "sha256": hashlib.sha256,
        "sha3-256": hashlib.sha3_256,
        "sha512": hashlib.sha512,
        "sha3-512": hashlib.sha3_512,
    }
    func = _hash_funcs.get(algorithm)
    if func is None:
        return None
    return func(data).digest()


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
    2. Parse timestamp token (ASN.1 DER) -- or verify mock / disabled token
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
        ...     tsa_url="https://freetsa.org/tsr",
        ...     hash_algorithm='sha3-256',
        ...     data_hash=b'...'
        ... )
        >>> is_valid = verify_timestamp(b"Important document", result)
        >>> print(f"Timestamp valid: {is_valid}")
    """
    # ---- Disabled tokens: still verify data integrity (S2 fix) ----
    # Even when timestamping is disabled, the data_hash stored in the
    # TimestampResult must match the actual data. Without this check,
    # a TimestampResult from payload A would validate payload B.
    if timestamp_result.tsa_url == "disabled" and timestamp_result.token == b"":
        computed_hash = _compute_data_hash(data, timestamp_result.hash_algorithm)
        if computed_hash is None:
            return False
        return computed_hash == timestamp_result.data_hash

    # ---- Mock token path (does not require rfc3161ng) ----
    if _is_mock_token(timestamp_result.token):
        try:
            computed_hash = _compute_data_hash(data, timestamp_result.hash_algorithm)
            if computed_hash is None or computed_hash != timestamp_result.data_hash:
                return False
            return MockTSA.verify(timestamp_result.token, computed_hash)
        except Exception as exc:
            _logger.error("Mock timestamp verification failed: %s", exc)
            return False

    # ---- Online (real RFC 3161) verification ----
    if not RFC3161_AVAILABLE:
        raise TimestampUnavailableError(
            "RFC3161_UNAVAILABLE: rfc3161ng library not installed. "
            "Install with: pip install rfc3161ng"
        )

    try:
        computed_hash = _compute_data_hash(data, timestamp_result.hash_algorithm)
        if computed_hash is None or computed_hash != timestamp_result.data_hash:
            return False

        # Create timestamper for verification
        timestamper = RemoteTimestamper(
            timestamp_result.tsa_url,
            certificate=certificate_file,
            hashname=timestamp_result.hash_algorithm.replace("-", ""),
        )

        # Verify timestamp token
        is_valid = timestamper.check(
            timestamp_result.token,
            data=data,
        )

        return bool(is_valid)

    except Exception as exc:
        _logger.error("RFC 3161 timestamp verification failed: %s", exc)
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
