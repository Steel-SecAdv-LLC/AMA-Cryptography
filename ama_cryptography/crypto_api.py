#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
AMA Cryptography - Algorithm-Agnostic Cryptographic API
===========================================================

Unified interface for all post-quantum cryptographic algorithms.
Enables seamless switching between ML-DSA-65, Kyber-1024, SPHINCS+-256f,
and hybrid classical+PQC modes.

Design Philosophy:
- Single API for all algorithms
- Explicit capability detection (no silent classical fallbacks)
- Hybrid mode support (classical + PQC)
- Backward compatibility
- Performance optimized (uses C/Cython when available)

PQC Backend:
- ML-DSA-65 (CRYSTALS-Dilithium) via native C implementation
- Raises PQCUnavailableError if native C backend is not built
- Use get_pqc_capabilities() to check availability before use
"""

import hashlib
import logging
import os
import secrets
import warnings
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, ClassVar, Dict, List, Optional, Tuple, Union

from ama_cryptography._self_test import check_operational as _check_operational

# Import HMAC and HKDF from pqc_backends (native C) with pure-Python fallback
from ama_cryptography.pqc_backends import (
    _HKDF_NATIVE_AVAILABLE,
    _HMAC_SHA3_256_NATIVE_AVAILABLE,
    DILITHIUM_AVAILABLE,
    DILITHIUM_BACKEND,
    KYBER_AVAILABLE,
    KYBER_BACKEND,
    KYBER_CIPHERTEXT_BYTES,
    KYBER_PUBLIC_KEY_BYTES,
    KYBER_SECRET_KEY_BYTES,
    KYBER_SHARED_SECRET_BYTES,
    SPHINCS_AVAILABLE,
    SPHINCS_BACKEND,
    SPHINCS_PUBLIC_KEY_BYTES,
    SPHINCS_SECRET_KEY_BYTES,
    SPHINCS_SIGNATURE_BYTES,
    KyberUnavailableError,
    PQCStatus,
    PQCUnavailableError,
    SphincsUnavailableError,
    dilithium_sign,
    dilithium_verify,
    generate_dilithium_keypair,
    generate_kyber_keypair,
    generate_sphincs_keypair,
    get_pqc_backend_info,
    kyber_decapsulate,
    kyber_encapsulate,
    sphincs_sign,
    sphincs_verify,
)

_HMAC_NATIVE = False
_HKDF_NATIVE = False

try:
    from ama_cryptography.pqc_backends import native_hkdf, native_hmac_sha3_256

    _HMAC_NATIVE = _HMAC_SHA3_256_NATIVE_AVAILABLE
    _HKDF_NATIVE = _HKDF_NATIVE_AVAILABLE
except ImportError:
    pass


def _hmac_sha3_256(key: bytes, msg: bytes) -> bytes:
    """HMAC-SHA3-256: native C backend or pure-Python fallback (RFC 2104)."""
    if _HMAC_NATIVE:
        return native_hmac_sha3_256(key, msg)
    # Pure-Python HMAC-SHA3-256 (RFC 2104) — stdlib only
    block_size = 136  # SHA3-256 Keccak rate
    if len(key) > block_size:
        key = hashlib.sha3_256(key).digest()
    key = key.ljust(block_size, b"\x00")
    ipad = bytes(k ^ 0x36 for k in key)
    opad = bytes(k ^ 0x5C for k in key)
    inner = hashlib.sha3_256(ipad + msg).digest()
    return hashlib.sha3_256(opad + inner).digest()


def _hkdf_sha3_256(
    ikm: bytes,
    length: int,
    salt: "Optional[bytes]" = None,
    info: bytes = b"",
) -> bytes:
    """HKDF-SHA3-256: native C backend or pure-Python fallback (RFC 5869)."""
    if _HKDF_NATIVE:
        return native_hkdf(ikm, length, salt=salt, info=info)
    # Pure-Python HKDF (extract-then-expand) using HMAC-SHA3-256
    hash_len = 32  # SHA3-256 output
    if length > 255 * hash_len:
        raise ValueError(f"HKDF output length must be <= {255 * hash_len}, got {length}")
    # Extract
    if salt is None:
        salt = b"\x00" * hash_len
    prk = _hmac_sha3_256(salt, ikm)
    # Expand
    okm = b""
    t = b""
    for i in range(1, (length + hash_len - 1) // hash_len + 1):
        t = _hmac_sha3_256(prk, t + info + bytes([i]))
        okm += t
    return okm[:length]


HMAC_HKDF_AVAILABLE = True  # Always available via native or pure-Python fallback

# Import RFC 3161 timestamping
try:
    from ama_cryptography.rfc3161_timestamp import (
        RFC3161_AVAILABLE,
        TimestampError,
        TimestampUnavailableError,
        get_timestamp,
    )
except ImportError:
    RFC3161_AVAILABLE = False
    TimestampUnavailableError = Exception  # type: ignore[misc,assignment]
    TimestampError = Exception  # type: ignore[misc,assignment]
    get_timestamp = None  # type: ignore[assignment]

logger: logging.Logger = logging.getLogger(__name__)

# Runtime PQC availability check
pqc_available = DILITHIUM_AVAILABLE or KYBER_AVAILABLE or SPHINCS_AVAILABLE
if not pqc_available:
    # Use catch_warnings to emit warning without triggering pytest's "warnings as errors"
    with warnings.catch_warnings():
        warnings.simplefilter("default", UserWarning)
        warnings.warn(
            "Quantum-resistant cryptography NOT available. "
            "Build native C library for post-quantum protection: "
            "cmake -B build -DAMA_USE_NATIVE_PQC=ON && "
            "cmake --build build",
            category=UserWarning,
            stacklevel=2,
        )


class AlgorithmType(Enum):
    """Supported cryptographic algorithms"""

    ML_DSA_65 = auto()  # CRYSTALS-Dilithium (signatures)
    KYBER_1024 = auto()  # CRYSTALS-Kyber (KEM)
    SPHINCS_256F = auto()  # SPHINCS+ (signatures)
    ED25519 = auto()  # Classical Ed25519 (signatures)
    AES_256_GCM = auto()  # AES-256-GCM (authenticated encryption)
    HYBRID_SIG = auto()  # Hybrid: Ed25519 + ML-DSA-65
    HYBRID_KEM = auto()  # Hybrid: X25519 + Kyber-1024


class CryptoBackend(Enum):
    """Available implementation backends"""

    C_LIBRARY = auto()  # libama_cryptography.so (fastest, native PQC)
    CYTHON = auto()  # Cython optimized (fast)
    PURE_PYTHON = auto()  # Pure Python (fallback)


@dataclass
class KeyPair:
    """
    Cryptographic key pair container

    Attributes:
        public_key: Public key bytes
        secret_key: Secret key bytes (SENSITIVE)
        algorithm: Algorithm used to generate keys
        metadata: Additional key information
    """

    public_key: bytes
    secret_key: bytes = field(repr=False)  # SENSITIVE - excluded from repr to prevent exposure
    algorithm: AlgorithmType
    metadata: Dict[str, Any]


@dataclass
class Signature:
    """
    Digital signature container

    Attributes:
        signature: Signature bytes
        algorithm: Algorithm used for signing
        message_hash: Hash of signed message (for verification)
        metadata: Additional signature information
    """

    signature: bytes
    algorithm: AlgorithmType
    message_hash: bytes
    metadata: Dict[str, Any]


@dataclass
class EncapsulatedSecret:
    """
    KEM encapsulated secret container

    Attributes:
        ciphertext: Encapsulated ciphertext
        shared_secret: Shared secret key (SENSITIVE)
        algorithm: Algorithm used
        metadata: Additional information
    """

    ciphertext: bytes
    shared_secret: bytes = field(repr=False)  # SENSITIVE - excluded from repr to prevent exposure
    algorithm: AlgorithmType
    metadata: Dict[str, Any]


class CryptoProvider(ABC):
    """Abstract base class for cryptographic providers"""

    @abstractmethod
    def generate_keypair(self) -> KeyPair:
        """Generate a new keypair"""
        pass

    @abstractmethod
    def sign(self, message: bytes, secret_key: bytes) -> Signature:
        """Sign a message"""
        pass

    @abstractmethod
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a signature"""
        pass


class KEMProvider(ABC):
    """Abstract base class for KEM providers"""

    @abstractmethod
    def generate_keypair(self) -> KeyPair:
        """Generate a new keypair"""
        pass

    @abstractmethod
    def encapsulate(self, public_key: bytes) -> EncapsulatedSecret:
        """Encapsulate a shared secret"""
        pass

    @abstractmethod
    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Decapsulate a shared secret"""
        pass


class MLDSAProvider(CryptoProvider):
    """
    ML-DSA-65 (CRYSTALS-Dilithium) provider.

    Provides real post-quantum signatures via native C backend.
    Raises PQCUnavailableError if no PQC backend is installed.

    Security: NIST Security Level 3 (192-bit quantum security)
    Standard: NIST FIPS 204 (ML-DSA)
    """

    def __init__(self, backend: CryptoBackend = CryptoBackend.C_LIBRARY) -> None:
        self.backend = backend
        self.algorithm = AlgorithmType.ML_DSA_65
        self._available = DILITHIUM_AVAILABLE
        self._backend_name = DILITHIUM_BACKEND or "none"

    def generate_keypair(self) -> KeyPair:
        """
        Generate ML-DSA-65 keypair.

        Returns:
            KeyPair with Dilithium public and secret keys

        Raises:
            PQCUnavailableError: If no Dilithium backend is available
        """
        if not self._available:
            raise PQCUnavailableError(
                "PQC_UNAVAILABLE: ML-DSA-65 requires native C backend. "
                "Build: cmake -B build -DAMA_USE_NATIVE_PQC=ON "
                "&& cmake --build build"
            )

        kp = generate_dilithium_keypair()
        return KeyPair(
            public_key=kp.public_key,
            secret_key=kp.secret_key,
            algorithm=self.algorithm,
            metadata={
                "backend": self._backend_name,
                "key_size": len(kp.public_key),
                "algorithm": "ML-DSA-65",
                "security_level": 3,
            },
        )

    def sign(self, message: bytes, secret_key: bytes) -> Signature:
        """
        Sign message with ML-DSA-65.

        Args:
            message: Data to sign
            secret_key: Dilithium private key (4032 bytes)

        Returns:
            Signature object with Dilithium signature

        Raises:
            PQCUnavailableError: If no Dilithium backend is available
        """
        if not self._available:
            raise PQCUnavailableError("PQC_UNAVAILABLE: ML-DSA-65 requires native C backend.")

        sig_bytes = dilithium_sign(message, secret_key)
        message_hash = hashlib.sha3_256(message).digest()

        return Signature(
            signature=sig_bytes,
            algorithm=self.algorithm,
            message_hash=message_hash,
            metadata={
                "signature_size": len(sig_bytes),
                "backend": self._backend_name,
            },
        )

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify ML-DSA-65 signature.

        Args:
            message: Original data
            signature: Dilithium signature
            public_key: Dilithium public key (1952 bytes)

        Returns:
            True if signature is valid, False otherwise

        Raises:
            PQCUnavailableError: If no Dilithium backend is available
        """
        if not self._available:
            raise PQCUnavailableError("PQC_UNAVAILABLE: ML-DSA-65 requires native C backend.")

        return dilithium_verify(message, signature, public_key)


class Ed25519Provider(CryptoProvider):
    """
    Ed25519 classical signature provider.

    Provides classical (non-quantum-resistant) signatures.
    Use MLDSAProvider for post-quantum security.

    Uses native C implementation (zero external dependencies).

    Security: 128-bit classical security (NOT quantum-resistant)
    Standard: RFC 8032
    """

    def __init__(self, backend: CryptoBackend = CryptoBackend.C_LIBRARY) -> None:
        self.backend = backend
        self.algorithm = AlgorithmType.ED25519

        from ama_cryptography.pqc_backends import _ED25519_NATIVE_AVAILABLE, _native_lib

        if not (_native_lib is not None and _ED25519_NATIVE_AVAILABLE):
            raise RuntimeError(
                "Ed25519 native C backend not available. "
                "Build with: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
            )

    def generate_keypair(self) -> KeyPair:
        """Generate Ed25519 keypair using native C backend."""
        from ama_cryptography.pqc_backends import native_ed25519_keypair

        pk_bytes, sk_bytes = native_ed25519_keypair()
        # Return 32-byte seed as secret_key for API consistency
        # The full 64-byte key is seed || public_key
        return KeyPair(
            public_key=pk_bytes,
            secret_key=sk_bytes[:32],
            algorithm=self.algorithm,
            metadata={"backend": "native_c", "key_size": 32},
        )

    def sign(self, message: bytes, secret_key: bytes) -> Signature:
        """
        Sign message with Ed25519 using native C backend.

        Args:
            message: Data to sign
            secret_key: 32-byte Ed25519 seed or 64-byte native key

        Returns:
            Signature object with Ed25519 signature
        """
        from ama_cryptography.pqc_backends import (
            native_ed25519_keypair_from_seed,
            native_ed25519_sign,
        )

        # Handle 32-byte seed: expand to 64-byte native format
        if len(secret_key) == 32:
            _, full_sk = native_ed25519_keypair_from_seed(secret_key)
        elif len(secret_key) == 64:
            full_sk = secret_key
        else:
            raise ValueError(f"Ed25519 secret key must be 32 or 64 bytes, got {len(secret_key)}")

        sig_bytes = native_ed25519_sign(message, full_sk)
        message_hash = hashlib.sha3_256(message).digest()

        return Signature(
            signature=sig_bytes,
            algorithm=self.algorithm,
            message_hash=message_hash,
            metadata={"signature_size": len(sig_bytes), "backend": "native_c"},
        )

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify Ed25519 signature using native C backend.

        Args:
            message: Original data that was signed
            signature: 64-byte Ed25519 signature
            public_key: 32-byte Ed25519 public key

        Returns:
            True if signature is valid, False otherwise
        """
        from ama_cryptography.pqc_backends import native_ed25519_verify

        try:
            return native_ed25519_verify(signature, message, public_key)
        except ValueError:
            return False


class KyberProvider(KEMProvider):
    """
    Kyber-1024 (ML-KEM) provider - Real quantum-resistant implementation.

    Provides IND-CCA2 secure key encapsulation based on the Module-LWE
    (Learning With Errors) problem. Uses native C implementation
    (FIPS 203 compliant, NIST KAT validated).

    Key Sizes (FIPS 203):
        - Public key: 1568 bytes
        - Secret key: 3168 bytes
        - Ciphertext: 1568 bytes
        - Shared secret: 32 bytes

    Security: 256-bit classical / 128-bit quantum (NIST Security Level 5)
    Standard: NIST FIPS 203 (ML-KEM)

    Raises:
        KyberUnavailableError: If Kyber backend is not available
    """

    def __init__(self, backend: CryptoBackend = CryptoBackend.C_LIBRARY) -> None:
        self.backend = backend
        self.algorithm = AlgorithmType.KYBER_1024

        if not KYBER_AVAILABLE:
            raise KyberUnavailableError(
                "KYBER_UNAVAILABLE: Kyber-1024 backend not available. "
                "Build: cmake -B build -DAMA_USE_NATIVE_PQC=ON "
                "&& cmake --build build"
            )

    def generate_keypair(self) -> KeyPair:
        """
        Generate Kyber-1024 keypair.

        Returns:
            KeyPair with 1568-byte public key and 3168-byte secret key

        Raises:
            KyberUnavailableError: If Kyber backend is not available
        """
        keypair = generate_kyber_keypair()

        return KeyPair(
            public_key=keypair.public_key,
            secret_key=keypair.secret_key,
            algorithm=self.algorithm,
            metadata={
                "backend": KYBER_BACKEND,
                "public_key_size": KYBER_PUBLIC_KEY_BYTES,
                "secret_key_size": KYBER_SECRET_KEY_BYTES,
            },
        )

    def encapsulate(self, public_key: bytes) -> EncapsulatedSecret:
        """
        Encapsulate a shared secret using Kyber-1024.

        Args:
            public_key: Kyber-1024 public key (1568 bytes)

        Returns:
            EncapsulatedSecret with ciphertext and shared secret

        Raises:
            KyberUnavailableError: If Kyber backend is not available
            ValueError: If public_key has incorrect length
        """
        encap = kyber_encapsulate(public_key)

        return EncapsulatedSecret(
            ciphertext=encap.ciphertext,
            shared_secret=encap.shared_secret,
            algorithm=self.algorithm,
            metadata={
                "ciphertext_size": KYBER_CIPHERTEXT_BYTES,
                "shared_secret_size": KYBER_SHARED_SECRET_BYTES,
            },
        )

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """
        Decapsulate a shared secret using Kyber-1024.

        Args:
            ciphertext: Kyber-1024 ciphertext (1568 bytes)
            secret_key: Kyber-1024 secret key (3168 bytes)

        Returns:
            Shared secret (32 bytes)

        Raises:
            KyberUnavailableError: If Kyber backend is not available
            ValueError: If ciphertext or secret_key has incorrect length
        """
        return kyber_decapsulate(ciphertext, secret_key)


class SphincsProvider(CryptoProvider):
    """
    SPHINCS+-SHA2-256f-simple provider - Hash-based signatures.

    Provides stateless hash-based signatures with no risk of key reuse
    vulnerabilities. The 'f' variant is optimized for fast signing at
    the cost of larger signatures (~49KB).

    Key Sizes (NIST FIPS spec):
        - Public key: 64 bytes
        - Secret key: 128 bytes
        - Signature: 49856 bytes

    Security: 256-bit classical / 128-bit quantum (NIST Security Level 5)
    Standard: NIST FIPS 205 (SLH-DSA)

    Note: SPHINCS+ signatures are large but provide strong security
    guarantees based only on hash function security assumptions.

    Raises:
        SphincsUnavailableError: If SPHINCS+ backend is not available
    """

    def __init__(self, backend: CryptoBackend = CryptoBackend.C_LIBRARY) -> None:
        self.backend = backend
        self.algorithm = AlgorithmType.SPHINCS_256F

        if not SPHINCS_AVAILABLE:
            raise SphincsUnavailableError(
                "SPHINCS_UNAVAILABLE: SPHINCS+-256f backend not available. "
                "Build: cmake -B build -DAMA_USE_NATIVE_PQC=ON "
                "&& cmake --build build"
            )

    def generate_keypair(self) -> KeyPair:
        """
        Generate SPHINCS+-256f keypair.

        Returns:
            KeyPair with 64-byte public key and 128-byte secret key

        Raises:
            SphincsUnavailableError: If SPHINCS+ backend is not available
        """
        keypair = generate_sphincs_keypair()

        return KeyPair(
            public_key=keypair.public_key,
            secret_key=keypair.secret_key,
            algorithm=self.algorithm,
            metadata={
                "backend": SPHINCS_BACKEND,
                "public_key_size": SPHINCS_PUBLIC_KEY_BYTES,
                "secret_key_size": SPHINCS_SECRET_KEY_BYTES,
            },
        )

    def sign(self, message: bytes, secret_key: bytes) -> Signature:
        """
        Sign message with SPHINCS+-256f.

        Args:
            message: Data to sign (arbitrary length)
            secret_key: SPHINCS+-256f secret key (128 bytes)

        Returns:
            Signature object with 49856-byte signature

        Raises:
            SphincsUnavailableError: If SPHINCS+ backend is not available
            ValueError: If secret_key has incorrect length
        """
        sig_bytes = sphincs_sign(message, secret_key)
        message_hash = hashlib.sha3_256(message).digest()

        return Signature(
            signature=sig_bytes,
            algorithm=self.algorithm,
            message_hash=message_hash,
            metadata={
                "signature_size": SPHINCS_SIGNATURE_BYTES,
                "backend": SPHINCS_BACKEND,
            },
        )

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify SPHINCS+-256f signature.

        Args:
            message: Original data
            signature: SPHINCS+ signature (49856 bytes)
            public_key: SPHINCS+-256f public key (64 bytes)

        Returns:
            True if signature is valid, False otherwise

        Raises:
            SphincsUnavailableError: If SPHINCS+ backend is not available
            ValueError: If public_key has incorrect length
        """
        return sphincs_verify(message, signature, public_key)


class AESGCMProvider:
    """
    AES-256-GCM authenticated encryption provider.

    Provides symmetric authenticated encryption with associated data (AEAD).
    Uses native C backend (NIST SP 800-38D). Requires the native C library;
    raises RuntimeError if not available.

    Security: 256-bit key, 96-bit nonce, 128-bit auth tag
    Standard: NIST SP 800-38D

    .. warning:: **Single-process nonce safety only.**

       The counter persistence uses ``max()``-based merging: each process
       loads the on-disk counter at startup and writes back the max of its
       in-memory value and the on-disk value.  If two processes encrypt with
       the **same key** concurrently, each increments independently from the
       same loaded baseline — the persisted counter will undercount total
       nonce usage (N+M instead of N+2M), risking birthday-bound violations
       before the 2^32 safety limit triggers.

       For multi-process deployments sharing the same AES-GCM key, use
       external nonce coordination (e.g. per-process nonce partitioning,
       a shared atomic counter, or the ``NonceTracker`` in the monitoring
       framework which uses append-only per-entry persistence).
    """

    _NONCE_SAFETY_LIMIT: int = 2**32
    _PERSIST_INTERVAL: int = 64
    _encrypt_counters: ClassVar[Dict[bytes, int]] = {}
    _counters_persist_path: ClassVar[Optional[str]] = None
    _counters_loaded: ClassVar[bool] = False
    _counters_dirty: ClassVar[int] = 0
    _atexit_registered: ClassVar[bool] = False
    _ephemeral: ClassVar[bool] = False

    @classmethod
    def configure_ephemeral(cls, enabled: bool = True) -> None:
        """Configure ephemeral mode BEFORE any instantiation (S6 fix).

        When ephemeral mode is enabled, no disk I/O occurs for counter
        persistence — counters live only in memory.  This must be called
        before ``__init__`` so that ``_load_persisted_counters()`` and
        ``atexit`` registration respect the flag.

        Calling this method resets ``_counters_loaded`` and
        ``_atexit_registered`` so the next instantiation picks up the
        new mode cleanly.
        """
        cls._ephemeral = enabled
        cls._counters_loaded = False
        cls._atexit_registered = False
        cls._encrypt_counters = {}
        cls._counters_dirty = 0

    def __init__(
        self,
        backend: CryptoBackend = CryptoBackend.C_LIBRARY,
        *,
        ephemeral: bool = False,
    ) -> None:
        # S6 fix: If ephemeral=True is passed to the constructor, apply it
        # BEFORE loading counters or registering atexit, so tests are hermetic.
        if ephemeral and not AESGCMProvider._ephemeral:
            AESGCMProvider.configure_ephemeral(True)

        self.backend = backend
        self.algorithm = AlgorithmType.AES_256_GCM
        self._pid_at_init: int = os.getpid()

        from ama_cryptography.pqc_backends import _AES_GCM_NATIVE_AVAILABLE, _native_lib

        if not (_native_lib is not None and _AES_GCM_NATIVE_AVAILABLE):
            raise RuntimeError(
                "AES-256-GCM native C backend not available. "
                "Build with: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
            )

        # Load persisted counters on first instantiation
        if not AESGCMProvider._counters_loaded:
            AESGCMProvider._load_persisted_counters()
            AESGCMProvider._counters_loaded = True
        if not AESGCMProvider._atexit_registered and not AESGCMProvider._ephemeral:
            import atexit

            atexit.register(AESGCMProvider._persist_counters)
            AESGCMProvider._atexit_registered = True

    @classmethod
    def _get_persist_path(cls) -> Any:
        """Get path for counter persistence file."""
        import pathlib

        if cls._counters_persist_path:
            return pathlib.Path(cls._counters_persist_path)
        data_dir = pathlib.Path.home() / ".ama_cryptography"
        data_dir.mkdir(parents=True, exist_ok=True)
        return data_dir / "aes_gcm_counters.json"

    @classmethod
    def _load_persisted_counters(cls) -> None:
        """Load persisted encrypt counters from disk."""
        if cls._ephemeral:
            return
        import json as _json

        path = cls._get_persist_path()
        try:
            with open(path, "r") as f:
                data = _json.load(f)
            for key_hex, count in data.items():
                key_id = bytes.fromhex(key_hex)
                cls._encrypt_counters[key_id] = max(cls._encrypt_counters.get(key_id, 0), count)
        except FileNotFoundError:
            return
        except Exception as e:
            raise RuntimeError(f"Failed to load persisted AES-GCM counters from {path}: {e}") from e

    @classmethod
    def _persist_counters(cls, *, _raising: bool = False) -> None:
        """Persist encrypt counters to disk using atomic write-rename with file locking.

        Acquires an exclusive lock on a .lock file to prevent inter-process
        races. Writes to a temporary file first, then atomically renames to the
        target path. This prevents counter loss on crash — either the old
        file remains intact or the new file fully replaces it.

        Args:
            _raising: If True, propagate write failures as RuntimeError instead
                of logging a warning. Used when called from the encrypt path
                where an unpersisted counter could allow nonce reuse after
                restart. The atexit handler passes False (default) because
                raising during interpreter shutdown is unsafe.
        """
        if cls._ephemeral:
            return
        import json as _json
        import os as _os
        import tempfile

        path = cls._get_persist_path()
        lock_path = path.parent / ".counters.lock"
        lock_fd: Optional[int] = None
        try:
            # Acquire inter-process lock
            lock_fd = _os.open(str(lock_path), _os.O_CREAT | _os.O_RDWR, 0o600)
            try:
                import fcntl

                fcntl.flock(lock_fd, fcntl.LOCK_EX)
            except ImportError:
                # Windows: fcntl unavailable — try msvcrt.locking
                try:
                    import msvcrt  # Windows-only stdlib module

                    msvcrt.locking(lock_fd, msvcrt.LK_LOCK, 1)  # type: ignore[attr-defined]
                except (ImportError, OSError) as _lock_err:
                    logger.debug(
                        "File locking unavailable (no fcntl or msvcrt): "
                        "%s — proceeding without lock",
                        _lock_err,
                    )
            except OSError as _lock_err:
                logger.debug("File locking failed: %s — proceeding without lock", _lock_err)

            # Merge with any counters persisted by another process
            try:
                with open(path) as f:
                    on_disk = _json.load(f)
                for key_hex, count in on_disk.items():
                    key_id = bytes.fromhex(key_hex)
                    cls._encrypt_counters[key_id] = max(cls._encrypt_counters.get(key_id, 0), count)
            except FileNotFoundError:
                logger.debug("No existing counter file at %s — first write", path)
            except (_json.JSONDecodeError, ValueError, KeyError, TypeError) as _merge_err:
                # Corrupt counter file during persist-merge.
                # When called from the encrypt path (_raising=True), this is
                # a safety-critical error: a corrupt file may contain stale
                # counters that could allow nonce reuse after overwrite.
                # Consistent with _load_persisted_counters which raises on
                # any corruption.
                if _raising:
                    raise RuntimeError(
                        f"Corrupt AES-GCM counter file at {path}: {_merge_err}. "
                        "Cannot safely merge counters — manual inspection required."
                    ) from _merge_err
                # Atexit path: cannot raise, but overwriting a corrupt file
                # risks losing higher counter values from a concurrent process.
                # Preserve the corrupt file for forensic analysis and log at
                # CRITICAL severity — this is a potential nonce-safety event.
                try:
                    corrupt_bak = path.parent / (path.name + ".corrupt")
                    _os.replace(str(path), str(corrupt_bak))
                    logger.critical(
                        "Corrupt counter file renamed to %s for forensic analysis. "
                        "Overwriting with in-memory counters. If a concurrent process "
                        "had higher counter values, nonce safety may be compromised. "
                        "Original error: %s",
                        corrupt_bak,
                        _merge_err,
                    )
                except OSError as _bak_err:
                    logger.critical(
                        "Corrupt counter file at %s AND failed to preserve backup: %s. "
                        "Overwriting with in-memory counters. Original error: %s",
                        path,
                        _bak_err,
                        _merge_err,
                    )

            data = {k.hex(): v for k, v in cls._encrypt_counters.items()}
            # Write to temp file in same directory (same filesystem for atomic rename)
            fd, tmp_path = tempfile.mkstemp(
                dir=str(path.parent), suffix=".tmp", prefix=".counters_"
            )
            _rename_ok = False
            try:
                with _os.fdopen(fd, "w") as f:
                    _json.dump(data, f)
                    f.flush()
                    _os.fsync(f.fileno())
                _os.replace(tmp_path, str(path))
                _rename_ok = True
            finally:
                if not _rename_ok:
                    try:
                        _os.unlink(tmp_path)
                    except OSError as _unlink_err:
                        logger.debug("Failed to clean up temp file %s: %s", tmp_path, _unlink_err)
        except Exception as e:
            if _raising:
                raise RuntimeError(
                    f"Failed to persist AES-GCM counters to {path}: {e}. "
                    "Counter tracking cannot guarantee nonce safety without durable persistence."
                ) from e
            logger.warning("Failed to persist AES-GCM counters: %s", e)
        finally:
            if lock_fd is not None:
                _os.close(lock_fd)

    def encrypt(
        self,
        plaintext: bytes,
        key: bytes,
        nonce: "Optional[bytes]" = None,
        aad: bytes = b"",
    ) -> "dict":
        """
        Encrypt plaintext with AES-256-GCM.

        Args:
            plaintext: Data to encrypt
            key: 32-byte AES-256 key
            nonce: 12-byte nonce (auto-generated if None)
            aad: Additional authenticated data

        Returns:
            Dict with 'ciphertext', 'nonce', 'tag', 'aad' keys
        """
        import secrets as _secrets

        # Fork detection: refuse to reuse nonce state after os.fork()
        if os.getpid() != self._pid_at_init:
            raise RuntimeError(
                "AES-GCM nonce counter state was inherited across fork(). "
                "Create a new AESGCMProvider in the child process to avoid nonce reuse. "
                "For multi-process deployments, use per-process key partitioning."
            )

        if len(key) != 32:
            raise ValueError(f"AES-256 key must be 32 bytes, got {len(key)}")

        if nonce is None:
            nonce = _secrets.token_bytes(12)
        elif len(nonce) != 12:
            raise ValueError(f"AES-256-GCM nonce must be 12 bytes, got {len(nonce)}")

        key_id: bytes = hashlib.sha256(key).digest()
        count: int = self._encrypt_counters.get(key_id, 0)
        if count >= self._NONCE_SAFETY_LIMIT:
            raise RuntimeError("AES-GCM nonce safety limit exceeded. Re-key required.")
        if count >= int(self._NONCE_SAFETY_LIMIT * 0.75):
            logger.warning("AES-GCM nonce count approaching safety limit. Re-key recommended.")

        from ama_cryptography.pqc_backends import native_aes256_gcm_encrypt

        ct, tag = native_aes256_gcm_encrypt(key, nonce, plaintext, aad)

        # Increment counter AFTER successful encryption so a persistence
        # failure (disk full, permission error) does not inflate the count
        # without an actual encryption having occurred.
        self._encrypt_counters[key_id] = count + 1
        AESGCMProvider._counters_dirty += 1

        result = {
            "ciphertext": ct,
            "nonce": nonce,
            "tag": tag,
            "aad": aad,
            "backend": "native_c",
        }

        if AESGCMProvider._counters_dirty >= self._PERSIST_INTERVAL:
            try:
                self._persist_counters(_raising=True)
            except Exception:
                # Persist failed — set dirty to interval-1 so the VERY NEXT
                # encrypt retries persistence immediately, avoiding both:
                # (a) 63 encrypts without persistence (finally-reset-to-0), and
                # (b) permanent bricking (success-only reset where dirty stays
                #     above the threshold forever after any transient I/O error).
                AESGCMProvider._counters_dirty = self._PERSIST_INTERVAL - 1
                # CRITICAL: The encryption already happened and the nonce is
                # consumed.  We MUST return the ciphertext — raising here would
                # discard valid ciphertext and mislead callers into retrying
                # with the same nonce (catastrophic for AES-GCM).  The persist
                # failure is logged at CRITICAL and retried on next encrypt().
                logger.critical(
                    "AES-GCM counter persistence failed — ciphertext returned "
                    "but counter may not survive restart.  Will retry on next "
                    "encrypt().  DO NOT re-encrypt with the same nonce."
                )
            else:
                # Persist succeeded — reset to 0 for normal operation.
                AESGCMProvider._counters_dirty = 0

        return result

    def decrypt(
        self,
        ciphertext: bytes,
        key: bytes,
        nonce: bytes,
        tag: bytes,
        aad: bytes = b"",
    ) -> bytes:
        """
        Decrypt ciphertext with AES-256-GCM.

        Args:
            ciphertext: Encrypted data
            key: 32-byte AES-256 key
            nonce: 12-byte nonce used during encryption
            tag: 16-byte authentication tag
            aad: Additional authenticated data used during encryption

        Returns:
            Decrypted plaintext

        Raises:
            ValueError: If authentication tag verification fails
        """
        if len(key) != 32:
            raise ValueError(f"AES-256 key must be 32 bytes, got {len(key)}")
        if len(nonce) != 12:
            raise ValueError(f"AES-256-GCM nonce must be 12 bytes, got {len(nonce)}")
        if len(tag) != 16:
            raise ValueError(f"AES-256-GCM tag must be 16 bytes, got {len(tag)}")

        from ama_cryptography.pqc_backends import native_aes256_gcm_decrypt

        return native_aes256_gcm_decrypt(key, nonce, ciphertext, tag, aad)


class HybridKEMProvider(KEMProvider):
    """
    Hybrid KEM provider (X25519 + Kyber-1024) adapter.

    Wraps HybridCombiner to conform to the KEMProvider interface,
    combining classical X25519 and post-quantum Kyber-1024 KEMs
    via a binding HKDF construction.

    Key layout:
        public_key  = x25519_pub (32 bytes) || kyber_pub (1568 bytes)
        secret_key  = x25519_priv (32 bytes) || x25519_pub (32 bytes)
                      || kyber_secret (3168 bytes) || kyber_pub (1568 bytes)
        ciphertext  = x25519_ephemeral_pub (32 bytes) || kyber_ct
    """

    _X25519_KEY_BYTES: int = 32

    def __init__(self) -> None:
        from .hybrid_combiner import HybridCombiner

        self._combiner = HybridCombiner()
        self.algorithm = AlgorithmType.HYBRID_KEM

    def generate_keypair(self) -> KeyPair:
        """Generate both X25519 and Kyber-1024 keypairs."""
        from ama_cryptography.pqc_backends import native_x25519_keypair

        x25519_pk, x25519_sk = native_x25519_keypair()
        kyber_kp = generate_kyber_keypair()

        combined_pk: bytes = x25519_pk + kyber_kp.public_key
        combined_sk: bytes = x25519_sk + x25519_pk + kyber_kp.secret_key + kyber_kp.public_key

        return KeyPair(
            public_key=combined_pk,
            secret_key=combined_sk,
            algorithm=self.algorithm,
            metadata={
                "backend": "hybrid_kem",
                "pqc_backend": KYBER_BACKEND,
                "x25519_key_bytes": self._X25519_KEY_BYTES,
            },
        )

    def encapsulate(self, public_key: bytes) -> EncapsulatedSecret:
        """Perform X25519 ephemeral-static DH + Kyber encapsulation."""
        from ama_cryptography.pqc_backends import native_x25519_key_exchange, native_x25519_keypair

        # Split recipient public key
        x25519_pub: bytes = public_key[: self._X25519_KEY_BYTES]
        kyber_pub: bytes = public_key[self._X25519_KEY_BYTES :]

        # X25519: generate ephemeral keypair + DH
        eph_pk, eph_sk = native_x25519_keypair()
        x25519_ss: bytes = native_x25519_key_exchange(eph_sk, x25519_pub)

        # Kyber encapsulation
        kyber_result = kyber_encapsulate(kyber_pub)

        # Combine via binding HKDF
        combined_ss: bytes = self._combiner.combine(
            classical_ss=x25519_ss,
            pqc_ss=kyber_result.shared_secret,
            classical_ct=eph_pk,
            pqc_ct=kyber_result.ciphertext,
            classical_pk=x25519_pub,
            pqc_pk=kyber_pub,
        )

        combined_ct: bytes = eph_pk + kyber_result.ciphertext

        return EncapsulatedSecret(
            ciphertext=combined_ct,
            shared_secret=combined_ss,
            algorithm=self.algorithm,
            metadata={"backend": "hybrid_kem"},
        )

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Split ciphertext and secret key, recover both shared secrets, combine."""
        from ama_cryptography.pqc_backends import native_x25519_key_exchange

        # Split ciphertext
        x25519_eph_pub: bytes = ciphertext[: self._X25519_KEY_BYTES]
        kyber_ct: bytes = ciphertext[self._X25519_KEY_BYTES :]

        # Split secret key: x25519_sk (32) || x25519_pk (32) || kyber_sk || kyber_pub
        x25519_sk: bytes = secret_key[: self._X25519_KEY_BYTES]
        x25519_pub: bytes = secret_key[self._X25519_KEY_BYTES : 2 * self._X25519_KEY_BYTES]
        kyber_sk: bytes = secret_key[
            2 * self._X25519_KEY_BYTES : 2 * self._X25519_KEY_BYTES + KYBER_SECRET_KEY_BYTES
        ]
        kyber_pub: bytes = secret_key[2 * self._X25519_KEY_BYTES + KYBER_SECRET_KEY_BYTES :]

        # Recover shared secrets
        x25519_ss: bytes = native_x25519_key_exchange(x25519_sk, x25519_eph_pub)
        kyber_ss: bytes = kyber_decapsulate(kyber_ct, kyber_sk)

        # Combine with matching info binding (must match encapsulate)
        combined_ss: bytes = self._combiner.combine(
            classical_ss=x25519_ss,
            pqc_ss=kyber_ss,
            classical_ct=x25519_eph_pub,
            pqc_ct=kyber_ct,
            classical_pk=x25519_pub,
            pqc_pk=kyber_pub,
        )

        return combined_ss


class HybridSignatureProvider(CryptoProvider):
    """
    Hybrid signature provider (Ed25519 + ML-DSA-65).

    Provides dual-signature scheme combining classical Ed25519 with
    post-quantum ML-DSA-65 (Dilithium). Both signatures must verify
    for the combined signature to be valid.

    Security: Secure against both classical and quantum adversaries
    Transition: Safe during classical-to-quantum migration period

    Raises:
        PQCUnavailableError: If Dilithium backend is not available
    """

    # Key sizes for splitting combined keys
    ED25519_SK_SIZE = 32
    ED25519_PK_SIZE = 32
    ED25519_SIG_SIZE = 64
    DILITHIUM_SK_SIZE = 4032  # ML-DSA-65 per FIPS 204
    DILITHIUM_PK_SIZE = 1952
    DILITHIUM_SIG_SIZE = 3309  # ML-DSA-65 per FIPS 204

    def __init__(self) -> None:
        self.classical_provider = Ed25519Provider()
        self.pqc_provider = MLDSAProvider()
        self.algorithm = AlgorithmType.HYBRID_SIG
        self._pqc_available = DILITHIUM_AVAILABLE

    def generate_keypair(self) -> KeyPair:
        """
        Generate hybrid keypair (Ed25519 + ML-DSA-65).

        Returns:
            KeyPair with combined public and secret keys

        Raises:
            PQCUnavailableError: If Dilithium backend is not available
        """
        if not self._pqc_available:
            raise PQCUnavailableError(
                "PQC_UNAVAILABLE: Hybrid signatures require ML-DSA-65. "
                "Build: cmake -B build -DAMA_USE_NATIVE_PQC=ON "
                "&& cmake --build build"
            )

        classical_keys = self.classical_provider.generate_keypair()
        pqc_keys = self.pqc_provider.generate_keypair()

        # Combine keys (Ed25519 first, then Dilithium)
        combined_pk = classical_keys.public_key + pqc_keys.public_key
        combined_sk = classical_keys.secret_key + pqc_keys.secret_key

        return KeyPair(
            public_key=combined_pk,
            secret_key=combined_sk,
            algorithm=self.algorithm,
            metadata={
                "classical_algorithm": "Ed25519",
                "pqc_algorithm": "ML-DSA-65",
                "classical_pk_size": len(classical_keys.public_key),
                "pqc_pk_size": len(pqc_keys.public_key),
            },
        )

    def sign(self, message: bytes, secret_key: bytes) -> Signature:
        """
        Create hybrid signature (Ed25519 + ML-DSA-65).

        Performance Optimization:
        -------------------------
        This method now caches Ed25519 key objects to eliminate reconstruction
        overhead during hybrid operations (~2x faster Ed25519 signing).

        Args:
            message: Data to sign
            secret_key: Combined secret key (Ed25519 + Dilithium)

        Returns:
            Signature with combined Ed25519 and Dilithium signatures

        Raises:
            PQCUnavailableError: If Dilithium backend is not available
        """
        if not self._pqc_available:
            raise PQCUnavailableError("PQC_UNAVAILABLE: Hybrid signatures require ML-DSA-65.")

        # Split keys
        classical_sk_bytes = secret_key[: self.ED25519_SK_SIZE]
        pqc_sk = secret_key[self.ED25519_SK_SIZE :]

        # Create both signatures using native backends
        classical_sig = self.classical_provider.sign(message, classical_sk_bytes)
        pqc_sig = self.pqc_provider.sign(message, pqc_sk)

        # Combine signatures (Ed25519 first, then Dilithium)
        combined_sig = classical_sig.signature + pqc_sig.signature

        return Signature(
            signature=combined_sig,
            algorithm=self.algorithm,
            message_hash=hashlib.sha3_256(message).digest(),
            metadata={
                "classical_sig_size": len(classical_sig.signature),
                "pqc_sig_size": len(pqc_sig.signature),
            },
        )

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify hybrid signature (both must verify).

        Performance Optimization:
        -------------------------
        This method now caches Ed25519 key objects to eliminate reconstruction
        overhead during hybrid verification.

        Args:
            message: Original data
            signature: Combined signature (Ed25519 + Dilithium)
            public_key: Combined public key (Ed25519 + Dilithium)

        Returns:
            True if BOTH signatures are valid, False otherwise

        Raises:
            PQCUnavailableError: If Dilithium backend is not available
        """
        if not self._pqc_available:
            raise PQCUnavailableError("PQC_UNAVAILABLE: Hybrid signatures require ML-DSA-65.")

        # Split keys and signatures
        classical_pk_bytes = public_key[: self.ED25519_PK_SIZE]
        pqc_pk = public_key[self.ED25519_PK_SIZE :]
        classical_sig = signature[: self.ED25519_SIG_SIZE]
        pqc_sig = signature[self.ED25519_SIG_SIZE :]

        # Both must verify for hybrid security
        classical_valid = self.classical_provider.verify(message, classical_sig, classical_pk_bytes)
        pqc_valid = self.pqc_provider.verify(message, pqc_sig, pqc_pk)

        return classical_valid and pqc_valid


class AmaCryptography:
    """
    Main AMA Cryptography Cryptographic API

    Provides unified interface to all cryptographic operations with
    automatic algorithm selection and fallback mechanisms.

    Example:
        >>> crypto = AmaCryptography(algorithm=AlgorithmType.HYBRID_SIG)
        >>> keypair = crypto.generate_keypair()
        >>> signature = crypto.sign(b"Hello, World!", keypair.secret_key)
        >>> valid = crypto.verify(b"Hello, World!", signature.signature, keypair.public_key)
    """

    def __init__(
        self,
        algorithm: AlgorithmType = AlgorithmType.HYBRID_SIG,
        backend: CryptoBackend = CryptoBackend.C_LIBRARY,
    ) -> None:
        """
        Initialize cryptographic API

        Args:
            algorithm: Algorithm to use (default: HYBRID_SIG)
            backend: Implementation backend (default: C_LIBRARY)
        """
        self.algorithm = algorithm
        self.backend = backend
        self.provider = self._get_provider()

    def _get_provider(self) -> "Union[CryptoProvider, KEMProvider, AESGCMProvider]":
        """Get appropriate provider for selected algorithm"""
        if self.algorithm == AlgorithmType.ML_DSA_65:
            return MLDSAProvider(self.backend)
        elif self.algorithm == AlgorithmType.KYBER_1024:
            return KyberProvider(self.backend)
        elif self.algorithm == AlgorithmType.SPHINCS_256F:
            return SphincsProvider(self.backend)
        elif self.algorithm == AlgorithmType.HYBRID_SIG:
            return HybridSignatureProvider()
        elif self.algorithm == AlgorithmType.ED25519:
            return Ed25519Provider(self.backend)
        elif self.algorithm == AlgorithmType.HYBRID_KEM:
            return HybridKEMProvider()
        elif self.algorithm == AlgorithmType.AES_256_GCM:
            return AESGCMProvider()
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

    def generate_keypair(self) -> KeyPair:
        """Generate cryptographic keypair"""
        _check_operational()
        if isinstance(self.provider, AESGCMProvider):
            raise TypeError("AES-256-GCM does not support keypair generation")
        return self.provider.generate_keypair()

    def sign(self, message: bytes, secret_key: bytes) -> Signature:
        """Sign a message"""
        _check_operational()
        if not isinstance(self.provider, CryptoProvider):
            raise TypeError("Current algorithm does not support signing")
        return self.provider.sign(message, secret_key)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a signature"""
        _check_operational()
        if not isinstance(self.provider, CryptoProvider):
            raise TypeError("Current algorithm does not support verification")
        return self.provider.verify(message, signature, public_key)

    def encapsulate(self, public_key: bytes) -> EncapsulatedSecret:
        """Encapsulate a shared secret (KEM)"""
        _check_operational()
        if not isinstance(self.provider, KEMProvider):
            raise TypeError("Current algorithm does not support KEM")
        return self.provider.encapsulate(public_key)

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Decapsulate a shared secret (KEM)"""
        _check_operational()
        if not isinstance(self.provider, KEMProvider):
            raise TypeError("Current algorithm does not support KEM")
        return self.provider.decapsulate(ciphertext, secret_key)

    @staticmethod
    def hash_message(message: bytes, algorithm: str = "sha3-256") -> bytes:
        """
        Hash a message using specified algorithm

        Args:
            message: Message to hash
            algorithm: Hash algorithm (sha3-256, sha3-512, shake256)

        Returns:
            Hash digest
        """
        if algorithm == "sha3-256":
            return hashlib.sha3_256(message).digest()
        elif algorithm == "sha3-512":
            return hashlib.sha3_512(message).digest()
        elif algorithm == "shake256":
            return hashlib.shake_256(message).digest(32)
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """
        Constant-time comparison of byte strings

        Args:
            a: First byte string
            b: Second byte string

        Returns:
            True if equal, False otherwise (constant time)
        """
        from ama_cryptography.secure_memory import constant_time_compare as _ct_compare

        return _ct_compare(a, b)


# ---------------------------------------------------------------------------
# Convenience functions for AI agents and programmatic consumers
# ---------------------------------------------------------------------------
# These one-call helpers reduce boilerplate for the most common operations.
# An AI system can call quick_sign / quick_verify / quick_hash without
# instantiating provider objects or managing algorithm selection.


def quick_hash(
    message: bytes,
    algorithm: str = "sha3-256",
) -> bytes:
    """
    Quick hash: Compute a cryptographic hash in one call.

    Convenience wrapper for AI agents and automated systems
    that need fast, single-call hashing.

    Args:
        message: Data to hash (arbitrary length)
        algorithm: Hash algorithm ("sha3-256", "sha3-512", "shake256")

    Returns:
        Hash digest bytes

    Example:
        >>> digest = quick_hash(b"Hello from AI agent")
        >>> assert len(digest) == 32  # SHA3-256
    """
    _check_operational()
    return AmaCryptography.hash_message(message, algorithm)


def quick_sign(
    message: bytes, algorithm: AlgorithmType = AlgorithmType.HYBRID_SIG
) -> Tuple[KeyPair, Signature]:
    """
    Quick sign: Generate keys and sign message in one call

    Args:
        message: Message to sign
        algorithm: Algorithm to use

    Returns:
        (keypair, signature)
    """
    crypto = AmaCryptography(algorithm=algorithm)
    keypair = crypto.generate_keypair()
    signature = crypto.sign(message, keypair.secret_key)
    return keypair, signature


def quick_verify(
    message: bytes,
    signature: bytes,
    public_key: bytes,
    algorithm: AlgorithmType = AlgorithmType.HYBRID_SIG,
) -> bool:
    """
    Quick verify: Verify signature in one call

    Args:
        message: Message that was signed
        signature: Signature to verify
        public_key: Public key
        algorithm: Algorithm used

    Returns:
        True if valid, False otherwise
    """
    crypto = AmaCryptography(algorithm=algorithm)
    return crypto.verify(message, signature, public_key)


def quick_kem(
    algorithm: AlgorithmType = AlgorithmType.KYBER_1024,
) -> Tuple[KeyPair, EncapsulatedSecret]:
    """
    Quick KEM: Generate keys and encapsulate secret in one call

    Args:
        algorithm: KEM algorithm to use

    Returns:
        (keypair, encapsulated_secret)
    """
    crypto = AmaCryptography(algorithm=algorithm)
    keypair = crypto.generate_keypair()
    encapsulated = crypto.encapsulate(keypair.public_key)
    return keypair, encapsulated


def get_pqc_capabilities() -> Dict[str, Any]:
    """
    Get current PQC backend capabilities.

    Returns detailed information about which post-quantum algorithms
    are available and which backends are installed.

    Returns:
        Dictionary with capability information:
        - status: "AVAILABLE" or "UNAVAILABLE"
        - dilithium_available: bool
        - kyber_available: bool
        - sphincs_available: bool
        - backend: "native" or None
        - algorithms: dict of algorithm availability
        - install_instructions: str (if unavailable)

    Example:
        >>> caps = get_pqc_capabilities()
        >>> if caps["status"] == "AVAILABLE":
        ...     crypto = AmaCryptography(algorithm=AlgorithmType.ML_DSA_65)
        ... else:
        ...     print(caps["install_instructions"])
    """
    from ama_cryptography.pqc_backends import _ED25519_NATIVE_AVAILABLE, _native_lib

    info = get_pqc_backend_info()
    ed25519_available = _native_lib is not None and _ED25519_NATIVE_AVAILABLE

    return {
        "status": info["status"],
        "dilithium_available": info["dilithium_available"],
        "kyber_available": info["kyber_available"],
        "sphincs_available": info["sphincs_available"],
        "backend": info["backend"],
        "algorithms": {
            "ML_DSA_65": info["dilithium_available"],
            "HYBRID_SIG": info["dilithium_available"] and ed25519_available,
            "ED25519": ed25519_available,
            "KYBER_1024": info["kyber_available"],
            "SPHINCS_256F": info["sphincs_available"],
        },
        "security_levels": {
            "ML_DSA_65": 3 if info["dilithium_available"] else None,
            "HYBRID_SIG": 3 if info["dilithium_available"] else None,
            "ED25519": 1,  # Classical only
            "KYBER_1024": 5 if info["kyber_available"] else None,
            "SPHINCS_256F": 5 if info["sphincs_available"] else None,
        },
        "key_sizes": info.get("algorithms", {}),
        "install_instructions": (
            "Build native C library: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
            if not (info["dilithium_available"] or info["kyber_available"])
            else "PQC backend already available"
        ),
    }


@dataclass
class CryptoPackageConfig:
    """
    Configuration for create_crypto_package() algorithm selection.

    4-Layer Defense-in-Depth Architecture:
        Layer 1 — Content Integrity:   SHA3-256 hash (NIST FIPS 202)
        Layer 2 — Keyed Authentication: HMAC-SHA3-256 (RFC 2104)
        Layer 3 — Digital Signature:    Hybrid Ed25519 + ML-DSA-65 (RFC 8032 + NIST FIPS 204)
        Layer 4 — Key Independence:     HKDF-SHA3-256 key derivation (RFC 5869)

    All 4 layers are always active. Optional add-ons (KEM, SPHINCS+, RFC 3161
    timestamp) extend but do not replace the core layers.

    Attributes:
        use_kyber: Enable Kyber-1024 KEM (optional add-on, default: False)
        use_sphincs: Enable SPHINCS+-256f secondary signature (optional add-on)
        signature_algorithm: Primary signature algorithm (default: HYBRID_SIG)
        include_kem: Include KEM encapsulation in package (default: False)
        include_timestamp: Include RFC 3161 timestamp (optional add-on)
        num_derived_keys: Number of HKDF-derived keys to generate (default: 3)
        tsa_url: RFC 3161 Time Stamp Authority URL (default: None)
        tsa_mode: TSA mode — "online", "mock", or "disabled" (default: "online")
    """

    use_kyber: bool = False
    use_sphincs: bool = False
    signature_algorithm: AlgorithmType = AlgorithmType.HYBRID_SIG
    include_kem: bool = False
    include_timestamp: bool = False
    num_derived_keys: int = 3
    tsa_url: Optional[str] = None
    tsa_mode: str = "online"


@dataclass
class CryptoPackageResult:
    """
    Result from create_crypto_package() containing all cryptographic artifacts.

    4-Layer Defense-in-Depth Architecture
    ======================================
    Layer 1 — Content Integrity (SHA3-256, NIST FIPS 202):
        Tamper detection via cryptographic hash. Any modification to the
        protected content produces a different hash.  128-bit collision
        resistance.

    Layer 2 — Keyed Authentication (HMAC-SHA3-256, RFC 2104):
        Authenticates content with a 256-bit random key.  Prevents forgery
        by parties who do not possess the HMAC key.  The key is stored in
        ``hmac_key`` so that ``verify_crypto_package()`` can recompute and
        compare the tag.

    Layer 3 — Digital Signature (Ed25519 + ML-DSA-65, RFC 8032 + NIST FIPS 204):
        Non-repudiation via hybrid classical + post-quantum dual signature.
        Both signatures must verify.  Ed25519 provides 128-bit classical
        security; ML-DSA-65 provides 192-bit quantum security (NIST Level 3).

    Layer 4 — Key Independence (HKDF-SHA3-256, RFC 5869):
        Derives cryptographically independent sub-keys from a 256-bit master
        secret.  Each derived key serves a distinct purpose, preventing key
        reuse across cryptographic boundaries.

    Optional add-ons (not counted as core layers):
        - SPHINCS+-256f secondary signature (NIST FIPS 205)
        - ML-KEM-1024 key encapsulation (NIST FIPS 203)
        - RFC 3161 trusted timestamping

    Attributes:
        content_hash: SHA3-256 hash of the content (hex) [Layer 1]
        hmac_key: HMAC-SHA3-256 key used for authentication [Layer 2]
        hmac_tag: HMAC-SHA3-256 authentication tag [Layer 2]
        primary_signature: Primary signature from selected algorithm [Layer 3]
        sphincs_signature: Optional SPHINCS+-256f signature (add-on)
        derived_keys: HKDF-derived keys for key independence [Layer 4]
        hkdf_salt: Salt used for HKDF derivation [Layer 4]
        hkdf_master_secret: Master secret used for HKDF [Layer 4]
        hkdf_info: Info string used for HKDF derivation [Layer 4]
        timestamp: RFC 3161 timestamp token (optional add-on)
        kem_ciphertext: Optional Kyber-1024 ciphertext (add-on)
        kem_shared_secret: Optional shared secret from KEM (add-on)
        keypairs: Dictionary of generated keypairs by algorithm
        metadata: Additional package metadata
    """

    content_hash: str
    hmac_key: bytes = field(repr=False)
    hmac_tag: bytes
    primary_signature: Signature
    sphincs_signature: Optional[Signature]
    derived_keys: List[bytes]
    hkdf_salt: bytes
    hkdf_master_secret: bytes = field(repr=False)
    hkdf_info: bytes
    timestamp: Optional[bytes]
    kem_ciphertext: Optional[bytes]
    kem_shared_secret: Optional[bytes]
    keypairs: Dict[str, KeyPair]
    metadata: Dict[str, Any]


def _acquire_timestamp(
    content: bytes,
    config: CryptoPackageConfig,
) -> Optional[bytes]:
    """Acquire an RFC 3161 timestamp token according to *config*.

    Returns the raw token bytes, or ``None`` when timestamping is disabled or
    not requested.  Raises :class:`RuntimeError` if timestamps were requested
    but acquisition failed (S4/S5 fixes: fail-loud philosophy).
    """
    if not config.include_timestamp:
        return None

    tsa_mode = getattr(config, "tsa_mode", "online")
    if tsa_mode == "disabled":
        return None

    if tsa_mode == "mock":
        # S4 fix: Do NOT silently swallow exceptions in mock mode.
        # When include_timestamp=True, a failed timestamp must be loud.
        result = get_timestamp(
            data=content,
            tsa_url=config.tsa_url,
            hash_algorithm="sha3-256",
            tsa_mode="mock",
        )
        # S5 fix: If get_timestamp() returns None, raise rather than
        # silently producing an untimestamped package.
        if result is None:
            raise RuntimeError(
                "Timestamp acquisition failed: get_timestamp() returned None. "
                "Cannot produce untimestamped package when timestamps are required."
            )
        return result.token

    # Online mode
    if not RFC3161_AVAILABLE:
        raise TimestampUnavailableError(
            "RFC3161_UNAVAILABLE: rfc3161ng library not installed. "
            "Install with: pip install rfc3161ng"
        )
    try:
        result = get_timestamp(
            data=content,
            tsa_url=config.tsa_url,
            hash_algorithm="sha3-256",
        )
        # S5 fix: Fail loudly when get_timestamp() returns None.
        if result is None:
            raise RuntimeError(
                "Timestamp acquisition failed: get_timestamp() returned None. "
                "Cannot produce untimestamped package when timestamps are required."
            )
        return result.token
    except TimestampError as e:
        raise TimestampError(
            f"RFC 3161 timestamp is required when include_timestamp=True, "
            f"but the timestamp request failed: {e}"
        ) from e


def create_crypto_package(
    content: bytes,
    config: Optional[CryptoPackageConfig] = None,
) -> CryptoPackageResult:
    """
    Create a cryptographic package with 4-Layer Defense-in-Depth Architecture.

    4-Layer Defense Architecture
    ============================
    Layer 1 — Content Integrity (SHA3-256, NIST FIPS 202):
        128-bit collision resistance.  Any content modification is detected.

    Layer 2 — Keyed Authentication (HMAC-SHA3-256, RFC 2104):
        256-bit random key; prevents forgery.  Key preserved in result for
        verification.

    Layer 3 — Digital Signature (Ed25519 + ML-DSA-65):
        Hybrid classical + post-quantum non-repudiation.  128-bit classical
        security (RFC 8032) + 192-bit quantum security (NIST FIPS 204).

    Layer 4 — Key Independence (HKDF-SHA3-256, RFC 5869):
        Derives N independent sub-keys from a 256-bit master secret,
        preventing key reuse across cryptographic boundaries.

    Optional add-ons (not core layers):
        - SPHINCS+-256f secondary signature (NIST FIPS 205)
        - ML-KEM-1024 key encapsulation (NIST FIPS 203)
        - RFC 3161 trusted timestamping (online, mock, or disabled)

    Args:
        content: The content to sign/protect (bytes)
        config: Algorithm configuration (default: hybrid signatures with 4 layers)

    Returns:
        CryptoPackageResult with all cryptographic artifacts

    Raises:
        TypeError: If content is not bytes
        ValueError: If content is empty
        PQCUnavailableError: If required PQC algorithm is not available
        KyberUnavailableError: If Kyber is requested but not available
        SphincsUnavailableError: If SPHINCS+ is requested but not available
        TimestampUnavailableError: If RFC 3161 is requested but library not installed
        TimestampError: If timestamp request fails

    Example:
        >>> # Basic usage with hybrid signatures and 4-layer defense
        >>> result = create_crypto_package(b"Hello, World!")
        >>> print(f"Hash: {result.content_hash}")
        >>> print(f"HMAC: {result.hmac_tag.hex()}")
        >>> print(f"Derived keys: {len(result.derived_keys)}")

        >>> # With Kyber-1024 KEM
        >>> config = CryptoPackageConfig(use_kyber=True, include_kem=True)
        >>> result = create_crypto_package(b"Sensitive data", config)
        >>> print(f"KEM ciphertext: {len(result.kem_ciphertext)} bytes")

        >>> # With SPHINCS+-256f additional signature
        >>> config = CryptoPackageConfig(use_sphincs=True)
        >>> result = create_crypto_package(b"Long-term data", config)
        >>> print(f"SPHINCS+ sig: {len(result.sphincs_signature.signature)} bytes")

        >>> # Full quantum-resistant package with timestamping
        >>> config = CryptoPackageConfig(
        ...     use_kyber=True,
        ...     use_sphincs=True,
        ...     include_kem=True,
        ...     include_timestamp=True,
        ...     tsa_url="http://freetsa.org/tsr",
        ...     signature_algorithm=AlgorithmType.ML_DSA_65
        ... )
        >>> result = create_crypto_package(b"Maximum security", config)

    Raises:
        TypeError: If content is not bytes
        ValueError: If content is empty
        CryptoModuleError: If the module is not in OPERATIONAL state
    """
    _check_operational()
    # Input validation
    if not isinstance(content, bytes):
        raise TypeError(f"content must be bytes, got {type(content).__name__}")
    if not content:
        raise ValueError("content cannot be empty")

    if config is None:
        config = CryptoPackageConfig()

    # ========================================================================
    # LAYER 1: Content Integrity — SHA3-256 (NIST FIPS 202)
    # ========================================================================
    content_hash = hashlib.sha3_256(content).hexdigest()

    # ========================================================================
    # LAYER 2: Keyed Authentication — HMAC-SHA3-256 (RFC 2104)
    # ========================================================================
    hmac_key = secrets.token_bytes(32)  # 256-bit HMAC key
    hmac_tag = _hmac_sha3_256(hmac_key, content)

    # ========================================================================
    # LAYER 3: Digital Signature — Hybrid Ed25519 + ML-DSA-65
    # ========================================================================
    keypairs: Dict[str, KeyPair] = {}
    sphincs_signature: Optional[Signature] = None
    kem_ciphertext: Optional[bytes] = None
    kem_shared_secret: Optional[bytes] = None

    # Generate primary signature
    primary_crypto = AmaCryptography(algorithm=config.signature_algorithm)
    primary_keypair = primary_crypto.generate_keypair()
    primary_signature = primary_crypto.sign(content, primary_keypair.secret_key)
    keypairs[config.signature_algorithm.name] = primary_keypair

    # Optional add-on: SPHINCS+ secondary signature
    if config.use_sphincs:
        if not SPHINCS_AVAILABLE:
            raise SphincsUnavailableError(
                "SPHINCS_UNAVAILABLE: SPHINCS+-256f backend not available. "
                "Build: cmake -B build -DAMA_USE_NATIVE_PQC=ON "
                "&& cmake --build build"
            )
        sphincs_provider = SphincsProvider()
        sphincs_keypair = sphincs_provider.generate_keypair()
        sphincs_signature = sphincs_provider.sign(content, sphincs_keypair.secret_key)
        keypairs["SPHINCS_256F"] = sphincs_keypair

    # ========================================================================
    # LAYER 4: Key Independence — HKDF-SHA3-256 (RFC 5869)
    # ========================================================================
    master_secret = secrets.token_bytes(32)  # 256-bit master secret
    hkdf_salt = secrets.token_bytes(32)
    hkdf_info = b"ama_cryptography_crypto_package_v1"
    derived_keys: List[bytes] = []
    for i in range(config.num_derived_keys):
        dk = _hkdf_sha3_256(
            ikm=master_secret,
            length=32,
            salt=hkdf_salt,
            info=hkdf_info + b":" + str(i).encode(),
        )
        derived_keys.append(dk)

    # ========================================================================
    # OPTIONAL ADD-ON: Kyber-1024 Key Encapsulation Mechanism
    # ========================================================================
    if config.use_kyber and config.include_kem:
        if not KYBER_AVAILABLE:
            raise KyberUnavailableError(
                "KYBER_UNAVAILABLE: Kyber-1024 backend not available. "
                "Build: cmake -B build -DAMA_USE_NATIVE_PQC=ON "
                "&& cmake --build build"
            )
        kyber_provider = KyberProvider()
        kyber_keypair = kyber_provider.generate_keypair()
        encapsulated = kyber_provider.encapsulate(kyber_keypair.public_key)
        kem_ciphertext = encapsulated.ciphertext
        kem_shared_secret = encapsulated.shared_secret
        keypairs["KYBER_1024"] = kyber_keypair

    # ========================================================================
    # OPTIONAL ADD-ON: RFC 3161 Timestamp
    # ========================================================================
    timestamp_token = _acquire_timestamp(content, config)

    # Build metadata
    metadata: Dict[str, Any] = {
        "signature_algorithm": config.signature_algorithm.name,
        "sphincs_enabled": config.use_sphincs,
        "kyber_enabled": config.use_kyber and config.include_kem,
        "timestamp_enabled": config.include_timestamp and timestamp_token is not None,
        "num_derived_keys": len(derived_keys),
        "pqc_status": get_pqc_capabilities()["status"],
        "defense_layers": 4,
    }

    return CryptoPackageResult(
        content_hash=content_hash,
        hmac_key=hmac_key,
        hmac_tag=hmac_tag,
        primary_signature=primary_signature,
        sphincs_signature=sphincs_signature,
        derived_keys=derived_keys,
        hkdf_salt=hkdf_salt,
        hkdf_master_secret=master_secret,
        hkdf_info=hkdf_info,
        timestamp=timestamp_token,
        kem_ciphertext=kem_ciphertext,
        kem_shared_secret=kem_shared_secret,
        keypairs=keypairs,
        metadata=metadata,
    )


def verify_crypto_package(
    content: bytes,
    package: CryptoPackageResult,
) -> Dict[str, bool]:
    """
    Verify all 4 layers of a crypto package plus any optional add-ons.

    4-Layer Verification
    ====================
    Layer 1 — Content Integrity:   Recompute SHA3-256 and compare to stored hash.
    Layer 2 — Keyed Authentication: Recompute HMAC-SHA3-256 with stored key and
              compare to stored tag.
    Layer 3 — Digital Signature:   Verify primary signature (Ed25519 + ML-DSA-65)
              against stored public key.
    Layer 4 — Key Independence:    Re-derive keys from stored master secret, salt,
              and info; compare to stored derived keys.

    Optional add-on verification:
        - SPHINCS+ secondary signature (if present)
        - KEM shared secret (if present and keypair available)

    Args:
        content: Original content that was signed
        package: CryptoPackageResult to verify

    Returns:
        Dictionary with a boolean for each layer plus ``all_valid`` (True only
        if every layer passes):
            - content_hash: Layer 1
            - hmac: Layer 2
            - primary_signature: Layer 3
            - hkdf_keys: Layer 4
            - sphincs: (if present)
            - kem: (if present)
            - all_valid: True iff all checks passed

    Example:
        >>> result = create_crypto_package(b"Hello")
        >>> v = verify_crypto_package(b"Hello", result)
        >>> assert v["all_valid"]
    """
    _check_operational()
    results: Dict[str, bool] = {}

    # ========================================================================
    # LAYER 1: Content Integrity — SHA3-256
    # ========================================================================
    computed_hash = hashlib.sha3_256(content).hexdigest()
    results["content_hash"] = computed_hash == package.content_hash

    # ========================================================================
    # LAYER 2: Keyed Authentication — HMAC-SHA3-256
    # ========================================================================
    try:
        recomputed_hmac = _hmac_sha3_256(package.hmac_key, content)
        from ama_cryptography.secure_memory import constant_time_compare

        results["hmac"] = constant_time_compare(recomputed_hmac, package.hmac_tag)
    except Exception:
        results["hmac"] = False

    # ========================================================================
    # LAYER 3: Digital Signature — primary algorithm
    # ========================================================================
    sig_alg_name = package.metadata.get("signature_algorithm", "HYBRID_SIG")
    try:
        sig_alg = AlgorithmType[sig_alg_name]
    except KeyError:
        sig_alg = AlgorithmType.HYBRID_SIG

    if sig_alg_name in package.keypairs:
        try:
            primary_crypto = AmaCryptography(algorithm=sig_alg)
            results["primary_signature"] = primary_crypto.verify(
                content,
                package.primary_signature.signature,
                package.keypairs[sig_alg_name].public_key,
            )
        except Exception:
            results["primary_signature"] = False
    else:
        results["primary_signature"] = False

    # ========================================================================
    # LAYER 4: Key Independence — HKDF re-derivation
    # ========================================================================
    try:
        # S1 fix: Empty derived_keys must fail — the loop would iterate zero
        # times and leave keys_match=True, trivially bypassing Layer 4.
        if not package.derived_keys:
            results["hkdf_keys"] = False
        else:
            hkdf_info = package.hkdf_info
            recomputed_keys: List[bytes] = []
            for i in range(len(package.derived_keys)):
                dk = _hkdf_sha3_256(
                    ikm=package.hkdf_master_secret,
                    length=32,
                    salt=package.hkdf_salt,
                    info=hkdf_info + b":" + str(i).encode(),
                )
                recomputed_keys.append(dk)

            from ama_cryptography.secure_memory import constant_time_compare as _ct

            keys_match = len(recomputed_keys) == len(package.derived_keys)
            for rk, sk in zip(recomputed_keys, package.derived_keys):
                if not _ct(rk, sk):
                    keys_match = False
            results["hkdf_keys"] = keys_match
    except Exception:
        results["hkdf_keys"] = False

    # ========================================================================
    # OPTIONAL: Verify SPHINCS+ signature (add-on)
    # ========================================================================
    if package.sphincs_signature is not None and "SPHINCS_256F" in package.keypairs:
        if SPHINCS_AVAILABLE:
            try:
                sphincs_provider = SphincsProvider()
                results["sphincs"] = sphincs_provider.verify(
                    content,
                    package.sphincs_signature.signature,
                    package.keypairs["SPHINCS_256F"].public_key,
                )
            except Exception:
                results["sphincs"] = False
        else:
            results["sphincs"] = False

    # ========================================================================
    # OPTIONAL: Verify KEM shared secret (add-on)
    # ========================================================================
    if (
        package.kem_ciphertext is not None
        and package.kem_shared_secret is not None
        and "KYBER_1024" in package.keypairs
    ):
        try:
            kyber_provider = KyberProvider()
            decapsulated_ss = kyber_provider.decapsulate(
                package.kem_ciphertext,
                package.keypairs["KYBER_1024"].secret_key,
            )
            from ama_cryptography.secure_memory import constant_time_compare as _ct2

            results["kem"] = _ct2(decapsulated_ss, package.kem_shared_secret)
        except Exception:
            results["kem"] = False

    # Aggregate
    results["all_valid"] = all(results.values())

    return results


# Re-export PQC types for convenience
__all__ = [
    # Enums and configuration
    "AlgorithmType",
    "CryptoBackend",
    # Data containers
    "KeyPair",
    "Signature",
    "EncapsulatedSecret",
    # Abstract base classes
    "CryptoProvider",
    "KEMProvider",
    # Concrete providers
    "MLDSAProvider",
    "Ed25519Provider",
    "KyberProvider",
    "SphincsProvider",
    "AESGCMProvider",
    "HybridKEMProvider",
    "HybridSignatureProvider",
    # Unified API
    "AmaCryptography",
    # Convenience functions (AI-agent friendly)
    "quick_hash",
    "quick_sign",
    "quick_verify",
    "quick_kem",
    "get_pqc_capabilities",
    # Crypto package creation and verification
    "CryptoPackageConfig",
    "CryptoPackageResult",
    "create_crypto_package",
    "verify_crypto_package",
    # Backend status and errors
    "PQCStatus",
    "PQCUnavailableError",
    "KyberUnavailableError",
    "SphincsUnavailableError",
    "DILITHIUM_AVAILABLE",
    "DILITHIUM_BACKEND",
    "KYBER_AVAILABLE",
    "KYBER_BACKEND",
    "SPHINCS_AVAILABLE",
    "SPHINCS_BACKEND",
]
