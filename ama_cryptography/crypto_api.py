#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
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

import concurrent.futures
import contextlib
import logging
import os
import pathlib
import sys
import threading
import time
import warnings
from _thread import LockType
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, ClassVar, Dict, List, Mapping, Optional, Tuple, Union

from ama_cryptography._finalizer_health import record_finalizer_error as _record_finalizer_error
from ama_cryptography._module_state import check_operational as _check_operational
from ama_cryptography._module_state import secure_token_bytes
from ama_cryptography.monitor import AmaCryptographyMonitor, create_monitor

# Module-level 3R monitor instance — feeds timing data to anomaly detection.
#
# A corrupt / torn / oversized / unwritable persisted nonce ledger
# (~/.ama_cryptography/nonce_tracker.dat) must NOT brick the entire library at
# import.  The persistent ledger is a cross-restart defense-in-depth feature
# whose history is already unrecoverable once the file is corrupt (a torn
# append after a crash or power-loss needs no attacker), and an unresolvable or
# read-only HOME is an environment fault, not a cryptographic one — so a
# failure to load it degrades the monitor to in-memory-only nonce tracking with
# a logged warning rather than aborting `import ama_cryptography`.  The strict
# fail-closed RuntimeError still fires for a caller who explicitly constructs a
# persistent NonceTracker / monitor with a good path.  (2026-08 v5 audit,
# item 15 — corrupt-ledger availability defect.)
try:
    _monitor: AmaCryptographyMonitor = create_monitor(enabled=True)
except Exception as _monitor_persist_exc:  # noqa: BLE001 -- degrade, never brick import (AUDIT-15)
    logging.getLogger(__name__).warning(
        "monitor persistence unavailable (%s: %s); continuing with in-memory-only "
        "nonce tracking. Persistent cross-restart nonce-reuse detection is disabled "
        "until the backing file is repaired or removed.",
        type(_monitor_persist_exc).__name__,
        _monitor_persist_exc,
    )
    try:
        _monitor = AmaCryptographyMonitor(enabled=True, nonce_persist_path=os.devnull)
    except (
        Exception
    ):  # noqa: BLE001 -- last resort: monitoring off, library still imports (AUDIT-15)
        _monitor = create_monitor(enabled=False)

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

from ama_cryptography.pqc_backends import (
    _native_lib,
    native_ed25519_batch_verify,
    native_ed25519_keypair,
    native_ed25519_keypair_from_seed,
    native_ed25519_sign,
    native_ed25519_verify,
    native_hkdf,
    native_hmac_sha3_256,
    native_sha3_256,
    native_sha256,
)

_HMAC_NATIVE = _HMAC_SHA3_256_NATIVE_AVAILABLE
_HKDF_NATIVE = _HKDF_NATIVE_AVAILABLE

# INVARIANT-7 module-level flag: set once during import, checked per-call
# without re-importing. Eliminates ~200-500ns import machinery overhead.
_INVARIANT7_OK: bool = _native_lib is not None

# Deprecation warning for AMA_REQUIRE_CONSTANT_TIME is emitted by
# pqc_backends.py at import time; no need to duplicate it here.


# INVARIANT-7 (revised): No cryptographic fallbacks, ever.
# When native constant-time backend is unavailable the library MUST refuse to
# operate.  Pure-Python fallback for any cryptographic primitive is prohibited.
#
# Documentation exception: Sphinx autodoc needs to import the module to
# extract docstrings.  The guard's purpose is to refuse *cryptographic calls*
# without a constant-time backend; introspection for docs is orthogonal to
# that guarantee.  Setting AMA_SPHINX_BUILD=1 (or SPHINX_BUILD=1) permits the
# import, but every call-time path still invokes _enforce_invariant7(), which
# will raise if the native library is truly absent.  The env-var check
# requires an explicit truthy value ("1"/"true"/"yes"/"on") so that an
# accidental ``AMA_SPHINX_BUILD=0`` / ``=false`` does NOT bypass the
# fail-closed import guard.
def _env_flag_enabled(name: str) -> bool:
    """Return True only for an explicit truthy env value.

    Required for INVARIANT-7 fail-closed semantics: mere presence of the
    variable must not disable the import guard — only an opt-in value does.
    """
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


_AMA_DOCS_IMPORT = _env_flag_enabled("AMA_SPHINX_BUILD") or _env_flag_enabled("SPHINX_BUILD")
if not _AMA_DOCS_IMPORT and (not _HMAC_NATIVE or not _HKDF_NATIVE):
    raise RuntimeError(
        "INVARIANT-7: Native HMAC/HKDF C accelerators are unavailable. "
        "The library refuses to operate without a constant-time backend. "
        "Build the native C library: "
        "cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
    )


def _hmac_sha3_256(key: bytes, msg: bytes) -> bytes:
    """HMAC-SHA3-256 via native C backend (RFC 2104).

    INVARIANT-1: This function MUST NOT use ``import hmac`` (the stdlib
    module).  All cryptographic primitives delegate to the native C
    backend (INVARIANT-7 revised: no pure-Python fallbacks).

    INVARIANT-12: This is a secret-dependent operation; the native
    backend provides constant-time guarantees.
    """
    _enforce_invariant7()
    return native_hmac_sha3_256(key, msg)


def _hkdf_sha3_256(
    ikm: bytes,
    length: int,
    salt: "Optional[bytes]" = None,
    info: bytes = b"",
) -> bytes:
    """HKDF-SHA3-256 via native C backend (RFC 5869).

    INVARIANT-7 revised: no pure-Python fallback.  The import-time
    guard above ensures the native backend is always available.
    """
    _enforce_invariant7()
    return native_hkdf(ikm, length, salt=salt, info=info)


HMAC_HKDF_AVAILABLE = True  # Guaranteed by INVARIANT-7 import-time check


def _enforce_invariant7() -> None:
    """INVARIANT-7 call-time enforcement: refuse to operate if native backends
    are no longer reachable.

    Uses a module-level boolean flag set during import to avoid per-call
    import machinery overhead (~200-500ns savings per call).  Also checks
    ``pqc_backends._native_lib`` through ``sys.modules`` so that runtime
    patches (e.g. in tests via ``unittest.mock.patch``) are respected—
    patching the attribute on the *module* object changes
    ``pqc_backends._native_lib`` but not the local binding imported at
    the top of this file.
    """
    _pb = sys.modules["ama_cryptography.pqc_backends"]
    if not _INVARIANT7_OK or getattr(_pb, "_native_lib", None) is None:
        raise RuntimeError(
            "INVARIANT-7 (call-time): Native C cryptographic library is not loaded. "
            "The library refuses to operate without a constant-time backend. "
            "Build the native C library: "
            "cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
        )


# Import RFC 3161 timestamping
try:
    from ama_cryptography.rfc3161_timestamp import (
        RFC3161_AVAILABLE,
        TimestampError,
        TimestampUnavailableError,
        get_timestamp,
    )
except ImportError:
    # Not "the optional dependency is missing" any more: RFC 3161 is a
    # first-party module in this same package, implemented on AMA's own DER
    # codec, and the third-party `rfc3161ng` client was removed under
    # INVARIANT-1. Reaching this branch means the in-tree module failed to
    # import, i.e. a broken installation — not a supported configuration.
    RFC3161_AVAILABLE = False
    TimestampUnavailableError = Exception  # type: ignore[misc,assignment]  # in-tree RFC 3161 module failed to import, Exception fallback (CA-001)
    TimestampError = Exception  # type: ignore[misc,assignment]  # in-tree RFC 3161 module failed to import, Exception fallback (CA-002)
    get_timestamp = None  # type: ignore[assignment]  # in-tree RFC 3161 module failed to import, None stub (CA-003)

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
    def sign(self, message: bytes, secret_key: Union[bytes, bytearray]) -> Signature:
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
    def decapsulate(self, ciphertext: bytes, secret_key: Union[bytes, bytearray]) -> bytes:
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
        _enforce_invariant7()
        if not self._available:
            raise PQCUnavailableError(
                "PQC_UNAVAILABLE: ML-DSA-65 requires native C backend. "
                "Build: cmake -B build -DAMA_USE_NATIVE_PQC=ON "
                "&& cmake --build build"
            )

        kp = generate_dilithium_keypair()
        # Copy secret_key to detach from DilithiumKeyPair's bytearray;
        # DilithiumKeyPair.__del__ wipes its own copy on scope exit.
        return KeyPair(
            public_key=kp.public_key,
            secret_key=bytes(kp.secret_key),
            algorithm=self.algorithm,
            metadata={
                "backend": self._backend_name,
                "key_size": len(kp.public_key),
                "algorithm": "ML-DSA-65",
                "security_level": 3,
            },
        )

    def sign(
        self,
        message: bytes,
        secret_key: Union[bytes, bytearray],
        precomputed_hash: Optional[bytes] = None,
    ) -> Signature:
        """
        Sign message with ML-DSA-65.

        Args:
            message: Data to sign
            secret_key: Dilithium private key (4032 bytes)
            precomputed_hash: Optional pre-computed SHA3-256 hash of message.
                When provided, skips redundant hash computation (~2x savings).

        Returns:
            Signature object with Dilithium signature

        Raises:
            PQCUnavailableError: If no Dilithium backend is available
        """
        _enforce_invariant7()
        if not self._available:
            raise PQCUnavailableError("PQC_UNAVAILABLE: ML-DSA-65 requires native C backend.")

        sig_bytes = dilithium_sign(message, secret_key)
        message_hash = (
            precomputed_hash if precomputed_hash is not None else native_sha3_256(message)
        )

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
        _enforce_invariant7()
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

        from ama_cryptography.pqc_backends import _ED25519_NATIVE_AVAILABLE

        if not (_native_lib is not None and _ED25519_NATIVE_AVAILABLE):
            raise RuntimeError(
                "Ed25519 native C backend not available. "
                "Build with: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
            )

    def generate_keypair(self) -> KeyPair:
        """Generate Ed25519 keypair using native C backend."""
        _enforce_invariant7()
        pk_bytes, sk_bytes = native_ed25519_keypair()
        # Return 32-byte seed as secret_key for API consistency
        # The full 64-byte key is seed || public_key
        return KeyPair(
            public_key=pk_bytes,
            secret_key=sk_bytes[:32],
            algorithm=self.algorithm,
            metadata={"backend": "native_c", "key_size": 32},
        )

    def sign(
        self,
        message: bytes,
        secret_key: Union[bytes, bytearray],
        precomputed_hash: Optional[bytes] = None,
    ) -> Signature:
        """
        Sign message with Ed25519 using native C backend.

        Args:
            message: Data to sign
            secret_key: 32-byte Ed25519 seed or 64-byte native key
            precomputed_hash: Optional pre-computed SHA3-256 hash of message.
                When provided, skips redundant hash computation (~2x savings).

        Returns:
            Signature object with Ed25519 signature
        """
        _enforce_invariant7()
        # Handle 32-byte seed: expand to 64-byte native format
        if len(secret_key) == 32:
            _, full_sk = native_ed25519_keypair_from_seed(bytes(secret_key))
        elif len(secret_key) == 64:
            full_sk = bytes(secret_key) if isinstance(secret_key, bytearray) else secret_key
        else:
            raise ValueError(f"Ed25519 secret key must be 32 or 64 bytes, got {len(secret_key)}")

        sig_bytes = native_ed25519_sign(message, full_sk)
        message_hash = (
            precomputed_hash if precomputed_hash is not None else native_sha3_256(message)
        )

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
        _enforce_invariant7()
        try:
            return native_ed25519_verify(signature, message, public_key)
        except ValueError:
            return False

    @staticmethod
    def batch_verify(
        entries: "list[tuple[bytes, bytes, bytes]]",
    ) -> "list[bool]":
        """
        Batch verify multiple Ed25519 signatures.

        This is intentionally non-constant-time (vartime) because verification
        scalars are public. Enables batch anomaly result verification.

        Args:
            entries: List of (message, signature, public_key) tuples.

        Returns:
            List of bools — True if corresponding signature is valid.
        """
        _enforce_invariant7()
        return native_ed25519_batch_verify(entries)


def batch_verify_ed25519(
    entries: "list[tuple[bytes, bytes, bytes]]",
) -> "list[bool]":
    """
    Batch verify multiple Ed25519 signatures via native C backend.

    Standalone convenience function wrapping Ed25519Provider.batch_verify().
    Intentionally non-constant-time (vartime) — verification scalars are public.

    Args:
        entries: List of (message, signature, public_key) tuples.
            - message: bytes — data that was signed
            - signature: 64-byte Ed25519 signature
            - public_key: 32-byte Ed25519 public key

    Returns:
        List of bools — True if corresponding signature is valid.

    Raises:
        RuntimeError: If native library is not available
        ValueError: If any entry has invalid lengths
    """
    _enforce_invariant7()
    return native_ed25519_batch_verify(entries)


def _kc_secure_memzero(buf: bytearray) -> None:
    """Zero a bytearray in-place."""
    for i in range(len(buf)):
        buf[i] = 0


class KeypairCache:
    """Thread-safe cache for signing keypairs within a session.

    Useful for agents (e.g. Mercury Agent) that sign many results with
    the same identity, avoiding the ~1-2ms keypair generation cost per call.

    INVARIANT-6: secret key stored as mutable ``bytearray`` and securely
    zeroed on ``rotate()`` and ``__del__``.

    Usage::

        cache = KeypairCache()  # default: HYBRID_SIG
        pk, sk = cache.get_or_generate()

        config = CryptoPackageConfig(signing_keypair=(pk, sk))
        result = create_crypto_package(content, config)

        # Rotate when identity changes or on schedule
        cache.rotate()
    """

    def __init__(self, algorithm: AlgorithmType = AlgorithmType.HYBRID_SIG) -> None:
        self._algorithm = algorithm
        self._lock = threading.Lock()
        self._pk: Optional[bytes] = None
        self._sk: Optional[bytearray] = None

    def _wipe_sk(self) -> None:
        """Zero secret key material in-place via _kc_secure_memzero."""
        if self._sk is not None and len(self._sk) > 0:
            _kc_secure_memzero(self._sk)
            self._sk = None

    def get_or_generate(self) -> Tuple[bytes, bytes]:
        """Return cached keypair, generating one if needed.

        Returns an immutable ``bytes`` copy of the secret key.  The caller's
        copy cannot be securely wiped by ``rotate()``/``__del__``; the cache
        controls the only wipeable ``bytearray`` reference internally.
        """
        _enforce_invariant7()
        with self._lock:
            if self._pk is None or self._sk is None:
                crypto = AmaCryptography(algorithm=self._algorithm)
                kp = crypto.generate_keypair()
                self._pk = kp.public_key
                self._sk = bytearray(kp.secret_key)
            return (self._pk, bytes(self._sk))

    def rotate(self) -> None:
        """Securely zero and discard cached keypair."""
        with self._lock:
            self._wipe_sk()
            self._pk = None

    def __del__(self) -> None:
        try:
            self._wipe_sk()
        except Exception as exc:
            _record_finalizer_error("KeypairCache", f"wipe failed: {exc}")


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
        _enforce_invariant7()
        keypair = generate_kyber_keypair()

        # Copy secret_key to detach from KyberKeyPair's bytearray;
        # KyberKeyPair.__del__ wipes its own copy on scope exit.
        return KeyPair(
            public_key=keypair.public_key,
            secret_key=bytes(keypair.secret_key),
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
        _enforce_invariant7()
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

    def decapsulate(self, ciphertext: bytes, secret_key: Union[bytes, bytearray]) -> bytes:
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
        _enforce_invariant7()
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
        _enforce_invariant7()
        keypair = generate_sphincs_keypair()

        # Copy secret_key to detach from SphincsKeyPair's bytearray;
        # SphincsKeyPair.__del__ wipes its own copy on scope exit.
        return KeyPair(
            public_key=keypair.public_key,
            secret_key=bytes(keypair.secret_key),
            algorithm=self.algorithm,
            metadata={
                "backend": SPHINCS_BACKEND,
                "public_key_size": SPHINCS_PUBLIC_KEY_BYTES,
                "secret_key_size": SPHINCS_SECRET_KEY_BYTES,
            },
        )

    def sign(
        self,
        message: bytes,
        secret_key: Union[bytes, bytearray],
        precomputed_hash: Optional[bytes] = None,
    ) -> Signature:
        """
        Sign message with SPHINCS+-256f.

        Args:
            message: Data to sign (arbitrary length)
            secret_key: SPHINCS+-256f secret key (128 bytes)
            precomputed_hash: Optional pre-computed SHA3-256 hash of message.
                When provided, skips redundant hash computation (~2x savings).

        Returns:
            Signature object with 49856-byte signature

        Raises:
            SphincsUnavailableError: If SPHINCS+ backend is not available
            ValueError: If secret_key has incorrect length
        """
        _enforce_invariant7()
        sig_bytes = sphincs_sign(message, secret_key)
        message_hash = (
            precomputed_hash if precomputed_hash is not None else native_sha3_256(message)
        )

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
        _enforce_invariant7()
        return sphincs_verify(message, signature, public_key)


def _atomic_write_json(
    data: Mapping[str, object],
    target: pathlib.Path,
    *,
    tmp_prefix: str = ".counters_",
) -> None:
    """Atomically write *data* as JSON to *target* via temp-file + rename.

    Guards the ``os.fdopen`` call so the raw file descriptor is closed if
    ``fdopen`` itself fails, preventing fd leaks.
    """
    import json as _json
    import tempfile

    fd, tmp_path = tempfile.mkstemp(dir=str(target.parent), suffix=".tmp", prefix=tmp_prefix)
    try:
        f = os.fdopen(fd, "w")
    except BaseException:
        os.close(fd)
        try:
            os.unlink(tmp_path)
        except OSError:
            pass  # best-effort cleanup; don't mask the original fdopen error
        raise
    _rename_ok = False
    try:
        with f:
            _json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, str(target))
        _rename_ok = True
    finally:
        if not _rename_ok:
            try:
                os.unlink(tmp_path)
            except OSError as _unlink_err:
                logger.debug("Failed to clean up temp file %s: %s", tmp_path, _unlink_err)


class AESGCMProvider:
    """
    AES-256-GCM authenticated encryption provider.

    Provides symmetric authenticated encryption with associated data (AEAD).
    Uses native C backend (NIST SP 800-38D). Requires the native C library;
    raises RuntimeError if not available.

    Security: 256-bit key, 96-bit nonce, 128-bit auth tag
    Standard: NIST SP 800-38D

    **Multi-process nonce safety (hardened).**

    Every encryption acquires a per-key counter slot atomically via an
    inter-process file lock: the on-disk counter is reloaded under the
    lock, incremented, persisted, and the lock released — *before* the
    nonce is generated or the AEAD is invoked.  This closes the
    previous race window where two processes sharing the same key could
    each load the same baseline N, encrypt independently, and write
    back ``max(N+a, N+b)`` instead of ``N+a+b``, undercounting total
    nonce usage and risking birthday-bound violations before the 2^32
    safety limit triggered.

    The lock is held only for the read-modify-write transaction on the
    counter file (microseconds in the steady state), not for the AEAD
    call itself, so contention between concurrent encrypters is
    minimal.  Single-process callers see no functional change; ephemeral
    mode (``configure_ephemeral(True)`` or ``ephemeral=True`` in the
    constructor) still bypasses all disk I/O for hermetic tests.

    Threading: in-memory counter dict mutations are also protected by
    a per-class ``threading.Lock`` so multi-threaded encrypt on the
    same key from one process is serialised consistently with the
    inter-process file lock.

    The counter file must be writable only by the encrypting principal: the
    read-modify-write is atomic across processes, but a file-based counter
    cannot detect an offline rollback or deletion of its own state (see
    INVARIANT-22).
    """

    _NONCE_SAFETY_LIMIT: int = 2**32
    _encrypt_counters: ClassVar[Dict[bytes, int]] = {}
    _counters_persist_path: ClassVar[Optional[str]] = None
    _counters_loaded: ClassVar[bool] = False
    _atexit_registered: ClassVar[bool] = False
    _ephemeral: ClassVar[bool] = False
    # Process-local lock protecting in-memory counter mutations and
    # serialising the slot-reservation transaction against parallel
    # threads inside the SAME process.  The file lock (fcntl.flock)
    # protects between processes; this protects within one process.
    _counter_lock: ClassVar[LockType] = threading.Lock()

    @classmethod
    def configure_ephemeral(cls, enabled: bool = True) -> None:
        """Configure ephemeral mode BEFORE any instantiation (S6 fix).

        When ephemeral mode is enabled, no disk I/O occurs for counter
        persistence — counters live only in memory.  This must be called
        before ``__init__`` so that ``_load_persisted_counters()`` and
        ``atexit`` registration respect the flag.

        .. warning::
            Call this method **before** any encryption operations.
            Switching to ephemeral mode while non-ephemeral counters exist
            would clear accumulated counters, risking nonce reuse.

        Raises:
            RuntimeError: If switching to ephemeral mode while non-ephemeral
                counters exist (counters non-empty and not already ephemeral).
        """
        if enabled and not cls._ephemeral and cls._encrypt_counters:
            raise RuntimeError(
                "Cannot switch to ephemeral mode while non-ephemeral counters exist. "
                "This would clear accumulated nonce counters and risk nonce reuse. "
                "Call configure_ephemeral(True) BEFORE any encryption operations."
            )
        cls._ephemeral = enabled
        cls._counters_loaded = False
        cls._atexit_registered = False
        cls._encrypt_counters = {}

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
        """Load persisted encrypt counters from disk (no locking).

        Bootstrap-only: called once during ``__init__`` to populate the
        in-memory dict.  The slot-reservation path
        (:meth:`_reserve_counter_slot`) re-reads under the file lock
        before every encrypt, so a stale baseline from this load
        cannot cause undercounting.
        """
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
    def _acquire_file_lock(cls, lock_fd: int) -> None:
        """Acquire an exclusive flock on ``lock_fd`` (blocking).

        Tries ``fcntl.flock`` on POSIX, ``msvcrt.locking`` on Windows.
        Fail-closed if no supported OS lock can be acquired.  A noisy
        warning-only fallback would recreate the exact cross-process
        nonce race this persistence path exists to close.
        """
        try:
            import fcntl

            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            return
        except ImportError:
            pass  # POSIX flock unavailable — try Windows
        except OSError as _lock_err:
            raise RuntimeError(
                "AES-GCM counter file lock (fcntl) failed; refusing to encrypt because "
                "multi-process nonce safety cannot be guaranteed"
            ) from _lock_err
        try:
            import msvcrt  # Windows-only stdlib module

            msvcrt.locking(lock_fd, msvcrt.LK_LOCK, 1)  # type: ignore[attr-defined]  # Windows-only attr (CA-004)
            return
        except (ImportError, OSError) as _lock_err:
            raise RuntimeError(
                "AES-GCM counter file lock unavailable (no working fcntl or msvcrt); "
                "refusing to encrypt because multi-process nonce safety cannot be guaranteed"
            ) from _lock_err

    @classmethod
    @contextlib.contextmanager
    def _counter_file_lock(cls) -> "Any":
        """Acquire the inter-process counter file lock + the thread lock.

        Ephemeral mode: only the thread lock is taken (no disk file is
        opened).  In all modes the thread lock is taken FIRST so
        nested thread-level acquisitions inside the same process
        don't deadlock against the kernel-level file lock.
        """
        # The thread lock keeps multi-threaded code inside a single
        # process from racing the in-memory dict mutation against a
        # parallel thread that also holds the file lock.  Acquiring it
        # before the file lock keeps lock ordering consistent and
        # prevents thread-vs-file-lock interleavings.
        with cls._counter_lock:
            if cls._ephemeral:
                yield
                return
            import os as _os

            path = cls._get_persist_path()
            lock_path = path.parent / ".counters.lock"
            lock_fd = _os.open(str(lock_path), _os.O_CREAT | _os.O_RDWR, 0o600)
            try:
                cls._acquire_file_lock(lock_fd)
                yield
            finally:
                # Closing the fd implicitly releases an fcntl.flock —
                # POSIX semantics.  On Windows the msvcrt.locking
                # region is also released on close, so a single close
                # suffices for both backends.
                _os.close(lock_fd)

    @classmethod
    def _reload_counters_under_lock(cls, *, raising: bool) -> None:
        """Merge on-disk counters into the in-memory dict (caller holds the lock).

        Caller MUST hold the file lock (via :meth:`_counter_file_lock`).
        This method does the unsynchronised read — splitting load from
        lock acquisition keeps the lock-acquire path testable.

        Args:
            raising: If True (encrypt path), propagate corrupt-file
                errors so the caller refuses to encrypt.  If False
                (atexit path), preserve the corrupt file for forensic
                analysis and proceed with in-memory state.
        """
        import json as _json
        import os as _os

        path = cls._get_persist_path()
        try:
            with open(path) as f:
                on_disk = _json.load(f)
            for key_hex, count in on_disk.items():
                key_id = bytes.fromhex(key_hex)
                cls._encrypt_counters[key_id] = max(cls._encrypt_counters.get(key_id, 0), count)
        except FileNotFoundError:
            logger.debug("No existing counter file at %s — first write", path)
        except (_json.JSONDecodeError, ValueError, KeyError, TypeError) as _merge_err:
            if raising:
                raise RuntimeError(
                    f"Corrupt AES-GCM counter file at {path}: {_merge_err}. "
                    "Cannot safely merge counters — manual inspection required."
                ) from _merge_err
            # atexit path: preserve corrupt file for forensic analysis
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

    @classmethod
    def _write_counters_under_lock(cls) -> None:
        """Atomic-write the in-memory counter dict to disk (caller holds the lock).

        Caller MUST hold the file lock (via :meth:`_counter_file_lock`).
        ``_atomic_write_json`` does temp-file + ``os.replace``, so
        either the previous file remains intact or the new file fully
        replaces it.
        """
        path = cls._get_persist_path()
        data = {k.hex(): v for k, v in cls._encrypt_counters.items()}
        _atomic_write_json(data, path)

    @classmethod
    def _reserve_counter_slot(cls, key_id: bytes) -> int:
        """Atomically reserve one counter slot for ``key_id`` and persist it.

        Returns the reserved counter value (which the caller may then
        consume).  After this returns:

          * The on-disk counter for ``key_id`` is the slot+1
            high-water mark.  No subsequent encrypt — in this or any
            other process — can reuse the same slot.
          * The in-memory dict mirrors the on-disk value.

        Failure modes:
          * ``RuntimeError`` if the safety limit (2^32) is reached.
            No slot is consumed.
          * ``RuntimeError`` if the on-disk counter file is corrupt.
            No slot is consumed.
          * ``RuntimeError`` if the disk write fails.  The in-memory
            increment is rolled back so the caller does not encrypt
            with a slot that was never durably persisted.

        Ephemeral mode skips disk I/O and uses only the in-memory
        counter; in that mode the per-process race surface is
        unchanged from the pre-existing single-process design.
        """
        with cls._counter_file_lock():
            if not cls._ephemeral:
                # Reload from disk under the lock so we see any slot
                # reservations made by other processes after our last
                # write.  This is the critical step that closes the
                # multi-process race.
                cls._reload_counters_under_lock(raising=True)

            count = cls._encrypt_counters.get(key_id, 0)
            if count >= cls._NONCE_SAFETY_LIMIT:
                raise RuntimeError(
                    f"AES-GCM nonce safety limit ({cls._NONCE_SAFETY_LIMIT}) "
                    f"reached for this key. Re-key required."
                )
            if count >= int(cls._NONCE_SAFETY_LIMIT * 0.75):
                logger.warning(
                    "AES-GCM nonce count approaching safety limit (%d / %d). "
                    "Re-key recommended.",
                    count,
                    cls._NONCE_SAFETY_LIMIT,
                )

            # Reserve the slot in memory FIRST so a concurrent thread
            # in this process (already past the thread lock acquire
            # since we hold it) cannot race us — well, the thread
            # lock already prevents that, but the +1 is the durable
            # commitment.
            cls._encrypt_counters[key_id] = count + 1

            if not cls._ephemeral:
                try:
                    cls._write_counters_under_lock()
                except Exception as exc:
                    # Roll the in-memory increment back so a later
                    # reserve doesn't see a count that was never
                    # durably persisted.  Better to refuse the
                    # encrypt than to issue ciphertext whose slot
                    # could be reused after restart.
                    cls._encrypt_counters[key_id] = count
                    raise RuntimeError(
                        f"Failed to persist AES-GCM counter slot for this key: "
                        f"{exc}.  No slot reserved; counter unchanged."
                    ) from exc

            return count

    @classmethod
    def _persist_counters(cls, *, _raising: bool = False) -> None:
        """Persist in-memory counters to disk under the file lock.

        Used by the ``atexit`` handler to flush the final in-memory
        state on interpreter shutdown.  The encrypt path no longer
        relies on this — :meth:`_reserve_counter_slot` persists each
        slot immediately under the same lock — so the on-disk file
        is always current; this method is a defence-in-depth flush
        that captures any in-memory state mutated outside the
        reservation path (e.g. tests that poke ``_encrypt_counters``
        directly).

        Args:
            _raising: If True, propagate write failures as
                ``RuntimeError`` instead of logging a warning.
                The atexit handler passes False (default) because
                raising during interpreter shutdown is unsafe.
        """
        if cls._ephemeral:
            return

        path = cls._get_persist_path()
        try:
            with cls._counter_file_lock():
                cls._reload_counters_under_lock(raising=_raising)
                cls._write_counters_under_lock()
        except Exception as e:
            if _raising:
                raise RuntimeError(
                    f"Failed to persist AES-GCM counters to {path}: {e}. "
                    "Counter tracking cannot guarantee nonce safety without durable persistence."
                ) from e
            logger.warning("Failed to persist AES-GCM counters: %s", e)

    def encrypt(
        self,
        plaintext: bytes,
        key: bytes,
        nonce: "Optional[bytes]" = None,
        aad: bytes = b"",
    ) -> "dict":
        """
        Encrypt plaintext with AES-256-GCM.

        Multi-process / multi-thread safe: the per-key counter slot
        is reserved atomically via :meth:`_reserve_counter_slot`
        BEFORE the AEAD runs.  That reservation acquires an
        inter-process file lock, re-reads the on-disk counter,
        increments, and persists — so two processes (or threads)
        encrypting with the same key cannot race the in-memory
        counter against the persisted value.  The slot is committed
        to disk before any nonce is generated or any plaintext is
        consumed, so even a crash mid-encrypt cannot leave a slot
        that gets reused after restart.

        Args:
            plaintext: Data to encrypt
            key: 32-byte AES-256 key
            nonce: 12-byte nonce (auto-generated if None)
            aad: Additional authenticated data

        Returns:
            Dict with 'ciphertext', 'nonce', 'tag', 'aad' keys

        Raises:
            RuntimeError: If the per-key counter would exceed the
                2^32 safety limit, the on-disk counter file is
                corrupt, persistence fails, or the provider state
                was inherited across ``os.fork()``.
        """
        _enforce_invariant7()

        # Fork detection: refuse to reuse nonce state after os.fork()
        if os.getpid() != self._pid_at_init:
            raise RuntimeError(
                "AES-GCM nonce counter state was inherited across fork(). "
                "Create a new AESGCMProvider in the child process to avoid nonce reuse. "
                "For multi-process deployments, use per-process key partitioning."
            )

        if len(key) != 32:
            raise ValueError(f"AES-256 key must be 32 bytes, got {len(key)}")

        if nonce is not None and len(nonce) != 12:
            raise ValueError(f"AES-256-GCM nonce must be 12 bytes, got {len(nonce)}")

        # SHA-256 (NOT SHA3-256): key_id is the persisted namespace for the
        # AES-GCM nonce-counter high-water mark. native_sha256 is byte-identical
        # to hashlib.sha256, so on-disk counters keep matching across the
        # upgrade; switching the algorithm would remap every key to a fresh
        # counter, reset the 2^32 birthday-safety limit, and risk random-nonce
        # reuse (INVARIANT-1: native, no stdlib hashlib).
        key_id: bytes = native_sha256(key)

        # Reserve a counter slot atomically.  This is the critical
        # change vs. the previous "increment in memory, batch-persist
        # every 64 calls" design.  On return, the disk reflects
        # slot+1 and no concurrent process can issue the same slot.
        # If reservation raises (corrupt file, full disk, safety
        # limit), no nonce has been generated and no AEAD has run.
        AESGCMProvider._reserve_counter_slot(key_id)

        # Generate the random nonce only after the durable counter
        # reservation succeeds, so failed persistence cannot consume
        # entropy or leave an untracked nonce candidate in caller state.
        #
        # INVARIANT-41: drawn through the health-tested, error-state-gated
        # CSPRNG.  The counter machinery above bounds how MANY nonces a key
        # may see; it never inspects their values, so a stuck DRBG repeating a
        # nonce under one key — keystream reuse plus GHASH-subkey recovery —
        # would pass every check here.  The continuous repeated-output test is
        # the only control that can see it.
        if nonce is None:
            nonce = secure_token_bytes(12)

        from ama_cryptography.pqc_backends import native_aes256_gcm_encrypt

        ct, tag = native_aes256_gcm_encrypt(key, nonce, plaintext, aad)

        return {
            "ciphertext": ct,
            "nonce": nonce,
            "tag": tag,
            "aad": aad,
            "backend": "native_c",
        }

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
        _enforce_invariant7()
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

    Key layout::

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
        _enforce_invariant7()
        from ama_cryptography.pqc_backends import native_x25519_keypair

        x25519_pk, x25519_sk = native_x25519_keypair()
        kyber_kp = generate_kyber_keypair()

        combined_pk: bytes = x25519_pk + kyber_kp.public_key
        # Copy kyber secret_key to bytes to detach from KyberKeyPair's bytearray
        combined_sk: bytes = (
            x25519_sk + x25519_pk + bytes(kyber_kp.secret_key) + kyber_kp.public_key
        )

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
        _enforce_invariant7()
        from ama_cryptography.pqc_backends import (
            native_x25519_key_exchange,
            native_x25519_keypair,
        )

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

    def decapsulate(self, ciphertext: bytes, secret_key: Union[bytes, bytearray]) -> bytes:
        """Split ciphertext and secret key, recover both shared secrets, combine."""
        _enforce_invariant7()
        from ama_cryptography.pqc_backends import native_x25519_key_exchange

        # Split ciphertext
        x25519_eph_pub: bytes = ciphertext[: self._X25519_KEY_BYTES]
        kyber_ct: bytes = ciphertext[self._X25519_KEY_BYTES :]

        # Split secret key: x25519_sk (32) || x25519_pk (32) || kyber_sk || kyber_pub
        # Convert to bytes once — secret_key may be bytearray (INVARIANT-6)
        sk_bytes = bytes(secret_key)
        x25519_sk: bytes = sk_bytes[: self._X25519_KEY_BYTES]
        x25519_pub: bytes = sk_bytes[self._X25519_KEY_BYTES : 2 * self._X25519_KEY_BYTES]
        kyber_sk: bytes = sk_bytes[
            2 * self._X25519_KEY_BYTES : 2 * self._X25519_KEY_BYTES + KYBER_SECRET_KEY_BYTES
        ]
        kyber_pub: bytes = sk_bytes[2 * self._X25519_KEY_BYTES + KYBER_SECRET_KEY_BYTES :]

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
    ED25519_FULL_SK_SIZE = 64  # expanded native form: seed || public key
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
        _enforce_invariant7()
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

    # Module-level thread pool for parallel hybrid verification (Item 9).
    # Shared across all HybridSignatureProvider instances to avoid per-call
    # pool creation overhead.
    _verify_pool: ClassVar[concurrent.futures.ThreadPoolExecutor] = (
        concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="hybrid_verify")
    )

    def sign(
        self,
        message: bytes,
        secret_key: Union[bytes, bytearray],
        precomputed_hash: Optional[bytes] = None,
    ) -> Signature:
        """
        Create hybrid signature (Ed25519 + ML-DSA-65).

        Args:
            message: Data to sign
            secret_key: Combined secret key (Ed25519 + Dilithium).  The
                Ed25519 component may be either the 32-byte seed (the format
                :meth:`generate_keypair` emits) or the 64-byte expanded
                native key (the format
                ``create_crypto_package``'s per-config normalization caches
                so steady-state signing skips the per-call seed expansion);
                the two are distinguished unambiguously by total length,
                because the ML-DSA-65 component is a fixed 4,032 bytes.
            precomputed_hash: Optional pre-computed SHA3-256 hash of message.
                When provided, skips redundant hash computation (~2x savings).

        Returns:
            Signature with combined Ed25519 and Dilithium signatures

        Raises:
            PQCUnavailableError: If Dilithium backend is not available
        """
        _enforce_invariant7()
        if not self._pqc_available:
            raise PQCUnavailableError("PQC_UNAVAILABLE: Hybrid signatures require ML-DSA-65.")

        # Split keys — see the ``secret_key`` docstring for the two accepted
        # classical-component widths.
        classical_size = (
            self.ED25519_FULL_SK_SIZE
            if len(secret_key) == self.ED25519_FULL_SK_SIZE + self.DILITHIUM_SK_SIZE
            else self.ED25519_SK_SIZE
        )
        classical_sk_bytes = secret_key[:classical_size]
        pqc_sk = secret_key[classical_size:]

        # Compute hash once and pass to both providers
        msg_hash = precomputed_hash if precomputed_hash is not None else native_sha3_256(message)

        # Create both signatures using native backends, passing precomputed hash
        classical_sig = self.classical_provider.sign(
            message, classical_sk_bytes, precomputed_hash=msg_hash
        )
        pqc_sig = self.pqc_provider.sign(message, pqc_sk, precomputed_hash=msg_hash)

        # Combine signatures (Ed25519 first, then Dilithium)
        combined_sig = classical_sig.signature + pqc_sig.signature

        return Signature(
            signature=combined_sig,
            algorithm=self.algorithm,
            message_hash=msg_hash,
            metadata={
                "classical_sig_size": len(classical_sig.signature),
                "pqc_sig_size": len(pqc_sig.signature),
            },
        )

    def verify(
        self,
        message: bytes,
        signature: bytes,
        public_key: bytes,
        parallel: bool = True,
    ) -> bool:
        """
        Verify hybrid signature (both must verify).

        Performance Optimization:
        -------------------------
        Uses a thread pool to verify Ed25519 and ML-DSA-65 in parallel,
        reducing latency from ~257us to ~154us (~40% faster).

        Args:
            message: Original data
            signature: Combined signature (Ed25519 + Dilithium)
            public_key: Combined public key (Ed25519 + Dilithium)
            parallel: When True (default), run both verifications in parallel
                using a thread pool. Set to False for debugging/testing.

        Returns:
            True if BOTH signatures are valid, False otherwise

        Raises:
            PQCUnavailableError: If Dilithium backend is not available
        """
        _enforce_invariant7()
        if not self._pqc_available:
            raise PQCUnavailableError("PQC_UNAVAILABLE: Hybrid signatures require ML-DSA-65.")

        # Split keys and signatures
        classical_pk_bytes = public_key[: self.ED25519_PK_SIZE]
        pqc_pk = public_key[self.ED25519_PK_SIZE :]
        classical_sig = signature[: self.ED25519_SIG_SIZE]
        pqc_sig = signature[self.ED25519_SIG_SIZE :]

        if parallel:
            # Submit both verifications to thread pool for parallel execution.
            # The GIL is released during native C calls, so true parallelism
            # is achieved for the C-level verification work.
            classical_future = self._verify_pool.submit(
                self.classical_provider.verify, message, classical_sig, classical_pk_bytes
            )
            pqc_future = self._verify_pool.submit(
                self.pqc_provider.verify, message, pqc_sig, pqc_pk
            )

            # Both futures must complete; collect results
            classical_valid = classical_future.result()
            pqc_valid = pqc_future.result()
        else:
            # Sequential fallback for debugging/testing
            classical_valid = self.classical_provider.verify(
                message, classical_sig, classical_pk_bytes
            )
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
        >>> valid = crypto.verify(b"Hello, World!", signature, keypair.public_key)
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
        _enforce_invariant7()
        _check_operational()
        if isinstance(self.provider, AESGCMProvider):
            raise TypeError("AES-256-GCM does not support keypair generation")
        return self.provider.generate_keypair()

    def sign(self, message: bytes, secret_key: Union[bytes, bytearray]) -> Signature:
        """Sign a message"""
        _enforce_invariant7()
        _check_operational()
        if not isinstance(self.provider, CryptoProvider):
            raise TypeError("Current algorithm does not support signing")
        return self.provider.sign(message, secret_key)

    def verify(
        self,
        message: bytes,
        signature: Union[bytes, Signature],
        public_key: bytes,
    ) -> bool:
        """Verify a signature.

        Args:
            message: Message that was signed.
            signature: Raw signature bytes or a :class:`Signature` object.
            public_key: Public key used for verification.

        Returns:
            True if valid, False otherwise.
        """
        _enforce_invariant7()
        _check_operational()
        if not isinstance(self.provider, CryptoProvider):
            raise TypeError("Current algorithm does not support verification")
        sig_bytes = signature.signature if isinstance(signature, Signature) else signature
        return self.provider.verify(message, sig_bytes, public_key)

    def encapsulate(self, public_key: bytes) -> EncapsulatedSecret:
        """Encapsulate a shared secret (KEM)"""
        _enforce_invariant7()
        _check_operational()
        if not isinstance(self.provider, KEMProvider):
            raise TypeError("Current algorithm does not support KEM")
        return self.provider.encapsulate(public_key)

    def decapsulate(self, ciphertext: bytes, secret_key: Union[bytes, bytearray]) -> bytes:
        """Decapsulate a shared secret (KEM)"""
        _enforce_invariant7()
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

        Always uses the native FIPS 202 C kernels (ama_sha3_256/512,
        ama_shake256). Per INVARIANT-7 there is no hashlib fallback: a hash is a
        cryptographic primitive, so when the native backend is unavailable the
        underlying ``native_sha3_*`` / ``native_shake256`` helpers raise
        ``RuntimeError`` (fail closed) rather than substituting stdlib hashing —
        including under the docs-build import override, where call-time
        enforcement still refuses to operate without the native library.

        Enforces the invariant/operational gate itself so it is safe to call
        standalone (not only via :func:`quick_hash`): a caller cannot bypass the
        module's INVARIANT-7 refusal or the FIPS operational error-state lockout
        by invoking this static method directly.
        """
        _enforce_invariant7()
        _check_operational()

        from ama_cryptography.pqc_backends import (
            native_sha3_256,
            native_sha3_512,
            native_shake256,
        )

        if algorithm == "sha3-256":
            return native_sha3_256(message)
        elif algorithm == "sha3-512":
            return native_sha3_512(message)
        elif algorithm == "shake256":
            return native_shake256(message, 32)
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
    # hash_message() now enforces the invariant/operational gate itself, so it
    # is the single enforcement point (no redundant double-check here).
    return AmaCryptography.hash_message(message, algorithm)


def quick_hmac(key: bytes, message: bytes, algorithm: str = "sha256") -> bytes:
    """
    Quick HMAC: compute a keyed MAC in one call via the native backend.

    Unified dispatcher over the native ama_hmac_* kernels so callers do not
    have to reach into ``ama_cryptography.pqc_backends`` and pick a variant by
    hand.  INVARIANT-1 compliant (no stdlib hmac).

    Args:
        key: HMAC key (any length; oversized keys are hashed per RFC 2104 §2).
        message: Message to authenticate.
        algorithm: One of "sha256" (32-byte tag), "sha384" (48), "sha512" (64),
            or "sha3-256" (32).

    Returns:
        The HMAC tag, byte-identical to ``hmac.new(key, message, <hash>)``.

    Raises:
        ValueError: Unsupported algorithm.
        RuntimeError: Native backend unavailable.

    Example:
        >>> tag = quick_hmac(b"key", b"message", "sha256")
        >>> assert len(tag) == 32
    """
    _enforce_invariant7()
    _check_operational()
    from ama_cryptography.pqc_backends import (
        native_hmac_sha3_256,
        native_hmac_sha256,
        native_hmac_sha384,
        native_hmac_sha512,
    )

    dispatch = {
        "sha256": native_hmac_sha256,
        "sha384": native_hmac_sha384,
        "sha512": native_hmac_sha512,
        "sha3-256": native_hmac_sha3_256,
    }
    if algorithm not in dispatch:
        raise ValueError(
            f"Unsupported HMAC algorithm: {algorithm}. " f"Supported: {sorted(dispatch)}"
        )
    return dispatch[algorithm](key, message)


def quick_hkdf(
    ikm: bytes,
    length: int,
    salt: "Optional[bytes]" = None,
    info: bytes = b"",
    algorithm: str = "sha256",
) -> bytes:
    """
    Quick HKDF (RFC 5869): derive key material in one call via the native
    backend.

    Unified dispatcher over the native HKDF kernels.  "sha256"/"sha384"/"sha512"
    select the interoperable HKDF-SHA-2 variants (TLS 1.3 / HPKE); "sha3-256"
    selects AMA's default HMAC-SHA3-256 HKDF.  INVARIANT-1 compliant.

    Args:
        ikm: Input key material.
        length: Desired output length in bytes (max 255 * HashLen).
        salt: Optional salt (None -> HashLen zero bytes per RFC 5869 §2.2).
        info: Optional context/application info.
        algorithm: "sha256" (default), "sha384", "sha512", or "sha3-256".

    Returns:
        `length` bytes of derived key material.

    Raises:
        ValueError: Unsupported algorithm or length out of range.
        RuntimeError: Native backend unavailable.
    """
    _enforce_invariant7()
    _check_operational()
    from ama_cryptography.pqc_backends import (
        native_hkdf,
        native_hkdf_sha256,
        native_hkdf_sha384,
        native_hkdf_sha512,
    )

    if algorithm == "sha256":
        return native_hkdf_sha256(ikm, length, salt, info)
    if algorithm == "sha384":
        return native_hkdf_sha384(ikm, length, salt, info)
    if algorithm == "sha512":
        return native_hkdf_sha512(ikm, length, salt, info)
    if algorithm == "sha3-256":
        return native_hkdf(ikm, length, salt=salt, info=info)
    raise ValueError(
        f"Unsupported HKDF algorithm: {algorithm}. "
        "Supported: ['sha256', 'sha384', 'sha512', 'sha3-256']"
    )


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
    _enforce_invariant7()
    crypto = AmaCryptography(algorithm=algorithm)
    keypair = crypto.generate_keypair()
    signature = crypto.sign(message, keypair.secret_key)
    return keypair, signature


def quick_verify(
    message: bytes,
    signature: Union[bytes, Signature],
    public_key: bytes,
    algorithm: AlgorithmType = AlgorithmType.HYBRID_SIG,
) -> bool:
    """
    Quick verify: Verify signature in one call

    Args:
        message: Message that was signed
        signature: Raw signature bytes or a :class:`Signature` object
        public_key: Public key
        algorithm: Algorithm used

    Returns:
        True if valid, False otherwise
    """
    _enforce_invariant7()
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
    _enforce_invariant7()
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
        "hmac_hkdf_available": HMAC_HKDF_AVAILABLE,
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
    signing_keypair: Optional[Tuple[bytes, bytes]] = None
    """Pre-generated signing keypair (public_key, secret_key) to reuse.

    When provided, ``create_crypto_package()`` skips keypair generation and
    uses the supplied keys for the primary signature.  This is useful for
    agents (e.g. Mercury Agent) that sign many results with the same identity.

    The supplied keys are checked to ensure they are non-empty and not
    composed entirely of zero bytes, and — for HYBRID_SIG and ED25519 —
    that the Ed25519 public-key component matches the supplied seed (see
    ``_normalized_signing_secret``).  Other algorithm-specific key length
    validation is not performed at this layer; invalid keys will surface as
    errors from the underlying signing call.
    When ``None`` (default), a fresh keypair is generated per call.
    """

    _normalized_signing_memo: Optional[Tuple[bytes, bytes, bytes]] = field(
        default=None, init=False, repr=False, compare=False
    )
    """``(public_key identity, secret_key identity, normalized secret)`` memo.

    Keyed on the identity of the two ELEMENTS, not of the container: the
    runtime validator admits a list, whose identity survives element
    replacement, and a container-identity memo kept returning the previous
    key's normalization after ``signing_keypair[1] = new_sk``.  bytes are
    immutable, so element identity implies element value.

    Written by ``_normalized_signing_secret`` on first use of a
    ``signing_keypair`` so the per-call Ed25519 seed expansion (and the
    keygen pairwise consistency test it drags in) is paid once per identity
    instead of once per package.  Lives on this object deliberately: the
    caller already owns the secret key stored two fields up, so the memo
    introduces no new key-material retention class.
    """


@dataclass
class CryptoPackageResult:
    """
    Result from create_crypto_package() containing all cryptographic artifacts.

    .. warning::
        This object contains **secret key material** (``hmac_key``,
        ``hkdf_master_secret``).  Do not serialize or log without
        stripping these fields.  Use :meth:`to_dict` for safe serialization.

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
        - RFC 3161 timestamp token — stored, not verified here, and not
          third-party attestation. AMA verifies the §2.4.2 message-imprint
          binding only; it does not verify the TSA's CMS ``SignerInfo``
          signature or validate its certificate chain, so ``TSTInfo.genTime``
          is unauthenticated (INVARIANT-37).

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

    # Secret fields that must be stripped during serialization.
    #
    # `keypairs` is deliberately NOT in this set: it has to survive
    # serialization, because the verifying public keys live in it.  Its
    # private half is removed separately — see `_redact_keypairs`.
    _SECRET_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "hmac_key",
            "hkdf_master_secret",
            # The Layer-4 output keys, not only the master secret they come
            # from.  Emitting these hands over the derived key material
            # directly, which makes stripping the master secret pointless.
            "derived_keys",
            # The KEM's entire output, and named a secret in its own field
            # name.
            "kem_shared_secret",
        }
    )

    #: Type-correct stand-ins for stripped fields when rebuilding from a
    #: pickle.  A blanket ``b""`` would give ``derived_keys`` a ``bytes``
    #: where the annotation promises ``List[bytes]``, so a caller iterating it
    #: after a round-trip would silently get single bytes instead of keys.
    #: Bandit's B105 heuristic fires on a secret-sounding key assigned a
    #: literal.  Here the literals are the *absence* of the secret — this is
    #: the table that replaces stripped fields — so the finding is exactly
    #: inverted.  Suppressed line-scoped with a tracking ID per INVARIANT-13;
    #: the values are pinned by
    #: tests/test_crypto_api_packages.py::test_pickle_strips_the_private_signing_key.
    _SECRET_FIELD_PLACEHOLDERS: ClassVar[Dict[str, Any]] = {
        "hmac_key": b"",
        "hkdf_master_secret": b"",  # nosec B105 -- empty placeholder for a stripped field, not a secret (CAPI-002)
        "derived_keys": [],
        "kem_shared_secret": None,  # nosec B105 -- empty placeholder for a stripped field, not a secret (CAPI-002)
    }

    @staticmethod
    def _redact_keypairs(keypairs: Dict[str, KeyPair]) -> Dict[str, KeyPair]:
        """Return the keypairs with every private half replaced by ``b""``.

        ``KeyPair.secret_key`` is the most sensitive value in a package — for
        the default hybrid signer, ~4 KB of Ed25519 + ML-DSA-65 private key.
        It was passing through both serialization paths intact while they
        advertised "stripping secret fields", so anything that wrote a package
        to a log, a cache, a queue or a pickle file wrote the signing key out
        with it.  ``KeyPair`` already marks the field ``repr=False`` for
        exactly this reason; this applies the same rule to the paths that
        actually leave the process.

        The public half is preserved — it is what a verifier needs, and it is
        public by construction.
        """
        from dataclasses import replace as _replace

        return {name: _replace(kp, secret_key=b"") for name, kp in keypairs.items()}

    def to_dict(self, include_secrets: bool = False) -> Dict[str, Any]:
        """Serialize to a dictionary, stripping secret fields by default.

        Args:
            include_secrets: If True, include every field verbatim — the HMAC
                key, the HKDF master secret and derived keys, the KEM shared
                secret, and the private half of every keypair.  Use it only
                when the destination is as trusted as the package itself.
                Defaults to False for safe serialization.

        Returns:
            Dictionary representation.  Unless *include_secrets* is True the
            fields in :attr:`_SECRET_FIELDS` are omitted entirely and
            ``keypairs`` carries public keys only.

        .. versionchanged:: 4.0
           ``derived_keys``, ``kem_shared_secret`` and each
           ``KeyPair.secret_key`` are now stripped as well.  Through 3.x only
           ``hmac_key`` and ``hkdf_master_secret`` were, so the default —
           documented as safe — emitted the package's private signing key.
           Callers that genuinely need the full object pass
           ``include_secrets=True``.
        """
        from dataclasses import fields as _fields

        result: Dict[str, Any] = {}
        for f in _fields(self):
            if not include_secrets and f.name in self._SECRET_FIELDS:
                continue
            value = getattr(self, f.name)
            if not include_secrets and f.name == "keypairs":
                value = self._redact_keypairs(value)
            result[f.name] = value
        return result

    def __getstate__(self) -> Dict[str, Any]:
        """Strip secret fields during pickling for safety.

        A pickled package was already unusable for verification — ``hmac_key``
        has always been stripped and Layer 2 cannot be checked without it — so
        removing the rest costs no working flow.  Recovering secrets through a
        pickle round-trip was never a supported behaviour; it was a leak.
        """
        state = self.__dict__.copy()
        for key in self._SECRET_FIELDS:
            state.pop(key, None)
        if "keypairs" in state:
            state["keypairs"] = self._redact_keypairs(state["keypairs"])
        return state

    def __setstate__(self, state: Dict[str, Any]) -> None:
        """Restore state from pickle, substituting empties for stripped secrets."""
        for key, placeholder in self._SECRET_FIELD_PLACEHOLDERS.items():
            if key not in state:
                # Copy mutable placeholders so two restored instances never
                # share one list.
                state[key] = list(placeholder) if isinstance(placeholder, list) else placeholder
        self.__dict__.update(state)


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
    if tsa_mode not in ("online", "mock", "disabled"):
        # No default branch (INVARIANT-35's rule applied to a mode selector):
        # an unrecognised value used to fall through to the ONLINE path, so a
        # typo like "disable" or "off" in an air-gapped or privacy-sensitive
        # deployment silently sent the content digest to an external TSA
        # instead of failing.
        raise ValueError(
            f"unknown tsa_mode {tsa_mode!r}: expected 'online', 'mock' or "
            f"'disabled'.  Refusing to guess — the previous fallthrough "
            f"contacted an external timestamp authority."
        )
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
        # get_timestamp() always returns a TimestampResult (never None).
        # Check for an empty token which would indicate an unexpected failure.
        if not result.token:
            raise RuntimeError(
                "Timestamp acquisition failed: get_timestamp() returned empty token "
                "in mock mode. Cannot produce untimestamped package when timestamps "
                "are required."
            )
        return result.token

    # Online mode
    if not RFC3161_AVAILABLE:
        # Unreachable in a working installation: `RFC3161_AVAILABLE` is
        # unconditionally True in `ama_cryptography.rfc3161_timestamp`, which
        # is a first-party module. This branch survives only for the case that
        # module fails to import at all. It used to say "pip install
        # rfc3161ng", which by the time this PR removed that dependency was
        # instructing the operator to install a third-party cryptographic
        # implementation that INVARIANT-1 forbids the core package from using.
        raise TimestampUnavailableError(
            "RFC3161_UNAVAILABLE: ama_cryptography.rfc3161_timestamp failed to import. "
            "RFC 3161 is implemented in-tree on AMA's own DER codec and needs nothing "
            "installed, so this indicates a damaged installation rather than a missing "
            "dependency. Reinstall the package."
        )
    try:
        result = get_timestamp(
            data=content,
            tsa_url=config.tsa_url,
            hash_algorithm="sha3-256",
        )
        # get_timestamp() always returns a TimestampResult (never None).
        # Check for an empty token which would indicate an unexpected failure.
        if not result.token:
            raise RuntimeError(
                "Timestamp acquisition failed: get_timestamp() returned empty token. "
                "Cannot produce untimestamped package when timestamps are required."
            )
        return result.token
    except TimestampError as e:
        raise TimestampError(
            f"RFC 3161 timestamp is required when include_timestamp=True, "
            f"but the timestamp request failed: {e}"
        ) from e


def _public_key_fingerprint(public_key: bytes) -> bytes:
    """First 8 bytes of a public key, for volume-detector churn accounting.

    Public keys are public, so no hashing is needed and none is done — this
    must not add a digest to a signing path.  The detector only ever compares
    fingerprints for equality within a one-second bucket, so an 8-byte prefix
    of an already-uniform key is sufficient to tell "a fresh identity per
    operation" from "a hot loop over one key".  Never called with secret key
    material.
    """
    return bytes(public_key[:8])


def _normalized_signing_secret(
    config: CryptoPackageConfig, public_key: bytes, secret_key: bytes
) -> bytes:
    """Normalize a pre-generated signing secret once per config object.

    HYBRID_SIG and ED25519 secret keys embed the Ed25519 secret as its
    32-byte seed.  :meth:`Ed25519Provider.sign` expands a seed to the
    64-byte native form on every call, and that expansion is a key
    *generation* (``native_ed25519_keypair_from_seed``), so it also re-ran
    the INVARIANT-41 pairwise consistency test per signature — measured at
    ~0.2 ms per package on the agent flow the ``signing_keypair`` option
    exists for, a cost with no security payoff after the first call.

    The expansion is done once here and memoized on the *config object*,
    which the caller already owns and which already holds the secret key —
    the cached expansion is derivable from what the object stores, so this
    creates no new key-material retention class (contrast module-level
    caches, which INVARIANT-41's continuous-RNG fix removed).  The memo is
    keyed on the identity of the two bytes ELEMENTS (immutable, so
    identity implies value), so replacing the tuple or swapping an element
    inside an admitted list container (e.g. after ``KeypairCache.rotate()``)
    re-normalizes.

    Normalization also *strengthens* validation: the Ed25519 public key
    derived from the seed must equal the supplied public-key component,
    which previously went unchecked — a mismatched pair produced packages
    whose signatures could never verify, discovered only downstream.

    Signing behaviour is unchanged: the native signer derives its scalar
    from the seed and reads the public-key half from the expanded form,
    which this function guarantees is the seed's own derived key.
    """
    # Memo hit requires ELEMENT identity, not container identity.  The
    # runtime validator in create_crypto_package deliberately admits a list
    # container, and a list's identity survives element replacement — so a
    # container-identity memo returned the OLD normalized secret after a
    # caller swapped config.signing_keypair[1] in place, silently signing
    # every subsequent package under the replaced key while attaching the
    # new public key: unverifiable by construction, detected only
    # downstream.  The elements themselves are enforced to be bytes
    # (immutable), so element identity implies element value — two `is`
    # checks close the hole completely, at no cost, with no behavioural
    # change for any caller who replaces the tuple (both keyings miss) or
    # reuses it (both hit).
    cached = config._normalized_signing_memo
    if cached is not None and cached[0] is public_key and cached[1] is secret_key:
        return cached[2]

    algorithm = config.signature_algorithm
    normalized = secret_key
    if (
        algorithm is AlgorithmType.HYBRID_SIG
        and len(secret_key)
        == HybridSignatureProvider.ED25519_SK_SIZE + HybridSignatureProvider.DILITHIUM_SK_SIZE
    ):
        seed = secret_key[: HybridSignatureProvider.ED25519_SK_SIZE]
        derived_pk, full_sk = native_ed25519_keypair_from_seed(seed)
        if derived_pk != public_key[: HybridSignatureProvider.ED25519_PK_SIZE]:
            raise ValueError(
                "signing_keypair mismatch: the Ed25519 public-key component does "
                "not correspond to the supplied Ed25519 seed"
            )
        normalized = full_sk + secret_key[HybridSignatureProvider.ED25519_SK_SIZE :]
    elif algorithm is AlgorithmType.ED25519 and len(secret_key) == 32:
        derived_pk, full_sk = native_ed25519_keypair_from_seed(secret_key)
        if derived_pk != public_key:
            raise ValueError(
                "signing_keypair mismatch: the Ed25519 public key does not "
                "correspond to the supplied seed"
            )
        normalized = full_sk

    config._normalized_signing_memo = (public_key, secret_key, normalized)
    return normalized


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
        - RFC 3161 timestamp token (online, mock, or disabled) — acquired and
          stored. Not third-party attestation: see
          :class:`CryptoPackageResult` and INVARIANT-37.

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
        TimestampError: If the timestamp request fails

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
    _enforce_invariant7()
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
    content_hash = native_sha3_256(content).hex()

    # Precompute the SHA3-256 digest once for reuse across sign() calls.
    # This eliminates redundant hash computations: Layer 1 computes the hash,
    # and each provider's .sign() would otherwise recompute it independently.
    _precomputed_hash = bytes.fromhex(content_hash)

    # ========================================================================
    # LAYER 2: Keyed Authentication — HMAC-SHA3-256 (RFC 2104)
    # ========================================================================
    # INVARIANT-41: key material comes from the health-tested, error-state-gated
    # draw, not bare secrets.token_bytes — a stuck DRBG must be detected here.
    hmac_key = secure_token_bytes(32)  # 256-bit HMAC key
    hmac_tag = _hmac_sha3_256(hmac_key, content)

    # ========================================================================
    # LAYER 3: Digital Signature — Hybrid Ed25519 + ML-DSA-65
    # ========================================================================
    keypairs: Dict[str, KeyPair] = {}
    sphincs_signature: Optional[Signature] = None
    kem_ciphertext: Optional[bytes] = None
    kem_shared_secret: Optional[bytes] = None

    # Generate primary signature (with 3R timing instrumentation)
    primary_crypto = AmaCryptography(algorithm=config.signature_algorithm)
    if config.signing_keypair is not None:
        if (
            not isinstance(config.signing_keypair, (tuple, list))
            or len(config.signing_keypair) != 2
        ):
            raise TypeError(
                "signing_keypair must be a (public_key, secret_key) pair of two "
                "bytes values (tuple, or the equivalent list)"
            )
        _pk, _sk = config.signing_keypair
        if not isinstance(_pk, bytes) or not isinstance(_sk, bytes):
            raise TypeError("signing_keypair must be a tuple of (bytes, bytes)")
        if len(_pk) == 0 or len(_sk) == 0:
            raise ValueError("signing_keypair keys must be non-empty")
        from ama_cryptography.secure_memory import constant_time_compare

        if constant_time_compare(_pk, b"\x00" * len(_pk)) or constant_time_compare(
            _sk, b"\x00" * len(_sk)
        ):
            raise ValueError("signing_keypair keys must not be all-zero")
        primary_keypair = KeyPair(
            public_key=_pk,
            secret_key=_sk,
            algorithm=config.signature_algorithm,
            metadata={"source": "pre-generated"},
        )
        _signing_secret = _normalized_signing_secret(config, _pk, _sk)
    else:
        primary_keypair = primary_crypto.generate_keypair()
        _signing_secret = primary_keypair.secret_key
    _t0 = time.perf_counter_ns()
    primary_signature = primary_crypto.sign(content, _signing_secret)
    _sign_ns = time.perf_counter_ns() - _t0
    _monitor.monitor_crypto_operation("sign", _sign_ns / 1_000_000)
    # INVARIANT-30 companion signal.  Wired at the sites that are already
    # instrumented rather than pushed down into the providers, so no new call
    # path acquires a lock and the hot primitives stay untouched.  The
    # fingerprint is a slice of the PUBLIC key — it lets the detector tell
    # ephemeral-identity-per-artifact churn from a hot loop over one key.
    _monitor.record_operation_event(
        f"{config.signature_algorithm.name.lower()}_sign",
        key_fingerprint=_public_key_fingerprint(primary_keypair.public_key),
    )
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
        _t0 = time.perf_counter_ns()
        sphincs_signature = sphincs_provider.sign(
            content, sphincs_keypair.secret_key, precomputed_hash=_precomputed_hash
        )
        _sphincs_ns = time.perf_counter_ns() - _t0
        _monitor.monitor_crypto_operation("sphincs_sign", _sphincs_ns / 1_000_000)
        _monitor.record_operation_event(
            "sphincs_sign",
            key_fingerprint=_public_key_fingerprint(sphincs_keypair.public_key),
        )
        keypairs["SPHINCS_256F"] = sphincs_keypair

    # ========================================================================
    # LAYER 4: Key Independence — HKDF-SHA3-256 (RFC 5869)
    # ========================================================================
    # INVARIANT-41: health-tested, error-state-gated draw (see above).
    master_secret = secure_token_bytes(32)  # 256-bit master secret
    hkdf_salt = secure_token_bytes(32)
    hkdf_info = b"ama_cryptography_crypto_package_v1"
    derived_keys: List[bytes] = []
    if config.num_derived_keys < 1:
        # Layer 4 requires at least one derived key: verify_crypto_package
        # fails closed on an empty derived_keys list, so a package built with
        # 0 (or a negative count) is rejected by its own verifier — including
        # by the party that created it — while creation reported success and
        # recorded metadata["defense_layers"] = 4.
        raise ValueError(
            f"num_derived_keys must be at least 1, got {config.num_derived_keys}: "
            f"Layer 4 (HKDF key derivation) cannot be verified without one."
        )
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
        _t0 = time.perf_counter_ns()
        encapsulated = kyber_provider.encapsulate(kyber_keypair.public_key)
        _encaps_ns = time.perf_counter_ns() - _t0
        _monitor.monitor_crypto_operation("encrypt", _encaps_ns / 1_000_000)
        _monitor.record_operation_event(
            "kyber_encaps",
            key_fingerprint=_public_key_fingerprint(kyber_keypair.public_key),
        )
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
        "multi_layer_defense": True,
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


def _verify_package_signature(
    content: bytes,
    package: CryptoPackageResult,
    sig_alg: AlgorithmType,
    sig_alg_name: str,
    expected_public_key: Optional[bytes],
) -> Tuple[bool, bool]:
    """Verify a package's Layer-3 signature against a trust anchor.

    The signing public key travels INSIDE the package, so a signature that
    verifies against it proves only that the package is internally consistent
    — never that it came from a particular signer.  An adversary can mint a
    keypair, sign arbitrary content, and produce a package whose every layer
    verifies.  ``expected_public_key`` supplies the out-of-band anchor that
    turns this into an authenticity check.

    Args:
        content: Original content that was signed.
        package: Package carrying the signature and its embedded public key.
        sig_alg: Resolved signature algorithm.
        sig_alg_name: Key under which the signing keypair is stored.
        expected_public_key: Optional out-of-band anchor. When supplied and
            mismatched, the signature is NOT evaluated at all (fail closed).

    Returns:
        ``(signature_valid, key_pinned)``. ``key_pinned`` is True only when an
        anchor was supplied AND matched, so callers can distinguish an
        authenticity check from a bare self-consistency check (INVARIANT-37).
    """
    if sig_alg_name not in package.keypairs:
        return False, False

    embedded_pk = package.keypairs[sig_alg_name].public_key

    if expected_public_key is not None:
        from ama_cryptography.secure_memory import constant_time_compare, lengths_match

        # Public length pre-check.  `expected_public_key` is the caller's, but
        # `embedded_pk` came out of the package; a signing public key has one
        # length per algorithm and that length is not secret.  Checking it here
        # separates "this package is malformed" from "this package was signed
        # by someone else" in the log, and keeps an untrusted length out of the
        # comparison.
        if not lengths_match(expected_public_key, embedded_pk):
            logger.error(
                "Layer 3 trust anchor mismatch: expected a %d-byte %s public "
                "key, package carries %d bytes — refusing to verify the "
                "signature.",
                len(expected_public_key),
                sig_alg_name,
                len(embedded_pk),
            )
            return False, False
        if not constant_time_compare(embedded_pk, expected_public_key):
            logger.error(
                "Layer 3 trust anchor mismatch: package signing key does not "
                "match expected_public_key — refusing to verify the signature."
            )
            return False, False
        key_pinned = True
    else:
        key_pinned = False

    try:
        primary_crypto = AmaCryptography(algorithm=sig_alg)
        _t0 = time.perf_counter_ns()
        signature_valid = primary_crypto.verify(
            content,
            package.primary_signature.signature,
            embedded_pk,
        )
        _verify_ns = time.perf_counter_ns() - _t0
        _monitor.monitor_crypto_operation("verify", _verify_ns / 1_000_000)
    except Exception as exc:
        logger.error("Layer 3 signature verification error: %s", exc)
        return False, key_pinned

    return signature_valid, key_pinned


def _verify_addon_layers(
    content: bytes,
    package: CryptoPackageResult,
    results: Dict[str, bool],
) -> None:
    """Verify the optional SPHINCS+ and KEM add-on layers into ``results``.

    Split out of :func:`verify_crypto_package`, whose branch count the
    present-but-unverifiable handling below pushed over the project's
    complexity ceiling.  INVARIANT-13 prefers a refactor to a suppression,
    and these two blocks are a natural unit: they read only ``content`` and
    ``package`` and write only their own keys in ``results``.

    An add-on that is PRESENT but cannot be checked records ``False`` — see
    the comments in each branch.
    """
    # ========================================================================
    # OPTIONAL: Verify SPHINCS+ signature (add-on)
    # ========================================================================
    if package.sphincs_signature is not None and "SPHINCS_256F" not in package.keypairs:
        # Present but unverifiable: the package still CARRIES a SPHINCS+
        # signature, so a caller reading `all_valid: True` would believe it was
        # evaluated.  Omitting the key entirely — which is what this branch used
        # to do — kept it out of the aggregate and let the package pass with a
        # visible signature nobody checked.  The primary-signature path fails
        # closed for exactly this condition (`sig_alg_name not in
        # package.keypairs` returns False, False); an add-on must not be more
        # permissive than the layer it supplements (INVARIANT-37).
        logger.error(
            "SPHINCS+ signature present but its public key is missing from the "
            "package — recording the layer as FAILED rather than skipping it"
        )
        results["sphincs"] = False
    elif package.sphincs_signature is not None and "SPHINCS_256F" in package.keypairs:
        if SPHINCS_AVAILABLE:
            try:
                sphincs_provider = SphincsProvider()
                results["sphincs"] = sphincs_provider.verify(
                    content,
                    package.sphincs_signature.signature,
                    package.keypairs["SPHINCS_256F"].public_key,
                )
            except Exception as exc:
                logger.error("SPHINCS+ signature verification error: %s", exc)
                results["sphincs"] = False
        else:
            results["sphincs"] = False

    # ========================================================================
    # OPTIONAL: Verify KEM shared secret (add-on)
    # ========================================================================
    if package.kem_ciphertext is not None and (
        package.kem_shared_secret is None or "KYBER_1024" not in package.keypairs
    ):
        # Same rule as the SPHINCS+ add-on above: a ciphertext the package still
        # carries, whose counterpart secret or keypair has been stripped, is an
        # unverifiable layer and must be reported False rather than dropped from
        # the aggregate (INVARIANT-37).
        logger.error(
            "KEM ciphertext present but its shared secret or keypair is missing "
            "from the package — recording the layer as FAILED rather than skipping it"
        )
        results["kem"] = False
    elif (
        package.kem_ciphertext is not None
        and package.kem_shared_secret is not None
        and "KYBER_1024" in package.keypairs
    ):
        try:
            kyber_provider = KyberProvider()
            _t0 = time.perf_counter_ns()
            decapsulated_ss = kyber_provider.decapsulate(
                package.kem_ciphertext,
                package.keypairs["KYBER_1024"].secret_key,
            )
            _decaps_ns = time.perf_counter_ns() - _t0
            _monitor.monitor_crypto_operation("decrypt", _decaps_ns / 1_000_000)
            from ama_cryptography.secure_memory import constant_time_compare as _ct2

            results["kem"] = _ct2(decapsulated_ss, package.kem_shared_secret)
        except Exception as exc:
            logger.error("KEM decapsulation verification error: %s", exc)
            results["kem"] = False


def verify_crypto_package(
    content: bytes,
    package: CryptoPackageResult,
    expected_public_key: Optional[bytes] = None,
) -> Dict[str, bool]:
    """
    Verify all 4 layers of a crypto package plus any optional add-ons.

    **4-Layer Verification**

    - *Layer 1 — Content Integrity:* recompute SHA3-256 and compare to
      stored hash.
    - *Layer 2 — Keyed Authentication:* recompute HMAC-SHA3-256 with
      stored key and compare to stored tag.
    - *Layer 3 — Digital Signature:* verify primary signature
      (Ed25519 + ML-DSA-65) against the signing public key, which is taken
      from ``expected_public_key`` when supplied and otherwise from the
      package itself (see the authenticity note below).
    - *Layer 4 — Key Independence:* re-derive keys from stored master
      secret, salt, and info; compare to stored derived keys.

    Optional add-on verification:

    - SPHINCS+ secondary signature (if present)
    - KEM shared secret (if present and keypair available)

    **Not verified here, stated so it is not assumed:** the RFC 3161
    ``timestamp`` token that :func:`create_crypto_package` may have stored on
    the package is *not* checked by this function, and no result key reports on
    it. ``all_valid`` is therefore silent about the timestamp — it is neither
    an assertion that the token is good nor that one is present. To check a
    token, call :func:`ama_cryptography.rfc3161_timestamp.verify_timestamp_binding`
    (or :func:`~ama_cryptography.rfc3161_timestamp.describe_token_verification`)
    explicitly, and read INVARIANT-37 first: AMA verifies the RFC 3161 §2.4.2
    message-imprint binding only, never the TSA's signature or certificate
    chain, so no result it can return is third-party time attestation.

    **Authenticity requires a trust anchor, and ``all_valid`` now demands
    one.** Every key this function needs to check a package is carried *by
    that package*: the signing public key lives in ``package.keypairs``, the
    HMAC key in ``package.hmac_key``, and the Layer-4 master secret in
    ``package.hkdf_master_secret``. Verifying a package against its own
    material proves **integrity and internal consistency only** — that the
    parts agree with each other and were not corrupted in transit. It is *not*
    proof of origin: anyone can generate a keypair, call
    :func:`create_crypto_package` over content of their choosing, and obtain a
    package whose every layer verifies.

    To obtain authenticity, pass ``expected_public_key`` — a signing public
    key you obtained out of band (pinned in config, fetched from a directory
    you trust, or established at enrollment). It is compared in constant time
    against the package's embedded signing key; on mismatch the signature is
    not evaluated and ``primary_signature`` is False.

    .. versionchanged:: 4.0
       ``all_valid`` is False unless ``expected_public_key`` was supplied and
       matched. Through 3.x an unanchored call returned ``all_valid`` True,
       which reported success for a check that could not distinguish the
       expected signer from an attacker who had built their own package. The
       safe mode was the one a caller had to opt into, so the default was
       changed rather than documented harder.

       **Migration.** If you were relying on the old meaning — "these parts
       agree with each other" — read ``core_valid``, which is unchanged and
       still covers Layers 1-4. If you want what ``all_valid`` now asserts,
       supply the anchor. There is no flag to restore the old aggregate: it
       would reintroduce the same silent default under a different name.

    The ``key_pinned`` result key still reports which mode ran, so an auditor
    can distinguish the two programmatically (INVARIANT-37: the boundary is
    published as data, not only as prose).

    Note that Layers 1, 2 and 4 remain self-referential even when the
    signature is anchored — they are integrity checks, and only the anchored
    Layer 3 signature carries origin.

    Args:
        content: Original content that was signed.
        package: CryptoPackageResult to verify.
        expected_public_key: Out-of-band signing public key to pin the package
            against. Optional in signature only: when omitted, no authenticity
            claim is made (``key_pinned`` is False) and ``all_valid`` is False.
            When supplied and mismatched, the signature check fails closed.

    Returns:
        Dictionary with a boolean for each layer plus ``all_valid``. Keys:

        - ``content_hash``: Layer 1
        - ``hmac``: Layer 2
        - ``primary_signature``: Layer 3
        - ``hkdf_keys``: Layer 4
        - ``sphincs``: (if present)
        - ``kem``: (if present)
        - ``key_pinned``: True iff ``expected_public_key`` was supplied and
          matched the package's signing key.
        - ``core_valid``: True iff Layers 1-4 passed. Self-consistency only;
          unchanged in 4.0.
        - ``all_valid``: True iff every executed check passed **and** the
          package was anchored. An origin claim.

    Example:
        >>> result = create_crypto_package(b"Hello")
        >>> v = verify_crypto_package(b"Hello", result)
        >>> assert v["core_valid"]        # integrity / self-consistency
        >>> assert not v["key_pinned"]    # no authenticity claimed
        >>> assert not v["all_valid"]     # 4.0: unanchored is not "valid"

        Anchored verification, which is what proves origin::

        >>> pk = result.keypairs["HYBRID_SIG"].public_key  # obtained out of band
        >>> v = verify_crypto_package(b"Hello", result, expected_public_key=pk)
        >>> assert v["all_valid"] and v["key_pinned"]
    """
    _enforce_invariant7()
    _check_operational()
    results: Dict[str, bool] = {}

    # ========================================================================
    # LAYER 1: Content Integrity — SHA3-256
    # ========================================================================
    computed_hash = native_sha3_256(content).hex()
    results["content_hash"] = computed_hash == package.content_hash

    # ========================================================================
    # LAYER 2: Keyed Authentication — HMAC-SHA3-256
    # ========================================================================
    try:
        recomputed_hmac = _hmac_sha3_256(package.hmac_key, content)
        from ama_cryptography.secure_memory import constant_time_compare, lengths_match

        # Public length pre-check first.  `package.hmac_tag` is whatever the
        # package says it is, and an HMAC-SHA3-256 tag has exactly one length,
        # which is not a secret.  Refusing a wrong-length tag here says
        # "malformed" in the log instead of letting a structural defect arrive
        # at the caller as "the tag did not match", and it means no untrusted
        # length reaches the comparison at all.
        if not lengths_match(recomputed_hmac, package.hmac_tag):
            logger.error(
                "Layer 2 HMAC tag is malformed: expected %d bytes, package " "carries %d.",
                len(recomputed_hmac),
                len(package.hmac_tag),
            )
            results["hmac"] = False
        else:
            results["hmac"] = constant_time_compare(recomputed_hmac, package.hmac_tag)
    except Exception as exc:
        logger.error("Layer 2 HMAC verification error: %s", exc)
        results["hmac"] = False

    # ========================================================================
    # LAYER 3: Digital Signature — primary algorithm
    # ========================================================================
    sig_alg_name = package.metadata.get("signature_algorithm", "HYBRID_SIG")
    try:
        sig_alg = AlgorithmType[sig_alg_name]
    except KeyError:
        sig_alg = AlgorithmType.HYBRID_SIG

    signature_valid, key_pinned = _verify_package_signature(
        content, package, sig_alg, sig_alg_name, expected_public_key
    )
    results["primary_signature"] = signature_valid
    results["key_pinned"] = key_pinned
    # Backward compatibility: the key was previously named 'primary'.
    # Deprecated — will be removed in a future version.
    results["primary"] = results["primary_signature"]

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
    except Exception as exc:
        logger.error("Layer 4 HKDF key verification error: %s", exc)
        results["hkdf_keys"] = False

    # Optional add-on layers (SPHINCS+, KEM).  Extracted to keep this function
    # under the complexity ceiling — the add-ons are a self-contained pass over
    # the package and share no state with the core four layers beyond `results`.
    _verify_addon_layers(content, package, results)

    # Aggregate: separate core 4-layer validity from optional add-ons.
    # Core 4 layers: content_hash (L1), hmac (L2), primary_signature (L3),
    # hkdf_keys (L4).  Optional add-ons: sphincs, kem.
    # The 'primary' key is a backward-compat alias and excluded from aggregation.
    #
    # `key_pinned` IS part of `all_valid` (4.0 change).  Every key this
    # function needs to check a package travels inside the package, so without
    # an out-of-band anchor the strongest available statement is "internally
    # consistent" -- an adversary can generate a keypair, call
    # create_crypto_package over content of their choosing, and produce a
    # package whose every layer verifies.  Reporting all_valid True for that
    # made the safe default the one nobody selected.  Callers who genuinely
    # only want self-consistency read `core_valid`, which is unchanged.
    _core_keys = {"content_hash", "hmac", "primary_signature", "hkdf_keys"}
    _aggregate_exclude = {"core_valid", "all_valid", "primary"}
    core_results = {k: v for k, v in results.items() if k in _core_keys}
    results["core_valid"] = all(core_results.values()) if core_results else False
    results["all_valid"] = all(v for k, v in results.items() if k not in _aggregate_exclude)

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
    "quick_hmac",
    "quick_hkdf",
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
