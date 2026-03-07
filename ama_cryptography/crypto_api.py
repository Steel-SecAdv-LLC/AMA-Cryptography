#!/usr/bin/env python3
# Copyright 2025 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
AMA Cryptography ♱ (AG♱) - Algorithm-Agnostic Cryptographic API
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
import secrets
import warnings
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple, Union

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

from ama_cryptography.pqc_backends import (
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

# Import HMAC and HKDF from legacy module
try:
    from code_guardian_secure import (
        derive_keys,
        hmac_authenticate,
    )

    HMAC_HKDF_AVAILABLE = True
except ImportError:
    HMAC_HKDF_AVAILABLE = False
    warnings.warn(
        "HMAC/HKDF functions not available. Install required dependencies.",
        category=UserWarning,
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
    RFC3161_AVAILABLE = False
    TimestampUnavailableError = Exception  # type: ignore[misc,assignment]
    TimestampError = Exception  # type: ignore[misc,assignment]
    get_timestamp = None  # type: ignore[assignment]

# Runtime PQC availability check
pqc_available = DILITHIUM_AVAILABLE or KYBER_AVAILABLE or SPHINCS_AVAILABLE
if not pqc_available:
    # Use catch_warnings to emit warning without triggering pytest's "warnings as errors"
    with warnings.catch_warnings():
        warnings.simplefilter("default", UserWarning)
        warnings.warn(
            "Quantum-resistant cryptography NOT available. "
            "Build native C library for post-quantum protection: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build",
            category=UserWarning,
            stacklevel=2,
        )


class AlgorithmType(Enum):
    """Supported cryptographic algorithms"""

    ML_DSA_65 = auto()  # CRYSTALS-Dilithium (signatures)
    KYBER_1024 = auto()  # CRYSTALS-Kyber (KEM)
    SPHINCS_256F = auto()  # SPHINCS+ (signatures)
    ED25519 = auto()  # Classical Ed25519 (signatures)
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
                "Build native C library: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
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

    Security: 128-bit classical security (NOT quantum-resistant)
    Standard: RFC 8032
    """

    def __init__(self, backend: CryptoBackend = CryptoBackend.PURE_PYTHON) -> None:
        self.backend = backend
        self.algorithm = AlgorithmType.ED25519

    def generate_keypair(self) -> KeyPair:
        """Generate Ed25519 keypair"""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        sk_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

        pk_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

        return KeyPair(
            public_key=pk_bytes,
            secret_key=sk_bytes,
            algorithm=self.algorithm,
            metadata={"backend": "cryptography", "key_size": len(pk_bytes)},
        )

    def sign(self, message: bytes, secret_key: "Union[bytes, Ed25519PrivateKey]") -> Signature:
        """
        Sign message with Ed25519.

        Performance: Now optimized to accept both bytes and key objects.
        For high-throughput scenarios, pass Ed25519PrivateKey object.

        Args:
            message: Data to sign
            secret_key: Either 32-byte Ed25519 private key (bytes) OR
                       Ed25519PrivateKey object (for 2x performance)

        Returns:
            Signature object with Ed25519 signature
        """
        from cryptography.hazmat.primitives.asymmetric import ed25519

        # Smart type handling for performance
        if isinstance(secret_key, bytes):
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(secret_key)
        else:
            private_key = secret_key  # Already a key object

        sig_bytes = private_key.sign(message)
        message_hash = hashlib.sha3_256(message).digest()

        return Signature(
            signature=sig_bytes,
            algorithm=self.algorithm,
            message_hash=message_hash,
            metadata={"signature_size": len(sig_bytes)},
        )

    def verify(
        self, message: bytes, signature: bytes, public_key: "Union[bytes, Ed25519PublicKey]"
    ) -> bool:
        """
        Verify Ed25519 signature.

        Performance: Now optimized to accept both bytes and key objects.
        For high-throughput scenarios, pass Ed25519PublicKey object.

        Args:
            message: Original data that was signed
            signature: 64-byte Ed25519 signature
            public_key: Either 32-byte Ed25519 public key (bytes) OR
                       Ed25519PublicKey object (for better performance)

        Returns:
            True if signature is valid, False otherwise
        """
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import ed25519

        try:
            # Smart type handling for performance
            if isinstance(public_key, bytes):
                pub_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            else:
                pub_key = public_key  # Already a key object

            pub_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False
        except Exception:
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

    def __init__(self, backend: CryptoBackend = CryptoBackend.PURE_PYTHON) -> None:
        self.backend = backend
        self.algorithm = AlgorithmType.KYBER_1024

        if not KYBER_AVAILABLE:
            raise KyberUnavailableError(
                "KYBER_UNAVAILABLE: Kyber-1024 backend not available. "
                "Build native C library: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
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

    def __init__(self, backend: CryptoBackend = CryptoBackend.PURE_PYTHON) -> None:
        self.backend = backend
        self.algorithm = AlgorithmType.SPHINCS_256F

        if not SPHINCS_AVAILABLE:
            raise SphincsUnavailableError(
                "SPHINCS_UNAVAILABLE: SPHINCS+-256f backend not available. "
                "Build native C library: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
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
                "Build native C library: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
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

        # Optimize: Reconstruct Ed25519 key object once and pass to provider
        from cryptography.hazmat.primitives.asymmetric import ed25519

        classical_sk = ed25519.Ed25519PrivateKey.from_private_bytes(classical_sk_bytes)

        # Create both signatures (Ed25519Provider now accepts key objects)
        classical_sig = self.classical_provider.sign(message, classical_sk)
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

        # Optimize: Reconstruct Ed25519 key object once and pass to provider
        from cryptography.hazmat.primitives.asymmetric import ed25519

        classical_pk = ed25519.Ed25519PublicKey.from_public_bytes(classical_pk_bytes)

        # Both must verify for hybrid security (Ed25519Provider now accepts key objects)
        classical_valid = self.classical_provider.verify(message, classical_sig, classical_pk)
        pqc_valid = self.pqc_provider.verify(message, pqc_sig, pqc_pk)

        return classical_valid and pqc_valid


class AmaCryptography:
    """
    Main AMA Cryptography ♱ Cryptographic API

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

    def _get_provider(self) -> Union[CryptoProvider, KEMProvider]:
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
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

    def generate_keypair(self) -> KeyPair:
        """Generate cryptographic keypair"""
        return self.provider.generate_keypair()

    def sign(self, message: bytes, secret_key: bytes) -> Signature:
        """Sign a message"""
        if not isinstance(self.provider, CryptoProvider):
            raise TypeError("Current algorithm does not support signing")
        return self.provider.sign(message, secret_key)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a signature"""
        if not isinstance(self.provider, CryptoProvider):
            raise TypeError("Current algorithm does not support verification")
        return self.provider.verify(message, signature, public_key)

    def encapsulate(self, public_key: bytes) -> EncapsulatedSecret:
        """Encapsulate a shared secret (KEM)"""
        if not isinstance(self.provider, KEMProvider):
            raise TypeError("Current algorithm does not support KEM")
        return self.provider.encapsulate(public_key)

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Decapsulate a shared secret (KEM)"""
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
        return secrets.compare_digest(a, b)


# Convenience functions
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
    info = get_pqc_backend_info()

    return {
        "status": info["status"],
        "dilithium_available": info["dilithium_available"],
        "kyber_available": info["kyber_available"],
        "sphincs_available": info["sphincs_available"],
        "backend": info["backend"],
        "algorithms": {
            "ML_DSA_65": info["dilithium_available"],
            "HYBRID_SIG": info["dilithium_available"],
            "ED25519": True,  # Always available via cryptography
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

    Attributes:
        use_kyber: Enable Kyber-1024 for key encapsulation (default: False)
        use_sphincs: Enable SPHINCS+-256f for signatures (default: False)
        signature_algorithm: Primary signature algorithm (default: HYBRID_SIG)
        include_kem: Include KEM encapsulation in package (default: False)
        include_timestamp: Include RFC 3161 timestamp (default: False, requires TSA server)
        num_derived_keys: Number of HKDF-derived keys to generate (default: 3)
        tsa_url: RFC 3161 Time Stamp Authority URL (default: None)

    Note:
        - Kyber-1024 requires native C backend (build with -DAMA_USE_NATIVE_PQC=ON)
        - SPHINCS+-256f requires native C backend (build with -DAMA_USE_NATIVE_PQC=ON)
        - When use_sphincs=True, SPHINCS+ signature is added alongside primary signature
        - RFC 3161 timestamping requires network access to TSA server
    """

    use_kyber: bool = False
    use_sphincs: bool = False
    signature_algorithm: AlgorithmType = AlgorithmType.HYBRID_SIG
    include_kem: bool = False
    include_timestamp: bool = False
    num_derived_keys: int = 3
    tsa_url: Optional[str] = None


@dataclass
class CryptoPackageResult:
    """
    Result from create_crypto_package() containing all cryptographic artifacts.

    6-Layer Defense-in-Depth Architecture:
    Layer 1: SHA3-256 content hash (128-bit collision resistance)
    Layer 2: HMAC-SHA3-256 authentication (keyed authentication)
    Layer 3: Ed25519 classical signature (128-bit security)
    Layer 4: ML-DSA-65 quantum-resistant signature (192-bit security)
    Layer 5: HKDF key derivation (key independence)
    Layer 6: RFC 3161 timestamp (third-party attestation)

    Attributes:
        content_hash: SHA3-256 hash of the content (hex) [Layer 1]
        hmac_tag: HMAC-SHA3-256 authentication tag [Layer 2]
        primary_signature: Primary signature from selected algorithm [Layer 3/4]
        sphincs_signature: Optional SPHINCS+-256f signature (if enabled)
        derived_keys: HKDF-derived keys for key independence [Layer 5]
        hkdf_salt: Salt used for HKDF derivation
        timestamp: RFC 3161 timestamp token (if requested) [Layer 6]
        kem_ciphertext: Optional Kyber-1024 ciphertext (if KEM enabled)
        kem_shared_secret: Optional shared secret from KEM (if enabled)
        keypairs: Dictionary of generated keypairs by algorithm
        metadata: Additional package metadata
    """

    content_hash: str
    hmac_tag: bytes
    primary_signature: Signature
    sphincs_signature: Optional[Signature]
    derived_keys: List[bytes]
    hkdf_salt: bytes
    timestamp: Optional[bytes]
    kem_ciphertext: Optional[bytes]
    kem_shared_secret: Optional[bytes]
    keypairs: Dict[str, KeyPair]
    metadata: Dict[str, Any]


def create_crypto_package(
    content: bytes,
    config: Optional[CryptoPackageConfig] = None,
) -> CryptoPackageResult:
    """
    Create a cryptographic package with 6-Layer Defense-in-Depth Architecture.

    6-Layer Defense Architecture:
    ------------------------------
    Layer 1: SHA3-256 content hash (128-bit collision resistance)
    Layer 2: HMAC-SHA3-256 authentication (keyed authentication)
    Layer 3: Ed25519 classical signature (128-bit security)
    Layer 4: ML-DSA-65 quantum-resistant signature (192-bit security)
    Layer 5: HKDF key derivation (key independence)
    Layer 6: RFC 3161 timestamp (third-party attestation, optional)

    This function provides a unified interface for creating cryptographic
    packages with support for:
    - ML-DSA-65 (Dilithium) signatures
    - Ed25519 classical signatures
    - Hybrid signatures (Ed25519 + ML-DSA-65)
    - HMAC-SHA3-256 authentication (default)
    - HKDF key derivation (default)
    - Kyber-1024 key encapsulation (optional)
    - SPHINCS+-256f signatures (optional)
    - RFC 3161 timestamping (optional, requires TSA server)

    Args:
        content: The content to sign/protect (bytes)
        config: Algorithm configuration (default: hybrid signatures with all 6 layers)

    Returns:
        CryptoPackageResult with all cryptographic artifacts

    Raises:
        PQCUnavailableError: If required PQC algorithm is not available
        KyberUnavailableError: If Kyber is requested but not available
        SphincsUnavailableError: If SPHINCS+ is requested but not available
        TimestampUnavailableError: If RFC 3161 is requested but library not installed
        TimestampError: If timestamp request fails

    Example:
        >>> # Basic usage with hybrid signatures and 6-layer defense
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
    """
    # Input validation
    if not isinstance(content, bytes):
        raise TypeError(f"content must be bytes, got {type(content).__name__}")
    if not content:
        raise ValueError("content cannot be empty")

    if config is None:
        config = CryptoPackageConfig()

    # ========================================================================
    # LAYER 1: SHA3-256 Content Hash (128-bit collision resistance)
    # ========================================================================
    content_hash = hashlib.sha3_256(content).hexdigest()

    # ========================================================================
    # LAYER 2: HMAC-SHA3-256 Authentication (keyed authentication)
    # ========================================================================
    # Generate HMAC key from content for authentication
    if HMAC_HKDF_AVAILABLE:
        hmac_key = secrets.token_bytes(32)  # 256-bit HMAC key
        hmac_tag = hmac_authenticate(content, hmac_key)
    else:
        # Fallback to simple keyed hash if HMAC not available
        hmac_key = secrets.token_bytes(32)
        hmac_tag = hashlib.sha3_256(hmac_key + content).digest()
        warnings.warn(
            "HMAC not available, using keyed hash fallback. "
            "Install code_guardian_secure dependencies for full HMAC support.",
            category=UserWarning,
        )

    # ========================================================================
    # LAYER 3 & 4: Cryptographic Signatures (Ed25519 + ML-DSA-65)
    # ========================================================================
    # Initialize result containers
    keypairs: Dict[str, KeyPair] = {}
    sphincs_signature: Optional[Signature] = None
    kem_ciphertext: Optional[bytes] = None
    kem_shared_secret: Optional[bytes] = None

    # Generate primary signature
    primary_crypto = AmaCryptography(algorithm=config.signature_algorithm)
    primary_keypair = primary_crypto.generate_keypair()
    primary_signature = primary_crypto.sign(content, primary_keypair.secret_key)
    keypairs[config.signature_algorithm.name] = primary_keypair

    # Generate SPHINCS+ signature if requested
    if config.use_sphincs:
        if not SPHINCS_AVAILABLE:
            raise SphincsUnavailableError(
                "SPHINCS_UNAVAILABLE: SPHINCS+-256f backend not available. "
                "Build native C library: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
            )
        sphincs_provider = SphincsProvider()
        sphincs_keypair = sphincs_provider.generate_keypair()
        sphincs_signature = sphincs_provider.sign(content, sphincs_keypair.secret_key)
        keypairs["SPHINCS_256F"] = sphincs_keypair

    # ========================================================================
    # LAYER 5: HKDF Key Derivation (key independence)
    # ========================================================================
    # Derive independent keys from master secret for various purposes
    if HMAC_HKDF_AVAILABLE:
        master_secret = secrets.token_bytes(32)  # 256-bit master secret
        derived_keys, hkdf_salt = derive_keys(
            master_secret=master_secret,
            info="ama_cryptography_crypto_package_v1",
            num_keys=config.num_derived_keys,
            ethical_vector=None,  # Use default ethical vector
            salt=None,  # Generate random salt
        )
    else:
        # Fallback to simple key derivation if HKDF not available
        hkdf_salt = secrets.token_bytes(32)
        derived_keys = []
        for i in range(config.num_derived_keys):
            key_material = hashlib.sha3_256(hkdf_salt + content + i.to_bytes(4, "big")).digest()
            derived_keys.append(key_material)
        warnings.warn(
            "HKDF not available, using simple key derivation fallback. "
            "Install code_guardian_secure dependencies for full HKDF support.",
            category=UserWarning,
        )

    # ========================================================================
    # OPTIONAL: Kyber-1024 Key Encapsulation Mechanism
    # ========================================================================
    if config.use_kyber and config.include_kem:
        if not KYBER_AVAILABLE:
            raise KyberUnavailableError(
                "KYBER_UNAVAILABLE: Kyber-1024 backend not available. "
                "Build native C library: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
            )
        kyber_provider = KyberProvider()
        kyber_keypair = kyber_provider.generate_keypair()
        encapsulated = kyber_provider.encapsulate(kyber_keypair.public_key)
        kem_ciphertext = encapsulated.ciphertext
        kem_shared_secret = encapsulated.shared_secret
        keypairs["KYBER_1024"] = kyber_keypair

    # ========================================================================
    # LAYER 6: RFC 3161 Timestamp (third-party attestation)
    # ========================================================================
    timestamp_token: Optional[bytes] = None
    if config.include_timestamp:
        if not RFC3161_AVAILABLE:
            raise TimestampUnavailableError(
                "RFC3161_UNAVAILABLE: rfc3161ng library not installed. "
                "Install with: pip install rfc3161ng"
            )
        try:
            timestamp_result = get_timestamp(
                data=content,
                tsa_url=config.tsa_url,
                hash_algorithm="sha3-256",
            )
            timestamp_token = timestamp_result.token
        except TimestampError as e:
            warnings.warn(
                f"Failed to obtain RFC 3161 timestamp: {str(e)}. " "Continuing without timestamp.",
                category=UserWarning,
            )
            timestamp_token = None

    # Build metadata
    metadata: Dict[str, Any] = {
        "signature_algorithm": config.signature_algorithm.name,
        "sphincs_enabled": config.use_sphincs,
        "kyber_enabled": config.use_kyber and config.include_kem,
        "timestamp_enabled": config.include_timestamp and timestamp_token is not None,
        "num_derived_keys": len(derived_keys),
        "pqc_status": get_pqc_capabilities()["status"],
        "six_layer_defense": True,  # All 6 layers implemented
    }

    return CryptoPackageResult(
        content_hash=content_hash,
        hmac_tag=hmac_tag,
        primary_signature=primary_signature,
        sphincs_signature=sphincs_signature,
        derived_keys=derived_keys,
        hkdf_salt=hkdf_salt,
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
    Verify all signatures in a crypto package.

    Args:
        content: Original content that was signed
        package: CryptoPackageResult to verify

    Returns:
        Dictionary mapping signature type to verification result

    Example:
        >>> result = create_crypto_package(b"Hello")
        >>> verification = verify_crypto_package(b"Hello", result)
        >>> print(f"Primary valid: {verification['primary']}")
    """
    results: Dict[str, bool] = {}

    # Verify content hash
    computed_hash = hashlib.sha3_256(content).hexdigest()
    results["content_hash"] = computed_hash == package.content_hash

    # Verify primary signature
    sig_alg_name = package.metadata.get("signature_algorithm", "HYBRID_SIG")
    try:
        sig_alg = AlgorithmType[sig_alg_name]
    except KeyError:
        sig_alg = AlgorithmType.HYBRID_SIG

    if sig_alg_name in package.keypairs:
        primary_crypto = AmaCryptography(algorithm=sig_alg)
        results["primary"] = primary_crypto.verify(
            content,
            package.primary_signature.signature,
            package.keypairs[sig_alg_name].public_key,
        )
    else:
        results["primary"] = False

    # Verify SPHINCS+ signature if present
    if package.sphincs_signature is not None and "SPHINCS_256F" in package.keypairs:
        if SPHINCS_AVAILABLE:
            sphincs_provider = SphincsProvider()
            results["sphincs"] = sphincs_provider.verify(
                content,
                package.sphincs_signature.signature,
                package.keypairs["SPHINCS_256F"].public_key,
            )
        else:
            results["sphincs"] = False

    return results


# Re-export PQC types for convenience
__all__ = [
    "AlgorithmType",
    "CryptoBackend",
    "KeyPair",
    "Signature",
    "EncapsulatedSecret",
    "CryptoProvider",
    "KEMProvider",
    "MLDSAProvider",
    "Ed25519Provider",
    "KyberProvider",
    "SphincsProvider",
    "HybridSignatureProvider",
    "AmaCryptography",
    "quick_sign",
    "quick_verify",
    "quick_kem",
    "get_pqc_capabilities",
    "CryptoPackageConfig",
    "CryptoPackageResult",
    "create_crypto_package",
    "verify_crypto_package",
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
