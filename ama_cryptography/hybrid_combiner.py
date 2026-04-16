#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
AMA Cryptography - Hybrid Key Combiner
==========================================

Binding construction for hybrid KEM (classical + PQC) shared secrets
using the existing native HKDF-SHA3-256 implementation.

Follows the dual-PRF combiner approach from:
    Bindel, Brendel, Fischlin, Goncalves, Stebila.
    "Hybrid Key Encapsulation Mechanisms and Authenticated Key Exchange"
    (PQCrypto 2019 / IACR ePrint 2018/903)

The binding construction ensures that the combined shared secret is
secure if EITHER the classical or PQC component remains unbroken.
This is the standard IND-CCA2 secure combiner used in TLS 1.3
hybrid key agreement drafts.

Construction (length-prefixed encoding for domain separation):
    combined_ss = HKDF-SHA3-256(
        salt = len(classical_ct) || classical_ct || len(pqc_ct) || pqc_ct,
        ikm  = classical_ss || pqc_ss,
        info = label || component_count(2)
                     || len(classical_pk) || classical_pk
                     || len(pqc_pk) || pqc_pk,
        len  = 32
    )

The length-prefixed ciphertext binding in the salt prevents
mix-and-match and component stripping attacks.

Design decision: This module uses the established HKDF-SHA3-256 combiner
(RFC 5869) rather than the experimental Double-Helix KDF. The standard
combiner has formal IND-CCA2 security proofs and is auditable against
published specifications. Double-Helix KDF may be evaluated in a
dedicated research module once peer-reviewed analysis is available.

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Version: 2.1.2
"""

import ctypes
import hashlib
import logging
import struct
from dataclasses import dataclass
from typing import Any, List

logger = logging.getLogger(__name__)

# Default label for domain separation in hybrid HKDF
_HYBRID_LABEL = b"ama-hybrid-kem-v2"

# Upper bounds for KEM encapsulation/decapsulation output validation.
# These are generous limits — any legitimate KEM produces much smaller
# outputs — but prevent multi-GB allocation from attacker-controlled input.
_MAX_CT_BYTES = 8192  # generous upper bound for any KEM ciphertext
_MAX_SS_BYTES = 256  # generous upper bound for any shared secret


@dataclass
class HybridEncapsulation:
    """
    Result of a hybrid KEM encapsulation.

    Contains both component ciphertexts/secrets and the combined shared secret.

    Attributes:
        combined_secret: The binding-combined shared secret (32 bytes)
        classical_ciphertext: Classical KEM ciphertext (e.g., X25519 ephemeral public key)
        pqc_ciphertext: PQC KEM ciphertext (e.g., Kyber-1024 ciphertext, 1568 bytes)
        classical_shared_secret: Raw classical shared secret (before combination)
        pqc_shared_secret: Raw PQC shared secret (before combination)
    """

    combined_secret: bytes
    classical_ciphertext: bytes
    pqc_ciphertext: bytes
    classical_shared_secret: bytes
    pqc_shared_secret: bytes


class HybridCombiner:
    """
    Combines classical and PQC shared secrets via binding HKDF construction.

    Requires the native C HKDF-SHA3-256 (ama_hkdf) backend.  If the native
    library is unavailable, combine() raises RuntimeError per INVARIANT-7
    (no cryptographic fallbacks).  The _hkdf_python static method remains
    available for direct unit testing of the HKDF construction only.

    The combiner is algorithm-agnostic: it accepts raw shared secrets and
    ciphertexts from any classical + PQC KEM pair.

    Security properties:
        - IND-CCA2 secure if either component KEM is IND-CCA2
        - Ciphertext binding prevents substitution attacks
        - Public key binding provides full context binding
        - Domain-separated via configurable label
    """

    def __init__(
        self,
        native_lib: Any = None,
        label: bytes = _HYBRID_LABEL,
    ) -> None:
        """
        Args:
            native_lib: Pre-loaded ctypes CDLL of libama_cryptography
                        (auto-detected from pqc_backends if None)
            label: Domain separation label for HKDF info field
        """
        self.label = label
        self._native_lib = native_lib
        self._has_native = False

        if self._native_lib is None:
            self._native_lib = self._try_load_native()

        if self._native_lib is not None:
            self._has_native = self._setup_hkdf_ctypes(self._native_lib)

    @staticmethod
    def _try_load_native() -> Any:
        """Attempt to load the native library via pqc_backends."""
        try:
            from ama_cryptography.pqc_backends import _native_lib

            return _native_lib
        except (ImportError, AttributeError):
            return None

    @staticmethod
    def _setup_hkdf_ctypes(lib: Any) -> bool:
        """Configure ctypes for ama_hkdf. Returns True on success."""
        try:
            lib.ama_hkdf.argtypes = [
                ctypes.c_char_p,
                ctypes.c_size_t,  # salt, salt_len
                ctypes.c_char_p,
                ctypes.c_size_t,  # ikm, ikm_len
                ctypes.c_char_p,
                ctypes.c_size_t,  # info, info_len
                ctypes.c_char_p,
                ctypes.c_size_t,  # okm, okm_len
            ]
            lib.ama_hkdf.restype = ctypes.c_int
            return True
        except AttributeError:
            return False

    def combine(
        self,
        classical_ss: bytes,
        pqc_ss: bytes,
        classical_ct: bytes,
        pqc_ct: bytes,
        classical_pk: bytes = b"",
        pqc_pk: bytes = b"",
        output_len: int = 32,
    ) -> bytes:
        """
        Combine two shared secrets via binding HKDF.

        Args:
            classical_ss: Classical KEM shared secret
            pqc_ss: PQC KEM shared secret
            classical_ct: Classical KEM ciphertext (bound in salt)
            pqc_ct: PQC KEM ciphertext (bound in salt)
            classical_pk: Classical public key (bound in info, optional)
            pqc_pk: PQC public key (bound in info, optional)
            output_len: Desired output length (default 32)

        Returns:
            Combined shared secret of output_len bytes

        The construction uses length-prefixed encoding to provide
        unambiguous domain separation and prevent component stripping:

            salt = len(classical_ct) || classical_ct || len(pqc_ct) || pqc_ct
            ikm  = classical_ss || pqc_ss
            info = label || component_count(2) || len(classical_pk) || classical_pk
                        || len(pqc_pk) || pqc_pk
            output = HKDF(salt, ikm, info, output_len)
        """
        # SECURITY FIX (audit finding C6): Use length-prefixed encoding
        # for all variable-length components.  This prevents component
        # stripping / substitution attacks where an attacker manipulates
        # boundaries between classical and PQC ciphertexts or public keys.
        salt = (
            struct.pack(">I", len(classical_ct))
            + classical_ct
            + struct.pack(">I", len(pqc_ct))
            + pqc_ct
        )
        ikm = classical_ss + pqc_ss
        # Component count (2) is bound to prevent downgrade to single-component
        info = (
            self.label
            + struct.pack(">B", 2)  # component_count: always 2 for hybrid
            + struct.pack(">I", len(classical_pk))
            + classical_pk
            + struct.pack(">I", len(pqc_pk))
            + pqc_pk
        )

        if self._has_native:
            return self._hkdf_native(salt, ikm, info, output_len)
        # INVARIANT-7: No cryptographic fallbacks, ever.
        # The Python HKDF is NOT constant-time and MUST NOT be used for
        # secret-dependent key combination.  The _hkdf_python static method
        # remains in the class for direct unit testing of the HKDF construction
        # (see TestHKDFEdgeCases), but combine() refuses to use it.
        raise RuntimeError(
            "INVARIANT-7: Native HKDF-SHA3-256 (ama_hkdf) is unavailable. "
            "The Python fallback is not constant-time and MUST NOT be used "
            "for cryptographic key combination.  Build the native C library: "
            "cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
        )

    def _hkdf_native(self, salt: bytes, ikm: bytes, info: bytes, okm_len: int) -> bytes:
        """HKDF via native C ama_hkdf (HMAC-SHA3-256)."""
        okm_buf = ctypes.create_string_buffer(okm_len)
        rc = self._native_lib.ama_hkdf(
            salt,
            ctypes.c_size_t(len(salt)),
            ikm,
            ctypes.c_size_t(len(ikm)),
            info,
            ctypes.c_size_t(len(info)),
            okm_buf,
            ctypes.c_size_t(okm_len),
        )
        if rc != 0:
            raise RuntimeError(f"Native HKDF failed with error code {rc}")
        return bytes(okm_buf)

    @staticmethod
    def _hkdf_python(salt: bytes, ikm: bytes, info: bytes, okm_len: int) -> bytes:
        """Internal test-only fallback. Do NOT call from production code paths.

        Use the C-backed HKDF implementation (ama_hkdf) instead.
        combine() enforces INVARIANT-7 by refusing to call this method;
        it exists solely for direct unit testing of the HKDF construction
        (see TestHKDFEdgeCases).

        NOT constant-time — MUST NOT process secret material.

        Matches the native C ama_hkdf (HMAC-SHA3-256, RFC 5869).
        SHA3-256 block size (rate) = 136 bytes, digest size = 32 bytes.
        """
        hash_len = 32  # SHA3-256 digest size
        block_size = 136  # SHA3-256 rate (Keccak sponge rate for SHA3-256)

        def _hmac_sha3_256(key: bytes, data: bytes) -> bytes:
            """HMAC-SHA3-256 per RFC 2104, using SHA3-256 as H."""
            # If key > block_size, hash it first
            if len(key) > block_size:
                key = hashlib.sha3_256(key).digest()
            # Pad key to block_size
            key_padded = key + b"\x00" * (block_size - len(key))
            # ipad / opad
            ipad = bytes(b ^ 0x36 for b in key_padded)
            opad = bytes(b ^ 0x5C for b in key_padded)
            # inner = SHA3-256(ipad || data)
            inner = hashlib.sha3_256(ipad + data).digest()
            # outer = SHA3-256(opad || inner)
            return hashlib.sha3_256(opad + inner).digest()

        # Extract: PRK = HMAC-SHA3-256(salt, IKM)
        if not salt:
            salt = b"\x00" * hash_len
        prk = _hmac_sha3_256(salt, ikm)

        # Expand: OKM = T(1) || T(2) || ... truncated to okm_len
        n = (okm_len + hash_len - 1) // hash_len
        if n > 255:
            raise ValueError("HKDF output length exceeds maximum (255 * hash_len)")

        okm_parts: List[bytes] = []
        t_prev = b""
        for i in range(1, n + 1):
            t_prev = _hmac_sha3_256(prk, t_prev + info + bytes([i]))
            okm_parts.append(t_prev)

        return b"".join(okm_parts)[:okm_len]

    def encapsulate_hybrid(
        self,
        classical_encapsulate: Any,
        pqc_encapsulate: Any,
        classical_pk: bytes,
        pqc_pk: bytes,
    ) -> HybridEncapsulation:
        """
        Perform full hybrid encapsulation.

        Calls both classical and PQC encapsulation functions, then combines
        the shared secrets via the binding construction.

        Args:
            classical_encapsulate: Callable(pk) -> (ciphertext, shared_secret)
            pqc_encapsulate: Callable(pk) -> (ciphertext, shared_secret)
            classical_pk: Classical public key
            pqc_pk: PQC public key

        Returns:
            HybridEncapsulation with combined secret and component data
        """
        classical_ct, classical_ss = classical_encapsulate(classical_pk)
        pqc_ct, pqc_ss = pqc_encapsulate(pqc_pk)

        # SECURITY FIX: Validate encapsulation outputs to prevent injection
        # of zero-length secrets, oversized ciphertexts, or non-bytes types
        # that could cause downstream key compromise or DoS (audit finding H4).
        for label, ct, ss in [
            ("Classical", classical_ct, classical_ss),
            ("PQC", pqc_ct, pqc_ss),
        ]:
            if not isinstance(ct, bytes) or not isinstance(ss, bytes):
                raise TypeError(f"{label} encapsulate must return (bytes, bytes)")
            if len(ss) == 0:
                raise ValueError(f"{label} shared secret is empty")
            if len(ct) == 0:
                raise ValueError(f"{label} ciphertext is empty")
            if len(ct) > _MAX_CT_BYTES:
                raise ValueError(f"{label} ciphertext too large ({len(ct)} > {_MAX_CT_BYTES})")
            if len(ss) > _MAX_SS_BYTES:
                raise ValueError(f"{label} shared secret too large ({len(ss)} > {_MAX_SS_BYTES})")

        combined = self.combine(
            classical_ss=classical_ss,
            pqc_ss=pqc_ss,
            classical_ct=classical_ct,
            pqc_ct=pqc_ct,
            classical_pk=classical_pk,
            pqc_pk=pqc_pk,
        )

        return HybridEncapsulation(
            combined_secret=combined,
            classical_ciphertext=classical_ct,
            pqc_ciphertext=pqc_ct,
            classical_shared_secret=classical_ss,
            pqc_shared_secret=pqc_ss,
        )

    def decapsulate_hybrid(
        self,
        classical_decapsulate: Any,
        pqc_decapsulate: Any,
        classical_ct: bytes,
        pqc_ct: bytes,
        classical_sk: bytes,
        pqc_sk: bytes,
        classical_pk: bytes = b"",
        pqc_pk: bytes = b"",
    ) -> bytes:
        """
        Perform full hybrid decapsulation.

        Calls both classical and PQC decapsulation functions, then combines
        the recovered shared secrets via the same binding construction.

        Args:
            classical_decapsulate: Callable(ct, sk) -> shared_secret
            pqc_decapsulate: Callable(ct, sk) -> shared_secret
            classical_ct: Classical ciphertext
            pqc_ct: PQC ciphertext
            classical_sk: Classical secret key
            pqc_sk: PQC secret key
            classical_pk: Classical public key (for info binding)
            pqc_pk: PQC public key (for info binding)

        Returns:
            Combined shared secret (must match encapsulate output)
        """
        classical_ss = classical_decapsulate(classical_ct, classical_sk)
        pqc_ss = pqc_decapsulate(pqc_ct, pqc_sk)

        # SECURITY FIX: Validate decapsulation outputs (audit finding H4).
        # Same validation as encapsulate_hybrid — a buggy or attacker-controlled
        # decapsulate callable could return empty, non-bytes, or oversized values.
        for label, ss in [("Classical", classical_ss), ("PQC", pqc_ss)]:
            if not isinstance(ss, bytes):
                raise TypeError(f"{label} decapsulate must return bytes")
            if len(ss) == 0:
                raise ValueError(f"{label} shared secret is empty")
            if len(ss) > _MAX_SS_BYTES:
                raise ValueError(f"{label} shared secret too large ({len(ss)} > {_MAX_SS_BYTES})")

        return self.combine(
            classical_ss=classical_ss,
            pqc_ss=pqc_ss,
            classical_ct=classical_ct,
            pqc_ct=pqc_ct,
            classical_pk=classical_pk,
            pqc_pk=pqc_pk,
        )
