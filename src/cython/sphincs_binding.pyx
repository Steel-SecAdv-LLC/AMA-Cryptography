# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False

"""
Copyright 2025-2026 Steel Security Advisors LLC
Licensed under the Apache License, Version 2.0

AMA Cryptography — Native SPHINCS+/SLH-DSA Cython Binding
==========================================================

Direct C-to-C calls to ama_sphincs_*() with zero Python marshaling overhead.
INVARIANT-1 compliant: uses only AMA's own native C implementation.
NIST FIPS 205 compliant: SLH-DSA (SPHINCS+-256f).
"""

from libc.stdint cimport uint8_t
from libc.stddef cimport size_t
from libc.stdlib cimport malloc, free
from libc.string cimport memcpy

# SPHINCS+-256f sizes per FIPS 205
DEF SPHINCS_PK_BYTES = 64
DEF SPHINCS_SK_BYTES = 128
DEF SPHINCS_SIG_MAX_BYTES = 49856  # SPHINCS+-256f max signature size

cdef extern from "ama_cryptography.h":
    ctypedef int ama_error_t

    ama_error_t ama_sphincs_keypair(
        uint8_t *public_key, uint8_t *secret_key
    )

    ama_error_t ama_sphincs_sign(
        uint8_t *signature, size_t *signature_len,
        const uint8_t *message, size_t message_len,
        const uint8_t *secret_key
    )

    ama_error_t ama_sphincs_verify(
        const uint8_t *message, size_t message_len,
        const uint8_t *signature, size_t signature_len,
        const uint8_t *public_key
    )

    void ama_secure_memzero(void *ptr, size_t len)


def cy_sphincs_keypair():
    """
    Generate SPHINCS+-256f (SLH-DSA) keypair via native C.
    Cython binding — zero Python marshaling overhead.
    INVARIANT-1 compliant: calls only ama_cryptography native C.
    FIPS 205 compliant: SLH-DSA-256f.

    Returns:
        (public_key, secret_key) as bytes

    Raises:
        RuntimeError: on native C failure
        MemoryError: on allocation failure
    """
    cdef unsigned char pk[64]   # SPHINCS_PK_BYTES
    cdef unsigned char *sk = <unsigned char*>malloc(SPHINCS_SK_BYTES)
    if sk == NULL:
        raise MemoryError("Failed to allocate SPHINCS+ secret key buffer")

    cdef int ret
    try:
        ret = ama_sphincs_keypair(pk, sk)
        if ret != 0:
            raise RuntimeError(f"ama_sphincs_keypair failed (rc={ret})")
        return (bytes(pk[:SPHINCS_PK_BYTES]), bytes(sk[:SPHINCS_SK_BYTES]))
    finally:
        ama_secure_memzero(sk, SPHINCS_SK_BYTES)
        free(sk)


def cy_sphincs_sign(bytes message, bytes secret_key):
    """
    Sign message with SPHINCS+-256f via native C.
    Cython binding — zero Python marshaling overhead.
    INVARIANT-5 compliant: validates inputs at Python/C boundary.

    Args:
        message: message to sign
        secret_key: SPHINCS+ secret key (128 bytes)

    Returns:
        signature bytes

    Raises:
        ValueError: on invalid secret key length
        RuntimeError: on native C failure
        MemoryError: on allocation failure
    """
    if len(secret_key) != SPHINCS_SK_BYTES:
        raise ValueError(
            f"SPHINCS+ secret key must be {SPHINCS_SK_BYTES} bytes, "
            f"got {len(secret_key)}"
        )

    cdef unsigned char *sig = <unsigned char*>malloc(SPHINCS_SIG_MAX_BYTES)
    cdef unsigned char *sk_buf = <unsigned char*>malloc(SPHINCS_SK_BYTES)
    if sig == NULL or sk_buf == NULL:
        if sig != NULL:
            free(sig)
        if sk_buf != NULL:
            free(sk_buf)
        raise MemoryError("Failed to allocate SPHINCS+ sign buffers")

    cdef size_t sig_len = SPHINCS_SIG_MAX_BYTES
    cdef int ret
    try:
        memcpy(sk_buf, <const unsigned char*>secret_key, SPHINCS_SK_BYTES)
        ret = ama_sphincs_sign(
            sig, &sig_len,
            <const uint8_t*>message, len(message),
            sk_buf
        )
        ama_secure_memzero(sk_buf, SPHINCS_SK_BYTES)
        if ret != 0:
            raise RuntimeError(f"ama_sphincs_sign failed (rc={ret})")
        return bytes(sig[:sig_len])
    finally:
        ama_secure_memzero(sk_buf, SPHINCS_SK_BYTES)
        free(sig)
        free(sk_buf)


def cy_sphincs_verify(bytes signature, bytes message, bytes public_key):
    """
    Verify SPHINCS+-256f signature via native C.
    Cython binding — zero Python marshaling overhead.
    INVARIANT-5 compliant: validates inputs at Python/C boundary.

    Args:
        signature: SPHINCS+ signature bytes
        message: message to verify
        public_key: SPHINCS+ public key (64 bytes)

    Returns:
        True if valid, False otherwise

    Raises:
        ValueError: on invalid public key length
    """
    if len(public_key) != SPHINCS_PK_BYTES:
        raise ValueError(
            f"SPHINCS+ public key must be {SPHINCS_PK_BYTES} bytes, "
            f"got {len(public_key)}"
        )

    cdef int ret = ama_sphincs_verify(
        <const uint8_t*>message, len(message),
        <const uint8_t*>signature, len(signature),
        <const uint8_t*>public_key
    )
    return ret == 0
