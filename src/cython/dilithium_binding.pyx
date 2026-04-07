# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False

"""
Copyright 2025-2026 Steel Security Advisors LLC
Licensed under the Apache License, Version 2.0

AMA Cryptography — Native ML-DSA-65 (Dilithium) Cython Binding
===============================================================

Direct C-to-C calls to ama_dilithium_*() with zero Python marshaling overhead.
INVARIANT-1 compliant: uses only AMA's own native C implementation.
NIST FIPS 204 compliant: ML-DSA-65 (CRYSTALS-Dilithium Level 3).
"""

from libc.stdint cimport uint8_t
from libc.stddef cimport size_t
from libc.stdlib cimport malloc, free
from libc.string cimport memcpy, memset

# Key/signature sizes per NIST FIPS 204
DEF DILITHIUM_PK_BYTES = 1952
DEF DILITHIUM_SK_BYTES = 4032
DEF DILITHIUM_SIG_BYTES = 3309

cdef extern from "ama_cryptography.h":
    ctypedef int ama_error_t

    ama_error_t ama_dilithium_keypair(
        uint8_t *public_key, uint8_t *secret_key
    )

    ama_error_t ama_dilithium_sign(
        uint8_t *signature, size_t *sig_len,
        const uint8_t *message, size_t message_len,
        const uint8_t *secret_key
    )

    ama_error_t ama_dilithium_verify(
        const uint8_t *message, size_t message_len,
        const uint8_t *signature, size_t sig_len,
        const uint8_t *public_key
    )

    void ama_secure_memzero(void *ptr, size_t len)


def cy_dilithium_keygen():
    """
    Generate ML-DSA-65 keypair via native C.
    Returns (public_key, secret_key) as bytes.
    Raises RuntimeError on native C failure.
    """
    cdef unsigned char *pk = <unsigned char*>malloc(DILITHIUM_PK_BYTES)
    cdef unsigned char *sk = <unsigned char*>malloc(DILITHIUM_SK_BYTES)
    if pk == NULL or sk == NULL:
        if pk != NULL:
            free(pk)
        if sk != NULL:
            free(sk)
        raise MemoryError("Failed to allocate Dilithium key buffers")

    cdef int ret
    try:
        ret = ama_dilithium_keypair(pk, sk)
        if ret != 0:
            raise RuntimeError(f"ama_dilithium_keypair failed (rc={ret})")
        return (bytes(pk[:DILITHIUM_PK_BYTES]), bytes(sk[:DILITHIUM_SK_BYTES]))
    finally:
        ama_secure_memzero(sk, DILITHIUM_SK_BYTES)
        free(pk)
        free(sk)


def cy_dilithium_sign(bytes message, bytes secret_key):
    """
    Sign message with ML-DSA-65 via native C.
    Returns signature bytes.
    Raises RuntimeError on native C failure.
    """
    if len(secret_key) != DILITHIUM_SK_BYTES:
        raise ValueError(
            f"Dilithium secret key must be {DILITHIUM_SK_BYTES} bytes, "
            f"got {len(secret_key)}"
        )

    cdef unsigned char *sig = <unsigned char*>malloc(DILITHIUM_SIG_BYTES)
    cdef unsigned char *sk_buf = <unsigned char*>malloc(DILITHIUM_SK_BYTES)
    if sig == NULL or sk_buf == NULL:
        if sig != NULL:
            free(sig)
        if sk_buf != NULL:
            free(sk_buf)
        raise MemoryError("Failed to allocate Dilithium sign buffers")

    cdef size_t sig_len = DILITHIUM_SIG_BYTES
    cdef int ret
    try:
        memcpy(sk_buf, <const unsigned char*>secret_key, DILITHIUM_SK_BYTES)
        ret = ama_dilithium_sign(
            sig, &sig_len,
            <const uint8_t*>message, len(message),
            sk_buf
        )
        ama_secure_memzero(sk_buf, DILITHIUM_SK_BYTES)
        if ret != 0:
            raise RuntimeError(f"ama_dilithium_sign failed (rc={ret})")
        return bytes(sig[:sig_len])
    finally:
        ama_secure_memzero(sk_buf, DILITHIUM_SK_BYTES)
        free(sig)
        free(sk_buf)


def cy_dilithium_verify(bytes signature, bytes message, bytes public_key):
    """
    Verify ML-DSA-65 signature via native C.
    Returns True if valid, False otherwise.
    """
    if len(public_key) != DILITHIUM_PK_BYTES:
        raise ValueError(
            f"Dilithium public key must be {DILITHIUM_PK_BYTES} bytes, "
            f"got {len(public_key)}"
        )

    cdef int ret = ama_dilithium_verify(
        <const uint8_t*>message, len(message),
        <const uint8_t*>signature, len(signature),
        <const uint8_t*>public_key
    )
    return ret == 0
