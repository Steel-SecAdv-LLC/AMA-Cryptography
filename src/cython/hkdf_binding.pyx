# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False

"""
Copyright 2025-2026 Steel Security Advisors LLC
Licensed under the Apache License, Version 2.0

AMA Cryptography — Native HKDF-SHA3-256 Cython Binding
======================================================

Direct C-to-C call to ama_hkdf() with zero Python marshaling overhead.
INVARIANT-1 compliant: uses only AMA's own native C implementation.
RFC 5869 compliant: HKDF Extract-then-Expand with HMAC-SHA3-256.
"""

from libc.stdint cimport uint8_t
from libc.stddef cimport size_t
from libc.stdlib cimport malloc, free

cdef extern from "ama_cryptography.h":
    ctypedef int ama_error_t

    ama_error_t ama_hkdf(
        const uint8_t *salt, size_t salt_len,
        const uint8_t *ikm, size_t ikm_len,
        const uint8_t *info, size_t info_len,
        uint8_t *okm, size_t okm_len
    )

    void ama_secure_memzero(void *ptr, size_t len)


def cy_hkdf(bytes ikm, int length, bytes salt=None, bytes info=None):
    """
    HKDF-SHA3-256 key derivation via native C ama_hkdf().
    Cython binding — zero Python marshaling overhead.
    INVARIANT-1 compliant: calls only ama_cryptography native C.
    RFC 5869 compliant: Extract-then-Expand with HMAC-SHA3-256.

    Args:
        ikm: Input key material
        length: Desired output length (1..8160 bytes)
        salt: Optional salt (default: zero-length)
        info: Optional context info (default: zero-length)

    Returns:
        Derived key material of specified length.
    Raises RuntimeError on native C failure.
    """
    if length <= 0 or length > 8160:
        raise ValueError(f"HKDF output length must be 1..8160, got {length}")

    cdef const uint8_t *salt_ptr = NULL
    cdef size_t salt_len = 0
    cdef const uint8_t *info_ptr = NULL
    cdef size_t info_len = 0

    if salt is not None and len(salt) > 0:
        salt_ptr = <const uint8_t*>salt
        salt_len = len(salt)

    if info is not None and len(info) > 0:
        info_ptr = <const uint8_t*>info
        info_len = len(info)

    cdef unsigned char *okm = <unsigned char*>malloc(length)
    if okm == NULL:
        raise MemoryError("Failed to allocate HKDF output buffer")

    cdef int ret
    try:
        ret = ama_hkdf(
            salt_ptr, salt_len,
            <const uint8_t*>ikm, len(ikm),
            info_ptr, info_len,
            okm, length
        )
        if ret != 0:
            raise RuntimeError(f"ama_hkdf failed (rc={ret})")
        return bytes(okm[:length])
    finally:
        ama_secure_memzero(okm, length)
        free(okm)
