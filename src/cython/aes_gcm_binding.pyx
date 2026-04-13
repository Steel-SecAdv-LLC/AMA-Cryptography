# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False

"""
Copyright 2025-2026 Steel Security Advisors LLC
Licensed under the Apache License, Version 2.0

AMA Cryptography — Native AES-256-GCM Cython Binding
=====================================================

Direct C-to-C calls to ama_aes256_gcm_encrypt/decrypt() with zero Python
marshaling overhead. INVARIANT-1 compliant: uses only AMA's own native C.
NIST SP 800-38D compliant: AES-256-GCM.
"""

from libc.stdint cimport uint8_t
from libc.stddef cimport size_t
from libc.stdlib cimport malloc, free
from libc.string cimport memcpy, memset

cdef extern from "ama_cryptography.h":
    ctypedef int ama_error_t
    int AMA_SUCCESS

    ama_error_t ama_aes256_gcm_encrypt(
        const uint8_t *key,
        const uint8_t *nonce,
        const uint8_t *plaintext, size_t pt_len,
        const uint8_t *aad, size_t aad_len,
        uint8_t *ciphertext,
        uint8_t *tag
    )

    ama_error_t ama_aes256_gcm_decrypt(
        const uint8_t *key,
        const uint8_t *nonce,
        const uint8_t *ciphertext, size_t ct_len,
        const uint8_t *aad, size_t aad_len,
        const uint8_t *tag,
        uint8_t *plaintext
    )

    void ama_secure_memzero(void *ptr, size_t len)


def cy_aes256_gcm_encrypt(bytes key, bytes nonce, bytes plaintext,
                           bytes aad=b""):
    """
    AES-256-GCM encryption via native C ama_aes256_gcm_encrypt().
    Cython binding — zero Python marshaling overhead.
    INVARIANT-1 compliant: calls only ama_cryptography native C.
    INVARIANT-5 compliant: validates inputs at Python/C boundary.

    Args:
        key: 32-byte AES-256 key
        nonce: 12-byte nonce (IV)
        plaintext: data to encrypt
        aad: additional authenticated data (default empty)

    Returns:
        (ciphertext, tag) tuple where tag is 16 bytes

    Raises:
        ValueError: on invalid input lengths
        RuntimeError: on native C failure
        MemoryError: on allocation failure
    """
    if len(key) != 32:
        raise ValueError(f"AES-256-GCM key must be 32 bytes, got {len(key)}")
    if len(nonce) != 12:
        raise ValueError(f"AES-256-GCM nonce must be 12 bytes, got {len(nonce)}")

    cdef size_t pt_len = len(plaintext)
    cdef size_t aad_len = len(aad)
    cdef unsigned char tag[16]
    cdef unsigned char *ct = NULL

    if pt_len > 0:
        ct = <unsigned char*>malloc(pt_len)
        if ct == NULL:
            raise MemoryError("Failed to allocate ciphertext buffer")

    cdef int ret
    try:
        ret = ama_aes256_gcm_encrypt(
            <const uint8_t*>key,
            <const uint8_t*>nonce,
            <const uint8_t*>plaintext if pt_len > 0 else NULL,
            pt_len,
            <const uint8_t*>aad if aad_len > 0 else NULL,
            aad_len,
            ct,
            tag
        )
        if ret != 0:
            raise RuntimeError(f"ama_aes256_gcm_encrypt failed (rc={ret})")

        ct_bytes = bytes(ct[:pt_len]) if pt_len > 0 else b""
        tag_bytes = bytes(tag[:16])
        return (ct_bytes, tag_bytes)
    finally:
        if ct != NULL:
            ama_secure_memzero(ct, pt_len)
            free(ct)


def cy_aes256_gcm_decrypt(bytes key, bytes nonce, bytes ciphertext,
                           bytes tag, bytes aad=b""):
    """
    AES-256-GCM decryption via native C ama_aes256_gcm_decrypt().
    Cython binding — zero Python marshaling overhead.
    INVARIANT-1 compliant: calls only ama_cryptography native C.
    INVARIANT-5 compliant: validates inputs at Python/C boundary.

    Args:
        key: 32-byte AES-256 key
        nonce: 12-byte nonce (IV)
        ciphertext: data to decrypt
        tag: 16-byte authentication tag
        aad: additional authenticated data (default empty)

    Returns:
        plaintext bytes

    Raises:
        ValueError: on invalid input lengths or tag verification failure
        RuntimeError: on native C failure
        MemoryError: on allocation failure
    """
    if len(key) != 32:
        raise ValueError(f"AES-256-GCM key must be 32 bytes, got {len(key)}")
    if len(nonce) != 12:
        raise ValueError(f"AES-256-GCM nonce must be 12 bytes, got {len(nonce)}")
    if len(tag) != 16:
        raise ValueError(f"AES-256-GCM tag must be 16 bytes, got {len(tag)}")

    cdef size_t ct_len = len(ciphertext)
    cdef size_t aad_len = len(aad)
    cdef unsigned char *pt = NULL

    if ct_len > 0:
        pt = <unsigned char*>malloc(ct_len)
        if pt == NULL:
            raise MemoryError("Failed to allocate plaintext buffer")

    cdef int ret
    try:
        ret = ama_aes256_gcm_decrypt(
            <const uint8_t*>key,
            <const uint8_t*>nonce,
            <const uint8_t*>ciphertext if ct_len > 0 else NULL,
            ct_len,
            <const uint8_t*>aad if aad_len > 0 else NULL,
            aad_len,
            <const uint8_t*>tag,
            pt
        )
        if ret != 0:
            if pt != NULL:
                ama_secure_memzero(pt, ct_len)
            raise ValueError(
                "AES-256-GCM tag verification failed — ciphertext may be tampered"
            )

        result = bytes(pt[:ct_len]) if ct_len > 0 else b""
        return result
    finally:
        if pt != NULL:
            ama_secure_memzero(pt, ct_len)
            free(pt)
