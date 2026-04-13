# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False

"""
Copyright 2025-2026 Steel Security Advisors LLC
Licensed under the Apache License, Version 2.0

AMA Cryptography — Native ChaCha20-Poly1305 Cython Binding
===========================================================

Direct C-to-C calls to ama_chacha20poly1305_encrypt/decrypt() with zero
Python marshaling overhead. INVARIANT-1 compliant: uses only AMA's own
native C implementation. RFC 8439 compliant.
"""

from libc.stdint cimport uint8_t
from libc.stddef cimport size_t
from libc.stdlib cimport malloc, free
from libc.string cimport memcpy

cdef extern from "ama_cryptography.h":
    ctypedef int ama_error_t

    ama_error_t ama_chacha20poly1305_encrypt(
        const uint8_t *key,
        const uint8_t *nonce,
        const uint8_t *plaintext, size_t pt_len,
        const uint8_t *aad, size_t aad_len,
        uint8_t *ciphertext,
        uint8_t *tag
    )

    ama_error_t ama_chacha20poly1305_decrypt(
        const uint8_t *key,
        const uint8_t *nonce,
        const uint8_t *ciphertext, size_t ct_len,
        const uint8_t *aad, size_t aad_len,
        const uint8_t *tag,
        uint8_t *plaintext
    )

    void ama_secure_memzero(void *ptr, size_t len)


def cy_chacha20poly1305_encrypt(bytes key, bytes nonce, bytes plaintext,
                                 bytes aad=b""):
    """
    ChaCha20-Poly1305 AEAD encryption via native C.
    Cython binding — zero Python marshaling overhead.
    INVARIANT-1 compliant: calls only ama_cryptography native C.
    INVARIANT-5 compliant: validates inputs at Python/C boundary.
    RFC 8439 compliant.

    Args:
        key: 32-byte key
        nonce: 12-byte nonce
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
        raise ValueError(
            f"ChaCha20-Poly1305 key must be 32 bytes, got {len(key)}")
    if len(nonce) != 12:
        raise ValueError(
            f"ChaCha20-Poly1305 nonce must be 12 bytes, got {len(nonce)}")

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
        ret = ama_chacha20poly1305_encrypt(
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
            raise RuntimeError(
                f"ama_chacha20poly1305_encrypt failed (rc={ret})")

        ct_bytes = bytes(ct[:pt_len]) if pt_len > 0 else b""
        tag_bytes = bytes(tag[:16])
        return (ct_bytes, tag_bytes)
    finally:
        if ct != NULL:
            ama_secure_memzero(ct, pt_len)
            free(ct)


def cy_chacha20poly1305_decrypt(bytes key, bytes nonce, bytes ciphertext,
                                 bytes tag, bytes aad=b""):
    """
    ChaCha20-Poly1305 AEAD decryption via native C.
    Cython binding — zero Python marshaling overhead.
    INVARIANT-1 compliant: calls only ama_cryptography native C.
    INVARIANT-5 compliant: validates inputs at Python/C boundary.
    RFC 8439 compliant.

    Args:
        key: 32-byte key
        nonce: 12-byte nonce
        ciphertext: data to decrypt
        tag: 16-byte authentication tag
        aad: additional authenticated data (default empty)

    Returns:
        plaintext bytes

    Raises:
        ValueError: on invalid input lengths or tag verification failure
        RuntimeError: on native C failure
    """
    if len(key) != 32:
        raise ValueError(
            f"ChaCha20-Poly1305 key must be 32 bytes, got {len(key)}")
    if len(nonce) != 12:
        raise ValueError(
            f"ChaCha20-Poly1305 nonce must be 12 bytes, got {len(nonce)}")
    if len(tag) != 16:
        raise ValueError(
            f"ChaCha20-Poly1305 tag must be 16 bytes, got {len(tag)}")

    cdef size_t ct_len = len(ciphertext)
    cdef size_t aad_len = len(aad)
    cdef unsigned char *pt = NULL

    if ct_len > 0:
        pt = <unsigned char*>malloc(ct_len)
        if pt == NULL:
            raise MemoryError("Failed to allocate plaintext buffer")

    cdef int ret
    try:
        ret = ama_chacha20poly1305_decrypt(
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
                "ChaCha20-Poly1305 tag verification failed — "
                "ciphertext may be tampered"
            )

        result = bytes(pt[:ct_len]) if ct_len > 0 else b""
        return result
    finally:
        if pt != NULL:
            ama_secure_memzero(pt, ct_len)
            free(pt)
