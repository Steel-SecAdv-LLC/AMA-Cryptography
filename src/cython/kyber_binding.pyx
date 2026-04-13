# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False

"""
Copyright 2025-2026 Steel Security Advisors LLC
Licensed under the Apache License, Version 2.0

AMA Cryptography — Native ML-KEM-1024 (Kyber) Cython Binding
=============================================================

Direct C-to-C calls to ama_kyber_*() with zero Python marshaling overhead.
INVARIANT-1 compliant: uses only AMA's own native C implementation.
NIST FIPS 203 compliant: ML-KEM-1024 (CRYSTALS-Kyber).
"""

from libc.stdint cimport uint8_t
from libc.stddef cimport size_t
from libc.stdlib cimport malloc, free
from libc.string cimport memcpy

# Kyber-1024 sizes per FIPS 203
DEF KYBER1024_PK_BYTES = 1568
DEF KYBER1024_SK_BYTES = 3168
DEF KYBER1024_CT_BYTES = 1568
DEF KYBER1024_SS_BYTES = 32

cdef extern from "ama_cryptography.h":
    ctypedef int ama_error_t

    ama_error_t ama_kyber_keypair(
        uint8_t *pk, size_t pk_len,
        uint8_t *sk, size_t sk_len
    )

    ama_error_t ama_kyber_encapsulate(
        const uint8_t *pk, size_t pk_len,
        uint8_t *ct, size_t *ct_len,
        uint8_t *ss, size_t ss_len
    )

    ama_error_t ama_kyber_decapsulate(
        const uint8_t *ct, size_t ct_len,
        const uint8_t *sk, size_t sk_len,
        uint8_t *ss, size_t ss_len
    )

    void ama_secure_memzero(void *ptr, size_t len)


def cy_kyber_keypair():
    """
    Generate ML-KEM-1024 (Kyber) keypair via native C.
    Cython binding — zero Python marshaling overhead.
    INVARIANT-1 compliant: calls only ama_cryptography native C.
    FIPS 203 compliant: ML-KEM-1024.

    Returns:
        (public_key, secret_key) as bytes

    Raises:
        RuntimeError: on native C failure
        MemoryError: on allocation failure
    """
    cdef unsigned char *pk = <unsigned char*>malloc(KYBER1024_PK_BYTES)
    cdef unsigned char *sk = <unsigned char*>malloc(KYBER1024_SK_BYTES)
    if pk == NULL or sk == NULL:
        if pk != NULL:
            free(pk)
        if sk != NULL:
            free(sk)
        raise MemoryError("Failed to allocate Kyber key buffers")

    cdef int ret
    try:
        ret = ama_kyber_keypair(pk, KYBER1024_PK_BYTES, sk, KYBER1024_SK_BYTES)
        if ret != 0:
            raise RuntimeError(f"ama_kyber_keypair failed (rc={ret})")
        return (bytes(pk[:KYBER1024_PK_BYTES]), bytes(sk[:KYBER1024_SK_BYTES]))
    finally:
        ama_secure_memzero(sk, KYBER1024_SK_BYTES)
        free(pk)
        free(sk)


def cy_kyber_encapsulate(bytes public_key):
    """
    ML-KEM-1024 key encapsulation via native C.
    Cython binding — zero Python marshaling overhead.
    INVARIANT-5 compliant: validates inputs at Python/C boundary.

    Args:
        public_key: Kyber public key bytes

    Returns:
        (ciphertext, shared_secret) tuple

    Raises:
        ValueError: on invalid public key length
        RuntimeError: on native C failure
        MemoryError: on allocation failure
    """
    if len(public_key) != KYBER1024_PK_BYTES:
        raise ValueError(
            f"Kyber-1024 public key must be {KYBER1024_PK_BYTES} bytes, "
            f"got {len(public_key)}"
        )

    cdef unsigned char *ct = <unsigned char*>malloc(KYBER1024_CT_BYTES)
    cdef unsigned char ss[32]  # KYBER1024_SS_BYTES
    cdef size_t ct_len = KYBER1024_CT_BYTES

    if ct == NULL:
        raise MemoryError("Failed to allocate Kyber ciphertext buffer")

    cdef int ret
    try:
        ret = ama_kyber_encapsulate(
            <const uint8_t*>public_key, len(public_key),
            ct, &ct_len,
            ss, KYBER1024_SS_BYTES
        )
        if ret != 0:
            raise RuntimeError(f"ama_kyber_encapsulate failed (rc={ret})")
        return (bytes(ct[:ct_len]), bytes(ss[:KYBER1024_SS_BYTES]))
    finally:
        ama_secure_memzero(ss, KYBER1024_SS_BYTES)
        free(ct)


def cy_kyber_decapsulate(bytes ciphertext, bytes secret_key):
    """
    ML-KEM-1024 key decapsulation via native C.
    Cython binding — zero Python marshaling overhead.
    INVARIANT-5 compliant: validates inputs at Python/C boundary.
    INVARIANT-6 compliant: shared secret is wiped after extraction.

    Args:
        ciphertext: Kyber ciphertext bytes
        secret_key: Kyber secret key bytes

    Returns:
        shared_secret bytes (32 bytes)

    Raises:
        ValueError: on invalid input lengths
        RuntimeError: on native C failure
    """
    if len(secret_key) != KYBER1024_SK_BYTES:
        raise ValueError(
            f"Kyber-1024 secret key must be {KYBER1024_SK_BYTES} bytes, "
            f"got {len(secret_key)}"
        )

    cdef unsigned char ss[32]  # KYBER1024_SS_BYTES
    cdef int ret

    ret = ama_kyber_decapsulate(
        <const uint8_t*>ciphertext, len(ciphertext),
        <const uint8_t*>secret_key, len(secret_key),
        ss, KYBER1024_SS_BYTES
    )
    if ret != 0:
        ama_secure_memzero(ss, KYBER1024_SS_BYTES)
        raise RuntimeError(f"ama_kyber_decapsulate failed (rc={ret})")

    result = bytes(ss[:KYBER1024_SS_BYTES])
    ama_secure_memzero(ss, KYBER1024_SS_BYTES)
    return result
