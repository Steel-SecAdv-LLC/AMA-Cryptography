# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False

"""
Copyright 2025-2026 Steel Security Advisors LLC
Licensed under the Apache License, Version 2.0

AMA Cryptography — Native X25519 Cython Binding
================================================

Direct C-to-C calls to ama_x25519_*() with zero Python marshaling overhead.
INVARIANT-1 compliant: uses only AMA's own native C implementation.
RFC 7748 compliant: X25519 Diffie-Hellman key exchange.
"""

from libc.stdint cimport uint8_t
from libc.stddef cimport size_t
from libc.string cimport memcpy

cdef extern from "ama_cryptography.h":
    ctypedef int ama_error_t

    ama_error_t ama_x25519_keypair(
        uint8_t *public_key,
        uint8_t *secret_key
    )

    ama_error_t ama_x25519_key_exchange(
        uint8_t *shared_secret,
        const uint8_t *our_secret_key,
        const uint8_t *their_public_key
    )

    void ama_secure_memzero(void *ptr, size_t len)


def cy_x25519_keypair():
    """
    Generate X25519 keypair via native C ama_x25519_keypair().
    Cython binding — zero Python marshaling overhead.
    INVARIANT-1 compliant: calls only ama_cryptography native C.
    RFC 7748 compliant: X25519 (Curve25519 Diffie-Hellman).

    Returns:
        (public_key, secret_key) as bytes (32 bytes each)

    Raises:
        RuntimeError: on native C failure
    """
    cdef unsigned char pk[32]
    cdef unsigned char sk[32]
    cdef int ret

    ret = ama_x25519_keypair(pk, sk)
    if ret != 0:
        ama_secure_memzero(sk, 32)
        raise RuntimeError(f"ama_x25519_keypair failed (rc={ret})")

    result = (bytes(pk[:32]), bytes(sk[:32]))
    ama_secure_memzero(sk, 32)
    return result


def cy_x25519_key_exchange(bytes our_secret_key, bytes their_public_key):
    """
    X25519 Diffie-Hellman key exchange via native C.
    Cython binding — zero Python marshaling overhead.
    INVARIANT-5 compliant: validates inputs at Python/C boundary.
    INVARIANT-6 compliant: shared secret is wiped from stack after extraction.

    Args:
        our_secret_key: our 32-byte secret key
        their_public_key: their 32-byte public key

    Returns:
        shared_secret bytes (32 bytes)

    Raises:
        ValueError: on invalid input lengths or low-order point rejection
        RuntimeError: on native C failure
    """
    if len(our_secret_key) != 32:
        raise ValueError(
            f"X25519 secret key must be 32 bytes, got {len(our_secret_key)}")
    if len(their_public_key) != 32:
        raise ValueError(
            f"X25519 public key must be 32 bytes, got {len(their_public_key)}")

    cdef unsigned char ss[32]
    cdef unsigned char sk_buf[32]
    cdef int ret

    memcpy(sk_buf, <const unsigned char*>our_secret_key, 32)
    ret = ama_x25519_key_exchange(
        ss,
        sk_buf,
        <const uint8_t*>their_public_key
    )
    ama_secure_memzero(sk_buf, 32)

    if ret != 0:
        ama_secure_memzero(ss, 32)
        raise ValueError(
            "X25519 key exchange failed — possible low-order point rejection")

    result = bytes(ss[:32])
    ama_secure_memzero(ss, 32)
    return result
