# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False

"""
Copyright 2025-2026 Steel Security Advisors LLC
Licensed under the Apache License, Version 2.0

AMA Cryptography — Native Ed25519 Cython Binding
=================================================

Direct C-to-C calls to ama_ed25519_*() with zero Python marshaling overhead.
INVARIANT-1 compliant: uses only AMA's own native C implementation.
RFC 8032 compliant: Ed25519 (pure EdDSA).
"""

from libc.stdint cimport uint8_t
from libc.stddef cimport size_t
from libc.stdlib cimport malloc, free
from libc.string cimport memcpy

cdef extern from "ama_cryptography.h":
    ctypedef int ama_error_t

    ama_error_t ama_ed25519_keypair(
        uint8_t *public_key, uint8_t *secret_key
    )

    ama_error_t ama_ed25519_sign(
        uint8_t *signature,
        const uint8_t *message, size_t message_len,
        const uint8_t *secret_key
    )

    ama_error_t ama_ed25519_verify(
        const uint8_t *signature,
        const uint8_t *message, size_t message_len,
        const uint8_t *public_key
    )

    ctypedef struct ama_ed25519_batch_entry:
        const uint8_t *message
        size_t message_len
        const uint8_t *signature
        const uint8_t *public_key

    ama_error_t ama_ed25519_batch_verify(
        const ama_ed25519_batch_entry *entries,
        size_t count,
        int *results
    )

    void ama_secure_memzero(void *ptr, size_t len)


def cy_ed25519_keypair(bytes seed):
    """
    Generate Ed25519 keypair from 32-byte seed via native C.
    Returns (public_key, secret_key) as bytes.
    Raises RuntimeError on native C failure.
    """
    if len(seed) != 32:
        raise ValueError(f"Ed25519 seed must be 32 bytes, got {len(seed)}")

    cdef unsigned char pk[32]
    cdef unsigned char sk[64]
    cdef int ret

    memcpy(sk, <const unsigned char*>seed, 32)
    ret = ama_ed25519_keypair(pk, sk)
    if ret != 0:
        raise RuntimeError(f"ama_ed25519_keypair failed (rc={ret})")

    result = (bytes(pk[:32]), bytes(sk[:64]))
    ama_secure_memzero(sk, 64)
    return result


def cy_ed25519_sign(bytes message, bytes secret_key):
    """
    Sign message with Ed25519 via native C.
    Returns 64-byte signature.
    Raises RuntimeError on native C failure.
    """
    if len(secret_key) != 64:
        raise ValueError(f"Ed25519 secret key must be 64 bytes, got {len(secret_key)}")

    cdef unsigned char sig[64]
    cdef unsigned char sk_buf[64]
    cdef int ret

    memcpy(sk_buf, <const unsigned char*>secret_key, 64)
    ret = ama_ed25519_sign(
        sig,
        <const uint8_t*>message, len(message),
        sk_buf
    )
    ama_secure_memzero(sk_buf, 64)
    if ret != 0:
        raise RuntimeError(f"ama_ed25519_sign failed (rc={ret})")
    return bytes(sig[:64])


def cy_ed25519_verify(bytes signature, bytes message, bytes public_key):
    """
    Verify Ed25519 signature via native C.
    Returns True if valid, False otherwise.
    """
    if len(signature) != 64:
        raise ValueError(f"Ed25519 signature must be 64 bytes, got {len(signature)}")
    if len(public_key) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(public_key)}")

    cdef int ret = ama_ed25519_verify(
        <const uint8_t*>signature,
        <const uint8_t*>message, len(message),
        <const uint8_t*>public_key
    )
    return ret == 0
