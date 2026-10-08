# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False

"""
AMA Cryptography — Native HMAC-SHA3-256 Cython Binding
======================================================

Direct C-to-C call to ama_hmac_sha3_256() with zero Python marshaling overhead.
INVARIANT-1 compliant: uses only AMA's own native C implementation.
RFC 2104 compliant: 136-byte block size (SHA3-256 Keccak rate).
"""

from cpython.bytearray cimport PyByteArray_AS_STRING, PyByteArray_Check
from cpython.bytes cimport PyBytes_AS_STRING, PyBytes_Check
from libc.stdint cimport uint8_t
from libc.stddef cimport size_t

cdef extern from "ama_cryptography.h":
    void ama_secure_memzero(void* ptr, size_t len)
    int ama_hmac_sha3_256(
        const uint8_t *key, size_t key_len,
        const uint8_t *msg, size_t msg_len,
        uint8_t *out
    )


# FIPS 140-3 §4.9.2 output inhibition — see ed25519_binding.pyx for the
# full rationale.  This module is a public submodule whose cy_* function
# calls the C kernel directly, bypassing pqc_backends' gated wrappers (and,
# imported as a top-level module, POST itself); the guard refuses output in
# the FIPS error state and the import forces POST to run.
from ama_cryptography._module_state import check_crypto_permitted


cdef inline bint _is_octets(object value):
    return PyBytes_Check(value) or PyByteArray_Check(value)


cdef inline const uint8_t *_octets_ptr(object value):
    """Storage of a ``bytes`` or ``bytearray``; never NULL (an empty one
    still has a valid, NUL-terminated buffer)."""
    if PyBytes_Check(value):
        return <const uint8_t *>PyBytes_AS_STRING(value)
    return <const uint8_t *>PyByteArray_AS_STRING(value)


cdef bytes _mac(const uint8_t *key_p, size_t key_len, const uint8_t *msg_p, size_t msg_len):
    cdef unsigned char out[32]
    cdef int ret
    try:
        ret = ama_hmac_sha3_256(key_p, key_len, msg_p, msg_len, out)
        if ret != 0:
            raise RuntimeError(
                f"ama_hmac_sha3_256 failed (rc={ret})"
            )
        return bytes(out[:32])
    finally:
        ama_secure_memzero(out, 32)


cdef bytes _mac_views(const unsigned char[::1] key, const unsigned char[::1] msg):
    # &view[0] is undefined for a zero-length view; an empty key or message
    # is legal HMAC input, so it gets a valid pointer to nothing.
    cdef const uint8_t* empty = <const uint8_t*>b""
    cdef const uint8_t* key_p = &key[0] if key.shape[0] > 0 else empty
    cdef const uint8_t* msg_p = &msg[0] if msg.shape[0] > 0 else empty
    return _mac(key_p, <size_t>key.shape[0], msg_p, <size_t>msg.shape[0])


def cy_hmac_sha3_256(object key, object msg):
    """
    HMAC-SHA3-256 via native C ama_hmac_sha3_256().
    Cython binding — zero Python marshaling overhead.
    INVARIANT-1 compliant: calls only ama_cryptography native C.
    RFC 2104 compliant: 136-byte block size (SHA3-256 Keccak rate).

    ``key`` and ``msg`` may be ``bytes``, ``bytearray`` or any contiguous
    byte buffer; all are read in place, so a wipeable key is never copied
    into an immutable one on the way in.  ``bytes`` and ``bytearray`` are
    read straight from their storage under the GIL: a typed-memoryview
    acquisition per argument cost 0.35 us of a 4.1 us call (measured
    2026-10-08 against 774d050), so views are kept for other buffers only.

    Returns 32-byte HMAC digest.
    Raises RuntimeError on native C failure (e.g. AMA_ERROR_MEMORY).
    """
    check_crypto_permitted()
    if _is_octets(key) and _is_octets(msg):
        return _mac(_octets_ptr(key), <size_t>len(key), _octets_ptr(msg), <size_t>len(msg))
    return _mac_views(key, msg)
