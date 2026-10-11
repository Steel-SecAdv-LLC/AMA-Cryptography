# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False

"""
AMA Cryptography — Native HKDF-SHA3-256 Cython Binding
======================================================

Direct C-to-C call to ama_hkdf() with zero Python marshaling overhead.
INVARIANT-1 compliant: uses only AMA's own native C implementation.
RFC 5869 compliant: HKDF Extract-then-Expand with HMAC-SHA3-256.
"""

from cpython.bytearray cimport PyByteArray_AS_STRING, PyByteArray_Check, PyByteArray_FromStringAndSize
from cpython.bytes cimport PyBytes_AS_STRING, PyBytes_Check, PyBytes_GET_SIZE
from libc.stdint cimport uint8_t
from libc.stddef cimport size_t

cdef extern from "ama_cryptography.h":
    ctypedef int ama_error_t

    ama_error_t ama_hkdf(
        const uint8_t *salt, size_t salt_len,
        const uint8_t *ikm, size_t ikm_len,
        const uint8_t *info, size_t info_len,
        uint8_t *okm, size_t okm_len
    )

    void ama_secure_memzero(void *ptr, size_t len)


# FIPS 140-3 §4.9.2 output inhibition — see ed25519_binding.pyx for the
# full rationale.  This module is a public submodule whose cy_* function
# calls the C kernel directly, bypassing pqc_backends' gated wrappers (and,
# imported as a top-level module, POST itself); the guard refuses output in
# the FIPS error state and the import forces POST to run.
from ama_cryptography._module_state import check_crypto_permitted


cdef const uint8_t *_octets(object value, size_t *length, str name) except? NULL:
    """Address and length of a ``bytes`` or ``bytearray`` argument's storage.

    Read in place under the GIL, which the whole call holds, so a bytearray
    cannot be resized under the kernel.  The storage is reached directly
    rather than through a typed memoryview: acquiring one buffer view per
    argument cost 0.8 us of a 7 us call (measured 2026-10-08 against
    774d050, 13%), for nothing a direct read does not already give.
    Returns NULL only with ``*length == 0``; an empty value has no octet to
    point at, and the C kernel accepts NULL with a zero length.
    """
    cdef Py_ssize_t n
    if PyBytes_Check(value):
        n = PyBytes_GET_SIZE(value)
        length[0] = <size_t>n
        return <const uint8_t *>PyBytes_AS_STRING(value) if n > 0 else NULL
    if PyByteArray_Check(value):
        n = len(value)
        length[0] = <size_t>n
        return <const uint8_t *>PyByteArray_AS_STRING(value) if n > 0 else NULL
    raise TypeError(f"{name} must be bytes or bytearray, not {type(value).__name__}")


def cy_hkdf(object ikm, int length, object salt=None, object info=None):
    """
    HKDF-SHA3-256 key derivation via native C ama_hkdf().
    Cython binding — zero Python marshaling overhead.
    INVARIANT-1 compliant: calls only ama_cryptography native C.
    RFC 5869 compliant: Extract-then-Expand with HMAC-SHA3-256.

    Args:
        ikm: Input key material (``bytes`` or ``bytearray``, read in place)
        length: Desired output length (1..8160 bytes)
        salt: Optional salt (default: zero-length)
        info: Optional context info (default: zero-length)

    Returns:
        Derived key material of specified length, in a ``bytearray`` the C
        kernel writes directly: the caller holds the only copy and can wipe it
        (INVARIANT-6).
    Raises RuntimeError on native C failure.
    """
    check_crypto_permitted()
    if length <= 0 or length > 8160:
        raise ValueError(f"HKDF output length must be 1..8160, got {length}")

    cdef size_t ikm_len = 0
    cdef size_t salt_len = 0
    cdef size_t info_len = 0
    cdef const uint8_t *ikm_ptr = _octets(ikm, &ikm_len, "ikm")
    cdef const uint8_t *salt_ptr = NULL
    cdef const uint8_t *info_ptr = NULL
    cdef int ret
    if salt is not None:
        salt_ptr = _octets(salt, &salt_len, "salt")
    if info is not None:
        info_ptr = _octets(info, &info_len, "info")

    # Uninitialised storage: the kernel writes every octet, and a failure
    # zeroes it before raising, so no prior heap content can escape.
    okm = PyByteArray_FromStringAndSize(NULL, length)
    cdef uint8_t *okm_ptr = <uint8_t *>PyByteArray_AS_STRING(okm)
    ret = ama_hkdf(
        salt_ptr, salt_len,
        ikm_ptr, ikm_len,
        info_ptr, info_len,
        okm_ptr, <size_t>length
    )
    if ret != 0:
        ama_secure_memzero(okm_ptr, <size_t>length)
        raise RuntimeError(f"ama_hkdf failed (rc={ret})")
    return okm
