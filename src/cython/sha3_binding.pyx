# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False

"""
Copyright 2025-2026 Steel Security Advisors LLC
Licensed under the Apache License, Version 2.0

AMA Cryptography — Native SHA3-256 Cython Binding
==================================================

Direct C-to-C call to ama_sha3_256() with zero Python marshaling overhead.
INVARIANT-1 compliant: uses only AMA's own native C implementation.
FIPS 202 compliant: SHA3-256 via Keccak-f[1600].
"""

from libc.stdint cimport uint8_t
from libc.stddef cimport size_t

cdef extern from "ama_cryptography.h":
    int ama_sha3_256(
        const uint8_t *input, size_t input_len,
        uint8_t *output
    )


def cy_sha3_256(bytes data):
    """
    SHA3-256 via native C ama_sha3_256().
    Cython binding — zero Python marshaling overhead.
    INVARIANT-1 compliant: calls only ama_cryptography native C.
    FIPS 202 compliant: SHA3-256 (Keccak-f[1600], rate=136).

    Returns 32-byte digest.
    Raises RuntimeError on native C failure.
    """
    cdef unsigned char out[32]
    cdef int ret

    ret = ama_sha3_256(
        <const uint8_t*>data, len(data),
        out
    )
    if ret != 0:
        raise RuntimeError(
            f"ama_sha3_256 failed (rc={ret})"
        )
    return bytes(out[:32])
