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

from libc.stdint cimport uint8_t
from libc.stddef cimport size_t

cdef extern from "ama_cryptography.h":
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
from ama_cryptography._self_test import check_crypto_permitted


def cy_hmac_sha3_256(bytes key, bytes msg):
    """
    HMAC-SHA3-256 via native C ama_hmac_sha3_256().
    Cython binding — zero Python marshaling overhead.
    INVARIANT-1 compliant: calls only ama_cryptography native C.
    RFC 2104 compliant: 136-byte block size (SHA3-256 Keccak rate).

    Returns 32-byte HMAC digest.
    Raises RuntimeError on native C failure (e.g. AMA_ERROR_MEMORY).
    """
    check_crypto_permitted()
    cdef unsigned char out[32]
    cdef int ret

    ret = ama_hmac_sha3_256(
        <const uint8_t*>key, len(key),
        <const uint8_t*>msg, len(msg),
        out
    )
    if ret != 0:
        raise RuntimeError(
            f"ama_hmac_sha3_256 failed (rc={ret})"
        )
    return bytes(out[:32])
