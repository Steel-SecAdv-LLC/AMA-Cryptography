#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Ascon lightweight cryptography (NIST SP 800-232)
================================================

Thin Python surface over the native implementation in ``src/c/ama_ascon.c``.
Every byte of output is produced in C; this module marshals arguments and
refuses malformed input before it reaches the boundary (INVARIANT-5).

Two functions from SP 800-232 (final, 2025-08-13) are exposed:

* :func:`aead128_encrypt` / :func:`aead128_decrypt` — **Ascon-AEAD128**,
  a 128-bit-key, 128-bit-nonce, 128-bit-tag AEAD.
* :func:`hash256` — **Ascon-Hash256**, a 256-bit hash.

Why this is here alongside AES-256-GCM and ChaCha20-Poly1305
------------------------------------------------------------
It is not a replacement for either, and it is not faster than either on a
machine with AES-NI or ARMv8 crypto extensions. Ascon is the *constrained
device* member of this library's algorithm set: a 320-bit state, no lookup
tables of any kind, and a code footprint small enough for targets that cannot
host the other two well. It is also the only lightweight AEAD NIST has
standardized. See ``docs/decisions/0001-adopt-ascon.md`` for the full
rationale, including the measured cost on 64-bit hosts.

Interoperability warning
------------------------
SP 800-232 is **not** byte-compatible with the earlier Ascon v1.2 / CAESAR
submission — different rate, different IV, and a different bit-ordering
convention for the domain-separation constant. A peer running a v1.2-era
Ascon library will not interoperate with this one, and the failure presents as
a tag mismatch rather than as a version error. Confirm which specification a
counterparty implements before deploying.

Nonce discipline
----------------
Ascon-AEAD128 is a nonce-based AEAD with **no** nonce-misuse resistance.
Repeating a ``(key, nonce)`` pair reveals the XOR of the two plaintexts'
**first 16-byte block** — and, with enough reused-nonce pairs, gives an
attacker leverage on the internal state. It is not a total keystream reuse:
because the sponge absorbs plaintext into the rate before permuting, the two
states diverge after the first block, so later blocks do not XOR to the
plaintext XOR the way a stream cipher's would. That is a narrower failure
than ChaCha20-Poly1305 under the same misuse, not a safe one — treat nonce
uniqueness as mandatory either way.

:func:`aead128_encrypt` will not generate a nonce for you silently — pass one
explicitly, or use :func:`generate_nonce`, which draws from ``os.urandom``.

Usage
-----
::

    from ama_cryptography import ascon

    key = ascon.generate_key()
    nonce = ascon.generate_nonce()
    ct, tag = ascon.aead128_encrypt(key, nonce, b"message", aad=b"header")
    pt = ascon.aead128_decrypt(key, nonce, ct, tag, aad=b"header")

    digest = ascon.hash256(b"message")
"""

from __future__ import annotations

import ctypes
import os
from typing import Any, Optional, Tuple, Union

from ama_cryptography.exceptions import AmaCryptographyError

__all__ = [
    "ASCON_AVAILABLE",
    "AEAD128_KEY_BYTES",
    "AEAD128_NONCE_BYTES",
    "AEAD128_TAG_BYTES",
    "HASH256_DIGEST_BYTES",
    "AsconError",
    "AsconVerificationError",
    "aead128_decrypt",
    "aead128_encrypt",
    "generate_key",
    "generate_nonce",
    "hash256",
]

# Mirrors the constants in include/ama_cryptography.h.  Duplicated rather than
# read from the library because they back this module's own input validation,
# which must work even when the native library is absent.
AEAD128_KEY_BYTES = 16
AEAD128_NONCE_BYTES = 16
AEAD128_TAG_BYTES = 16
HASH256_DIGEST_BYTES = 32

_AMA_SUCCESS = 0
_AMA_ERROR_INVALID_PARAM = -1
_AMA_ERROR_VERIFY_FAILED = -4

_BufferInput = Union[bytes, bytearray, memoryview]


class AsconError(AmaCryptographyError):
    """Raised when an Ascon operation fails."""


class AsconVerificationError(AsconError):
    """Raised when Ascon-AEAD128 decryption fails to authenticate.

    Carries no detail about *why* the tag did not verify, deliberately: a
    caller cannot distinguish a corrupted tag from tampered associated data
    from a wrong key, and neither can an attacker.
    """


def _setup_ascon_ctypes(lib: Any) -> bool:
    """Bind the native entry points.  Returns False when they are absent."""
    try:
        lib.ama_ascon_hash256.argtypes = [
            ctypes.c_void_p,  # message
            ctypes.c_size_t,  # message_len
            ctypes.c_void_p,  # digest
        ]
        lib.ama_ascon_hash256.restype = ctypes.c_int

        lib.ama_ascon_aead128_encrypt.argtypes = [
            ctypes.c_void_p,  # key
            ctypes.c_void_p,  # nonce
            ctypes.c_void_p,  # plaintext
            ctypes.c_size_t,  # pt_len
            ctypes.c_void_p,  # aad
            ctypes.c_size_t,  # aad_len
            ctypes.c_void_p,  # ciphertext
            ctypes.c_void_p,  # tag
        ]
        lib.ama_ascon_aead128_encrypt.restype = ctypes.c_int

        lib.ama_ascon_aead128_decrypt.argtypes = [
            ctypes.c_void_p,  # key
            ctypes.c_void_p,  # nonce
            ctypes.c_void_p,  # ciphertext
            ctypes.c_size_t,  # ct_len
            ctypes.c_void_p,  # aad
            ctypes.c_size_t,  # aad_len
            ctypes.c_void_p,  # tag
            ctypes.c_void_p,  # plaintext
        ]
        lib.ama_ascon_aead128_decrypt.restype = ctypes.c_int
        return True
    except AttributeError:
        return False


# The native library is located once, by pqc_backends' loader, so there is a
# single search-path policy in the tree.
_lib: Any = None
try:
    from ama_cryptography import pqc_backends as _pqc

    _lib = _pqc._native_lib
except Exception:  # pragma: no cover - defensive; pqc_backends never raises
    _lib = None

#: True when the native Ascon implementation is present and callable.
ASCON_AVAILABLE: bool = bool(_lib is not None and _setup_ascon_ctypes(_lib))


def _require_native() -> Any:
    if not ASCON_AVAILABLE:
        # Ascon depends on no other primitive in this library and is in the
        # unconditional source list, so it is present in both the default and
        # the AMA_USE_NATIVE_PQC=OFF build.  A missing symbol means the native
        # library was not built at all.
        raise AsconError(
            "ASCON_UNAVAILABLE: native Ascon implementation not built. "
            "Build: cmake -B build && cmake --build build"
        )
    return _lib


def _as_bytes(name: str, value: _BufferInput, expected: Optional[int] = None) -> bytes:
    """Validate and normalise a byte-like argument (INVARIANT-5)."""
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"{name} must be bytes, bytearray or memoryview, " f"not {type(value).__name__}"
        )
    data = bytes(value)
    if expected is not None and len(data) != expected:
        raise ValueError(f"{name} must be exactly {expected} bytes, " f"got {len(data)}")
    return data


def generate_key() -> bytes:
    """Return a fresh 16-byte Ascon-AEAD128 key from ``os.urandom``."""
    return os.urandom(AEAD128_KEY_BYTES)


def generate_nonce() -> bytes:
    """Return a fresh 16-byte nonce from ``os.urandom``.

    A 128-bit random nonce makes collision probability negligible for any
    realistic message count, which is why this is offered rather than a
    counter: a counter is safer in principle but requires durable state that
    a stateless caller cannot provide, and a counter that resets is worse than
    a random nonce that does not.
    """
    return os.urandom(AEAD128_NONCE_BYTES)


def hash256(message: _BufferInput = b"") -> bytes:
    """Return the 32-byte Ascon-Hash256 digest of ``message``.

    :param message: Message to hash; defaults to the empty message.
    :raises AsconError: if the native library is unavailable or refuses.
    """
    lib = _require_native()
    data = _as_bytes("message", message)
    digest = ctypes.create_string_buffer(HASH256_DIGEST_BYTES)

    rc = lib.ama_ascon_hash256(
        ctypes.c_char_p(data) if data else None,
        ctypes.c_size_t(len(data)),
        ctypes.byref(digest),
    )
    if rc != _AMA_SUCCESS:
        raise AsconError(f"ama_ascon_hash256 failed with code {rc}")
    return digest.raw[:HASH256_DIGEST_BYTES]


def aead128_encrypt(
    key: _BufferInput,
    nonce: _BufferInput,
    plaintext: _BufferInput = b"",
    aad: _BufferInput = b"",
) -> Tuple[bytes, bytes]:
    """Encrypt with Ascon-AEAD128.

    :param key:       16-byte key.
    :param nonce:     16-byte nonce.  MUST be unique per key — see the module
                      docstring on nonce discipline.
    :param plaintext: Data to encrypt.
    :param aad:       Associated data, authenticated but not encrypted.
    :returns:         ``(ciphertext, tag)``; ciphertext is the same length as
                      plaintext and the tag is 16 bytes.
    :raises AsconError: if the native library is unavailable or refuses.
    """
    lib = _require_native()
    k = _as_bytes("key", key, AEAD128_KEY_BYTES)
    n = _as_bytes("nonce", nonce, AEAD128_NONCE_BYTES)
    pt = _as_bytes("plaintext", plaintext)
    ad = _as_bytes("aad", aad)

    ct = ctypes.create_string_buffer(len(pt)) if pt else None
    tag = ctypes.create_string_buffer(AEAD128_TAG_BYTES)

    rc = lib.ama_ascon_aead128_encrypt(
        ctypes.c_char_p(k),
        ctypes.c_char_p(n),
        ctypes.c_char_p(pt) if pt else None,
        ctypes.c_size_t(len(pt)),
        ctypes.c_char_p(ad) if ad else None,
        ctypes.c_size_t(len(ad)),
        ctypes.byref(ct) if ct is not None else None,
        ctypes.byref(tag),
    )
    if rc != _AMA_SUCCESS:
        raise AsconError(f"ama_ascon_aead128_encrypt failed with code {rc}")

    ciphertext = ct.raw[: len(pt)] if ct is not None else b""
    return ciphertext, tag.raw[:AEAD128_TAG_BYTES]


def aead128_decrypt(
    key: _BufferInput,
    nonce: _BufferInput,
    ciphertext: _BufferInput,
    tag: _BufferInput,
    aad: _BufferInput = b"",
) -> bytes:
    """Decrypt and authenticate with Ascon-AEAD128.

    Fail-closed: on an authentication failure this raises and returns no
    plaintext.  The native layer produces plaintext into a scratch buffer and
    only releases it once the tag verifies, so unauthenticated bytes are never
    handed back for the caller to "remember" to discard.

    :param key:        16-byte key.
    :param nonce:      16-byte nonce.
    :param ciphertext: Ciphertext to decrypt.
    :param tag:        16-byte authentication tag.
    :param aad:        Associated data supplied at encryption time.
    :returns:          The plaintext.
    :raises AsconVerificationError: if the tag does not verify.
    :raises AsconError: if the native library is unavailable or refuses.
    """
    lib = _require_native()
    k = _as_bytes("key", key, AEAD128_KEY_BYTES)
    n = _as_bytes("nonce", nonce, AEAD128_NONCE_BYTES)
    ct = _as_bytes("ciphertext", ciphertext)
    t = _as_bytes("tag", tag, AEAD128_TAG_BYTES)
    ad = _as_bytes("aad", aad)

    pt = ctypes.create_string_buffer(len(ct)) if ct else None

    rc = lib.ama_ascon_aead128_decrypt(
        ctypes.c_char_p(k),
        ctypes.c_char_p(n),
        ctypes.c_char_p(ct) if ct else None,
        ctypes.c_size_t(len(ct)),
        ctypes.c_char_p(ad) if ad else None,
        ctypes.c_size_t(len(ad)),
        ctypes.c_char_p(t),
        ctypes.byref(pt) if pt is not None else None,
    )
    if rc == _AMA_ERROR_VERIFY_FAILED:
        raise AsconVerificationError("Ascon-AEAD128 authentication failed")
    if rc != _AMA_SUCCESS:
        raise AsconError(f"ama_ascon_aead128_decrypt failed with code {rc}")

    return pt.raw[: len(ct)] if pt is not None else b""
