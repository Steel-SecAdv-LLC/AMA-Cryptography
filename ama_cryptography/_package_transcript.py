#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Canonical authenticated transcript for the crypto package
=========================================================

What this closes
----------------
:func:`ama_cryptography.crypto_api.create_crypto_package` used to sign the
``content`` bytes.  Everything *around* the content — the add-on signatures,
the KEM ciphertext, the timestamp token, the metadata — was therefore outside
the signature, and the 2026-09 audit measured the consequence directly
(finding A-2).  On a package built with ``use_sphincs=True, use_kyber=True,
include_kem=True`` and verified with ``expected_public_key`` pinned:

======================================  ============  ==========
Tamper                                  ``all_valid``  Detected
======================================  ============  ==========
``content`` or ``content_hash`` altered  ``False``     yes
``metadata["signature_algorithm"]``      ``False``     yes (indirect)
all other ``metadata`` rewritten          ``True``      **no**
``timestamp`` replaced                    ``True``      **no**
``sphincs_signature`` stripped            ``True``      **no**
``kem_ciphertext`` stripped               ``True``      **no**
======================================  ============  ==========

*Corrupting* an add-on was caught, because the verifier re-checks it.
*Removing* one was not, because nothing said it had been there.  That is a
downgrade attack on the project's central claim: an attacker who can modify a
stored or transmitted package strips the SLH-DSA and ML-KEM layers, needs no
key material to do it, and the package still verifies as fully valid.

What replaces it
----------------
The primary signature now covers a **transcript**: a canonical, injective,
domain-separated, length-prefixed encoding of every field of the package
except the primary signature itself.  Presence is encoded as much as content,
so ``None`` and *absent* and *present-but-empty* are three different
transcripts and each one is signed.

There is exactly **one** package format.  The ``1`` in :data:`DOMAIN` is a
domain-separation tag, not a format selector: no code reads it to decide how
to parse, and no second format exists to migrate between.

Why a hand-written encoding rather than JSON or pickle
------------------------------------------------------
A transcript has one requirement that ordinary serialization does not: it
must be **injective**.  Two different packages must never produce the same
bytes, or the signature over those bytes means less than it appears to.

* JSON has no canonical form in the standard library — key order, separator
  whitespace, and non-ASCII escaping are all free — and it cannot represent
  ``bytes`` without a lossy sidecar convention.
* ``pickle`` is executable and is not stable across interpreter versions.
* Concatenating fields without length prefixes is not injective at all:
  ``(b"ab", b"c")`` and ``(b"a", b"bc")`` encode identically, which is the
  classic length-extension-adjacent confusion that lets a signer be made to
  attest to a boundary it never saw.

So every value here carries a type tag, every variable-length value carries
an explicit 8-byte length, and dictionaries are emitted in sorted key order.

Fail closed on the unencodable
------------------------------
:func:`canonical` raises :class:`TypeError` for a type it does not know.  A
value the transcript cannot represent is a value the signature cannot bind,
which is the exact hole this module exists to close — so it is refused at
signing time rather than silently omitted and discovered by an auditor.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence, Tuple

__all__ = ["DOMAIN", "canonical", "transcript"]

#: Domain separator.  A signature over a transcript must never be mistakable
#: for a signature over anything else this project signs — see INVARIANT-1's
#: domain-separation requirement and the v3 composite digest in
#: ``_build_sign.py`` for the same reasoning applied to module integrity.
DOMAIN = b"ama_cryptography/crypto-package-transcript/1"

# Type tags.  One byte each, distinct, and never reused for another type: the
# tag is what makes the encoding self-describing, and therefore injective
# across types (b"" and None and False must not collide).
_TAG_NONE = b"\x00"
_TAG_FALSE = b"\x01"
_TAG_TRUE = b"\x02"
_TAG_INT = b"\x03"
_TAG_STR = b"\x04"
_TAG_BYTES = b"\x05"
_TAG_SEQ = b"\x06"
_TAG_MAP = b"\x07"

#: Width of every length and count field.  Eight bytes so the encoder cannot
#: be made to wrap by a caller who controls a large value; a 4-byte length
#: would silently truncate at 4 GiB.
_LEN = 8


def _blob(raw: bytes) -> bytes:
    """``raw`` with its length in front — the unit of injectivity."""
    return len(raw).to_bytes(_LEN, "big") + raw


def canonical(value: Any) -> bytes:
    """Encode ``value`` injectively.

    Supported: ``None``, ``bool``, ``int`` (any magnitude, either sign),
    ``str``, ``bytes``/``bytearray``/``memoryview``, and arbitrarily nested
    sequences and string-keyed mappings of those.

    ``bool`` is checked before ``int`` because it is an ``int`` subclass:
    without the ordering, ``True`` and ``1`` would encode identically and the
    encoding would not be injective on the very first type it meets.

    Raises:
        TypeError: for any other type, or for a mapping with a non-string
            key.  See the module docstring — refusing here is the point.
    """
    if value is None:
        return _TAG_NONE
    if value is True:
        return _TAG_TRUE
    if value is False:
        return _TAG_FALSE
    if isinstance(value, int):
        # Sign byte + minimal magnitude, so +0 has exactly one encoding and a
        # value of any width round-trips.  `int.to_bytes` needs an explicit
        # width, hence the bit_length arithmetic rather than a fixed size.
        magnitude = abs(value)
        width = (magnitude.bit_length() + 7) // 8
        sign = b"\x01" if value < 0 else b"\x00"
        return _TAG_INT + sign + _blob(magnitude.to_bytes(width, "big"))
    if isinstance(value, str):
        return _TAG_STR + _blob(value.encode("utf-8"))
    if isinstance(value, (bytes, bytearray, memoryview)):
        return _TAG_BYTES + _blob(bytes(value))
    if isinstance(value, Mapping):
        items = []
        for key in value:
            if not isinstance(key, str):
                raise TypeError(f"transcript mapping keys must be str, got {type(key).__name__}")
            items.append((key, value[key]))
        items.sort(key=lambda kv: kv[0])
        body = b"".join(canonical(k) + canonical(v) for k, v in items)
        return _TAG_MAP + len(items).to_bytes(_LEN, "big") + body
    if isinstance(value, Sequence):
        body = b"".join(canonical(item) for item in value)
        return _TAG_SEQ + len(value).to_bytes(_LEN, "big") + body
    raise TypeError(
        f"{type(value).__name__} cannot appear in a signed transcript: the "
        "signature could not bind it"
    )


def transcript(fields: Sequence[Tuple[str, Any]]) -> bytes:
    """The bytes a package signature is computed over.

    ``fields`` is an ordered sequence of ``(name, value)`` pairs.  The names
    are encoded too, so a field cannot be renamed, reordered or dropped
    without changing the transcript — the encoding binds the *shape* of the
    package, not only its values.
    """
    body = b"".join(canonical(name) + canonical(value) for name, value in fields)
    return DOMAIN + len(fields).to_bytes(_LEN, "big") + body
