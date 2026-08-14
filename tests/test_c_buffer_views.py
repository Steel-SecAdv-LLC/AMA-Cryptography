#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Pins for :class:`pqc_backends._CBufferViews` — the batched buffer borrow.

The generator-based ``@contextlib.contextmanager`` form of ``_c_buffer_view``
cost ~1 us per buffer per call in generator machinery alone; four of them on
every one-shot AEAD call halved the Python-level AES-256-GCM throughput
(measured 8.4 us vs 3.4 us per 1 KiB call — the difference between the ~283k
ops/sec the May 2026 ARM floors were calibrated against and the ~132k the
wrappers have delivered since).  The hand-written class handles all of a
call's buffers in one enter/exit with a pass-through fast path for ``bytes``.

What must never regress, pinned here from both directions:

* the SECURITY contract — ``bytearray``/writable-``memoryview`` key material
  is borrowed in place through the buffer protocol, never copied to an
  immutable ``bytes`` outside the secure-wipe path;
* the release contract — every acquired ``memoryview`` is released on exit,
  including when acquisition fails partway through;
* the validation contract — multi-dimensional and non-byte buffers are
  rejected, read-only memoryviews degrade to a copied ``bytes`` (public
  inputs only), and results arrive in input order.
"""

from __future__ import annotations

import ctypes

import pytest

from ama_cryptography.pqc_backends import _c_buffer_view, _CBufferViews


class TestFastPathAndOrdering:
    def test_bytes_pass_through_unchanged(self) -> None:
        a, b = b"first", b"second"
        with _CBufferViews(a, b) as (got_a, got_b):
            assert got_a is a
            assert got_b is b

    def test_results_in_input_order(self) -> None:
        with _CBufferViews(b"x", bytearray(b"y"), memoryview(b"z")) as (x, y, z):
            assert x == b"x"
            assert bytes(y) == b"y"
            assert bytes(z) == b"z"


class TestWritableBorrow:
    def test_bytearray_is_borrowed_not_copied(self) -> None:
        secret = bytearray(b"\xaa" * 32)
        with _CBufferViews(secret) as (borrowed,):
            assert isinstance(borrowed, ctypes.Array)
            # In-place mutation through the borrow must be visible in the
            # original storage: that is what "no transient copy" means.
            borrowed[0] = b"\x55"
        assert secret[0] == 0x55

    def test_writable_memoryview_is_borrowed(self) -> None:
        backing = bytearray(b"\x01" * 16)
        with _CBufferViews(memoryview(backing)) as (borrowed,):
            borrowed[3] = b"\x99"
        assert backing[3] == 0x99

    def test_readonly_memoryview_degrades_to_bytes(self) -> None:
        view = memoryview(b"public input")
        with _CBufferViews(view) as (got,):
            assert isinstance(got, bytes)
            assert got == b"public input"


class TestReleaseContract:
    def test_views_released_on_normal_exit(self) -> None:
        backing = bytearray(b"k" * 32)
        with _CBufferViews(backing):
            pass
        # A released export no longer blocks resizing the bytearray.
        backing.extend(b"grow")
        assert len(backing) == 36

    def test_views_released_when_acquisition_fails_partway(self) -> None:
        backing = bytearray(b"k" * 32)
        two_dimensional = memoryview(bytearray(range(16))).cast("B", (4, 4))
        with pytest.raises(TypeError, match="one-dimensional"):
            with _CBufferViews(backing, two_dimensional):
                raise AssertionError("body must not run")
        # The first view must have been released by the failure path.
        backing.extend(b"grow")
        assert len(backing) == 36

    def test_views_released_when_body_raises(self) -> None:
        backing = bytearray(b"k" * 32)
        with pytest.raises(RuntimeError, match="boom"):
            with _CBufferViews(backing):
                raise RuntimeError("boom")
        backing.extend(b"grow")
        assert len(backing) == 36


class TestValidation:
    def test_multidimensional_buffer_rejected(self) -> None:
        grid = memoryview(bytearray(range(16))).cast("B", (4, 4))
        with pytest.raises(TypeError, match="one-dimensional"):
            with _CBufferViews(grid):
                pass

    def test_wide_itemsize_buffer_rejected(self) -> None:
        import array

        wide = memoryview(array.array("I", [1, 2, 3, 4]))
        with pytest.raises(TypeError, match="one-dimensional byte buffer"):
            with _CBufferViews(wide):
                pass


class TestSingleBufferCompatibilityShim:
    """``_c_buffer_view`` remains for single-buffer callers and docs."""

    def test_single_view_matches_batched(self) -> None:
        secret = bytearray(b"\x42" * 16)
        with _c_buffer_view(secret) as borrowed:
            assert isinstance(borrowed, ctypes.Array)
            assert bytes(bytearray(borrowed)) == bytes(secret)
        # A caller-held borrow pins the exporter beyond the with block —
        # the same semantics the generator form had.  Dropping the last
        # reference releases it.
        del borrowed
        secret.extend(b"ok")
        assert len(secret) == 18


class TestChaChaWipeableKeyContract:
    """ChaCha20-Poly1305 accepts bytearray/memoryview key material.

    Until 4.0.0 the ChaCha wrappers were the one AEAD surface typed ``bytes``
    only, so a caller holding its session key in the zeroizable ``bytearray``
    storage the project recommends had to materialise an immutable copy first
    — the exact transient-copy hazard the borrow machinery exists to remove,
    and an inconsistency with the AES-256-GCM wrappers' contract.
    """

    def test_all_input_forms_agree(self) -> None:
        import secrets

        from ama_cryptography import pqc_backends as pb
        from ama_cryptography.pqc_backends import (
            native_chacha20poly1305_decrypt,
            native_chacha20poly1305_encrypt,
        )

        if not pb._CHACHA20_POLY1305_NATIVE_AVAILABLE:
            pytest.skip("ChaCha20-Poly1305 native backend not built")

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = secrets.token_bytes(256)
        aad = b"header"

        from_bytes = native_chacha20poly1305_encrypt(key, nonce, plaintext, aad)
        from_wipeable = native_chacha20poly1305_encrypt(
            bytearray(key), memoryview(nonce), bytearray(plaintext), aad
        )
        assert from_bytes == from_wipeable

        ciphertext, tag = from_bytes
        assert (
            native_chacha20poly1305_decrypt(bytearray(key), nonce, ciphertext, tag, aad)
            == plaintext
        )
        with pytest.raises(RuntimeError):
            native_chacha20poly1305_decrypt(key, nonce, ciphertext, bytes(16), aad)
