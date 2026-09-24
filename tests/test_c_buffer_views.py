#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Pins for :class:`pqc_backends._CBufferViews` — the batched buffer borrow.

The generator-based ``@contextlib.contextmanager`` form this class replaced
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
* the validation contract — multi-dimensional, strided and non-byte buffers
  are rejected (read-only or not), read-only byte memoryviews degrade to a
  copied ``bytes``, and results arrive in input order;
* the wrapper contract — every wrapper that hands a caller's buffer to C
  accepts ``bytes``, ``bytearray`` and ``memoryview`` alike, rather than
  failing with a ctypes ``ArgumentError`` for the wipeable forms.
"""

from __future__ import annotations

import ctypes
from contextlib import ExitStack

import pytest

from ama_cryptography.pqc_backends import _borrow, _CBufferViews


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


@pytest.fixture()
def recorded_views(monkeypatch: pytest.MonkeyPatch) -> list[memoryview]:
    """Every memoryview ``_byte_view`` hands to ``_CBufferViews``, kept alive.

    The release oracle is each view itself, read while this list holds a
    strong reference to it (see :func:`_released`).  A view this list keeps
    alive can only become released through an explicit ``release()``, so the
    oracle reports what ``__exit__`` did and not what the garbage collector
    did.

    The oracle this class used first — resize the backing ``bytearray`` after
    the ``with`` — could not tell the two apart.  Nothing bound the context
    manager, so CPython freed it the moment the block ended, and freeing its
    views and ctypes arrays drops the export whatever ``__exit__`` did.
    Measured 2026-09-24: with ``__exit__`` reduced to ``return None`` all
    three tests passed.
    """
    from ama_cryptography import pqc_backends

    recorded: list[memoryview] = []
    real = pqc_backends._byte_view

    def recording(data: bytes | bytearray | memoryview) -> memoryview:
        view = real(data)
        recorded.append(view)
        return view

    monkeypatch.setattr(pqc_backends, "_byte_view", recording)
    return recorded


def _released(view: memoryview) -> bool:
    """Whether ``view`` has been released.

    ``memoryview`` exposes no ``released`` attribute (the review that found
    this defect proposed reading one; it raises ``AttributeError``).  Every
    operation on a released view raises ``ValueError`` instead, so that is the
    observation.
    """
    try:
        len(view)
    except ValueError:
        return True
    return False


def _resizable(backing: bytearray) -> bool:
    """Whether no export is outstanding on ``backing`` — a resize succeeds."""
    try:
        backing.extend(b"grow")
    except BufferError:
        return False
    del backing[-4:]
    return True


class TestReleaseContract:
    """Every view ``__enter__`` takes is released, and every ctypes borrow is
    dropped, by the time the context manager is done — observed while the
    test still holds the context manager, so refcounting cannot do the work.

    The two properties are separate and both are checked: :func:`_released`
    on each view says ``__exit__`` released what it acquired, and a resizable
    backing ``bytearray`` says the ``from_buffer`` arrays are gone too (each
    holds its own view on the same managed buffer, so releasing the
    ``_byte_view`` view alone leaves the ``bytearray`` locked).
    """

    def test_views_released_on_normal_exit(self, recorded_views: list[memoryview]) -> None:
        backing = bytearray(b"k" * 32)
        other = memoryview(bytearray(b"m" * 8))
        cm = _CBufferViews(backing, b"bytes take no view", other)
        with cm:
            assert len(recorded_views) == 2
            assert not any(_released(view) for view in recorded_views)
            assert not _resizable(backing)
        assert all(_released(view) for view in recorded_views)
        assert _resizable(backing)

    def test_views_released_when_body_raises(self, recorded_views: list[memoryview]) -> None:
        backing = bytearray(b"k" * 32)
        cm = _CBufferViews(backing)

        def _explode() -> None:
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            with cm:
                _explode()
        assert len(recorded_views) == 1
        assert _released(recorded_views[0])
        assert _resizable(backing)

    def test_views_released_when_acquisition_fails_partway(
        self, recorded_views: list[memoryview]
    ) -> None:
        """``__enter__`` itself raises, so it is called directly.

        A ``with`` body would be a statement that can never run (CodeQL
        alerts 617/618), and ``ExitStack.enter_context`` — the form this test
        used before — never registers a context manager whose ``__enter__``
        raised, so it released nothing: the comment that said it did was
        wrong.  The release under test is ``__enter__``'s own
        ``except BaseException`` arm.
        """
        backing = bytearray(b"k" * 32)
        two_dimensional = memoryview(bytearray(range(16))).cast("B", (4, 4))
        cm = _CBufferViews(backing, two_dimensional)
        with pytest.raises(TypeError, match="one-dimensional"):
            cm.__enter__()
        # _byte_view refuses the second input itself and releases the view it
        # took, so exactly one view was handed over: the first one.
        assert len(recorded_views) == 1
        assert _released(recorded_views[0])
        assert _resizable(backing)


class TestValidation:
    def test_multidimensional_buffer_rejected(self) -> None:
        grid = memoryview(bytearray(range(16))).cast("B", (4, 4))
        with pytest.raises(TypeError, match="one-dimensional"), ExitStack() as stack:
            stack.enter_context(_CBufferViews(grid))

    def test_wide_itemsize_buffer_rejected(self) -> None:
        import array

        wide = memoryview(array.array("I", [1, 2, 3, 4]))
        with pytest.raises(TypeError, match="contiguous byte buffer"), ExitStack() as stack:
            stack.enter_context(_CBufferViews(wide))

    def test_readonly_wide_itemsize_buffer_rejected_not_copied(self) -> None:
        """The read-only branch used to copy BEFORE the item-size check ran.

        ``len()`` counts items, so a 32-item ``array('I')`` behind a read-only
        view passed a 32-byte key-length check and was then copied as 128
        bytes.  Both borrow helpers refuse it now.
        """
        import array

        wide = memoryview(array.array("I", range(32))).toreadonly()
        assert len(wide) == 32 and wide.nbytes == 128
        with pytest.raises(TypeError, match="contiguous byte buffer"), ExitStack() as stack:
            stack.enter_context(_CBufferViews(wide))
        with pytest.raises(TypeError, match="contiguous byte buffer"):
            _borrow(wide)

    def test_strided_buffer_rejected(self) -> None:
        strided = memoryview(bytearray(range(32)))[::2]
        with pytest.raises(TypeError, match="contiguous byte buffer"):
            _borrow(strided)


class TestChaChaWipeableKeyContract:
    """ChaCha20-Poly1305 accepts bytearray/memoryview key material.

    Until 5.0.0 the ChaCha wrappers were the one AEAD surface typed ``bytes``
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


class TestWrappersAcceptEveryBytesLikeInput:
    """Wrappers that used to pass a caller's buffer to ctypes unconverted.

    ``c_char_p`` accepts ``bytes`` only, so a ``bytearray`` secret — the form
    INVARIANT-6 asks callers to hold — raised ``ctypes.ArgumentError``; in
    FROST round 2 it did so after the nonce view was taken, consuming the pair.
    """

    FORMS = (bytes, bytearray, memoryview)

    @pytest.mark.parametrize("form", FORMS)
    def test_sha2_and_pbkdf2(self, form: type) -> None:
        import hashlib

        from ama_cryptography import pqc_backends as pb

        data = b"abc" * 50
        assert pb.native_sha512(form(data)) == hashlib.sha512(data).digest()
        assert pb.native_sha384(form(data)) == hashlib.sha384(data).digest()
        assert pb.native_pbkdf2_hmac_sha256(form(b"pw"), form(b"salt"), 2, 32) == (
            hashlib.pbkdf2_hmac("sha256", b"pw", b"salt", 2, 32)
        )

    @pytest.mark.parametrize("form", FORMS)
    def test_ml_dsa_hedged_sign(self, form: type) -> None:
        from ama_cryptography import pqc_backends as pb

        pk, sk = pb.native_ml_dsa_keypair(65)
        sig = pb.native_ml_dsa_sign_hedged(65, form(b"msg"), form(bytes(sk)), ctx=b"c")
        assert pb.native_ml_dsa_verify(65, b"msg", sig, pk, ctx=b"c")

    def test_ml_dsa_hedged_sign_refuses_a_malformed_key_as_value_error(self) -> None:
        """Same refusal type as the deterministic signer for an out-of-range s1."""
        from ama_cryptography import pqc_backends as pb

        _pk, sk = pb.native_ml_dsa_keypair(65)
        bad = bytearray(sk)
        bad[128:160] = b"\xff" * 32  # inside s1: coefficients far outside [-eta, eta]
        with pytest.raises(ValueError, match="Algorithm 25"):
            pb.native_ml_dsa_sign_hedged(65, b"m", bad)

    @pytest.mark.parametrize("form", FORMS)
    def test_frost_rounds(self, form: type) -> None:
        from ama_cryptography import pqc_backends as pb

        gpk, shares = pb.frost_keygen_trusted_dealer(threshold=2, num_participants=2)
        nonces, commits = zip(*(pb.frost_round1_commit(form(bytes(sh))) for sh in shares))
        all_commits = b"".join(commits)
        sig_shares = [
            pb.frost_round2_sign(
                message=form(b"m"),
                participant_share=form(bytes(shares[i])),
                participant_index=i + 1,
                nonce_pair=nonces[i],
                commitments=form(all_commits),
                signer_indices=form(b"\x01\x02"),
                num_signers=2,
                group_public_key=form(bytes(gpk)),
            )
            for i in range(2)
        ]
        signature = pb.frost_aggregate(
            sig_shares=b"".join(sig_shares),
            commitments=all_commits,
            signer_public_shares=b"".join(bytes(sh[32:64]) for sh in shares),
            signer_indices=b"\x01\x02",
            num_signers=2,
            message=b"m",
            group_public_key=bytes(gpk),
        )
        assert pb.native_ed25519_verify(signature, b"m", bytes(gpk))
