# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Non-canonical Ed25519 public-key ``y`` rejection (INVARIANT-38).

RFC 8032 §5.1.3 requires a compressed point whose ``y`` is not in ``[0, p)``
with ``p = 2^255 - 19`` to be **rejected**, not reduced. INVARIANT-27 already
recorded that rule — it is why X25519's canonicalisation sits on the 32-byte
encoding rather than inside the ``fe51_frombytes`` / ``fe64_frombytes``
helpers those two curves share — but neither backend enforced it: both reduced
mod ``p``, so each of the nineteen values in ``[p, 2^255)`` decoded to the same
curve point as its reduced counterpart and a public key had two accepted byte
encodings.

Why this module was rewritten
-----------------------------
Its first version drove every assertion through ``native_ed25519_verify``,
passing a non-canonical ``y`` as the public key alongside a signature made by
a *different* keypair. Those assertions were **vacuous**: verify returns False
for the wrong-key reason whether or not the canonical-``y`` rule exists, so
all thirty-eight of them passed with the check fully removed. Demonstrably so
— the canonical values ``y = 0`` and ``y = 12345`` return False through that
same call for exactly the same reason.

This is the second time this defect class has been found in the coverage for
this one invariant: ``tests/c/test_ed25519_canonical_s.c`` had it (``y = p``
is not the signer's key, so verify rejects it either way) and
``tools/check_ed25519_backend_parity.py`` had it (its corpus contained no
non-canonical ``y`` at all). The lesson is the same each time and it is worth
stating plainly: **a rejection is only evidence when something that differs
from it in exactly one respect is accepted.** A test whose expected result is
"False" needs a paired case whose expected result is "True" and which differs
only in the property under test.

What replaced it
----------------
The pair the C test settled on, driven here through the Python binding:

* ``y = 0`` is a genuine curve point — the curve equation gives ``x² = -1``,
  and ``-1`` is a square mod ``p`` — so it must decode.
* ``y = p`` reduces to ``0``. It denotes *the same point*, non-canonically
  encoded, so it must be refused.

Nothing but the canonicality rule can separate those two, which is what makes
the assertion non-vacuous. They are put to the two decode entry points
(``ama_ed25519_point_add`` and ``ama_ed25519_scalarmult_public``) rather than
to verify, because verify cannot distinguish a decode refusal from a signature
mismatch — that indistinguishability is what made the first version vacuous.

The remaining eighteen band values have no in-range twin (a key whose ``y``
has one needs ``y < 19``, probability ~``19 / 2^255``), so they are asserted
as refusals *alongside* the ``y = 0`` control that proves refusal is not the
uniform answer.

``tests/c/test_ed25519_canonical_s.c`` isolates the predicate itself, and the
backend-differential job proves donna and fe51 agree on every case.
"""

from __future__ import annotations

import ctypes
from typing import Callable

import pytest

from ama_cryptography.pqc_backends import (
    _native_lib,
    native_ed25519_keypair,
    native_ed25519_sign,
    native_ed25519_verify,
)

P = 2**255 - 19
MESSAGE = b"INVARIANT-38 canonical y"

#: Compressed encoding of the identity, y = 1. Used as the second operand of
#: point_add so the call exercises the decode of the operand under test.
_IDENTITY = (1).to_bytes(32, "little")

#: Scalar 2, for scalarmult_public. Any non-zero scalar works; the decode of
#: the point argument is what is under test.
_TWO = (2).to_bytes(32, "little")

#: Compressed encoding of 2·B, computed from the curve definition rather than
#: read back from the library, so the output-contract assertion below is not
#: circular. Derived by evaluating the twisted-Edwards addition formula on
#: RFC 8032 §5.1's base point (y = 4/5 mod p, x even) with
#: d = -121665/121666 mod p.
_TWO_G = bytes.fromhex("c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022")


def _encode(y: int, sign_bit: int = 0) -> bytes:
    """Compressed Edwards encoding: 255-bit little-endian y, x-sign in bit 255."""
    assert 0 <= y < 2**255
    return (y | (sign_bit << 255)).to_bytes(32, "little")


@pytest.fixture(scope="module")
def decode() -> dict[str, Callable[[bytes], bool]]:
    """Two decode entry points, bound through ctypes and returning bool.

    ``ama_ed25519_point_add`` and ``ama_ed25519_scalarmult_public`` are C-ABI
    only — ``pqc_backends`` exposes no Python wrapper — and they are the same
    pair ``tools/check_ed25519_backend_parity.py`` uses for its decode stage,
    for the same reason: they succeed or fail on the decode alone.
    """
    if _native_lib is None:  # pragma: no cover - INVARIANT-7 makes this unreachable
        pytest.skip("native library unavailable")

    _native_lib.ama_ed25519_point_add.restype = ctypes.c_int
    _native_lib.ama_ed25519_point_add.argtypes = [ctypes.c_char_p] * 3
    _native_lib.ama_ed25519_scalarmult_public.restype = ctypes.c_int
    _native_lib.ama_ed25519_scalarmult_public.argtypes = [ctypes.c_char_p] * 3

    def point_add(encoding: bytes) -> bool:
        out = ctypes.create_string_buffer(32)
        return bool(_native_lib.ama_ed25519_point_add(out, encoding, _IDENTITY) == 0)

    def scalarmult(encoding: bytes) -> bool:
        out = ctypes.create_string_buffer(32)
        return bool(_native_lib.ama_ed25519_scalarmult_public(out, _TWO, encoding) == 0)

    return {"point_add": point_add, "scalarmult_public": scalarmult}


OPS = ("point_add", "scalarmult_public")


class TestTheDiscriminatingPair:
    """``y = 0`` and ``y = p`` are one point under two encodings.

    This is the whole test. Everything else in the module is a boundary sweep
    around it.
    """

    @pytest.mark.parametrize("op", OPS)
    def test_canonical_zero_decodes(
        self, decode: dict[str, Callable[[bytes], bool]], op: str
    ) -> None:
        """``y = 0`` is on the curve (``x² = -1``, and ``-1`` is a QR mod p)."""
        assert decode[op](_encode(0)) is True

    @pytest.mark.parametrize("op", OPS)
    def test_its_non_canonical_twin_is_refused(
        self, decode: dict[str, Callable[[bytes], bool]], op: str
    ) -> None:
        """``y = p`` reduces to 0 — the same point, spelled non-canonically.

        Paired with the test above, this is the assertion that fails when the
        canonical-``y`` check is stripped, and the reason it cannot pass
        vacuously: a backend that reduced would decode both.
        """
        assert decode[op](_encode(P)) is False


class TestNonCanonicalYIsRejected:
    """The nineteen encodings in ``[p, 2^255)`` must not decode."""

    @pytest.mark.parametrize("op", OPS)
    @pytest.mark.parametrize("offset", range(19))
    def test_every_value_in_the_band_is_rejected(
        self, decode: dict[str, Callable[[bytes], bool]], op: str, offset: int
    ) -> None:
        assert decode[op](_encode(P + offset)) is False

    @pytest.mark.parametrize("op", OPS)
    @pytest.mark.parametrize("offset", range(19))
    def test_the_sign_bit_does_not_rescue_a_non_canonical_y(
        self, decode: dict[str, Callable[[bytes], bool]], op: str, offset: int
    ) -> None:
        """Bit 255 carries the sign of x, not part of y.

        Masking it off is the first thing the predicate does, so setting it
        must not change the verdict — a rejection that depended on the sign
        bit would be rejecting for the wrong reason.
        """
        assert decode[op](_encode(P + offset, 1)) is False

    @pytest.mark.parametrize("op", OPS)
    def test_the_sign_bit_does_not_break_a_canonical_y(
        self, decode: dict[str, Callable[[bytes], bool]], op: str
    ) -> None:
        """The other direction: bit 255 set on a canonical ``y`` still decodes.

        Without this, a predicate that rejected every encoding with the sign
        bit set would pass the test above for the wrong reason.
        """
        assert decode[op](_encode(0, 1)) is True

    def test_the_band_is_exactly_nineteen_values(self) -> None:
        """``2^255 - p == 19``: the guard covers the band and nothing beyond it."""
        assert 2**255 - P == 19


class TestCanonicalYStillDecodes:
    """The change must be strictly narrowing — no conformant encoding is lost."""

    @pytest.mark.parametrize("op", OPS)
    def test_p_minus_one_decodes_and_p_does_not(
        self, decode: dict[str, Callable[[bytes], bool]], op: str
    ) -> None:
        """The exact off-by-one boundary, and it is a genuine accept/reject pair.

        ``p - 1`` is the largest canonical ``y``, and it happens to be on the
        curve, so it decodes. ``p`` is one greater and is refused. Adjacent
        integers, opposite verdicts, and the only thing between them is the
        canonicality bound — so a predicate written with ``<=`` instead of
        ``<`` fails here and nowhere else.

        (This assertion was written the other way round first, on the
        assumption that ``p - 1`` would be off-curve like most values. The
        test falsified the assumption, which is the argument for asserting
        measured behaviour rather than expected behaviour at a boundary.)
        """
        assert decode[op](_encode(P - 1)) is True
        assert decode[op](_encode(P)) is False

    @pytest.mark.parametrize("op", OPS)
    def test_real_public_keys_decode(
        self, decode: dict[str, Callable[[bytes], bool]], op: str
    ) -> None:
        """Sanity floor: the guard must not reject honestly-generated keys."""
        for _ in range(16):
            public_key, _ = native_ed25519_keypair()
            assert decode[op](public_key) is True


class TestNullArgumentsAreRefused:
    """A NULL pointer must return AMA_ERROR_INVALID_PARAM, not segfault.

    ``ama_ed25519_double_scalarmult_public`` has always guarded its pointers;
    ``point_add``, ``scalarmult_public`` and ``point_from_scalar`` guarded none
    of theirs, in either backend, so a NULL argument dereferenced instead of
    returning an error.

    That mattered more once this module started driving those entry points
    through ctypes: a Python ``None`` arrives as NULL and takes the interpreter
    down with it, so an unguarded parameter turns a test-suite typo into a
    crash with no traceback. Both backends are fixed identically, which the
    backend-differential job requires — they must agree on the verdict for
    every input, and NULL is an input.

    ``point_from_scalar`` needed an ABI change to be fixable at all: it
    returned ``void`` through 3.x, so an early return on NULL would have left
    the caller's output buffer uninitialised — silently wrong where the crash
    was at least loud. It returns ``ama_error_t`` as of 4.0.0. These
    assertions are what makes that a fix rather than a signature edit: they
    fail against a build that changed the return type without adding the
    guard, because a missing guard still segfaults.
    """

    @pytest.mark.parametrize("null_position", [0, 1, 2])
    def test_point_add_refuses_null(self, null_position: int) -> None:
        args: list[object] = [ctypes.create_string_buffer(32), _encode(1), _IDENTITY]
        args[null_position] = None
        assert _native_lib.ama_ed25519_point_add(*args) != 0

    @pytest.mark.parametrize("null_position", [0, 1, 2])
    def test_scalarmult_public_refuses_null(self, null_position: int) -> None:
        args: list[object] = [ctypes.create_string_buffer(32), _TWO, _encode(1)]
        args[null_position] = None
        assert _native_lib.ama_ed25519_scalarmult_public(*args) != 0

    @pytest.mark.parametrize("null_position", [0, 1])
    def test_point_from_scalar_refuses_null(self, null_position: int) -> None:
        args: list[object] = [ctypes.create_string_buffer(32), _TWO]
        args[null_position] = None
        assert _native_lib.ama_ed25519_point_from_scalar(*args) != 0

    def test_the_same_calls_succeed_with_real_pointers(
        self, decode: dict[str, Callable[[bytes], bool]]
    ) -> None:
        """Non-vacuity: the refusal is about NULL, not about these arguments."""
        assert decode["point_add"](_encode(1)) is True
        assert decode["scalarmult_public"](_encode(1)) is True
        out = ctypes.create_string_buffer(32)
        assert _native_lib.ama_ed25519_point_from_scalar(out, _TWO) == 0

    def test_point_from_scalar_actually_writes_the_point(self) -> None:
        """The return code is new; the output contract is not, and must hold.

        A guard added by returning early on a path that *should* have
        succeeded would pass every assertion above while producing nothing.
        2·G is a fixed, known value: it pins that the success path still
        writes, and that the written bytes are the right ones.
        """
        out = ctypes.create_string_buffer(32)
        assert _native_lib.ama_ed25519_point_from_scalar(out, _TWO) == 0
        assert out.raw == _TWO_G

    def test_point_from_scalar_leaves_the_buffer_untouched_on_refusal(self) -> None:
        """The reason the ABI had to change, asserted directly.

        The 3.x ``void`` signature admitted no early return, because a caller
        cannot distinguish "did not write" from "wrote". Now that it can, the
        refusal path must not half-write: the sentinel survives intact.
        """
        out = ctypes.create_string_buffer(b"\xa5" * 32, 32)
        assert _native_lib.ama_ed25519_point_from_scalar(out, None) != 0
        assert out.raw == b"\xa5" * 32


class TestSignatureVerificationIsUnaffected:
    """The end-to-end half, kept honest about what it can and cannot show.

    These assertions are about the change being *narrowing*: conformant
    signing and verification still work. They deliberately make no claim about
    the canonical-``y`` rule — a verify() call cannot separate a decode
    refusal from a signature mismatch, which is exactly what made the first
    version of this module vacuous.
    """

    def test_fresh_keys_round_trip(self) -> None:
        for _ in range(64):
            public_key, secret_key = native_ed25519_keypair()
            assert int.from_bytes(public_key, "little") & ((1 << 255) - 1) < P
            signature = native_ed25519_sign(MESSAGE, secret_key)
            assert native_ed25519_verify(signature, MESSAGE, public_key) is True


class TestXIsZeroWithSignBitSet:
    """RFC 8032 §5.1.3 step 3: "if x = 0, and x_0 = 1, decoding fails."

    ``x = 0`` has a single square root, so the sign bit distinguishes nothing
    and the encoding carrying it is a SECOND spelling of a point whose
    canonical encoding does not.  Neither backend implemented the rule: the
    fe51 decoder negates conditionally and ``-0 == 0``, so the bit was silently
    ignored; donna compares parity and skips the negate for the same reason.

    ``x = 0`` exactly when ``y² = 1`` — the numerator of
    ``x² = (y²-1)/(dy²+1)`` vanishes — i.e. ``y = 1`` (the identity) or
    ``y = p-1``.  Those two, and only those two, must reject with the bit set.

    Not a forgery route: neither point is a usable verification key.  This is
    the encoding-uniqueness family of INVARIANT-26/29/38, applied to the
    coordinate those invariants do not cover.
    """

    @pytest.mark.parametrize("op", OPS)
    @pytest.mark.parametrize("y", [1, P - 1], ids=["y=1 (identity)", "y=p-1"])
    def test_sign_bit_set_is_refused(
        self, decode: dict[str, Callable[[bytes], bool]], op: str, y: int
    ) -> None:
        assert decode[op](_encode(y, sign_bit=1)) is False

    @pytest.mark.parametrize("op", OPS)
    @pytest.mark.parametrize("y", [1, P - 1], ids=["y=1 (identity)", "y=p-1"])
    def test_the_canonical_encoding_still_decodes(
        self, decode: dict[str, Callable[[bytes], bool]], op: str, y: int
    ) -> None:
        """The fix must reject the twin, not the point."""
        assert decode[op](_encode(y, sign_bit=0)) is True

    @pytest.mark.parametrize("op", OPS)
    def test_ordinary_points_keep_both_sign_bits(
        self, decode: dict[str, Callable[[bytes], bool]], op: str
    ) -> None:
        """Only x = 0 is affected.

        For every other y both sign bits are legitimate — they select the two
        distinct square roots — so a check that rejected them would break
        half of all public keys.  2G is a real point on the curve; its
        y-coordinate is not ±1, so flipping the bit must still decode.
        """
        y = int.from_bytes(_TWO_G, "little") & ((1 << 255) - 1)
        assert decode[op](_encode(y, sign_bit=0)) is True
        assert decode[op](_encode(y, sign_bit=1)) is True

    def test_real_keys_are_unaffected(self) -> None:
        """Freshly generated keypairs still sign and verify.

        The guard runs on every public-key decode, so a regression in it would
        surface here as a wholesale verification failure.
        """
        for _ in range(32):
            public_key, secret_key = native_ed25519_keypair()
            signature = native_ed25519_sign(MESSAGE, secret_key)
            assert native_ed25519_verify(signature, MESSAGE, public_key) is True
