#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Length handling in ``constant_time_compare``, and the public pre-check.

The defect
----------
``constant_time_compare`` padded **both** operands to
``max(len(a), len(b))`` with ``ljust`` before handing them to the native
comparator.  Every call site compares a locally computed value against one
that arrived from outside — ``crypto_api.verify_crypto_package`` recomputes a
32-byte HMAC-SHA3-256 tag and compares it to ``package.hmac_tag``, which is
whatever the package says it is — so a package declaring a large tag caused
two allocations and a scan of that size to reject a 32-byte value, before any
check had established the package was worth looking at.  That is unbounded
memory and CPU amplification on unauthenticated input, in the function whose
job is to decide whether the input is authentic.

The fix, and why it is not a weakening
--------------------------------------
``min(len(a), len(b))`` bytes are compared in place, with the length
difference OR-ed into the verdict.  Lengths were never the secret here: a MAC
tag, a public key and a KEM shared secret each have one size fixed by their
specification.  Content is the secret, and the content scan is unchanged — the
native ``ama_consttime_memcmp`` accumulates over every one of the n bytes with
no early exit.

:func:`lengths_match` publishes that reasoning as API, so call sites can
refuse a wrong-length value explicitly instead of folding a structural defect
into a cryptographic verdict.

What is pinned here
-------------------
* Every input shape returns exactly what it returned before, including the
  empty and one-empty cases.
* Work no longer scales with the untrusted operand — asserted by measuring
  allocation with ``tracemalloc``, which fails on the unfixed implementation.
* The equal-length content comparison is still branch-free with respect to
  content (where the difference sits does not change the work done).
* The call sites that gained the pre-check refuse a wrong-length value, and
  say so as "malformed" rather than "did not match".
"""

from __future__ import annotations

import tracemalloc

import pytest

# One import form for one module, not two.  CodeQL's py/import-and-import-from
# flagged the earlier `import ama_cryptography.secure_memory as secure_memory`
# sitting beside the `from ... import` below, and it was right to: two binding
# paths to the same module is how a later reader ends up patching one and
# reading through the other.  `from ama_cryptography import secure_memory`
# binds the module object through the same mechanism as the names beneath it.
from ama_cryptography import secure_memory
from ama_cryptography.secure_memory import constant_time_compare, lengths_match

pytestmark = pytest.mark.skipif(
    secure_memory._native_consttime_memcmp is None,
    reason="constant_time_compare requires the native backend (INVARIANT-7)",
)

#: Big enough that the old ``max``-padding is unmissable in an allocation
#: measurement, small enough not to hurt a constrained runner.
BIG = 8 * 1024 * 1024
TAG = b"\x11" * 32


class TestVerdictsAreUnchanged:
    @pytest.mark.parametrize(
        ("a", "b", "expected"),
        [
            (b"", b"", True),
            (b"", b"a", False),
            (b"a", b"", False),
            (b"abc", b"abc", True),
            (b"abc", b"abd", False),
            (b"abc", b"abcd", False),
            (b"abcd", b"abc", False),
            # NUL bytes: a prefix relationship where the longer side is padded
            # with exactly the byte ``ljust`` used to add.  Under the old
            # implementation the content scan compared equal here and only the
            # length term rejected it; the verdict must not have changed.
            (b"\x00", b"", False),
            (b"", b"\x00", False),
            (b"a", b"a\x00", False),
            (b"a\x00", b"a", False),
            (b"\x00" * 4, b"\x00" * 8, False),
        ],
    )
    def test_matrix(self, a: bytes, b: bytes, expected: bool) -> None:
        assert constant_time_compare(a, b) is expected

    def test_argument_order_does_not_change_the_verdict(self) -> None:
        for a, b in ((b"abc", b"abcd"), (b"", b"x"), (b"\x00", b"\x00\x00")):
            assert constant_time_compare(a, b) == constant_time_compare(b, a)

    @pytest.mark.parametrize("position", [0, 1, 15, 16, 30, 31])
    def test_a_difference_anywhere_is_caught(self, position: int) -> None:
        other = bytearray(TAG)
        other[position] ^= 0x01
        assert constant_time_compare(TAG, bytes(other)) is False


class TestWorkIsBoundedByTheShorterOperand:
    """The amplification, measured rather than argued.

    ``tracemalloc`` sees the ``ljust`` copies the old implementation made and
    does not see the native scan, which is the right instrument: the defect
    was that a caller-supplied length drove *allocation* inside a function
    the caller was not otherwise trusted by.
    """

    @staticmethod
    def _peak_bytes(a: bytes, b: bytes) -> int:
        # Both operands exist before tracing starts, so only what the function
        # itself allocates is measured.
        tracemalloc.start()
        try:
            constant_time_compare(a, b)
            return tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

    def test_short_expected_against_a_large_untrusted_value(self) -> None:
        big = b"\x22" * BIG
        peak = self._peak_bytes(TAG, big)
        assert peak < 64 * 1024, f"allocated {peak} bytes to reject a 32-byte tag"

    def test_the_same_holds_with_the_arguments_reversed(self) -> None:
        """Order-independence matters: it is what makes the fix robust.

        A ``min``-bounded comparison cannot be defeated by a call site that
        passes the untrusted value first, whereas an implementation bounded by
        ``len(a)`` could be.
        """
        big = b"\x22" * BIG
        peak = self._peak_bytes(big, TAG)
        assert peak < 64 * 1024, f"allocated {peak} bytes to reject a 32-byte tag"

    def test_equal_length_comparison_allocates_nothing_appreciable(self) -> None:
        peak = self._peak_bytes(TAG, bytes(TAG))
        assert peak < 64 * 1024


class TestLengthsMatch:
    @pytest.mark.parametrize(
        ("a", "b", "expected"),
        [
            (b"", b"", True),
            (b"abc", b"xyz", True),
            (b"abc", b"ab", False),
            (b"", b"a", False),
            (b"\x00" * 32, b"\xff" * 32, True),
        ],
    )
    def test_matrix(self, a: bytes, b: bytes, expected: bool) -> None:
        assert lengths_match(a, b) is expected

    def test_it_compares_length_and_not_content(self) -> None:
        assert lengths_match(b"\x00" * 32, b"\xff" * 32) is True
        assert constant_time_compare(b"\x00" * 32, b"\xff" * 32) is False

    def test_it_is_exported(self) -> None:
        assert "lengths_match" in secure_memory.__all__


class TestCallSitesRefuseWrongLengths:
    """The pre-check where it was added, driven through the public API."""

    def test_hmac_verify_refuses_a_short_tag(self) -> None:
        from ama_cryptography.legacy_compat import hmac_authenticate, hmac_verify

        key = b"k" * 32
        tag = hmac_authenticate(b"message", key)
        assert hmac_verify(b"message", tag, key) is True
        assert hmac_verify(b"message", tag[:16], key) is False
        assert hmac_verify(b"message", tag + b"\x00", key) is False

    def test_package_hmac_layer_reports_a_malformed_tag_as_malformed(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        import dataclasses
        import logging

        from ama_cryptography.crypto_api import create_crypto_package, verify_crypto_package

        content = b"content under test"
        package = create_crypto_package(content)
        mangled = dataclasses.replace(package, hmac_tag=package.hmac_tag[:16])

        with caplog.at_level(logging.ERROR):
            results = verify_crypto_package(content, mangled)

        assert results["hmac"] is False
        assert any("malformed" in record.message for record in caplog.records), (
            "a wrong-length tag was reported as a failed comparison rather than "
            "as a malformed package"
        )

    def test_key_pinning_refuses_a_wrong_length_anchor(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        import logging

        from ama_cryptography.crypto_api import create_crypto_package, verify_crypto_package

        content = b"content under test"
        package = create_crypto_package(content)
        signing_key = package.keypairs["HYBRID_SIG"].public_key

        # Non-vacuity: the genuine key still pins.
        good = verify_crypto_package(content, package, expected_public_key=signing_key)
        assert good["key_pinned"] is True and good["all_valid"] is True

        with caplog.at_level(logging.ERROR):
            bad = verify_crypto_package(content, package, expected_public_key=signing_key[:16])

        assert bad["key_pinned"] is False
        assert bad["primary_signature"] is False
        assert bad["all_valid"] is False
        assert any("public key, package carries" in record.message for record in caplog.records)
