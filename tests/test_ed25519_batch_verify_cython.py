#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Ed25519 Batch Verify — Cython Path Tests
==========================================

Tests for the Cython cy_ed25519_batch_verify() wrapper.
Separated from test_ed25519_batch_verify.py to avoid the module-level
pytestmark skipif (which triggers CI backend enforcement when the native
C library is present but Cython extensions are not compiled).

AI Co-Architects: Eris -> | Eden + | Devin <> | Claude <>
"""

from __future__ import annotations

import secrets

import pytest


def _generate_random_entry(index: int) -> tuple[bytes, bytes, bytes]:
    """Generate a valid signed entry using the native C library."""
    from ama_cryptography.pqc_backends import (
        native_ed25519_keypair,
        native_ed25519_sign,
    )

    pk, sk = native_ed25519_keypair()
    msg = f"cython-test-message-{index}-{secrets.token_hex(8)}".encode()
    sig = native_ed25519_sign(msg, sk)
    return (msg, sig, pk)


class TestBatchVerifyCython:
    """Explicitly test the Cython batch verify path if available."""

    def test_cython_path(self) -> None:
        """Verify Cython cy_ed25519_batch_verify works if compiled."""
        cy_batch = pytest.importorskip(
            "src.cython.ed25519_binding",
            reason="Cython ed25519_binding not compiled",
        ).cy_ed25519_batch_verify

        entries = [_generate_random_entry(i) for i in range(5)]
        results = cy_batch(entries)

        assert len(results) == 5
        assert all(results)

    def test_cython_empty(self) -> None:
        """Cython batch verify with empty input."""
        cy_batch = pytest.importorskip(
            "src.cython.ed25519_binding",
            reason="Cython ed25519_binding not compiled",
        ).cy_ed25519_batch_verify

        assert cy_batch([]) == []

    def test_cython_over_max_raises(self) -> None:
        """Cython batch verify raises ValueError for >64 entries."""
        cy_batch = pytest.importorskip(
            "src.cython.ed25519_binding",
            reason="Cython ed25519_binding not compiled",
        ).cy_ed25519_batch_verify

        # Create 65 dummy entries (won't actually be verified)
        dummy = [(b"m", b"\x00" * 64, b"\x00" * 32)] * 65
        with pytest.raises(ValueError, match="64"):
            cy_batch(dummy)

    def test_cython_mixed(self) -> None:
        """Cython batch verify with mixed valid/invalid entries."""
        cy_batch = pytest.importorskip(
            "src.cython.ed25519_binding",
            reason="Cython ed25519_binding not compiled",
        ).cy_ed25519_batch_verify

        entries = [_generate_random_entry(i) for i in range(3)]

        # Corrupt entry 1
        msg1, sig1, pk1 = entries[1]
        bad_sig = bytearray(sig1)
        bad_sig[0] ^= 0xFF
        entries[1] = (msg1, bytes(bad_sig), pk1)

        results = cy_batch(entries)

        assert results[0] is True
        assert results[1] is False
        assert results[2] is True
