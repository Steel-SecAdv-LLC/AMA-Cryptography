#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Edge-case tests for HybridCombiner.

Covers empty inputs, very large inputs, mismatched ciphertexts,
round-trip consistency, output uniqueness, zero-length context,
and corrupted ciphertext binding.
"""

import os

import pytest

from ama_cryptography.hybrid_combiner import HybridCombiner, HybridEncapsulation


@pytest.fixture
def combiner() -> HybridCombiner:
    """Return a HybridCombiner using the Python fallback (no native lib)."""
    return HybridCombiner(native_lib=None)


# ---- helpers ----------------------------------------------------------------

def _random(n: int) -> bytes:
    return os.urandom(n)


# ---- tests ------------------------------------------------------------------


class TestHybridCombinerEdgeCases:
    """Edge-case tests for HybridCombiner.combine()."""

    def test_empty_classical_shared_secret(self, combiner: HybridCombiner) -> None:
        """Combining with an empty classical shared secret should still
        produce a 32-byte output without raising."""
        result = combiner.combine(
            classical_ss=b"",
            pqc_ss=_random(32),
            classical_ct=_random(32),
            pqc_ct=_random(1568),
        )
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_empty_pqc_shared_secret(self, combiner: HybridCombiner) -> None:
        """Combining with an empty PQC shared secret should still produce
        a 32-byte output without raising."""
        result = combiner.combine(
            classical_ss=_random(32),
            pqc_ss=b"",
            classical_ct=_random(32),
            pqc_ct=_random(1568),
        )
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_very_large_inputs(self, combiner: HybridCombiner) -> None:
        """Large shared secrets and ciphertexts should be handled without error."""
        large = _random(100_000)
        result = combiner.combine(
            classical_ss=large,
            pqc_ss=large,
            classical_ct=large,
            pqc_ct=large,
        )
        assert len(result) == 32

    def test_mismatched_ciphertext_lengths(self, combiner: HybridCombiner) -> None:
        """Ciphertexts of wildly different lengths should still produce
        a valid 32-byte combined secret."""
        result = combiner.combine(
            classical_ss=_random(32),
            pqc_ss=_random(32),
            classical_ct=_random(5),
            pqc_ct=_random(5000),
        )
        assert len(result) == 32

    def test_round_trip_consistency(self, combiner: HybridCombiner) -> None:
        """Calling combine() twice with identical inputs must return the
        same output (deterministic HKDF)."""
        classical_ss = _random(32)
        pqc_ss = _random(32)
        classical_ct = _random(32)
        pqc_ct = _random(1568)
        classical_pk = _random(32)
        pqc_pk = _random(1184)

        r1 = combiner.combine(
            classical_ss, pqc_ss, classical_ct, pqc_ct, classical_pk, pqc_pk
        )
        r2 = combiner.combine(
            classical_ss, pqc_ss, classical_ct, pqc_ct, classical_pk, pqc_pk
        )
        assert r1 == r2

    def test_different_inputs_produce_different_outputs(
        self, combiner: HybridCombiner
    ) -> None:
        """Changing any single input must change the output."""
        base_args = dict(
            classical_ss=_random(32),
            pqc_ss=_random(32),
            classical_ct=_random(32),
            pqc_ct=_random(1568),
            classical_pk=_random(32),
            pqc_pk=_random(1184),
        )

        baseline = combiner.combine(**base_args)

        for key in ("classical_ss", "pqc_ss", "classical_ct", "pqc_ct"):
            modified = dict(base_args)
            modified[key] = _random(len(base_args[key]))
            assert combiner.combine(**modified) != baseline, (
                f"Changing {key} did not change the output"
            )

    def test_zero_length_additional_context(self, combiner: HybridCombiner) -> None:
        """Passing empty public keys (zero-length context) should work and
        produce a valid combined secret."""
        result = combiner.combine(
            classical_ss=_random(32),
            pqc_ss=_random(32),
            classical_ct=_random(32),
            pqc_ct=_random(1568),
            classical_pk=b"",
            pqc_pk=b"",
        )
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_corrupted_ciphertext_binding(self, combiner: HybridCombiner) -> None:
        """Flipping a single byte in a ciphertext must change the combined
        secret (ciphertext is bound into the HKDF salt)."""
        classical_ss = _random(32)
        pqc_ss = _random(32)
        classical_ct = bytearray(_random(32))
        pqc_ct = _random(1568)

        original = combiner.combine(
            classical_ss, pqc_ss, bytes(classical_ct), pqc_ct
        )

        # Flip one bit in the classical ciphertext
        classical_ct[0] ^= 0x01

        corrupted = combiner.combine(
            classical_ss, pqc_ss, bytes(classical_ct), pqc_ct
        )

        assert original != corrupted

    def test_encapsulate_hybrid_returns_dataclass(
        self, combiner: HybridCombiner
    ) -> None:
        """encapsulate_hybrid() should return a properly populated
        HybridEncapsulation dataclass."""

        def fake_classical_encaps(pk: bytes):
            return (_random(32), _random(32))

        def fake_pqc_encaps(pk: bytes):
            return (_random(1568), _random(32))

        result = combiner.encapsulate_hybrid(
            classical_encapsulate=fake_classical_encaps,
            pqc_encapsulate=fake_pqc_encaps,
            classical_pk=_random(32),
            pqc_pk=_random(1184),
        )
        assert isinstance(result, HybridEncapsulation)
        assert len(result.combined_secret) == 32
        assert isinstance(result.classical_ciphertext, bytes)
        assert isinstance(result.pqc_ciphertext, bytes)
