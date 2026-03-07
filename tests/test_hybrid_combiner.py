#!/usr/bin/env python3
# Copyright 2025 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Tests for the Hybrid Key Combiner module.

Validates:
    - Encapsulate/decapsulate round-trip produces identical combined secrets
    - Different inputs produce different outputs (collision resistance)
    - Ciphertext binding: swapping ciphertexts breaks the combined secret
    - Public key binding: different PKs produce different outputs
    - Python HKDF-SHA3-256 correctness (extract-then-expand)
    - Native vs Python HKDF path selection
    - Edge cases: empty inputs, large inputs
"""

import os
from unittest.mock import MagicMock

import pytest

from ama_cryptography.hybrid_combiner import (
    _HYBRID_LABEL,
    HybridCombiner,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _random_bytes(n: int) -> bytes:
    return os.urandom(n)


def _mock_classical_encapsulate(pk: bytes):
    """Simulates X25519 encapsulation: returns (ct, ss)."""
    ct = _random_bytes(32)
    ss = _random_bytes(32)
    return ct, ss


def _mock_pqc_encapsulate(pk: bytes):
    """Simulates Kyber encapsulation: returns (ct, ss)."""
    ct = _random_bytes(1568)
    ss = _random_bytes(32)
    return ct, ss


# ---------------------------------------------------------------------------
# Python HKDF fallback tests
# ---------------------------------------------------------------------------


class TestHybridCombinerPythonHKDF:
    """Tests using the Python HKDF-SHA3-256 fallback (no native lib)."""

    def setup_method(self):
        """Create a combiner forced to Python fallback."""
        # Pass a mock with no ama_hkdf attribute to prevent native detection
        self.combiner = HybridCombiner(native_lib=MagicMock(spec=[]))
        assert not self.combiner._has_native

    def test_combine_produces_32_bytes(self):
        """Default output should be 32 bytes."""
        result = self.combiner.combine(
            classical_ss=_random_bytes(32),
            pqc_ss=_random_bytes(32),
            classical_ct=_random_bytes(32),
            pqc_ct=_random_bytes(1568),
        )
        assert len(result) == 32

    def test_combine_custom_output_length(self):
        """Custom output lengths should work."""
        for length in [16, 48, 64]:
            result = self.combiner.combine(
                classical_ss=_random_bytes(32),
                pqc_ss=_random_bytes(32),
                classical_ct=_random_bytes(32),
                pqc_ct=_random_bytes(1568),
                output_len=length,
            )
            assert len(result) == length

    def test_deterministic_with_same_inputs(self):
        """Same inputs must produce same output."""
        css = _random_bytes(32)
        pss = _random_bytes(32)
        cct = _random_bytes(32)
        pct = _random_bytes(1568)
        cpk = _random_bytes(32)
        ppk = _random_bytes(1184)

        r1 = self.combiner.combine(css, pss, cct, pct, cpk, ppk)
        r2 = self.combiner.combine(css, pss, cct, pct, cpk, ppk)
        assert r1 == r2

    def test_different_secrets_produce_different_output(self):
        """Changing shared secrets must change the combined secret."""
        cct = _random_bytes(32)
        pct = _random_bytes(1568)
        r1 = self.combiner.combine(_random_bytes(32), _random_bytes(32), cct, pct)
        r2 = self.combiner.combine(_random_bytes(32), _random_bytes(32), cct, pct)
        assert r1 != r2

    def test_ciphertext_binding(self):
        """Swapping ciphertexts must change the combined secret (anti-substitution)."""
        css = _random_bytes(32)
        pss = _random_bytes(32)
        cct_a = _random_bytes(32)
        cct_b = _random_bytes(32)
        pct = _random_bytes(1568)

        r1 = self.combiner.combine(css, pss, cct_a, pct)
        r2 = self.combiner.combine(css, pss, cct_b, pct)
        assert r1 != r2

    def test_public_key_binding(self):
        """Different public keys must produce different output."""
        css = _random_bytes(32)
        pss = _random_bytes(32)
        cct = _random_bytes(32)
        pct = _random_bytes(1568)

        r1 = self.combiner.combine(css, pss, cct, pct, _random_bytes(32), b"")
        r2 = self.combiner.combine(css, pss, cct, pct, _random_bytes(32), b"")
        assert r1 != r2

    def test_label_domain_separation(self):
        """Different labels must produce different output."""
        no_native = MagicMock(spec=[])
        combiner_a = HybridCombiner(native_lib=no_native, label=b"label-a")
        combiner_b = HybridCombiner(native_lib=no_native, label=b"label-b")

        css = _random_bytes(32)
        pss = _random_bytes(32)
        cct = _random_bytes(32)
        pct = _random_bytes(1568)

        r1 = combiner_a.combine(css, pss, cct, pct)
        r2 = combiner_b.combine(css, pss, cct, pct)
        assert r1 != r2

    def test_empty_public_keys_allowed(self):
        """Empty public keys should work (no binding, still valid)."""
        result = self.combiner.combine(
            classical_ss=_random_bytes(32),
            pqc_ss=_random_bytes(32),
            classical_ct=_random_bytes(32),
            pqc_ct=_random_bytes(1568),
            classical_pk=b"",
            pqc_pk=b"",
        )
        assert len(result) == 32

    def test_empty_salt_fallback(self):
        """HKDF with empty salt should use zero-filled default."""
        result = self.combiner.combine(
            classical_ss=_random_bytes(32),
            pqc_ss=_random_bytes(32),
            classical_ct=b"",
            pqc_ct=b"",
        )
        assert len(result) == 32


# ---------------------------------------------------------------------------
# Round-trip encapsulate/decapsulate tests
# ---------------------------------------------------------------------------


class TestHybridRoundTrip:
    """Encapsulate + decapsulate must produce identical combined secrets."""

    def test_round_trip_with_mock_kems(self):
        """Full encapsulate → decapsulate round-trip."""
        combiner = HybridCombiner(native_lib=None)

        # Simulate KEM key pairs
        classical_pk = _random_bytes(32)
        classical_sk = _random_bytes(32)
        pqc_pk = _random_bytes(1184)
        pqc_sk = _random_bytes(2400)

        # Capture the shared secrets for decapsulation
        classical_ct = _random_bytes(32)
        classical_ss = _random_bytes(32)
        pqc_ct = _random_bytes(1568)
        pqc_ss = _random_bytes(32)

        def enc_classical(pk):
            return classical_ct, classical_ss

        def enc_pqc(pk):
            return pqc_ct, pqc_ss

        def dec_classical(ct, sk):
            return classical_ss

        def dec_pqc(ct, sk):
            return pqc_ss

        encap = combiner.encapsulate_hybrid(enc_classical, enc_pqc, classical_pk, pqc_pk)
        decap_secret = combiner.decapsulate_hybrid(
            dec_classical,
            dec_pqc,
            classical_ct,
            pqc_ct,
            classical_sk,
            pqc_sk,
            classical_pk,
            pqc_pk,
        )

        assert encap.combined_secret == decap_secret
        assert len(encap.combined_secret) == 32

    def test_encapsulation_dataclass_fields(self):
        """HybridEncapsulation should carry all component data."""
        combiner = HybridCombiner(native_lib=None)
        ct_c = _random_bytes(32)
        ss_c = _random_bytes(32)
        ct_p = _random_bytes(1568)
        ss_p = _random_bytes(32)

        encap = combiner.encapsulate_hybrid(
            lambda pk: (ct_c, ss_c),
            lambda pk: (ct_p, ss_p),
            _random_bytes(32),
            _random_bytes(1184),
        )
        assert encap.classical_ciphertext == ct_c
        assert encap.pqc_ciphertext == ct_p
        assert encap.classical_shared_secret == ss_c
        assert encap.pqc_shared_secret == ss_p
        assert isinstance(encap.combined_secret, bytes)

    def test_mismatched_ciphertext_breaks_decapsulation(self):
        """Using wrong ciphertext in decapsulation must produce different secret."""
        combiner = HybridCombiner(native_lib=None)
        classical_ss = _random_bytes(32)
        pqc_ss = _random_bytes(32)
        classical_ct = _random_bytes(32)
        pqc_ct = _random_bytes(1568)
        wrong_ct = _random_bytes(32)
        pk_c = _random_bytes(32)
        pk_p = _random_bytes(1184)

        encap = combiner.encapsulate_hybrid(
            lambda pk: (classical_ct, classical_ss),
            lambda pk: (pqc_ct, pqc_ss),
            pk_c,
            pk_p,
        )

        # Decapsulate with wrong classical ciphertext
        decap_wrong = combiner.decapsulate_hybrid(
            lambda ct, sk: classical_ss,
            lambda ct, sk: pqc_ss,
            wrong_ct,  # Wrong!
            pqc_ct,
            _random_bytes(32),
            _random_bytes(2400),
            pk_c,
            pk_p,
        )

        assert encap.combined_secret != decap_wrong


# ---------------------------------------------------------------------------
# Native library path tests
# ---------------------------------------------------------------------------


class TestHybridCombinerNativePath:
    """Tests for native C library integration."""

    def test_native_lib_detection(self):
        """When native lib has ama_hkdf, _has_native should be True."""
        mock_lib = MagicMock()
        mock_lib.ama_hkdf = MagicMock()
        combiner = HybridCombiner(native_lib=mock_lib)
        assert combiner._has_native

    def test_native_hkdf_called_when_available(self):
        """combine() should use native path when available."""
        mock_lib = MagicMock()
        mock_lib.ama_hkdf = MagicMock(return_value=0)
        combiner = HybridCombiner(native_lib=mock_lib)
        combiner.combine(
            classical_ss=b"\x00" * 32,
            pqc_ss=b"\x00" * 32,
            classical_ct=b"\x00" * 32,
            pqc_ct=b"\x00" * 1568,
        )
        mock_lib.ama_hkdf.assert_called_once()

    def test_native_hkdf_error_raises(self):
        """Non-zero return from native HKDF should raise RuntimeError."""
        mock_lib = MagicMock()
        mock_lib.ama_hkdf = MagicMock(return_value=-1)
        combiner = HybridCombiner(native_lib=mock_lib)
        with pytest.raises(RuntimeError, match="Native HKDF failed"):
            combiner.combine(
                classical_ss=b"\x00" * 32,
                pqc_ss=b"\x00" * 32,
                classical_ct=b"\x00" * 32,
                pqc_ct=b"\x00" * 1568,
            )

    def test_fallback_when_no_ama_hkdf(self):
        """Lib without ama_hkdf attribute should fall back to Python."""
        mock_lib = MagicMock(spec=[])  # No attributes
        combiner = HybridCombiner(native_lib=mock_lib)
        assert not combiner._has_native
        # Should still work via Python fallback
        result = combiner.combine(
            classical_ss=_random_bytes(32),
            pqc_ss=_random_bytes(32),
            classical_ct=_random_bytes(32),
            pqc_ct=_random_bytes(1568),
        )
        assert len(result) == 32


# ---------------------------------------------------------------------------
# HKDF-SHA3-256 edge cases
# ---------------------------------------------------------------------------


class TestHKDFEdgeCases:
    """Edge case tests for the Python HKDF-SHA3-256 implementation."""

    def test_large_key_hashed(self):
        """HMAC key longer than block_size should be hashed before use."""
        combiner = HybridCombiner(native_lib=None)
        # Use a very large shared secret (> 136 bytes, SHA3-256 block size)
        large_ss = _random_bytes(256)
        result = combiner.combine(
            classical_ss=large_ss,
            pqc_ss=large_ss,
            classical_ct=_random_bytes(32),
            pqc_ct=_random_bytes(1568),
        )
        assert len(result) == 32

    def test_hkdf_output_exceeding_max_raises(self):
        """Output length > 255 * 32 should raise ValueError."""
        combiner = HybridCombiner(native_lib=None)
        with pytest.raises(ValueError, match="exceeds maximum"):
            combiner._hkdf_python(b"salt", b"ikm", b"info", 255 * 32 + 1)

    def test_default_label(self):
        """Default label should match module constant."""
        combiner = HybridCombiner(native_lib=None)
        assert combiner.label == _HYBRID_LABEL
        assert combiner.label == b"ama-hybrid-kem-v2"
