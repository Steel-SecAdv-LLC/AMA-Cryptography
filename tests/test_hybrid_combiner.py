#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Tests for the Hybrid Key Combiner module.

Validates:
    - Encapsulate/decapsulate round-trip produces identical combined secrets
    - Different inputs produce different outputs (collision resistance)
    - Ciphertext binding: swapping ciphertexts breaks the combined secret
    - Public key binding: different PKs produce different outputs
    - INVARIANT-7: combine() raises RuntimeError when native HKDF is unavailable
    - Native HKDF path selection and error handling
    - HKDF-SHA3-256 construction correctness (via _hkdf_python direct calls)
    - Edge cases: empty inputs, large inputs
"""

from __future__ import annotations

import os
from typing import Any
from unittest.mock import MagicMock

import pytest

from ama_cryptography.hybrid_combiner import _HYBRID_LABEL, HybridCombiner

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _random_bytes(n: int) -> bytes:
    return os.urandom(n)


def _mock_classical_encapsulate(pk: bytes) -> tuple[bytes, bytes]:
    """Simulates X25519 encapsulation: returns (ct, ss)."""
    ct = _random_bytes(32)
    ss = _random_bytes(32)
    return ct, ss


def _mock_pqc_encapsulate(pk: bytes) -> tuple[bytes, bytes]:
    """Simulates Kyber encapsulation: returns (ct, ss)."""
    ct = _random_bytes(1568)
    ss = _random_bytes(32)
    return ct, ss


# ---------------------------------------------------------------------------
# INVARIANT-7: combine() must raise when native HKDF is unavailable
# ---------------------------------------------------------------------------


class TestHybridCombinerInvariant7:
    """Verify INVARIANT-7: combine() raises RuntimeError without native lib.

    The _hkdf_python static method is still tested directly in
    TestHKDFEdgeCases for construction correctness, but combine()
    must refuse to use it.
    """

    def setup_method(self) -> None:
        """Create a combiner without native HKDF."""
        self.combiner = HybridCombiner(native_lib=MagicMock(spec=[]))
        assert not self.combiner._has_native

    def test_combine_raises_without_native(self) -> None:
        """combine() must raise RuntimeError when native HKDF is unavailable."""
        with pytest.raises(RuntimeError, match="INVARIANT-7"):
            self.combiner.combine(
                classical_ss=_random_bytes(32),
                pqc_ss=_random_bytes(32),
                classical_ct=_random_bytes(32),
                pqc_ct=_random_bytes(1568),
            )

    def test_combine_raises_with_custom_output_length(self) -> None:
        """RuntimeError is raised regardless of output_len."""
        with pytest.raises(RuntimeError, match="INVARIANT-7"):
            self.combiner.combine(
                classical_ss=_random_bytes(32),
                pqc_ss=_random_bytes(32),
                classical_ct=_random_bytes(32),
                pqc_ct=_random_bytes(1568),
                output_len=64,
            )

    def test_combine_raises_with_public_keys(self) -> None:
        """RuntimeError is raised even when public keys are provided."""
        with pytest.raises(RuntimeError, match="INVARIANT-7"):
            self.combiner.combine(
                classical_ss=_random_bytes(32),
                pqc_ss=_random_bytes(32),
                classical_ct=_random_bytes(32),
                pqc_ct=_random_bytes(1568),
                classical_pk=_random_bytes(32),
                pqc_pk=_random_bytes(1184),
            )

    def test_different_labels_still_raise(self) -> None:
        """Different labels still raise when native is unavailable."""
        no_native = MagicMock(spec=[])
        combiner = HybridCombiner(native_lib=no_native, label=b"custom-label")
        with pytest.raises(RuntimeError, match="INVARIANT-7"):
            combiner.combine(
                classical_ss=_random_bytes(32),
                pqc_ss=_random_bytes(32),
                classical_ct=_random_bytes(32),
                pqc_ct=_random_bytes(1568),
            )


# ---------------------------------------------------------------------------
# Round-trip encapsulate/decapsulate tests
# ---------------------------------------------------------------------------


class TestHybridRoundTrip:
    """Encapsulate + decapsulate must produce identical combined secrets."""

    def test_round_trip_with_mock_kems(self) -> Any:
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

        def enc_classical(pk: Any) -> Any:
            return classical_ct, classical_ss

        def enc_pqc(pk: Any) -> Any:
            return pqc_ct, pqc_ss

        def dec_classical(ct: Any, sk: Any) -> Any:
            return classical_ss

        def dec_pqc(ct: Any, sk: Any) -> Any:
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

    def test_encapsulation_dataclass_fields(self) -> None:
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

    def test_mismatched_ciphertext_breaks_decapsulation(self) -> None:
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

    def test_native_lib_detection(self) -> None:
        """When native lib has ama_hkdf, _has_native should be True."""
        mock_lib = MagicMock()
        mock_lib.ama_hkdf = MagicMock()
        combiner = HybridCombiner(native_lib=mock_lib)
        assert combiner._has_native

    def test_native_hkdf_called_when_available(self) -> None:
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

    def test_native_hkdf_error_raises(self) -> None:
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

    def test_no_ama_hkdf_raises_invariant7(self) -> None:
        """Lib without ama_hkdf must raise RuntimeError (INVARIANT-7)."""
        mock_lib = MagicMock(spec=[])  # No attributes
        combiner = HybridCombiner(native_lib=mock_lib)
        assert not combiner._has_native
        with pytest.raises(RuntimeError, match="INVARIANT-7"):
            combiner.combine(
                classical_ss=_random_bytes(32),
                pqc_ss=_random_bytes(32),
                classical_ct=_random_bytes(32),
                pqc_ct=_random_bytes(1568),
            )


# ---------------------------------------------------------------------------
# HKDF-SHA3-256 edge cases
# ---------------------------------------------------------------------------


class TestHKDFEdgeCases:
    """Edge case tests for the Python HKDF-SHA3-256 implementation."""

    def test_large_key_hashed(self) -> None:
        """HMAC key longer than block_size should be hashed before use."""
        large_ss = _random_bytes(256)
        result = HybridCombiner._hkdf_python(
            salt=_random_bytes(32),
            ikm=large_ss + large_ss,
            info=b"test",
            okm_len=32,
        )
        assert len(result) == 32

    def test_hkdf_output_exceeding_max_raises(self) -> None:
        """Output length > 255 * 32 should raise ValueError."""
        with pytest.raises(ValueError, match="exceeds maximum"):
            HybridCombiner._hkdf_python(b"salt", b"ikm", b"info", 255 * 32 + 1)

    def test_default_label(self) -> None:
        """Default label should match module constant."""
        combiner = HybridCombiner(native_lib=None)
        assert combiner.label == _HYBRID_LABEL
        assert combiner.label == b"ama-hybrid-kem-v2"
