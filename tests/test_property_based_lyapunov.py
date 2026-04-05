#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Property-Based Lyapunov Tests
===============================

Hypothesis-driven property tests covering:
1. Lyapunov stability invariant
2. Golden ratio convergence
3. NTT roundtrip (placeholder — NTT not exposed in public API)
4. HKDF determinism
5. Signature determinism for Ed25519
6. Kyber encaps/decaps roundtrip

AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ama_cryptography.pqc_backends import (
    _ED25519_NATIVE_AVAILABLE,
    _HKDF_NATIVE_AVAILABLE,
    DILITHIUM_AVAILABLE,
    KYBER_AVAILABLE,
    _native_lib,
)

NATIVE_AVAILABLE = _native_lib is not None

skip_no_native = pytest.mark.skipif(not NATIVE_AVAILABLE, reason="Native C library not available")
skip_no_kyber = pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber not available")
skip_no_ed25519 = pytest.mark.skipif(not _ED25519_NATIVE_AVAILABLE, reason="Ed25519 not available")
skip_no_hkdf = pytest.mark.skipif(not _HKDF_NATIVE_AVAILABLE, reason="Native HKDF not available")
skip_no_dilithium = pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium not available")


# ===========================================================================
# 1. LYAPUNOV STABILITY INVARIANT
# ===========================================================================


class TestLyapunovStability:
    """Property: V(x) >= 0 for all x, and V(0) == 0."""

    @given(
        state=st.lists(
            st.floats(min_value=-100.0, max_value=100.0, allow_nan=False, allow_infinity=False),
            min_size=3,
            max_size=10,
        )
    )
    @settings(max_examples=100)
    def test_lyapunov_nonnegative(self, state: "list[float]") -> None:
        """Lyapunov function value must be non-negative for any state."""
        from ama_cryptography._numeric import array
        from ama_cryptography.equations import lyapunov_function

        x = array(state)
        target = array([0.0] * len(state))
        v = lyapunov_function(x, target)
        assert v >= 0.0, f"V(x) = {v} < 0 for state {state}"

    def test_lyapunov_zero_at_equilibrium(self) -> None:
        """Lyapunov function must be zero at the equilibrium point."""
        from ama_cryptography._numeric import array
        from ama_cryptography.equations import lyapunov_function

        for n in [3, 5, 10]:
            zero = array([0.0] * n)
            v = lyapunov_function(zero, zero)
            assert abs(v) < 1e-10, f"V(0) = {v} != 0 for dim {n}"

    @given(
        state=st.lists(
            st.floats(min_value=-100.0, max_value=100.0, allow_nan=False, allow_infinity=False),
            min_size=3,
            max_size=10,
        )
    )
    @settings(max_examples=50)
    def test_lyapunov_derivative_negative(self, state: "list[float]") -> None:
        """Lyapunov derivative must be <= 0 (stability)."""
        from ama_cryptography._numeric import array
        from ama_cryptography.equations import lyapunov_derivative, lyapunov_function

        x = array(state)
        target = array([0.0] * len(state))
        v = lyapunov_function(x, target)
        v_dot = lyapunov_derivative(v)
        assert v_dot <= 0.0, f"V_dot = {v_dot} > 0 for V = {v}"


# ===========================================================================
# 2. GOLDEN RATIO CONVERGENCE
# ===========================================================================


class TestGoldenRatioConvergence:
    """Property: Fibonacci ratio converges to PHI."""

    @given(n=st.integers(min_value=10, max_value=50))
    @settings(max_examples=20)
    def test_fibonacci_ratio_converges_to_phi(self, n: int) -> None:
        """Ratio of consecutive Fibonacci terms must converge to PHI."""
        from ama_cryptography.equations import PHI, fibonacci_sequence

        seq = fibonacci_sequence(n)
        if len(seq) >= 2 and seq[-2] > 0:
            ratio = seq[-1] / seq[-2]
            assert abs(ratio - PHI) < 0.01, f"Ratio {ratio} not close to PHI={PHI} for n={n}"

    def test_golden_ratio_convergence_proof(self) -> None:
        """The built-in golden ratio convergence proof must pass."""
        from ama_cryptography.equations import golden_ratio_convergence_proof

        passed, final_ratio, _details = golden_ratio_convergence_proof(iterations=30)
        assert passed, f"Golden ratio convergence failed: ratio={final_ratio}"


# ===========================================================================
# 3. NTT ROUNDTRIP (HKDF-based determinism as substitute)
# ===========================================================================


@skip_no_hkdf
class TestNTTRoundtripSubstitute:
    """NTT is internal to the C library; test HKDF determinism instead."""

    @given(
        ikm=st.binary(min_size=1, max_size=64),
        salt=st.binary(min_size=1, max_size=64),
        info=st.binary(min_size=0, max_size=64),
    )
    @settings(max_examples=50)
    def test_hkdf_roundtrip_determinism(self, ikm: bytes, salt: bytes, info: bytes) -> None:
        """HKDF must produce identical output for identical inputs."""
        from ama_cryptography.pqc_backends import native_hkdf

        key1 = native_hkdf(ikm, 32, salt=salt, info=info)
        key2 = native_hkdf(ikm, 32, salt=salt, info=info)
        assert key1 == key2, "HKDF produced different outputs for same inputs"


# ===========================================================================
# 4. HKDF DETERMINISM
# ===========================================================================


@skip_no_hkdf
class TestHKDFDeterminism:
    """Property: HKDF is deterministic — same inputs produce same output."""

    @given(
        ikm=st.binary(min_size=0, max_size=128),
        salt=st.binary(min_size=0, max_size=128),
        info=st.binary(min_size=0, max_size=128),
    )
    @settings(max_examples=100)
    def test_hkdf_deterministic(self, ikm: bytes, salt: bytes, info: bytes) -> None:
        """Identical (ikm, salt, info) triple must produce identical output."""
        from ama_cryptography.pqc_backends import native_hkdf

        out1 = native_hkdf(ikm, 32, salt=salt if salt else None, info=info)
        out2 = native_hkdf(ikm, 32, salt=salt if salt else None, info=info)
        assert out1 == out2


# ===========================================================================
# 5. SIGNATURE DETERMINISM FOR Ed25519
# ===========================================================================


@skip_no_ed25519
class TestEd25519SignatureDeterminism:
    """Property: Ed25519 signing is deterministic (RFC 8032)."""

    @given(msg=st.binary(min_size=0, max_size=1000))
    @settings(max_examples=50)
    def test_ed25519_deterministic_signatures(self, msg: bytes) -> None:
        """Signing the same message twice with the same key must produce the same sig."""
        from ama_cryptography.pqc_backends import (
            native_ed25519_keypair,
            native_ed25519_sign,
        )

        _pk, sk = native_ed25519_keypair()
        sig1 = native_ed25519_sign(msg, sk)
        sig2 = native_ed25519_sign(msg, sk)
        assert sig1 == sig2, "Ed25519 produced non-deterministic signatures"


# ===========================================================================
# 6. KYBER ENCAPS/DECAPS ROUNDTRIP
# ===========================================================================


@skip_no_kyber
class TestKyberEncapsDecapsRoundtrip:
    """Property: encapsulate then decapsulate must recover the shared secret."""

    @settings(max_examples=50)
    @given(data=st.data())
    def test_kyber_roundtrip(self, data: st.DataObject) -> None:
        """Encaps/decaps roundtrip must recover the same shared secret."""
        from ama_cryptography.pqc_backends import (
            generate_kyber_keypair,
            kyber_decapsulate,
            kyber_encapsulate,
        )

        kp = generate_kyber_keypair()
        encap = kyber_encapsulate(kp.public_key)
        ss = kyber_decapsulate(encap.ciphertext, kp.secret_key)
        assert ss == encap.shared_secret, "Kyber roundtrip failed"
        assert len(ss) == 32
