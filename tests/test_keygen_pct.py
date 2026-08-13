#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Pairwise consistency tests on every keygen path (INVARIANT-41)
==============================================================

Three directions, each of which must hold for the invariant to mean anything:

* **Wiring** — every asymmetric keygen entry point invokes the matching
  pairwise helper.  Proven by substituting recorders for the helpers and
  driving each entry point once, so a future keygen path that forgets the
  test fails the coverage assertion here rather than shipping ungated.
* **Failure** — a keypair whose halves do not correspond must raise
  ``CryptoModuleError`` and put the module in the ERROR state, and the ERROR
  state must then refuse further key generation (INVARIANT-39).
* **Positive** — the real tests pass on real keypairs for every fast family,
  so the wiring proven above is exercised end to end, not merely recorded.

Every test that can drive the module into ERROR restores OPERATIONAL in a
``finally`` — a poisoned state here would cascade into every later test in
the session.
"""

from __future__ import annotations

import ctypes
from typing import Any, Callable

import pytest

import ama_cryptography._module_state as ms
import ama_cryptography.pqc_backends as pb
from ama_cryptography.exceptions import CryptoModuleError

pytestmark = pytest.mark.skipif(
    pb._native_lib is None, reason="native library not loaded in this environment"
)


@pytest.fixture(autouse=True)
def _never_leak_the_error_state() -> Any:
    """Restore OPERATIONAL after EVERY test in this file, unconditionally.

    The per-test ``finally`` blocks below remain (they restore even when a
    later assertion in the same test would run), but this fixture is the
    backstop the file's docstring promises: the positive-path tests run REAL
    pairwise tests on real keypairs, and a genuine failure there would
    otherwise leave the module in ERROR and cascade a POST-lockout failure
    into every subsequent test in the session.
    """
    yield
    if ms.module_status() != "OPERATIONAL":
        ms._set_operational()


# ---------------------------------------------------------------------------
# Wiring: every keygen entry point must invoke its pairwise helper.
# ---------------------------------------------------------------------------


class TestEveryKeygenPathIsWired:
    def test_all_pqc_backends_keygens_run_a_pct(self, monkeypatch: pytest.MonkeyPatch) -> None:
        recorded: list[str] = []

        def rec_sig(sign_fn: Any, verify_fn: Any, sk: Any, pk: Any, name: str) -> None:
            recorded.append(name)

        def rec_kem(encaps_fn: Any, decaps_fn: Any, pk: Any, sk: Any, name: str) -> None:
            recorded.append(name)

        def rec_agree(agree_fn: Any, ephemeral: Any, sk: Any, pk: Any, name: str) -> None:
            recorded.append(name)

        monkeypatch.setattr(pb, "pairwise_test_signature", rec_sig)
        monkeypatch.setattr(pb, "pairwise_test_kem", rec_kem)
        monkeypatch.setattr(pb, "pairwise_test_agreement", rec_agree)

        # Each family is driven only when its backend is built, so on a
        # partial build (a real, documented configuration — see the
        # missing_families machinery) this test still proves the wiring of
        # every family that EXISTS instead of erroring out of the coverage
        # assertion entirely.
        expected: list[str] = []
        if pb._ED25519_NATIVE_AVAILABLE:
            pb.native_ed25519_keypair()
            pb.native_ed25519_keypair_from_seed(b"\x01" * 32)
            expected += ["Ed25519", "Ed25519"]
        if pb._ML_DSA_NATIVE_AVAILABLE:
            pb.native_ml_dsa_keypair(65)
            pb.native_ml_dsa_keypair_from_seed(65, b"\x02" * 32)
            expected += ["ML-DSA-65", "ML-DSA-65"]
        if pb._ML_KEM_NATIVE_AVAILABLE:
            pb.native_ml_kem_keypair(1024)
            pb.native_ml_kem_keypair_from_seed(1024, b"\x03" * 32, b"\x04" * 32)
            expected += ["ML-KEM-1024", "ML-KEM-1024"]
        if pb._X25519_NATIVE_AVAILABLE:
            pb.native_x25519_keypair()
            expected += ["X25519"]
        if pb._NISTP_NATIVE_AVAILABLE:
            pb.native_nistp_keypair(256)
            expected += ["P-256"]
        if pb.DILITHIUM_AVAILABLE:
            pb.generate_dilithium_keypair()
            expected += ["ML-DSA-65 (Dilithium)"]
        if pb.KYBER_AVAILABLE:
            pb.generate_kyber_keypair()
            expected += ["ML-KEM-1024 (Kyber)"]
        if pb._DETERMINISTIC_KEYGEN_AVAILABLE and pb.KYBER_AVAILABLE:
            pb.native_kyber_keypair_from_seed(b"\x05" * 32, b"\x06" * 32)
            expected += ["ML-KEM-1024 (deterministic)"]
        if pb._DETERMINISTIC_KEYGEN_AVAILABLE and pb.DILITHIUM_AVAILABLE:
            pb.native_dilithium_keypair_from_seed(b"\x07" * 32)
            expected += ["ML-DSA-65 (deterministic)"]
        if pb.FROST_AVAILABLE and pb._ED25519_NATIVE_AVAILABLE:
            pb.frost_keygen_trusted_dealer(2, 3)
            expected += ["FROST(Ed25519)"]

        assert expected, "no family available at all — the sweep proved nothing"
        assert recorded == expected

    def test_slhdsa_keygens_run_a_pct(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Separate from the sweep above only because a REAL SLH-DSA PCT costs
        ~1 s at the slow parameter set; the recorder keeps this instant."""
        recorded: list[str] = []
        monkeypatch.setattr(
            pb,
            "pairwise_test_signature",
            lambda s, v, sk, pk, name: recorded.append(name),
        )
        pb.generate_slhdsa_keypair("SHAKE-128s")
        pb.generate_sphincs_keypair()
        assert recorded == ["SLH-DSA-SHAKE-128s", "SLH-DSA-SHA2-256f (SPHINCS+)"]

    def test_context_keypair_generate_runs_a_pct(self, monkeypatch: pytest.MonkeyPatch) -> None:
        recorded: list[str] = []
        monkeypatch.setattr(
            pb, "pairwise_test_signature", lambda s, v, sk, pk, name: recorded.append(name)
        )
        monkeypatch.setattr(
            pb, "pairwise_test_kem", lambda e, d, pk, sk, name: recorded.append(name)
        )
        if not pb._CONTEXT_API_AVAILABLE:
            pytest.skip("context API not available in this build")
        for alg in (
            pb.AmaContext.ALG_ML_DSA_65,
            pb.AmaContext.ALG_KYBER_1024,
            pb.AmaContext.ALG_SPHINCS_256F,
            pb.AmaContext.ALG_ED25519,
            pb.AmaContext.ALG_HYBRID,
        ):
            pk_size, sk_size = pb.AmaContext._KEY_SIZES[alg]
            with pb.AmaContext(alg) as ctx:
                pk = ctypes.create_string_buffer(pk_size)
                sk = ctypes.create_string_buffer(sk_size)
                assert ctx.keypair_generate(pk, pk_size, sk, sk_size) == 0
        assert recorded == [
            "AmaContext(alg=0)",
            "AmaContext(ML-KEM-1024)",
            "AmaContext(alg=2)",
            "AmaContext(alg=3)",
            "AmaContext(alg=4)",
        ]

    def test_context_keypair_generate_refuses_undersized_buffers(self) -> None:
        """The capacity contract, enforced Python-side (review 6a).

        The C side's HYBRID capacity check was vacuous (get_key_sizes had no
        HYBRID case — now fixed in ama_core.c), so the Python layer refuses
        undersized buffers itself rather than letting the C write past them
        and then slicing out of a too-small Python buffer.
        """
        if not pb._CONTEXT_API_AVAILABLE:
            pytest.skip("context API not available in this build")
        with pb.AmaContext(pb.AmaContext.ALG_HYBRID) as ctx:
            small_pk = ctypes.create_string_buffer(8)
            small_sk = ctypes.create_string_buffer(8)
            assert ctx.keypair_generate(small_pk, 8, small_sk, 8) == -1

    def test_bip32_master_and_children_run_a_pct(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from ama_cryptography.key_management import HDKeyDerivation

        recorded: list[str] = []
        monkeypatch.setattr(
            ms, "pairwise_test_signature", lambda s, v, sk, pk, name: recorded.append(name)
        )
        hd = HDKeyDerivation(seed=b"\x11" * 64)
        hd.derive_path("m/0'/1")
        assert recorded[0] == "secp256k1 (BIP32 master)"
        children = [name for name in recorded if "child" in name]
        assert len(children) == 2, recorded


# ---------------------------------------------------------------------------
# Failure direction: an inconsistent keypair enters ERROR and inhibits output.
# ---------------------------------------------------------------------------


class TestPctFailureFailsClosed:
    def _expect_error_state(self, trigger: Callable[[], Any]) -> None:
        try:
            with pytest.raises(CryptoModuleError, match="Pairwise test failed"):
                trigger()
            assert ms.module_status() == "ERROR"
            with pytest.raises(CryptoModuleError):
                pb.native_ml_kem_keypair(1024)
        finally:
            ms._set_operational()

    def test_signature_pct_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pb, "native_ed25519_verify", lambda s, m, p: False)
        self._expect_error_state(pb.native_ed25519_keypair)

    def test_kem_pct_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # A decapsulation that returns a fixed wrong secret: the encapsulated
        # secret is a fresh random 32 bytes, so a collision with zeros has
        # probability 2^-256 — the comparison must fail.
        monkeypatch.setattr(pb, "native_ml_kem_decapsulate", lambda ps, ct, sk: b"\x00" * 32)
        self._expect_error_state(lambda: pb.native_ml_kem_keypair(1024))

    def test_agreement_pct_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # A constant exchange result would make BOTH roundtrip halves agree,
        # so the corruption has to vary per call: a counter guarantees the
        # two DH computations disagree and the roundtrip must fail.
        calls = {"n": 0}

        def _drifting_exchange(sk: bytes, pk: bytes) -> bytes:
            calls["n"] += 1
            return calls["n"].to_bytes(32, "big")

        monkeypatch.setattr(pb, "native_x25519_key_exchange", _drifting_exchange)
        self._expect_error_state(pb.native_x25519_keypair)


# ---------------------------------------------------------------------------
# Positive path: real pairwise tests on real keypairs, for the fast families.
# ---------------------------------------------------------------------------


class TestPctPositivePath:
    def test_fast_families_generate_with_real_pcts(self) -> None:
        pk, sk = pb.native_ed25519_keypair()
        assert len(pk) == 32 and len(sk) == 64
        pk, sk = pb.native_ml_dsa_keypair(65)
        assert len(pk) == 1952 and len(sk) == 4032
        pk, sk = pb.native_ml_kem_keypair(1024)
        assert len(pk) == 1568 and len(sk) == 3168
        pk, sk = pb.native_x25519_keypair()
        assert len(pk) == 32 and len(sk) == 32
        pub, priv = pb.native_nistp_keypair(384)
        assert len(pub) == 96 and len(priv) == 48
        assert ms.module_status() == "OPERATIONAL"

    def test_deterministic_keygen_is_still_deterministic(self) -> None:
        """The PCT must not perturb the derived keys themselves."""
        first = pb.native_ml_dsa_keypair_from_seed(65, b"\x42" * 32)
        second = pb.native_ml_dsa_keypair_from_seed(65, b"\x42" * 32)
        assert first == second

    def test_frost_dealer_shares_verify_end_to_end(self) -> None:
        if not pb.FROST_AVAILABLE:
            pytest.skip("FROST not available in this build")
        gpk, shares = pb.frost_keygen_trusted_dealer(2, 3)
        assert len(gpk) == 32 and len(shares) == 3


# ---------------------------------------------------------------------------
# The new agreement helper, both directions.
# ---------------------------------------------------------------------------


class TestPairwiseAgreementHelper:
    def test_passes_when_the_roundtrip_agrees(self) -> None:
        # A toy commutative "agreement": XOR of the two single-byte halves,
        # so agree(sk, eph_pk) == agree(eph_sk, pk) holds whenever the four
        # values XOR consistently — which the chosen constants do.
        def agree(own_sk: bytes, peer_pk: bytes) -> bytes:
            return bytes([own_sk[0] ^ peer_pk[0]])

        ms.pairwise_test_agreement(agree, (b"\x21", b"\x2c"), b"\x0e", b"\x03", "test-algo")

    def test_fails_closed_when_the_roundtrip_disagrees(self) -> None:
        # A function that ignores the peer cannot satisfy the roundtrip: the
        # two sides return their own (different) secrets and the helper must
        # fail closed.
        def agree(own_sk: bytes, peer_pk: bytes) -> bytes:
            return bytes(own_sk)

        try:
            with pytest.raises(CryptoModuleError, match="Pairwise test failed"):
                ms.pairwise_test_agreement(agree, (b"\x21", b"\x2c"), b"\x0e", b"\x03", "test-algo")
            assert ms.module_status() == "ERROR"
        finally:
            ms._set_operational()


# ---------------------------------------------------------------------------
# The ABI version handshake (INVARIANT-42, runtime half).
# ---------------------------------------------------------------------------


class TestAbiVersionHandshake:
    def test_loaded_library_reports_the_package_major(self) -> None:
        diag = pb.native_backend_diagnostics()
        assert diag["native_version"] is not None
        major = int(diag["native_version"].split(".")[0])
        assert major == pb._CRYPTOGRAPHY_VERSION_MAJOR

    def test_handshake_rejects_a_foreign_major(self) -> None:
        def fake_version_number(pmaj: Any, pmin: Any, ppat: Any) -> None:
            pmaj._obj.value = pb._CRYPTOGRAPHY_VERSION_MAJOR + 1
            pmin._obj.value = 0
            ppat._obj.value = 0

        class _FakeLib:
            ama_version_number = staticmethod(fake_version_number)

        version, reject = pb._abi_handshake(_FakeLib())  # type: ignore[arg-type]  # duck-typed stand-in for a CDLL; only ama_version_number is touched (PCT-001)
        assert version == f"{pb._CRYPTOGRAPHY_VERSION_MAJOR + 1}.0.0"
        assert reject is not None and "handshake failed" in reject

    def test_handshake_rejects_an_object_with_no_version_symbol(self) -> None:
        class _NoVersion:
            pass

        version, reject = pb._abi_handshake(_NoVersion())  # type: ignore[arg-type]  # duck-typed stand-in for a CDLL (PCT-001)
        assert version is None
        assert reject is not None and "no ama_version_number" in reject

    def test_handshake_accepts_the_package_major(self) -> None:
        def fake_version_number(pmaj: Any, pmin: Any, ppat: Any) -> None:
            pmaj._obj.value = pb._CRYPTOGRAPHY_VERSION_MAJOR
            pmin._obj.value = 9
            ppat._obj.value = 9

        class _FakeLib:
            ama_version_number = staticmethod(fake_version_number)

        version, reject = pb._abi_handshake(_FakeLib())  # type: ignore[arg-type]  # duck-typed stand-in for a CDLL (PCT-001)
        assert version == f"{pb._CRYPTOGRAPHY_VERSION_MAJOR}.9.9"
        assert reject is None
