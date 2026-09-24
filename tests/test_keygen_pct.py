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
import importlib
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, cast

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
            pytest.skip("native context API not available in this build")
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
            pytest.skip("native context API not available in this build")
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
            pytest.skip("native FROST backend not available in this build")
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


# ---------------------------------------------------------------------------
# Output-buffer capacity on the whole context API (2026-09 audit, A-1).
# ---------------------------------------------------------------------------


class TestContextOutputBufferCapacity:
    """The capacity contract, on every context method that writes a buffer.

    ``keypair_generate`` refused undersized buffers from the day the gap was
    found on *its* arguments (the test above).  ``sign``,
    ``kem_encapsulate`` and ``kem_decapsulate`` take the same
    ``(buffer, declared-length)`` shape and did not, and the C side cannot
    make the check for them: ``ama_sign`` in ``src/c/ama_core.c`` validates
    only that the DECLARED length is at least
    ``AMA_ML_DSA_65_SIGNATURE_BYTES``, which a caller-declared 3309 satisfies
    whatever the real allocation is.

    Measured by the audit before the fix: a 64-byte buffer declared as 3309
    returned ``AMA_SUCCESS``, reported 3309 bytes written, and killed the
    process with SIGSEGV.  Each refusal below is that measurement, pinned.
    """

    @staticmethod
    def _skip_without_context_api() -> None:
        if not pb._CONTEXT_API_AVAILABLE:
            pytest.skip("native context API not available in this build")

    # -- the measurement, in a process of its own ---------------------------

    #: The audit's reproduction, verbatim, for a child interpreter.  It is run
    #: out-of-process because a regression here is *memory corruption*: the
    #: in-process tests below would take the whole pytest session down with
    #: SIGSEGV, and a dead session reports a signal rather than a diagnosis.
    #: Declared first in the class so its clean verdict is on the record
    #: before any in-process test can crash the run.
    _REPRODUCTION = """
import ctypes
import sys

import ama_cryptography.pqc_backends as pb

if not pb._CONTEXT_API_AVAILABLE:
    print("VERDICT SKIP")
    sys.exit(0)

with pb.AmaContext(pb.AmaContext.ALG_ML_DSA_65) as ctx:
    pk = ctypes.create_string_buffer(pb.DILITHIUM_PUBLIC_KEY_BYTES)
    sk = ctypes.create_string_buffer(pb.DILITHIUM_SECRET_KEY_BYTES)
    assert ctx.keypair_generate(
        pk, pb.DILITHIUM_PUBLIC_KEY_BYTES, sk, pb.DILITHIUM_SECRET_KEY_BYTES
    ) == 0
    signature = ctypes.create_string_buffer(64)
    declared = ctypes.pointer(ctypes.c_size_t(pb.DILITHIUM_SIGNATURE_BYTES))
    rc = ctx.sign(b"audit A-1", sk.raw, signature, declared)

print("VERDICT", rc, declared.contents.value)
"""

    def test_the_measured_overflow_cannot_crash_a_child_interpreter(self) -> None:
        """Before the fix this child returned ``AMA_SUCCESS``, reported 3309
        bytes written into a 64-byte buffer, and died with SIGSEGV (exit
        ``-11``).  Both halves are asserted: a clean exit alone would also be
        produced by a build whose ``sign`` had been made to fail everywhere,
        and ``rc == -1`` alone would be produced by a guard that refuses and
        then lets the call through anyway.
        """
        self._skip_without_context_api()
        proc = subprocess.run(
            [sys.executable, "-c", self._REPRODUCTION],
            cwd=str(Path(__file__).resolve().parents[1]),
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        assert proc.returncode == 0, (
            f"child exited {proc.returncode} "
            f"(negative = killed by that signal)\n{proc.stderr[-2000:]}"
        )
        verdict = [ln for ln in proc.stdout.splitlines() if ln.startswith("VERDICT")]
        assert verdict, proc.stdout + proc.stderr[-2000:]
        if verdict[-1] == "VERDICT SKIP":
            pytest.skip("native context API not available in the child build")
        assert verdict[-1] == f"VERDICT -1 {pb.DILITHIUM_SIGNATURE_BYTES}", verdict[-1]

    # -- sign ---------------------------------------------------------------

    def test_sign_refuses_a_declared_length_larger_than_the_buffer(self) -> None:
        """The exact shape that segfaulted: an honest algorithm-sized
        declaration over a buffer that is nowhere near that size."""
        self._skip_without_context_api()
        with pb.AmaContext(pb.AmaContext.ALG_ML_DSA_65) as ctx:
            pk = ctypes.create_string_buffer(pb.DILITHIUM_PUBLIC_KEY_BYTES)
            sk = ctypes.create_string_buffer(pb.DILITHIUM_SECRET_KEY_BYTES)
            assert (
                ctx.keypair_generate(
                    pk,
                    pb.DILITHIUM_PUBLIC_KEY_BYTES,
                    sk,
                    pb.DILITHIUM_SECRET_KEY_BYTES,
                )
                == 0
            )
            sig = ctypes.create_string_buffer(64)
            sig_len = ctypes.pointer(ctypes.c_size_t(pb.DILITHIUM_SIGNATURE_BYTES))
            assert ctx.sign(b"regression", sk.raw, sig, sig_len) == -1

    def test_sign_refuses_a_read_only_output_buffer(self) -> None:
        """``ctypes`` marshals an immutable ``bytes`` as an output pointer
        without complaint; CPython then has C write through an object it
        guarantees is immutable (interned literals are shared process-wide)."""
        self._skip_without_context_api()
        with pb.AmaContext(pb.AmaContext.ALG_ML_DSA_65) as ctx:
            pk = ctypes.create_string_buffer(pb.DILITHIUM_PUBLIC_KEY_BYTES)
            sk = ctypes.create_string_buffer(pb.DILITHIUM_SECRET_KEY_BYTES)
            ctx.keypair_generate(
                pk, pb.DILITHIUM_PUBLIC_KEY_BYTES, sk, pb.DILITHIUM_SECRET_KEY_BYTES
            )
            frozen = self._frozen(pb.DILITHIUM_SIGNATURE_BYTES)
            sig_len = ctypes.pointer(ctypes.c_size_t(pb.DILITHIUM_SIGNATURE_BYTES))
            assert ctx.sign(b"regression", sk.raw, frozen, sig_len) == -1

    def test_sign_still_succeeds_on_a_correctly_sized_buffer(self) -> None:
        """The positive control: the guard refuses the hazard, not the API.

        Without this, every refusal above would also pass if ``sign`` had
        simply been made to return ``-1`` unconditionally.
        """
        self._skip_without_context_api()
        with pb.AmaContext(pb.AmaContext.ALG_ML_DSA_65) as ctx:
            pk = ctypes.create_string_buffer(pb.DILITHIUM_PUBLIC_KEY_BYTES)
            sk = ctypes.create_string_buffer(pb.DILITHIUM_SECRET_KEY_BYTES)
            assert (
                ctx.keypair_generate(
                    pk,
                    pb.DILITHIUM_PUBLIC_KEY_BYTES,
                    sk,
                    pb.DILITHIUM_SECRET_KEY_BYTES,
                )
                == 0
            )
            sig = ctypes.create_string_buffer(pb.DILITHIUM_SIGNATURE_BYTES)
            sig_len = ctypes.pointer(ctypes.c_size_t(pb.DILITHIUM_SIGNATURE_BYTES))
            assert ctx.sign(b"regression", sk.raw, sig, sig_len) == 0
            assert sig_len.contents.value == pb.DILITHIUM_SIGNATURE_BYTES
            assert ctx.verify(
                b"regression",
                sig.raw[: sig_len.contents.value],
                pk.raw[: pb.DILITHIUM_PUBLIC_KEY_BYTES],
            )

    # -- kem_encapsulate ----------------------------------------------------

    def test_kem_encapsulate_refuses_an_oversized_ciphertext_declaration(self) -> None:
        self._skip_without_context_api()
        with pb.AmaContext(pb.AmaContext.ALG_KYBER_1024) as ctx:
            pk, _sk = self._kyber_keypair(ctx)
            ct = ctypes.create_string_buffer(8)
            ct_len = ctypes.pointer(ctypes.c_size_t(pb.KYBER_CIPHERTEXT_BYTES))
            ss = ctypes.create_string_buffer(pb.KYBER_SHARED_SECRET_BYTES)
            assert ctx.kem_encapsulate(pk, ct, ct_len, ss, pb.KYBER_SHARED_SECRET_BYTES) == -1

    def test_kem_encapsulate_refuses_an_oversized_shared_secret_declaration(self) -> None:
        """The second output buffer is checked too: a caller who gets one
        right and the other wrong is the shape that produced the defect."""
        self._skip_without_context_api()
        with pb.AmaContext(pb.AmaContext.ALG_KYBER_1024) as ctx:
            pk, _sk = self._kyber_keypair(ctx)
            ct = ctypes.create_string_buffer(pb.KYBER_CIPHERTEXT_BYTES)
            ct_len = ctypes.pointer(ctypes.c_size_t(pb.KYBER_CIPHERTEXT_BYTES))
            ss = ctypes.create_string_buffer(1)
            assert ctx.kem_encapsulate(pk, ct, ct_len, ss, pb.KYBER_SHARED_SECRET_BYTES) == -1

    def test_kem_encapsulate_refuses_read_only_output_buffers(self) -> None:
        self._skip_without_context_api()
        with pb.AmaContext(pb.AmaContext.ALG_KYBER_1024) as ctx:
            pk, _sk = self._kyber_keypair(ctx)
            ct_len = ctypes.pointer(ctypes.c_size_t(pb.KYBER_CIPHERTEXT_BYTES))
            frozen_ct = self._frozen(pb.KYBER_CIPHERTEXT_BYTES)
            ss = ctypes.create_string_buffer(pb.KYBER_SHARED_SECRET_BYTES)
            assert (
                ctx.kem_encapsulate(pk, frozen_ct, ct_len, ss, pb.KYBER_SHARED_SECRET_BYTES) == -1
            )
            ct = ctypes.create_string_buffer(pb.KYBER_CIPHERTEXT_BYTES)
            frozen_ss = self._frozen(pb.KYBER_SHARED_SECRET_BYTES)
            assert (
                ctx.kem_encapsulate(pk, ct, ct_len, frozen_ss, pb.KYBER_SHARED_SECRET_BYTES) == -1
            )

    # -- kem_decapsulate ----------------------------------------------------

    def test_kem_decapsulate_refuses_an_oversized_shared_secret_declaration(self) -> None:
        """Here the declared length is a by-value ``size_t`` rather than an
        in/out pointer — the third spelling ``_declared_out_len`` resolves."""
        self._skip_without_context_api()
        with pb.AmaContext(pb.AmaContext.ALG_KYBER_1024) as ctx:
            pk, sk = self._kyber_keypair(ctx)
            ct, _ss = self._encapsulate(ctx, pk)
            small = ctypes.create_string_buffer(1)
            assert ctx.kem_decapsulate(ct, sk, small, pb.KYBER_SHARED_SECRET_BYTES) == -1

    def test_kem_decapsulate_refuses_a_read_only_output_buffer(self) -> None:
        self._skip_without_context_api()
        with pb.AmaContext(pb.AmaContext.ALG_KYBER_1024) as ctx:
            pk, sk = self._kyber_keypair(ctx)
            ct, _ss = self._encapsulate(ctx, pk)
            frozen = self._frozen(pb.KYBER_SHARED_SECRET_BYTES)
            assert ctx.kem_decapsulate(ct, sk, frozen, pb.KYBER_SHARED_SECRET_BYTES) == -1

    def test_the_kem_round_trip_still_agrees(self) -> None:
        """Positive control for both KEM methods at once."""
        self._skip_without_context_api()
        with pb.AmaContext(pb.AmaContext.ALG_KYBER_1024) as ctx:
            pk, sk = self._kyber_keypair(ctx)
            ct, ss_enc = self._encapsulate(ctx, pk)
            ss_dec = ctypes.create_string_buffer(pb.KYBER_SHARED_SECRET_BYTES)
            assert ctx.kem_decapsulate(ct, sk, ss_dec, pb.KYBER_SHARED_SECRET_BYTES) == 0
            assert ss_dec.raw[: pb.KYBER_SHARED_SECRET_BYTES] == ss_enc

    # -- keypair_generate ---------------------------------------------------

    def test_keypair_generate_refuses_read_only_key_buffers(self) -> None:
        """The undersized direction was already covered; the immutable one
        was not, and it reaches further: an immutable ``bytes`` passes the
        capacity check, so the pairwise consistency test then ran against a
        buffer the native side could not have written."""
        self._skip_without_context_api()
        with pb.AmaContext(pb.AmaContext.ALG_ED25519) as ctx:
            frozen_pk = self._frozen(pb.ED25519_PUBLIC_KEY_BYTES)
            sk = ctypes.create_string_buffer(pb.ED25519_SECRET_KEY_BYTES)
            assert (
                ctx.keypair_generate(
                    frozen_pk,
                    pb.ED25519_PUBLIC_KEY_BYTES,
                    sk,
                    pb.ED25519_SECRET_KEY_BYTES,
                )
                == -1
            )
            pk = ctypes.create_string_buffer(pb.ED25519_PUBLIC_KEY_BYTES)
            frozen_sk = self._frozen(pb.ED25519_SECRET_KEY_BYTES)
            assert (
                ctx.keypair_generate(
                    pk,
                    pb.ED25519_PUBLIC_KEY_BYTES,
                    frozen_sk,
                    pb.ED25519_SECRET_KEY_BYTES,
                )
                == -1
            )

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _frozen(size: int) -> ctypes.Array[ctypes.c_char]:
        """An immutable ``bytes`` of ``size``, typed as an output buffer.

        ``AmaContext`` annotates these parameters as ``ctypes`` arrays.  An
        annotation is a promise, not a mechanism: ``ctypes`` marshals a
        ``bytes`` through the same ``c_char_p`` parameter without complaint,
        so at run time the guard is the only thing between a mistaken caller
        and C writing through an object CPython guarantees is immutable.
        Testing the guard therefore means passing exactly what the annotation
        forbids — laundered once here, with the reason stated, rather than
        with six suppressions scattered over the call sites (PCT-002).
        """
        return cast("ctypes.Array[ctypes.c_char]", b"\x00" * size)

    @staticmethod
    def _kyber_keypair(ctx: Any) -> tuple[bytes, bytes]:
        pk = ctypes.create_string_buffer(pb.KYBER_PUBLIC_KEY_BYTES)
        sk = ctypes.create_string_buffer(pb.KYBER_SECRET_KEY_BYTES)
        assert (
            ctx.keypair_generate(pk, pb.KYBER_PUBLIC_KEY_BYTES, sk, pb.KYBER_SECRET_KEY_BYTES) == 0
        )
        return pk.raw[: pb.KYBER_PUBLIC_KEY_BYTES], sk.raw[: pb.KYBER_SECRET_KEY_BYTES]

    @staticmethod
    def _encapsulate(ctx: Any, public_key: bytes) -> tuple[bytes, bytes]:
        ct = ctypes.create_string_buffer(pb.KYBER_CIPHERTEXT_BYTES)
        ct_len = ctypes.pointer(ctypes.c_size_t(pb.KYBER_CIPHERTEXT_BYTES))
        ss = ctypes.create_string_buffer(pb.KYBER_SHARED_SECRET_BYTES)
        assert ctx.kem_encapsulate(public_key, ct, ct_len, ss, pb.KYBER_SHARED_SECRET_BYTES) == 0
        return (
            ct.raw[: ct_len.contents.value],
            ss.raw[: pb.KYBER_SHARED_SECRET_BYTES],
        )


# ---------------------------------------------------------------------------
# The helpers the guard is built from, pinned on their own.
# ---------------------------------------------------------------------------


class TestOutputBufferHelpers:
    """``_declared_out_len`` and ``_out_buffer_is_writable`` decide every
    refusal above, including the two cases where they deliberately decline to
    refuse.  Those two are the ones most likely to be "tidied" by a later
    reader, so they are stated here rather than left implicit."""

    def test_declared_out_len_resolves_all_three_spellings(self) -> None:
        assert pb._declared_out_len(3309) == 3309
        assert pb._declared_out_len(ctypes.c_size_t(3309)) == 3309
        assert pb._declared_out_len(ctypes.pointer(ctypes.c_size_t(3309))) == 3309

    def test_declared_out_len_rejects_a_bool(self) -> None:
        """``bool`` is an ``int`` subclass; ``True`` must not read as 1."""
        assert pb._declared_out_len(True) is None
        assert pb._declared_out_len(False) is None

    def test_declared_out_len_gives_up_on_byref(self) -> None:
        """``byref`` returns a ``CArgObject``, which exposes nothing.  The
        guard treats an unreadable declaration as "nothing to compare"
        rather than as a refusal — refusing a spelling the C ABI accepts
        would break working callers to close a hazard it cannot see."""
        assert pb._declared_out_len(ctypes.byref(ctypes.c_size_t(3309))) is None

    def test_writability_distinguishes_the_buffer_kinds(self) -> None:
        assert pb._out_buffer_is_writable(ctypes.create_string_buffer(16)) is True
        assert pb._out_buffer_is_writable(bytearray(16)) is True
        assert pb._out_buffer_is_writable(b"\x00" * 16) is False
        assert pb._out_buffer_is_writable(memoryview(b"\x00" * 16)) is False

    def test_capacity_is_read_from_arrays_and_buffers_only(self) -> None:
        assert pb._output_buffer_capacity(ctypes.create_string_buffer(16)) == 16
        assert pb._output_buffer_capacity((ctypes.c_ubyte * 16)()) == 16
        assert pb._output_buffer_capacity(bytearray(16)) == 16
        assert pb._output_buffer_capacity(b"\x00" * 16) == 16
        assert pb._output_buffer_capacity(None) is None

    def test_a_pointer_is_left_to_the_callers_contract(self) -> None:
        """``ctypes.cast(buf, c_char_p)`` is a legitimate spelling for a
        buffer of ANY size, and the pointer hides that size completely.

        ``ctypes.sizeof`` answers 8 for it — the width of the pointer, not of
        the buffer — so a capacity check built on ``sizeof`` alone would
        refuse every such caller while proving nothing.  Refusing a spelling
        the C ABI accepts would be a breaking change dressed up as a
        hardening, so the pointer passes through and ``ama_sign``'s own NULL
        and length checks in ``src/c/ama_core.c`` remain its only contract.
        """
        big = ctypes.create_string_buffer(pb.DILITHIUM_SIGNATURE_BYTES)
        pointer = ctypes.cast(big, ctypes.c_char_p)
        assert ctypes.sizeof(pointer) == ctypes.sizeof(ctypes.c_void_p)
        assert pb._output_buffer_capacity(pointer) is None
        assert pb._declared_length_fits(pointer, pb.DILITHIUM_SIGNATURE_BYTES) is True
        assert pb._out_buffer_is_writable(pointer) is True


# ---------------------------------------------------------------------------
# The Cython bindings are keygen surfaces too.
# ---------------------------------------------------------------------------


def _binding(name: str) -> Any:
    module = None
    try:
        module = importlib.import_module(f"ama_cryptography.{name}")
    except ImportError:
        pytest.skip(f"native {name} binding is not built in this environment")
    return module


class TestCythonBindingKeygens:
    """``cy_dilithium_keygen`` and ``cy_ed25519_keypair`` are importable,
    ``check_crypto_permitted``-gated keygen entry points of the package, and
    released keypairs with no pairwise test until 2026-09-24 (found by the
    partitioned review of PR #394).  They now run the same helper as
    ``pqc_backends``: wired, failing closed, and passing on real keys."""

    CASES = (
        ("dilithium_binding", "cy_dilithium_verify", lambda b: b.cy_dilithium_keygen()),
        ("ed25519_binding", "cy_ed25519_verify", lambda b: b.cy_ed25519_keypair(bytes(32))),
    )

    @pytest.mark.parametrize(("module", "_verify", "keygen"), CASES)
    def test_the_keygen_invokes_the_pairwise_helper(
        self, monkeypatch: pytest.MonkeyPatch, module: str, _verify: str, keygen: Any
    ) -> None:
        binding = _binding(module)
        seen: list[str] = []

        def recorder(sign: Any, verify: Any, sk: Any, pk: Any, algo: str) -> None:
            seen.append(algo)
            ms.pairwise_test_signature(sign, verify, sk, pk, algo)

        monkeypatch.setattr(binding, "pairwise_test_signature", recorder)
        public_key, secret_key = keygen(binding)
        assert len(seen) == 1 and module in seen[0]
        assert public_key and secret_key

    @pytest.mark.parametrize(("module", "verify", "keygen"), CASES)
    def test_a_failing_pairwise_test_enters_the_error_state(
        self, monkeypatch: pytest.MonkeyPatch, module: str, verify: str, keygen: Any
    ) -> None:
        binding = _binding(module)
        monkeypatch.setattr(binding, verify, lambda sig, msg, pk: False)
        try:
            with pytest.raises(CryptoModuleError, match="Pairwise test failed"):
                keygen(binding)
            assert ms.module_status() == "ERROR"
        finally:
            ms._set_operational()
