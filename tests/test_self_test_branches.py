#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Branch-coverage additions for ``ama_cryptography._self_test``.

Focuses on KAT failure paths (both within individual KATs and inside
``_run_self_tests``), timing-oracle negative outcomes, and the RNG
health check — all of which are exceedingly hard to trigger "for real"
and are therefore covered via monkeypatching the algorithms the KATs
depend on.
"""

from __future__ import annotations

import pytest

from ama_cryptography import _self_test as st


# ---------------------------------------------------------------------------
# KAT failure branches
# ---------------------------------------------------------------------------


class TestKatFailureBranches:
    def test_kat_sha3_256_returns_false_on_wrong_digest(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If hashlib.sha3_256 yields the wrong digest, KAT reports failure."""

        class _FakeDigest:
            @staticmethod
            def hexdigest() -> str:
                return "00" * 32

        def _fake_sha3_256(_data: bytes) -> _FakeDigest:
            return _FakeDigest()

        monkeypatch.setattr(st.hashlib, "sha3_256", _fake_sha3_256)
        passed, detail = st._kat_sha3_256()
        assert passed is False
        assert "fail" in detail.lower() or "got" in detail.lower()

    def test_kat_hmac_sha3_256_wrong_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Wrong HMAC output triggers the mismatch branch."""
        from ama_cryptography import pqc_backends as pq

        if not pq._HMAC_SHA3_256_NATIVE_AVAILABLE:
            pytest.skip("HMAC-SHA3-256 native backend not built")

        monkeypatch.setattr(pq, "native_hmac_sha3_256", lambda key, data: b"\x00" * 32)
        passed, detail = st._kat_hmac_sha3_256()
        assert passed is False
        assert "KAT" in detail

    def test_kat_hmac_sha3_256_exception_branch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ama_cryptography import pqc_backends as pq

        if not pq._HMAC_SHA3_256_NATIVE_AVAILABLE:
            pytest.skip("HMAC-SHA3-256 native backend not built")

        def _boom(_k: bytes, _d: bytes) -> bytes:
            raise RuntimeError("simulated native failure")

        monkeypatch.setattr(pq, "native_hmac_sha3_256", _boom)
        passed, detail = st._kat_hmac_sha3_256()
        assert passed is False
        assert "exception" in detail.lower()

    def test_kat_aes_256_gcm_ciphertext_mismatch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ama_cryptography import pqc_backends as pq

        if not pq._AES_GCM_NATIVE_AVAILABLE:
            pytest.skip("AES-256-GCM native backend not built")

        def _fake_enc(*args: object, **kwargs: object) -> tuple:
            return b"\x00" * 64, b"\x00" * 16  # wrong ct and tag

        monkeypatch.setattr(pq, "native_aes256_gcm_encrypt", _fake_enc)
        passed, detail = st._kat_aes_256_gcm()
        assert passed is False
        assert "ciphertext" in detail.lower() or "tag" in detail.lower()

    def test_kat_aes_256_gcm_exception_branch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ama_cryptography import pqc_backends as pq

        if not pq._AES_GCM_NATIVE_AVAILABLE:
            pytest.skip("AES-256-GCM native backend not built")

        def _boom(*args: object, **kwargs: object) -> tuple:
            raise RuntimeError("simulated encrypt failure")

        monkeypatch.setattr(pq, "native_aes256_gcm_encrypt", _boom)
        passed, detail = st._kat_aes_256_gcm()
        assert passed is False
        assert "exception" in detail.lower()

    def test_kat_ml_kem_1024_mismatch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from ama_cryptography import pqc_backends as pq

        if not pq.KYBER_AVAILABLE:
            pytest.skip("Kyber backend unavailable")

        monkeypatch.setattr(pq, "kyber_decapsulate", lambda ct, sk: b"\x00" * 32)
        passed, detail = st._kat_ml_kem_1024()
        assert passed is False
        assert "mismatch" in detail.lower()

    def test_kat_ml_dsa_65_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from ama_cryptography import pqc_backends as pq

        if not pq.DILITHIUM_AVAILABLE:
            pytest.skip("Dilithium backend unavailable")

        def _boom(*args: object, **kwargs: object) -> bytes:
            raise RuntimeError("simulated sign failure")

        monkeypatch.setattr(pq, "dilithium_sign", _boom)
        passed, detail = st._kat_ml_dsa_65()
        assert passed is False
        assert "exception" in detail.lower()


# ---------------------------------------------------------------------------
# Integrity branches
# ---------------------------------------------------------------------------


class TestIntegrityBranches:
    def test_update_integrity_then_verify_passes(self) -> None:
        st.update_integrity_digest()
        passed, _ = st.verify_module_integrity()
        assert passed is True


# ---------------------------------------------------------------------------
# _run_self_tests error branches
# ---------------------------------------------------------------------------


class TestRunSelfTestsFailures:
    def test_integrity_failure_short_circuits(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A failing integrity check sets ERROR and aborts without running KATs."""
        from ama_cryptography._self_test import (
            _run_self_tests,
            _set_operational,
            module_status,
        )

        monkeypatch.setattr(
            "ama_cryptography._self_test.verify_module_integrity",
            lambda: (False, "synthetic integrity failure"),
        )
        try:
            assert _run_self_tests() is False
            assert module_status() == "ERROR"
        finally:
            # Restore good state so later tests see OPERATIONAL module.
            st.update_integrity_digest()
            _set_operational()

    def test_integrity_exception_short_circuits(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ama_cryptography._self_test import (
            _run_self_tests,
            _set_operational,
            module_status,
        )

        def _boom() -> tuple:
            raise RuntimeError("simulated integrity exception")

        monkeypatch.setattr(
            "ama_cryptography._self_test.verify_module_integrity", _boom
        )
        try:
            assert _run_self_tests() is False
            assert module_status() == "ERROR"
        finally:
            st.update_integrity_digest()
            _set_operational()

    def test_kat_exception_sets_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from ama_cryptography._self_test import (
            _run_self_tests,
            _set_operational,
            module_status,
        )

        # Force the first KAT to raise; the runner must treat this as failure.
        def _boom() -> tuple:
            raise RuntimeError("KAT exploded")

        monkeypatch.setattr("ama_cryptography._self_test._kat_sha3_256", _boom)
        try:
            assert _run_self_tests() is False
            assert module_status() == "ERROR"
        finally:
            st.update_integrity_digest()
            _set_operational()

    def test_kat_soft_failure_sets_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ama_cryptography._self_test import (
            _run_self_tests,
            _set_operational,
            module_status,
        )

        monkeypatch.setattr(
            "ama_cryptography._self_test._kat_sha3_256",
            lambda: (False, "synthetic soft failure"),
        )
        try:
            assert _run_self_tests() is False
            assert module_status() == "ERROR"
        finally:
            st.update_integrity_digest()
            _set_operational()

    def test_rng_identical_outputs_fails(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two identical consecutive RNG draws must fail the runner."""
        from ama_cryptography._self_test import (
            _run_self_tests,
            _set_operational,
            module_status,
        )

        counter = {"n": 0}
        fixed = b"\xaa" * 32

        def _fake_token(n: int) -> bytes:
            counter["n"] += 1
            return fixed[:n]

        monkeypatch.setattr("ama_cryptography._self_test.secrets.token_bytes", _fake_token)
        try:
            assert _run_self_tests() is False
            assert module_status() == "ERROR"
        finally:
            st.update_integrity_digest()
            _set_operational()

    def test_rng_exception_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from ama_cryptography._self_test import (
            _run_self_tests,
            _set_operational,
            module_status,
        )

        def _boom(_n: int) -> bytes:
            raise RuntimeError("simulated RNG failure")

        monkeypatch.setattr("ama_cryptography._self_test.secrets.token_bytes", _boom)
        try:
            assert _run_self_tests() is False
            assert module_status() == "ERROR"
        finally:
            st.update_integrity_digest()
            _set_operational()


# ---------------------------------------------------------------------------
# Accessors
# ---------------------------------------------------------------------------


class TestAccessors:
    def test_module_self_test_results_defensive_copy(self) -> None:
        first = st.module_self_test_results()
        first.append(("probe", True, "mutation should not affect module state"))
        second = st.module_self_test_results()
        assert ("probe", True, "mutation should not affect module state") not in second

    def test_post_duration_is_non_negative(self) -> None:
        assert st.post_duration_ms() >= 0.0
