# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Trust-anchor pinning for package verification and the Noise-NK handshake.

Both APIs previously verified a signature against a public key that travelled
inside the very message being checked, so the check proved self-consistency
rather than origin: an adversary could mint a keypair, sign content of their
choosing, and produce an artefact that verified.  These tests pin the fix:

  * ``verify_crypto_package`` accepts an out-of-band ``expected_public_key``,
    compares it in constant time, fails closed on mismatch, and publishes
    which mode ran via the ``key_pinned`` result key (INVARIANT-37 — the
    boundary is data, not prose).
  * ``SecureChannelInitiator`` accepts ``expected_responder_sig_pk`` and
    rejects a handshake response carrying any other signature key.

The unpinned paths are asserted to keep their previous behaviour so the fix
stays backwards compatible.
"""

from __future__ import annotations

import os

import pytest

from ama_cryptography.crypto_api import (
    HybridKEMProvider,
    HybridSignatureProvider,
    KeyPair,
    create_crypto_package,
    verify_crypto_package,
)
from ama_cryptography.secure_channel import (
    HandshakeError,
    HandshakeResponse,
    SecureChannelInitiator,
    SecureChannelResponder,
)

CONTENT = b"transfer 100 units to alice"
FORGED_CONTENT = b"transfer 1000000 units to attacker"


class TestCryptoPackagePinning:
    """``verify_crypto_package`` trust anchor."""

    def test_unpinned_is_self_consistent_but_not_valid(self) -> None:
        """Without an anchor the layers agree, but all_valid is False (4.0).

        core_valid keeps the old meaning -- "these parts agree with each
        other" -- and is the migration path for callers that only ever wanted
        an integrity check.
        """
        pkg = create_crypto_package(CONTENT)
        results = verify_crypto_package(CONTENT, pkg)

        assert results["core_valid"] is True
        # The honesty signal: no origin was established...
        assert results["key_pinned"] is False
        # ...and that now costs the aggregate, rather than being a footnote.
        assert results["all_valid"] is False

    def test_pinned_with_correct_key_verifies_and_reports_pinned(self) -> None:
        pkg = create_crypto_package(CONTENT)
        pk = pkg.keypairs["HYBRID_SIG"].public_key

        results = verify_crypto_package(CONTENT, pkg, expected_public_key=pk)

        assert results["all_valid"] is True
        assert results["primary_signature"] is True
        assert results["key_pinned"] is True

    def test_forged_package_is_rejected_when_pinned(self) -> None:
        """The core regression: a self-signed forgery must not pass a pinned check.

        The attacker never sees the victim's secret key.  They simply call the
        same public API with their own freshly generated keypair, which is what
        made the unpinned check meaningless.
        """
        victim = create_crypto_package(CONTENT)
        victim_pk = victim.keypairs["HYBRID_SIG"].public_key

        forged = create_crypto_package(FORGED_CONTENT)

        # Unpinned: internally consistent, so the layers agree — but since
        # 4.0 that alone is not "valid", precisely because this forgery is
        # indistinguishable from a genuine package at this level.
        unpinned = verify_crypto_package(FORGED_CONTENT, forged)
        assert unpinned["core_valid"] is True
        assert unpinned["key_pinned"] is False
        assert unpinned["all_valid"] is False

        # Pinned against the victim's real key: fails closed.
        pinned = verify_crypto_package(FORGED_CONTENT, forged, expected_public_key=victim_pk)
        assert pinned["key_pinned"] is False
        assert pinned["primary_signature"] is False
        assert pinned["all_valid"] is False
        assert pinned["core_valid"] is False

    def test_mismatched_anchor_does_not_leak_via_other_layers(self) -> None:
        """A pinned mismatch must not be masked by the self-referential layers."""
        victim_pk = create_crypto_package(CONTENT).keypairs["HYBRID_SIG"].public_key
        forged = create_crypto_package(FORGED_CONTENT)

        results = verify_crypto_package(FORGED_CONTENT, forged, expected_public_key=victim_pk)

        # Layers 1/2/4 still pass — they are integrity checks over the
        # attacker's own material — which is exactly why all_valid alone
        # cannot be an authenticity claim.
        assert results["content_hash"] is True
        assert results["hmac"] is True
        assert results["hkdf_keys"] is True
        # But the aggregate is False because Layer 3 failed closed.
        assert results["all_valid"] is False

    def test_truncated_or_empty_anchor_is_rejected(self) -> None:
        pkg = create_crypto_package(CONTENT)
        pk = pkg.keypairs["HYBRID_SIG"].public_key

        for bad in (b"", pk[:-1], pk[:16], bytes(len(pk))):
            results = verify_crypto_package(CONTENT, pkg, expected_public_key=bad)
            assert results["key_pinned"] is False
            assert results["primary_signature"] is False
            assert results["all_valid"] is False

    def test_key_pinned_gates_all_valid_but_not_core_valid(self) -> None:
        """key_pinned is aggregated into all_valid, and only into all_valid.

        The 4.0 split: all_valid is an origin claim and needs the anchor;
        core_valid is the Layer 1-4 self-consistency result and does not.
        Pinning must move the first and leave the second alone, so a caller
        migrating from 3.x has somewhere accurate to go.
        """
        pkg = create_crypto_package(CONTENT)
        pk = pkg.keypairs["HYBRID_SIG"].public_key

        unpinned = verify_crypto_package(CONTENT, pkg)
        pinned = verify_crypto_package(CONTENT, pkg, expected_public_key=pk)

        # Only the anchor differs between the two calls.
        assert unpinned["key_pinned"] is False
        assert pinned["key_pinned"] is True

        assert unpinned["all_valid"] is False
        assert pinned["all_valid"] is True

        # core_valid is identical either way — the layers did the same work.
        assert unpinned["core_valid"] is True
        assert pinned["core_valid"] is True


class TestSecureChannelPinning:
    """``SecureChannelInitiator`` responder-signature-key pinning."""

    @staticmethod
    def _responder_keys() -> tuple[KeyPair, KeyPair]:
        kem = HybridKEMProvider().generate_keypair()
        sig = HybridSignatureProvider().generate_keypair()
        return kem, sig

    def test_pinned_handshake_succeeds_end_to_end(self) -> None:
        kem, sig = self._responder_keys()

        initiator = SecureChannelInitiator(kem.public_key, expected_responder_sig_pk=sig.public_key)
        handshake = initiator.create_handshake()

        responder = SecureChannelResponder(kem.secret_key, sig.secret_key, sig.public_key)
        response, server_session = responder.handle_handshake(handshake)
        client_session = initiator.complete_handshake(response)

        message = client_session.encrypt(b"ping")
        assert server_session.decrypt(message) == b"ping"

    def test_attacker_signature_key_is_rejected_when_pinned(self) -> None:
        """The core regression: an arbitrary signing key must not authenticate."""
        kem, sig = self._responder_keys()

        initiator = SecureChannelInitiator(kem.public_key, expected_responder_sig_pk=sig.public_key)
        # Establishes the transcript hash the attacker will sign over.
        initiator.create_handshake()

        # Attacker signs the real transcript with a key of their own.
        sig_provider = HybridSignatureProvider()
        attacker = sig_provider.generate_keypair()
        session_id = os.urandom(32)
        handshake_hash = initiator._handshake_hash
        assert handshake_hash is not None, "create_handshake must set the transcript hash"
        transcript = handshake_hash + session_id
        forged_sig = sig_provider.sign(transcript, attacker.secret_key)

        response = HandshakeResponse(
            session_id=session_id,
            signature=forged_sig.signature,
            responder_public_key=attacker.public_key,
        )

        with pytest.raises(HandshakeError, match="pinned key"):
            initiator.complete_handshake(response)

    def test_unpinned_initiator_keeps_previous_behaviour(self) -> None:
        """Backwards compatibility: omitting the pin must not change behaviour."""
        kem, sig = self._responder_keys()

        initiator = SecureChannelInitiator(kem.public_key)
        handshake = initiator.create_handshake()
        responder = SecureChannelResponder(kem.secret_key, sig.secret_key, sig.public_key)
        response, _ = responder.handle_handshake(handshake)

        session = initiator.complete_handshake(response)
        assert len(session.session_id) == 32

    def test_pinning_rejects_before_signature_check(self) -> None:
        """A wrong pinned key fails even when the signature itself is well-formed."""
        kem, sig = self._responder_keys()
        other = HybridSignatureProvider().generate_keypair()

        initiator = SecureChannelInitiator(
            kem.public_key, expected_responder_sig_pk=other.public_key
        )
        handshake = initiator.create_handshake()
        responder = SecureChannelResponder(kem.secret_key, sig.secret_key, sig.public_key)
        response, _ = responder.handle_handshake(handshake)

        with pytest.raises(HandshakeError, match="pinned key"):
            initiator.complete_handshake(response)


class TestAnchoredBuildRefusesDigestOnlyFallback:
    """A compiled trust anchor must close the unsigned fallback.

    The signed path already refuses a signature made under the wrong key, so
    an attacker cannot re-sign edited ``.py`` files with a key of their own.
    They never had to: deleting ``_integrity_signature.py`` dropped control
    into the digest-only fallback, where ``_integrity_digest.txt`` is
    plaintext with no signature at all. Rewriting that one line got modified
    code accepted on a build carrying an anchor — forging the signature was
    hard, removing it was not, and removal reached the same place.

    The guard that was supposed to stop this tested
    ``AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR``, a *build-time* variable that is
    gone by the time anyone imports the installed wheel. The compiled anchor
    is the part of that intent that survives into the shipped ``.so``.
    """

    ANCHOR = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

    def _run(
        self, monkeypatch: pytest.MonkeyPatch, anchor: tuple[str | None, str | None]
    ) -> tuple[bool, str]:
        from ama_cryptography import _self_test

        # Force the "signature artefact absent" branch without touching the
        # installed tree, then vary only whether a build anchor is present.
        monkeypatch.setattr(
            _self_test,
            "_verify_signed_integrity",
            lambda digest_hex: (None, "no signed-integrity artefact (digest-only fallback)"),
        )
        monkeypatch.setattr(_self_test, "_load_integrity_trust_anchor", lambda: anchor)
        monkeypatch.delenv("AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR", raising=False)
        return _self_test.verify_module_integrity()

    def test_anchored_build_refuses_a_missing_signature(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ok, detail = self._run(monkeypatch, (self.ANCHOR, None))
        assert ok is False
        assert "compiled trust anchor" in detail

    def test_unanchored_build_keeps_the_documented_fallback(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Non-vacuity control: without an anchor the same inputs still pass.

        Without this, a check that simply refused everything would satisfy the
        assertion above.
        """
        ok, detail = self._run(monkeypatch, (None, None))
        assert ok is True
        assert "digest-only fallback" in detail

    def test_unresolvable_anchor_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """If we cannot tell whether the build is anchored, do not assume it is not."""
        ok, detail = self._run(monkeypatch, (None, "native trust-anchor lookup failed: boom"))
        assert ok is False
        assert "trust-anchor lookup failed" in detail

    def test_anchored_build_refuses_an_unverifiable_signature(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The second route into the same refusal: present artefact, absent verifier.

        ``_verify_signed_integrity`` returns ``None`` both when the artefact is
        missing and when the Ed25519 verifier could not run — the two ways of
        failing to check rather than checking and failing.  The second is newer
        and is the one the reported build hit, so it needs its own coverage
        here: an anchored build must refuse it exactly as it refuses a missing
        artefact, or a native library that failed to load becomes a way to skip
        the anchor.
        """
        from ama_cryptography import _self_test

        monkeypatch.setattr(
            _self_test,
            "_verify_signed_integrity",
            lambda digest_hex: (
                None,
                "Ed25519 verifier unavailable — cannot check the signed-integrity artefact.",
            ),
        )
        monkeypatch.setattr(
            _self_test, "_load_integrity_trust_anchor", lambda: (self.ANCHOR, None)
        )
        monkeypatch.delenv("AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR", raising=False)

        ok, detail = _self_test.verify_module_integrity()
        assert ok is False, "an anchored build accepted an unverifiable artefact"
        assert "compiled trust anchor" in detail
        # The refusal must carry the reason it could not verify, or the
        # operator is told only that something is wrong.
        assert "verifier unavailable" in detail
