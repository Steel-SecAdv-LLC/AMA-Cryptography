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
        monkeypatch.setattr(_self_test, "_load_integrity_trust_anchor", lambda: (self.ANCHOR, None))
        monkeypatch.delenv("AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR", raising=False)

        ok, detail = _self_test.verify_module_integrity()
        assert ok is False, "an anchored build accepted an unverifiable artefact"
        assert "compiled trust anchor" in detail
        # The refusal must carry the reason it could not verify, or the
        # operator is told only that something is wrong.
        assert "verifier unavailable" in detail


class TestSignerProcessAnchoredClassification:
    """The one legitimate holder of an anchored, artefact-less tree.

    ``tools/resign_wheel.py`` deletes the stale pre-repair artefact and then
    launches ``python -m ama_cryptography._build_sign`` inside the unpacked
    wheel — so the signer subprocess imports an anchored tree with no
    artefact, which is byte-for-byte the state the anchored refusal above
    calls tampering.  The first exercised release dry run failed exactly
    there on both Linux cibuildwheel jobs while macOS and Windows (no
    re-sign chain) passed.

    The rule these tests pin: the stage FAILS either way; only the
    *classification* differs.  A signer-identified process records a stale
    binding, which is what lets ``__init__``'s ``AMA_BUILD_PIPELINE`` escape
    complete the import in the ERROR state.  Everyone else keeps the
    tampering verdict, and a positively invalid signature stays tampering
    even for the signer — re-signing over a bad signature would launder it.
    """

    ANCHOR = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

    def _run_anchored_missing_artefact(
        self, monkeypatch: pytest.MonkeyPatch, *, signer: bool
    ) -> tuple[bool, str]:
        from ama_cryptography import _self_test

        monkeypatch.setattr(_self_test, "_INTEGRITY_FAILURE_KIND", None)
        monkeypatch.setattr(
            _self_test,
            "_verify_signed_integrity",
            lambda digest_hex: (None, "no signed-integrity artefact (digest-only fallback)"),
        )
        monkeypatch.setattr(_self_test, "_load_integrity_trust_anchor", lambda: (self.ANCHOR, None))
        monkeypatch.setattr(_self_test, "_integrity_signer_process", lambda: signer)
        monkeypatch.delenv("AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR", raising=False)
        return _self_test.verify_module_integrity()

    def test_signer_process_fails_repairably_not_as_tampering(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ama_cryptography import _self_test

        ok, detail = self._run_anchored_missing_artefact(monkeypatch, signer=True)
        assert ok is False, "the stage must FAIL for the signer too - only the class changes"
        assert "integrity signer" in detail
        assert _self_test.integrity_failure_was_stale_binding(), (
            "the signer's anchored missing-artefact failure must classify as a stale "
            "binding so the AMA_BUILD_PIPELINE import escape can admit the signing run"
        )

    def test_non_signer_process_keeps_the_tampering_verdict(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ama_cryptography import _self_test

        ok, detail = self._run_anchored_missing_artefact(monkeypatch, signer=False)
        assert ok is False
        assert "compiled trust anchor" in detail
        assert not _self_test.integrity_failure_was_stale_binding(), (
            "a non-signer process holding an anchored artefact-less tree is the "
            "attack this branch exists to stop; it must classify as tampering"
        )

    def test_invalid_signature_is_tampering_even_for_the_signer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A present-but-wrong artefact never reaches the signer carve-out."""
        from ama_cryptography import _self_test

        monkeypatch.setattr(_self_test, "_INTEGRITY_FAILURE_KIND", None)
        monkeypatch.setattr(
            _self_test,
            "_verify_signed_integrity",
            lambda digest_hex: (False, "Ed25519 signature did NOT verify - module tampered"),
        )
        monkeypatch.setattr(_self_test, "_load_integrity_trust_anchor", lambda: (self.ANCHOR, None))
        monkeypatch.setattr(_self_test, "_integrity_signer_process", lambda: True)
        monkeypatch.delenv("AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR", raising=False)

        ok, detail = _self_test.verify_module_integrity()
        assert ok is False
        assert "did NOT verify" in detail
        assert not _self_test.integrity_failure_was_stale_binding(), (
            "re-signing over an invalid signature would launder it; the signer "
            "identity must not soften a positive tampering verdict"
        )


class TestSignerIdentityRunpyWindow:
    """``_process_is_the_integrity_signer`` during runpy's parent import.

    ``python -m ama_cryptography._build_sign`` imports this package before
    runpy binds the target module into ``__main__``, so during POST the
    ``__main__.__spec__`` check cannot identify anyone.  ``sys.orig_argv``
    — the interpreter's immutable record of its own command line — covers
    that window.  These pin the recognised spellings and, more importantly,
    the shapes that must NOT be recognised.
    """

    def _identity(
        self,
        monkeypatch: pytest.MonkeyPatch,
        argv: list[str],
        *,
        env: str | None = "1",
    ) -> bool:
        import sys

        from ama_cryptography import pqc_backends

        if env is None:
            monkeypatch.delenv("AMA_BUILD_PIPELINE", raising=False)
        else:
            monkeypatch.setenv("AMA_BUILD_PIPELINE", env)
        monkeypatch.setattr(sys, "orig_argv", argv)
        return pqc_backends._process_is_the_integrity_signer()

    def test_dash_m_separate_token_is_recognised(self, monkeypatch: pytest.MonkeyPatch) -> None:
        argv = ["/usr/bin/python3", "-m", "ama_cryptography._build_sign", "--package-dir", "x"]
        assert self._identity(monkeypatch, argv) is True

    def test_dash_m_concatenated_form_is_recognised(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``-mmod`` must parse exactly as ``-m mod`` — in BOTH directions.

        This test previously asserted that ``-mama_cryptography.integrity
        --verify`` conferred signer identity, which encoded the fail-open
        that identity alone answered for a mixed-mode CLI: ``--verify`` and
        ``--show`` write nothing, so granting them the pre-load digest escape
        let a build-pipeline environment map an unverified shared object
        during the documented *verification* command.  The joined spelling is
        still what this test is for, so it is now driven with a subcommand
        that legitimately confers scope, and the refused direction is
        asserted alongside it rather than dropped.
        """
        writing = ["/usr/bin/python3", "-mama_cryptography.integrity", "--update"]
        assert self._identity(monkeypatch, writing) is True

        read_only = ["/usr/bin/python3", "-mama_cryptography.integrity", "--verify"]
        assert self._identity(monkeypatch, read_only) is False

    def test_the_signing_module_needs_no_subcommand(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``_build_sign`` has no read-only mode, so identity is the whole test.

        Pinned separately because the release path depends on it: the wheel
        re-signer launches it with no ``--update``, during the parent import
        where POST runs.
        """
        argv = ["/usr/bin/python3", "-mama_cryptography._build_sign"]
        assert self._identity(monkeypatch, argv) is True

    def test_env_flag_is_still_required(self, monkeypatch: pytest.MonkeyPatch) -> None:
        argv = ["/usr/bin/python3", "-m", "ama_cryptography._build_sign"]
        assert self._identity(monkeypatch, argv, env=None) is False

    def test_other_modules_are_not_the_signer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        argv = ["/usr/bin/python3", "-m", "pytest", "tests/"]
        assert self._identity(monkeypatch, argv) is False

    def test_a_script_mentioning_the_module_is_not_the_signer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The scan must stop at the first positional: an argv token AFTER a
        script path is that script's argument, not an interpreter option."""
        argv = ["/usr/bin/python3", "attack.py", "-m", "ama_cryptography._build_sign"]
        assert self._identity(monkeypatch, argv) is False

    def test_dash_c_ends_the_scan(self, monkeypatch: pytest.MonkeyPatch) -> None:
        argv = ["/usr/bin/python3", "-c", "print(1)", "-m", "ama_cryptography._build_sign"]
        assert self._identity(monkeypatch, argv) is False

    def test_stdin_script_ends_the_scan(self, monkeypatch: pytest.MonkeyPatch) -> None:
        argv = ["/usr/bin/python3", "-", "-m", "ama_cryptography._build_sign"]
        assert self._identity(monkeypatch, argv) is False

    def test_empty_orig_argv_is_not_the_signer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert self._identity(monkeypatch, []) is False


class TestSignerAnchorMismatchCarveOut:
    """The documented pre-signing state must not hard-fail the signer.

    Every wheel build starts from (freshly built anchored library + committed
    dev-signed artefact): the anchor comparison on that artefact can only
    mismatch, and the signer exists to replace it.  The first head where the
    signer identity legitimately mapped the library exposed this — all five
    cibuildwheel platforms failed the BUILD phase on "integrity trust anchor
    mismatch" (previously the unreadable anchor made the branch unreachable
    at build time, an accident of blindness, not a design).  These drive the
    REAL _verify_signed_integrity against the repository's real artefact.
    """

    @staticmethod
    def _artefact_digest_hex() -> str:
        from ama_cryptography import _integrity_signature as sig

        return str(sig.INTEGRITY_DIGEST_HEX)

    def test_signer_with_coherent_foreign_artefact_fails_repairably(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ama_cryptography import _self_test

        monkeypatch.setattr(_self_test, "_INTEGRITY_FAILURE_KIND", None)
        monkeypatch.setattr(
            _self_test,
            "_validate_trust_anchor",
            lambda pubkey_hex: (None, "integrity trust anchor mismatch: synthetic"),
        )
        monkeypatch.setattr(_self_test, "_integrity_signer_process", lambda: True)

        ok, detail = _self_test._verify_signed_integrity(self._artefact_digest_hex())
        assert ok is False, "the stage must FAIL for the signer too"
        assert "integrity signer" in detail
        assert _self_test.integrity_failure_was_stale_binding(), (
            "a coherent-but-foreign artefact in the signer process is the "
            "documented pre-signing state and must classify repairable"
        )

    def test_non_signer_anchor_mismatch_stays_a_hard_refusal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ama_cryptography import _self_test

        monkeypatch.setattr(_self_test, "_INTEGRITY_FAILURE_KIND", None)
        monkeypatch.setattr(
            _self_test,
            "_validate_trust_anchor",
            lambda pubkey_hex: (None, "integrity trust anchor mismatch: synthetic"),
        )
        monkeypatch.setattr(_self_test, "_integrity_signer_process", lambda: False)

        ok, detail = _self_test._verify_signed_integrity(self._artefact_digest_hex())
        assert ok is False
        assert "trust anchor mismatch" in detail
        assert not _self_test.integrity_failure_was_stale_binding(), (
            "for every non-signer process an anchor mismatch is the re-signed-"
            "tree attack; the caller finalises it to tampering"
        )

    def test_signer_with_an_invalid_signature_stays_tampering(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The carve-out requires coherence: a signature that does not verify
        under its own embedded key is a tampering event even for the signer —
        re-signing over it would launder it."""
        from ama_cryptography import _self_test, pqc_backends

        monkeypatch.setattr(_self_test, "_INTEGRITY_FAILURE_KIND", None)
        monkeypatch.setattr(
            _self_test,
            "_validate_trust_anchor",
            lambda pubkey_hex: (None, "integrity trust anchor mismatch: synthetic"),
        )
        monkeypatch.setattr(_self_test, "_integrity_signer_process", lambda: True)
        monkeypatch.setattr(pqc_backends, "native_ed25519_verify", lambda sig, msg, pk: False)

        ok, detail = _self_test._verify_signed_integrity(self._artefact_digest_hex())
        assert ok is False
        assert "did NOT verify" in detail
        assert not _self_test.integrity_failure_was_stale_binding()
