#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""A V2 package minted by 4.0.0, verified by this tree: what survives the 5.0 break.

``legacy_compat`` says ``verify_crypto_package`` still accepts V1 and V2
packages.  Until 2026-09-24 it said they "remain verifiable" without
qualification, which is false for the layer 5.0 deliberately broke: 4.x's
``dilithium_sign`` was the FIPS 204 internal interface (Algorithm 7), 5.0's
``dilithium_verify`` is the external, empty-context interface, and so every
pre-5.0 ML-DSA-65 signature verifies False here.  Under the default policy
(``require_quantum_signatures`` defaults to ``DILITHIUM_AVAILABLE``) the whole
verification then raises ``QuantumSignatureRequiredError``.

The fixture ``tests/oracle/legacy_v2_packages_v4.0.0.json`` holds two packages
minted by ``legacy_compat.create_crypto_package`` at git tag ``v4.0.0`` — one
with the ML-DSA-65 layer, one with the quantum layer disabled — over the codes
and helix parameters it records, with the HMAC key fixed to
``bytes(range(32))`` so the fixture carries no secret worth the name.  It is an
answer an earlier release of this library gave, not another implementation's
(INVARIANT-36), and it cannot be regenerated from this tree: 5.0 mints only V3
and ships no internal-interface ML-DSA signer (INVARIANT-50).  Procedure used:
``git archive v4.0.0``, ``python setup.py build_ext --inplace``, sign the
build, then call ``create_crypto_package`` with those inputs and record
``dataclasses.asdict`` of the result.

Each claim the ``SIGNATURE_FORMAT_V3`` comment in ``legacy_compat`` makes about
these packages is asserted here, so the comment cannot drift from the code
again without a test failing.
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path
from typing import Any

import pytest

FIXTURE = Path(__file__).resolve().parent / "oracle" / "legacy_v2_packages_v4.0.0.json"
LABELS = ("with_ml_dsa_65", "without_quantum_layer")


def _fixture() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return data


def _verify(label: str, **kwargs: Any) -> Any:
    from ama_cryptography import legacy_compat as lc

    fx = _fixture()
    package = lc.CryptoPackage(**fx["packages"][label])
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return lc.verify_crypto_package(
            fx["codes"],
            [tuple(pair) for pair in fx["helix_params"]],
            package,
            bytes.fromhex(fx["hmac_key_hex"]),
            **kwargs,
        )


def _dilithium_available() -> bool:
    from ama_cryptography.legacy_compat import DILITHIUM_AVAILABLE

    return bool(DILITHIUM_AVAILABLE)


needs_dilithium = pytest.mark.skipif(
    not _dilithium_available(),
    reason="ML-DSA-65 backend not built; the default policy then differs by design",
)


class TestTheFixtureIsWhatItSays:
    def test_both_packages_are_v2_from_4_0_0(self) -> None:
        fx = _fixture()
        assert fx["format"] == "ama-legacy-package-oracle v1"
        assert "4.0.0" in fx["generated_by"]
        assert fx["hmac_key_hex"] == bytes(range(32)).hex()
        for label in LABELS:
            assert fx["packages"][label]["signature_format_version"] == "2.0.0", label

    def test_one_carries_the_ml_dsa_65_layer_and_one_does_not(self) -> None:
        packages = _fixture()["packages"]
        assert packages["with_ml_dsa_65"]["quantum_signatures_enabled"] is True
        assert packages["with_ml_dsa_65"]["dilithium_signature"]
        assert packages["without_quantum_layer"]["quantum_signatures_enabled"] is False
        assert packages["without_quantum_layer"]["dilithium_signature"] is None


class TestWhatStillVerifies:
    @pytest.mark.parametrize("label", LABELS)
    def test_content_hash_hmac_and_ed25519_verify_as_they_did(self, label: str) -> None:
        results = _verify(label, require_quantum_signatures=False)
        for layer in ("content_hash", "hmac", "ed25519"):
            assert results[layer] is True, f"{label}: {layer} no longer verifies"


@needs_dilithium
class TestWhatTheFiveZeroWireBreakCosts:
    def test_the_4x_ml_dsa_65_signature_verifies_false(self) -> None:
        """Internal-interface signature, external-interface verifier."""
        assert _verify("with_ml_dsa_65", require_quantum_signatures=False)["dilithium"] is False

    def test_a_package_without_the_layer_reports_none(self) -> None:
        results = _verify("without_quantum_layer", require_quantum_signatures=False)
        assert results["dilithium"] is None

    @pytest.mark.parametrize(
        "label,reason",
        [
            ("with_ml_dsa_65", "Dilithium signature verification failed"),
            ("without_quantum_layer", "lacks Dilithium signature"),
        ],
    )
    def test_the_default_policy_raises(self, label: str, reason: str) -> None:
        from ama_cryptography.exceptions import QuantumSignatureRequiredError

        with pytest.raises(QuantumSignatureRequiredError, match=reason):
            _verify(label)


class TestTheRfc3161TokenIsOutsideTheV2Transcripts:
    """The other half of the ``SIGNATURE_FORMAT_V3`` comment's token note.

    V3 binds ``timestamp_token`` into both transcripts
    (``tests/test_crypto_package_transcript.py`` pins that every
    authenticator moves).  V1 and V2 never did: their signature covers the
    content and ethical hashes and their HMAC the content hash, so a token
    added to a 4.0.0 package moves ``rfc3161_binding`` and nothing else.
    """

    def test_injecting_a_token_moves_only_the_binding_verdict(self) -> None:
        import dataclasses

        from ama_cryptography import legacy_compat as lc

        fx = _fixture()
        package = lc.CryptoPackage(**fx["packages"]["with_ml_dsa_65"])
        assert package.timestamp_token is None, "precondition: minted without a token"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            results = lc.verify_crypto_package(
                fx["codes"],
                [tuple(pair) for pair in fx["helix_params"]],
                dataclasses.replace(package, timestamp_token="AAAA"),
                bytes.fromhex(fx["hmac_key_hex"]),
                require_quantum_signatures=False,
            )
        for layer in ("content_hash", "hmac", "ed25519"):
            assert results[layer] is True, f"{layer} moved: V2 does not bind the token"
        assert results["rfc3161_binding"] is False
