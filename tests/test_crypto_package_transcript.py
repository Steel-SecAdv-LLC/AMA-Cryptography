# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
The package signature covers the whole package (2026-09 audit, A-2)
===================================================================

``create_crypto_package`` used to sign the ``content`` bytes, so every field
around the content — the add-on signatures, the KEM ciphertext, the timestamp
token, the metadata — sat outside the signature.  Corrupting an add-on was
caught, because the verifier re-checks it; **removing** one was not, because
nothing said it had been there.  That is a downgrade attack on the project's
central claim, and it needed no key material: anyone able to modify a stored
or transmitted package could strip its SLH-DSA and ML-KEM layers and have it
still verify as fully valid.

The signature now covers a canonical transcript of the whole package.  The
measurement below is the audit's own tamper matrix, run as a test.  Against
the code as it stood, seven of the seventeen rows it then had returned
``all_valid`` True; the parametrisation is the pin that keeps them at False.

Two classes here, deliberately separate:

* :class:`TestTheEncodingIsInjective` tests the encoder alone.  Its property —
  two different inputs never produce the same bytes — is what a signature over
  its output is worth, and it needs no backend to test.
* :class:`TestEveryFieldIsUnderTheSignature` tests the package end to end and
  needs the native stack.
"""

import dataclasses
from typing import Any, Callable

import pytest

from ama_cryptography import _package_transcript as tx


def _skip_if_no_backends() -> None:
    """Skip when the native backends this file's end-to-end half needs are absent."""
    try:
        from ama_cryptography.crypto_api import create_crypto_package

        create_crypto_package(b"test")
    except Exception as exc:
        if "native" in str(exc).lower() or "unavailable" in str(exc).lower():
            pytest.skip(f"Native backend required: {exc}")
        raise


# ---------------------------------------------------------------------------
# The encoder, on its own.
# ---------------------------------------------------------------------------


class TestTheEncodingIsInjective:
    """Distinct values must never encode to the same bytes.

    A signature over a non-injective encoding attests to an equivalence class
    rather than to a value, which is how a signer ends up having attested to
    something it never saw.
    """

    #: Values that a careless encoding would conflate.  Every pair drawn from
    #: this list must differ, which is a stronger statement than any hand-
    #: picked pair list and does not rot when a case is added.
    COLLISION_CANDIDATES: tuple[Any, ...] = (
        None,
        False,
        True,
        0,
        1,
        -1,
        "",
        b"",
        "0",
        b"0",
        "1",
        b"1",
        [],
        {},
        [b""],
        [b"", b""],
        [b"ab", b"c"],
        [b"a", b"bc"],
        [b"abc"],
        {"a": b"b"},
        {"ab": b""},
        {"a": b"", "b": b""},
        {"a": [b"b"]},
        [{"a": b"b"}],
        256,
        -256,
    )

    def test_no_two_candidates_collide(self) -> None:
        seen: dict[bytes, Any] = {}
        for value in self.COLLISION_CANDIDATES:
            encoded = tx.canonical(value)
            assert encoded not in seen, f"{value!r} collides with {seen[encoded]!r}"
            seen[encoded] = value
        assert len(seen) == len(self.COLLISION_CANDIDATES)

    def test_bool_does_not_encode_as_int(self) -> None:
        """``bool`` is an ``int`` subclass, so the tag order in ``canonical``
        is load-bearing: check ``int`` first and ``True`` becomes ``1``."""
        assert tx.canonical(True) != tx.canonical(1)
        assert tx.canonical(False) != tx.canonical(0)

    def test_mapping_order_does_not_change_the_encoding(self) -> None:
        """Python dicts preserve insertion order; a transcript must not."""
        assert tx.canonical({"a": 1, "b": 2}) == tx.canonical({"b": 2, "a": 1})

    def test_concatenation_ambiguity_is_impossible(self) -> None:
        """The classic failure: without length prefixes, ``(b"ab", b"c")`` and
        ``(b"a", b"bc")`` are the same bytes, so a signature over one is a
        signature over the other."""
        assert tx.canonical([b"ab", b"c"]) != tx.canonical([b"a", b"bc"])

    def test_field_names_are_bound_too(self) -> None:
        """Renaming or reordering a field must move the transcript: the
        encoding binds the package's shape, not only its values."""
        a = tx.transcript([("x", b"1"), ("y", b"2")])
        assert a != tx.transcript([("y", b"1"), ("x", b"2")])
        assert a != tx.transcript([("y", b"2"), ("x", b"1")])
        assert a != tx.transcript([("x", b"1")])

    def test_the_domain_separator_leads_every_transcript(self) -> None:
        assert tx.transcript([]).startswith(tx.DOMAIN)
        assert tx.transcript([("x", 1)]).startswith(tx.DOMAIN)

    def test_bytearray_and_memoryview_match_bytes(self) -> None:
        """Three spellings of the same octets are the same value, and a
        creator and a verifier holding different spellings must still agree."""
        assert tx.canonical(bytearray(b"ab")) == tx.canonical(b"ab")
        assert tx.canonical(memoryview(b"ab")) == tx.canonical(b"ab")

    def test_large_and_negative_integers_round_trip_distinctly(self) -> None:
        big = 2**512 + 1
        assert tx.canonical(big) != tx.canonical(big + 1)
        assert tx.canonical(big) != tx.canonical(-big)

    @pytest.mark.parametrize("value", [1.5, object(), {1: b"a"}, {b"k": b"v"}])
    def test_an_unencodable_value_is_refused_not_skipped(self, value: Any) -> None:
        """A value the transcript cannot represent is a value the signature
        cannot bind — which is the hole this module closes.  It is refused at
        signing time rather than quietly omitted."""
        with pytest.raises(TypeError):
            tx.canonical(value)


# ---------------------------------------------------------------------------
# The package, end to end.
# ---------------------------------------------------------------------------


CONTENT = b"audit A-2 tamper matrix"


def _clone(package: Any) -> Any:
    """A full copy of a package — no field elided, no secret stripped.

    ``copy.deepcopy`` MUST NOT be used here.  ``CryptoPackageResult`` defines
    ``__getstate__`` to strip ``hmac_key``, ``hkdf_master_secret``,
    ``derived_keys`` and ``kem_shared_secret``, and ``deepcopy`` goes through
    it — so a deepcopied package already fails Layers 2 and 4 and the KEM
    add-on before a single byte is tampered with, and every row of the matrix
    below would report "detected" for a reason with nothing to do with the
    signature.  ``test_an_untampered_clone_still_verifies`` is the control
    that keeps this honest.
    """
    from ama_cryptography.crypto_api import CryptoPackageResult

    return CryptoPackageResult(
        content_hash=package.content_hash,
        hmac_key=package.hmac_key,
        hmac_tag=package.hmac_tag,
        primary_signature=dataclasses.replace(
            package.primary_signature, metadata=dict(package.primary_signature.metadata)
        ),
        sphincs_signature=(
            None
            if package.sphincs_signature is None
            else dataclasses.replace(
                package.sphincs_signature, metadata=dict(package.sphincs_signature.metadata)
            )
        ),
        derived_keys=list(package.derived_keys),
        hkdf_salt=package.hkdf_salt,
        hkdf_master_secret=package.hkdf_master_secret,
        hkdf_info=package.hkdf_info,
        timestamp=package.timestamp,
        kem_ciphertext=package.kem_ciphertext,
        kem_shared_secret=package.kem_shared_secret,
        keypairs={
            name: dataclasses.replace(kp, metadata=dict(kp.metadata))
            for name, kp in package.keypairs.items()
        },
        metadata=dict(package.metadata),
    )


@pytest.fixture(scope="module")
def full_package() -> Any:
    """One package carrying every optional layer, built once.

    Module-scoped because building it costs an SLH-DSA-256f signature; every
    test below tampers with a *clone*, so no test can disturb another.
    """
    _skip_if_no_backends()
    from ama_cryptography.crypto_api import CryptoPackageConfig, create_crypto_package

    config = CryptoPackageConfig(use_sphincs=True, use_kyber=True, include_kem=True)
    return create_crypto_package(CONTENT, config)


def _rewrite_metadata(package: Any) -> None:
    package.metadata["defense_layers"] = 99
    package.metadata["multi_layer_defense"] = False
    package.metadata["pqc_status"] = "totally fine"


def _swap_hmac_consistently(package: Any) -> None:
    """Replace the Layer-2 key AND recompute its tag, so Layer 2 checks out.

    The key travels inside the package, so Layer 2 alone can never do better
    than "these two agree".  Only the signature can say the pair is the one
    the signer chose.
    """
    from ama_cryptography.crypto_api import _hmac_sha3_256

    package.hmac_key = b"\x03" * 32
    package.hmac_tag = _hmac_sha3_256(b"\x03" * 32, CONTENT)


def _corrupt_sphincs(package: Any) -> None:
    sig = package.sphincs_signature.signature
    package.sphincs_signature.signature = bytes([sig[0] ^ 0xFF]) + sig[1:]


def _swap_kyber_key_and_secret_consistently(package: Any) -> None:
    """Replace the Kyber secret key and set the stored secret to what it decapsulates to.

    Neither field is signed, so before the shared secret was committed in the
    signed metadata this left the KEM layer self-consistent and passing.
    """
    from ama_cryptography.pqc_backends import generate_kyber_keypair, kyber_decapsulate

    other = generate_kyber_keypair()
    # A copy: the keypair object wipes its own bytearray when collected, which
    # would leave the package holding zeros and fail the row for that reason.
    secret_key = bytes(other.secret_key)
    package.keypairs["KYBER_1024"].secret_key = secret_key
    package.kem_shared_secret = kyber_decapsulate(package.kem_ciphertext, secret_key)


def _swap_hkdf_master_secret_consistently(package: Any) -> None:
    """Replace the Layer-4 master secret AND re-derive every key from it.

    Salt, info and count are unchanged, so Layer 4 checks out on its own.  The
    derived keys are not in the transcript — they are secrets, and the redacted
    form must still verify Layer 3 — so this row is caught only by Layer 4
    comparing them with ``metadata["derived_keys_commitment"]``, which is.
    """
    from ama_cryptography.crypto_api import _hkdf_sha3_256

    package.hkdf_master_secret = b"\x06" * 32
    package.derived_keys = [
        _hkdf_sha3_256(
            ikm=package.hkdf_master_secret,
            length=32,
            salt=package.hkdf_salt,
            info=package.hkdf_info + b":" + str(i).encode(),
        )
        for i in range(len(package.derived_keys))
    ]


#: (name, mutation).  The rows the audit measured, plus the three this
#: remediation found while proving the fix: a rewritten add-on signature
#: metadata dict, a consistently swapped HMAC key/tag pair, and a dropped
#: derived key.  Seven of these returned ``all_valid`` True before the fix.
#: The consistently swapped HKDF master secret was added on 2026-09-24, when
#: the derived keys moved out of the transcript behind a signed commitment.
TAMPERS: tuple[tuple[str, Callable[[Any], None]], ...] = (
    ("content_hash altered", lambda p: setattr(p, "content_hash", "00" * 32)),
    (
        "metadata signature_algorithm changed",
        lambda p: p.metadata.__setitem__("signature_algorithm", "ED25519"),
    ),
    ("all other metadata rewritten", _rewrite_metadata),
    ("timestamp replaced", lambda p: setattr(p, "timestamp", b"forged-token")),
    ("sphincs_signature stripped", lambda p: setattr(p, "sphincs_signature", None)),
    ("sphincs_signature corrupted", _corrupt_sphincs),
    (
        "sphincs_signature metadata rewritten",
        lambda p: p.sphincs_signature.metadata.__setitem__("backend", "not-really"),
    ),
    ("kem_ciphertext stripped", lambda p: setattr(p, "kem_ciphertext", None)),
    ("kem_ciphertext replaced", lambda p: setattr(p, "kem_ciphertext", b"\x01" * 1568)),
    ("kem_shared_secret replaced", lambda p: setattr(p, "kem_shared_secret", b"\x02" * 32)),
    (
        "kyber secret key and shared secret swapped consistently",
        _swap_kyber_key_and_secret_consistently,
    ),
    ("hmac key and tag swapped consistently", _swap_hmac_consistently),
    ("hkdf_salt altered", lambda p: setattr(p, "hkdf_salt", b"\x04" * 32)),
    ("hkdf_info altered", lambda p: setattr(p, "hkdf_info", b"other-info")),
    ("a derived key dropped", lambda p: p.derived_keys.pop()),
    (
        "hkdf master secret and derived keys swapped consistently",
        _swap_hkdf_master_secret_consistently,
    ),
    (
        "embedded SPHINCS public key swapped",
        lambda p: setattr(p.keypairs["SPHINCS_256F"], "public_key", b"\x05" * 64),
    ),
    ("a whole keypair entry removed", lambda p: p.keypairs.pop("KYBER_1024")),
)


class TestEveryFieldIsUnderTheSignature:
    @staticmethod
    def _pin(package: Any) -> bytes:
        return bytes(package.keypairs[package.metadata["signature_algorithm"]].public_key)

    def test_an_untampered_clone_still_verifies(self, full_package: Any) -> None:
        """The control every row below depends on.

        Without it, a clone that quietly lost a field would make the whole
        matrix pass while proving nothing — which is exactly what
        ``copy.deepcopy`` does here (see ``_clone``).
        """
        from ama_cryptography.crypto_api import verify_crypto_package

        verdict = verify_crypto_package(
            CONTENT, _clone(full_package), expected_public_key=self._pin(full_package)
        )
        assert verdict["all_valid"] is True
        assert verdict["key_pinned"] is True

    @pytest.mark.parametrize("name,mutate", TAMPERS, ids=[t[0] for t in TAMPERS])
    def test_tampering_is_detected(
        self, full_package: Any, name: str, mutate: Callable[[Any], None]
    ) -> None:
        from ama_cryptography.crypto_api import verify_crypto_package

        package = _clone(full_package)
        mutate(package)
        verdict = verify_crypto_package(
            CONTENT, package, expected_public_key=self._pin(full_package)
        )
        assert verdict["all_valid"] is False, name

    def test_verifying_different_content_fails_the_signature_itself(
        self, full_package: Any
    ) -> None:
        """Not merely ``all_valid``.

        The transcript binds the digest of the content actually in hand, not
        only the package's stored claim about it, so a caller who reads
        ``primary_signature`` alone is never told a signature covered bytes it
        did not cover.
        """
        from ama_cryptography.crypto_api import verify_crypto_package

        verdict = verify_crypto_package(
            b"different content", _clone(full_package), expected_public_key=self._pin(full_package)
        )
        assert verdict["primary_signature"] is False
        assert verdict["content_hash"] is False
        assert verdict["all_valid"] is False

    def test_the_transcript_ignores_the_signature_it_authorises(self, full_package: Any) -> None:
        """The creator assembles the package with a placeholder signature,
        takes the transcript, then fills the real signature in.  That is only
        sound if ``package_transcript`` never reads the field — pinned here
        rather than left to the reader of ``create_crypto_package``."""
        from ama_cryptography.crypto_api import package_transcript
        from ama_cryptography.pqc_backends import native_sha3_256

        digest = native_sha3_256(CONTENT)
        before = package_transcript(full_package, digest)
        mutated = _clone(full_package)
        mutated.primary_signature.signature = b"\x00" * len(
            full_package.primary_signature.signature
        )
        mutated.primary_signature.metadata["anything"] = "at all"
        assert package_transcript(mutated, digest) == before

    def test_a_package_carrying_an_unencodable_field_fails_closed(self, full_package: Any) -> None:
        """A metadata value the transcript cannot represent must not verify.

        The package is malformed rather than merely wrong, and the failure is
        reported as a Layer-3 failure rather than raised at the caller — a
        verifier that throws on hostile input is a denial-of-service surface.
        """
        from ama_cryptography.crypto_api import verify_crypto_package

        package = _clone(full_package)
        package.metadata["unencodable"] = 1.5
        verdict = verify_crypto_package(
            CONTENT, package, expected_public_key=self._pin(full_package)
        )
        assert verdict["primary_signature"] is False
        assert verdict["all_valid"] is False

    @pytest.mark.parametrize("form", ["pickle_state", "to_dict"])
    def test_the_redacted_form_still_verifies_the_signature(
        self, full_package: Any, form: str
    ) -> None:
        """Every secret is kept out of the transcript so that the forms which
        strip them — ``to_dict()`` and a pickle — can still check the one
        layer that carries origin.

        ``derived_keys`` was bound directly although both forms strip it, so
        a redacted package failed Layer 3 as well as the layers whose secrets
        it no longer carries (2026-09 review).  They are now bound through
        ``metadata["derived_keys_commitment"]``.  The stripped layers still
        fail, which is correct: nothing here claims the redacted form is
        ``all_valid``, only that its signature is checkable.

        ``pickle_state`` goes through ``__getstate__``/``__setstate__``, the
        pair a pickle round-trip calls, by way of ``copy.deepcopy`` — the
        route ``_clone`` above exists to avoid — so no blob is deserialised.
        """
        import copy

        from ama_cryptography.crypto_api import CryptoPackageResult, verify_crypto_package

        if form == "pickle_state":
            redacted = copy.deepcopy(full_package)
        else:
            fields = full_package.to_dict()
            fields.update(CryptoPackageResult._SECRET_FIELD_PLACEHOLDERS)
            fields["derived_keys"] = []
            redacted = CryptoPackageResult(**fields)
        assert redacted.derived_keys == [] and redacted.hkdf_master_secret == b""

        verdict = verify_crypto_package(
            CONTENT, redacted, expected_public_key=self._pin(full_package)
        )
        assert verdict["primary_signature"] is True
        assert verdict["key_pinned"] is True
        assert verdict["content_hash"] is True
        assert verdict["hkdf_keys"] is False
        assert verdict["all_valid"] is False


def _drop_kem_commitment(package: Any) -> None:
    del package.metadata["kem_shared_secret_commitment"]


def _rewrite_kem_commitment(package: Any) -> None:
    package.metadata["kem_shared_secret_commitment"] = "00" * 32


#: Every way the stored secret can fail the signed commitment.  The Kyber key
#: and ciphertext beside such a secret are unauthenticated input.
COMMITMENT_FAILURES: tuple[tuple[str, Callable[[Any], None]], ...] = (
    ("kem_shared_secret replaced", lambda p: setattr(p, "kem_shared_secret", b"\x02" * 32)),
    (
        "kyber secret key and shared secret swapped consistently",
        _swap_kyber_key_and_secret_consistently,
    ),
    ("commitment removed", _drop_kem_commitment),
    ("commitment rewritten", _rewrite_kem_commitment),
)


class TestTheKemCommitmentIsCheckedBeforeDecapsulation:
    """The KEM layer checks the signed commitment first and decapsulates second.

    The stored ``kem_shared_secret``, the Kyber secret key and the ciphertext
    are all outside the signature; only ``metadata["kem_shared_secret_commitment"]``
    is under it.  A package whose stored secret does not match that commitment
    is refused without its key and ciphertext being run through ML-KEM
    decapsulation — which is the order the 2026-09-23 journal entry states.
    The verdict alone cannot see the order (it is False either way), so these
    tests count the decapsulations.
    """

    @staticmethod
    def _spy_decapsulate(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
        from ama_cryptography import crypto_api

        seen: list[bytes] = []
        original = crypto_api.KyberProvider.decapsulate

        def spy(self: Any, ciphertext: bytes, secret_key: Any) -> bytes:
            seen.append(bytes(ciphertext))
            return original(self, ciphertext, secret_key)

        monkeypatch.setattr(crypto_api.KyberProvider, "decapsulate", spy)
        return seen

    @pytest.mark.parametrize(
        "name,mutate", COMMITMENT_FAILURES, ids=[row[0] for row in COMMITMENT_FAILURES]
    )
    def test_a_secret_failing_its_commitment_is_never_decapsulated(
        self,
        full_package: Any,
        monkeypatch: pytest.MonkeyPatch,
        name: str,
        mutate: Callable[[Any], None],
    ) -> None:
        from ama_cryptography.crypto_api import verify_crypto_package

        package = _clone(full_package)
        mutate(package)
        seen = self._spy_decapsulate(monkeypatch)
        verdict = verify_crypto_package(CONTENT, package)
        assert verdict["kem"] is False, name
        assert seen == [], f"{name}: decapsulated before the commitment was checked"

    def test_a_secret_matching_its_commitment_is_decapsulated_once(
        self, full_package: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The control: the spy sees the call when the commitment holds."""
        from ama_cryptography.crypto_api import verify_crypto_package

        seen = self._spy_decapsulate(monkeypatch)
        verdict = verify_crypto_package(CONTENT, _clone(full_package))
        assert verdict["kem"] is True
        assert seen == [bytes(full_package.kem_ciphertext)]

    def test_a_replaced_ciphertext_still_fails_after_decapsulation(
        self, full_package: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The commitment pins the secret, not the ciphertext: decapsulation
        remains the check that the ciphertext yields that secret."""
        from ama_cryptography.crypto_api import verify_crypto_package

        package = _clone(full_package)
        package.kem_ciphertext = b"\x01" * len(full_package.kem_ciphertext)
        seen = self._spy_decapsulate(monkeypatch)
        verdict = verify_crypto_package(CONTENT, package)
        assert verdict["kem"] is False
        assert seen == [package.kem_ciphertext]


# ---------------------------------------------------------------------------
# The legacy package, whose HMAC covered the content hash and nothing else.
# ---------------------------------------------------------------------------


LEGACY_CODES = "OMNI-A\nOMNI-B"
LEGACY_HELIX = [(1.0, 2.0), (3.0, 4.0)]


@pytest.fixture(scope="module")
def legacy_pair() -> Any:
    """A legacy KMS and a package signed by it.

    ``legacy_compat.create_crypto_package`` is deprecated in favour of the
    ``crypto_api`` one, which is why this lives at the end of the file rather
    than at the front — but a deprecated API with forgeable authorship is
    still a forgeable authorship, and it is the surface the audit's
    sub-reviews found the same defect class on.
    """
    _skip_if_no_backends()
    import warnings

    import ama_cryptography.legacy_compat as lc

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        kms = lc.generate_key_management_system("real-author")
        package = lc.create_crypto_package(LEGACY_CODES, LEGACY_HELIX, kms, "real-author")
    return lc, kms, package


def _legacy_verify(lc: Any, kms: Any, package: Any) -> Any:
    """Verify, mapping a fail-closed raise onto a verdict.

    ``verify_crypto_package`` raises ``QuantumSignatureRequiredError`` when a
    required ML-DSA-65 signature does not verify, so a tamper that breaks the
    signature surfaces as an exception rather than as ``False``.  Both are
    detections; conflating them would let a test pass on the exception while
    the boolean silently said True.
    """
    import warnings

    from ama_cryptography.exceptions import QuantumSignatureRequiredError

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            return lc.verify_crypto_package(LEGACY_CODES, LEGACY_HELIX, package, kms.hmac_key)
        except QuantumSignatureRequiredError:
            return None


#: Fields the V2 construction left outside BOTH the signature (which covered
#: the content hash and the ethical hash) and the HMAC (which covered the
#: content hash alone).  All four were forgeable under a package whose every
#: reported check passed; the first three name the signer and the last is the
#: ethical metadata ``ARCHITECTURE.md`` says cannot be separated from the
#: cryptographic proofs.
LEGACY_TAMPERS: tuple[tuple[str, Callable[[Any], None]], ...] = (
    ("author rewritten", lambda p: setattr(p, "author", "someone-else")),
    ("timestamp rewritten", lambda p: setattr(p, "timestamp", "1999-01-01T00:00:00+00:00")),
    ("version rewritten", lambda p: setattr(p, "version", "9.9")),
    (
        "ethical_vector rewritten",
        lambda p: p.ethical_vector.__setitem__(next(iter(p.ethical_vector)), 0.0),
    ),
    ("ethical_hash rewritten", lambda p: setattr(p, "ethical_hash", "00" * 32)),
    ("ed25519_pubkey swapped", lambda p: setattr(p, "ed25519_pubkey", "aa" * 32)),
    # Outside both authenticators until 2026-09-23: stripping or injecting it
    # moved only the RFC 3161 verdict, never the signature.
    ("timestamp_token injected", lambda p: setattr(p, "timestamp_token", "AAAA")),
)


class TestTheLegacyPackageBindsItsOwnIdentity:
    @staticmethod
    def _clone(package: Any) -> Any:
        return dataclasses.replace(package, ethical_vector=dict(package.ethical_vector))

    def test_the_produced_format_is_the_transcript_one(self, legacy_pair: Any) -> None:
        lc, _kms, package = legacy_pair
        assert package.signature_format_version == lc.SIGNATURE_FORMAT_V3

    def test_an_untampered_clone_still_verifies(self, legacy_pair: Any) -> None:
        lc, kms, package = legacy_pair
        verdict = _legacy_verify(lc, kms, self._clone(package))
        assert verdict is not None
        for key in ("content_hash", "hmac", "ed25519", "ethical_vector"):
            assert verdict[key] is True, key

    @pytest.mark.parametrize("name,mutate", LEGACY_TAMPERS, ids=[t[0] for t in LEGACY_TAMPERS])
    def test_tampering_is_detected(
        self, legacy_pair: Any, name: str, mutate: Callable[[Any], None]
    ) -> None:
        lc, kms, package = legacy_pair
        tampered = self._clone(package)
        mutate(tampered)
        verdict = _legacy_verify(lc, kms, tampered)
        if verdict is None:
            return  # fail-closed raise: detected
        checked = [v for k, v in verdict.items() if k in {"content_hash", "hmac", "ed25519"}]
        assert not all(checked), name

    def test_the_ed25519_signature_covers_the_dilithium_fallback(
        self, legacy_pair: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When ML-DSA-65 is unavailable the package drops its quantum fields.

        Those fields are in the transcript, so the Ed25519 signature and the
        HMAC must be taken after they change.  Ed25519 used to be signed
        first, over a transcript that still claimed a quantum layer, and a
        freshly created package failed its own verification.
        """
        import warnings

        from ama_cryptography.exceptions import QuantumSignatureUnavailableError

        lc, kms, _package = legacy_pair

        def unavailable(*_args: Any, **_kwargs: Any) -> bytes:
            raise QuantumSignatureUnavailableError("ML-DSA-65 backend not available")

        monkeypatch.setattr(lc, "dilithium_sign", unavailable)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            package = lc.create_crypto_package(LEGACY_CODES, LEGACY_HELIX, kms, "real-author")
            verdict = lc.verify_crypto_package(
                LEGACY_CODES, LEGACY_HELIX, package, kms.hmac_key, require_quantum_signatures=False
            )
        assert package.quantum_signatures_enabled is False
        assert package.dilithium_signature is None
        assert verdict["ed25519"] is True
        assert verdict["hmac"] is True

    def test_the_ethical_vector_is_derived_not_trusted(self, legacy_pair: Any) -> None:
        """The specific claim: ethical metadata cannot be separated from the
        proofs.  A rewritten vector must move ``ethical_vector`` to False AND
        break the signature — reporting only the former would leave a caller
        who reads ``ed25519`` alone believing a forged vector was covered."""
        lc, kms, package = legacy_pair
        tampered = self._clone(package)
        tampered.ethical_vector[next(iter(tampered.ethical_vector))] = 0.0
        verdict = _legacy_verify(lc, kms, tampered)
        if verdict is None:
            return  # the signature failed closed, which is the stronger half
        assert verdict["ethical_vector"] is False
        assert verdict["ed25519"] is False

    def test_the_signature_and_the_mac_never_share_a_transcript(self, legacy_pair: Any) -> None:
        """A signature must not be replayable as a MAC, or the reverse: the
        ``purpose`` field is the first thing in both, for that reason."""
        lc, _kms, package = legacy_pair
        from ama_cryptography.pqc_backends import native_sha3_256

        digest = native_sha3_256(b"whatever")
        ethical = lc.recompute_ethical_hash(package.ethical_vector)
        assert lc.build_package_transcript(
            "signature", package, digest, ethical
        ) != lc.build_package_transcript("hmac", package, digest, ethical)
