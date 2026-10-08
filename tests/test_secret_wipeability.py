#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Wipeable secrets, the native entropy seam, and the constant-time codecs.

INVARIANT-6 asks that secret material live where it can be zeroed.  The tests
here pin the mechanisms that make that true in the Python layer:

* every secret the library mints comes back in a ``bytearray``;
* a container's finalizer zeroes only what dies with it -- the
  extract-from-a-temporary bug zeroed a caller's key mid-statement;
* ``secure_random_fill`` draws in place from the native CSPRNG through one
  seam, with the continuous health test, and zeroes on any failure;
* ``_take_secret`` leaves no populated ctypes buffer behind;
* the PEM body regex compiles to no character-class bitmap (a table indexed
  by the private key's characters, INVARIANT-12 rule 4);
* the native Base64 codec and the BIP32 seckey operations are wired through
  ctypes with their refusals mapped.

Each test's docstring names what fails without its guard; those labelled
PIN were checked by reverting the guard (AGENTS.md 6.2).
"""

from __future__ import annotations

import base64
import ctypes
import importlib
import sys
from typing import Any, Callable

import pytest

import ama_cryptography._module_state as ms
import ama_cryptography.pqc_backends as pb
from ama_cryptography import _secret_material as sm
from ama_cryptography import key_formats as kf
from ama_cryptography.exceptions import CryptoModuleError, KeyFormatError


@pytest.fixture
def restore_rng_state() -> Any:
    saved = ms._rng_state["previous"]
    saved_state, saved_reason = ms._MODULE_STATE, ms._ERROR_REASON
    yield
    ms._rng_state["previous"] = saved
    ms._MODULE_STATE, ms._ERROR_REASON = saved_state, saved_reason


# ---------------------------------------------------------------------------
# The extract-from-a-temporary bug (Critical, 2026-10-08)
# ---------------------------------------------------------------------------


def test_a_key_taken_from_a_temporary_keypair_is_not_zeroed() -> None:
    """PIN.  ``sk = generate_kyber_keypair().secret_key`` drops the keypair in
    the same statement, and its finalizer zeroed the caller's key: an all-zero
    ML-KEM decapsulation key, which implicit rejection does not refuse.
    Reverting ``_wipe_if_last_owner`` to an unconditional zero fails this."""
    pk, sk = (lambda kp: (kp.public_key, kp.secret_key))(pb.generate_kyber_keypair())
    assert any(sk), "the extracted secret key was zeroed by the dying keypair"
    enc = pb.kyber_encapsulate(pk)
    assert pb.kyber_decapsulate(enc.ciphertext, sk) == enc.shared_secret


@pytest.fixture
def zeroed_ids(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Record the id of every object the wipe path zeroes.

    Observing the buffer any other way -- a memoryview, a ctypes view --
    makes the observer a second holder, and the last-owner rule then
    (correctly) declines to wipe.  An id is not a reference.
    """
    seen: list[int] = []
    real = sm.zeroize

    def recording(value: Any) -> None:
        seen.append(id(value))
        real(value)

    monkeypatch.setattr(sm, "_zero", recording)
    return seen


def test_a_secret_only_the_container_holds_is_zeroed_when_it_dies(
    zeroed_ids: list[int],
) -> None:
    """PIN.  The other half of the rule: with no other holder, collection
    zeroes.  Removing the zeroing from ``_wipe_if_last_owner`` fails this."""
    kp = pb.KyberKeyPair(public_key=b"\x00" * 1568, secret_key=bytearray(b"\x5a" * 32))
    target = id(kp.secret_key)
    del kp
    assert target in zeroed_ids


def test_wipe_is_unconditional() -> None:
    held = bytearray(b"\x33" * 16)
    kp = pb.KyberKeyPair(public_key=b"\x00" * 1568, secret_key=held)
    kp.wipe()
    assert held == bytearray(16), "an explicit wipe() zeroes even a shared buffer"


def test_release_if_unshared_zeroes_a_sole_local_and_spares_a_shared_one(
    zeroed_ids: list[int],
) -> None:
    """PIN both ways: the threshold is calibrated at import, so an off-by-one
    either zeroes a value someone else holds or never zeroes at all."""

    def sole() -> int:
        value = bytearray(b"\x11" * 8)
        ident = id(value)
        sm.release_if_unshared(value)
        return ident

    assert sole() in zeroed_ids
    # The zeroed value is freed and its address may be reused at once: an id
    # recorded above would then match the next allocation.
    zeroed_ids.clear()

    def one_other_holder() -> tuple[int, list[bytearray]]:
        # Exactly one reference more than the sole case: the boundary.
        value = bytearray(b"\x22" * 8)
        other = [value]
        sm.release_if_unshared(value)
        return id(value), other

    ident, other = one_other_holder()
    assert ident not in zeroed_ids
    assert other[0] == bytearray(b"\x22" * 8), "a value someone else holds was zeroed"


def test_adopt_converts_bytes_to_a_wipeable_bytearray() -> None:
    kp = pb.KyberKeyPair(public_key=b"\x00" * 1568, secret_key=b"\x01" * 3168)
    assert isinstance(kp.secret_key, bytearray)


# ---------------------------------------------------------------------------
# Every secret the library mints is a bytearray
# ---------------------------------------------------------------------------

_SECRET_OUTPUTS: dict[str, Callable[[], Any]] = {
    "native_ed25519_keypair": lambda: pb.native_ed25519_keypair()[1],
    "native_x25519_keypair": lambda: pb.native_x25519_keypair()[1],
    "native_nistp_keypair": lambda: pb.native_nistp_keypair("P-256")[1],
    "native_ml_kem_keypair": lambda: pb.native_ml_kem_keypair(768)[1],
    "native_ml_dsa_keypair": lambda: pb.native_ml_dsa_keypair(65)[1],
    "generate_kyber_keypair": lambda: pb.generate_kyber_keypair().secret_key,
    "kyber_encapsulate": lambda: pb.kyber_encapsulate(
        pb.generate_kyber_keypair().public_key
    ).shared_secret,
    "native_ml_kem_encapsulate": lambda: pb.native_ml_kem_encapsulate(
        768, pb.native_ml_kem_keypair(768)[0]
    )[1],
    "native_x25519_key_exchange": lambda: pb.native_x25519_key_exchange(
        pb.native_x25519_keypair()[1], pb.native_x25519_keypair()[0]
    ),
    "native_nistp_ecdh": lambda: pb.native_nistp_ecdh(
        "P-256", pb.native_nistp_keypair("P-256")[1], pb.native_nistp_keypair("P-256")[0]
    ),
    "native_hkdf (bytes, Cython)": lambda: pb.native_hkdf(b"k" * 32, 32),
    "native_hkdf (bytearray)": lambda: pb.native_hkdf(bytearray(b"k" * 32), 32),
    "native_hkdf (memoryview, ctypes)": lambda: pb.native_hkdf(memoryview(b"k" * 32), 32),
    "native_hkdf_sha384": lambda: pb.native_hkdf_sha384(b"k" * 32, 48),
    "native_pbkdf2_hmac_sha256": lambda: pb.native_pbkdf2_hmac_sha256(b"pw", b"salt", 2, 32),
    "native_argon2id": lambda: pb.native_argon2id(
        b"pw", b"saltsalt", t_cost=1, m_cost=64, parallelism=1
    ),
    "native_hmac_sha512_prf": lambda: pb.native_hmac_sha512_prf(b"k", b"m"),
    "native_secp256k1_seckey_tweak_add": lambda: pb.native_secp256k1_seckey_tweak_add(
        b"\x00" * 31 + b"\x05", b"\x00" * 31 + b"\x07"
    ),
    "frost dealt share": lambda: pb.frost_keygen_trusted_dealer(2, 3)[1][0],
    "secure_token_bytearray": lambda: ms.secure_token_bytearray(32),
}


@pytest.mark.parametrize("name", sorted(_SECRET_OUTPUTS))
def test_every_minted_secret_is_a_bytearray(name: str) -> None:
    """RANGE: the return-type contract across the secret-output surface."""
    value = _SECRET_OUTPUTS[name]()
    assert isinstance(value, bytearray), f"{name} returned {type(value).__name__}"
    assert any(value), f"{name} returned an all-zero secret"


def test_a_mac_tag_stays_bytes() -> None:
    """Tags are public; only the PRF form of HMAC-SHA-512 is a secret."""
    assert isinstance(pb.native_hmac_sha512(b"k", b"m"), bytes)
    assert pb.native_hmac_sha512(b"k", b"m") == bytes(pb.native_hmac_sha512_prf(b"k", b"m"))


# ---------------------------------------------------------------------------
# The native entropy seam
# ---------------------------------------------------------------------------


def test_secure_random_fill_writes_in_place() -> None:
    buf = bytearray(64)
    ident = id(buf)
    ms.secure_random_fill(buf)
    assert id(buf) == ident and any(buf)


def test_a_short_draw_is_filled_and_health_tested(restore_rng_state: Any) -> None:
    """A draw under the 32-byte window takes a separate window draw and is
    filled from it; the window's digest is what the state keeps."""
    ms._rng_state["previous"] = None
    buf = bytearray(7)
    ms.secure_random_fill(buf)
    assert any(buf)
    assert ms._rng_state["previous"] is not None
    assert ms._rng_state["previous"] != bytes(buf)


def test_a_read_only_buffer_is_refused() -> None:
    with pytest.raises(TypeError, match="writable"):
        ms.secure_random_fill(memoryview(b"\x00" * 32))


def test_a_failing_source_leaves_the_buffer_zeroed(
    monkeypatch: pytest.MonkeyPatch, restore_rng_state: Any
) -> None:
    """PIN.  A source that writes and then fails must not leave its partial
    output in the caller's buffer.  Removing the zeroing in
    ``secure_random_fill``'s exception path fails this."""

    def half_then_fail(view: Any) -> None:
        memoryview(view).cast("B")[:16] = b"\xa5" * 16
        raise CryptoModuleError("entropy source failed")

    monkeypatch.setattr(ms, "_entropy_fill", half_then_fail)
    buf = bytearray(b"\x00" * 32)
    with pytest.raises(CryptoModuleError):
        ms.secure_random_fill(buf)
    assert buf == bytearray(32)


def test_a_stuck_source_enters_the_error_state(
    monkeypatch: pytest.MonkeyPatch, restore_rng_state: Any
) -> None:
    def stuck(view: Any) -> None:
        out = memoryview(view).cast("B")
        out[:] = b"\x42" * out.nbytes

    monkeypatch.setattr(ms, "_entropy_fill", stuck)
    ms._rng_state["previous"] = None
    ms.secure_random_fill(bytearray(32))
    second = bytearray(32)
    with pytest.raises(CryptoModuleError, match="Continuous RNG"):
        ms.secure_random_fill(second)
    assert second == bytearray(32), "the refused draw was zeroed"
    assert ms.module_status() == "ERROR"


def test_post_draws_through_the_same_seam(
    monkeypatch: pytest.MonkeyPatch, restore_rng_state: Any
) -> None:
    """PIN.  POST's RNG stage examines the source the library draws from: a
    substituted source is the one it sees.  Pointing the stage back at a
    different source (``secrets``, or the native fill directly) fails this."""
    from ama_cryptography import _self_test as st

    seen: list[int] = []

    def recording(view: Any) -> None:
        out = memoryview(view).cast("B")
        seen.append(out.nbytes)
        out[:] = bytes((len(seen) * 7 + i) & 0xFF for i in range(out.nbytes))

    monkeypatch.setattr(ms, "_entropy_fill", recording)
    saved = list(st._SELF_TEST_RESULTS)
    try:
        passed, reason = st._run_rng_stage()
    finally:
        st._SELF_TEST_RESULTS[:] = saved
    assert passed, reason
    assert seen == [32, 32]


# ---------------------------------------------------------------------------
# _take_secret
# ---------------------------------------------------------------------------


def test_take_secret_wipes_the_ctypes_buffer() -> None:
    """PIN.  The ctypes staging buffer is zeroed once the bytearray is made;
    removing the ``_wipe`` from ``_take_secret`` fails this."""
    buf = ctypes.create_string_buffer(b"\x77" * 24, 24)
    out = pb._take_secret(buf, 20)
    assert out == bytearray(b"\x77" * 20)
    assert buf.raw == bytes(24)


def test_an_ed25519_key_that_fails_its_pairwise_test_is_zeroed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  A key that fails the INVARIANT-41 pairwise test is zeroed before
    the error propagates (INVARIANT-6, every exit path); before 2026-10-08 it
    was dropped intact.  Moving the test outside the zeroing guard fails this."""
    seen: list[bytearray] = []

    def failing_pct(sign: Any, verify: Any, sk: bytearray, pk: bytes, name: str) -> None:
        seen.append(sk)
        assert any(sk), "the pairwise test must see the real key"
        raise CryptoModuleError(f"{name} pairwise consistency test failed (simulated)")

    monkeypatch.setattr(pb, "pairwise_test_signature", failing_pct)
    with pytest.raises(CryptoModuleError, match="simulated"):
        pb.native_ed25519_keypair()
    assert len(seen) == 1
    assert seen[0] == bytearray(len(seen[0]))


def _key_forms() -> list[Any]:
    return [
        bytearray(b"\x5a" * 32),
        memoryview(bytearray(b"\x5a" * 32)),
        ctypes.create_string_buffer(b"\x5a" * 32, 32),
    ]


def _raw(key: Any) -> bytes:
    return key.raw if isinstance(key, ctypes.Array) else bytes(key)


@pytest.mark.parametrize("form", range(3), ids=["bytearray", "memoryview", "ctypes"])
@pytest.mark.parametrize("which", ["signature", "kem", "agreement"])
def test_a_key_that_fails_any_pairwise_test_is_zeroed(
    which: str, form: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PIN.  The three pairwise-test helpers zero the key they were handed
    when the test raises, in every buffer form a keygen passes them; deleting
    the scrub in ``_KeyReleasedOnlyIfConsistent.__exit__`` fails all nine."""
    monkeypatch.setattr(ms, "_set_error", lambda reason: None)
    key = _key_forms()[form]

    def boom(*_args: Any) -> Any:
        raise ValueError("simulated fault")

    with pytest.raises(CryptoModuleError):
        if which == "signature":
            ms.pairwise_test_signature(boom, boom, key, b"pk", "test")
        elif which == "kem":
            ms.pairwise_test_kem(boom, boom, b"pk", key, "test")
        else:
            ms.pairwise_test_agreement(boom, (b"epk", bytearray(32)), key, b"pk", "test")
    assert _raw(key) == bytes(32)


def test_a_key_that_passes_is_left_intact() -> None:
    """SMOKE.  The guard acts on failure only."""
    key = bytearray(b"\x5a" * 32)
    ms.pairwise_test_signature(lambda m, k: b"sig", lambda m, s, p: True, key, b"pk", "test")
    assert key == bytearray(b"\x5a" * 32)


def test_a_key_whose_test_could_not_run_is_zeroed_too() -> None:
    """PIN.  A test that could not run (the backend refused) releases no key
    either, so its key is zeroed although the module stays OPERATIONAL."""
    key = bytearray(b"\x5a" * 32)

    def refused(*_args: Any) -> Any:
        raise pb.NativeBackendUnavailableError("not built")

    with pytest.raises(pb.NativeBackendUnavailableError):
        ms.pairwise_test_signature(refused, refused, key, b"pk", "test")
    assert key == bytearray(32)


# ---------------------------------------------------------------------------
# The PEM body regex classifies no secret character through a table
# ---------------------------------------------------------------------------


def _parser() -> Any:
    # re._parser from 3.11; sre_parse (deprecated there) before it.
    name = "re._parser" if sys.version_info >= (3, 11) else "sre_parse"
    return importlib.import_module(name)


def _character_sets(node: Any) -> list[list[Any]]:
    """Every IN (character set) under a parsed subpattern."""
    found: list[list[Any]] = []
    for op, arg in node:
        name = str(op)
        if name == "IN":
            found.append(arg)
        elif name in ("SUBPATTERN",):
            found.extend(_character_sets(arg[-1]))
        elif name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            found.extend(_character_sets(arg[2]))
        elif name == "BRANCH":
            for alternative in arg[1]:
                found.extend(_character_sets(alternative))
    return found


def test_the_pem_body_is_matched_without_a_character_class_table() -> None:
    """PIN.  The regex engine compiles a set of more than two runs to a
    256-bit bitmap indexed by each character -- for a private-key PEM, by the
    key.  The body set must be a negation of at most two literals, which
    compiles to equality tests.  Restoring ``[A-Za-z0-9+/=]`` fails this."""
    parsed = _parser().parse(kf._PEM_RE.pattern)
    body_group = parsed.state.groupdict["body"]
    body = None
    for op, arg in parsed:
        if str(op) == "SUBPATTERN" and arg[0] == body_group:
            body = arg[-1]
    assert body is not None, "no body group in the PEM pattern"
    sets = _character_sets(body)
    assert sets, "the body matches no character set at all"
    for items in sets:
        kinds = [str(op) for op, _ in items]
        assert set(kinds) <= {"NEGATE", "LITERAL"}, kinds
        assert kinds.count("LITERAL") <= 2, kinds


def test_crlf_pem_is_still_accepted() -> None:
    public, _ = _p256()
    crlf = public.to_pem().replace("\n", "\r\n")
    assert kf.load_spki(crlf) == public


def _p256() -> Any:
    _, secret = pb.native_nistp_keypair("P-256")
    key = kf.PrivateKey("P-256", secret)
    return key.public(), key


# ---------------------------------------------------------------------------
# The native Base64 codec through ctypes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("length", [0, 1, 2, 3, 31, 32, 33, 64, 65, 2592])
def test_the_native_codec_agrees_with_the_stdlib_reference(length: int) -> None:
    data = bytes((i * 167 + 13) & 0xFF for i in range(length))
    std = pb.native_base64_encode(data, pb.BASE64_STANDARD_PADDED)
    url = pb.native_base64_encode(data, pb.BASE64_URL_UNPADDED)
    assert bytes(std) == base64.b64encode(data)
    assert bytes(url) == base64.urlsafe_b64encode(data).rstrip(b"=")
    assert pb.native_base64_decode(bytes(std), pb.BASE64_STANDARD_PADDED) == data
    assert pb.native_base64_decode(bytes(url), pb.BASE64_URL_UNPADDED) == data


@pytest.mark.parametrize(
    "text,variant",
    [
        (b"Zh==", pb.BASE64_STANDARD_PADDED),  # pad bits
        (b"Zg=", pb.BASE64_STANDARD_PADDED),  # length
        (b"Zm9v!g==", pb.BASE64_STANDARD_PADDED),  # alphabet
        (b"Zg==", pb.BASE64_URL_UNPADDED),  # padding in url
        (b"Zm+v", pb.BASE64_URL_UNPADDED),  # standard alphabet in url
        (b"Z", pb.BASE64_URL_UNPADDED),  # impossible length
    ],
)
def test_the_native_codec_refuses_non_canonical_text(text: bytes, variant: int) -> None:
    with pytest.raises(ValueError, match="canonical"):
        pb.native_base64_decode(text, variant)


def test_an_unknown_variant_is_refused() -> None:
    with pytest.raises(ValueError, match="variant"):
        pb.native_base64_encode(b"x", 0)


def test_a_pem_with_a_space_in_its_body_is_refused() -> None:
    public, _ = _p256()
    pem = kf.encode_pem(public.to_spki(), "PUBLIC KEY")
    lines = pem.split("\n")
    lines[1] = lines[1][:10] + " " + lines[1][11:]
    with pytest.raises(KeyFormatError, match="base64"):
        kf.load_spki("\n".join(lines))


# ---------------------------------------------------------------------------
# BIP32 through the native seckey operations
# ---------------------------------------------------------------------------

_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)


def test_seckey_verify_bounds() -> None:
    assert pb.native_secp256k1_seckey_verify((1).to_bytes(32, "big"))
    assert pb.native_secp256k1_seckey_verify((_N - 1).to_bytes(32, "big"))
    assert not pb.native_secp256k1_seckey_verify(bytes(32))
    assert not pb.native_secp256k1_seckey_verify(_N.to_bytes(32, "big"))


def test_seckey_tweak_add_matches_modular_addition() -> None:
    for k, t in [(5, 7), (_N - 1, _N - 1), (_N - 10, 9), (1, 0)]:
        out = pb.native_secp256k1_seckey_tweak_add(k.to_bytes(32, "big"), t.to_bytes(32, "big"))
        assert int.from_bytes(out, "big") == (k + t) % _N


def test_seckey_tweak_add_refuses_a_zero_sum_and_an_oversized_tweak() -> None:
    with pytest.raises(ValueError, match="tweak refused"):
        pb.native_secp256k1_seckey_tweak_add((1).to_bytes(32, "big"), (_N - 1).to_bytes(32, "big"))
    with pytest.raises(ValueError, match="tweak refused"):
        pb.native_secp256k1_seckey_tweak_add((1).to_bytes(32, "big"), _N.to_bytes(32, "big"))


def test_an_invalid_child_is_reported_as_bip32_says(monkeypatch: pytest.MonkeyPatch) -> None:
    """BIP32: I_L >= n or a zero child means "proceed with the next index"."""
    from ama_cryptography.key_management import HDKeyDerivation

    hd = HDKeyDerivation(seed=bytes(range(64)))

    def refuse(_key: Any, _tweak: Any) -> bytearray:
        raise ValueError("secp256k1 tweak refused")

    monkeypatch.setattr(pb, "native_secp256k1_seckey_tweak_add", refuse)
    with pytest.raises(ValueError, match="Try next index"):
        hd.derive_path("m/0'")


def test_an_invalid_master_key_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    from ama_cryptography.key_management import HDKeyDerivation

    monkeypatch.setattr(pb, "native_secp256k1_seckey_verify", lambda _key: False)
    with pytest.raises(ValueError, match="Invalid BIP32 master key"):
        HDKeyDerivation(seed=bytes(range(64)))


def test_derive_path_returns_fresh_buffers_not_the_masters() -> None:
    """``m`` hands back copies: a caller wiping its result must not zero the
    hierarchy's own master key."""
    from ama_cryptography.key_management import HDKeyDerivation

    hd = HDKeyDerivation(seed=bytes(range(64)))
    key, _chain = hd.derive_path("m")
    assert key == hd.master_key and key is not hd.master_key
    key[:] = bytes(32)
    assert any(hd.master_key)


def test_a_private_key_is_unhashable_by_decision() -> None:
    """PIN.  A frozen dataclass over a bytearray would raise an incidental
    ``unhashable type: 'bytearray'``; the refusal is explicit and says what
    to key on.  Equality still works."""
    _public, key = _p256()
    with pytest.raises(TypeError, match="not hashable"):
        hash(key)
    assert key == kf.PrivateKey(key.algorithm, bytes(key.key), key.public_key, None)


def test_a_signing_key_changed_in_place_is_not_served_from_the_memo() -> None:
    """PIN.  ``create_crypto_package`` memoizes the expanded signing key on
    the config, keyed by element identity -- which implied value only while
    keys were immutable ``bytes``.  A bytearray seed overwritten in place with
    another valid key keeps its identity; served from the memo, the package
    would be signed with the PREVIOUS key, silently.  It must be re-expanded,
    and the new seed then fails to match the public key the config carries.
    (A seed wiped to zeros is refused earlier, by the all-zero check, so it
    cannot stand in for this case.)  Removing ``_expansion_still_matches``
    from the memo test fails this."""
    from ama_cryptography.crypto_api import (
        AlgorithmType,
        CryptoPackageConfig,
        create_crypto_package,
    )

    public, expanded = pb.native_ed25519_keypair()
    _other_public, other_expanded = pb.native_ed25519_keypair()
    seed = bytearray(memoryview(expanded)[:32])
    config = CryptoPackageConfig(
        signature_algorithm=AlgorithmType.ED25519, signing_keypair=(public, seed)
    )
    create_crypto_package(b"before the change", config)
    seed[:] = memoryview(other_expanded)[:32]
    with pytest.raises(ValueError, match="signing_keypair mismatch"):
        create_crypto_package(b"after the change", config)
