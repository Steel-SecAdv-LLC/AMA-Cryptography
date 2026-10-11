#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Signing-path secrets (INVARIANT-6): no unwiped copy of a signing key or of
the derived keys.

Covers the hybrid key split, the seed expansion and its memo on
``CryptoPackageConfig``, the derived-keys commitment and the constant-time
equality of the secret containers.  A copy freed at once is pinned by what is
done (a slice-recording ``bytearray``, recorders on the inner calls)."""

from __future__ import annotations

import array
import ast
import base64
import contextlib
import dataclasses
import gc
import inspect
import pickle
import sys
import textwrap
import threading
import time
import types
from typing import Any, Callable, Iterator, cast

import pytest

import ama_cryptography._package_transcript as pt
import ama_cryptography.crypto_api as ca
import ama_cryptography.pqc_backends as pb
from ama_cryptography import _module_state as ms
from ama_cryptography import _secret_material as sm
from ama_cryptography.crypto_api import (
    AlgorithmType,
    AmaCryptography,
    CryptoPackageConfig,
    HybridSignatureProvider,
    create_crypto_package,
    verify_crypto_package,
)

pytestmark = pytest.mark.skipif(
    not pb.DILITHIUM_AVAILABLE, reason="hybrid signatures require the native ML-DSA-65 backend"
)

CONTENT = b"signing path secrets"
SEED = HybridSignatureProvider.ED25519_SK_SIZE
FULL = HybridSignatureProvider.ED25519_FULL_SK_SIZE
MLDSA = HybridSignatureProvider.DILITHIUM_SK_SIZE


class _SliceSpy(bytearray):
    """A ``bytearray`` that records every slice taken of it: a slice is an unwiped
    copy, a ``memoryview`` slice is not."""

    def __init__(self, data: Any = b"") -> None:
        super().__init__(data)
        self.sliced: list[slice] = []

    def __getitem__(self, index: Any) -> Any:
        if isinstance(index, slice):
            self.sliced.append(index)
        return super().__getitem__(index)


def _hybrid_keypair() -> tuple[bytes, bytearray]:
    kp = AmaCryptography(algorithm=AlgorithmType.HYBRID_SIG).generate_keypair()
    assert isinstance(kp.secret_key, bytearray)
    return kp.public_key, kp.secret_key


def _expanded(sk: bytearray) -> bytearray:
    """The 4,096-byte form ``create_crypto_package`` caches, built with the
    reference expansion (seed -> seed || public) and a plain concatenation."""
    _pk, full = pb.native_ed25519_keypair_from_seed(bytes(sk[:SEED]))
    return bytearray(bytes(full) + bytes(sk[SEED:]))


# ---------------------------------------------------------------------------
# Site 5: HybridSignatureProvider.sign
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("form", ["seed", "expanded"])
def test_hybrid_sign_cuts_no_copy_of_the_callers_key(form: str) -> None:
    """PIN.  The seed form (4,064 bytes) and the expanded form (4,096) are both
    split at the Ed25519/ML-DSA boundary; the split must borrow the caller's
    buffer.  Restoring ``secret_key[:n]`` / ``secret_key[n:]`` records two
    slices here and fails.  The signature must still verify under both."""
    public_key, sk = _hybrid_keypair()
    key = _SliceSpy(sk if form == "seed" else _expanded(sk))
    provider = HybridSignatureProvider()
    signature = provider.sign(b"message", key)
    assert key.sliced == [], "the key was sliced into independent copies"
    assert provider.verify(b"message", signature.signature, public_key)


def test_hybrid_sign_hands_the_inner_signers_views_not_copies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  The two inner calls receive ``memoryview`` objects over the
    caller's own buffer.  Restoring the slices hands them two ``bytearray``
    copies and fails this (the slice-spy test above fails too; this one reads
    what the callees actually receive, which a spy on ``__getitem__`` cannot)."""
    _public_key, sk = _hybrid_keypair()
    # What each callee was handed, read while it holds it: the loan is over
    # (released) by the time sign() returns.
    handed: list[tuple[bool, int, bool]] = []
    real_ctx = pb.dilithium_sign_ctx
    real_ed = ca.Ed25519Provider.sign

    def note(secret_key: Any) -> None:
        view = isinstance(secret_key, memoryview)
        handed.append((view, len(secret_key), view and secret_key.obj is sk))

    def ctx(message: bytes, secret_key: Any, context: bytes) -> bytes:
        note(secret_key)
        return real_ctx(message, secret_key, context)

    def ed(self: Any, message: bytes, secret_key: Any, precomputed_hash: Any = None) -> Any:
        note(secret_key)
        return real_ed(self, message, secret_key, precomputed_hash)

    monkeypatch.setattr("ama_cryptography.crypto_api.dilithium_sign_ctx", ctx)
    monkeypatch.setattr(ca.Ed25519Provider, "sign", ed)
    HybridSignatureProvider().sign(b"message", sk)
    assert sorted(length for _view, length, _own in handed) == [SEED, MLDSA]
    assert all(view and own for view, _length, own in handed), handed


def test_hybrid_sign_leaves_no_library_copy_in_the_failure_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  A signing failure keeps every frame's locals alive in the
    traceback.  At the base commit those locals held a populated
    32-byte and a populated 4,032-byte ``bytearray`` of the key; now they hold
    views.  Restoring the slices fails this."""
    _public_key, sk = _hybrid_keypair()

    def refuse(*_args: Any, **_kwargs: Any) -> bytes:
        raise RuntimeError("signing refused")

    monkeypatch.setattr("ama_cryptography.crypto_api.dilithium_sign_ctx", refuse)
    with pytest.raises(RuntimeError, match="signing refused") as caught:
        HybridSignatureProvider().sign(b"message", sk)
    tb: types.TracebackType | None = caught.value.__traceback__
    held: list[tuple[str, int]] = []
    while tb is not None:
        for name, value in tb.tb_frame.f_locals.items():
            if isinstance(value, bytearray) and value is not sk and any(value):
                held.append((name, len(value)))
        tb = tb.tb_next
    assert held == []


def test_hybrid_sign_still_accepts_a_bytes_key() -> None:
    """PIN.  The ctypes boundary refuses a read-only view of part of a buffer,
    so a ``bytes`` key must keep being cut as ``bytes``, not viewed."""
    public_key, sk = _hybrid_keypair()
    provider = HybridSignatureProvider()
    signature = provider.sign(b"message", bytes(sk))
    assert provider.verify(b"message", signature.signature, public_key)


class _RefusingLib:
    """The native library, except that one entry point reports failure."""

    def __init__(self, real: Any, symbol: str) -> None:
        self._real = real
        self._symbol = symbol

    def __getattr__(self, name: str) -> Any:
        if name == self._symbol:
            return lambda *_args: 7
        return getattr(self._real, name)


@pytest.mark.parametrize("failing_half", ["ml-dsa", "ed25519"])
def test_a_failed_hybrid_sign_does_not_pin_the_callers_key(
    monkeypatch: pytest.MonkeyPatch, failing_half: str
) -> None:
    """PIN.  A signer that raises must not leave the caller's key pinned against
    ``clear()`` by the exception's traceback: the loan is released and the finished
    callee frames cleared.  Exercised for the ML-DSA and the Ed25519 half."""
    _public_key, sk = _hybrid_keypair()
    if failing_half == "ml-dsa":
        monkeypatch.setattr(
            pb, "_native_lib", _RefusingLib(pb._native_lib, "ama_dilithium_sign_ctx")
        )
        expected: type[Exception] = pb.QuantumSignatureUnavailableError
    else:

        def refuse(self: Any, message: bytes, secret_key: Any, precomputed_hash: Any = None) -> Any:
            _array_over_the_loan = pb._borrow(secret_key)
            raise RuntimeError("signing refused")

        monkeypatch.setattr(ca.Ed25519Provider, "sign", refuse)
        expected = RuntimeError
    with pytest.raises(expected) as caught:
        HybridSignatureProvider().sign(b"message", sk)
    sk.clear()
    assert len(sk) == 0 and caught.value is not None


def test_hybrid_signature_bytes_are_unchanged_by_borrowing() -> None:
    """SMOKE.  The Ed25519 half is deterministic (RFC 8032), so a hybrid
    signature's first 64 bytes must equal the standalone signature over the
    same domain-bound wrapper; a view that fed the signer the wrong span
    would change them."""
    _public_key, sk = _hybrid_keypair()
    signature = HybridSignatureProvider().sign(b"message", sk).signature
    expected = pb.native_ed25519_sign(ca.hybrid_classical_input(b"message"), _expanded(sk)[:FULL])
    assert signature[:64] == expected


# ---------------------------------------------------------------------------
# Site 6: _normalized_signing_secret
# ---------------------------------------------------------------------------


def _record_expansions(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, Any]]:
    """Every ``(seed argument, returned expansion)`` of the keygen-from-seed, the
    seed read while the keygen holds it."""
    seen: list[tuple[Any, Any]] = []
    real = pb.native_ed25519_keypair_from_seed

    def recording(seed: Any) -> Any:
        borrowed = seed.obj if isinstance(seed, memoryview) else None
        public, full = real(seed)
        seen.append(((type(seed), borrowed), full))
        return public, full

    monkeypatch.setattr("ama_cryptography.crypto_api.native_ed25519_keypair_from_seed", recording)
    return seen


def test_normalizing_a_hybrid_key_borrows_the_seed_and_zeroes_the_expansion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN (two guards).  The seed handed to keygen is a view of the caller's
    key, not a 32-byte copy; and the 64-byte expansion is zero once its bytes
    are in the cached buffer.  Restoring ``secret_key[:32]`` fails the first
    assertion; deleting the ``zeroize(full_sk)`` fails the second."""
    public_key, sk = _hybrid_keypair()
    seen = _record_expansions(monkeypatch)
    config = CryptoPackageConfig(signing_keypair=(public_key, sk))
    normalized = ca._normalized_signing_secret(config, public_key, sk)
    (((seed_type, borrowed), full),) = seen
    assert seed_type is memoryview and borrowed is sk
    assert not any(full), "the 64-byte Ed25519 expansion was left populated"
    assert bytes(normalized) == bytes(_expanded(sk))
    assert len(normalized) == FULL + MLDSA


def test_normalizing_a_hybrid_key_cuts_no_slice_of_it() -> None:
    """PIN.  The 4,000-byte ML-DSA tail was cut with ``secret_key[32:]`` and
    concatenated, a populated temporary nothing owned.  Restoring that
    expression records a slice here and fails."""
    public_key, sk = _hybrid_keypair()
    key = _SliceSpy(sk)
    config = CryptoPackageConfig(signing_keypair=(public_key, key))
    normalized = ca._normalized_signing_secret(config, public_key, key)
    assert key.sliced == []
    assert bytes(normalized) == bytes(_expanded(sk))


@pytest.mark.parametrize("algorithm", [AlgorithmType.HYBRID_SIG, AlgorithmType.ED25519])
def test_a_refused_normalization_leaves_no_populated_expansion(
    monkeypatch: pytest.MonkeyPatch, algorithm: AlgorithmType
) -> None:
    """PIN (one guard per row).  A public key that does not match the seed is
    refused after the expansion exists; it must not stay populated, and the
    caller's key must be byte-for-byte unchanged."""
    other_public, _ = pb.native_ed25519_keypair()
    if algorithm is AlgorithmType.HYBRID_SIG:
        _public, sk = _hybrid_keypair()
    else:
        _public, full = pb.native_ed25519_keypair()
        sk = bytearray(memoryview(full)[:SEED])
    supplied = bytes(sk)
    seen = _record_expansions(monkeypatch)
    config = CryptoPackageConfig(signature_algorithm=algorithm, signing_keypair=(other_public, sk))
    with pytest.raises(ValueError, match="signing_keypair mismatch"):
        ca._normalized_signing_secret(config, other_public, sk)
    ((_seed, full_sk),) = seen
    assert not any(full_sk)
    assert config._normalized_signing_memo is None
    assert bytes(sk) == supplied, "a refused normalization destroyed the key the caller supplied"


@pytest.mark.parametrize("algorithm", [AlgorithmType.HYBRID_SIG, AlgorithmType.ED25519])
def test_a_failed_normalization_does_not_pin_the_callers_key(
    monkeypatch: pytest.MonkeyPatch, algorithm: AlgorithmType
) -> None:
    """PIN.  The seed is lent to the keygen as a view; a keygen that raises
    (its pairwise consistency test, a native failure) is held by its traceback
    with the ctypes array over that view, so a caller keeping the exception
    could not ``clear()`` its key (``BufferError``).  Both arms lend the seed
    through ``_Borrowed``; lending it bare fails the row of that arm."""
    if algorithm is AlgorithmType.HYBRID_SIG:
        public, sk = _hybrid_keypair()
    else:
        public, full = pb.native_ed25519_keypair()
        sk = bytearray(memoryview(full)[:SEED])

    def refuse(seed: Any) -> Any:
        _array_over_the_loan = pb._borrow(seed)
        raise RuntimeError("keygen refused")

    monkeypatch.setattr("ama_cryptography.crypto_api.native_ed25519_keypair_from_seed", refuse)
    config = CryptoPackageConfig(signature_algorithm=algorithm, signing_keypair=(public, sk))
    with pytest.raises(RuntimeError, match="keygen refused") as caught:
        ca._normalized_signing_secret(config, public, sk)
    sk.clear()
    assert len(sk) == 0 and caught.value is not None


def test_the_ed25519_normalization_keeps_its_expansion_for_the_memo() -> None:
    """PIN against over-scrubbing.  On success the ED25519 expansion IS the
    memo; scrubbing it on the way out would sign every later package with
    zeros."""
    public, full = pb.native_ed25519_keypair()
    seed = bytearray(memoryview(full)[:SEED])
    config = CryptoPackageConfig(
        signature_algorithm=AlgorithmType.ED25519, signing_keypair=(public, seed)
    )
    normalized = ca._normalized_signing_secret(config, public, seed)
    assert len(normalized) == FULL and any(normalized)
    assert bytes(normalized) == bytes(full)


# ---------------------------------------------------------------------------
# Site 6b: the miss path is safe to enter from several threads
# ---------------------------------------------------------------------------


def _ed25519_identity() -> tuple[bytes, bytearray]:
    public, full = pb.native_ed25519_keypair()
    return public, bytearray(memoryview(full)[:SEED])


def _identity(algorithm: AlgorithmType) -> tuple[bytes, bytearray]:
    return _hybrid_keypair() if algorithm is AlgorithmType.HYBRID_SIG else _ed25519_identity()


_BOTH_ALGORITHMS = [AlgorithmType.ED25519, AlgorithmType.HYBRID_SIG]


@pytest.mark.parametrize("algorithm", _BOTH_ALGORITHMS)
def test_a_nested_normalization_is_not_zeroed_by_the_one_it_interrupted(
    monkeypatch: pytest.MonkeyPatch, algorithm: AlgorithmType
) -> None:
    """PIN.  A normalization run inside another's keygen stores an expansion the
    interrupted one must not zero: the superseded expansion is read before the
    build, not after."""
    public, sk = _identity(algorithm)
    config = CryptoPackageConfig(signature_algorithm=algorithm, signing_keypair=(public, sk))
    nested: list[sm.SecretBytes] = []
    real = pb.native_ed25519_keypair_from_seed

    def interrupting(seed: Any) -> Any:
        if not nested:
            nested.append(bytearray())  # entered: the nested call builds for real
            nested[0] = ca._normalized_signing_secret(config, public, sk)
        return real(seed)

    monkeypatch.setattr(
        "ama_cryptography.crypto_api.native_ed25519_keypair_from_seed", interrupting
    )
    outer = ca._normalized_signing_secret(config, public, sk)
    (inner,) = nested
    assert any(inner), "the interrupted normalization zeroed the nested one's expansion"
    assert any(outer) and bytes(outer) == bytes(inner)


def test_a_refused_swap_leaves_the_expansion_it_would_have_replaced_intact() -> None:
    """PIN.  The superseded expansion is zeroed only after the new one is
    stored.  A key that is refused must leave the memo serving the old
    expansion populated when the original key comes back; zeroing before the
    build serves an all-zero expansion."""
    public, seed = _ed25519_identity()
    sk = bytes(seed)
    config = CryptoPackageConfig(
        signature_algorithm=AlgorithmType.ED25519, signing_keypair=(public, sk)
    )
    first = ca._normalized_signing_secret(config, public, sk)
    other_public, _full = pb.native_ed25519_keypair()
    with pytest.raises(ValueError, match="signing_keypair mismatch"):
        ca._normalized_signing_secret(config, other_public, sk)
    again = ca._normalized_signing_secret(config, public, sk)
    assert again is first and any(again) and config._signing_expansion is first


@pytest.mark.parametrize("algorithm", _BOTH_ALGORITHMS)
def test_a_second_thread_waits_for_the_first_expansion_instead_of_building_its_own(
    monkeypatch: pytest.MonkeyPatch, algorithm: AlgorithmType
) -> None:
    """PIN.  The miss path is locked and re-checked: a second thread asking for a
    key mid-build waits and is served the first's expansion instead of building and
    orphaning its own.  No sleep decides the order."""
    public, sk = _identity(algorithm)
    config = CryptoPackageConfig(signature_algorithm=algorithm, signing_keypair=(public, sk))
    entered, release = threading.Event(), threading.Event()
    calls: list[str] = []
    real = pb.native_ed25519_keypair_from_seed

    def gated(seed: Any) -> Any:
        calls.append(threading.current_thread().name)
        if len(calls) == 1:
            entered.set()
            assert release.wait(30), "the test never released the first thread"
        return real(seed)

    class Arrivals:
        """The real lock, announcing the second thread to ask for it."""

        def __init__(self, lock: Any) -> None:
            self.lock, self.asked, self.arrived = lock, 0, threading.Event()

        def __enter__(self) -> Any:
            self.asked += 1
            if self.asked >= 2:
                self.arrived.set()
            return self.lock.__enter__()

        def __exit__(self, *exc: Any) -> Any:
            return self.lock.__exit__(*exc)

    arrivals = Arrivals(ca._SIGNING_EXPANSION_LOCK)
    monkeypatch.setattr("ama_cryptography.crypto_api.native_ed25519_keypair_from_seed", gated)
    monkeypatch.setattr("ama_cryptography.crypto_api._SIGNING_EXPANSION_LOCK", arrivals)
    results: dict[str, sm.SecretBytes] = {}
    failures: list[BaseException] = []

    def work(name: str) -> None:
        try:
            results[name] = ca._normalized_signing_secret(config, public, sk)
        except BaseException as exc:  # reported by the test, not lost in a thread
            failures.append(exc)

    first = threading.Thread(target=work, args=("first",), name="first")
    second = threading.Thread(target=work, args=("second",), name="second")
    first.start()
    assert entered.wait(30)
    second.start()
    deadline = time.monotonic() + 30
    while not (arrivals.arrived.is_set() or "second" in results or failures):
        assert time.monotonic() < deadline, "the second thread neither waited nor finished"
        time.sleep(0.001)
    release.set()
    first.join(30)
    second.join(30)
    assert not failures, failures
    assert len(calls) == 1, f"the key was expanded {len(calls)} times, by {calls}"
    assert results["first"] is results["second"] and any(results["first"])
    config.wipe()
    assert not any(results["first"]) and not any(results["second"])


def _released_together(threads: int, job: Callable[[int], None]) -> None:
    """Run ``job(slot)`` on ``threads`` threads released by one barrier."""
    start = threading.Barrier(threads)

    def run(slot: int) -> None:
        start.wait(30)
        job(slot)

    pool = [threading.Thread(target=run, args=(slot,)) for slot in range(threads)]
    for thread in pool:
        thread.start()
    for thread in pool:
        thread.join(60)


@contextlib.contextmanager
def _interleaving_threads() -> Iterator[None]:
    """A switch interval of a microsecond, to make the threads interleave."""
    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        yield
    finally:
        sys.setswitchinterval(previous)


def _first_use_round(
    algorithm: AlgorithmType, threads: int
) -> tuple[CryptoPackageConfig, list[Any]]:
    public, sk = _identity(algorithm)
    config = CryptoPackageConfig(signature_algorithm=algorithm, signing_keypair=(public, sk))
    got: list[Any] = [None] * threads

    def job(slot: int) -> None:
        got[slot] = ca._normalized_signing_secret(config, public, sk)

    _released_together(threads, job)
    return config, got


@pytest.mark.parametrize(
    ("algorithm", "rounds"), [(AlgorithmType.ED25519, 300), (AlgorithmType.HYBRID_SIG, 100)]
)
def test_threads_first_using_one_config_all_get_a_live_expansion(
    algorithm: AlgorithmType, rounds: int
) -> None:
    """PIN, statistical.  Six threads released together on a fresh config each get
    the same populated expansion, still populated after all of them return."""
    with _interleaving_threads():
        for _ in range(rounds):
            config, got = _first_use_round(algorithm, 6)
            assert all(item is not None for item in got), "a thread did not return"
            assert all(item is got[0] for item in got)
            assert any(got[0]), "a thread zeroed the expansion the others were handed"
            config.wipe()


def _package_round(threads: int) -> tuple[bytes, list[Any]]:
    public, sk = _ed25519_identity()
    config = CryptoPackageConfig(
        signature_algorithm=AlgorithmType.ED25519, signing_keypair=(public, sk)
    )
    outcomes: list[Any] = [None] * threads

    def job(slot: int) -> None:
        try:
            outcomes[slot] = create_crypto_package(CONTENT, config)
        except BaseException as exc:  # reported by the test, not lost in a thread
            outcomes[slot] = exc

    _released_together(threads, job)
    config.wipe()
    return public, outcomes


def test_threads_sharing_a_config_all_create_verifying_packages() -> None:
    """End to end, statistical.  Threads sharing one config all create packages that
    verify."""
    with _interleaving_threads():
        for _ in range(40):
            public, outcomes = _package_round(6)
            for outcome in outcomes:
                assert not isinstance(outcome, BaseException), repr(outcome)
                assert outcome is not None, "a thread did not return"
                verdict = verify_crypto_package(CONTENT, outcome, expected_public_key=public)
                assert verdict["all_valid"]


# ---------------------------------------------------------------------------
# Site 7: CryptoPackageConfig owns, and can wipe, the cached expansion
# ---------------------------------------------------------------------------


@pytest.fixture
def zeroed_contents(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    """The contents of every populated ``bytearray`` the finalizer path zeroes, read
    just before it is.  By content, not ``id()``, which CPython recycles."""
    seen: list[bytes] = []
    real = sm.zeroize

    def recording(value: Any) -> None:
        if isinstance(value, bytearray) and any(value):
            seen.append(bytes(value))
        real(value)

    monkeypatch.setattr(sm, "_zero", recording)
    return seen


def _signed_config() -> tuple[CryptoPackageConfig, bytes, bytearray]:
    public_key, sk = _hybrid_keypair()
    config = CryptoPackageConfig(signing_keypair=(public_key, sk))
    create_crypto_package(CONTENT, config)
    return config, public_key, sk


def test_wipe_zeroes_the_cached_expansion_and_spares_the_callers_key() -> None:
    """PIN.  Before the fix the config had no ``wipe()`` at all (AttributeError)
    and the 4,096-byte expansion outlived the caller's own wipe.  Removing the
    zeroing from ``_drop_signing_memo`` fails the first assertion; zeroing the
    ``signing_keypair`` along with it fails the second."""
    config, public_key, sk = _signed_config()
    expansion = config._signing_expansion
    assert expansion is not None and len(expansion) == FULL + MLDSA and any(expansion)
    config.wipe()
    assert not any(expansion)
    assert config._signing_expansion is None and config._normalized_signing_memo is None
    assert any(sk), "wipe() destroyed the key the caller supplied"
    package = create_crypto_package(CONTENT, config)
    assert verify_crypto_package(CONTENT, package, expected_public_key=public_key)["all_valid"]


def test_a_wiped_config_does_not_serve_a_zeroed_expansion_for_a_bytes_key() -> None:
    """PIN.  A ``bytes`` key is trusted by identity alone, so a memo left in
    place after its expansion was zeroed would sign every later package with
    zeros and the signature could never verify.  Dropping the memo along with
    the expansion is what prevents it: removing ``_normalized_signing_memo =
    None`` from ``_drop_signing_memo`` fails this."""
    public_key, sk = _hybrid_keypair()
    config = CryptoPackageConfig(signing_keypair=(public_key, bytes(sk)))
    create_crypto_package(CONTENT, config)
    config.wipe()
    package = create_crypto_package(CONTENT, config)
    assert verify_crypto_package(CONTENT, package, expected_public_key=public_key)["all_valid"]


def test_a_dying_config_zeroes_the_expansion_it_alone_holds(
    zeroed_contents: list[bytes],
) -> None:
    """PIN.  A dying config zeroes the expansion it alone holds and spares the
    caller's key.  The expansion is identified by its bytes, so the result does not
    depend on test order."""
    config, _public_key, sk = _signed_config()
    expansion = config._signing_expansion
    assert expansion is not None
    expected = bytes(expansion)
    del expansion
    zeroed_contents.clear()
    del config
    gc.collect()
    assert expected in zeroed_contents, "the dead config's expansion was never zeroed"
    assert any(sk), "collecting the config zeroed the caller's key"


def test_an_expansion_someone_else_still_holds_is_not_zeroed_by_collection(
    zeroed_contents: list[bytes],
) -> None:
    """PIN of the last-owner rule applied to the config (the extract-from-a-
    temporary rule): a caller who took the expansion owns it.  An
    unconditional zero in ``__del__`` fails this."""
    config, _public_key, _sk = _signed_config()
    taken = config._signing_expansion
    assert taken is not None
    expected = bytes(taken)
    zeroed_contents.clear()
    del config
    gc.collect()
    assert expected not in zeroed_contents
    assert bytes(taken) == expected


def test_a_key_the_config_did_not_expand_is_never_wiped_with_it() -> None:
    """PIN.  For an algorithm with nothing to expand the "normalized" secret IS
    the caller's key.  Recording it as the config's own expansion would make
    ``wipe()`` zero the caller's key.  Doing so fails this."""
    kp = AmaCryptography(algorithm=AlgorithmType.ML_DSA_65).generate_keypair()
    config = CryptoPackageConfig(
        signature_algorithm=AlgorithmType.ML_DSA_65,
        signing_keypair=(kp.public_key, kp.secret_key),
    )
    package = create_crypto_package(CONTENT, config)
    assert config._signing_expansion is None
    config.wipe()
    assert any(kp.secret_key)
    del config
    gc.collect()
    assert any(kp.secret_key)
    assert verify_crypto_package(CONTENT, package, expected_public_key=kp.public_key)["all_valid"]


@pytest.mark.parametrize("kind", [bytearray, bytes])
def test_wiping_a_result_never_zeroes_the_key_the_caller_supplied(kind: type) -> None:
    """PIN.  The result owns a copy of the signing key's secret half: wiping the
    result never zeroes the key the caller supplied."""
    public_key, sk = _hybrid_keypair()
    supplied = bytes(sk)
    config = CryptoPackageConfig(signing_keypair=(public_key, kind(sk)))
    caller_key = config.signing_keypair[1] if config.signing_keypair else b""
    result = create_crypto_package(CONTENT, config)
    stored = result.keypairs["HYBRID_SIG"].secret_key
    assert stored is not caller_key and isinstance(stored, bytearray) and bytes(stored) == supplied
    result.wipe()
    assert not any(stored), "result.wipe() left its own copy of the signing key populated"
    assert bytes(caller_key) == supplied, "result.wipe() zeroed the key the caller supplied"
    package = create_crypto_package(CONTENT, config)
    assert verify_crypto_package(CONTENT, package, expected_public_key=public_key)["all_valid"]
    del package, result, stored
    gc.collect()
    assert bytes(caller_key) == supplied, "collecting the result zeroed the caller's key"


def test_a_refused_package_zeroes_the_copy_of_the_signing_key_it_made() -> None:
    """PIN.  The copy the result's keypair holds is minted by the call, so a
    refusal later in the same call (here: the public key does not match the
    seed) zeroes it with the rest of what the call minted, and spares the
    caller's key.  Not registering the keypair with ``held`` leaves it populated
    while the exception is referenced (the traceback keeps the frame)."""
    other_public, _ = pb.native_ed25519_keypair()
    _public, sk = _ed25519_identity()
    supplied = bytes(sk)
    config = CryptoPackageConfig(
        signature_algorithm=AlgorithmType.ED25519, signing_keypair=(other_public, sk)
    )
    with pytest.raises(ValueError, match="signing_keypair mismatch") as caught:
        create_crypto_package(CONTENT, config)
    frame = None
    step: types.TracebackType | None = caught.tb
    while step is not None:
        if step.tb_frame.f_code.co_name == "create_crypto_package":
            frame = step.tb_frame
        step = step.tb_next
    assert frame is not None
    refused = frame.f_locals["primary_keypair"]
    assert refused.secret_key is not sk
    assert not any(refused.secret_key), "the refused call left its copy of the key populated"
    assert bytes(sk) == supplied


def test_a_superseded_expansion_is_zeroed() -> None:
    """PIN.  Replacing the signing keypair re-expands and zeroes the previous
    expansion (a copy of the old key).  Removing ``zeroize(superseded)``
    fails this."""
    config, _public_key, _sk = _signed_config()
    old = config._signing_expansion
    assert old is not None and any(old)
    new_public, new_sk = _hybrid_keypair()
    config.signing_keypair = (new_public, new_sk)
    package = create_crypto_package(CONTENT, config)
    assert not any(old)
    assert config._signing_expansion is not old and any(config._signing_expansion or b"")
    assert verify_crypto_package(CONTENT, package, expected_public_key=new_public)["all_valid"]


def test_config_equality_does_not_depend_on_whether_it_has_signed() -> None:
    """PIN.  The cache is not a dataclass field, so equality cannot depend on
    it (the memo was ``compare=False``).  Declaring the expansion as a field
    of the config fails this."""
    public_key, sk = _hybrid_keypair()
    used = CryptoPackageConfig(signing_keypair=(public_key, sk))
    fresh = CryptoPackageConfig(signing_keypair=(public_key, sk))
    create_crypto_package(CONTENT, used)
    assert used == fresh


def test_the_memo_is_still_a_hit_on_the_second_package() -> None:
    """PIN.  The point of keeping the memo: the second package does not expand
    again (0.84-0.88 M instructions avoided per package; see
    ``_normalized_signing_secret``).  A memo that is never written fails this."""
    config, _public_key, _sk = _signed_config()
    memo = config._normalized_signing_memo
    assert memo is not None
    create_crypto_package(CONTENT, config)
    assert config._normalized_signing_memo is memo


# The ``__dict__`` of a config as the release before this change pickled it
# (protocol 2, made by the unmodified 8aaa7107 tree for
# ``CryptoPackageConfig(signature_algorithm=ED25519, signing_keypair=(pk,
# bytes(range(32))))``, never used to sign).  That release declared the memo
# as a defaulted dataclass field, so the pickle carries no cache attribute at
# all: an object restored from it, or any object that never ran the
# constructor, must read the cache as empty.
_BASE_RELEASE_PICKLE = (
    "gAJjYW1hX2NyeXB0b2dyYXBoeS5jcnlwdG9fYXBpCkNyeXB0b1BhY2thZ2VDb25maWcKcQApgXEBfXECKFgJAAAA"
    "dXNlX2t5YmVycQOJWAsAAAB1c2Vfc3BoaW5jc3EEiVgTAAAAc2lnbmF0dXJlX2FsZ29yaXRobXEFY2FtYV9jcnlw"
    "dG9ncmFwaHkuY3J5cHRvX2FwaQpBbGdvcml0aG1UeXBlCnEGSwSFcQdScQhYCwAAAGluY2x1ZGVfa2VtcQmJWBEA"
    "AABpbmNsdWRlX3RpbWVzdGFtcHEKiVgQAAAAbnVtX2Rlcml2ZWRfa2V5c3ELSwNYBwAAAHRzYV91cmxxDE5YCAAA"
    "AHRzYV9tb2RlcQ1YBgAAAG9ubGluZXEOWA8AAABzaWduaW5nX2tleXBhaXJxD2NfY29kZWNzCmVuY29kZQpxEFgw"
    "AAAAA8KhB8K/w7PDjhDCvh1ww50Yw6dLw4DCmWfDpMOWMMKbwqUNXx3DnMKGZBJVMcK4cRFYBgAAAGxhdGluMXES"
    "hnETUnEUaBBYIAAAAAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fcRVoEoZxFlJxF4ZxGHViLg=="
)


def _ed25519_config_state_only() -> tuple[CryptoPackageConfig, bytes]:
    seed = bytes(range(32))
    public, _full = pb.native_ed25519_keypair_from_seed(seed)
    config = object.__new__(CryptoPackageConfig)
    config.__dict__.update(
        use_kyber=False,
        use_sphincs=False,
        signature_algorithm=AlgorithmType.ED25519,
        include_kem=False,
        include_timestamp=False,
        num_derived_keys=3,
        tsa_url=None,
        tsa_mode="online",
        signing_keypair=(bytes(public), seed),
    )
    return config, bytes(public)


def test_a_config_pickled_by_the_base_release_signs() -> None:
    """PIN.  A config pickled by the base release carries no cache attribute;
    restored here it must still sign a package that verifies (class-level
    defaults for the two cache attributes)."""
    blob = base64.b64decode("".join(_BASE_RELEASE_PICKLE.split()))
    config = pickle.loads(blob)  # noqa: S301 -- self blob, bytes pinned in this file (SPS-001)  # fmt: skip
    assert isinstance(config, CryptoPackageConfig)
    package = create_crypto_package(CONTENT, config)
    public_key = config.signing_keypair[0] if config.signing_keypair else b""
    assert verify_crypto_package(CONTENT, package, expected_public_key=public_key)["all_valid"]
    config.wipe()
    assert config._signing_expansion is None


def test_a_config_that_never_ran_the_constructor_signs_and_wipes() -> None:
    """PIN, as above without a pickle: an instance built around ``__init__``
    has no cache attributes in its ``__dict__`` and must still sign, wipe and
    be collected."""
    config, public_key = _ed25519_config_state_only()
    assert "_signing_expansion" not in config.__dict__
    config.wipe()
    package = create_crypto_package(CONTENT, config)
    assert verify_crypto_package(CONTENT, package, expected_public_key=public_key)["all_valid"]
    del config
    gc.collect()


def test_a_configs_repr_does_not_print_the_signing_key() -> None:
    """PIN.  ``repr`` of a config must not print the signing key
    (``repr=False`` on the field)."""
    public_key, sk = _hybrid_keypair()
    text = repr(CryptoPackageConfig(signing_keypair=(public_key, sk)))
    assert "signing_keypair" not in text
    assert repr(bytes(sk[:24])) not in text and sk[:24].hex() not in text


def _comparator_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[bytes, bytes]]:
    calls: list[tuple[bytes, bytes]] = []
    from ama_cryptography import secure_memory

    real = secure_memory.constant_time_compare

    def recording(a: Any, b: Any) -> bool:
        calls.append((bytes(a), bytes(b)))
        return real(a, b)

    monkeypatch.setattr(ms, "_secret_comparator", recording)
    return calls


def test_config_equality_compares_the_signing_key_in_constant_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  ``==`` on a config compares ``signing_keypair`` with the native
    constant-time comparison for every element, whichever differs first."""
    public_a, sk_a = _hybrid_keypair()
    public_b, sk_b = _hybrid_keypair()
    calls = _comparator_calls(monkeypatch)
    same = CryptoPackageConfig(signing_keypair=(public_a, bytearray(sk_a)))
    held = CryptoPackageConfig(signing_keypair=(public_a, sk_a))
    other = CryptoPackageConfig(signing_keypair=(public_b, sk_b))
    assert held == same
    assert (bytes(sk_a), bytes(sk_a)) in calls
    calls.clear()
    assert held != other
    # Both elements were compared although the first already differs.
    assert (public_a, public_b) in calls and (bytes(sk_a), bytes(sk_b)) in calls
    assert held != CryptoPackageConfig()
    assert CryptoPackageConfig() == CryptoPackageConfig()
    listed = CryptoPackageConfig(signing_keypair=cast(Any, [public_a, sk_a]))
    assert listed != held and listed == CryptoPackageConfig(
        signing_keypair=cast(Any, [public_a, sk_a])
    )


def test_every_crypto_api_secret_container_names_only_fields_in_its_equality() -> None:
    """RANGE (mutation-tested on ``CryptoPackageConfig`` only).  Every
    ``SecretMaterial`` dataclass in ``crypto_api`` names only dataclass fields in
    its constant-time equality, so ``==`` never depends on a cache attribute."""
    pending = list(sm.SecretMaterial.__subclasses__())
    checked: list[str] = []
    while pending:
        cls = pending.pop()
        pending.extend(cls.__subclasses__())
        if not (dataclasses.is_dataclass(cls) and cls.__module__ == ca.__name__):
            continue
        named = getattr(cls.__eq__, "constant_time_secret_fields", None)
        if named is None:
            continue
        fields = {f.name for f in dataclasses.fields(cls)}
        assert set(named) <= fields, (cls.__qualname__, sorted(set(named) - fields))
        checked.append(cls.__qualname__)
    assert "CryptoPackageConfig" in checked


@pytest.mark.parametrize("kind", [list, tuple])
def test_sequences_that_differ_only_in_length_are_unequal(kind: type) -> None:
    """PIN of the length guard in ``_secrets_equal``.  Two sequences whose
    common prefix is equal are told apart by their lengths and nothing else;
    without the guard ``zip`` stops at the shorter and they compare equal.
    Covers a longer, a shorter and an empty-against-one-empty-item pair, both
    ways round."""
    longer, shorter = kind([b"k1", b"k2"]), kind([b"k1"])
    assert not sm._secrets_equal(longer, shorter)
    assert not sm._secrets_equal(shorter, longer)
    assert not sm._secrets_equal(kind(), kind([b""]))
    assert sm._secrets_equal(kind([b"k1"]), kind([b"k1"])) and sm._secrets_equal(kind(), kind())


class _Tally:
    """An object whose ``==`` counts how often it is asked."""

    def __init__(self) -> None:
        self.asked = 0

    def __eq__(self, other: object) -> bool:
        self.asked += 1
        return True

    def __hash__(self) -> int:
        return id(self)


@sm.constant_time_equality(secret=("first", "second"))
@dataclasses.dataclass
class _TwoSecrets:
    first: bytes
    second: bytes
    label: Any = None


def test_every_field_is_compared_whichever_differs_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  The generated ``__eq__`` has no early exit: with both secret fields
    differing, the second is still compared natively and the ordinary field
    after them is still asked."""
    calls = _comparator_calls(monkeypatch)
    tally = _Tally()
    left = _TwoSecrets(b"a" * 8, b"b" * 8, tally)
    right = _TwoSecrets(b"x" * 8, b"y" * 8, tally)
    assert left != right
    assert (b"a" * 8, b"x" * 8) in calls and (b"b" * 8, b"y" * 8) in calls
    assert tally.asked == 1


def test_session_equality_compares_the_session_keys_in_constant_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  ``SecureSession`` compares ``send_key`` and ``recv_key`` (``InitVar``
    attributes, not fields) in constant time, and each decides the result alone."""
    from ama_cryptography.secure_channel import SecureSession

    def session(send: bytes, recv: bytes) -> SecureSession:
        return SecureSession(
            session_id=b"s" * 32,
            send_key=bytearray(send),
            recv_key=bytearray(recv),
            created_at=1.0,
        )

    calls = _comparator_calls(monkeypatch)
    base = session(b"A" * 32, b"B" * 32)
    assert base == session(b"A" * 32, b"B" * 32)
    assert (b"A" * 32, b"A" * 32) in calls and (b"B" * 32, b"B" * 32) in calls
    assert base != session(b"A" * 32, b"D" * 32)
    assert base != session(b"C" * 32, b"B" * 32)
    calls.clear()
    assert base != session(b"C" * 32, b"D" * 32)
    assert (b"A" * 32, b"C" * 32) in calls and (b"B" * 32, b"D" * 32) in calls


# ---------------------------------------------------------------------------
# Site 8: _derived_keys_commitment
# ---------------------------------------------------------------------------

# Frozen from the base commit's expression, native_sha3_256(DOMAIN +
# canonical(list(keys))), for keys[i] = bytes((17 * (i + 1) + j) % 256 for j
# in range(32)).  A signed package carries this value, so it must not move.
_BASE_COMMITMENTS = {
    1: "fda60abb130db56c7a32b0ed881cd7655f824fb22384ab481cbf7403c77a4fa9",
    3: "262e536a9da93525e2fb9062e8401ffefc655326e6c9ba4559571573fad46a84",
    8: "d9f64175b73b7ee6d6799c02367db4ecf1838748fae4dd27ca1df7c6c2fef5aa",
}


def _keys(count: int) -> list[bytes]:
    return [bytes((17 * (i + 1) + j) % 256 for j in range(32)) for i in range(count)]


def _reference_commitment(keys: list[bytes]) -> str:
    """The encoding written out by hand from the module's documented layout
    (``tag || 8-byte big-endian length || octets``), sharing no code with
    ``canonical`` or the new appender."""
    body = b"\x06" + len(keys).to_bytes(8, "big")
    for key in keys:
        body += b"\x05" + len(key).to_bytes(8, "big") + key
    return pb.native_sha3_256(b"AMA/crypto-package/derived-keys/v1" + body).hex()


@pytest.mark.parametrize("count", [1, 3, 8])
@pytest.mark.parametrize("kind", [bytes, bytearray])
def test_the_derived_keys_commitment_is_byte_identical_to_the_base(count: int, kind: type) -> None:
    """PIN.  The commitment is signed into every package, so the new assembly
    must hash the same bytes as the old expression for 1, 3 and 8 keys, held
    as ``bytes`` or ``bytearray``: against the digest frozen from the base
    commit and against a by-hand reference.  Any change to a tag, a length
    width or the order of the parts fails every row."""
    keys = [kind(k) for k in _keys(count)]
    assert ca._derived_keys_commitment(keys) == _BASE_COMMITMENTS[count]
    assert ca._derived_keys_commitment(keys) == _reference_commitment(_keys(count))


def test_the_derived_keys_commitment_hashes_a_buffer_it_then_zeroes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN (two guards).  The hashed preimage is a ``bytearray``, not an
    immutable ``bytes`` holding every derived key, and it is zero afterwards.
    Hashing ``bytes(preimage)`` fails the first assertion; removing the
    ``zeroize`` fails the second."""
    hashed: list[Any] = []
    real = pb.native_sha3_256

    def recording(data: Any) -> Any:
        hashed.append(data)
        return real(data)

    monkeypatch.setattr("ama_cryptography.crypto_api.native_sha3_256", recording)
    keys = _keys(3)
    ca._derived_keys_commitment(keys)
    (preimage,) = hashed
    assert type(preimage) is bytearray
    assert not any(preimage)
    assert len(preimage) == len(b"AMA/crypto-package/derived-keys/v1") + 9 + 3 * (9 + 32)


@pytest.mark.parametrize(
    "items",
    [
        [],
        [b""],
        [b"a", b"bc", b""],
        [bytearray(b"\x00" * 32), memoryview(b"\xff" * 31), b"\x01"],
        [b"x" * 300] * 5,
        [memoryview(array.array("I", [1, 2, 3, 4])), b"z"],
    ],
    ids=["none", "one-empty", "mixed-lengths", "mixed-types", "long", "wide-elements"],
)
def test_the_appender_encodes_exactly_what_canonical_encodes(items: list[Any]) -> None:
    """PIN.  ``append_canonical_byte_strings`` equals ``canonical`` for every shape,
    including the empty list, an empty item and a ``memoryview`` of wide elements
    (its length is octets, not elements)."""
    out = bytearray(b"prefix")
    pt.append_canonical_byte_strings(out, items)
    assert bytes(out) == b"prefix" + pt.canonical(list(items))


@pytest.mark.parametrize(
    "bad",
    [
        [b"a", [1, 2]],
        [b"a", "text"],
        [None],
        [5],
        [b"a", (1, 2)],
        [b"a", {"k": b"v"}],
        [b"a", array.array("B", [1, 2])],
    ],
    ids=["list-of-ints", "str", "none", "int", "tuple-of-ints", "mapping", "array-of-bytes"],
)
def test_the_appender_refuses_what_is_not_a_byte_string_and_writes_nothing(bad: list[Any]) -> None:
    """PIN.  Anything that is not bytes, bytearray or memoryview is refused with
    ``TypeError`` before anything is written."""
    out = bytearray(b"prefix")
    with pytest.raises(TypeError):
        pt.append_canonical_byte_strings(out, bad)
    assert bytes(out) == b"prefix"


class _NoImmutableCopy(bytearray):
    """A key that cannot be turned into ``bytes`` (``bytes(key)`` raises)."""

    def __bytes__(self) -> bytes:
        raise AssertionError("an immutable bytes copy of a derived key was minted")


def test_the_derived_keys_commitment_mints_no_immutable_copy_of_a_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN.  The commitment makes no ``bytes`` of a key through ``canonical()`` or
    ``bytes(item)``; copies by other routes are bounded by the two structural tests
    below."""

    def boom(*_args: Any, **_kwargs: Any) -> bytes:
        raise AssertionError("canonical() makes a bytes of every key")

    monkeypatch.setattr(pt, "canonical", boom)
    monkeypatch.setattr(ca, "_canonical", boom, raising=False)
    keys = [_NoImmutableCopy(k) for k in _keys(3)]
    assert ca._derived_keys_commitment(keys) == _BASE_COMMITMENTS[3]


def _what_a_function_calls(function: Any) -> set[str]:
    """The names a function body calls, plus ``"+"`` for a binary operator and
    ``"[:]"`` for a subscript, the three ways it could build a copy of what it
    is handed.  A ``memoryview(...)`` counts only as ``.nbytes`` of one: its
    size, not a view that can be turned into octets.  Read from the source's
    syntax tree, so a copy is found whichever type, name or alias makes it."""
    (node,) = ast.parse(textwrap.dedent(inspect.getsource(function))).body
    assert isinstance(node, ast.FunctionDef)
    body = [item for statement in node.body for item in ast.walk(statement)]  # not the annotations
    parent = {child: p for p in body for child in ast.iter_child_nodes(p)}
    found: set[str] = set()
    for item in body:
        if isinstance(item, ast.Call):
            name = (
                item.func.id
                if isinstance(item.func, ast.Name)
                else item.func.attr if isinstance(item.func, ast.Attribute) else "<call>"
            )
            above = parent[item]
            if name == "memoryview" and not (
                isinstance(above, ast.Attribute) and above.attr == "nbytes"
            ):
                name = "memoryview(...) used as a buffer"
            found.add(name)
        elif isinstance(item, ast.BinOp):
            found.add("+")
        elif isinstance(item, ast.Subscript):
            found.add("[:]")
    return found


def test_the_appender_calls_nothing_that_copies_an_item() -> None:
    """PIN, structural.  The appender may call only type tests, ``len``,
    ``memoryview(...).nbytes``, the integer encoder and ``+=`` onto the caller's
    buffer."""
    allowed = {"isinstance", "TypeError", "type", "len", "memoryview", "to_bytes"}
    called = _what_a_function_calls(pt.append_canonical_byte_strings)
    assert called <= allowed, sorted(called - allowed)
    assert {"memoryview", "to_bytes"} <= called, "the encoder no longer reads sizes this way"


def test_the_derived_keys_commitment_calls_nothing_that_copies_a_key() -> None:
    """PIN, structural: the function that holds the whole preimage builds it in
    one ``bytearray``, hands it to the appender and the hash, and zeroes it.
    ``bytes(preimage)`` (the hash of an immutable copy of every key), a
    ``canonical()`` call under any name, a join or a slice adds a call outside
    that set and fails."""
    allowed = {"bytearray", "_append_byte_strings", "native_sha3_256", "hex", "zeroize"}
    called = _what_a_function_calls(ca._derived_keys_commitment)
    assert called <= allowed, sorted(called - allowed)
    assert allowed <= called, "the commitment no longer has the shape this pins"


def test_a_package_round_trips_with_the_new_commitment() -> None:
    """SMOKE.  Create and verify both compute the commitment; they agree."""
    public_key, sk = _hybrid_keypair()
    package = create_crypto_package(
        CONTENT, CryptoPackageConfig(signing_keypair=(public_key, sk), num_derived_keys=8)
    )
    assert package.metadata["derived_keys_commitment"] == ca._derived_keys_commitment(
        package.derived_keys
    )
    assert verify_crypto_package(CONTENT, package, expected_public_key=public_key)["all_valid"]
