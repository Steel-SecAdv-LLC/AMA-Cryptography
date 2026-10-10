#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""POST known-answer tests keep their secrets wipeable (INVARIANT-6, -12).

``_kat_ml_kem_1024``, ``_kat_ml_dsa_65``, ``_kat_ed25519`` and
``tools/build_post_kats.py`` zero every seed, secret key and shared secret they
derive on every exit, never render one as hex, compare them only through the
constant-time comparator, and make no second copy: a copy bound to a local (or
held one level down in a list, tuple, set or dict) of the KAT's own source
file, or handed to a native or to the comparator, is a stray, in any encoding.
Not pinned: unbound temporaries (``len(bytes(sk))``), partial or transformed
copies, and copies bound in helper frames of other files.
"""

from __future__ import annotations

import base64
import binascii
import sys
import types
from typing import Any, Callable, Iterable, Iterator, Optional

import pytest

import ama_cryptography._module_state as ms
import ama_cryptography.pqc_backends as pb
from ama_cryptography import _self_test as st

Log = list[tuple[tuple[Any, ...], Any]]

_MIN_SECRET = 16  # shorter buffers are not indexed (nothing in the KATs is shorter)


class _Held(list[tuple[bytearray, bytes]]):
    """The ``(buffer, snapshot)`` pairs of every secret recorded in a run.

    It is also the stray-copy index: ``inspect(obj, where)`` records a stray
    when ``obj`` is not one of the recorded buffers but its content is a
    recorded secret, or a hex / base64 / ``repr`` / integer rendering of one.
    """

    def __init__(self) -> None:
        super().__init__()
        self.strays: list[str] = []
        self.quiet = False
        self.allowed_text: set[str] = set()
        self._indexed = -1
        self._ids: set[int] = set()
        self._raw: dict[bytes, str] = {}
        self._text: dict[str, str] = {}
        self._ints: dict[int, str] = {}

    def _refresh(self) -> None:
        if self._indexed == len(self):
            return
        self._indexed = len(self)
        self.quiet = True  # building the index renders secrets; the probe must not count that
        self._ids = {id(buf) for buf, _ in self}
        self._raw, self._text, self._ints = {}, {}, {}
        for _, snap in self:
            if len(snap) < _MIN_SECRET or not any(snap):
                continue
            size = f"{len(snap)}-byte secret"
            for raw in (
                snap,
                binascii.hexlify(snap),
                base64.b64encode(snap),
                base64.urlsafe_b64encode(snap),
                base64.b64encode(snap) + b"\n",
            ):
                self._raw[raw] = size
            hexed = snap.hex()
            for text in (
                hexed,
                hexed.upper(),
                base64.b64encode(snap).decode(),
                base64.urlsafe_b64encode(snap).decode(),
                repr(snap),
                repr(bytearray(snap)),
            ):
                self._text[text] = size
            for order in ("big", "little"):
                self._ints[int.from_bytes(snap, order)] = size
        self.quiet = False

    def scan(self, obj: Any, where: str) -> None:
        """``inspect`` ``obj`` and, one level down, the members of a container."""
        self.inspect(obj, where)
        members: tuple[Any, ...] = ()
        if isinstance(obj, dict):
            members = (*obj.keys(), *obj.values())
        elif isinstance(obj, (list, tuple, set, frozenset)):
            members = tuple(obj)
        for member in members:
            self.inspect(member, f"member of {where}")

    def inspect(self, obj: Any, where: str) -> None:
        """Record ``obj`` as a stray if it carries a recorded secret."""
        self._refresh()
        if id(obj) in self._ids:
            return
        label: Optional[str] = None
        if isinstance(obj, (bytes, bytearray, memoryview)):
            label = self._raw.get(bytes(obj))
        elif isinstance(obj, str):
            label = None if obj in self.allowed_text else self._text.get(obj)
        elif isinstance(obj, int) and not isinstance(obj, bool):
            label = self._ints.get(obj)
        if label is not None:
            self.strays.append(f"{type(obj).__name__} copy of a {label} at {where}")


class _Probe:
    """Record hex rendering of byte strings, ``fromhex`` constructions and strays.

    Every event raised by a frame of a ``watch``ed source file (a Python call,
    a return, a C call) inspects that frame's locals against ``held``: a
    second copy of a secret bound to a name is seen at the next call or at the
    return, however it was made (``bytes(sk)``, ``bytearray(sk)``, ``sk[:]``,
    ``base64``, ``repr``, ``int.from_bytes``).
    """

    def __init__(self, held: Optional[_Held] = None, watch: Iterable[str] = ()) -> None:
        self.hexed: list[bytes] = []
        self.opaque_hex = 0
        self.hexlify = 0
        self.fromhex = {"bytes": 0, "bytearray": 0}
        self._held = held
        self._watch = frozenset(watch)

    def _scan(self, frame: Any, event: str) -> None:
        assert self._held is not None
        where = f"{frame.f_code.co_name}:{frame.f_lineno} ({event})"
        for name, value in list(frame.f_locals.items()):
            self._held.scan(value, f"local {name!r} in {where}")

    def _profile(self, frame: Any, event: str, arg: Any) -> None:
        if self._held is not None and self._held.quiet:
            return
        if self._held is not None and frame.f_code.co_filename in self._watch:
            self._scan(frame, event)
        if event != "c_call":
            return
        name = getattr(arg, "__name__", "")
        owner = getattr(arg, "__self__", None)
        if name == "hex":
            if isinstance(owner, (bytes, bytearray, memoryview)):
                self.hexed.append(bytes(owner))
            else:  # a ``.hex`` on something else (``float.hex``): not a secret render
                self.opaque_hex += 1
        elif name in ("hexlify", "b2a_hex"):
            self.hexlify += 1
        elif name == "fromhex":
            if owner is bytes:
                self.fromhex["bytes"] += 1
            elif owner is bytearray:
                self.fromhex["bytearray"] += 1

    def __enter__(self) -> _Probe:
        self._previous = sys.getprofile()
        sys.setprofile(self._profile)
        return self

    def __exit__(self, *exc: object) -> None:
        sys.setprofile(self._previous)


def test_the_probe_sees_what_it_claims_to_see() -> None:
    """The probe is live: a hex render, a hexlify and both fromhex are counted."""
    with _Probe() as probe:
        b"\x01\x02".hex()
        bytearray(b"\x03").hex()
        bytes.hex(b"\x04")
        (1.5).hex()
        binascii.hexlify(b"\x05")
        bytes.fromhex("00")
        bytearray.fromhex("00")
        bytearray.fromhex("00")
    # The unbound form ``bytes.hex(x)`` is attributed to its receiver too.
    assert probe.hexed == [b"\x01\x02", b"\x03", b"\x04"]
    assert probe.opaque_hex == 1  # a ``.hex`` whose receiver is not a byte string
    assert probe.hexlify == 1
    assert probe.fromhex == {"bytes": 1, "bytearray": 2}


_SECRET = bytes(range(1, 65))


def _stray_kinds() -> list[str]:
    """Bind every kind of second copy of a 64-byte secret to a local, call, return."""
    held = _Held()
    original = bytearray(_SECRET)
    held.append((original, bytes(original)))
    held.allowed_text = {"published"}
    kept: dict[str, Any] = {
        "bytes": bytes(original),
        "bytearray": bytearray(original),
        "slice": original[:],
        "memoryview": memoryview(bytes(original)),
        "hexlify": binascii.hexlify(original),
        "hex text": original.hex(),
        "base64": base64.b64encode(original),
        "base64 text": base64.b64encode(original).decode(),
        "urlsafe": base64.urlsafe_b64encode(original).decode(),
        "repr": repr(bytes(original)),
        "bytearray repr": repr(original),
        "integer": int.from_bytes(original, "big"),
        "little-endian integer": int.from_bytes(original, "little"),
    }
    for kind, value in kept.items():
        before = len(held.strays)
        held.inspect(value, kind)
        assert len(held.strays) == before + 1, f"{kind} copy of a secret not detected"
    return held.strays


def _inspect_innocents() -> _Held:
    held = _Held()
    original = bytearray(_SECRET)
    held.append((original, bytes(original)))
    held.allowed_text = {"published"}
    for innocent in (
        original,  # the recorded buffer itself
        bytes(64),  # zeros
        bytes(range(2, 66)),  # a different 64 bytes
        bytes(original[:-1]),  # one byte short
        "published",
        "unrelated text",
        7,
        True,
        None,
    ):
        held.inspect(innocent, "innocent")
    original[:] = bytes(64)  # once wiped, the recorded buffer is no secret
    held.inspect(original, "wiped")
    return held


def test_the_stray_detector_flags_every_copy_kind_and_only_those() -> None:
    """RANGE: each kind of second copy is flagged; the buffer, zeros and near misses are not."""
    assert len(_stray_kinds()) == 13
    assert _inspect_innocents().strays == []


def test_the_probe_scans_the_locals_of_watched_frames_only() -> None:
    """PIN: a copy bound to a local, or one level down in a container, is seen in watched files."""

    def holder(held: _Held) -> None:
        secret = held[0][0]
        _copy = bytes(secret)
        _list = [bytes(secret)]
        _tuple = (1, bytes(secret))
        _dict = {"k": bytes(secret)}
        _key = {bytes(secret): 1}
        _set = {bytes(secret)}
        len(_copy)

    held = _Held()
    held.append((bytearray(_SECRET), _SECRET))
    with _Probe(held, _source(holder)):
        holder(held)
    for name in ("_copy", "_list", "_tuple", "_dict", "_key", "_set"):
        assert any(f"local '{name}'" in stray for stray in held.strays), name

    unwatched = _Held()
    unwatched.append((bytearray(_SECRET), _SECRET))
    with _Probe(unwatched, ["/nonexistent.py"]):
        holder(unwatched)
    assert unwatched.strays == []


def test_the_index_follows_secrets_recorded_after_it_was_built() -> None:
    """PIN: a secret recorded after the first inspection is flagged on the next one."""
    held = _Held()
    first, second = bytearray(_SECRET), bytearray(range(100, 164))
    held.append((first, bytes(first)))
    held.inspect(bytes(second), "before it is recorded")
    assert held.strays == []
    held.inspect(bytes(first), "first")
    assert len(held.strays) == 1
    held.append((second, bytes(second)))
    held.inspect(bytes(second), "second")
    assert len(held.strays) == 2


def _stray_at(held: _Held, where: str) -> list[str]:
    return [stray for stray in held.strays if where in stray]


def test_wrap_inspects_every_argument_it_forwards(monkeypatch: pytest.MonkeyPatch) -> None:
    """PIN: ``_wrap`` flags a copy passed positionally, by keyword or inside a container."""
    name = "_argument_channel_target"
    monkeypatch.setattr(pb, name, lambda *a, **k: None, raising=False)
    held = _Held()
    held.append((bytearray(_SECRET), _SECRET))
    _wrap(monkeypatch, name, held)
    target = getattr(pb, name)
    target(1, bytes(_SECRET))
    target(key=bytearray(_SECRET))
    target([bytes(_SECRET)])
    assert len(_stray_at(held, f"argument of {name}")) == 3


def test_comparator_spy_inspects_both_operands(monkeypatch: pytest.MonkeyPatch) -> None:
    """PIN: the comparator spy flags a copy as the first operand and as the second."""
    module = types.SimpleNamespace(compare=lambda a, b: bytes(a) == bytes(b))
    held = _Held()
    secret = bytearray(_SECRET)
    held.append((secret, bytes(secret)))
    _spy_comparator(monkeypatch, held, module, "compare")
    module.compare(bytes(_SECRET), secret)
    module.compare(secret, bytes(_SECRET))
    assert len(_stray_at(held, "first argument of compare")) == 1
    assert len(_stray_at(held, "second argument of compare")) == 1


def test_ed25519_sign_wrapper_inspects_the_key_it_signs_with(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN: a copy of the secret key handed to ``sign`` is flagged by the sign wrapper alone."""

    def leaky_kat() -> tuple[bool, str]:
        _, sk = pb.native_ed25519_keypair_from_seed(bytearray(range(32)))
        pb.native_ed25519_sign(b"", bytes(sk))
        return True, "leaky"

    run = _run_ed(monkeypatch, kat=leaky_kat, watch=[])
    assert _stray_at(run.held, "argument of native_ed25519_sign")


def _publish(held: _Held, kat: str) -> None:
    """Let the vector's own hex text (published NIST data) be bound to a name."""
    held.allowed_text = {v for v in st._load_post_kat(kat).values() if isinstance(v, str)}


def _assert_no_strays(run: Any) -> None:
    assert not run.held.strays, "a second copy of a secret outlived its use: " + "; ".join(
        run.held.strays
    )


def _source(function: Callable[..., Any]) -> list[str]:
    """The source file ``function`` is defined in (the frames the probe scans)."""
    return [function.__code__.co_filename]


def _record_fromhex_copies(monkeypatch: pytest.MonkeyPatch, module: Any, held: _Held) -> None:
    """Record every ``bytearray.fromhex`` buffer ``module`` builds."""

    class Recording(bytearray):
        @classmethod
        def fromhex(cls, string: str) -> Any:
            buf = bytearray.fromhex(string)
            held.append((buf, bytes(buf)))
            return buf

    monkeypatch.setattr(module, "bytearray", Recording, raising=False)


def _assert_scrubbed(held: _Held, sizes: dict[int, int]) -> None:
    """Exactly ``sizes[n]`` buffers of ``n`` bytes were held, and all are zero."""
    seen: dict[int, int] = {}
    for buf, _ in held:
        seen[len(buf)] = seen.get(len(buf), 0) + 1
    assert seen == sizes, "recorded a different set of secret buffers than expected"
    for buf, snapshot in held:
        assert any(snapshot), "a recorded buffer was already zero when returned"
        assert not any(buf), f"a {len(buf)}-byte secret survived the function"


def _assert_never_hexed(held: _Held, probe: _Probe) -> None:
    secrets = {snapshot for _, snapshot in held}
    leaked = [h for h in probe.hexed if h in secrets]
    assert not leaked, f"a {len(leaked[0])}-byte secret was rendered with .hex()"
    assert probe.opaque_hex == 0 and probe.hexlify == 0


@pytest.fixture(autouse=True)
def _keep_module_operational() -> Iterator[None]:
    """A lie that leaks into a pairwise test must not poison later tests."""
    yield
    if st.module_status() != "OPERATIONAL":
        st._set_operational()


def _wrap(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    held: _Held,
    mutate: Any = None,
    only: Optional[Callable[..., bool]] = None,
) -> Log:
    """Patch ``pb.<name>``; record every bytearray it returns, and its calls.

    ``only`` restricts the lie, the recording and the call log to the KAT's
    own call: keygen runs a pairwise test (INVARIANT-41) through the same
    name, which must stay honest and unrecorded.
    """
    real = getattr(pb, name)
    log: Log = []

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        mine = only is None or only(*args)
        for arg in (*args, *kwargs.values()):
            held.scan(arg, f"argument of {name}")
        if mine and mutate == "raise":
            log.append((args, None))
            raise RuntimeError("simulated native failure")
        result = real(*args, **kwargs)
        if mine:
            if callable(mutate):
                result = mutate(result)
            log.append((args, result))
            for item in result if isinstance(result, tuple) else (result,):
                if isinstance(item, bytearray):
                    held.append((item, bytes(item)))
        return result

    monkeypatch.setattr(pb, name, wrapper)
    return log


def _spy_comparator(
    monkeypatch: pytest.MonkeyPatch,
    held: _Held,
    module: Any,
    attr: str,
    refuse: Optional[Callable[[Any], bool]] = None,
) -> list[tuple[Any, bytes]]:
    """Spy on a constant-time comparator: log ``(a, bytes(b))``, optionally refuse.

    ``refuse(a)`` returning true makes the comparator say "different" for that
    first argument, so a verdict that does not come from it is exposed.
    """
    real = getattr(module, attr)
    assert real is not None
    calls: list[tuple[Any, bytes]] = []

    def spy(a: Any, b: Any) -> bool:
        held.scan(a, f"first argument of {attr}")
        held.scan(b, f"second argument of {attr}")
        calls.append((a, bytes(b)))
        if refuse is not None and refuse(a):
            return False
        return bool(real(a, b))

    monkeypatch.setattr(module, attr, spy)
    return calls


def _flip_sk(result: Any) -> Any:
    pk, sk = result
    sk[0] ^= 0x01
    return pk, sk


def _flip_pk(result: Any) -> Any:
    pk, sk = result
    return bytes([pk[0] ^ 0x01]) + bytes(pk[1:]), sk


def _flip_ss(result: Any) -> Any:
    result[0] ^= 0x01
    return result


def _calls_with(calls: list[tuple[Any, bytes]], obj: Any) -> list[bytes]:
    return [b for a, b in calls if a is obj]


# --------------------------------------------------------------------------
# ML-KEM-1024
# --------------------------------------------------------------------------

# exit -> (ok, text, keygen lie, decaps lie, buffers by size,
#          bytes.fromhex calls, bytearray.fromhex calls)
# bytes.fromhex is the ciphertext only (public); bytearray.fromhex is d, z,
# the expected sk and the expected ss, each only once the KAT reaches it.
_KEM: dict[str, Any] = {
    "pass": (True, "passed", None, None, {3168: 2, 32: 4}, 1, 4),
    "pk_mismatch": (
        False,
        "keygen public key != NIST known answer",
        _flip_pk,
        None,
        {3168: 1, 32: 2},
        0,
        2,
    ),
    "sk_mismatch": (
        False,
        "keygen secret key != NIST known answer",
        _flip_sk,
        None,
        {3168: 2, 32: 2},
        0,
        3,
    ),
    "ss_mismatch": (
        False,
        "decapsulated secret != NIST known answer",
        None,
        _flip_ss,
        {3168: 2, 32: 4},
        1,
        4,
    ),
    "decaps_raises": (False, "exception", None, "raise", {3168: 2, 32: 2}, 1, 3),
}


class _Run:
    """Everything one instrumented KAT run produced."""

    passed: Optional[bool]
    detail: str
    held: _Held
    probe: _Probe
    keygen: Log
    decaps: Log
    compared: list[tuple[Any, bytes]]


def _run_kem(
    monkeypatch: pytest.MonkeyPatch,
    exit_path: str = "pass",
    refuse_sk: bool = False,
    refuse_ss: bool = False,
) -> _Run:
    if not pb.KYBER_AVAILABLE:
        pytest.skip("ML-KEM backend unavailable")
    _, _, keygen_mut, decaps_mut, _, _, _ = _KEM[exit_path]
    run = _Run()
    run.held = _Held()
    _publish(run.held, "ml_kem_1024_kat.json")
    _record_fromhex_copies(monkeypatch, st, run.held)
    run.keygen = _wrap(monkeypatch, "native_ml_kem_keypair_from_seed", run.held, keygen_mut)
    vector_ct = bytes.fromhex(st._load_post_kat("ml_kem_1024_kat.json")["ct_hex"])
    run.decaps = _wrap(
        monkeypatch,
        "native_ml_kem_decapsulate",
        run.held,
        decaps_mut,
        only=lambda ps, ct, sk: ct == vector_ct,
    )

    def refuse(a: Any) -> bool:
        if refuse_sk and run.keygen and a is run.keygen[0][1][1]:
            return True
        return bool(refuse_ss and run.decaps and a is run.decaps[0][1])

    run.compared = _spy_comparator(monkeypatch, run.held, ms, "_secret_comparator", refuse)
    with _Probe(run.held, _source(st._kat_ml_kem_1024)) as run.probe:
        run.passed, run.detail = st._kat_ml_kem_1024()
    return run


@pytest.mark.parametrize("exit_path", list(_KEM))
def test_ml_kem_kat_scrubs_every_secret(monkeypatch: pytest.MonkeyPatch, exit_path: str) -> None:
    """PIN: d, z, sk, ss and the expected copies are zero after any exit."""
    want_ok, want_text, _, _, sizes, _, _ = _KEM[exit_path]
    run = _run_kem(monkeypatch, exit_path)
    assert run.passed is want_ok and want_text in run.detail
    _assert_scrubbed(run.held, sizes)


@pytest.mark.parametrize("exit_path", list(_KEM))
def test_ml_kem_kat_never_renders_a_secret_as_hex(
    monkeypatch: pytest.MonkeyPatch, exit_path: str
) -> None:
    """No recorded secret passes through ``.hex()``; the public key does (probe is live)."""
    run = _run_kem(monkeypatch, exit_path)
    assert any(len(h) == 1568 for h in run.probe.hexed), "the probe saw no hex render at all"
    _assert_never_hexed(run.held, run.probe)


@pytest.mark.parametrize("exit_path", list(_KEM))
def test_ml_kem_kat_makes_no_immutable_copy_of_a_secret(
    monkeypatch: pytest.MonkeyPatch, exit_path: str
) -> None:
    """Only the public ciphertext goes through ``bytes.fromhex``; secrets are bytearrays.

    A ``bytes.fromhex`` of the sk, of d or z, or of the vector's ss is an
    immutable copy nothing can wipe, and raises the count by one.
    """
    _, _, _, _, _, n_bytes, n_bytearray = _KEM[exit_path]
    run = _run_kem(monkeypatch, exit_path)
    assert run.probe.fromhex == {"bytes": n_bytes, "bytearray": n_bytearray}


@pytest.mark.parametrize("exit_path", list(_KEM))
def test_ml_kem_kat_keeps_no_second_copy_of_a_secret(
    monkeypatch: pytest.MonkeyPatch, exit_path: str
) -> None:
    """No copy of d, z, sk, ss or the expected values is bound to a name, passed to a native
    or to the comparator, other than the recorded buffers themselves (see ``_Probe``)."""
    _assert_no_strays(_run_kem(monkeypatch, exit_path))


def test_ml_kem_kat_decapsulates_with_the_derived_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Decapsulation is handed the very sk object keygen returned, not a fresh copy.

    PIN: ``bytes.fromhex(v["sk_hex"])`` as the decaps argument is a second,
    immutable copy of the secret key; it is not the keygen object.
    """
    run = _run_kem(monkeypatch)
    assert run.passed is True
    assert len(run.keygen) == 1 and len(run.decaps) == 1
    sk_derived = run.keygen[0][1][1]
    assert run.decaps[0][0][2] is sk_derived


def test_ml_kem_kat_compares_secrets_through_the_registered_comparator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """sk and ss reach the constant-time comparator, against the vector's values."""
    run = _run_kem(monkeypatch)
    assert run.passed is True
    vector = st._load_post_kat("ml_kem_1024_kat.json")
    sk_derived = run.keygen[0][1][1]
    ss_derived = run.decaps[0][1]
    assert _calls_with(run.compared, sk_derived) == [bytes.fromhex(vector["sk_hex"])]
    assert _calls_with(run.compared, ss_derived) == [bytes.fromhex(vector["ss_hex"])]


@pytest.mark.parametrize(
    "which, text",
    [
        ("sk", "keygen secret key != NIST known answer"),
        ("ss", "decapsulated secret != NIST known answer"),
    ],
)
def test_ml_kem_kat_verdict_comes_from_the_comparator(
    monkeypatch: pytest.MonkeyPatch, which: str, text: str
) -> None:
    """A comparator that says "different" fails the KAT, though the bytes are equal.

    PIN against any ``==`` / ``!=`` that decides instead of the comparator:
    such a KAT would still pass here.
    """
    run = _run_kem(monkeypatch, refuse_sk=which == "sk", refuse_ss=which == "ss")
    assert run.passed is False and text in run.detail


# --------------------------------------------------------------------------
# ML-DSA-65
# --------------------------------------------------------------------------

# exit -> (ok, text, keygen lie, verify lie, buffers by size,
#          bytes.fromhex calls, bytearray.fromhex calls)
# bytes.fromhex is pk, msg, ctx, sig (all public); bytearray.fromhex is the
# seed and the expected sk.
_DSA: dict[str, Any] = {
    "pass": (True, "passed", None, None, {4032: 2, 32: 1}, 4, 2),
    "pk_mismatch": (
        False,
        "keygen public key != NIST known answer",
        _flip_pk,
        None,
        {4032: 1, 32: 1},
        0,
        1,
    ),
    "sk_mismatch": (
        False,
        "keygen secret key != NIST known answer",
        _flip_sk,
        None,
        {4032: 2, 32: 1},
        0,
        2,
    ),
    "verify_rejects": (False, "did not verify", None, "reject", {4032: 2, 32: 1}, 4, 2),
    "verify_raises": (False, "exception", None, "raise", {4032: 2, 32: 1}, 4, 2),
}


def _run_dsa(
    monkeypatch: pytest.MonkeyPatch, exit_path: str = "pass", refuse_sk: bool = False
) -> _Run:
    if not pb.DILITHIUM_AVAILABLE:
        pytest.skip("ML-DSA backend unavailable")
    _, _, keygen_mut, verify_patch, _, _, _ = _DSA[exit_path]
    run = _Run()
    run.held = _Held()
    _publish(run.held, "ml_dsa_65_kat.json")
    _record_fromhex_copies(monkeypatch, st, run.held)
    run.keygen = _wrap(monkeypatch, "native_ml_dsa_keypair_from_seed", run.held, keygen_mut)
    run.decaps = []
    if verify_patch is not None:
        real_verify = pb.native_ml_dsa_verify
        vector_sig = bytes.fromhex(st._load_post_kat("ml_dsa_65_kat.json")["sig_hex"])

        # Lie only about the vector's signature: keygen's pairwise test
        # (INVARIANT-41) verifies through the same name and must stay honest.
        def verify(ps: Any, msg: bytes, sig: bytes, pk: bytes, **kw: Any) -> bool:
            if sig == vector_sig:
                if verify_patch == "raise":
                    raise RuntimeError("simulated native failure")
                return False
            return bool(real_verify(ps, msg, sig, pk, **kw))

        monkeypatch.setattr(pb, "native_ml_dsa_verify", verify)

    def refuse(a: Any) -> bool:
        return bool(refuse_sk and run.keygen and a is run.keygen[0][1][1])

    run.compared = _spy_comparator(monkeypatch, run.held, ms, "_secret_comparator", refuse)
    with _Probe(run.held, _source(st._kat_ml_dsa_65)) as run.probe:
        run.passed, run.detail = st._kat_ml_dsa_65()
    return run


@pytest.mark.parametrize("exit_path", list(_DSA))
def test_ml_dsa_kat_scrubs_the_seed_and_secret_key(
    monkeypatch: pytest.MonkeyPatch, exit_path: str
) -> None:
    """The 32-byte seed, the 4032-byte sk and its expected copy are zero after any exit."""
    want_ok, want_text, _, _, sizes, _, _ = _DSA[exit_path]
    run = _run_dsa(monkeypatch, exit_path)
    assert run.passed is want_ok and want_text in run.detail
    _assert_scrubbed(run.held, sizes)


@pytest.mark.parametrize("exit_path", list(_DSA))
def test_ml_dsa_kat_never_renders_a_secret_as_hex(
    monkeypatch: pytest.MonkeyPatch, exit_path: str
) -> None:
    run = _run_dsa(monkeypatch, exit_path)
    assert any(len(h) == 1952 for h in run.probe.hexed), "the probe saw no hex render at all"
    _assert_never_hexed(run.held, run.probe)


@pytest.mark.parametrize("exit_path", list(_DSA))
def test_ml_dsa_kat_makes_no_immutable_copy_of_a_secret(
    monkeypatch: pytest.MonkeyPatch, exit_path: str
) -> None:
    """The seed and the expected sk are bytearrays; only public inputs use bytes.fromhex."""
    _, _, _, _, _, n_bytes, n_bytearray = _DSA[exit_path]
    run = _run_dsa(monkeypatch, exit_path)
    assert run.probe.fromhex == {"bytes": n_bytes, "bytearray": n_bytearray}


@pytest.mark.parametrize("exit_path", list(_DSA))
def test_ml_dsa_kat_keeps_no_second_copy_of_a_secret(
    monkeypatch: pytest.MonkeyPatch, exit_path: str
) -> None:
    _assert_no_strays(_run_dsa(monkeypatch, exit_path))


def test_ml_dsa_kat_compares_the_secret_key_through_the_registered_comparator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _run_dsa(monkeypatch)
    assert run.passed is True
    vector = st._load_post_kat("ml_dsa_65_kat.json")
    assert _calls_with(run.compared, run.keygen[0][1][1]) == [bytes.fromhex(vector["sk_hex"])]


def test_ml_dsa_kat_verdict_comes_from_the_comparator(monkeypatch: pytest.MonkeyPatch) -> None:
    """PIN against an ``==`` / ``!=`` that decides instead of the comparator."""
    run = _run_dsa(monkeypatch, refuse_sk=True)
    assert run.passed is False and "keygen secret key != NIST known answer" in run.detail


# --------------------------------------------------------------------------
# Ed25519
# --------------------------------------------------------------------------

_PAIRWISE_MSG = b"FIPS 140-3 Ed25519 pairwise consistency"
# exit -> (ok, text, buffers by size).  The fresh pairwise key is the second
# 64-byte buffer, present on every path that reaches the pairwise stage.
_ED: dict[str, Any] = {
    "pass": (True, "passed", {64: 2, 32: 1}),
    "pk_mismatch": (False, "public key mismatch", {64: 1, 32: 1}),
    "sig_mismatch": (False, "signature mismatch", {64: 1, 32: 1}),
    "verify_rejects": (False, "did not verify", {64: 1, 32: 1}),
    "sign_raises": (False, "exception", {64: 1, 32: 1}),
    "pairwise_sign_raises": (False, "exception", {64: 2, 32: 1}),
    "pairwise_fails": (False, "pairwise consistency test failed", {64: 2, 32: 1}),
}


def _run_ed(
    monkeypatch: pytest.MonkeyPatch,
    exit_path: str = "pass",
    kat: Callable[[], tuple[Optional[bool], str]] = st._kat_ed25519,
    watch: Optional[Iterable[str]] = None,
) -> _Run:
    if not pb._ED25519_NATIVE_AVAILABLE:
        pytest.skip("native Ed25519 unavailable")
    run = _Run()
    run.held = _Held()
    _record_fromhex_copies(monkeypatch, st, run.held)
    run.keygen = _wrap(
        monkeypatch,
        "native_ed25519_keypair_from_seed",
        run.held,
        _flip_pk if exit_path == "pk_mismatch" else None,
    )
    # The fresh pairwise key (and the pairwise stage's own seed draw).
    run.decaps = _wrap(monkeypatch, "native_ed25519_keypair", run.held)
    real_sign = pb.native_ed25519_sign
    real_verify = pb.native_ed25519_verify

    # Lie only about the KAT's own messages: keygen's pairwise test
    # (INVARIANT-41) signs and verifies others and must stay honest.
    def sign(msg: bytes, sk: Any) -> Any:
        run.held.scan(sk, "argument of native_ed25519_sign")
        if exit_path == "sign_raises" and msg == b"":
            raise RuntimeError("simulated native failure")
        if exit_path == "pairwise_sign_raises" and msg == _PAIRWISE_MSG:
            raise RuntimeError("simulated native failure")
        sig = real_sign(msg, sk)
        if exit_path == "sig_mismatch" and msg == b"":
            return bytes([sig[0] ^ 0x01]) + bytes(sig[1:])
        return sig

    def verify(sig: bytes, msg: bytes, pk: bytes) -> bool:
        if exit_path == "verify_rejects" and msg == b"":
            return False
        if exit_path == "pairwise_fails" and msg == _PAIRWISE_MSG:
            return False
        return bool(real_verify(sig, msg, pk))

    monkeypatch.setattr(pb, "native_ed25519_sign", sign)
    monkeypatch.setattr(pb, "native_ed25519_verify", verify)
    run.compared = []
    with _Probe(run.held, _source(kat) if watch is None else watch) as run.probe:
        run.passed, run.detail = kat()
    return run


@pytest.mark.parametrize("exit_path", list(_ED))
def test_ed25519_kat_scrubs_the_seed_and_both_secret_keys(
    monkeypatch: pytest.MonkeyPatch, exit_path: str
) -> None:
    """PIN: the RFC 8032 seed, its sk and the fresh pairwise sk are zero after any exit."""
    want_ok, want_text, sizes = _ED[exit_path]
    run = _run_ed(monkeypatch, exit_path)
    assert run.passed is want_ok and want_text in run.detail
    _assert_scrubbed(run.held, sizes)


@pytest.mark.parametrize("exit_path", list(_ED))
def test_ed25519_kat_never_hexes_a_secret_nor_copies_the_seed(
    monkeypatch: pytest.MonkeyPatch, exit_path: str
) -> None:
    """The seed is a bytearray; only the public pk and signature use bytes.fromhex."""
    run = _run_ed(monkeypatch, exit_path)
    _assert_never_hexed(run.held, run.probe)
    assert run.probe.fromhex == {"bytes": 2, "bytearray": 1}


@pytest.mark.parametrize("exit_path", list(_ED))
def test_ed25519_kat_keeps_no_second_copy_of_a_secret(
    monkeypatch: pytest.MonkeyPatch, exit_path: str
) -> None:
    """The seed and both secret keys reach the natives as the recorded buffers."""
    _assert_no_strays(_run_ed(monkeypatch, exit_path))


# --------------------------------------------------------------------------
# tools/build_post_kats.py
# --------------------------------------------------------------------------


def _load_build_tool() -> Any:
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parent.parent / "tools" / "build_post_kats.py"
    spec = importlib.util.spec_from_file_location("_build_post_kats_under_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# (kat, corrupt) -> (buffers by size, bytes.fromhex, bytearray.fromhex)
_TOOL: dict[tuple[str, bool], Any] = {
    ("ml_kem_1024_kat.json", False): ({3168: 2, 32: 4}, 1, 4),
    ("ml_kem_1024_kat.json", True): ({3168: 2, 32: 2}, 0, 3),
    ("ml_dsa_65_kat.json", False): ({4032: 2, 32: 1}, 4, 2),
    ("ml_dsa_65_kat.json", True): ({4032: 2, 32: 1}, 0, 2),
}


class _ToolRun:
    held: _Held
    probe: _Probe
    keygen: Log
    decaps: Log
    compared: list[tuple[Any, bytes]]
    error: Optional[RuntimeError]


def _run_tool(
    monkeypatch: pytest.MonkeyPatch, kat: str, corrupt: bool, refuse_sk: bool = False
) -> _ToolRun:
    if not (pb.KYBER_AVAILABLE and pb.DILITHIUM_AVAILABLE):
        pytest.skip("PQC backend unavailable")
    # The tool setdefault()s AMA_POST_DIAGNOSTIC_IMPORT; make monkeypatch
    # remove it again so no later subprocess test inherits it.
    monkeypatch.setenv("AMA_POST_DIAGNOSTIC_IMPORT", "1")
    monkeypatch.delenv("AMA_POST_DIAGNOSTIC_IMPORT")
    import ama_cryptography.secure_memory as sm

    tool = _load_build_tool()
    payload = st._load_post_kat(kat)
    kem = kat.startswith("ml_kem")
    run = _ToolRun()
    run.held = _Held()
    _publish(run.held, kat)
    run.decaps = []
    _record_fromhex_copies(monkeypatch, tool, run.held)
    run.keygen = _wrap(
        monkeypatch,
        "native_ml_kem_keypair_from_seed" if kem else "native_ml_dsa_keypair_from_seed",
        run.held,
        _flip_sk if corrupt else None,
    )
    if kem:
        vector_ct = bytes.fromhex(payload["ct_hex"])
        run.decaps = _wrap(
            monkeypatch,
            "native_ml_kem_decapsulate",
            run.held,
            only=lambda ps, ct, sk: ct == vector_ct,
        )

    def refuse(a: Any) -> bool:
        return bool(refuse_sk and run.keygen and a is run.keygen[0][1][1])

    run.compared = _spy_comparator(monkeypatch, run.held, sm, "constant_time_compare", refuse)
    run.error = None
    with _Probe(run.held, _source(tool._verify_against_native)) as run.probe:
        try:
            tool._verify_against_native(kat, payload)
        except RuntimeError as exc:
            run.error = exc
    return run


_TOOL_IDS = [f"{'corrupt' if c else 'valid'}-{k.split('_')[1]}" for (k, c) in _TOOL]


@pytest.mark.parametrize("kat, corrupt", list(_TOOL), ids=_TOOL_IDS)
def test_build_tool_verification_scrubs_the_secrets_it_derives(
    monkeypatch: pytest.MonkeyPatch, kat: str, corrupt: bool
) -> None:
    """PIN: the tool zeroes seeds, sk, ss and expected copies, pass or mismatch."""
    run = _run_tool(monkeypatch, kat, corrupt)
    if corrupt:
        assert run.error is not None and "sk mismatch" in str(run.error)
    else:
        assert run.error is None
    _assert_scrubbed(run.held, _TOOL[(kat, corrupt)][0])


@pytest.mark.parametrize("kat, corrupt", list(_TOOL), ids=_TOOL_IDS)
def test_build_tool_never_hexes_a_secret_nor_copies_one_immutably(
    monkeypatch: pytest.MonkeyPatch, kat: str, corrupt: bool
) -> None:
    """No secret goes through ``.hex()`` or ``bytes.fromhex`` (seeds included)."""
    run = _run_tool(monkeypatch, kat, corrupt)
    assert any(len(h) in (1568, 1952) for h in run.probe.hexed), "the probe saw no hex render"
    _assert_never_hexed(run.held, run.probe)
    _, n_bytes, n_bytearray = _TOOL[(kat, corrupt)]
    assert run.probe.fromhex == {"bytes": n_bytes, "bytearray": n_bytearray}


@pytest.mark.parametrize("kat, corrupt", list(_TOOL), ids=_TOOL_IDS)
def test_build_tool_keeps_no_second_copy_of_a_secret(
    monkeypatch: pytest.MonkeyPatch, kat: str, corrupt: bool
) -> None:
    _assert_no_strays(_run_tool(monkeypatch, kat, corrupt))


@pytest.mark.parametrize("kat", ["ml_kem_1024_kat.json", "ml_dsa_65_kat.json"])
def test_build_tool_compares_secrets_through_constant_time_compare(
    monkeypatch: pytest.MonkeyPatch, kat: str
) -> None:
    """The sk (and ss) reach ``constant_time_compare`` with the vector's values."""
    run = _run_tool(monkeypatch, kat, corrupt=False)
    assert run.error is None
    vector = st._load_post_kat(kat)
    assert _calls_with(run.compared, run.keygen[0][1][1]) == [bytes.fromhex(vector["sk_hex"])]
    if run.decaps:
        assert _calls_with(run.compared, run.decaps[0][1]) == [bytes.fromhex(vector["ss_hex"])]


@pytest.mark.parametrize("kat", ["ml_kem_1024_kat.json", "ml_dsa_65_kat.json"])
def test_build_tool_verdict_comes_from_the_comparator(
    monkeypatch: pytest.MonkeyPatch, kat: str
) -> None:
    """A refusing comparator fails a valid vector (PIN against ``==`` / ``!=``)."""
    run = _run_tool(monkeypatch, kat, corrupt=False, refuse_sk=True)
    assert run.error is not None and "sk mismatch" in str(run.error)


def test_build_tool_decapsulates_with_the_derived_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Decapsulation gets the keygen's own sk object, not ``bytes.fromhex(sk_hex)``."""
    run = _run_tool(monkeypatch, "ml_kem_1024_kat.json", corrupt=False)
    assert run.error is None
    assert len(run.decaps) == 1 and run.decaps[0][0][2] is run.keygen[0][1][1]
