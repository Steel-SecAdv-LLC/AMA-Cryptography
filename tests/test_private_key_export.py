#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Private-key exports are wipeable, byte-identical, and leave no scratch.

``to_pkcs8``, ``to_pem``, ``to_jwk``, ``to_cose``, ``private_key_to_jwk``,
``private_key_to_cose`` and ``encode_pem`` return a ``ZeroizingBytearray``.
Pinned for every algorithm family: the type, the bytes against
``tests/ref_keyformat.py``, zeroed scratch on return and on failure, and that
a failed export leaves nothing referring to the key's buffer.
"""

from __future__ import annotations

import base64
import functools
import gc
import hashlib
import json
import tracemalloc
from pathlib import Path
from typing import Any, Callable

import pytest

import ama_cryptography._module_state as ms
import ama_cryptography._secret_writer as sw
import ama_cryptography.key_formats as kf
import ama_cryptography.pqc_backends as pb
import tests.ref_keyformat as ref
from ama_cryptography import _secret_material as sm
from ama_cryptography._asn1 import cbor_encode_canonical
from ama_cryptography._secret_material import ZeroizingBytearray
from ama_cryptography.exceptions import (
    CryptoModuleError,
    KeyFormatError,
    UnsupportedKeyFormatError,
)

pytestmark = pytest.mark.skipif(pb._native_lib is None, reason="native library not built")

ALL = sorted(kf.ALGORITHMS)
CLASSICAL = [n for n in ALL if kf.ALGORITHMS[n].kind != "pq"]
PQ = [n for n in ALL if kf.ALGORITHMS[n].kind == "pq"]


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------
def make_private(name: str, *, seeded: bool = True) -> kf.PrivateKey:
    """A key of ``name``.  PQ keys carry a known seed unless ``seeded`` is
    False (then they are expandedKey-only, like one imported from such a file)."""
    alg = kf.ALGORITHMS[name]
    if alg.kind == "pq":
        seed = bytes((0x5A + i) & 0xFF for i in range(alg.pq_seed_bytes))
        assert alg.pq_param_set is not None
        if alg.pq_family == "ml-dsa":
            public, secret = pb.native_ml_dsa_keypair_from_seed(alg.pq_param_set, seed)
        else:
            public, secret = pb.native_ml_kem_keypair_from_seed(
                alg.pq_param_set, seed[:32], seed[32:]
            )
        return kf.PrivateKey(name, secret, public, seed if seeded else None)
    if name == "Ed25519":
        public, secret = pb.native_ed25519_keypair()
        return kf.PrivateKey(name, secret[:32], public)
    if name == "X25519":
        public, secret = pb.native_x25519_keypair()
        return kf.PrivateKey(name, secret, public)
    if name == "secp256k1":
        scalar = bytes(range(1, 33))
        public = pb.native_secp256k1_pubkey_decompress(
            pb.native_secp256k1_pubkey_from_privkey(scalar)
        )
        return kf.PrivateKey(name, scalar, public)
    assert alg.curve is not None
    public, secret = pb.native_nistp_keypair(alg.curve)
    return kf.PrivateKey(name, secret, public)


def pem_begin(label: str = "PRIVATE KEY") -> bytes:
    """The PEM header line.  Assembled, not written out: INVARIANT-23's scanner
    reads source text for a private-key armour line, and a test that spells one
    would be indistinguishable from a committed key (no allowlist entry is the
    answer; the header is built from its parts, as ``test_secret_scanner``'s
    own fixtures are)."""
    return ("-----" + "BEGIN " + label + "-----\n").encode("ascii")


def b64u(data: bytes | bytearray) -> str:
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def cbor_bstr_head(n: int) -> bytes:
    """RFC 8949 §3 major type 2, by threshold (not ``_asn1._cbor_head``)."""
    if n <= 23:
        return bytes([0x40 | n])
    if n <= 0xFF:
        return bytes([0x58, n])
    return bytes([0x59, n >> 8, n & 0xFF])


def expected_jwk(key: kf.PrivateKey) -> bytes:
    alg = kf.ALGORITHMS[key.algorithm]
    public = key.public().key
    if alg.kind == "okp":
        members = {"kty": "OKP", "crv": alg.okp_crv, "x": b64u(public)}
    else:
        half = alg.field_bytes
        members = {
            "kty": "EC",
            "crv": alg.jwk_crv,
            "x": b64u(public[:half]),
            "y": b64u(public[half:]),
        }
    members["d"] = b64u(key.key)
    return json.dumps(members, separators=(",", ":")).encode("ascii")


def expected_cose_by_hand(key: kf.PrivateKey) -> bytes:
    """A private COSE_Key assembled from the RFC 9052/9053 byte layout with
    literal heads: map(4|5), then labels 1, -1, -2, [-3], -4 (0x01, 0x20,
    0x21, 0x22, 0x23 -- the order of their encodings), byte strings behind
    their own heads.  Shares nothing with ``_asn1`` or the writer."""
    alg = kf.ALGORITHMS[key.algorithm]
    public = key.public().key
    d = bytes(key.key)
    assert alg.cose_crv is not None and alg.cose_crv < 24
    if alg.kind == "okp":
        return (
            bytes([0xA4, 0x01, 0x01, 0x20, alg.cose_crv, 0x21])
            + cbor_bstr_head(len(public))
            + public
            + bytes([0x23])
            + cbor_bstr_head(len(d))
            + d
        )
    half = alg.field_bytes
    x, y = public[:half], public[half:]
    return (
        bytes([0xA5, 0x01, 0x02, 0x20, alg.cose_crv, 0x21])
        + cbor_bstr_head(half)
        + x
        + bytes([0x22])
        + cbor_bstr_head(half)
        + y
        + bytes([0x23])
        + cbor_bstr_head(len(d))
        + d
    )


def pkcs8_arms(name: str) -> list[tuple[bool | None, str]]:
    alg = kf.ALGORITHMS[name]
    arms = ["auto", "seed", "expandedKey", "both"] if alg.kind == "pq" else ["auto"]
    return [(include, arm) for include in (None, True, False) for arm in arms]


def reference_pkcs8(key: kf.PrivateKey, include: bool | None, arm: str) -> bytes:
    alg = kf.ALGORITHMS[key.algorithm]
    resolved = kf.CONVENTIONAL_PUBLIC_KEY[key.algorithm] if include is None else include
    if arm == "auto":
        arm = "seed" if key.seed is not None else "expandedKey"
    return ref.pkcs8(
        key.algorithm,
        key.key,
        public_key=key.public().key if resolved else None,
        include_public_key=resolved,
        seed=key.seed,
        pq_arm=arm if alg.kind == "pq" else "expandedKey",
    )


# ---------------------------------------------------------------------------
# Type, and wire identity
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", ALL)
def test_every_private_export_is_a_zeroizing_bytearray(name: str) -> None:
    """PIN.  ``type(x) is ZeroizingBytearray`` for every private encoding of
    every algorithm the library emits.  Returning ``bytes(out)`` /
    ``out.decode()`` / a plain ``bytearray`` from any exporter, or a ``dict``
    from the JWK one, fails its row."""
    key = make_private(name)
    outputs: list[Any] = [key.to_pkcs8(), key.to_pem(), kf.encode_pem(b"\x05\x00", "X")]
    outputs.append(kf.decode_pem(key.to_pem(), "PRIVATE KEY")[1])
    if name in CLASSICAL:
        outputs += [key.to_jwk(), key.to_cose(), kf.private_key_to_jwk(key)]
        outputs.append(kf.private_key_to_cose(key))
    for out in outputs:
        assert type(out) is ZeroizingBytearray, type(out)


@pytest.mark.parametrize("name", ALL)
def test_pkcs8_and_pem_are_byte_identical_to_the_reference_encoder(name: str) -> None:
    """PIN.  Every algorithm, every ``include_public_key`` setting and every
    PQ CHOICE arm, against ``tests/ref_keyformat.py`` -- a second encoder
    written from the RFCs' ASN.1 that imports nothing from the library.  A
    wrong tag, a dropped ``[1]`` wrapper, ``seed || key`` in ``both``, or a
    mis-sized header fails the row it breaks."""
    for seeded in (True, False) if name in PQ else (True,):
        key = make_private(name, seeded=seeded)
        for include, arm in pkcs8_arms(name):
            try:
                expected = reference_pkcs8(key, include, arm)
            except ValueError:
                # The reference refuses an arm the key cannot supply.
                with pytest.raises(KeyFormatError):
                    key.to_pkcs8(include_public_key=include, pq_format=arm)
                continue
            der = key.to_pkcs8(include_public_key=include, pq_format=arm)
            assert bytes(der) == expected, (name, include, arm, seeded)
            pem = key.to_pem(include_public_key=include, pq_format=arm)
            assert bytes(pem) == ref.pem(expected, "PRIVATE KEY").encode("ascii")


@pytest.mark.parametrize("name", CLASSICAL)
def test_jwk_text_is_byte_identical_and_in_the_fixed_member_order(name: str) -> None:
    """PIN.  Compact separators and the members ``kty``, ``crv``, ``x``,
    (``y``), ``d`` in that order, exactly as the dict this replaced serialised.
    A reordering (``d`` before ``x``), a pretty-printed separator, or padding
    on ``d`` fails."""
    key = make_private(name)
    assert bytes(key.to_jwk()) == expected_jwk(key)
    assert bytes(kf.private_key_to_jwk(key)) == expected_jwk(key)


@pytest.mark.parametrize("name", CLASSICAL)
def test_cose_is_byte_identical_to_the_old_encoder_and_to_a_hand_assembly(name: str) -> None:
    """PIN.  Two oracles: the immutable ``cbor_encode_canonical`` composition
    the exporter replaced, and a hand assembly from literal CBOR heads that
    shares nothing with ``_asn1`` or the writer (there is no external vector
    for a private COSE_Key, so this is the independent check).  Swapping two
    members, a wrong byte-string head, or a wrong map count fails."""
    key = make_private(name)
    alg = kf.ALGORITHMS[key.algorithm]
    public = key.public().key
    members: dict[int, Any] = {
        1: 1 if alg.kind == "okp" else 2,
        -1: alg.cose_crv,
        -4: bytes(key.key),
    }
    if alg.kind == "okp":
        members[-2] = public
    else:
        members[-2], members[-3] = public[: alg.field_bytes], public[alg.field_bytes :]
    assert bytes(key.to_cose()) == cbor_encode_canonical(members)
    assert bytes(key.to_cose()) == expected_cose_by_hand(key)
    assert bytes(kf.private_key_to_cose(key)) == expected_cose_by_hand(key)


def test_a_p521_cose_key_uses_a_one_octet_length_head() -> None:
    """PIN of the 24..255 head: P-521's 66-octet scalar and coordinates are
    ``58 42``, the case where an off-by-one in the threshold shows."""
    key = make_private("P-521")
    encoded = bytes(key.to_cose())
    assert b"\x58\x42" in encoded and encoded == expected_cose_by_hand(key)


@pytest.mark.parametrize("name", PQ)
def test_pq_jwk_and_cose_are_still_refused(name: str) -> None:
    """RANGE.  ML-DSA/ML-KEM have no JWK or COSE encoding; the refusal is
    unchanged by the move to the writer (and happens before any allocation)."""
    key = make_private(name)
    for call in (key.to_jwk, key.to_cose):
        with pytest.raises(UnsupportedKeyFormatError, match="no standardised"):
            call()


@pytest.mark.parametrize("name", ["Ed25519", "P-256"])
def test_public_outputs_keep_their_immutable_types(name: str) -> None:
    """SMOKE.  A public key holds no secret: SPKI/COSE stay ``bytes``, the PEM
    a ``str``, the JWK a ``dict``."""
    public = make_private(name).public()
    assert type(public.to_spki()) is bytes
    assert type(public.to_cose()) is bytes
    assert type(public.to_pem()) is str
    assert type(public.to_jwk()) is dict
    assert public.to_pem().startswith("-----BEGIN PUBLIC KEY-----\n")


def test_encode_pem_returns_a_bytearray_for_public_data_too() -> None:
    """SMOKE (a contract consequence, documented): ``encode_pem`` cannot tell
    a public DER from a private one, so it has one return type."""
    out = kf.encode_pem(make_private("Ed25519").public().to_spki(), "PUBLIC KEY")
    assert type(out) is ZeroizingBytearray and bytes(out).startswith(
        b"-----BEGIN PUBLIC KEY-----\n"
    )
    with pytest.raises(KeyFormatError, match="ASCII"):
        kf.encode_pem(b"\x05\x00", "KÉY")


@pytest.mark.parametrize("size", [0, 1, 47, 48, 49, 96, 4059])
def test_encode_pem_wraps_at_64_for_any_length(size: int) -> None:
    """RANGE.  Against the stdlib folding in ``tests/ref_keyformat.pem``."""
    der = bytes((i * 31 + 7) & 0xFF for i in range(size))
    assert bytes(kf.encode_pem(der, "TEST")) == ref.pem(der, "TEST").encode("ascii")


# ---------------------------------------------------------------------------
# The contract's consequences, listed so none is a surprise
# ---------------------------------------------------------------------------
def test_the_consequences_of_a_bytearray_are_loud_where_they_can_be() -> None:
    """SMOKE.  ``hash``, ``write_text``, ``json.dumps``, ``str`` methods raise
    ``TypeError``; ``isinstance(x, bytes)`` is False (not an error); ``==``
    against a ``str`` is silently False; ``==`` against ``bytes`` holds; the
    explicit conversions work."""
    key = make_private("Ed25519")
    pem = key.to_pem()
    with pytest.raises(TypeError):
        hash(pem)
    with pytest.raises(TypeError):
        json.dumps(key.to_jwk())
    starts: Any = pem
    with pytest.raises(TypeError):
        starts.startswith("-----BEGIN")
    assert not isinstance(pem, bytes)
    left: Any = pem
    assert not left == pem.decode("ascii")
    assert left == bytes(pem) and bytes(pem).startswith(pem_begin())
    assert pem.decode("ascii").endswith("-----END PRIVATE KEY-----\n")
    assert json.loads(bytes(key.to_jwk()))["kty"] == "OKP"


def test_write_bytes_works_and_write_text_does_not(tmp_path: Path) -> None:
    """SMOKE.  The documented idiom, and the loud failure of the old one."""
    pem = make_private("P-256").to_pem()
    (tmp_path / "k.pem").write_bytes(pem)
    assert (tmp_path / "k.pem").read_bytes() == bytes(pem)
    text_writer: Any = tmp_path / "k2.pem"
    with pytest.raises(TypeError):
        text_writer.write_text(pem, encoding="utf-8")


def test_the_export_is_equal_to_bytes_through_hashlib_and_base64() -> None:
    """SMOKE.  Interop with the stdlib consumers the documentation names."""
    der = make_private("Ed25519").to_pkcs8()
    assert hashlib.sha256(der).digest() == hashlib.sha256(bytes(der)).digest()
    assert base64.b64encode(der) == base64.b64encode(bytes(der))


# ---------------------------------------------------------------------------
# Scratch buffers: captured, then required to be zero
# ---------------------------------------------------------------------------
class Captured:
    """Every scratch buffer an export allocates, with a snapshot of what it
    held when it was handed back (so a buffer that was never filled cannot
    pass as a zeroed one)."""

    def __init__(self) -> None:
        self.encoded: list[tuple[bytearray, bytes]] = []  # Base64 output
        self.inputs: list[tuple[bytearray, bytes]] = []  # buffers passed to the codec
        self.outputs: list[ZeroizingBytearray] = []  # buffers `build` allocated

    def scratch(self, *owned: Any) -> list[bytearray]:
        """Everything captured except what the caller owns: the returned value
        and the key's own buffer (which the codec reads in place)."""
        every = [b for b, _ in self.encoded] + [b for b, _ in self.inputs] + self.outputs
        return [b for b in every if not any(b is mine for mine in owned)]


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> Captured:
    cap = Captured()
    real_encode = pb.native_base64_encode

    def encode(data: Any, variant: int) -> bytearray:
        out = real_encode(data, variant)
        cap.encoded.append((out, bytes(out)))
        if isinstance(data, bytearray):
            cap.inputs.append((data, bytes(data)))
        return out

    class Recording(ZeroizingBytearray):
        def __init__(self, *args: Any) -> None:
            super().__init__(*args)
            cap.outputs.append(self)

    monkeypatch.setattr(pb, "native_base64_encode", encode)
    monkeypatch.setattr(sw, "ZeroizingBytearray", Recording)
    return cap


EXPORTS: dict[str, tuple[str, Callable[[kf.PrivateKey], Any]]] = {
    "to_pkcs8": ("Ed25519", lambda k: k.to_pkcs8()),
    "to_pem": ("P-256", lambda k: k.to_pem()),
    "to_jwk": ("P-256", lambda k: k.to_jwk()),
    "to_cose": ("P-256", lambda k: k.to_cose()),
    "encode_pem": ("Ed25519", lambda k: kf.encode_pem(bytes(range(200)), "PRIVATE KEY")),
}


@pytest.mark.parametrize("export", sorted(EXPORTS))
def test_every_scratch_buffer_is_zero_when_the_export_returns(
    captured: Captured, export: str
) -> None:
    """PIN.  The Base64 characters, the intermediate DER and the intermediate
    build outputs, held by this test, are zero when the export returns."""
    name, run = EXPORTS[export]
    key = make_private(name)
    result = run(key)
    assert any(result), "the export is empty"
    for _buffer, snapshot in captured.encoded + captured.inputs:
        assert any(snapshot), "a captured scratch buffer was never filled"
    leftovers = [b for b in captured.scratch(result, key.key) if any(b)]
    assert not leftovers, f"{len(leftovers)} scratch buffer(s) still hold data"
    if export in ("to_pem", "to_jwk", "encode_pem"):
        assert captured.encoded, "the export did not go through the native codec"


INJECTIONS: dict[str, tuple[str, str, Callable[[kf.PrivateKey], Any]]] = {
    "to_pkcs8": ("Sec", "Ed25519", lambda k: k.to_pkcs8()),
    "to_pem": ("Wrapped", "P-256", lambda k: k.to_pem()),
    "to_jwk": ("Sec", "P-256", lambda k: k.to_jwk()),
    "to_cose": ("Sec", "P-256", lambda k: k.to_cose()),
}


@pytest.mark.parametrize("export", sorted(INJECTIONS))
def test_every_scratch_buffer_is_zero_after_a_failure_mid_write(
    captured: Captured, monkeypatch: pytest.MonkeyPatch, export: str
) -> None:
    """PIN.  When the write raises after the secret is in the output and the
    scratch, the output, the characters and the intermediate DER are all zero."""
    piece, name, run = INJECTIONS[export]
    real = getattr(sw, piece).write

    def write_then_fail(self: Any, out: memoryview, at: int) -> int:
        real(self, out, at)
        raise RuntimeError("injected failure")

    monkeypatch.setattr(getattr(sw, piece), "write", write_then_fail)
    key = make_private(name)
    with pytest.raises(RuntimeError, match="injected failure"):
        run(key)
    assert captured.outputs, "no output buffer was allocated before the failure"
    leftovers = [b for b in captured.scratch(key.key) if any(b)]
    assert not leftovers, f"{len(leftovers)} buffer(s) still hold data after the failure"
    if export in ("to_pem", "to_jwk"):
        assert captured.encoded and any(captured.encoded[0][1])


# ---------------------------------------------------------------------------
# A failed export leaves nothing that outlives the key's own wipe
# ---------------------------------------------------------------------------
def _failing_exports() -> dict[str, tuple[str, str, Callable[[kf.PrivateKey], Any]]]:
    return {
        "to_pkcs8": ("Sec", "P-256", lambda k: k.to_pkcs8()),
        "to_pem": ("Wrapped", "P-256", lambda k: k.to_pem()),
        "to_jwk": ("Sec", "P-256", lambda k: k.to_jwk()),
        "to_cose": ("Sec", "P-256", lambda k: k.to_cose()),
        "to_pkcs8 (ML-DSA-65)": ("Sec", "ML-DSA-65", lambda k: k.to_pkcs8()),
        # The seed is a second secret buffer the PrivateKey owns and wipes
        # (INVARIANT-6); the arms that write it are the ones that could make a
        # piece hold it.  `auto` resolves to `seed` for a seeded key, so the
        # row above already writes the seed -- these name the arms outright.
        "to_pkcs8 seed (ML-DSA-65)": (
            "Sec",
            "ML-DSA-65",
            lambda k: k.to_pkcs8(pq_format="seed"),
        ),
        "to_pkcs8 both (ML-DSA-65)": (
            "Sec",
            "ML-DSA-65",
            lambda k: k.to_pkcs8(pq_format="both"),
        ),
        "to_pkcs8 expandedKey (ML-DSA-65)": (
            "Sec",
            "ML-DSA-65",
            lambda k: k.to_pkcs8(pq_format="expandedKey"),
        ),
        "to_pkcs8 seed (ML-KEM-1024)": (
            "Sec",
            "ML-KEM-1024",
            lambda k: k.to_pkcs8(pq_format="seed"),
        ),
        "to_pkcs8 both (ML-KEM-1024)": (
            "Sec",
            "ML-KEM-1024",
            lambda k: k.to_pkcs8(pq_format="both"),
        ),
        "to_pem seed (ML-KEM-1024)": (
            "Wrapped",
            "ML-KEM-1024",
            lambda k: k.to_pem(pq_format="seed"),
        ),
    }


def _secret_buffers(key: kf.PrivateKey) -> dict[str, bytes | bytearray]:
    """The buffers a key owns and wipes: its secret key, and its seed if any."""
    owned: dict[str, bytes | bytearray] = {"key": key.key}
    if key.seed is not None:
        owned["seed"] = key.seed
    return owned


@pytest.mark.parametrize("export", sorted(_failing_exports()))
def test_nothing_but_the_key_refers_to_its_buffer_after_a_failed_export(
    monkeypatch: pytest.MonkeyPatch, export: str
) -> None:
    """PIN.  With the exception and its frames alive, only the key refers to its
    buffer and to its seed's, so dropping the key still wipes them."""
    piece, name, run = _failing_exports()[export]

    def fail(self: Any, out: memoryview, at: int) -> int:
        raise RuntimeError("injected failure")

    monkeypatch.setattr(getattr(sw, piece), "write", fail)
    key = make_private(name)
    try:
        run(key)
    except RuntimeError as exc:
        kept = exc
    gc.collect()
    # Iterate names first and re-fetch each buffer through a transient mapping
    # that is freed before ``get_referrers`` runs.  Holding the ``_secret_buffers``
    # mapping (or its ``items()`` tuples) alive across the check would itself
    # refer to each buffer; Python 3.14 surfaces those as referrers where 3.13
    # did not, so the loop must not keep them.  What remains is the key's own
    # ``__dict__`` and the live test frame -- any library object retaining the
    # buffer still appears and fails the assertion (the PIN).
    for which in list(_secret_buffers(key)):
        buffer = _secret_buffers(key)[which]
        gc.collect()
        stray = [
            r
            for r in gc.get_referrers(buffer)
            if r is not key.__dict__ and type(r).__name__ != "frame"
        ]
        assert not stray, (which, sorted({type(r).__name__ for r in stray}))
    assert kept.__traceback__ is not None


@pytest.mark.parametrize("retained", ["exception", "piece tree"])
@pytest.mark.parametrize("export", sorted(_failing_exports()))
def test_dropping_a_key_after_a_failed_export_still_wipes_it(
    monkeypatch: pytest.MonkeyPatch, export: str, retained: str
) -> None:
    """The last-owner wipe reads the key buffer's reference count, so after a
    failed export the buffer carries no extra reference.  ``retained="piece tree"``
    is PIN (a piece binding a buffer makes the key die first and skip the wipe);
    ``retained="exception"`` is SMOKE."""
    piece, name, run = _failing_exports()[export]

    def fail(self: Any, out: memoryview, at: int) -> int:
        raise RuntimeError("injected failure")

    monkeypatch.setattr(getattr(sw, piece), "write", fail)
    key = make_private(name)
    targets = {which: id(buffer) for which, buffer in _secret_buffers(key).items()}
    seen: set[int] = set()
    real_zero = sm._zero

    def spy(value: Any) -> None:
        seen.add(id(value))
        real_zero(value)

    monkeypatch.setattr(sm, "_zero", spy)
    kept: Any = None
    try:
        run(key)
    except RuntimeError as exc:
        if retained == "exception":
            kept = exc
        else:
            # The root of the description of the failed write: the `piece` that
            # `build` was given, found in the frame that holds it.
            walk = exc.__traceback__
            while walk is not None:
                if walk.tb_frame.f_code.co_name == "build":
                    kept = walk.tb_frame.f_locals["piece"]
                walk = walk.tb_next
            assert kept is not None, "no build() frame in the traceback"
    del key
    gc.collect()
    kept = None
    gc.collect()
    unwiped = sorted(which for which, target in targets.items() if target not in seen)
    assert not unwiped, f"the dropped key's {unwiped} buffer was not zeroed by its finalizer"


# ---------------------------------------------------------------------------
# What the writer reads from: the key's own buffer or a codec scratch, never a copy
# ---------------------------------------------------------------------------
@pytest.fixture
def sources(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Every object a ``Sec`` or ``Wrapped`` was given to write from, in order,
    recorded at the moment the writer reads it."""
    seen: list[Any] = []
    real_init = sw.Sec.__init__

    def init(self: Any, source: Callable[[], Any]) -> None:
        def spy() -> Any:
            secret = source()
            seen.append(secret)
            return secret

        real_init(self, spy)

    monkeypatch.setattr(sw.Sec, "__init__", init)
    return seen


def _label(secret: Any, key: kf.PrivateKey, captured: Captured) -> str:
    if secret is key.key:
        return "key"
    if key.seed is not None and secret is key.seed:
        return "seed"
    if any(secret is scratch for scratch, _ in captured.encoded):
        return "scratch"
    return f"STRAY {type(secret).__name__}[{len(secret)}]"


def _pkcs8_reads(key: kf.PrivateKey, arm: str) -> set[str]:
    if key.algorithm not in PQ:
        return {"key"}
    return {
        "auto": {"seed"},
        "seed": {"seed"},
        "expandedKey": {"key"},
        "both": {"seed", "key"},
    }[arm]


@pytest.mark.parametrize("name", ALL)
def test_every_octet_the_writer_reads_comes_from_the_keys_own_buffer_or_a_codec_scratch(
    captured: Captured, sources: list[Any], name: str
) -> None:
    """PIN.  Each ``Sec`` and ``Wrapped`` reads from the key's buffer, its seed's,
    or a native codec's output, by identity; a mutable copy is a stray.  The set
    of origins is also checked per encoding."""
    key = make_private(name)
    arms = ["auto", "seed", "expandedKey", "both"] if name in PQ else ["auto"]
    calls: list[tuple[str, Callable[[], Any], set[str]]] = []
    for arm in arms:
        reads = _pkcs8_reads(key, arm)
        calls.append((f"to_pkcs8({arm})", functools.partial(key.to_pkcs8, pq_format=arm), reads))
        calls.append(
            (f"to_pem({arm})", functools.partial(key.to_pem, pq_format=arm), reads | {"scratch"})
        )
    if name in CLASSICAL:
        calls.append(("to_jwk", key.to_jwk, {"scratch"}))
        calls.append(("to_cose", key.to_cose, {"key"}))
    for label, run, expected in calls:
        sources.clear()
        captured.encoded.clear()
        result = run()
        found = {_label(secret, key, captured) for secret in sources}
        assert found == expected, (name, label, sorted(found))
        assert result, "the export is empty"


@pytest.mark.parametrize(
    ("export", "which"),
    [
        ("to_pkcs8", "key"),
        ("to_pem", "key"),
        ("to_jwk", "key"),
        ("to_cose", "key"),
        ("to_pkcs8", "seed"),
        ("to_pem", "seed"),
    ],
)
def test_an_export_refuses_a_key_whose_buffer_is_not_a_bytearray(export: str, which: str) -> None:
    """PIN.  A key whose field was replaced by ``bytes`` is refused by
    ``_secret_buffer`` in every exporter rather than copied into the output."""
    if which == "seed":
        key = make_private("ML-DSA-65")  # a PQ key: the seed rows are PKCS#8 and PEM only
        run: Callable[[], Any] = functools.partial(getattr(key, export), pq_format="seed")
    else:
        key = make_private("P-256")
        run = getattr(key, export)
    object.__setattr__(key, which, bytes(getattr(key, which)))
    with pytest.raises(TypeError, match="held in a bytearray"):
        run()


# ---------------------------------------------------------------------------
# The error state refuses before anything is allocated
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("export", sorted(INJECTIONS))
def test_a_module_in_the_error_state_exports_nothing_and_allocates_nothing(
    captured: Captured, monkeypatch: pytest.MonkeyPatch, export: str
) -> None:
    """PIN.  FIPS 140-3 §4.9.2: while the module is in the error state no
    secret key leaves it, and the refusal comes *before* the first scratch
    allocation.  Moving ``check_crypto_permitted()`` after the first allocation
    fails the allocation check; deleting it fails the raise."""
    _, name, run = INJECTIONS[export]
    key = make_private(name)
    monkeypatch.setattr(ms, "_MODULE_STATE", "ERROR")
    monkeypatch.setattr(ms, "_ERROR_REASON", "simulated POST failure")
    with pytest.raises(CryptoModuleError):
        run(key)
    assert captured.outputs == [] and captured.encoded == []


@pytest.mark.parametrize("export", ["to_jwk", "to_pem", "to_pkcs8", "to_cose"])
def test_a_module_in_the_error_state_refuses_before_it_reaches_the_codec_or_the_writer(
    monkeypatch: pytest.MonkeyPatch, export: str
) -> None:
    """PIN.  The exporter's own ``check_crypto_permitted()`` runs first: neither
    the native Base64 codec nor the writer is reached (both replaced by tripwires)."""
    key = make_private("P-256")

    def tripwire(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("an export in the error state reached the codec or the writer")

    monkeypatch.setattr(pb, "native_base64_encode", tripwire)
    monkeypatch.setattr(sw, "build", tripwire)
    monkeypatch.setattr(kf, "build", tripwire)
    monkeypatch.setattr(ms, "_MODULE_STATE", "ERROR")
    monkeypatch.setattr(ms, "_ERROR_REASON", "simulated POST failure")
    with pytest.raises(CryptoModuleError):
        getattr(key, export)()


# ---------------------------------------------------------------------------
# Volume: the output, and nothing the size of the key beside it
# ---------------------------------------------------------------------------
# A fixed slack cannot tell a key-sized copy from interpreter noise on every
# Python (a ctypes call alone allocates several KiB), so the volume is measured
# as a SLOPE: the same export of a small and of a large key of one family
# differs in peak allocation by exactly the difference in the buffers the
# encoding legitimately holds -- whatever constant overhead the platform has
# cancels.  A key-sized copy at any layer adds its size to the large key and
# not to the small one, and the difference grows by it.
SLACK = 512
FAMILIES = [("ML-DSA-44", "ML-DSA-87"), ("ML-KEM-512", "ML-KEM-1024")]


def _peak_extra(make: Callable[[], Any]) -> tuple[int, Any]:
    gc.collect()
    tracemalloc.start()
    try:
        baseline = tracemalloc.get_traced_memory()[0]
        tracemalloc.reset_peak()
        result = make()
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    return peak - baseline, result


@pytest.mark.parametrize(("small", "large"), FAMILIES)
def test_a_pkcs8_allocates_its_output_and_no_second_copy(small: str, large: str) -> None:
    """PIN.  Building the DER costs the output and nothing that scales with the
    key beside it: the peak grows by exactly the DER's growth.  A ``bytes``
    intermediate of the key's size at any layer, or a ``bytes`` right-hand
    side in the final copy, makes it grow by twice that.  Platform-independent:
    ``tracemalloc`` counts Python allocations."""

    def measure(name: str) -> tuple[int, int]:
        key = make_private(name, seeded=False)
        key.to_pkcs8()  # warm every lazy structure
        extra, der = _peak_extra(key.to_pkcs8)
        return extra, len(der)

    peaks = [measure(small), measure(large)]
    (extra_small, size_small), (extra_large, size_large) = peaks
    assert size_large - size_small > 1000, "the two keys must differ enough to measure"
    assert extra_large - extra_small <= (size_large - size_small) + SLACK, peaks


@pytest.mark.parametrize(("small", "large"), FAMILIES)
def test_a_pem_allocates_der_characters_and_text_once_each(
    monkeypatch: pytest.MonkeyPatch, small: str, large: str
) -> None:
    """PIN.  A PEM allocates the intermediate DER, the Base64 characters and the
    text once each, and nothing else the size of the key."""

    def measure(name: str) -> tuple[int, int]:
        key = make_private(name, seeded=False)
        key.to_pem()
        template = bytes(pb.native_base64_encode(key.to_pkcs8(), pb.BASE64_STANDARD_PADDED))
        with monkeypatch.context() as patch:
            patch.setattr(
                pb, "native_base64_encode", lambda data, variant, t=template: bytearray(t)
            )
            extra, pem = _peak_extra(key.to_pem)
        # The DER, the characters, the text.  `zeroize` no longer allocates an
        # all-zero operand the size of what it wipes (it copies a fixed run), so
        # nothing else is alive beside them; restoring `bytes(len(value))` there
        # adds `len(template)` to the large key's peak and fails the bound.
        return extra, len(key.to_pkcs8()) + len(template) + len(pem)

    peaks = [measure(small), measure(large)]
    (extra_small, held_small), (extra_large, held_large) = peaks
    assert held_large - held_small > 1000
    assert extra_large - extra_small <= (held_large - held_small) + SLACK, peaks
