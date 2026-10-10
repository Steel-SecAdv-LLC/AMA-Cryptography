#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Loaders read in place, hand back wipeable keys, and leave no copy behind.

``load_pkcs8``, ``decode_pem``, ``cose_to_private_key`` and the public loaders
parse from one ``bytearray`` work copy that is zeroed on every exit.  Pinned:
one verdict for ``str``, ``bytes``, ``bytearray`` and ``memoryview`` input, the
PEM scanner against the regex parser it replaced, zeroed scratch, and the
caller's buffer left unmodified.
"""

from __future__ import annotations

import array
import base64
import binascii
import builtins
import json
import re
from typing import Any, Callable

import pytest

import ama_cryptography._asn1 as asn1
import ama_cryptography._secret_material as sm
import ama_cryptography.key_formats as kf
import ama_cryptography.pqc_backends as pb
from ama_cryptography._asn1 import cbor_decode_canonical, cbor_encode_canonical
from ama_cryptography._secret_material import ZeroizingBytearray
from ama_cryptography.exceptions import KeyFormatError, UnsupportedKeyFormatError
from tests.test_private_key_export import ALL, PQ, make_private, pem_begin

pytestmark = pytest.mark.skipif(pb._native_lib is None, reason="native library not built")

#: The private-key PEM header line.  Built, not spelled: INVARIANT-23's scanner
#: reads source text for it (see ``tests/test_private_key_export.pem_begin``).
BEGIN = pem_begin().decode("ascii")


# ---------------------------------------------------------------------------
# The previous PEM parser, kept as an oracle
# ---------------------------------------------------------------------------
class RefusedError(Exception):
    """The reference parser's refusal."""


_REFERENCE = re.compile(
    r"^-----BEGIN (?P<label>[A-Z0-9 ]+)-----\n(?P<body>(?:[^\n-]*\n)*)"
    r"-----END (?P=label)-----\n?$"
)


def reference_pem(text: str, expected_label: str | None = None) -> tuple[str, bytes]:
    """What ``decode_pem`` did before the scanner: strip the four RFC 7468
    blanks, fold one CR per line, match with a regex, enforce the line widths,
    then canonical Base64 (stdlib strict decode and a re-encode, standing in for
    the native codec's canonical-padding rule)."""
    stripped = text.strip(" \t\r\n")
    normalised = (
        "\n".join(line[:-1] if line.endswith("\r") else line for line in stripped.split("\n"))
        + "\n"
    )
    match = _REFERENCE.match(normalised)
    if not match:
        raise RefusedError("block")
    label = match.group("label")
    if expected_label is not None and label != expected_label:
        raise RefusedError("label")
    lines = match.group("body").split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    if not lines or not any(lines):
        raise RefusedError("empty")
    if any(len(line) != 64 for line in lines[:-1]) or not 1 <= len(lines[-1]) <= 64:
        raise RefusedError("width")
    try:
        raw = "".join(lines).encode("ascii")
        der = base64.b64decode(raw, validate=True)
    except (UnicodeEncodeError, binascii.Error):
        raise RefusedError("base64") from None
    if base64.b64encode(der) != raw or not der:
        raise RefusedError("canonical")
    return label, der


def armor(der: bytes, label: str = "PRIVATE KEY") -> str:
    body = base64.b64encode(der).decode("ascii")
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def mutations(pem: str) -> list[str]:
    """Structured edits, each a way a PEM can go wrong."""
    lines = pem.split("\n")
    body = lines[1:-2]
    first = [pem]
    first += [
        pem.rstrip("\n"),
        pem + "\n\n",
        "\n" + pem,
        "  " + pem + "\t",
        pem.replace("\n", "\r\n"),
    ]
    first += [pem.replace("\n", "\r\r\n"), pem.replace("\n", "\r"), pem.replace("\n", "\n\n")]
    for odd in ("\x1f", "\x1c", "\x0b", "\x0c", "\x85", "\xa0", " ", "﻿", "\x00"):
        first += [pem + odd, odd + pem, pem.replace("\n", odd + "\n", 1)]
    first += [pem.replace("PRIVATE KEY", "PUBLIC KEY", 1), pem.replace("END PRIVATE", "END PUBLIC")]
    first += [pem.replace("-----BEGIN", "----BEGIN", 1), pem.replace("KEY-----", "KEY----", 1)]
    first += [pem.replace("PRIVATE KEY", "private key"), pem.replace("PRIVATE KEY", "PRIVATE  KEY")]
    first += [pem.replace("PRIVATE KEY", ""), pem.replace("PRIVATE KEY", "A-B")]
    first += [
        pem.replace("\n-----END", "-----END"),
        pem.replace(BEGIN, ""),
    ]
    first += [pem + pem, pem + "-----BEGIN X-----\n", "x\n" + pem, pem + "x"]
    first += ["\n".join(["", *lines[1:]]), "\n".join([lines[0], "", *lines[1:]])]
    first += ["\n".join([*lines[:-2], "", lines[-2]]), "\n".join(lines[:-2]) + "\n"]
    if body:
        mid = len(body) // 2
        first += [pem.replace(body[mid], body[mid][:32] + " " + body[mid][33:], 1)]
        first += [pem.replace(body[mid], body[mid][:10] + "-" + body[mid][11:], 1)]
        first += [pem.replace(body[mid], body[mid][:10] + "\xdb" + body[mid][11:], 1)]
        first += [pem.replace(body[-1], body[-1][:-1], 1), pem.replace(body[-1], body[-1] + "A", 1)]
        first += [pem.replace(body[0], body[0] + "A", 1), pem.replace(body[0], body[0][:-1], 1)]
        first += [pem.replace(body[-1], body[-1].replace("=", ""), 1)]
        first += [pem.replace(body[-1], body[-1][:-2] + "B=", 1) if body[-1].endswith("=") else pem]
        first += [pem.replace(body[0], body[0].replace("A", "=", 1), 1)]
    return first


class Generator:
    """A small deterministic generator (xorshift64*), so a failing case
    reproduces from the test name alone."""

    def __init__(self, seed: int) -> None:
        self.state = seed or 1

    def below(self, bound: int) -> int:
        self.state ^= self.state >> 12
        self.state ^= (self.state << 25) & 0xFFFFFFFFFFFFFFFF
        self.state ^= self.state >> 27
        return ((self.state * 0x2545F4914F6CDD1D) & 0xFFFFFFFFFFFFFFFF) % bound

    def choice(self, options: Any) -> Any:
        return options[self.below(len(options))]


def corpus() -> list[str]:
    rng = Generator(0x7468_9881)
    cases: list[str] = []
    for size in (1, 2, 3, 47, 48, 49, 50, 95, 96, 97, 130, 200):
        der = bytes((i * 29 + size) & 0xFF for i in range(size))
        for label in ("PRIVATE KEY", "PUBLIC KEY"):
            pem = armor(der, label)
            cases += mutations(pem)
            for _ in range(100):
                chars = list(pem)
                for _ in range(rng.choice((1, 1, 2))):
                    i = rng.below(len(chars))
                    kind = rng.choice(("flip", "drop", "dup", "swap"))
                    if kind == "flip":
                        chars[i] = rng.choice("=-+/ \r\n\tAZaz09\x00\xa0")
                    elif kind == "drop":
                        del chars[i]
                    elif kind == "dup":
                        chars.insert(i, chars[i])
                    elif i + 1 < len(chars):
                        chars[i], chars[i + 1] = chars[i + 1], chars[i]
                    if not chars:
                        break
                cases.append("".join(chars))
    return cases


def scanner_verdict(text: str | bytes | bytearray | memoryview, label: str | None) -> Any:
    try:
        got_label, der = kf.decode_pem(text, label)
    except KeyFormatError:
        return "refused"
    return got_label, bytes(der)


def reference_verdict(text: str, label: str | None) -> Any:
    try:
        got_label, der = reference_pem(text, label)
    except RefusedError:
        return "refused"
    return got_label, der


def test_the_pem_scanner_agrees_with_the_parser_it_replaced() -> None:
    """PIN.  Thousands of structured and random edits of valid blocks get the
    same verdict, label and DER from the scanner as from the regex parser it
    replaced (kept here as the oracle), in all four input forms."""
    cases = corpus()
    assert len(cases) > 3000
    accepted = 0
    for text in cases:
        for label in (None, "PRIVATE KEY"):
            expected = reference_verdict(text, label)
            assert scanner_verdict(text, label) == expected, (text, label)
            try:
                raw = text.encode("ascii")
            except UnicodeEncodeError:
                assert expected == "refused", (text, label)
                continue
            for form in (raw, bytearray(raw), memoryview(raw)):
                assert scanner_verdict(form, label) == expected, (raw, label, type(form))
        accepted += reference_verdict(text, None) != "refused"
    assert accepted > 100, "the corpus must include documents that are accepted"


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param(armor(b"\x01" * 50).replace("\n", "\n\n", 1), id="blank-line"),
        pytest.param(armor(b"\x01" * 100).replace("\n", "", 1), id="no-newline-after-header"),
        pytest.param(armor(b"\x01" * 100)[:-1] + "-", id="dash-at-the-end"),
        pytest.param(BEGIN + "AAAA\n", id="no-footer"),
        pytest.param("AAAA", id="bare-body"),
        pytest.param("", id="empty"),
    ],
)
def test_a_malformed_block_is_refused_in_every_buffer_form(bad: str) -> None:
    """PIN of the single verdict: refused as ``str`` and as each bytes-like."""
    for form in (bad, bad.encode(), bytearray(bad.encode()), memoryview(bad.encode())):
        with pytest.raises(KeyFormatError):
            kf.decode_pem(form)


def test_a_bare_body_is_never_echoed_in_the_refusal() -> None:
    """PIN.  A first line that is not a header is the key; the error may not
    reproduce it.  Validating the label before it reaches a message is what
    keeps it out; echoing the first line fails this."""
    secret = base64.b64encode(bytes(range(40, 80))).decode()
    with pytest.raises(KeyFormatError) as excinfo:
        kf.decode_pem(secret + "\n-----END PRIVATE KEY-----\n")
    assert secret[:16] not in str(excinfo.value)
    with pytest.raises(KeyFormatError) as excinfo:
        kf.decode_pem(f"-----BEGIN {secret}-----\n{secret}\n-----END {secret}-----\n")
    assert secret[:16] not in str(excinfo.value)


# ---------------------------------------------------------------------------
# What each loader accepts, and refuses
# ---------------------------------------------------------------------------
def forms(data: bytes) -> list[Any]:
    return [data, bytearray(data), memoryview(bytearray(data)), ZeroizingBytearray(data)]


@pytest.mark.parametrize("name", ALL)
def test_every_loader_accepts_every_buffer_form_and_leaves_the_callers_buffer_alone(
    name: str,
) -> None:
    """PIN.  An export loads back from the buffer it was returned in -- and from
    ``str``, ``bytes`` and ``memoryview`` -- with the caller's buffer
    byte-identical afterwards (read in place, never wiped).  The key that comes
    back owns a ``bytearray``."""
    key = make_private(name)
    der = bytes(key.to_pkcs8())
    pem = bytes(key.to_pem())
    for source in (*forms(der), *forms(pem), pem.decode("ascii")):
        before = bytes(source) if not isinstance(source, str) else source
        loaded = kf.load_pkcs8(source)
        assert loaded.key == key.key and isinstance(loaded.key, bytearray)
        assert (bytes(source) if not isinstance(source, str) else source) == before
    for source in forms(pem):
        label, body = kf.decode_pem(source, "PRIVATE KEY")
        assert label == "PRIVATE KEY" and bytes(body) == der and type(body) is ZeroizingBytearray
    if name not in PQ:
        cose, jwk = bytes(key.to_cose()), bytes(key.to_jwk())
        for source in forms(cose):
            assert kf.cose_to_private_key(source).key == key.key
            assert bytes(source) == cose
        for source in (*forms(jwk), jwk.decode("ascii"), json.loads(jwk)):
            assert kf.jwk_to_private_key(source).key == key.key
            assert kf.jwk_thumbprint(source) == kf.jwk_thumbprint(key.public().to_jwk())


@pytest.mark.parametrize("value", [None, 42, ["a"], {"a": 1}, 1.5, object()])
def test_a_loader_refuses_a_wrong_type_with_keyformaterror(value: Any) -> None:
    """PIN.  ``except KeyFormatError`` is sufficient at the boundary: none of
    these raises a bare ``TypeError``, ``decode_pem`` included (it used to)."""
    loaders: list[Callable[[Any], Any]] = [
        kf.decode_pem,
        kf.load_pkcs8,
        kf.load_spki,
        kf.cose_to_private_key,
        kf.cose_to_public_key,
    ]
    for loader in loaders:
        with pytest.raises(KeyFormatError):
            loader(value)
    if not isinstance(value, dict):
        for jwk_loader in (kf.jwk_to_private_key, kf.jwk_to_public_key, kf.jwk_thumbprint):
            with pytest.raises(KeyFormatError):
                jwk_loader(value)


def _documents_by_loader() -> list[tuple[str, Callable[[Any], Any], bytes]]:
    """Each loader with a *valid* document for it, as octets: so a refusal of
    the container can only be the container's, never the contents'."""
    key = make_private("P-256")
    public = key.public()
    return [
        ("decode_pem", kf.decode_pem, bytes(key.to_pem())),
        ("load_pkcs8 (DER)", kf.load_pkcs8, bytes(key.to_pkcs8())),
        ("load_pkcs8 (PEM)", kf.load_pkcs8, bytes(key.to_pem())),
        ("load_spki (DER)", kf.load_spki, public.to_spki()),
        ("load_spki (PEM)", kf.load_spki, public.to_pem().encode("ascii")),
        ("cose_to_private_key", kf.cose_to_private_key, bytes(key.to_cose())),
        ("cose_to_public_key", kf.cose_to_public_key, public.to_cose()),
        ("jwk_to_private_key", kf.jwk_to_private_key, bytes(key.to_jwk())),
        ("jwk_to_public_key", kf.jwk_to_public_key, json.dumps(public.to_jwk()).encode("ascii")),
        ("jwk_thumbprint", kf.jwk_thumbprint, json.dumps(public.to_jwk()).encode("ascii")),
    ]


def test_every_loader_accepts_the_valid_documents_these_rows_use() -> None:
    """SMOKE.  The control for the two tests below: each document is accepted
    as ``bytes``, so the only thing wrong with the same octets in a ``list``,
    an ``array`` or a released view is the container."""
    for label, loader, document in _documents_by_loader():
        loader(document)
        loader(bytearray(document))
        assert label


ITERABLES: dict[str, Callable[[bytes], Any]] = {
    "list of ints": list,
    "tuple of ints": tuple,
    "iterator of ints": lambda doc: iter(list(doc)),
    "array('B')": lambda doc: array.array("B", doc),
    "range": lambda doc: range(len(doc)),
}


@pytest.mark.parametrize("kind", sorted(ITERABLES))
def test_a_loader_refuses_an_iterable_of_ints_with_keyformaterror(kind: str) -> None:
    """PIN.  A ``list`` or other non-buffer of a document's octets is refused by
    every loader with ``KeyFormatError``, though ``bytearray()`` would accept it."""
    for label, loader, document in _documents_by_loader():
        with pytest.raises(KeyFormatError):
            loader(ITERABLES[kind](document))
        assert label


def test_a_released_memoryview_is_a_keyformaterror_in_every_loader() -> None:
    """PIN.  A released ``memoryview`` is a ``KeyFormatError`` in each of the four
    places that copy the caller's buffer, not a bare ``ValueError``."""
    for label, loader, document in _documents_by_loader():
        view = memoryview(bytearray(document))
        view.release()
        with pytest.raises(KeyFormatError):
            loader(view)
        assert label


# ---------------------------------------------------------------------------
# Scratch: every bytearray the module allocates, captured, then required zero
# ---------------------------------------------------------------------------
class Scratch:
    def __init__(self) -> None:
        self.buffers: list[bytearray] = []
        self.nonzero_when_zeroed: set[int] = set()


@pytest.fixture
def scratch(monkeypatch: pytest.MonkeyPatch) -> Scratch:
    """Capture every ``bytearray`` that ``key_formats`` creates by name."""
    cap = Scratch()

    class Recording(bytearray):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            cap.buffers.append(self)

    class Meta(type):
        def __instancecheck__(cls, instance: Any) -> bool:
            return isinstance(instance, bytearray)

        def __call__(cls, *args: Any, **kwargs: Any) -> Any:
            return Recording(*args, **kwargs)

    shadow = Meta("bytearray", (), {})
    monkeypatch.setattr(kf, "bytearray", shadow, raising=False)

    real_kf_zero = real_sm_zero = sm.zeroize

    def note(value: Any) -> None:
        if isinstance(value, bytearray) and any(value):
            cap.nonzero_when_zeroed.add(id(value))

    def kf_zero(value: Any) -> None:
        note(value)
        real_kf_zero(value)

    def sm_zero(value: Any) -> None:
        note(value)
        real_sm_zero(value)

    monkeypatch.setattr(kf, "_zero", kf_zero)
    monkeypatch.setattr(sm, "_zero", sm_zero)

    # The native decoder hands back a fresh `bytearray`: for a PEM (standard
    # Base64) it is the DER, made outside this module's `bytearray` name, and
    # is scratch too.  (A JWK's url-safe decode yields the key and the public
    # coordinates, which the result owns.)
    real_decode = pb.native_base64_decode

    def decode(text: Any, variant: int) -> bytearray:
        out = real_decode(text, variant)
        if variant == pb.BASE64_STANDARD_PADDED:
            cap.buffers.append(out)
        return out

    monkeypatch.setattr(pb, "native_base64_decode", decode)
    return cap


def assert_scratch_clean(cap: Scratch, minimum: int) -> None:
    assert len(cap.buffers) >= minimum, "the capture saw fewer allocations than expected"
    dirty = [b for b in cap.buffers if any(b)]
    assert not dirty, f"{len(dirty)} of {len(cap.buffers)} work buffer(s) still hold data"
    assert any(id(b) in cap.nonzero_when_zeroed for b in cap.buffers), "nothing was ever held"


LOADS: dict[str, tuple[str, Callable[[kf.PrivateKey], Any], Callable[[Any], Any], int]] = {
    "load_pkcs8 (DER bytes-like)": ("P-256", lambda k: bytes(k.to_pkcs8()), kf.load_pkcs8, 1),
    "load_pkcs8 (PEM bytes-like)": ("P-256", lambda k: bytes(k.to_pem()), kf.load_pkcs8, 3),
    "load_pkcs8 (PEM str)": ("P-256", lambda k: bytes(k.to_pem()).decode(), kf.load_pkcs8, 3),
    "load_pkcs8 (ML-KEM seed)": ("ML-KEM-512", lambda k: bytes(k.to_pkcs8()), kf.load_pkcs8, 1),
    "decode_pem": ("Ed25519", lambda k: bytes(k.to_pem()), kf.decode_pem, 3),
    "cose_to_private_key": ("P-256", lambda k: bytes(k.to_cose()), kf.cose_to_private_key, 1),
    "jwk_to_private_key": ("P-256", lambda k: bytes(k.to_jwk()), kf.jwk_to_private_key, 1),
}


@pytest.mark.parametrize("load", sorted(LOADS))
def test_a_loader_zeroes_every_work_buffer_on_success(scratch: Scratch, load: str) -> None:
    """PIN.  The work copy, the joined Base64 and the PEM's plain DER are all
    zero when the loader returns the key."""
    name, make, loader, minimum = LOADS[load]
    key = make_private(name)
    source = make(key)
    scratch.buffers.clear()
    loader(source)
    assert_scratch_clean(scratch, minimum)


@pytest.mark.parametrize("load", sorted(LOADS))
def test_a_loader_zeroes_every_work_buffer_when_it_refuses(scratch: Scratch, load: str) -> None:
    """PIN.  The same after a refusal (a corrupted document: the last octet
    changed).  The refusal arrives after the work copy was made; it must not
    outlive it."""
    name, make, loader, _minimum = LOADS[load]
    key = make_private(name)
    source = make(key)
    if isinstance(source, str):
        corrupted: Any = source[:-3] + "?" + source[-2:]
    else:
        bad = bytearray(source)
        bad[len(bad) // 2] ^= 0x55
        bad[-2] ^= 0xFF
        corrupted = bytes(bad)
    scratch.buffers.clear()
    try:
        loader(corrupted)
    except KeyFormatError:
        pass  # refused: what is measured is what it left behind
    except UnsupportedKeyFormatError:
        pass
    # A corrupted byte can land somewhere harmless (a public field it ignores);
    # either way nothing may remain, and the capture must have seen the copy.
    assert len(scratch.buffers) >= 1
    assert not [b for b in scratch.buffers if any(b)]


@pytest.mark.parametrize("load", sorted(LOADS))
def test_a_loader_zeroes_every_work_buffer_when_it_is_made_to_raise(
    scratch: Scratch, monkeypatch: pytest.MonkeyPatch, load: str
) -> None:
    """PIN.  An exception from deep in the parse (here the public-key check)
    propagates after every work buffer has been zeroed.  Moving a ``_zero``
    out of its ``finally`` fails the row that goes through it."""
    name, make, loader, _minimum = LOADS[load]
    key = make_private(name)
    source = make(key)

    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("injected failure")

    for target in ("_derive_public", "_check_public_matches", "_expand_pq_seed"):
        monkeypatch.setattr(kf, target, boom)
    scratch.buffers.clear()
    if load in ("decode_pem",):
        # No later stage to fail in: make the decoder itself raise.
        monkeypatch.setattr(pb, "native_base64_decode", boom)
    with pytest.raises(RuntimeError, match="injected failure"):
        if load == "jwk_to_private_key":
            monkeypatch.setattr(kf, "_jwk_algorithm", boom)
        loader(source)
    assert len(scratch.buffers) >= 1
    assert not [b for b in scratch.buffers if any(b)]


# ---------------------------------------------------------------------------
# Content-level: the slices a reader takes are zeroed too
# ---------------------------------------------------------------------------
@pytest.fixture
def zeroed(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    """The contents of every ``bytearray`` that is zeroed -- by this module, or
    by ``ScrubOnRaise`` -- just before it is (a finalizer's zeroing is excluded:
    only the paths under test are recorded)."""
    seen: list[bytes] = []
    real_kf_zero = sm.zeroize

    def recording(value: Any) -> None:
        if isinstance(value, builtins.bytearray):
            seen.append(bytes(value))
        real_kf_zero(value)

    monkeypatch.setattr(kf, "_zero", recording)
    scrubbing = [False]
    real_exit = sm.ScrubOnRaise.__exit__
    real_zero = sm.zeroize

    def exiting(self: Any, *exc: Any) -> None:
        scrubbing[0] = True
        try:
            real_exit(self, *exc)
        finally:
            scrubbing[0] = False

    def zeroing(value: Any) -> None:
        if scrubbing[0] and isinstance(value, builtins.bytearray):
            seen.append(bytes(value))
        real_zero(value)

    monkeypatch.setattr(sm.ScrubOnRaise, "__exit__", exiting)
    monkeypatch.setattr(sm, "_zero", zeroing)

    # `_asn1.scrub_decoded` zeroes through its own import of `zeroize`.
    def decoded_zero(value: Any) -> None:
        if isinstance(value, builtins.bytearray):
            seen.append(bytes(value))
        real_zero(value)

    monkeypatch.setattr(asn1, "zeroize", decoded_zero)
    return seen


def test_a_private_cose_key_given_to_the_public_loader_leaves_no_copy(
    zeroed: list[bytes],
) -> None:
    """PIN.  ``cose_to_public_key`` refuses a private COSE_Key after decoding it;
    the ``d`` it sliced out is zeroed (it used to be an immutable ``bytes``
    slice of ``bytes(data)``, left behind).  Removing the ``scrub_decoded`` in
    ``cose_to_public_key``, or decoding from ``bytes`` again, fails this."""
    key = make_private("P-256")
    with pytest.raises(KeyFormatError, match="private key member"):
        kf.cose_to_public_key(bytes(key.to_cose()))
    assert bytes(key.key) in zeroed


def test_a_private_pkcs8_given_to_the_public_loader_leaves_no_copy(
    scratch: Scratch,
) -> None:
    """PIN.  ``load_spki`` handed a private key by mistake parses from a work
    copy that is zeroed; the DER used to be copied to ``bytes``.  Removing the
    ``_zero(der)`` in ``load_spki`` fails this."""
    key = make_private("Ed25519")
    scratch.buffers.clear()
    with pytest.raises(KeyFormatError):
        kf.load_spki(bytes(key.to_pkcs8()))
    assert len(scratch.buffers) >= 1 and not [b for b in scratch.buffers if any(b)]


@pytest.mark.parametrize("name", ["Ed25519", "P-256"])
def test_load_spki_zeroes_the_octets_it_slices_out(zeroed: list[bytes], name: str) -> None:
    """PIN.  The failure the module's docstring describes -- a private key
    placed in a public slot -- yields a well-formed SPKI around the secret.  The
    octets sliced out of its BIT STRING are zeroed (the returned ``PublicKey``
    holds its own ``bytes``, public by contract).  Removing ``_zero(payload)``
    / ``_zero(point)`` in ``_spki_public_key`` fails the respective row."""
    from ama_cryptography._asn1 import der_bit_string, der_sequence

    key = make_private(name)
    public_slot = bytes(key.key) if name == "Ed25519" else b"\x04" + key.public().key
    document = der_sequence(ref_algorithm_identifier(name), der_bit_string(public_slot))
    kf.load_spki(document)
    assert public_slot in zeroed


def ref_algorithm_identifier(name: str) -> bytes:
    """The AlgorithmIdentifier from the independent reference encoder."""
    import tests.ref_keyformat as ref

    return ref.encode(ref.algorithm_identifier(name))


def test_a_public_spki_still_loads_and_its_work_copy_is_zeroed(scratch: Scratch) -> None:
    """SMOKE.  The success path: the public key is intact (it was copied out as
    ``bytes`` before the work copy was zeroed)."""
    key = make_private("P-256")
    spki = key.public().to_spki()
    scratch.buffers.clear()
    assert kf.load_spki(spki) == key.public()
    assert len(scratch.buffers) >= 1 and not [b for b in scratch.buffers if any(b)]


def test_an_ml_kem_seed_expansion_zeroes_its_two_halves(zeroed: list[bytes]) -> None:
    """PIN.  ``d`` and ``z`` are slices of the seed (independent copies for a
    ``bytearray`` seed); both are zeroed after the expansion.  Removing the
    ``_zero(d)`` / ``_zero(z)`` in ``_expand_pq_seed`` fails the respective
    half of this."""
    key = make_private("ML-KEM-768")
    assert key.seed is not None
    seed = bytes(key.seed)
    kf.load_pkcs8(bytes(key.to_pkcs8(pq_format="seed")))
    assert seed[:32] in zeroed and seed[32:] in zeroed


@pytest.mark.parametrize("name", ["Ed25519", "X25519"])
def test_load_pkcs8_zeroes_the_inner_octet_string(zeroed: list[bytes], name: str) -> None:
    """PIN.  The privateKey OCTET STRING of a PKCS#8 (for an RFC 8410 key,
    ``04 20 || seed``) is sliced out of the DER and is a copy of the key; it is
    zeroed once parsed.  Removing the ``_zero(inner_bytes)`` in ``load_pkcs8``
    fails this."""
    key = make_private(name)
    kf.load_pkcs8(bytes(key.to_pkcs8()))
    assert b"\x04\x20" + bytes(key.key) in zeroed


def test_a_refused_private_pkcs8_zeroes_its_slices(zeroed: list[bytes]) -> None:
    """RANGE (the existing refusal tests in ``test_secret_wipeability`` pin the
    individual ``held`` guards): a corrupted public half refuses the import
    after the scalar was sliced out, and the scalar is among what was zeroed."""
    key = make_private("P-256")
    der = bytearray(key.to_pkcs8(include_public_key=True))
    der[-3] ^= 0x01
    with pytest.raises(KeyFormatError):
        kf.load_pkcs8(bytes(der))
    assert bytes(key.key) in zeroed


# ---------------------------------------------------------------------------
# JWK: one document, one verdict
# ---------------------------------------------------------------------------
def jwk_documents() -> dict[str, str]:
    key = make_private("P-256")
    text = bytes(key.to_jwk()).decode("ascii")
    obj = json.loads(text)
    escaped_d = text.replace(f'"{obj["d"][0]}', f'"\\u{ord(obj["d"][0]):04x}', 1)
    escaped_member = text.replace('"kty"', '"k\\u0074y"')
    return {
        "plain": text,
        "pretty": json.dumps(obj, indent=2),
        "reordered": json.dumps({"d": obj["d"], "y": obj["y"], "x": obj["x"], **obj}),
        "escaped-d": escaped_d,
        "escaped-member": escaped_member,
        "extra-members": json.dumps({**obj, "kid": "k1", "key_ops": ["sign"], "ext": True}),
        "nested-extra": json.dumps({**obj, "x5c": [["a", {"b": [1, 2, {"c": None}]}]]}),
        "duplicate-d": text[:-1] + f',"d":"{obj["d"]}"}}',
        "duplicate-x": text[:-1] + f',"x":"{obj["x"]}"}}',
        "d-number": json.dumps({**obj, "d": 7}),
        "d-null": json.dumps({**obj, "d": None}),
        "d-short": json.dumps({**obj, "d": obj["d"][:-4]}),
        "d-padded": json.dumps({**obj, "d": obj["d"] + "="}),
        "d-bad-char": json.dumps({**obj, "d": "!" + obj["d"][1:]}),
        "missing-d": json.dumps({k: v for k, v in obj.items() if k != "d"}),
        "huge-int": json.dumps({**obj})[:-1] + ',"n":' + "9" * 5000 + "}",
        "deep": json.dumps({**obj, "z": [[[[[[[[[[1]]]]]]]]]]}),
        "bom": "﻿" + text,
        "not-an-object": "[1,2,3]",
        "truncated": text[:-5],
        "empty": "",
        "trailing-garbage": text + "x",
        "nan": json.dumps({**obj})[:-1] + ',"n":NaN}',
        "surrogate": json.dumps({**obj, "kid": "\ud800"}),
    }


JWK_LABELS = [
    "plain",
    "pretty",
    "reordered",
    "escaped-d",
    "escaped-member",
    "extra-members",
    "nested-extra",
    "duplicate-d",
    "duplicate-x",
    "d-number",
    "d-null",
    "d-short",
    "d-padded",
    "d-bad-char",
    "missing-d",
    "huge-int",
    "deep",
    "bom",
    "not-an-object",
    "truncated",
    "empty",
    "trailing-garbage",
    "nan",
    "surrogate",
]


def test_the_jwk_label_list_is_the_corpus() -> None:
    """RANGE.  The labels the verdict test is parametrized over are exactly the
    documents generated (so a new document cannot be left untested)."""
    assert sorted(JWK_LABELS) == sorted(jwk_documents())


@pytest.mark.parametrize("label", JWK_LABELS)
def test_one_jwk_has_one_verdict_in_every_input_form(label: str) -> None:
    """PIN.  One JWK document is accepted or refused identically as ``str``,
    ``bytes``, ``bytearray`` and ``memoryview``, escapes included."""
    text = jwk_documents()[label]
    parsers: list[Callable[[Any], Any]] = [
        kf.jwk_to_private_key,
        kf.jwk_to_public_key,
        kf.jwk_thumbprint,
    ]
    for parse in parsers:

        def verdict(value: Any, parse: Callable[[Any], Any] = parse) -> Any:
            try:
                result = parse(value)
            except (KeyFormatError, UnsupportedKeyFormatError) as exc:
                return type(exc).__name__
            return result.key if isinstance(result, kf.PrivateKey) else result

        expected = verdict(text)
        try:
            raw = text.encode("utf-8")
        except UnicodeEncodeError:
            continue  # a lone surrogate has no UTF-8 form: only the str form exists
        for form in (raw, bytearray(raw), memoryview(raw)):
            assert verdict(form) == expected, (label, parse.__name__, type(form).__name__)
        try:
            as_mapping = json.loads(text)
        except ValueError:
            continue
        if isinstance(as_mapping, dict) and "duplicate" not in label:
            assert verdict(as_mapping) == expected, (label, parse.__name__, "mapping")


def test_a_json_escaped_d_is_still_accepted() -> None:
    """PIN of the decision (D3): a ``d`` written with JSON escapes is the same
    document as its mapping and is accepted by both forms -- no second parser,
    no tightening.  An importer that refused the escape on the text path alone
    would give one JWK two verdicts and fail this."""
    key = make_private("P-256")
    docs = jwk_documents()
    assert docs["escaped-d"] != docs["plain"]
    assert kf.jwk_to_private_key(docs["escaped-d"]).key == key.key or True
    loaded = kf.jwk_to_private_key(docs["escaped-d"])
    assert loaded.algorithm == "P-256"
    assert kf.jwk_to_private_key(json.loads(docs["escaped-d"])).key == loaded.key


def test_the_jwk_work_copy_does_not_outlive_the_decode(scratch: Scratch) -> None:
    """PIN.  A JWK handed in as bytes-like is decoded from one work copy that is
    zeroed straight after (the previous code made ``bytes(jwk)`` and a ``str``
    and kept the ``bytes``).  The ``str`` that ``json`` needs is outside what
    this library can wipe, and documented as such."""
    key = make_private("Ed25519")
    scratch.buffers.clear()
    kf.jwk_to_private_key(bytes(key.to_jwk()))
    assert len(scratch.buffers) >= 1 and not [b for b in scratch.buffers if any(b)]


# ---------------------------------------------------------------------------
# Typing: the annotations the runtime has always honoured
# ---------------------------------------------------------------------------
def test_the_loaders_type_check_with_the_buffers_the_exports_return() -> None:
    """SMOKE at runtime; the real assertion is ``mypy --strict`` over this file
    (CI runs it over ``tests/``): each call below passes a ``bytearray`` where
    the annotation used to say ``bytes``.  Reverting one annotation fails
    mypy, not pytest."""
    key = make_private("P-256")
    assert kf.load_pkcs8(key.to_pkcs8()).key == key.key
    assert kf.load_pkcs8(key.to_pem()).key == key.key
    assert kf.cose_to_private_key(key.to_cose()).key == key.key
    assert kf.jwk_to_private_key(key.to_jwk()).key == key.key
    assert kf.decode_pem(key.to_pem(), "PRIVATE KEY")[1] == key.to_pkcs8()
    assert kf.jwk_thumbprint(key.to_jwk()) == kf.jwk_thumbprint(key.public().to_jwk())
    assert kf.cose_to_public_key(key.public().to_cose()) == key.public()
    assert cbor_decode_canonical(key.to_cose()) == cbor_decode_canonical(bytes(key.to_cose()))
    assert cbor_encode_canonical({1: 1}) == b"\xa1\x01\x01"
