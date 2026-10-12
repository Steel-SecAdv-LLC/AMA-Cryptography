#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""No immutable copy of a private key is made on the encode and decode paths.

Three instruments: a return-value tap under ``sys.setprofile`` that flags any
``bytes``/``str`` holding the key, a syntactic ban on key-bearing names in
copying calls, and a rule that every getter handed to the writer is a bare name
or ``_secret_buffer(key.key|seed)``.  Each checker is shown to flag the
spellings it claims to.  JWK importers (the JSON parser builds a ``str``) and
caller-supplied ``str`` input are outside them.
"""

from __future__ import annotations

import ast
import base64
import functools
import sys
from pathlib import Path
from typing import Any, Callable

import pytest

import ama_cryptography._asn1 as asn1
import ama_cryptography._secret_writer as sw
import ama_cryptography.key_formats as kf
import ama_cryptography.pqc_backends as pb
from tests.test_private_key_export import ALL, CLASSICAL, make_private

pytestmark = pytest.mark.skipif(pb._native_lib is None, reason="native library not built")


# ---------------------------------------------------------------------------
# 1. The return-value tap
# ---------------------------------------------------------------------------
def needles(key: kf.PrivateKey) -> list[bytes]:
    """Byte strings whose presence in an immutable value means it holds the key:
    a raw window, and the Base64 and Base64url text of a window at each of the
    three alignments, taken from the secret-only part of the key."""
    alg = kf.ALGORITHMS[key.algorithm]
    start = {"ml-dsa": 128, "ml-kem": 64}.get(alg.pq_family or "", 0)
    found: list[bytes] = []
    for secret, at in ((key.key, start), (key.seed, 0)):
        if secret is None:
            continue
        data = bytes(secret)
        found.append(data[at : at + 16])
        for shift in range(3):
            window = data[at + shift : at + shift + 15]
            found += [base64.b64encode(window), base64.urlsafe_b64encode(window)]
    return found


def holds(value: Any, wanted: list[bytes], depth: int = 0) -> bool:
    if isinstance(value, bytes):
        return any(n in value for n in wanted)
    if isinstance(value, str):
        encoded = value.encode("utf-8", "ignore")
        return any(n in encoded for n in wanted)
    if depth < 3 and isinstance(value, (list, tuple)):
        return any(holds(item, wanted, depth + 1) for item in value)
    if depth < 3 and isinstance(value, dict):
        return any(holds(item, wanted, depth + 1) for item in value.values())
    return False  # a bytearray / memoryview is mutable: wipeable, not a finding


def tap(run: Callable[[], Any], wanted: list[bytes]) -> list[str]:
    """Run ``run`` and name every ``ama_cryptography`` function that returned
    an immutable value holding the key."""
    findings: list[str] = []

    def profile(frame: Any, event: str, value: Any) -> None:
        if event == "return" and "ama_cryptography" in frame.f_code.co_filename:
            if holds(value, wanted):
                findings.append(f"{Path(frame.f_code.co_filename).name}:{frame.f_code.co_name}")

    sys.setprofile(profile)
    try:
        run()
    finally:
        sys.setprofile(None)
    return findings


def test_the_tap_sees_what_the_old_layered_encoders_did() -> None:
    """Non-vacuity.  The immutable composition this change replaced -- each
    ``_asn1`` layer returning a fresh ``bytes`` of everything beneath it -- is
    found at every layer, and so is the ``str`` the JWK ``d`` used to be.  A
    tap that saw nothing would pass the real exports for no reason."""
    key = make_private("P-256")
    wanted = needles(key)

    def old_pkcs8() -> bytes:
        inner = asn1.der_sequence(asn1.der_integer(1), asn1.der_octet_string(bytes(key.key)))
        return asn1.der_sequence(asn1.der_integer(0), asn1.der_octet_string(inner))

    found = tap(old_pkcs8, wanted)
    assert found.count("_asn1.py:_tlv") >= 3, found
    assert tap(lambda: kf._b64u(key.key), wanted) == ["key_formats.py:_b64u"]
    assert "_asn1.py:cbor_encode_canonical" in tap(
        lambda: asn1.cbor_encode_canonical({-4: bytes(key.key)}), wanted
    )


@pytest.mark.parametrize("name", ALL)
def test_no_export_returns_an_immutable_value_holding_the_key(name: str) -> None:
    """PIN.  For every encoding, algorithm and PKCS#8 arm, nothing called while
    the export runs returns a ``bytes`` or ``str`` containing the key."""
    for seeded in (True, False) if name.startswith("ML-") else (True,):
        key = make_private(name, seeded=seeded)
        wanted = needles(key)
        for run in export_runs(key, seeded):
            assert tap(run, wanted) == []


def export_runs(key: kf.PrivateKey, seeded: bool) -> list[Callable[[], Any]]:
    """Every export of ``key``: each PKCS#8 arm and ``include_public_key``
    setting, the PEM (twice: the method and ``encode_pem``), JWK and COSE."""
    pq = key.algorithm.startswith("ML-")
    arms = ("auto", "seed", "expandedKey", "both") if pq else ("auto",)
    runs: list[Callable[[], Any]] = []
    for include in (None, True, False):
        for arm in arms:
            if arm in ("seed", "both") and not seeded:
                continue
            runs.append(functools.partial(key.to_pkcs8, include_public_key=include, pq_format=arm))
    runs.append(key.to_pem)
    runs.append(functools.partial(kf.encode_pem, key.to_pkcs8(), "PRIVATE KEY"))
    if key.algorithm in CLASSICAL:
        runs += [key.to_jwk, key.to_cose]
    return runs


@pytest.mark.parametrize("name", ALL)
def test_no_binary_loader_returns_an_immutable_value_holding_the_key(name: str) -> None:
    """PIN.  ``load_pkcs8`` (DER and PEM, bytes-like), ``decode_pem`` and
    ``cose_to_private_key`` hand back only wipeable buffers.  (The JWK loader is
    outside: ``json`` builds a ``str`` of the document, documented.)  A
    ``bytes(der)`` for the result, a ``str`` of the PEM, or an immutable slice
    of the key fails the row."""
    key = make_private(name)
    wanted = needles(key)
    der, pem = bytearray(key.to_pkcs8()), bytearray(key.to_pem())
    assert tap(lambda: kf.load_pkcs8(der), wanted) == []
    assert tap(lambda: kf.load_pkcs8(pem), wanted) == []
    assert tap(lambda: kf.decode_pem(pem, "PRIVATE KEY"), wanted) == []
    if name in CLASSICAL:
        cose = bytearray(key.to_cose())
        assert tap(lambda: kf.cose_to_private_key(cose), wanted) == []


# ---------------------------------------------------------------------------
# 2. The syntactic ban
# ---------------------------------------------------------------------------
BANNED_CALLS = {"bytes", "str", "repr", "format", "ascii", "hex"}
BANNED_METHODS = {
    "tobytes",
    "decode",
    "encode",
    "hex",
    "join",
    "format",
    "translate",
    "split",
    "strip",
    "replace",
}


#: Attributes that are sizes and flags, not the octets: arithmetic on them
#: (``at + view.nbytes``) is not a copy of the buffer.
SIZE_ATTRIBUTES = {"nbytes", "itemsize", "ndim", "format", "readonly", "shape"}


def root(node: ast.AST) -> str | None:
    """The name an expression is built on: ``a`` for ``a``, ``a[1:]``,
    ``a.b``, ``a.b(...)`` (but ``None`` for a size such as ``a.nbytes``)."""
    while True:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute) and node.attr in SIZE_ATTRIBUTES:
            return None
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            node = node.value
        elif isinstance(node, ast.Call):
            node = node.func
        else:
            return None


def mentions(node: ast.AST, names: set[str]) -> bool:
    """Whether a name in ``names`` is read anywhere inside ``node`` other than
    as a size, looking through arguments, subscripts, conditionals and nested
    calls."""
    if isinstance(node, ast.Name):
        return node.id in names
    if isinstance(node, ast.Attribute) and node.attr in SIZE_ATTRIBUTES:
        return False
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in ("len", "type")
    ):
        return False
    return any(mentions(child, names) for child in ast.iter_child_nodes(node))


#: A *mutable* copy is still a copy nothing zeroes unless its maker does.  In
#: the functions that only describe or write an export, no copy of the key is
#: ever needed, so ``bytearray(...)`` of a key-bearing name is banned there too;
#: the loaders' own first step is exactly ``bytearray(document)`` (the work
#: copy they zero), so the loaders are not in this set.
EXPORT_FUNCTIONS = frozenset(
    {
        "_secret_buffer",
        "_key_secret",
        "_seed_secret",
        "_pq_private_key_piece",
        "_encode_pkcs8",
        "_pem_armor",
        "PrivateKey.to_pem",
        "private_key_to_jwk",
        "private_key_to_cose",
        "Sec._view",
        "Sec.size",
        "Sec.write",
        "Wrapped.write",
        "Framed.write",
        "build",
    }
)


def violations(
    source: str, key_bearing: dict[str, set[str]], copying: frozenset[str] = frozenset()
) -> list[str]:
    """Calls, concatenations and formattings of a name that holds key material,
    in the functions listed (qualified ``Class.method`` / ``function``);
    ``copying`` names those where ``bytearray(...)`` is banned as well."""
    tree = ast.parse(source)
    found: list[str] = []
    seen: set[str] = set()

    def visit(node: ast.AST, scope: tuple[str, ...]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                visit(child, (*scope, child.name))
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualified = ".".join((*scope, child.name))
                if qualified in key_bearing:
                    seen.add(qualified)
                    banned = BANNED_CALLS | ({"bytearray"} if qualified in copying else set())
                    found.extend(check(child, qualified, key_bearing[qualified], banned))
                visit(child, (*scope, child.name))
            else:
                visit(child, scope)

    visit(tree, ())
    missing = set(key_bearing) - seen
    assert not missing, f"functions named in the inventory no longer exist: {sorted(missing)}"
    return found


def check(function: ast.AST, qualified: str, names: set[str], banned: set[str]) -> list[str]:
    found: list[str] = []
    for node in ast.walk(function):
        where = f"{qualified}:{getattr(node, 'lineno', '?')}"
        if isinstance(node, ast.Call):
            callee = node.func
            if isinstance(callee, ast.Name) and callee.id in banned:
                if any(mentions(arg, names) for arg in node.args):
                    found.append(f"{where} {callee.id}(<key-bearing>)")
            if isinstance(callee, ast.Attribute) and callee.attr in BANNED_METHODS:
                receiver_hit = mentions(callee.value, names)
                argument_hit = any(mentions(arg, names) for arg in node.args)
                if receiver_hit or (callee.attr == "join" and argument_hit):
                    found.append(f"{where} .{callee.attr}(<key-bearing>)")
        elif isinstance(node, ast.JoinedStr):
            for part in ast.walk(node):
                if isinstance(part, ast.FormattedValue) and mentions(part.value, names):
                    found.append(f"{where} f-string of <key-bearing>")
        elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            if mentions(node.left, names) or mentions(node.right, names):
                found.append(f"{where} concatenation/format of <key-bearing>")
    return found


def test_the_checker_flags_every_spelling_of_an_immutable_copy() -> None:
    """Non-vacuity of the ban: each of these functions copies ``secret`` into
    something immutable, and each is flagged."""
    bodies = {
        "a": "bytes(secret)",
        "b": "secret.tobytes()",
        "c": "secret.decode('ascii')",
        "d": "str(secret[1:])",
        "e": "b''.join([secret, b'x'])",
        "f": "f'{secret}'",
        "g": "b'-----' + secret",
        "h": "secret[:4].hex()",
        "i": "'%s' % secret",
        "j": "secret.replace(b'a', b'b')",
        "k": "bytearray(secret)",
        # A copy whose argument is a call *on* the key, not the key itself: the
        # spelling `bytearray(_secret_buffer(key.seed))` that a check
        # following only the receiver chain never saw.
        "l": "bytearray(wrap(secret))",
        "m": "bytes(wrap(secret))",
        "n": "Sec(lambda: bytearray(wrap(secret)))",
        "o": "bytearray(secret if flag else other)",
        "p": "bytearray(secret[:4])",
    }
    source = "\n".join(f"def {n}(secret):\n    return {expr}\n" for n, expr in bodies.items())
    flagged = violations(
        source, {n: {"secret"} for n in bodies}, frozenset({"k", "l", "n", "o", "p"})
    )
    assert {f.split(":")[0] for f in flagged} == set(bodies), flagged
    clean = (
        "def k(secret, out):\n    out[0:4] = secret\n    return len(secret)\n"
        "def m(secret):\n    return bytearray(len(secret)), f'{type(secret).__name__}'\n"
    )
    assert violations(clean, {"k": {"secret"}, "m": {"secret"}}, frozenset({"m"})) == []


# ---------------------------------------------------------------------------
# 3. The getters handed to the writer
# ---------------------------------------------------------------------------
def getter_findings(source: str) -> tuple[list[str], int]:
    """Every ``Sec(...)`` / ``Wrapped(...)`` construction in ``source``, and the
    ones whose first argument is not a plain getter: a zero-argument ``lambda``
    returning a bare name or ``_secret_buffer(key.key|seed)``.  The runtime
    counterpart is the identity test in ``tests/test_private_key_export.py``."""
    tree = ast.parse(source)
    found: list[str] = []
    constructions = 0
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in ("Sec", "Wrapped")
        ):
            continue
        constructions += 1
        getter = node.args[0] if node.args else None
        plain = (
            isinstance(getter, ast.Lambda)
            and not getter.args.args
            and not getter.args.kwonlyargs
            and not getter.args.vararg
            and _plain_getter_body(getter.body)
        )
        if not plain:
            found.append(f"line {node.lineno}: {node.func.id}(<{type(getter).__name__}>)")
    return found, constructions


def _plain_getter_body(body: ast.expr) -> bool:
    if isinstance(body, ast.Name):
        return True
    return (
        isinstance(body, ast.Call)
        and isinstance(body.func, ast.Name)
        and body.func.id == "_secret_buffer"
        and not body.keywords
        and len(body.args) == 1
        and isinstance(body.args[0], ast.Attribute)
        and isinstance(body.args[0].value, ast.Name)
        and body.args[0].value.id == "key"
        and body.args[0].attr in ("key", "seed")
    )


def test_the_getter_checker_flags_every_way_to_read_from_a_copy() -> None:
    """Non-vacuity of the getter rule: each of these constructions reads from a
    copy, or holds a buffer, and is flagged; the plain forms are not."""
    copies = [
        "Sec(lambda: bytearray(chars))",
        "Wrapped(lambda: bytearray(chars), 64)",
        "Sec(lambda: bytearray(_secret_buffer(key.seed)))",
        "Sec(lambda: _secret_buffer(key.seed)[:])",
        "Sec(lambda: chars[:])",
        "Sec(lambda: chars if flag else other)",
        "Sec(lambda: copy(chars))",
        "Sec(lambda: _secret_buffer(key.seed, True))",
        "Sec(lambda: _secret_buffer(other.seed))",
        "Sec(chars)",  # holds the buffer for as long as the piece lives
        "Sec(getter_function)",
        "Sec(lambda x: chars)",
    ]
    for source in copies:
        assert getter_findings(source)[0] != [], source
    plain = [
        "Sec(lambda: chars)",
        "Wrapped(lambda: chars, 64)",
        "Sec(lambda: _secret_buffer(key.key))",
        "Sec(lambda: _secret_buffer(key.seed))",
    ]
    for source in plain:
        assert getter_findings(source) == ([], 1), source


def test_every_getter_given_to_the_writer_is_a_plain_one() -> None:
    """PIN.  The four constructions in ``key_formats`` use plain getters, and
    the count is checked so a renamed constructor cannot empty the scan."""
    source = Path(kf.__file__).read_text(encoding="utf-8")
    found, constructions = getter_findings(source)
    assert constructions >= 4, constructions
    assert found == []


#: The functions that handle the key's octets, and the names inside each that
#: hold them.  Public fragments (OIDs, headers, the public key) pass through
#: other names and are not in the lists.  The JWK importer's ``str`` is outside
#: (see the module docstring), and so is not listed.
KEY_FORMATS_FUNCTIONS: dict[str, set[str]] = {
    "_secret_buffer": {"value"},
    "_key_secret": {"key"},
    "_seed_secret": {"key"},
    "_pq_private_key_piece": {"key"},
    "_encode_pkcs8": {"key"},
    "_pem_armor": {"chars", "der"},
    "PrivateKey.to_pem": {"der"},
    "private_key_to_jwk": {"chars", "key"},
    "private_key_to_cose": {"key"},
    "decode_pem": {"der"},
    "_pem_work_copy": {"text"},
    "_decode_pem_der": {"work"},
    "_pem_line_spans": {"work"},
    "_pem_scan": {"work", "joined", "source", "target", "der"},
    "_as_der": {"raw"},
    "load_spki": {"der"},
    "load_pkcs8": {"der", "inner_bytes"},
    "_pkcs8_private_key_checked": {"inner_bytes", "secret", "seed", "derived"},
    "_parse_ec_private_key": {"inner", "secret"},
    "_parse_pq_private_key": {"inner", "seed", "expanded", "from_seed", "body"},
    "_expand_pq_seed": {"seed", "d", "z", "secret"},
    "cose_to_private_key": {"obj", "secret"},
    "cose_to_public_key": {"obj"},
    "_load_cose": {"buf"},
}
WRITER_FUNCTIONS: dict[str, set[str]] = {
    "Sec._view": {"secret"},
    "Sec.size": {"view"},
    "Sec.write": {"view", "out"},
    "Wrapped.write": {"view", "out"},
    "Framed.write": {"out"},
    "build": {"out", "view"},
}


def test_the_key_handling_functions_make_no_immutable_copy_of_the_key() -> None:
    """PIN.  Adding ``bytes(chars)``, ``chars.decode()``, ``der.tobytes()``,
    ``b"".join(...)``, a ``str`` of the work copy, or a concatenation with a key
    buffer to any listed function fails.  The inventory is the set of functions
    that touch the key's octets; a function dropped from the source fails the
    lookup rather than silently leaving the list."""
    found = violations(
        Path(kf.__file__).read_text(encoding="utf-8"), KEY_FORMATS_FUNCTIONS, EXPORT_FUNCTIONS
    )
    found += violations(
        Path(sw.__file__).read_text(encoding="utf-8"), WRITER_FUNCTIONS, EXPORT_FUNCTIONS
    )
    assert found == []


def test_the_inventory_is_not_vacuous() -> None:
    """Every listed function references at least one of its key-bearing names,
    so a rename that orphaned the list is caught here."""
    for path, inventory in (
        (kf.__file__, KEY_FORMATS_FUNCTIONS),
        (sw.__file__, WRITER_FUNCTIONS),
    ):
        tree = ast.parse(Path(path).read_text(encoding="utf-8"))
        qualified: dict[str, ast.AST] = {}

        def collect(node: ast.AST, scope: tuple[str, ...], into: dict[str, ast.AST]) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.ClassDef):
                    collect(child, (*scope, child.name), into)
                elif isinstance(child, ast.FunctionDef):
                    into[".".join((*scope, child.name))] = child
                    collect(child, (*scope, child.name), into)

        collect(tree, (), qualified)
        for name, names in inventory.items():
            used = {n.id for n in ast.walk(qualified[name]) if isinstance(n, ast.Name)}
            assert used & names, f"{name} mentions none of {sorted(names)}"


def test_the_pem_scanner_uses_no_regular_expression_and_no_split() -> None:
    """PIN (replaces the charset-opcode pin on the old ``_PEM_RE``).  The PEM
    scanner is built from ``find``/``startswith``/``endswith`` and index
    arithmetic: no ``re`` module, no ``split``/``splitlines``/``partition``, and
    no ``.group``.  Importing ``re`` or splitting the body fails this."""
    tree = ast.parse(Path(kf.__file__).read_text(encoding="utf-8"))
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in (node.names if isinstance(node, ast.Import) else [])
    } | {
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert "re" not in imported
    scanner = {"_pem_line_spans", "_pem_header_label", "_pem_scan", "_decode_pem_der"}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in scanner:
            methods = {
                n.func.attr
                for n in ast.walk(node)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            }
            assert not methods & {"split", "splitlines", "partition", "group", "match", "search"}
