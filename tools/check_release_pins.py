#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — Release Build Dependency Pin Gate (INVARIANT-8, INVARIANT-11)
================================================================================

Two manifests at the repository root pin, by exact version AND by the SHA-256
of every file PyPI publishes for that version, everything a release build
installs from an index:

``requirements-release-build.txt``
    what compiles every wheel and the sdist — setuptools, wheel, cmake, Cython,
    numpy.  Installed by cibuildwheel's before-build hook on every matrix row,
    by ``build-sdist``, and into the sdist smoke-test venv, always through
    ``pip install --require-hashes -r``.
``requirements-release-tools.txt``
    the front end that drives the sdist build and its smoke install — pip,
    build, packaging, pyproject_hooks.

Why this exists
---------------
Until these manifests existed, ``release.yml`` resolved its build toolchain
from PyPI at release time against nothing but floors.  ``CIBW_BEFORE_BUILD_*``
ran ``pip install 'cmake>=4.4.3' 'cython>=3.3.0' 'numpy>=1.24.0'``;
``build-sdist`` ran ``pip install --upgrade pip`` and ``pip install build``;
and the wheel builds and the sdist smoke install all let pip build in an
ISOLATED environment that re-resolved ``[build-system].requires`` — the same
floors — from the index a second time.  The bytes that compiled a release were
therefore whatever PyPI served that day: the reproducibility gate
(``verify-reproducible-wheel``) compared two builds that had each resolved their
own toolchain, so it could pass on one day and the next tag could differ, and a
replaced upstream release could enter a signed, attested wheel with no pin
anywhere to refuse it.  INVARIANT-8 declares the build reproducible and
INVARIANT-11 makes the release pipeline a gate; a toolchain nothing pins is
neither.

What is checked (default mode, offline)
---------------------------------------
1. **Every requirement line of both manifests** is pinned with ``==`` exactly
   (no ``>=``, ``~=``, ``!=``, a bare name, or a multi-clause specifier),
   carries at least one ``--hash=sha256:<64 hex>``, and, when it has an
   environment marker, a marker that parses under the PEP 508 grammar.  The
   file must also be byte-identical to what ``--refresh`` would write for the
   same pins and hashes: sorted hashes, LF line endings, the generated header
   with its ``as-of`` date.  A hand edit, an unsorted hash list or a CRLF
   checkout is reported rather than silently accepted.
2. **Every pin satisfies the floors** ``pyproject.toml`` ``[build-system].requires``
   and ``setup.py``'s ``_BUILD_REQS`` preflight declare.  The floors are read
   from those two files with regular expressions, never restated here, so a
   floor raised there fails here until the pin follows.  Every floor package
   must be pinned in the build manifest, and for every interpreter
   ``release.yml``'s ``CIBW_BUILD`` names exactly one of its pins must apply
   (the numpy pin is split by ``python_version`` — see the manifest).
3. **``release.yml`` contains no ``pip install`` that is not one of two
   shapes.**  Every ``run:`` block and every ``CIBW_*`` string, at workflow,
   job and step scope, is tokenised the way a shell would, and each
   ``pip install`` / ``pip download`` / ``pip wheel`` — ``pip ...`` or
   ``python -m pip ...`` — must be either ``pip install --require-hashes -r
   <one of the two manifests>`` with nothing else on the line, or an install
   of the sdist this run has just built: ``--no-build-isolation`` plus paths
   under ``dist/`` and no index option.  Every offender is reported with its
   job and step.  The sdist shape resolves ``[project].dependencies`` from the
   index, so that list is required to be empty (it is: INVARIANT-1).
4. **Every build invocation runs without isolation**, so the pinned set is the
   only set that reaches the compiler: ``python -m build`` carries
   ``--no-isolation``, the sdist install carries ``--no-build-isolation``, and
   every cibuildwheel step sets ``CIBW_BUILD_FRONTEND`` to
   ``pip; args: --no-build-isolation`` or ``build; args: --no-isolation``.

Non-vacuity floors pin the live counts (``MIN_PIP_INSTALLS``,
``MIN_CIBUILDWHEEL_STEPS``, ``MIN_BUILD_INVOCATIONS``): a release.yml with
fewer installs or steps than the tree ships fails, so a deleted step cannot
leave this sweep reporting PASS over nothing.

What is NOT checked offline, stated plainly (INVARIANT-37)
----------------------------------------------------------
Whether a requirement's hash SET is complete — that the wheel pip will select
on each of the five release platforms has its digest listed — needs the index.
``--refresh --check`` (network) regenerates the set from PyPI and reports drift
without writing; the offline gate proves shape, floors and wiring, and a
missing digest fails closed on the matrix row that needs it, on the release
dry run or the tag.  Whether the tools manifest is the complete dependency
closure of ``build`` on the release Python is likewise proven by
``--require-hashes`` itself (pip refuses a dependency with no hash) when
``build-sdist`` runs, not here.  cibuildwheel's own build-venv tooling — the
pip that runs ``CIBW_BEFORE_BUILD``, auditwheel, delocate — comes from the
pinned cibuildwheel action commit's dependency constraints, not from these
manifests; the wheel it installs into the test venv is the one it just built.

Refreshing a pin
----------------
::

    python tools/check_release_pins.py --refresh --as-of YYYY-MM-DD

fetches ``https://pypi.org/pypi/<name>/<version>/json`` for each pinned
requirement, collects the sha256 of every entry in ``urls`` — every wheel of
every platform and interpreter plus the sdist, which is what lets one manifest
resolve on linux x86_64/aarch64 manylinux_2_28, macOS x86_64/arm64 and Windows
AMD64 for cp310-cp314 — and rewrites both manifests deterministically: sorted
hashes, LF line endings, a header carrying the ``--as-of`` date rather than the
clock, so two refreshes of the same pins produce identical bytes.  To move a
pin, edit the version on its requirement line and run ``--refresh``; a note
comment above a requirement is kept.  ``--refresh --check`` compares without
writing.

Dependencies: the standard library, ``urllib`` for the network path, and PyYAML
to read release.yml structurally — the dependency every workflow gate under
``tools/`` shares and the Code Quality job pins.

Exit status
-----------
0 every check passes; 1 a check fails (or ``--refresh --check`` found drift);
2 the checker could not run — a manifest, pyproject.toml, setup.py or
release.yml missing or unreadable, or a PyPI fetch failed under ``--refresh``.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Optional, Sequence

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

#: The two manifests, by repository-relative name, with the header each is
#: generated under.  The header is data here so that ``--refresh`` and the
#: offline canonical-form check (``render_manifest``) agree on every byte.
MANIFEST_HEADERS: dict[str, tuple[str, ...]] = {
    "requirements-release-build.txt": (
        "Release BUILD dependencies for ama-cryptography: the exact set that",
        "compiles every wheel and the sdist, pinned by version and by the SHA-256",
        "of every file PyPI publishes for that version (every wheel of every",
        "platform and interpreter plus the sdist), so that",
        "    pip install --require-hashes -r requirements-release-build.txt",
        "resolves on linux x86_64/aarch64 (manylinux_2_28), macOS x86_64/arm64 and",
        "Windows AMD64 for CPython 3.10-3.14 and refuses anything else.",
        "release.yml installs it in every cibuildwheel before-build hook, in",
        "build-sdist and into the sdist smoke-test venv, and every build then runs",
        "WITHOUT build isolation so this set is the only set that reaches the",
        "compiler.  Every pin is at or above the floors pyproject.toml",
        "[build-system].requires and setup.py's preflight declare;",
        "tools/check_release_pins.py (offline, in CI's Code Quality job) holds it",
        "there.",
    ),
    "requirements-release-tools.txt": (
        "Release TOOLING dependencies for ama-cryptography: the front end that",
        "builds the sdist and drives its smoke install, pinned by version and by",
        "the SHA-256 of every file PyPI publishes for that version.  release.yml's",
        "build-sdist installs it with",
        "    python -m pip install --require-hashes -r requirements-release-tools.txt",
        "before requirements-release-build.txt, so `python -m build --sdist",
        "--no-isolation` and the smoke venv's `pip install --no-build-isolation",
        "dist/*.tar.gz` run on exactly these versions of pip and build.  The set is",
        "the dependency closure of `build` on the release Python (3.11); pip's",
        "--require-hashes refuses any dependency that has no hash here.",
    ),
}

#: Lines every manifest header ends with, after the manifest-specific text.
#: The final line carries the ``--as-of`` date; ``_AS_OF_RE`` reads it back.
_HEADER_TAIL: tuple[str, ...] = (
    "",
    "GENERATED - do not edit the hashes by hand.  To move a pin, change the",
    "version on its requirement line and run",
    "    python tools/check_release_pins.py --refresh --as-of YYYY-MM-DD",
    "which fetches https://pypi.org/pypi/<name>/<version>/json for each pin and",
    "rewrites this file deterministically: sorted hashes, LF line endings, this",
    "header.  A comment directly above a requirement is kept.",
)

_AS_OF_PREFIX = "Hash set as published by PyPI on: "
_AS_OF_RE = re.compile(r"^# " + re.escape(_AS_OF_PREFIX) + r"(\d{4}-\d{2}-\d{2})$", re.M)
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

LICENSE_HEADER: tuple[str, ...] = (
    "# Copyright (C) 2025-2026 Steel Security Advisors LLC",
    "# SPDX-License-Identifier: Apache-2.0",
)

#: Non-vacuity floors, pinned to the live counts in release.yml.  A reduction
#: must lower these under review; ``tests/test_release_pins_gate.py`` asserts
#: the tree's counts equal them so the two cannot drift apart silently.
#:
#: 9 = three CIBW_BEFORE_BUILD_* installs in build-wheels, one in
#: verify-reproducible-wheel, and five in build-sdist (the two manifests for
#: the build, the two manifests into the smoke venv, the sdist itself).
MIN_PIP_INSTALLS = 9
#: build-wheels and verify-reproducible-wheel.
MIN_CIBUILDWHEEL_STEPS = 2
#: ``python -m build --sdist --no-isolation`` in build-sdist.
MIN_BUILD_INVOCATIONS = 1

_PIP_COMMANDS = frozenset({"pip", "pip3", "pip.exe", "pip3.exe"})
_PYTHON_COMMANDS = frozenset({"python", "python3", "py", "python.exe", "python3.exe"})
_BUILD_COMMANDS = frozenset({"pyproject-build", "pyproject-build.exe"})
#: pip subcommands that resolve names against an index.
_INDEX_SUBCOMMANDS = frozenset({"install", "download", "wheel"})
#: Options the sdist smoke install may carry besides the mandatory
#: ``--no-build-isolation``: neither adds an index lookup.
_SDIST_INSTALL_OPTIONS = frozenset({"--no-build-isolation", "--no-deps", "--no-index"})
_INDEX_OPTIONS = ("--index-url", "-i", "--extra-index-url", "--find-links", "-f")
_SDIST_PATH_RE = re.compile(r"^dist/[^/\s]+\.tar\.gz$")
_COMMAND_SEPARATOR_RE = re.compile(r"&&|\|\||[;|]")

_HASH_RE = re.compile(r"^--hash=sha256:([0-9a-f]{64})$")
_NAME_RE = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
_REQUIREMENT_RE = re.compile(
    rf"^(?P<name>{_NAME_RE})\s*(?:(?P<op>===|==|~=|!=|<=|>=|<|>)\s*(?P<version>\S+))?$"
)
_VERSION_RE = re.compile(r"^\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?$")
_RELEASE_RE = re.compile(r"^v?(\d+(?:\.\d+)*)")

_BUILD_SYSTEM_RE = re.compile(r"^\[build-system\][ \t]*$(?P<body>.*?)(?=^\[|\Z)", re.M | re.S)
_REQUIRES_LIST_RE = re.compile(r"^requires\s*=\s*\[(?P<items>.*?)\]", re.M | re.S)
_FLOOR_ITEM_RE = re.compile(
    rf"""["'](?P<name>{_NAME_RE})\s*(?P<op>===|==|~=|!=|<=|>=|<|>)\s*(?P<version>[0-9][0-9A-Za-z.]*)["']"""
)
_SETUP_BUILD_REQS_RE = re.compile(r"^_BUILD_REQS\s*=\s*\{(?P<body>.*?)^\}", re.M | re.S)
_SETUP_FLOOR_RE = re.compile(
    rf"""["'](?P<name>{_NAME_RE})["']\s*:\s*\(\s*\(\s*(?P<parts>\d+(?:\s*,\s*\d+)*)\s*,?\s*\)"""
)
_PROJECT_SECTION_RE = re.compile(r"^\[project\][ \t]*$(?P<body>.*?)(?=^\[|\Z)", re.M | re.S)
_EMPTY_DEPENDENCIES_RE = re.compile(r"^dependencies\s*=\s*\[\s*\]", re.M)
_CP_TAG_RE = re.compile(r"\bcp(\d)(\d+)-\*")


def normalize(name: str) -> str:
    """PEP 503 normalisation: ``Cython`` and ``pyproject_hooks`` compare by it."""
    return re.sub(r"[-_.]+", "-", name).lower()


def release_tuple(version: str) -> tuple[int, ...]:
    """The numeric release segment of ``version`` (``2.2.6`` -> ``(2, 2, 6)``)."""
    match = _RELEASE_RE.match(version.strip())
    if match is None:
        raise ValueError(f"not a version: {version!r}")
    return tuple(int(part) for part in match.group(1).split("."))


def compare_release(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    """Three-way comparison with zero padding, so ``1.0`` equals ``1.0.0``."""
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    if padded_left < padded_right:
        return -1
    return 1 if padded_left > padded_right else 0


def render_version(parts: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in parts)


# ---------------------------------------------------------------------------
# PEP 508 environment markers: parsed, and evaluated with three-valued logic.
# ---------------------------------------------------------------------------

_MARKER_VARIABLES = frozenset(
    {
        "python_version",
        "python_full_version",
        "os_name",
        "sys_platform",
        "platform_release",
        "platform_system",
        "platform_version",
        "platform_machine",
        "platform_python_implementation",
        "implementation_name",
        "implementation_version",
        "extra",
    }
)
#: Variables whose comparisons are version comparisons, not string ones.
_VERSION_VARIABLES = frozenset({"python_version", "python_full_version", "implementation_version"})
_MARKER_TOKEN_RE = re.compile(
    r"""\s*(?:(?P<lpar>\()|(?P<rpar>\))|(?P<str>"[^"]*"|'[^']*')"""
    r"""|(?P<op>===|==|!=|<=|>=|<|>|~=|not\s+in|in)|(?P<word>[A-Za-z_][A-Za-z_0-9.]*))"""
)


class MarkerSyntaxError(ValueError):
    """The marker does not parse under the PEP 508 grammar."""


#: A parsed marker: ``("or"|"and", left, right)`` or ``("cmp", lhs, op, rhs)``
#: where each side is ``("var", name)`` or ``("str", value)``.
MarkerNode = tuple[Any, ...]


class _MarkerParser:
    def __init__(self, marker: str) -> None:
        self.tokens: list[tuple[str, str]] = []
        position = 0
        text = marker.strip()
        while position < len(text):
            match = _MARKER_TOKEN_RE.match(text, position)
            if match is None or match.end() == position:
                raise MarkerSyntaxError(f"unexpected text at {text[position:]!r}")
            kind = str(match.lastgroup)
            self.tokens.append((kind, match.group(kind)))
            position = match.end()
        self.index = 0

    def _peek(self) -> Optional[tuple[str, str]]:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def _take(self) -> tuple[str, str]:
        token = self._peek()
        if token is None:
            raise MarkerSyntaxError("marker ends early")
        self.index += 1
        return token

    def parse(self) -> MarkerNode:
        node = self._expr()
        if self._peek() is not None:
            raise MarkerSyntaxError(f"trailing tokens after {self._peek()!r}")
        return node

    def _expr(self) -> MarkerNode:
        node = self._and()
        while self._peek() == ("word", "or"):
            self._take()
            node = ("or", node, self._and())
        return node

    def _and(self) -> MarkerNode:
        node = self._atom()
        while self._peek() == ("word", "and"):
            self._take()
            node = ("and", node, self._atom())
        return node

    def _atom(self) -> MarkerNode:
        kind, value = self._take()
        if kind == "lpar":
            node = self._expr()
            if self._take()[0] != "rpar":
                raise MarkerSyntaxError("unbalanced parenthesis")
            return node
        left = self._operand(kind, value)
        op_kind, op = self._take()
        if op_kind != "op":
            raise MarkerSyntaxError(f"expected an operator, found {op!r}")
        right = self._operand(*self._take())
        return ("cmp", left, re.sub(r"\s+", " ", op), right)

    @staticmethod
    def _operand(kind: str, value: str) -> MarkerNode:
        if kind == "str":
            return ("str", value[1:-1])
        if kind == "word" and value in _MARKER_VARIABLES:
            return ("var", value)
        raise MarkerSyntaxError(f"{value!r} is neither a marker variable nor a string")


def parse_marker(marker: str) -> MarkerNode:
    """Parse ``marker``; raise :class:`MarkerSyntaxError` when it is malformed."""
    return _MarkerParser(marker).parse()


def _compare_values(left: str, op: str, right: str, as_version: bool) -> bool:
    if op == "in":
        return left in right
    if op == "not in":
        return left not in right
    if op == "===":
        return left == right
    if as_version:
        try:
            order = compare_release(release_tuple(left), release_tuple(right))
        except ValueError:
            order = (left > right) - (left < right)
    else:
        order = (left > right) - (left < right)
    if op == "~=":
        floor = release_tuple(right)
        ceiling = floor[:-1] if len(floor) > 1 else floor
        candidate = release_tuple(left)
        return (
            compare_release(candidate, floor) >= 0
            and compare_release(candidate[: len(ceiling)], ceiling) == 0
        )
    return {
        "==": order == 0,
        "!=": order != 0,
        "<": order < 0,
        "<=": order <= 0,
        ">": order > 0,
        ">=": order >= 0,
    }[op]


def evaluate_marker(node: MarkerNode, environment: dict[str, str]) -> Optional[bool]:
    """Evaluate a parsed marker; ``None`` when a variable it needs is not given.

    Three-valued on purpose: the coverage check knows ``python_version`` for
    each interpreter release.yml builds and nothing about the platform, so a
    marker on ``sys_platform`` is "maybe", never a guess in either direction.
    """
    kind = node[0]
    if kind == "cmp":
        _, left, op, right = node
        sides: list[str] = []
        as_version = False
        for side in (left, right):
            if side[0] == "var":
                if side[1] not in environment:
                    return None
                as_version = as_version or side[1] in _VERSION_VARIABLES
                sides.append(environment[side[1]])
            else:
                sides.append(side[1])
        return _compare_values(sides[0], op, sides[1], as_version)
    left_value = evaluate_marker(node[1], environment)
    right_value = evaluate_marker(node[2], environment)
    if kind == "and":
        if left_value is False or right_value is False:
            return False
        if left_value is None or right_value is None:
            return None
        return True
    if left_value is True or right_value is True:
        return True
    if left_value is None or right_value is None:
        return None
    return False


# ---------------------------------------------------------------------------
# Manifests.
# ---------------------------------------------------------------------------


@dataclass
class Pin:
    """One requirement line of a manifest, continuation lines joined."""

    name: str
    version: str
    marker: Optional[str]
    hashes: list[str]
    notes: list[str]
    line: int
    operator: str
    problems: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return normalize(self.name)

    @property
    def requirement(self) -> str:
        text = f"{self.name}=={self.version}"
        return f"{text} ; {self.marker}" if self.marker else text


@dataclass
class ManifestText:
    """A parsed manifest: its pins, its as-of date, and what was wrong with it."""

    name: str
    pins: list[Pin]
    as_of: Optional[str]
    problems: list[str]


def _split_requirement(text: str) -> tuple[str, Optional[str]]:
    requirement, separator, marker = text.partition(";")
    return requirement.strip(), (marker.strip() if separator else None)


def parse_manifest(text: str, name: str) -> ManifestText:
    """Parse one manifest.  Problems are collected, never raised.

    Format: the license header and the generated header as one comment block
    ending at the first blank line; then groups separated by blank lines, each
    a run of note comments followed by one requirement whose ``--hash`` options
    sit on backslash-continued lines.  ``--refresh`` writes exactly this, so
    the parser is also the reader for the canonical-form comparison.
    """
    problems: list[str] = []
    pins: list[Pin] = []
    as_of_match = _AS_OF_RE.search(text)
    as_of = as_of_match.group(1) if as_of_match else None
    if as_of is None:
        problems.append(
            f"{name}: header carries no `# {_AS_OF_PREFIX}YYYY-MM-DD` line; "
            "regenerate it with tools/check_release_pins.py --refresh"
        )
    if "\r" in text:
        problems.append(f"{name}: contains a carriage return; the manifest must use LF only")

    lines = text.split("\n")
    in_header = True
    notes: list[str] = []
    index = 0
    while index < len(lines):
        raw = lines[index]
        stripped = raw.strip()
        if not stripped:
            in_header = False
            notes = []
            index += 1
            continue
        if stripped.startswith("#"):
            if not in_header:
                notes.append(stripped[1:].strip())
            index += 1
            continue
        in_header = False
        start = index + 1
        logical = stripped
        while logical.endswith("\\"):
            index += 1
            logical = logical[:-1].rstrip()
            if index >= len(lines):
                problems.append(f"{name}:{start}: continuation backslash at end of file")
                break
            logical += " " + lines[index].strip()
        index += 1
        pins.append(_parse_requirement_line(logical, start, name, list(notes), problems))
        notes = []
    return ManifestText(name=name, pins=pins, as_of=as_of, problems=problems)


def _parse_requirement_line(
    logical: str, line: int, name: str, notes: list[str], problems: list[str]
) -> Pin:
    tokens = logical.split()
    options = [token for token in tokens if token.startswith("-")]
    requirement_text, marker = _split_requirement(
        " ".join(token for token in tokens if not token.startswith("-"))
    )
    where = f"{name}:{line}"
    hashes: list[str] = []
    hash_options = 0
    for option in options:
        match = _HASH_RE.match(option)
        if option.startswith("--hash"):
            hash_options += 1
        if match is None:
            problems.append(
                f"{where}: option {option!r} is not `--hash=sha256:<64 hex>`; "
                "only sha256 hashes are accepted, one per continuation line"
            )
        else:
            hashes.append(match.group(1))
    match = _REQUIREMENT_RE.match(requirement_text)
    if match is None or "," in requirement_text:
        problems.append(
            f"{where}: {requirement_text!r} is not `name==version`; a release pin is "
            "exact, with no ranges and no extras"
        )
        return Pin(requirement_text, "", marker, hashes, notes, line, "")
    pin_name = match.group("name")
    operator = match.group("op") or ""
    version = match.group("version") or ""
    if operator != "==":
        problems.append(
            f"{where}: `{requirement_text}` is not pinned with `==` "
            f"({operator or 'no specifier'}); a floor is not a pin"
        )
    elif _VERSION_RE.match(version) is None:
        problems.append(f"{where}: {version!r} is not a PEP 440 version")
    if not hash_options:
        problems.append(
            f"{where}: `{requirement_text}` carries no --hash; pip --require-hashes "
            "refuses it, and without a hash the version is a name, not bytes"
        )
    if marker is not None:
        try:
            parse_marker(marker)
        except MarkerSyntaxError as exc:
            problems.append(f"{where}: marker {marker!r} does not parse: {exc}")
    return Pin(pin_name, version, marker, hashes, notes, line, operator)


def render_manifest(name: str, pins: Sequence[Pin], as_of: str) -> str:
    """The canonical text of a manifest: what ``--refresh`` writes."""
    header = MANIFEST_HEADERS[name]
    lines = list(LICENSE_HEADER)
    lines.append("#")
    for text in (*header, *_HEADER_TAIL, f"{_AS_OF_PREFIX}{as_of}"):
        lines.append(f"# {text}" if text else "#")
    for pin in pins:
        lines.append("")
        lines.extend(f"# {note}" if note else "#" for note in pin.notes)
        hashes = sorted(set(pin.hashes))
        if not hashes:
            lines.append(pin.requirement)
            continue
        lines.append(f"{pin.requirement} \\")
        for position, digest in enumerate(hashes):
            tail = " \\" if position + 1 < len(hashes) else ""
            lines.append(f"    --hash=sha256:{digest}{tail}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Floors, read from the two files that declare them.
# ---------------------------------------------------------------------------


@dataclass
class Floor:
    name: str
    version: tuple[int, ...]
    source: str


def pyproject_floors(text: str) -> list[Floor]:
    """``[build-system].requires`` entries, each a ``>=`` floor."""
    section = _BUILD_SYSTEM_RE.search(text)
    if section is None:
        return []
    items = _REQUIRES_LIST_RE.search(section.group("body"))
    if items is None:
        return []
    floors: list[Floor] = []
    for match in _FLOOR_ITEM_RE.finditer(items.group("items")):
        if match.group("op") != ">=":
            raise ValueError(
                f"pyproject.toml [build-system].requires pins {match.group(0)} with "
                f"{match.group('op')!r}; this gate reads `>=` floors only"
            )
        floors.append(
            Floor(match.group("name"), release_tuple(match.group("version")), "pyproject.toml")
        )
    return floors


def setup_floors(text: str) -> list[Floor]:
    """``setup.py``'s ``_BUILD_REQS`` preflight table: ``name: ((major, minor, patch), reason)``."""
    block = _SETUP_BUILD_REQS_RE.search(text)
    if block is None:
        return []
    return [
        Floor(
            match.group("name"),
            tuple(int(part) for part in re.split(r"\s*,\s*", match.group("parts").strip())),
            "setup.py",
        )
        for match in _SETUP_FLOOR_RE.finditer(block.group("body"))
    ]


def release_interpreters(document: Any) -> list[str]:
    """Every ``cpXY-*`` in any ``CIBW_BUILD`` value, as ``X.Y`` strings."""
    versions: set[str] = set()
    for location, value in _iter_env_values(document):
        if location.endswith(".CIBW_BUILD"):
            for major, minor in _CP_TAG_RE.findall(value):
                versions.add(f"{major}.{minor}")
    return sorted(versions, key=release_tuple)


# ---------------------------------------------------------------------------
# release.yml.
# ---------------------------------------------------------------------------


def _iter_env_values(document: Any) -> Iterator[tuple[str, str]]:
    """``(location, value)`` for every string under an ``env:`` mapping."""

    def walk(node: Any, trail: str) -> Iterator[tuple[str, str]]:
        if isinstance(node, dict):
            for key, value in node.items():
                here = f"{trail}.{key}" if trail else str(key)
                if key == "env" and isinstance(value, dict):
                    for env_key, env_value in value.items():
                        if isinstance(env_value, str):
                            yield f"{here}.{env_key}", env_value
                else:
                    yield from walk(value, here)
        elif isinstance(node, list):
            for index, item in enumerate(node):
                yield from walk(item, f"{trail}[{index}]")

    yield from walk(document, "")


def _step_label(job_id: str, index: int, step: dict[str, Any]) -> str:
    name = step.get("name")
    return f"job '{job_id}' step {index} ({name})" if name else f"job '{job_id}' step {index}"


def _iter_command_sources(document: Any) -> Iterator[tuple[str, str]]:
    """``(location, text)`` for every ``run:`` block and every ``CIBW_*`` value.

    Workflow- and job-level ``env:`` are walked as well as step ``env:``, so a
    cibuildwheel command moved up a scope is still seen.
    """
    if not isinstance(document, dict):
        return
    env = document.get("env")
    if isinstance(env, dict):
        for key, value in env.items():
            if str(key).startswith("CIBW_") and isinstance(value, str):
                yield f"workflow env {key}", value
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        return
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        env = job.get("env")
        if isinstance(env, dict):
            for key, value in env.items():
                if str(key).startswith("CIBW_") and isinstance(value, str):
                    yield f"job '{job_id}' env {key}", value
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            label = _step_label(str(job_id), index, step)
            run = step.get("run")
            if isinstance(run, str):
                yield f"{label} run", run
            env = step.get("env")
            if isinstance(env, dict):
                for key, value in env.items():
                    if str(key).startswith("CIBW_") and isinstance(value, str):
                        yield f"{label} env {key}", value


def _heredoc_stripped(text: str) -> str:
    """``text`` with every here-document body removed (data, not commands)."""
    out: list[str] = []
    terminator: Optional[str] = None
    for line in text.splitlines():
        if terminator is not None:
            if line.strip() == terminator:
                terminator = None
            continue
        out.append(line)
        match = re.search(r"""<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?\s*$""", line)
        if match and "<<<" not in line:
            terminator = match.group(1)
    return "\n".join(out)


def commands(text: str) -> Iterator[list[str]]:
    """The argv of every command in a script or command string.

    Continuations are joined, here-documents dropped, ``&&``/``||``/``;``/``|``
    split, comments removed by :mod:`shlex`, and leading ``NAME=value``
    assignments stripped so the command word is ``argv[0]``.  A fragment shlex
    cannot tokenise falls back to whitespace splitting: a command this gate
    cannot read must not become a command that does not exist.
    """
    joined = _heredoc_stripped(text).replace("\\\n", " ")
    for line in joined.splitlines():
        for fragment in _COMMAND_SEPARATOR_RE.split(line):
            fragment = fragment.strip()
            if not fragment:
                continue
            try:
                tokens = shlex.split(fragment, comments=True)
            except ValueError:
                tokens = [token for token in fragment.split() if not token.startswith("#")]
            while tokens and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0]):
                tokens = tokens[1:]
            if tokens:
                yield tokens


def _basename(token: str) -> str:
    return token.replace("\\", "/").rsplit("/", 1)[-1]


def pip_subcommand(tokens: Sequence[str]) -> Optional[tuple[str, list[str]]]:
    """``(subcommand, arguments)`` when ``tokens`` runs pip, else ``None``.

    ``pip ...``, ``pip3 ...`` and ``<python> [options] -m pip ...`` are all pip;
    global options before the subcommand are skipped.
    """
    command = _basename(tokens[0])
    rest = list(tokens[1:])
    if command in _PYTHON_COMMANDS:
        if "-m" not in rest:
            return None
        position = rest.index("-m")
        if rest[position + 1 : position + 2] != ["pip"]:
            return None
        rest = rest[position + 2 :]
    elif command not in _PIP_COMMANDS:
        return None
    for position, token in enumerate(rest):
        if token.startswith("-"):
            continue
        return token, rest[position + 1 :]
    return None


def _split_pip_arguments(arguments: Sequence[str]) -> tuple[list[str], list[str], list[str]]:
    """``(options, requirement_files, positionals)`` of a pip subcommand."""
    options: list[str] = []
    requirement_files: list[str] = []
    positionals: list[str] = []
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token in ("-r", "--requirement") and index + 1 < len(arguments):
            requirement_files.append(arguments[index + 1])
            index += 2
            continue
        if token.startswith("--requirement="):
            requirement_files.append(token.partition("=")[2])
        elif token.startswith("-r") and len(token) > 2:
            requirement_files.append(token[2:])
        elif token.startswith("-"):
            options.append(token)
        else:
            positionals.append(token)
        index += 1
    return options, requirement_files, positionals


def classify_pip_command(subcommand: str, arguments: Sequence[str]) -> tuple[str, str]:
    """``("manifest" | "sdist" | "offender", reason)`` for one pip command."""
    options, requirement_files, positionals = _split_pip_arguments(arguments)
    manifests = [_basename(path) for path in requirement_files]
    if (
        subcommand == "install"
        and options == ["--require-hashes"]
        and not positionals
        and len(manifests) == 1
        and manifests[0] in MANIFEST_HEADERS
    ):
        return "manifest", manifests[0]
    if (
        subcommand == "install"
        and "--no-build-isolation" in options
        and set(options) <= _SDIST_INSTALL_OPTIONS
        and not requirement_files
        and positionals
        and all(_SDIST_PATH_RE.match(path) for path in positionals)
    ):
        return "sdist", " ".join(positionals)
    if subcommand != "install":
        return "offender", f"`pip {subcommand}` resolves from the index with no hash pin"
    if any(option.startswith(_INDEX_OPTIONS) for option in options):
        return "offender", "names an index; release builds install pinned manifests only"
    if requirement_files and not all(name in MANIFEST_HEADERS for name in manifests):
        return "offender", (
            f"-r {', '.join(requirement_files)} is not one of the release manifests "
            f"({', '.join(MANIFEST_HEADERS)})"
        )
    if requirement_files and "--require-hashes" not in options:
        return "offender", "installs a manifest without --require-hashes"
    if positionals and all(_SDIST_PATH_RE.match(path) for path in positionals):
        return "offender", (
            "installs the sdist with build isolation, which resolves "
            "[build-system].requires from the index unpinned; add --no-build-isolation"
        )
    return "offender", (
        f"`pip install {' '.join(arguments)}` resolves {', '.join(positionals) or 'its target'} "
        "from the index against no hash; the only permitted installs are "
        "`pip install --require-hashes -r <manifest>` and the built sdist with "
        "--no-build-isolation"
    )


def is_build_invocation(tokens: Sequence[str]) -> bool:
    """``python -m build ...`` or ``pyproject-build ...``."""
    command = _basename(tokens[0])
    if command in _BUILD_COMMANDS:
        return True
    if command in _PYTHON_COMMANDS and "-m" in tokens:
        position = tokens.index("-m")
        return tokens[position + 1 : position + 2] == ["build"]
    return False


def frontend_disables_isolation(value: str) -> bool:
    """Whether a ``CIBW_BUILD_FRONTEND`` value turns build isolation off.

    cibuildwheel parses ``<name>; args: <args>`` (``BuildFrontendConfig.
    from_config_string`` in the pinned 4.2.1); the two accepted forms are the
    pip front end with ``--no-build-isolation`` and the build front end with
    ``--no-isolation``.
    """
    parts = [part.strip() for part in value.split(";")]
    name = parts[0]
    args: list[str] = []
    for part in parts[1:]:
        key, separator, rest = part.partition(":")
        if separator and key.strip() == "args":
            args.extend(shlex.split(rest))
    if name == "pip":
        return "--no-build-isolation" in args
    if name == "build":
        return "--no-isolation" in args or "-n" in args
    return False


def _resolve_frontend(document: dict[str, Any], job: dict[str, Any], step: dict[str, Any]) -> Any:
    """``CIBW_BUILD_FRONTEND`` as the runner composes it: step, then job, then workflow."""
    for scope in (step, job, document):
        env = scope.get("env")
        if isinstance(env, dict) and "CIBW_BUILD_FRONTEND" in env:
            return env["CIBW_BUILD_FRONTEND"]
    return None


@dataclass
class Report:
    problems: list[str] = field(default_factory=list)
    pip_installs: int = 0
    manifest_installs: int = 0
    sdist_installs: int = 0
    build_invocations: int = 0
    cibuildwheel_steps: int = 0
    pins_checked: int = 0
    floors: list[Floor] = field(default_factory=list)
    interpreters: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def check_workflow(document: Any, report: Report) -> None:
    """Checks 3 and 4 over a parsed release.yml."""
    for location, text in _iter_command_sources(document):
        for tokens in commands(text):
            pip = pip_subcommand(tokens)
            if pip is not None:
                subcommand, arguments = pip
                report.pip_installs += 1
                kind, detail = classify_pip_command(subcommand, arguments)
                if kind == "manifest":
                    report.manifest_installs += 1
                elif kind == "sdist":
                    report.sdist_installs += 1
                else:
                    report.problems.append(
                        f"release.yml: {location}: `{' '.join(tokens)}` -- {detail}"
                    )
            if is_build_invocation(tokens):
                report.build_invocations += 1
                if "--no-isolation" not in tokens and "-n" not in tokens:
                    report.problems.append(
                        f"release.yml: {location}: `{' '.join(tokens)}` builds in an "
                        "isolated environment, which resolves [build-system].requires "
                        "from the index unpinned; add --no-isolation"
                    )
    if not isinstance(document, dict):
        return
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        return
    for job_id, job in jobs.items():
        if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
            continue
        for index, step in enumerate(job["steps"]):
            if not isinstance(step, dict) or "cibuildwheel" not in str(step.get("uses", "")):
                continue
            report.cibuildwheel_steps += 1
            frontend = _resolve_frontend(document, job, step)
            if not isinstance(frontend, str) or not frontend_disables_isolation(frontend):
                report.problems.append(
                    f"release.yml: {_step_label(str(job_id), index, step)}: cibuildwheel "
                    f"runs with CIBW_BUILD_FRONTEND={frontend!r}, so pip builds each wheel "
                    "in an isolated environment resolved from the index; set it to "
                    "`pip; args: --no-build-isolation` (or `build; args: --no-isolation`)"
                )


def check_manifests(
    manifests: dict[str, ManifestText],
    floors: Sequence[Floor],
    interpreters: Sequence[str],
    report: Report,
) -> None:
    """Checks 1 and 2 over the parsed manifests."""
    effective: dict[str, tuple[str, tuple[int, ...]]] = {}
    for floor in floors:
        key = normalize(floor.name)
        current = effective.get(key)
        if current is None or compare_release(floor.version, current[1]) > 0:
            effective[key] = (floor.name, floor.version)
    build = manifests.get("requirements-release-build.txt")
    for manifest in manifests.values():
        report.problems.extend(manifest.problems)
        for pin in manifest.pins:
            report.pins_checked += 1
            declared = effective.get(pin.key)
            if declared is None or pin.operator != "==":
                continue
            try:
                pinned = release_tuple(pin.version)
            except ValueError:
                continue
            if compare_release(pinned, declared[1]) < 0:
                report.problems.append(
                    f"{manifest.name}:{pin.line}: {pin.name}=={pin.version} is below the "
                    f"declared floor {declared[0]}>={render_version(declared[1])} "
                    "(pyproject.toml [build-system].requires / setup.py _BUILD_REQS)"
                )
    if build is None:
        return
    for key, (name, version) in sorted(effective.items()):
        pins = [pin for pin in build.pins if pin.key == key]
        if not pins:
            report.problems.append(
                f"requirements-release-build.txt: {name} (floor >={render_version(version)}) "
                "is not pinned; without build isolation nothing else installs it"
            )
            continue
        for interpreter in interpreters:
            environment = {"python_version": interpreter, "python_full_version": f"{interpreter}.0"}
            applies: list[Pin] = []
            maybe: list[Pin] = []
            for pin in pins:
                if pin.marker is None:
                    applies.append(pin)
                    continue
                try:
                    verdict = evaluate_marker(parse_marker(pin.marker), environment)
                except MarkerSyntaxError:
                    # Already reported by the parser; undecided here, so the
                    # one defect is reported once rather than as a cascade.
                    maybe.append(pin)
                    continue
                if verdict is True:
                    applies.append(pin)
                elif verdict is None:
                    maybe.append(pin)
            if len(applies) > 1:
                report.problems.append(
                    f"requirements-release-build.txt: {name}: "
                    f"{len(applies)} pins apply on CPython {interpreter} "
                    f"({', '.join(pin.requirement for pin in applies)}); pip refuses a "
                    "double requirement"
                )
            elif not applies and not maybe:
                report.problems.append(
                    f"requirements-release-build.txt: {name}: no pin applies on CPython "
                    f"{interpreter}, which release.yml builds (CIBW_BUILD); the markers "
                    f"leave that row with no {name}"
                )


def run_checks(repo: Path) -> tuple[Report, Optional[str]]:
    """Run the offline gate over ``repo``.

    Returns ``(report, fatal)``: ``fatal`` names the input that could not be
    read, in which case the report is incomplete and the exit status is 2.
    """
    report = Report()
    manifests: dict[str, ManifestText] = {}
    for name in MANIFEST_HEADERS:
        path = repo / name
        try:
            # Bytes, decoded without newline translation, so a CRLF checkout is
            # seen as the bytes it is rather than normalised away.
            text = path.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return report, f"{name} could not be read: {exc}"
        parsed = parse_manifest(text, name)
        manifests[name] = parsed
        if parsed.as_of is not None and not parsed.problems:
            canonical = render_manifest(name, parsed.pins, parsed.as_of)
            if canonical != text:
                parsed.problems.append(
                    f"{name}: not in the generator's canonical form (sorted hashes, LF, "
                    "generated header); run tools/check_release_pins.py --refresh "
                    f"--as-of {parsed.as_of}"
                )
    try:
        pyproject = (repo / "pyproject.toml").read_text(encoding="utf-8")
        floors = pyproject_floors(pyproject)
        floors += setup_floors((repo / "setup.py").read_text(encoding="utf-8"))
    except OSError as exc:
        return report, f"a floor source could not be read: {exc}"
    except ValueError as exc:
        return report, str(exc)
    if not any(floor.source == "pyproject.toml" for floor in floors):
        return report, "pyproject.toml [build-system].requires declares no floors"
    if not any(floor.source == "setup.py" for floor in floors):
        return report, "setup.py _BUILD_REQS declares no floors"
    report.floors = floors

    workflow = repo / ".github" / "workflows" / "release.yml"
    try:
        document = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        return report, f"release.yml could not be parsed: {exc}"
    report.interpreters = release_interpreters(document)
    if not report.interpreters:
        report.problems.append("release.yml: no CIBW_BUILD value names a cpXY-* interpreter")

    check_manifests(manifests, floors, report.interpreters, report)
    check_workflow(document, report)

    project = _PROJECT_SECTION_RE.search(pyproject)
    if report.sdist_installs and (
        project is None or _EMPTY_DEPENDENCIES_RE.search(project.group("body")) is None
    ):
        report.problems.append(
            "pyproject.toml: [project].dependencies is not the empty list, so the sdist "
            "smoke install would resolve runtime dependencies from the index unpinned"
        )
    if report.pip_installs < MIN_PIP_INSTALLS:
        report.problems.append(
            f"release.yml: only {report.pip_installs} pip install(s) found "
            f"(floor {MIN_PIP_INSTALLS}); a deleted install step would otherwise pass"
        )
    if report.cibuildwheel_steps < MIN_CIBUILDWHEEL_STEPS:
        report.problems.append(
            f"release.yml: only {report.cibuildwheel_steps} cibuildwheel step(s) found "
            f"(floor {MIN_CIBUILDWHEEL_STEPS})"
        )
    if report.build_invocations < MIN_BUILD_INVOCATIONS:
        report.problems.append(
            f"release.yml: only {report.build_invocations} `python -m build` "
            f"invocation(s) found (floor {MIN_BUILD_INVOCATIONS})"
        )
    return report, None


# ---------------------------------------------------------------------------
# --refresh: regenerate the hash sets from PyPI.
# ---------------------------------------------------------------------------

#: ``(name, version) -> parsed JSON``; tests substitute a canned reader.
Fetcher = Callable[[str, str], Any]


def fetch_json(name: str, version: str) -> Any:
    """PyPI's JSON document for ``name==version``.

    The URL is spelled inside the call, as an ``https://pypi.org/`` literal, so
    the scheme and host are fixed in the source rather than chosen by an
    argument; ``urllib`` takes the proxy from the environment.
    """
    with urllib.request.urlopen(
        f"https://pypi.org/pypi/{name}/{version}/json", timeout=60
    ) as response:
        return json.load(response)


def release_hashes(name: str, version: str, fetch: Fetcher = fetch_json) -> list[str]:
    """The sha256 of every file PyPI publishes for ``name==version``, sorted."""
    document = fetch(name, version)
    if not isinstance(document, dict):
        raise ValueError(f"{name}=={version}: PyPI returned no JSON object")
    published = str(document.get("info", {}).get("version", ""))
    if published != version:
        raise ValueError(f"{name}=={version}: PyPI answered for version {published!r}")
    urls = document.get("urls")
    if not isinstance(urls, list) or not urls:
        raise ValueError(f"{name}=={version}: PyPI lists no files for this version")
    hashes: set[str] = set()
    for entry in urls:
        digest = str(entry.get("digests", {}).get("sha256", "")) if isinstance(entry, dict) else ""
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"{name}=={version}: a published file carries no sha256 digest")
        hashes.add(digest)
    return sorted(hashes)


def refresh(repo: Path, as_of: str, check_only: bool, fetch: Fetcher = fetch_json) -> int:
    """Rewrite (or, with ``check_only``, compare) both manifests from PyPI."""
    if _DATE_RE.match(as_of) is None:
        print(f"ERROR: --as-of must be YYYY-MM-DD, got {as_of!r}", file=sys.stderr)
        return 2
    drift = False
    for name in MANIFEST_HEADERS:
        path = repo / name
        try:
            current = path.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            print(f"ERROR: {name} could not be read: {exc}", file=sys.stderr)
            return 2
        parsed = parse_manifest(current, name)
        blocking = [
            problem
            for problem in parsed.problems
            if "carries no --hash" not in problem and "carries no `#" not in problem
        ]
        if blocking:
            for problem in blocking:
                print(f"ERROR: {problem}", file=sys.stderr)
            return 2
        for pin in parsed.pins:
            try:
                pin.hashes = release_hashes(pin.name, pin.version, fetch)
            except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
                print(f"ERROR: {pin.name}=={pin.version}: {exc}", file=sys.stderr)
                return 2
            print(f"  {pin.requirement}: {len(pin.hashes)} published file(s)")
        rendered = render_manifest(name, parsed.pins, as_of)
        if rendered == current:
            print(f"OK    {name} is current")
            continue
        drift = True
        if check_only:
            print(f"DRIFT {name} differs from what --refresh would write")
        else:
            path.write_bytes(rendered.encode("utf-8"))
            print(f"WROTE {name}")
    if check_only and drift:
        print("\nRELEASE PIN REFRESH CHECK FAILED: run --refresh to rewrite.", file=sys.stderr)
        return 1
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify that release.yml installs only the hash-pinned release manifests, at or "
            "above the declared build floors, with build isolation off; or refresh them from "
            "PyPI."
        )
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=REPO_ROOT,
        help="repository root holding the manifests, pyproject.toml, setup.py and release.yml",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="fetch every pin's published hashes from PyPI and rewrite the manifests",
    )
    parser.add_argument(
        "--as-of",
        default=None,
        help="YYYY-MM-DD written into the regenerated header (required with --refresh)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="with --refresh: report drift against PyPI without writing",
    )
    args = parser.parse_args(argv)

    if args.refresh:
        if args.as_of is None:
            parser.error("--refresh requires --as-of YYYY-MM-DD")
        return refresh(args.repo, args.as_of, args.check)
    if args.as_of is not None or args.check:
        parser.error("--as-of and --check apply to --refresh only")

    report, fatal = run_checks(args.repo)
    if fatal is not None:
        print(f"ERROR: {fatal}", file=sys.stderr)
        return 2
    print(
        f"Checked {report.pins_checked} pin(s) against {len(report.floors)} floor(s) "
        f"on CPython {', '.join(report.interpreters) or '(none)'}; "
        f"{report.pip_installs} pip install(s) in release.yml "
        f"({report.manifest_installs} manifest, {report.sdist_installs} sdist), "
        f"{report.cibuildwheel_steps} cibuildwheel step(s), "
        f"{report.build_invocations} build invocation(s)."
    )
    if report.ok:
        print("RELEASE PIN CHECK PASSED.")
        return 0
    print(f"\nRELEASE PIN CHECK FAILED -- {len(report.problems)} problem(s):", file=sys.stderr)
    for problem in report.problems:
        print(f"  - {problem}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
