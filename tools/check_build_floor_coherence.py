#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — Build-Dependency Floor Coherence Gate (INVARIANT-53, D-9)
============================================================================

``pyproject.toml``'s ``[build-system].requires`` is the floor an isolated
PEP 517 build resolves.  Seven other places in this tree state a version for
one of those same five packages, and four of them claim, in so many words, to
state the *same* value:

``setup.py``'s ``_BUILD_REQS``
    "Each floor here is kept IDENTICAL to the version pinned there, so the
    guard enforces exactly what an isolated PEP 517 build installs."
``setup.py``'s ``_REMEDY``
    the install line a failing preflight prints for the user to run.
the ``[build-system]`` comment
    "setup.py's preflight check enforces the SAME value so the isolated-build
    requirement and the guard cannot drift."
the preflight comment above ``_BUILD_REQS``
    "the floor is pinned at <version> to match pyproject.toml's
    ``[build-system]``."

The remaining three — ``pyproject.toml``'s extras, ``requirements-dev.txt``,
and every ``pip install`` in ``.github/workflows/**`` — state a minimum rather
than an identity, so they are required to be at or above the floor, not equal
to it.

Why this exists
---------------
Those four claims of identity were enforced by nothing but the comments
asserting them, and a comment is not a gate.

Measured on 2026-11-06, on this branch, before this gate existed.  Dependabot
PR #427 raised setuptools for GHSA-xmj3-9gf7-h52w (Windows path escape via
``.dist-info/namespace_packages.txt`` during legacy wheel installation, every
release from 38.2.2, fixed in 84.1.0).  It rewrote the ``[build-system]``
comment's first line to ``setuptools >= 84.2.1`` and moved
``requirements-dev.txt``, ``requirements-lock.txt`` and
``requirements-release-build.txt`` — and left at ``84.0.0``:

* the same comment's own second sentence ("the floor is pinned at 84.0.0"),
* ``[build-system].requires`` itself — the line an isolated build reads,
* the ``[dev]`` extra's build/packaging mirror,
* ``setup.py``'s ``_BUILD_REQS`` preflight floor,
* ``setup.py``'s ``_REMEDY`` string, and
* ``static-analysis.yml``'s reproducible-wheel build install.

Every gate in the tree passed.  ``tools/check_release_pins.py`` reads both
floor tables, but only to require that the *release manifest pins* are at or
above them; it never compares the two tables with each other, so a floor that
stays behind is invisible to it, and a release manifest moving past a stale
floor reads as compliance.  The advisory's remediation was therefore recorded
as done in the manifests while the declaration that governs
``pip install ama-cryptography`` still admitted the affected version.

The same sweep found two drifts already in the tree, of the same shape and
neither new: ``static-analysis.yml`` and ``integrity-anchor-check.yml``
installed ``cmake>=4.4.3`` beneath a declared floor of ``4.4.4``, and three
lanes installed ``Cython>=3.0.0`` beneath a declared floor of ``3.3.0``.
``setup.py`` carries a comment recording a third instance from before either:
"bumped to cmake>=4.3.2 but setup.py's preflight hadn't matched".  This is a
recurring defect class, not an incident.

Method
------
The floors are **read** from ``pyproject.toml``'s ``[build-system].requires``
through ``check_release_pins.pyproject_floors`` — the same reader the release
gate uses, never a second copy of the list — and every other site is read and
compared against them:

1. ``setup.py``'s ``_BUILD_REQS`` declares the identical package set with
   identical floors (``check_release_pins.setup_floors``).
2. Each prose restatement equals the floor.  Prose is scanned only inside the
   two blocks that make the claim — the ``[build-system]`` section, and the
   comment block immediately above ``_BUILD_REQS`` — so an unrelated or
   deliberately historical mention elsewhere (``setup.py`` has one) is not
   read as a declaration.  A package whose block names no version is not
   required to grow one; a block that names a *different* one fails.
3. ``_REMEDY``'s install tokens equal the floors, and name every package.
4. Every ``>=`` floor for one of these packages in ``pyproject.toml``'s
   ``[project.optional-dependencies]`` and in ``requirements-dev.txt`` is at
   or above the floor.
5. Every ``pip install`` in ``.github/workflows/**`` that gives one of these
   packages a ``>=`` floor is at or above it.  Workflow text is parsed as
   YAML, shell comments are stripped quote-aware, and arguments are read with
   ``shlex``, so a ``#``-commented historical command line (``release.yml`` has
   one) is not read as an install.

No exemption list, per AGENTS.md section 10: a site either states a version
for one of these five packages, in which case it is checked, or it does not
(a bare ``pip install setuptools`` resolves the latest and declares no floor),
in which case there is nothing to check.  Non-vacuity floors below pin the
live counts, so a refactor that stops matching fails here rather than
reporting PASS over nothing.

What is NOT checked, stated plainly (INVARIANT-37)
--------------------------------------------------
That a floor is high enough to clear a known advisory.  This gate proves the
tree states one version, not that the version is the right one; raising it is
Dependabot's job and the reviewer's.  What it guarantees is that a raise
either lands everywhere or fails.  It also does not read
``requirements-lock.txt`` or the hash-pinned release manifests: those carry
``==`` pins, and ``tools/check_release_pins.py`` already holds them at or
above these same floors.
"""

from __future__ import annotations

import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Iterator, Optional

import yaml

# Direct invocation (`python tools/check_build_floor_coherence.py`) puts
# tools/ on sys.path, not the repository root, so the `tools` package the
# readers live in is not importable without this.  ruff permits the import
# below a sys.path edit; mypy resolves it because the name is the package
# path tests/ already import by.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.check_release_pins import (
    Floor,
    normalize,
    pyproject_floors,
    release_tuple,
    setup_floors,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"

#: Non-vacuity floors: the live counts at the commit that added this gate.
#: A tree that matches fewer sites than this is not a tree with less drift,
#: it is a gate that has stopped reading.
MIN_PACKAGES = 5
MIN_PROSE_RESTATEMENTS = 9
MIN_REMEDY_TOKENS = 5
MIN_MANIFEST_FLOORS = 11
MIN_WORKFLOW_FLOORS = 15
MIN_WORKFLOWS_READ = 15

_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"

#: ``[build-system]`` through to the next top-level table.
_BUILD_SYSTEM_SECTION = re.compile(r"^\[build-system\][ \t]*$(?P<body>.*?)(?=^\[|\Z)", re.M | re.S)
#: ``[project.optional-dependencies]`` through to the next top-level table.
_EXTRAS_SECTION = re.compile(
    r"^\[project\.optional-dependencies\][ \t]*$(?P<body>.*?)(?=^\[[a-z]|\Z)", re.M | re.S
)
#: The contiguous comment block documenting the preflight, ending at the table.
_PREFLIGHT_COMMENT_BLOCK = re.compile(r"(?P<body>(?:^#.*\n)+)(?=^_BUILD_REQS\s*=\s*\{)", re.M)
#: ``_REMEDY = ( ... )``.
_REMEDY_BLOCK = re.compile(r"^_REMEDY\s*=\s*\((?P<body>.*?)^\)", re.M | re.S)
#: A prose floor: ``- setuptools >= 84.2.1`` / ``* cmake >= 4.4.4:``.
_PROSE_FLOOR = re.compile(rf"(?P<name>{_NAME})\s*>=\s*(?P<version>\d[0-9A-Za-z.]*)")
#: A requirement floor in a manifest or an extra: ``"numpy>=1.24.0,<3.0.0"``.
_REQUIREMENT_FLOOR = re.compile(rf"(?P<name>{_NAME})\s*>=\s*(?P<version>\d[0-9A-Za-z.]*)")


@dataclass
class Finding:
    """One disagreement, with enough detail to fix it without re-deriving it."""

    site: str
    package: str
    found: str
    expected: str
    relation: str

    def __str__(self) -> str:
        return (
            f"{self.site}: {self.package} {self.found} is {self.relation} the floor "
            f"pyproject.toml [build-system].requires declares ({self.package}>={self.expected})"
        )


def _floor_map(floors: Iterable[Floor]) -> dict[str, Floor]:
    return {normalize(floor.name): floor for floor in floors}


def _dotted(version: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in version)


def strip_shell_comments(script: str) -> str:
    """Drop ``#`` comments from a shell snippet, honouring quotes.

    A naive ``split("#")`` would cut ``'--hash=sha256:...'``-style arguments and
    any ``#`` inside a quoted string; a naive pass over the whole snippet would
    read ``release.yml``'s deliberately historical ``# This used to be `pip
    install 'cmake>=4.4.3'`...`` as a live install.  Both matter here, so the
    scan is per line and quote-aware.
    """
    out: list[str] = []
    for line in script.splitlines():
        quote: Optional[str] = None
        cut = len(line)
        index = 0
        while index < len(line):
            char = line[index]
            if quote is not None:
                if char == "\\" and quote == '"':
                    index += 2
                    continue
                if char == quote:
                    quote = None
            elif char in "'\"":
                quote = char
            elif char == "\\":
                index += 2
                continue
            elif char == "#" and (index == 0 or line[index - 1] in " \t"):
                cut = index
                break
            index += 1
        out.append(line[:cut])
    return "\n".join(out)


def _is_pip_executable(token: str) -> bool:
    """``pip``, ``pip3``, ``pip3.11``, or any of those behind a path.

    ``static-analysis.yml`` invokes ``/opt/python/cp311-cp311/bin/pip`` so the
    manylinux interpreter's pip is the one that runs; matching the bare word
    only made that lane — the one whose setuptools floor had drifted — the one
    lane this gate could not see.  Measured: the mutation test
    ``test_workflow_cmake_below_the_floor_is_caught`` failed against the
    bare-word form and passes against this one.
    """
    name = PurePosixPath(token).name
    return bool(re.fullmatch(r"pip3?(?:\.\d+)?(?:\.exe)?", name))


def _is_python_executable(token: str) -> bool:
    """``python``, ``python3``, ``python3.12``, or any of those behind a path."""
    name = PurePosixPath(token).name
    return bool(re.fullmatch(r"python3?(?:\.\d+)?(?:\.exe)?", name))


def pip_install_arguments(script: str) -> Iterator[str]:
    """Every argument of every ``pip install`` in a shell snippet.

    Line continuations are joined after comments are stripped — a ``#`` comment
    cannot be continued, so stripping first is what keeps a commented line from
    swallowing the command below it.  Both invocation shapes the workflows use
    are recognised: a pip executable directly, and ``<python> -m pip``.
    """
    joined = strip_shell_comments(script).replace("\\\n", " ")
    for line in joined.splitlines():
        if "install" not in line or "pip" not in line:
            continue
        try:
            tokens = shlex.split(line, comments=False)
        except ValueError:
            # An unbalanced quote is a shell defect, not a floor defect;
            # tools/check_workflow_commands.py (INVARIANT-25) owns that.
            continue
        index = 0
        while index < len(tokens):
            consumed = _install_verb_length(tokens, index)
            if consumed == 0:
                index += 1
                continue
            index += consumed
            while index < len(tokens):
                if tokens[index] in {"&&", "||", ";", "|", "&"}:
                    break
                yield tokens[index]
                index += 1


def _install_verb_length(tokens: list[str], index: int) -> int:
    """Tokens consumed by an ``install`` invocation starting at ``index``, else 0."""
    if _is_pip_executable(tokens[index]):
        if index + 1 < len(tokens) and tokens[index + 1] == "install":
            return 2
        return 0
    if _is_python_executable(tokens[index]):
        if tokens[index + 1 : index + 4] == ["-m", "pip", "install"]:
            return 4
    return 0


def _iter_yaml_scripts(node: object) -> Iterator[str]:
    """Every ``run:`` body and every ``env:`` value of a parsed workflow."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in {"run", "env"} or (isinstance(key, str) and key.startswith("CIBW_")):
                if isinstance(value, str):
                    yield value
                elif isinstance(value, dict):
                    for nested in value.values():
                        if isinstance(nested, str):
                            yield nested
            yield from _iter_yaml_scripts(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_yaml_scripts(item)


def check_prose(body: str, site: str, floors: dict[str, Floor]) -> tuple[list[Finding], int]:
    """Prose restatements inside one block must equal the floor."""
    findings: list[Finding] = []
    seen = 0
    for match in _PROSE_FLOOR.finditer(body):
        key = normalize(match.group("name"))
        floor = floors.get(key)
        if floor is None:
            continue
        seen += 1
        stated = release_tuple(match.group("version"))
        if stated != floor.version:
            relation = "below" if stated < floor.version else "above"
            findings.append(
                Finding(
                    site,
                    floor.name,
                    f">={match.group('version')}",
                    _dotted(floor.version),
                    relation,
                )
            )
    return findings, seen


def check_at_or_above(body: str, site: str, floors: dict[str, Floor]) -> tuple[list[Finding], int]:
    """Requirement floors in a manifest or an extra must be at or above."""
    findings: list[Finding] = []
    seen = 0
    for match in _REQUIREMENT_FLOOR.finditer(body):
        key = normalize(match.group("name"))
        floor = floors.get(key)
        if floor is None:
            continue
        seen += 1
        if release_tuple(match.group("version")) < floor.version:
            findings.append(
                Finding(
                    site, floor.name, f">={match.group('version')}", _dotted(floor.version), "below"
                )
            )
    return findings, seen


def run_checks(repo: Path = REPO_ROOT) -> tuple[list[Finding], list[str], dict[str, int]]:
    """Every check. Returns (findings, fatal errors, the counts for non-vacuity)."""
    findings: list[Finding] = []
    fatal: list[str] = []
    counts = {
        "packages": 0,
        "prose": 0,
        "remedy": 0,
        "manifest": 0,
        "workflow": 0,
        "workflows_read": 0,
    }

    pyproject_text = (repo / "pyproject.toml").read_text(encoding="utf-8")
    setup_text = (repo / "setup.py").read_text(encoding="utf-8")

    declared_floors = pyproject_floors(pyproject_text)
    floors = _floor_map(declared_floors)
    counts["packages"] = len(floors)
    if not floors:
        fatal.append("pyproject.toml [build-system].requires declares no floors")
        return findings, fatal, counts

    # 1. setup.py's _BUILD_REQS claims to be identical, package set included.
    preflight = _floor_map(setup_floors(setup_text))
    for key, floor in floors.items():
        guard = preflight.get(key)
        if guard is None:
            findings.append(
                Finding(
                    "setup.py _BUILD_REQS",
                    floor.name,
                    "absent",
                    _dotted(floor.version),
                    "missing from",
                )
            )
        elif guard.version != floor.version:
            relation = "below" if guard.version < floor.version else "above"
            findings.append(
                Finding(
                    "setup.py _BUILD_REQS",
                    floor.name,
                    f">={_dotted(guard.version)}",
                    _dotted(floor.version),
                    relation,
                )
            )
    for key, guard in preflight.items():
        if key not in floors:
            findings.append(
                Finding(
                    "setup.py _BUILD_REQS",
                    guard.name,
                    f">={_dotted(guard.version)}",
                    "(not a build-system requirement)",
                    "declared by only",
                )
            )

    # 2. Prose, scanned only inside the two blocks that claim identity.
    section = _BUILD_SYSTEM_SECTION.search(pyproject_text)
    if section is None:
        fatal.append("pyproject.toml has no [build-system] section to read")
    else:
        body = section.group("body")
        comment_only = "\n".join(
            line for line in body.splitlines() if line.lstrip().startswith("#")
        )
        found, seen = check_prose(comment_only, "pyproject.toml [build-system] comment", floors)
        findings += found
        counts["prose"] += seen

    block = _PREFLIGHT_COMMENT_BLOCK.search(setup_text)
    if block is None:
        fatal.append("setup.py has no comment block above _BUILD_REQS to read")
    else:
        found, seen = check_prose(block.group("body"), "setup.py preflight comment", floors)
        findings += found
        counts["prose"] += seen

    # 3. The remedy a failing preflight prints must name every floor, correctly.
    remedy = _REMEDY_BLOCK.search(setup_text)
    if remedy is None:
        fatal.append("setup.py has no _REMEDY block to read")
    else:
        named: set[str] = set()
        for match in _REQUIREMENT_FLOOR.finditer(remedy.group("body")):
            key = normalize(match.group("name"))
            declared = floors.get(key)
            if declared is None:
                continue
            named.add(key)
            counts["remedy"] += 1
            stated = release_tuple(match.group("version"))
            if stated != declared.version:
                findings.append(
                    Finding(
                        "setup.py _REMEDY",
                        declared.name,
                        f">={match.group('version')}",
                        _dotted(declared.version),
                        "below" if stated < declared.version else "above",
                    )
                )
        for key, floor in floors.items():
            if key not in named:
                findings.append(
                    Finding(
                        "setup.py _REMEDY",
                        floor.name,
                        "absent",
                        _dotted(floor.version),
                        "missing from",
                    )
                )

    # 4. Extras and requirements-dev.txt state a minimum: at or above.
    extras = _EXTRAS_SECTION.search(pyproject_text)
    if extras is not None:
        found, seen = check_at_or_above(
            extras.group("body"), "pyproject.toml [project.optional-dependencies]", floors
        )
        findings += found
        counts["manifest"] += seen
    dev_manifest = repo / "requirements-dev.txt"
    if dev_manifest.exists():
        found, seen = check_at_or_above(
            dev_manifest.read_text(encoding="utf-8"), "requirements-dev.txt", floors
        )
        findings += found
        counts["manifest"] += seen

    # 5. Every workflow pip install of a build package: at or above.
    workflow_dir = repo / ".github" / "workflows"
    for path in sorted(workflow_dir.glob("*.yml")):
        counts["workflows_read"] += 1
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as error:
            fatal.append(f"{path.name} is not parseable YAML: {error}")
            continue
        for script in _iter_yaml_scripts(document):
            for argument in pip_install_arguments(script):
                argument_floor = _REQUIREMENT_FLOOR.search(argument)
                if argument_floor is None or not argument.startswith(argument_floor.group("name")):
                    continue
                declared = floors.get(normalize(argument_floor.group("name")))
                if declared is None:
                    continue
                counts["workflow"] += 1
                if release_tuple(argument_floor.group("version")) < declared.version:
                    findings.append(
                        Finding(
                            f".github/workflows/{path.name}",
                            declared.name,
                            f">={argument_floor.group('version')}",
                            _dotted(declared.version),
                            "below",
                        )
                    )

    return findings, fatal, counts


def _vacuity(counts: dict[str, int]) -> list[str]:
    checks = (
        ("packages", MIN_PACKAGES, "[build-system].requires floors"),
        ("prose", MIN_PROSE_RESTATEMENTS, "prose restatements"),
        ("remedy", MIN_REMEDY_TOKENS, "_REMEDY tokens"),
        ("manifest", MIN_MANIFEST_FLOORS, "manifest/extra floors"),
        ("workflow", MIN_WORKFLOW_FLOORS, "workflow pip-install floors"),
        ("workflows_read", MIN_WORKFLOWS_READ, "workflows read"),
    )
    return [
        f"read {counts[key]} {label}, fewer than the {minimum} this tree ships; "
        "this gate has stopped reading something it used to read"
        for key, minimum, label in checks
        if counts[key] < minimum
    ]


def main() -> int:
    findings, fatal, counts = run_checks()
    vacuous = _vacuity(counts)

    for error in fatal:
        print(f"FATAL: {error}", file=sys.stderr)
    for finding in findings:
        print(f"DRIFT: {finding}", file=sys.stderr)
    for problem in vacuous:
        print(f"VACUOUS: {problem}", file=sys.stderr)

    print(
        f"Read {counts['packages']} build floor(s) against "
        f"{counts['prose']} prose restatement(s), {counts['remedy']} remedy token(s), "
        f"{counts['manifest']} manifest/extra floor(s) and {counts['workflow']} "
        f"workflow pip-install floor(s) across {counts['workflows_read']} workflow(s)."
    )
    if fatal or findings or vacuous:
        print("BUILD FLOOR COHERENCE CHECK FAILED.", file=sys.stderr)
        return 1
    print("BUILD FLOOR COHERENCE CHECK PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
