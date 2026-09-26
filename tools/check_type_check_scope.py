#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Every tracked Python file must be inside the ``mypy --strict`` run.

The type-check step used to name a hand-written list of paths — the shipped
package, the test tree, the gate scripts, four benchmark files — with the
chart, dashboard and comparative generators left out as "demo tooling ...
annotating them adds churn without protecting anything".  Two things were
wrong with that.  The list was maintained by hand, so a new tool joined the
check only if someone remembered to add it.  And the excluded third of the
Python in this repository was not inert: it held a ``dict[str, dict[str,
bool]]`` populated with ints, a coverage matrix built by ``zip`` that would
silently drop a library from the comparison if one row were short, three
``re.search(...).group(1)`` version reads that raise ``AttributeError``
instead of reporting a missing version, a Dilithium keypair dereferenced
without its ``Optional`` check, and four ``create_crypto_package(dna_codes=…)``
calls in the published integration examples naming a parameter the function
has never had.

``ARCHITECTURE.md`` says "type hints throughout (validated via mypy)".  This
gate is what makes that sentence checkable: the scope is now every tracked
``.py`` file, and a new one is in scope by existing rather than by being
remembered.

HOW IT WORKS
============

``mypy --linecoverage-report`` writes a ``coverage.json`` whose ``lines`` map
is keyed by the ABSOLUTE PATH of every SOURCE mypy was given — the files the
command line names, directly or through a directory.  A module mypy only
reached by following an import is analysed (an error in it is reported) but is
NOT a key of that map.  Measured with the pinned mypy 2.3.1, both on a single
followed module and on the CI shape (``MYPYPATH=. mypy --strict
--explicit-package-bases tests/`` with ``tests/`` importing ``schemas.x``):
the report lists ``tests/t.py`` alone.  This docstring used to say the
opposite — that ``schemas/`` and ``wycheproof_vectors/`` were covered by being
imported from ``tests/`` — and the failure message told the reader to "make it
reachable from a checked module", a remedy that could never satisfy this gate.
Both directories are named on the command line in both workflows; that is
what puts them in the report.

This gate reads that report and compares it against ``git ls-files '*.py'``.
A tracked file the report does not mention was not type-checked, whatever the
run's exit status said.

IN THE REPORT IS NOT THE SAME AS CHECKED
========================================

A file can be analysed, and therefore be a key of the report, while every
error in it is thrown away.  Three spellings do that.  Each was measured
against mypy 2.3.1 with a deliberate ``x: int = "s"`` in the file (the
configuration form through both a ``mypy.ini`` ``[mypy-<module>]`` section and
a ``[[tool.mypy.overrides]]`` table): mypy reported no error for the file, and
``coverage.json`` listed it.

* an inline ``# mypy: ignore-errors`` comment (mypy honours it only at column
  0, with any ``ignore-errors`` / ``ignore_errors`` spelling and a true value);
* a bare ``# type: ignore`` before the module's first statement, which mypy
  treats as "ignore the whole module" and marks the body unreachable;
* ``ignore_errors = true`` in a mypy configuration file, globally or in a
  per-module section whose pattern matches the file's module.

So "present in the report" is necessary but not sufficient, and the gate also
rejects any of the three on a tracked file.  Every configuration file mypy
discovers in the repository root is read (``mypy.ini``, ``.mypy.ini``,
``pyproject.toml``, ``setup.cfg``), not only the one mypy would pick: a
silencing section in a file that is not currently selected is one rename away
from being selected.  A per-module pattern is matched against every dotted
suffix of the file's path, because the module name mypy assigns depends on how
it was invoked (``examples.python.flask_integration`` under
``--explicit-package-bases``, ``flask_integration`` without it — the
``pyproject.toml`` overrides for the examples list both for that reason).

``follow_imports = silent`` is the other setting that analyses a module and
discards its errors.  It is not checked here because it cannot reach the
report: it applies only to modules mypy follows into, and those are never keys
of ``coverage.json`` (above), so such a module already fails the first check.

Exit codes
----------
* 0 — every tracked ``.py`` file appears in the report, and none has its
  errors discarded.
* 1 — a tracked file is outside the checked scope, a tracked file's errors are
  discarded, or the report / a source / a configuration file is unreadable
  (fail-closed).
"""

from __future__ import annotations

import argparse
import ast
import configparser
import importlib
import json
import re
import sys
from pathlib import Path
from typing import Any, NamedTuple

REPO = Path(__file__).resolve().parent.parent

#: A report covering fewer files than this has broken, not shrunk.  The tree
#: carries 293 checked files today; the floor sits well below that so ordinary
#: growth and pruning do not trip it, while a collapsed run (one file, or an
#: empty map) cannot read as success.
MIN_REPORTED_FILES = 200

#: Files that are tracked but deliberately outside the type check, each with
#: the reason.  Empty, and meant to stay that way: an entry here is a file
#: whose breakage no one would see.
EXEMPT: dict[str, str] = {}

#: The configuration files mypy discovers in a project directory, in its own
#: order (``mypy/defaults.py``: ``CONFIG_NAMES + SHARED_CONFIG_NAMES``).
MYPY_CONFIG_FILES: tuple[str, ...] = ("mypy.ini", ".mypy.ini", "pyproject.toml", "setup.cfg")

#: The strings ``configparser`` — and therefore mypy, which reads booleans with
#: ``getboolean`` — treats as true.
_TRUE_STRINGS = frozenset({"1", "yes", "true", "on"})

#: mypy's inline-configuration prefix, matched at column 0 exactly as
#: ``mypy.util.get_mypy_comments`` matches it: an indented copy is ignored.
_INLINE_PREFIX = "# mypy: "

#: An INI section that configures mypy: ``[mypy]`` or ``[mypy-<patterns>]``.
_INI_SECTION_RE = re.compile(r"^mypy(?:-(?P<patterns>.+))?$")


class Silencer(NamedTuple):
    """A configuration section that discards every error in the modules it covers.

    ``patterns`` is ``None`` for a global section, which covers every module.
    """

    source: str
    patterns: tuple[str, ...] | None


def _is_true(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in _TRUE_STRINGS


def _setting(section: Any, key: str) -> object:
    """``section[key]``, accepting the dashed spelling too."""
    for spelling in (key, key.replace("_", "-")):
        if spelling in section:
            return section[spelling]
    return None


def _load_toml(path: Path) -> dict[str, Any]:
    """Parse a TOML file with ``tomllib``, or ``tomli`` below Python 3.11.

    ``tomli`` is not declared by this project, but it is a hard dependency of
    pytest, black and mypy on Python < 3.11, so every environment that can run
    this gate or its tests has it; an environment that has neither fails
    closed through the caller rather than reading the file as empty.
    """
    if sys.version_info >= (3, 11):
        import tomllib

        with path.open("rb") as handle:
            return tomllib.load(handle)
    tomli = importlib.import_module("tomli")
    with path.open("rb") as handle:
        loaded: dict[str, Any] = tomli.load(handle)
    return loaded


def _glob_matches(pattern: str, module: str) -> bool:
    """mypy's own module-pattern semantics (``Options.compile_glob``).

    Each ``.*`` matches zero or more further dotted sections, so ``foo.*``
    matches ``foo`` and every submodule and ``foo.*.baz`` matches ``foo.baz``
    and ``foo.a.b.baz``; a pattern without ``*`` is an exact name.
    """
    parts = pattern.split(".")
    expr = re.escape(parts[0]) if parts[0] != "*" else ".*"
    for part in parts[1:]:
        expr += re.escape("." + part) if part != "*" else r"(\..*)?"
    return re.match(expr + r"\Z", module) is not None


def module_name_candidates(rel: str) -> list[str]:
    """Every module name mypy could assign ``rel``, depending on its invocation.

    Each dotted suffix of the path: ``examples/python/flask_integration.py``
    is ``examples.python.flask_integration`` under ``--explicit-package-bases``
    and ``flask_integration`` without it.  A package's ``__init__.py`` is the
    package itself.
    """
    stem = rel[: -len(".py")] if rel.endswith(".py") else rel
    parts = [part for part in stem.split("/") if part]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return [".".join(parts[index:]) for index in range(len(parts))]


def config_silencers(root: Path) -> list[Silencer]:
    """Every configuration section that sets ``ignore_errors`` true.

    Raises ``ValueError`` for a configuration file that cannot be parsed: a
    file mypy may read, and this gate cannot, is not a file this gate may
    report on as clean.
    """
    found: list[Silencer] = []
    for name in MYPY_CONFIG_FILES:
        path = root / name
        if not path.is_file():
            continue
        if name == "pyproject.toml":
            try:
                data = _load_toml(path)
            except (OSError, ValueError, ModuleNotFoundError) as exc:
                raise ValueError(f"{name}: cannot be parsed: {exc}") from exc
            tool = data.get("tool")
            mypy_section = tool.get("mypy") if isinstance(tool, dict) else None
            if not isinstance(mypy_section, dict):
                continue
            if _is_true(_setting(mypy_section, "ignore_errors")):
                found.append(Silencer(f"{name} [tool.mypy]", None))
            overrides = mypy_section.get("overrides") or []
            if not isinstance(overrides, list):
                raise ValueError(f"{name}: [tool.mypy] overrides is not an array of tables")
            for index, override in enumerate(overrides):
                if not isinstance(override, dict):
                    continue
                if not _is_true(_setting(override, "ignore_errors")):
                    continue
                modules = override.get("module")
                patterns = (modules,) if isinstance(modules, str) else tuple(modules or ())
                found.append(
                    Silencer(f"{name} [[tool.mypy.overrides]] #{index + 1}", tuple(patterns))
                )
            continue
        parser = configparser.RawConfigParser()
        try:
            parser.read(path, encoding="utf-8")
        except (OSError, configparser.Error, UnicodeDecodeError) as exc:
            raise ValueError(f"{name}: cannot be parsed: {exc}") from exc
        for section in parser.sections():
            match = _INI_SECTION_RE.match(section)
            if match is None or not _is_true(_setting(parser[section], "ignore_errors")):
                continue
            raw = match.group("patterns")
            section_patterns = None if raw is None else tuple(p.strip() for p in raw.split(","))
            found.append(Silencer(f"{name} [{section}]", section_patterns))
    return found


def _split_directive(text: str) -> list[str]:
    """Split an inline directive on commas outside double quotes (mypy's rule)."""
    parts: list[str] = []
    current: list[str] = []
    quoted = False
    for char in text:
        if char == '"':
            quoted = not quoted
        elif char == "," and not quoted:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if current:
        parts.append("".join(current).strip())
    return parts


def _first_statement_line(node: ast.stmt) -> int:
    """The line mypy attributes a statement to: its first decorator, if any."""
    decorators: list[ast.expr] = list(getattr(node, "decorator_list", None) or [])
    return min([node.lineno] + [decorator.lineno for decorator in decorators])


def source_silencers(source: str) -> list[str]:
    """Why every error in ``source`` would be discarded, one entry per cause.

    Raises ``SyntaxError`` for a source that does not parse — mypy would not
    have checked it either.
    """
    found: list[str] = []
    for lineno, line in enumerate(source.split("\n"), start=1):
        if not line.startswith(_INLINE_PREFIX):
            continue
        for entry in _split_directive(line[len(_INLINE_PREFIX) :]):
            key, has_value, value = entry.partition("=")
            if key.strip().replace("-", "_") != "ignore_errors":
                continue
            if _is_true(value if has_value else "True"):
                found.append(f"line {lineno}: inline `{line.strip()}`")
    tree = ast.parse(source, type_comments=True)
    if tree.type_ignores and tree.body:
        first_ignore = min(ignore.lineno for ignore in tree.type_ignores)
        if first_ignore < _first_statement_line(tree.body[0]):
            found.append(
                f"line {first_ignore}: a `# type: ignore` before the first statement, "
                "which mypy applies to the whole module"
            )
    return found


def tracked_python_files(root: Path) -> list[Path]:
    """Every ``*.py`` file git tracks, as absolute paths.

    git rather than a filesystem walk: a walk needs a hand-maintained list of
    directories to skip (``build/``, ``.venv/``, ``*.egg-info/``, whichever
    ``build-*`` a local run left behind), and that list is exactly the kind of
    thing that drifts and quietly narrows the check.

    Enumerated through ``tools/_repo.py`` (``git ls-files -z``): without ``-z``
    a non-ASCII name came back C-quoted and was compared against mypy's report
    under a name no file has, so the verdict was about a path that does not
    exist rather than the real one.  Raises ``TrackedFilesError`` (a
    ``RuntimeError``) if git fails or a tracked path is not a regular file.
    """
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    from tools._repo import tracked_files

    return tracked_files(root, "*.py")


def reported_files(report: Path) -> set[Path]:
    """The absolute paths mypy recorded in ``coverage.json``."""
    data = json.loads(report.read_text(encoding="utf-8"))
    lines = data.get("lines")
    if not isinstance(lines, dict):
        raise ValueError(f"{report} has no 'lines' map; this is not a mypy coverage report")
    return {Path(key).resolve() for key in lines}


def audit(report: Path, root: Path = REPO) -> list[str]:
    problems: list[str] = []
    try:
        covered = reported_files(report)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [f"cannot read the mypy coverage report at {report}: {exc}"]

    if len(covered) < MIN_REPORTED_FILES:
        return [
            f"the coverage report lists only {len(covered)} file(s) (expected at "
            f"least {MIN_REPORTED_FILES}) — a collapsed run, not a clean tree"
        ]

    try:
        tracked = tracked_python_files(root)
    except RuntimeError as exc:
        return [str(exc)]

    if not tracked:
        return ["git tracks no .py files; refusing to report success on an empty scope"]

    try:
        silencers = config_silencers(root)
    except ValueError as exc:
        return [f"cannot read the mypy configuration: {exc}"]

    for path in sorted(tracked):
        rel = path.relative_to(root).as_posix()
        if rel in EXEMPT:
            continue
        if path.resolve() not in covered:
            problems.append(
                f"{rel}: tracked but never type-checked. Add it to the mypy "
                f"invocation in .github/workflows/ci.yml and ci-build-test.yml — a "
                f"module mypy only follows into is analysed but is not in the "
                f"coverage report, so it cannot satisfy this gate."
            )
            continue
        names = module_name_candidates(rel)
        for silencer in silencers:
            if silencer.patterns is None or any(
                _glob_matches(pattern, module) for pattern in silencer.patterns for module in names
            ):
                problems.append(
                    f"{rel}: analysed, but {silencer.source} sets ignore_errors = true "
                    f"for it, so every type error in it is discarded while the run "
                    f"reports success. Remove the setting and fix the errors it hid."
                )
        try:
            causes = source_silencers(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, SyntaxError, ValueError) as exc:
            problems.append(f"{rel}: cannot be read to check for error suppression: {exc}")
            continue
        for cause in causes:
            problems.append(
                f"{rel}: analysed, but {cause} discards every type error in it while "
                f"the run reports success. Remove it and fix the errors it hid."
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "report",
        help="path to coverage.json from `mypy --linecoverage-report <dir>`",
    )
    parser.add_argument("--root", default=str(REPO))
    args = parser.parse_args(argv)

    problems = audit(Path(args.report), Path(args.root))
    if problems:
        print("TYPE-CHECK SCOPE GATE FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    covered = reported_files(Path(args.report))
    tracked = tracked_python_files(Path(args.root))
    print(
        f"OK: all {len(tracked)} tracked .py file(s) are inside the mypy --strict "
        f"run ({len(covered)} module(s) analysed), and none has its errors discarded."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
