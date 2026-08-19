#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — Workflow Command Verifier (INVARIANT-25)
===========================================================

Statically verifies the parts of ``.github/workflows/**`` that only fail when
the workflow actually runs — and therefore, for a workflow that runs only on a
tag push, only fail on release day.

Why this exists
---------------
``release.yml`` triggers on ``push: tags: ['v*']`` and nothing else.  Every
defect below sat in it undetected across multiple releases, each one on its
own sufficient to produce a release with zero binary artefacts:

1. **A retired runner label.**  The wheel matrix named ``macos-13`` after
   GitHub retired that image.  The job never received a runner: it queued
   until ``timeout-minutes`` expired, failed ``build-wheels``, and took every
   downstream stage with it.

2. **An inline Python payload broken by YAML folding.**  ``CIBW_TEST_COMMAND``
   was a folded scalar (``>-``), which joins the block's lines with a space.
   The payload reaching the interpreter began with a leading space::

       python -c " import ama_cryptography as a; ..."
                   ^ IndentationError: unexpected indent

   Every wheel built correctly on every platform and then failed this command.

3. **POSIX quoting sent to ``cmd.exe``.**  ``CIBW_BEFORE_BUILD_WINDOWS`` used
   single quotes to protect ``>=`` from shell redirection.  ``cmd.exe`` does
   not treat a single quote as a quoting operator, so pip received the quote
   as part of the requirement and every Windows wheel job died on
   ``Invalid requirement: "'cmake"``.

4. **Release-publishing inputs incompatible with immutable releases.**  Three
   defects in one step, all invisible until a tag was pushed: a ``name:`` that
   reset a hand-edited release title, a ``body:`` that destroyed hand-edited
   release notes, and a prerelease that published before its assets uploaded.
   See :func:`check_release_publishing` for the mechanics.

Each is a *latent outage*, not a style issue, and each is decidable without
running anything.  This checker decides them on the pull request that
introduces them.

What is checked
---------------
``runner labels``
    Every ``runs-on:`` value and every matrix ``os:`` entry must name a
    GitHub-hosted label that currently exists.  Retired labels are reported
    with what replaced them; unrecognised labels fail closed rather than
    being assumed valid.  Expressions (``${{ matrix.os }}``) are resolved
    through the job's own ``strategy.matrix`` where possible and skipped
    otherwise — a label this checker cannot resolve is never silently passed
    off as verified, it is counted separately and reported.

``inline python payloads``
    Any ``python -c "<payload>"`` appearing in a ``run:`` block or in an
    environment value is extracted and handed to :func:`compile`.  A payload
    that does not compile fails the build here rather than on the runner.

``windows shell quoting``
    Command strings that are Windows-specific by construction — the
    ``*_WINDOWS`` cibuildwheel variables, and ``run:`` steps declaring
    ``shell: cmd`` — must not use POSIX single-quoting around arguments.

``cmake build type``
    Every ``cmake`` *configure* in a ``run:`` block must state its optimization
    level, either with ``-DCMAKE_BUILD_TYPE`` or with an explicit ``-O`` inside
    ``CMAKE_C_FLAGS``.  This project sets no default build type, so a configure
    that names neither compiles with no ``-O`` flag at all — which is how ten
    instruction-count constant-time gates came to be measuring an unoptimized
    library.  See :func:`check_cmake_build_type`.

``release publishing``
    Steps using ``softprops/action-gh-release`` must not silently overwrite
    release text a maintainer edited by hand, and must not publish a
    prerelease before its assets have uploaded.  The rules are derived from
    the action's own resolution logic; see :func:`check_release_publishing`.

Known limitation, stated plainly
--------------------------------
The runner-label set is curated, not queried: GitHub publishes no API that
enumerates available hosted labels.  So this check catches a label that is
already known-retired, a typo, and a label that never existed — but it cannot
predict a *future* retirement.  The authoritative detector for that is a
manual dry run of the release workflow (``workflow_dispatch``,
``dry_run: true``) before cutting a tag.  Re-verify the table below against
https://github.com/actions/runner-images#available-images when a retirement
is announced.

Exit status
-----------
``0`` when every check passes, ``1`` when any check fails.
"""

from __future__ import annotations

import argparse
import re
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional, Sequence

import yaml

# --------------------------------------------------------------------------
# Runner labels.
#
# Verified against https://github.com/actions/runner-images#available-images
# and https://docs.github.com/en/actions/reference/runners/github-hosted-runners
# on 2026-07-25.  Keep the two sets disjoint: a label may be supported or
# retired, never both.
# --------------------------------------------------------------------------
SUPPORTED_LABELS: frozenset[str] = frozenset(
    {
        # Linux — x86_64
        "ubuntu-latest",
        "ubuntu-24.04",
        "ubuntu-22.04",
        # Linux — arm64
        "ubuntu-24.04-arm",
        "ubuntu-22.04-arm",
        # macOS — Apple Silicon (arm64)
        "macos-latest",
        "macos-26",
        "macos-15",
        "macos-14",
        # macOS — Intel (x86_64)
        "macos-26-intel",
        "macos-15-intel",
        # Windows
        "windows-latest",
        "windows-2025",
        "windows-2022",
    }
)

#: Labels GitHub has withdrawn, mapped to what a build should use instead.
#: A job naming one of these does not fail fast — it waits for a runner that
#: will never arrive, which is why the replacement matters more than the
#: diagnosis.
RETIRED_LABELS: dict[str, str] = {
    "macos-13": "macos-15-intel (Intel x86_64) or macos-15 (Apple Silicon arm64)",
    "macos-12": "macos-15-intel (Intel x86_64) or macos-15 (Apple Silicon arm64)",
    "macos-11": "macos-15-intel (Intel x86_64) or macos-15 (Apple Silicon arm64)",
    "ubuntu-20.04": "ubuntu-24.04 or ubuntu-latest",
    "ubuntu-18.04": "ubuntu-24.04 or ubuntu-latest",
    "windows-2019": "windows-2025 or windows-latest",
    "windows-2016": "windows-2025 or windows-latest",
}

#: Actions that create or update a GitHub Release.  The step-security fork is
#: a documented drop-in for softprops with the same input names, so the same
#: resolution logic — and the same defects — apply to it.
RELEASE_ACTIONS: tuple[str, ...] = (
    "softprops/action-gh-release",
    "step-security/action-gh-release",
)

#: Environment keys whose value is executed by ``cmd.exe`` on the runner.
WINDOWS_COMMAND_KEYS: tuple[str, ...] = (
    "CIBW_BEFORE_ALL_WINDOWS",
    "CIBW_BEFORE_BUILD_WINDOWS",
    "CIBW_BEFORE_TEST_WINDOWS",
    "CIBW_TEST_COMMAND_WINDOWS",
    "CIBW_REPAIR_WHEEL_COMMAND_WINDOWS",
)

#: ``python -c <payload>``, with the payload in single or double quotes.
#:
#: The two quote styles need separate branches because their escaping rules
#: differ in the shell.  Inside double quotes a backslash escape is legal, and
#: these payloads use it constantly (``\"`` to embed a quote in the Python
#: source); a naive non-greedy ``.*?`` stops at the first ``\"`` and reports a
#: truncated fragment as a syntax error.  Inside single quotes POSIX shells
#: allow no escaping at all, so the payload simply runs to the next ``'``.
#:
#: Intervening tokens are skipped lazily rather than enumerated, so flags that
#: take a value (``-X utf8``, ``-W ignore``) match as readily as bare ones.
#: The skip uses horizontal whitespace only: an invocation does not span lines,
#: and allowing it to would let ``python`` on one line pair with a ``-c`` many
#: lines below it in the same shell script.
_PYTHON_DASH_C = re.compile(
    r"""python[0-9.]*(?:[^\S\n]+\S+)*?[^\S\n]+-c[^\S\n]+"""
    r"""(?:"(?P<dq>(?:[^"\\]|\\.)*)"|'(?P<sq>[^']*)')""",
    re.DOTALL,
)

#: Escapes a POSIX shell honours inside double quotes.  Every other backslash
#: is passed through literally, which matters: Python source in these payloads
#: is full of ``\s`` and ``\d`` regex escapes that must survive intact.
_SH_DQ_ESCAPES = {'"': '"', "\\": "\\", "$": "$", "`": "`", "\n": ""}


def _unescape_double_quoted(payload: str) -> str:
    """Apply the shell's double-quote unescaping to a captured payload.

    Without this the checker compiles the source the *YAML* holds rather than
    the source the *interpreter* receives, and would flag correct workflows.
    """
    out: list[str] = []
    index = 0
    length = len(payload)
    while index < length:
        char = payload[index]
        if char == "\\" and index + 1 < length:
            nxt = payload[index + 1]
            if nxt in _SH_DQ_ESCAPES:
                out.append(_SH_DQ_ESCAPES[nxt])
                index += 2
                continue
        out.append(char)
        index += 1
    return "".join(out)


#: ``${{ ... }}`` expression, e.g. ``${{ matrix.os }}``.
#:
#: The inner text is captured raw and stripped by the caller.  Spelling it
#: ``\s*(?P<inner>[^}]+?)\s*`` instead put three overlapping whitespace
#: matchers in a row — the two ``\s*`` and the whitespace inside ``[^}]`` —
#: around a lazy quantifier, so a run of N spaces could be split among them
#: in O(N^2) ways and ``search`` retried every start offset: cubic.  Measured
#: on ``"${{" + " " * N``: 7.9x per doubling, 634 ms at N=1,000.  With the
#: ``\s*`` gone there is exactly one way to divide the text, and the bound
#: keeps a malformed workflow linear.
_EXPRESSION = re.compile(r"\$\{\{(?P<inner>[^}]{0,500})\}\}")

#: A single-quoted argument, as POSIX shells understand it.
_POSIX_SINGLE_QUOTED_ARG = re.compile(r"(?:^|\s)'[^']+'")


@dataclass
class Finding:
    """One defect, located precisely enough to fix without searching."""

    workflow: str
    location: str
    message: str
    remedy: str = ""


@dataclass
class Report:
    """Outcome of a full sweep."""

    findings: list[Finding] = field(default_factory=list)
    labels_checked: int = 0
    labels_unresolved: list[str] = field(default_factory=list)
    payloads_checked: int = 0
    expressions_checked: int = 0
    windows_commands_checked: int = 0
    release_steps_checked: int = 0
    gated_binaries_checked: int = 0
    cmake_configures_checked: int = 0

    @property
    def ok(self) -> bool:
        return not self.findings


def _iter_jobs(document: Any) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(job_id, job)`` for every job in a parsed workflow."""
    jobs = document.get("jobs") if isinstance(document, dict) else None
    if isinstance(jobs, dict):
        for job_id, job in jobs.items():
            if isinstance(job, dict):
                yield str(job_id), job


def _iter_steps(document: Any) -> Iterator[tuple[str, int, dict[str, Any]]]:
    """Yield ``(job_id, step_index, step)`` for every step in every job."""
    for job_id, job in _iter_jobs(document):
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for index, step in enumerate(steps):
            if isinstance(step, dict):
                yield job_id, index, step


def _is_literal_true(value: Any) -> bool:
    """True only for a value YAML resolves to a definite ``true``.

    A ``${{ ... }}`` expression is deliberately neither true nor false here:
    its value is decided on the runner, so the checker must not pretend to
    know it.
    """
    if value is True:
        return True
    return isinstance(value, str) and value.strip().lower() == "true"


def _is_literal_false(value: Any) -> bool:
    """True only for a value YAML resolves to a definite ``false``."""
    if value is False:
        return True
    return isinstance(value, str) and value.strip().lower() == "false"


def _matrix_values(job: dict[str, Any], key: str) -> Optional[list[str]]:
    """Return every literal value ``strategy.matrix.<key>`` can take.

    Both sources count:

    * the dimension list itself (``matrix.os: [a, b]``);
    * literal ``key:`` values inside ``matrix.include`` entries, which is how
      a job pairs a runner with other per-entry settings.

    Collecting from ``include`` is sound for this purpose even though the full
    combination semantics are more subtle: whether an include entry creates a
    new combination or augments an existing one, a literal ``os:`` in it is a
    label the workflow will really ask for.  ``exclude`` is not consulted —
    removing combinations can only shrink the set, never introduce a label.

    Returns ``None`` when no literal value can be recovered, so the caller can
    report the reference as unresolved instead of assuming it is fine.
    """
    strategy = job.get("strategy")
    if not isinstance(strategy, dict):
        return None
    matrix = strategy.get("matrix")
    if not isinstance(matrix, dict):
        return None

    values: list[str] = []
    dimension = matrix.get(key)
    if isinstance(dimension, list):
        values.extend(str(v) for v in dimension if isinstance(v, (str, int, float)))

    include = matrix.get("include")
    if isinstance(include, list):
        for entry in include:
            if isinstance(entry, dict) and isinstance(entry.get(key), (str, int, float)):
                values.append(str(entry[key]))

    if not values:
        return None
    # Preserve order for stable output while dropping duplicates.
    return list(dict.fromkeys(values))


def _resolve_runs_on(raw: Any, job: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Expand a ``runs-on:`` value into concrete labels.

    Returns ``(resolved, unresolved)``.  ``unresolved`` holds expressions this
    checker could not evaluate; the caller reports them rather than treating
    them as verified.
    """
    candidates: list[str] = []
    if isinstance(raw, str):
        candidates = [raw]
    elif isinstance(raw, list):
        candidates = [str(v) for v in raw]
    elif isinstance(raw, dict):
        # `runs-on: {group: ..., labels: [...]}` — self-hosted runner groups.
        labels = raw.get("labels")
        candidates = [str(v) for v in labels] if isinstance(labels, list) else []

    resolved: list[str] = []
    unresolved: list[str] = []
    for candidate in candidates:
        match = _EXPRESSION.fullmatch(candidate.strip())
        if match is None:
            if _EXPRESSION.search(candidate):
                unresolved.append(candidate)
            else:
                resolved.append(candidate)
            continue
        inner = match.group("inner").strip()
        if inner.startswith("matrix."):
            values = _matrix_values(job, inner[len("matrix.") :])
            if values is None:
                unresolved.append(candidate)
            else:
                resolved.extend(values)
        else:
            unresolved.append(candidate)
    return resolved, unresolved


def check_runner_labels(path: Path, document: Any, report: Report) -> None:
    """Every runner label must name an image that currently exists."""
    for job_id, job in _iter_jobs(document):
        resolved, unresolved = _resolve_runs_on(job.get("runs-on"), job)

        for label in unresolved:
            report.labels_unresolved.append(f"{path.name}:{job_id}: {label}")

        for label in resolved:
            report.labels_checked += 1
            if label in SUPPORTED_LABELS:
                continue
            if label in RETIRED_LABELS:
                report.findings.append(
                    Finding(
                        workflow=path.name,
                        location=f"job '{job_id}'",
                        message=f"runner label {label!r} has been retired by GitHub",
                        remedy=(
                            f"use {RETIRED_LABELS[label]}.  A retired label does not fail "
                            "fast — the job queues until timeout-minutes expires."
                        ),
                    )
                )
            else:
                report.findings.append(
                    Finding(
                        workflow=path.name,
                        location=f"job '{job_id}'",
                        message=f"runner label {label!r} is not a known GitHub-hosted image",
                        remedy=(
                            "fix the typo, or add the label to SUPPORTED_LABELS in "
                            "tools/check_workflow_commands.py after verifying it against "
                            "https://github.com/actions/runner-images#available-images"
                        ),
                    )
                )


def _iter_command_strings(document: Any) -> Iterator[tuple[str, str]]:
    """Yield ``(location, command)`` for every executable string in a workflow.

    Covers ``run:`` blocks and ``env:``/``with:`` values at workflow, job and
    step scope — an inline ``python -c`` is just as broken in an environment
    variable that a tool later executes as it is in a ``run:``.
    """

    def walk(node: Any, trail: list[str]) -> Iterator[tuple[str, str]]:
        if isinstance(node, dict):
            for key, value in node.items():
                label = str(key)
                if label == "run" and isinstance(value, str):
                    yield (".".join([*trail, "run"]), value)
                elif label in {"env", "with"} and isinstance(value, dict):
                    for env_key, env_value in value.items():
                        if isinstance(env_value, str):
                            yield (".".join([*trail, label, str(env_key)]), env_value)
                else:
                    yield from walk(value, [*trail, label])
        elif isinstance(node, list):
            for index, item in enumerate(node):
                yield from walk(item, [*trail, f"[{index}]"])

    yield from walk(document, [])


def check_inline_python(path: Path, document: Any, report: Report) -> None:
    """Every embedded ``python -c`` payload must compile."""
    for location, command in _iter_command_strings(document):
        for match in _PYTHON_DASH_C.finditer(command):
            if match.group("dq") is not None:
                payload = _unescape_double_quoted(match.group("dq"))
            else:
                payload = match.group("sq")
            report.payloads_checked += 1
            try:
                compile(payload, f"<{path.name}:{location}>", "exec")
            except SyntaxError as exc:
                report.findings.append(
                    Finding(
                        workflow=path.name,
                        location=location,
                        message=(
                            f"inline `python -c` payload does not compile: "
                            f"{type(exc).__name__}: {exc.msg}"
                        ),
                        remedy=(
                            "a YAML folded scalar (>-) joins lines with a space, so a "
                            "block-style payload arrives indented.  Put the code in a "
                            "file and call it, or keep it on one line."
                        ),
                    )
                )


def _windows_run_steps(document: Any) -> Iterator[tuple[str, str]]:
    """Yield ``(location, command)`` for ``run:`` steps executed by cmd.exe."""
    for job_id, job in _iter_jobs(document):
        job_shell = job.get("defaults", {}).get("run", {}).get("shell")
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            shell = step.get("shell", job_shell)
            command = step.get("run")
            if shell == "cmd" and isinstance(command, str):
                yield (f"job '{job_id}' step [{index}]", command)


def check_windows_quoting(path: Path, document: Any, report: Report) -> None:
    """cmd.exe does not strip single quotes — they must not be used there."""
    candidates: list[tuple[str, str]] = list(_windows_run_steps(document))
    for location, command in _iter_command_strings(document):
        key = location.rsplit(".", 1)[-1]
        if key in WINDOWS_COMMAND_KEYS:
            candidates.append((location, command))

    for location, command in candidates:
        report.windows_commands_checked += 1
        offenders = [m.group(0).strip() for m in _POSIX_SINGLE_QUOTED_ARG.finditer(command)]
        if offenders:
            report.findings.append(
                Finding(
                    workflow=path.name,
                    location=location,
                    message=(
                        "Windows command uses POSIX single-quoting: "
                        + ", ".join(sorted(set(offenders))[:4])
                    ),
                    remedy=(
                        "cmd.exe passes the quote through as a literal character, so the "
                        'argument arrives malformed.  Use double quotes ("cmake>=4.3.4"), '
                        "which cmd.exe honours and which still shield >= from redirection."
                    ),
                )
            )


def check_shell_parseable(path: Path, document: Any, report: Report) -> None:
    """Single-line command strings must at least tokenise as a shell would.

    An unbalanced quote is the other way a command string silently becomes
    something other than what was written.  Multi-line ``run:`` blocks are
    scripts with heredocs and loops, so they are left to the shell itself;
    this applies to the single-line strings where balance is unambiguous.
    """
    for location, command in _iter_command_strings(document):
        if "\n" in command or "${{" in command:
            continue
        try:
            shlex.split(command)
        except ValueError as exc:
            report.findings.append(
                Finding(
                    workflow=path.name,
                    location=location,
                    message=f"command string does not tokenise: {exc}",
                    remedy="balance the quoting, or move the command into a script file.",
                )
            )


def check_release_publishing(path: Path, document: Any, report: Report) -> None:
    """Release-creating steps must be safe under immutable releases and re-runs.

    Immutable releases freeze a release's tag and assets at publish time; the
    title and notes stay editable.  That makes the intended flow *publish via
    the workflow, then edit the text by hand* — and it makes two of this
    action's inputs destructive, because a workflow re-run for the same tag
    takes the action's ``updateRelease`` path and overwrites what was edited.

    All three rules below are read off the action's own resolution logic
    rather than its documentation:

    ``name``
        ``updateRelease`` resolves ``input_name || existingRelease.name ||
        tag``.  Passing a name therefore replaces a hand-edited title with
        whatever the workflow hardcodes.  Omitting it is not a regression for
        a first run: ``createRelease`` already falls back to ``input_name ||
        tag``, which is the bare tag either way.

    ``body`` / ``body_path`` without ``append_body``
        The body resolves as ``workflowBody || existingReleaseBody`` unless
        ``append_body`` is set, in which case an existing body is preserved
        and the workflow's text is appended to it.  Without the flag a re-run
        silently destroys the release notes.  ``createRelease`` never consults
        ``append_body``, so setting it costs a first run nothing.

    ``prerelease`` without ``draft``
        ``createRelease`` computes ``draft = prerelease === true ?
        input_draft === true : true`` — only a *non*-prerelease is drafted
        automatically.  A prerelease is therefore published immediately, its
        assets freeze, and the upload that follows fails with *Cannot upload
        assets to an immutable release*.  Checked only when the step actually
        uploads ``files``: with no assets there is nothing for the freeze to
        catch.

    An expression (``${{ ... }}``) counts as neither true nor false.  A step
    that drives ``draft`` from the same expression as ``prerelease`` has
    handled the case, and this checker does not second-guess a value it
    cannot evaluate.
    """
    for job_id, index, step in _iter_steps(document):
        uses = step.get("uses")
        if not isinstance(uses, str):
            continue
        if not any(action in uses for action in RELEASE_ACTIONS):
            continue

        inputs = step.get("with")
        if not isinstance(inputs, dict):
            inputs = {}
        report.release_steps_checked += 1
        location = f"job '{job_id}' step [{index}]"

        if "name" in inputs:
            report.findings.append(
                Finding(
                    workflow=path.name,
                    location=location,
                    message=(
                        "release step sets `name:`, which resets a hand-edited release "
                        "title on any re-run for the same tag"
                    ),
                    remedy=(
                        "omit `name:`.  updateRelease resolves `input_name || "
                        "existingRelease.name || tag`, so a hardcoded name wins over the "
                        "edited title; createRelease already defaults to the tag, so a "
                        "first run is unchanged."
                    ),
                )
            )

        has_body = "body" in inputs or "body_path" in inputs
        if has_body and not _is_literal_true(inputs.get("append_body")):
            report.findings.append(
                Finding(
                    workflow=path.name,
                    location=location,
                    message=(
                        "release step sets `body:`/`body_path:` without `append_body: true`, "
                        "which destroys hand-edited release notes on any re-run for the "
                        "same tag"
                    ),
                    remedy=(
                        "add `append_body: true`.  The body otherwise resolves as "
                        "`workflowBody || existingReleaseBody` and the workflow text wins.  "
                        "createRelease never consults append_body, so a first run still "
                        "gets the workflow body verbatim."
                    ),
                )
            )

        prerelease = inputs.get("prerelease")
        may_be_prerelease = "prerelease" in inputs and not _is_literal_false(prerelease)
        draft = inputs.get("draft")
        draft_never_true = "draft" not in inputs or _is_literal_false(draft)
        if "files" in inputs and may_be_prerelease and draft_never_true:
            report.findings.append(
                Finding(
                    workflow=path.name,
                    location=location,
                    message=(
                        "release step can publish a prerelease with assets but never drafts "
                        "it, so under immutable releases the assets freeze before they upload"
                    ),
                    remedy=(
                        "drive `draft:` from the same condition as `prerelease:`.  "
                        "createRelease computes `draft = prerelease === true ? input_draft "
                        "=== true : true`, so only a non-prerelease is drafted "
                        "automatically; a published prerelease fails the upload with "
                        "'Cannot upload assets to an immutable release'."
                    ),
                )
            )


#: ``option(NAME "help" ON|OFF)`` in the top-level CMakeLists.
_CMAKE_OPTION_RE = re.compile(r"^\s*option\(\s*(AMA_\w+)\s+\"[^\"]*\"\s+(ON|OFF)\s*\)", re.M)
#: ``AMA_ENABLE_*`` identifiers appearing in an ``if(...)`` condition.
_CMAKE_FLAG_RE = re.compile(r"\b(AMA_\w+)\b")
#: A binary a workflow runs out of the CMake build tree.
_BUILD_BIN_RE = re.compile(r"\./build/bin/([A-Za-z0-9_]+)")


def cmake_option_defaults(cmakelists: Path) -> dict[str, str]:
    """``{option_name: "ON"|"OFF"}`` from the top-level CMakeLists."""
    try:
        text = cmakelists.read_text(encoding="utf-8")
    except OSError:
        return {}
    return {m.group(1): m.group(2) for m in _CMAKE_OPTION_RE.finditer(text)}


def cmake_gated_targets(cmake_files: Sequence[Path]) -> dict[str, set[str]]:
    """``{executable_name: {flags whose if() guards it}}``.

    A deliberately small block-structured scan: track ``if(``/``endif(`` nesting,
    remember the ``AMA_*`` identifiers named by each open condition, and attribute
    them to every ``add_executable`` inside.  Derived from CMake rather than a
    hand-maintained table, so a target added under a new guard is covered without
    anyone remembering to update this file.
    """
    gated: dict[str, set[str]] = {}
    for path in cmake_files:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        stack: list[set[str]] = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("if("):
                stack.append(set(_CMAKE_FLAG_RE.findall(stripped)))
            elif stripped.startswith("elseif("):
                if stack:
                    stack[-1] = set(_CMAKE_FLAG_RE.findall(stripped))
            elif stripped.startswith("endif("):
                if stack:
                    stack.pop()
            match = re.match(r"add_executable\(\s*([A-Za-z0-9_]+)", stripped)
            if match:
                flags: set[str] = set()
                for frame in stack:
                    flags |= frame
                gated.setdefault(match.group(1), set()).update(flags)
    return gated


def check_cmake_gated_binaries(path: Path, document: Any, report: Report) -> None:
    """Every ``./build/bin/X`` a job runs must be a target that job builds.

    Why this exists
    ---------------
    ``dudect-legacy-harnesses`` configures CMake — but without
    ``-DAMA_ENABLE_DUDECT=ON``, because it exists to build the standalone
    ``tools/constant_time`` harnesses.  A ``./build/bin/test_dudect`` invocation
    added to that job is therefore a guaranteed ``exit 127``, and that is not a
    hypothetical: it shipped, on this branch, from an edit that inserted the same
    line into every run step in the file and matched one more step than intended.

    Nothing caught it before CI did, because the mistake is invisible at the
    point it is made — the line is correct in the four jobs above and below it.
    The property that distinguishes them is not in the workflow at all, it is in
    ``tests/c/CMakeLists.txt``: the target sits inside ``if(AMA_ENABLE_DUDECT)``,
    and that option defaults ``OFF``.

    So the guard is read from CMake and matched against each job's own configure
    flags.  Only options that default ``OFF`` are required explicitly; a target
    behind an ON-by-default guard is built without anyone asking, and demanding
    the flag would be noise.
    """
    repo_root = path.resolve().parent.parent.parent
    defaults = cmake_option_defaults(repo_root / "CMakeLists.txt")
    gated = cmake_gated_targets(sorted(repo_root.glob("tests/**/CMakeLists.txt")))

    for job_id, job in _iter_jobs(document):
        run_text = "\n".join(
            step.get("run", "") or ""
            for _, _, step in _iter_steps({"jobs": {job_id: job}})
            if isinstance(step, dict)
        )
        if not run_text:
            continue
        for binary in sorted(set(_BUILD_BIN_RE.findall(run_text))):
            required = {
                flag
                for flag in gated.get(binary, set())
                # An ON-by-default guard needs no flag; an unknown identifier is
                # not an option() and cannot be asserted about.
                if defaults.get(flag) == "OFF"
            }
            missing = sorted(flag for flag in required if f"-D{flag}=ON" not in run_text)
            report.gated_binaries_checked += 1
            if missing:
                report.findings.append(
                    Finding(
                        workflow=path.name,
                        location=f"jobs.{job_id}",
                        message=(
                            f"runs ./build/bin/{binary}, which tests/c/CMakeLists.txt "
                            f"builds only under {', '.join(missing)} (default OFF), "
                            f"but this job's cmake configure does not enable it"
                        ),
                        remedy=(
                            f"add -D{missing[0]}=ON to this job's cmake configure, or "
                            f"invoke a binary this job actually builds. A job that runs "
                            f"a binary it never built exits 127."
                        ),
                    )
                )


#: A `cmake` *configure* invocation: `cmake -B <dir>`, `cmake -S . -B <dir>`,
#: `cmake -D... <src>`, or `cmake <path-to-source>`.
#:
#: The shape of the FIRST argument is what identifies it, and that is
#: deliberate.  Matching the bare word `cmake` matches it as a package name in
#: `apt-install.sh cmake clang`, as a pip requirement in `'cmake>=4.4.0'`, and
#: in `cmake --build` / `--install` / `-E`, none of which take a build type.
#: The lookbehind additionally keeps `>=`, `/` and `-` off the front so a
#: version specifier or a path ending in `cmake` is not read as an invocation.
_CMAKE_CONFIGURE_RE = re.compile(r"(?<![\w./>=-])cmake\s+(?:-[BSD]|\.\.?(?=$|[\s/])|/)")

#: An explicit optimization level inside a `-DCMAKE_C_FLAGS=...` (or CXX) value.
_EXPLICIT_OPT_RE = re.compile(r"-O(?:[0-3]|s|z|fast|g)\b")


def _cmake_configure_commands(run_text: str) -> list[str]:
    """Every cmake configure command in a run block, line continuations joined.

    A configure spread over ten backslash-continued lines is one command, and
    every flag on those lines belongs to it.  Reading line by line would report
    a missing build type on the first line of every multi-line configure in the
    tree.
    """
    joined: list[str] = []
    buffer = ""
    for raw in run_text.split("\n"):
        line = raw.rstrip()
        stripped = line.strip()
        if buffer:
            buffer += " " + stripped.rstrip("\\").strip()
            if not line.endswith("\\"):
                joined.append(buffer)
                buffer = ""
            continue
        if stripped.startswith("#"):
            continue
        if not _CMAKE_CONFIGURE_RE.search(stripped):
            continue
        if line.endswith("\\"):
            buffer = stripped.rstrip("\\").strip()
        else:
            joined.append(stripped)
    if buffer:
        joined.append(buffer)
    return joined


def check_cmake_build_type(path: Path, document: Any, report: Report) -> None:
    """Every cmake configure in a workflow must state its optimization level.

    Why this exists
    ---------------
    ``CMakeLists.txt`` sets no default ``CMAKE_BUILD_TYPE``, and every
    optimization flag this project adds lives in ``CMAKE_C_FLAGS_RELEASE`` /
    ``_DEBUG``.  A configure that names no build type therefore compiles the
    library with **no** ``-O`` flag at all — not "the default", not "-O2", but
    unoptimized — and nothing in the log says so.

    That is not a style matter.  ``dudect.yml`` built the AMA_TESTING_MODE
    archive that way and ran all ten instruction-count constant-time targets
    against it.  Those targets exist to catch a transformation the *optimizer*
    performs (see ``src/c/internal/ama_ct_barrier.h``), so at ``-O0`` there was
    nothing for them to find and every one reported PASS.  Rebuilt at ``-O3``,
    ``--target ecdsa`` immediately measured a 9,424-instruction key-dependent
    spread in the secp256k1 scalar arithmetic under clang 18: a live Montgomery
    extra-reduction leak on the ECDSA signing path, which the gate had been
    passing over for as long as it had built the library the way it did.

    A job may legitimately want the unoptimized configuration — the strict
    warning sweep builds it deliberately, because some diagnostics only appear
    without the optimizer and some only with it.  What it may not do is leave
    that unstated: ``-DCMAKE_BUILD_TYPE=None`` says "no configuration flags, on
    purpose" in CMake's own vocabulary, and is accepted here.  An explicit
    ``-O`` inside ``CMAKE_C_FLAGS`` (what the sanitizer jobs pass) is likewise
    a statement of intent and is accepted.

    So the rule is not "must be Release" — it is "must say".
    """
    for job_id, job in _iter_jobs(document):
        for _, index, step in _iter_steps({"jobs": {job_id: job}}):
            if not isinstance(step, dict):
                continue
            run_text = step.get("run") or ""
            if not isinstance(run_text, str) or not run_text:
                continue
            for command in _cmake_configure_commands(run_text):
                report.cmake_configures_checked += 1
                if "CMAKE_BUILD_TYPE" in command:
                    continue
                if _EXPLICIT_OPT_RE.search(command):
                    continue
                report.findings.append(
                    Finding(
                        workflow=path.name,
                        location=f"jobs.{job_id}.steps[{index}]",
                        message=(
                            "cmake configure names neither -DCMAKE_BUILD_TYPE nor an "
                            "explicit -O in CMAKE_C_FLAGS, so it builds the library "
                            "with no optimization flag at all: "
                            + (command[:110] + "..." if len(command) > 110 else command)
                        ),
                        remedy=(
                            "add -DCMAKE_BUILD_TYPE=Release (or Debug / "
                            "RelWithDebInfo), or -DCMAKE_BUILD_TYPE=None if the "
                            "unoptimized build is the point. CMakeLists.txt sets no "
                            "default, so omitting it is not 'the usual build' — it is "
                            "-O0, and it silently invalidated every instruction-count "
                            "constant-time gate in dudect.yml."
                        ),
                    )
                )


#: Every operator GitHub Actions' expression grammar admits.
#:
#: The list is short and closed: logical `!`, `&&`, `||`; the comparisons
#: `<`, `<=`, `>`, `>=`, `==`, `!=`; grouping; indexing; and the documented
#: functions.  There is NO arithmetic.  `${{ matrix.sve_vq * 128 }}` is not a
#: wrong value — it is a parse error, and a workflow file that does not parse
#: never runs and never reports.
#:
#: That is exactly what happened to `.github/workflows/arm-qemu.yml`: the
#: expression above made the whole file invalid, so the AArch64 cross-tests,
#: the SVE2 lanes at VL=128 and VL=256, and the aggregating `ARM QEMU Gate`
#: produced no check on any pull request. The gate did not fail — it never
#: started, which looks identical to "not applicable to this change".
#:
#: Found by dispatching the workflow (GitHub answers `422 Invalid Argument -
#: failed to parse workflow`), not by any check in this repository.  It is
#: checked here now.
_ARITHMETIC_IN_EXPRESSION_RE = re.compile(
    r"\$\{\{(?P<body>[^}]*)\}\}",
)

#: Arithmetic operators, matched only where they can be an operator: between
#: two operand-ish characters.  Written narrowly so ordinary content inside an
#: expression — a `-` inside a quoted string, a `/` in a path literal, a `!` —
#: does not produce a false positive.
_ARITHMETIC_OPERATOR_RE = re.compile(r"[\w)\]]\s*[*/%+]\s*[\w(]")

#: A single-quoted GitHub-expression string literal, `''` being the escape.
_EXPRESSION_LITERAL_RE = re.compile(r"'(?:[^']|'')*'")


def _iter_expression_strings(node: Any, trail: str = "") -> list[tuple[str, str]]:
    """Every string in the document that contains a `${{ ... }}` expression."""
    found: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            found.extend(_iter_expression_strings(value, f"{trail}.{key}" if trail else str(key)))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(_iter_expression_strings(value, f"{trail}[{index}]"))
    elif isinstance(node, str) and "${{" in node:
        found.append((trail or "<root>", node))
    return found


def check_expression_syntax(path: Path, document: Any, report: Report) -> None:
    """Reject expression forms GitHub's parser rejects.

    Only arithmetic today, because that is the class that has actually shipped
    here and because it is decidable without reimplementing the grammar. YAML
    parses the file fine — the operator is inside a string as far as YAML is
    concerned — so this cannot be caught by loading the document, which is why
    the existing YAML guard in :func:`sweep` did not see it.
    """
    for location, text in _iter_expression_strings(document):
        for match in _ARITHMETIC_IN_EXPRESSION_RE.finditer(text):
            report.expressions_checked += 1
            body = match.group("body")
            # Blank single-quoted string literals first.  GitHub expressions
            # quote with `'` only, and their CONTENTS are data: `'refs/heads/main'`
            # contains a `/` between two word characters and would otherwise read
            # as a division.  Replaced with spaces rather than removed so the
            # reported text keeps its shape.
            scannable = _EXPRESSION_LITERAL_RE.sub(lambda m: " " * len(m.group(0)), body)
            operator = _ARITHMETIC_OPERATOR_RE.search(scannable)
            if operator is None:
                continue
            report.findings.append(
                Finding(
                    workflow=path.name,
                    location=location,
                    message=(
                        f"expression `${{{{{body}}}}}` uses the arithmetic operator "
                        f"`{operator.group(0).strip()}`. GitHub Actions expressions have no "
                        f"arithmetic; this makes the WHOLE FILE fail to parse, so every job "
                        f"in it silently produces no check at all."
                    ),
                    remedy=(
                        "carry the computed value in the matrix (matrix.include) or an env "
                        "var instead of computing it in the expression."
                    ),
                )
            )


def sweep(workflows_dir: Path) -> Report:
    """Run every check across every workflow file."""
    report = Report()
    paths = sorted(workflows_dir.glob("*.yml")) + sorted(workflows_dir.glob("*.yaml"))
    for path in paths:
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            report.findings.append(
                Finding(
                    workflow=path.name,
                    location="<file>",
                    message=f"could not be parsed as YAML: {exc}",
                    remedy="a workflow the runner cannot parse never runs at all.",
                )
            )
            continue
        check_runner_labels(path, document, report)
        check_inline_python(path, document, report)
        check_windows_quoting(path, document, report)
        check_shell_parseable(path, document, report)
        check_release_publishing(path, document, report)
        check_cmake_gated_binaries(path, document, report)
        check_cmake_build_type(path, document, report)
        check_expression_syntax(path, document, report)
    return report


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify GitHub Actions runner labels and embedded command strings."
    )
    parser.add_argument(
        "--workflows-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / ".github" / "workflows",
        help="directory of workflow files to check (default: this repository's)",
    )
    args = parser.parse_args(argv)

    report = sweep(args.workflows_dir)

    print(
        f"Checked {report.labels_checked} runner label(s), "
        f"{report.payloads_checked} inline python payload(s), "
        f"{report.windows_commands_checked} Windows command string(s), "
        f"{report.release_steps_checked} release-publishing step(s), "
        f"{report.gated_binaries_checked} CMake-gated binary invocation(s), "
        f"{report.cmake_configures_checked} cmake configure(s), "
        f"{report.expressions_checked} `${{{{ }}}}` expression(s)."
    )
    if report.labels_unresolved:
        # Reported, never counted as verified.  Silence here would read as
        # "all labels checked" when some were not.
        print("\nRunner labels this checker could not resolve statically:")
        for entry in report.labels_unresolved:
            print(f"  ?  {entry}")

    if report.ok:
        print("\nWORKFLOW COMMAND CHECK PASSED.")
        return 0

    print(
        f"\nWORKFLOW COMMAND CHECK FAILED — {len(report.findings)} problem(s):\n", file=sys.stderr
    )
    for finding in report.findings:
        print(f"  {finding.workflow}: {finding.location}", file=sys.stderr)
        print(f"      {finding.message}", file=sys.stderr)
        if finding.remedy:
            print(f"      -> {finding.remedy}", file=sys.stderr)
        print(file=sys.stderr)
    print(
        "Each of these fails only when the workflow runs.  For release.yml that "
        "means release day.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
