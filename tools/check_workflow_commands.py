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
_EXPRESSION = re.compile(r"\$\{\{\s*(?P<inner>[^}]+?)\s*\}\}")

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
    windows_commands_checked: int = 0

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
        inner = match.group("inner")
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
        f"{report.windows_commands_checked} Windows command string(s)."
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
