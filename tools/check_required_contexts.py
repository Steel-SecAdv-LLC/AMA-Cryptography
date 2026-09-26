#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — Required Status Context Verifier
===================================================

Verifies that every status context the default branch's ruleset REQUIRES is
still produced by a job that runs on a pull request, and reports which of this
repository's aggregating gate jobs the ruleset does not require.

Why this exists
---------------
The ruleset on ``main`` names individual job contexts — ``Python 3.10 on
windows-latest``, ``Test windows-latest / Python 3.10`` and 53 others — as
required status checks.  Those names are produced by job ``name:`` templates
expanded over their matrices, so renaming a job, dropping a matrix cell, or
moving a leg from one workflow to another removes a required context without
any file in this repository saying so.  GitHub then waits for a context that
will never report, and the pull request cannot merge until an administrator
edits the ruleset.

That is not hypothetical.  A 2026-09-24 change on PR #394 removed the
ubuntu-latest and windows-latest legs of ``ci-build-test.yml::python-package``
as duplicates of ``ci.yml::test`` — cell for cell they were — and so removed
ten contexts the ruleset requires.  Every check the branch ran stayed green;
the merge was blocked all the same.  The change was reverted.

The ruleset lives outside the repository, so this reads a snapshot of it,
``.github/required-status-checks.json`` (captured from the public rules
endpoint; ``--live`` re-reads the endpoint and reports drift, ``--write``
refreshes the snapshot).  The snapshot is the reviewed record: changing the
required set means changing that file in the same pull request.

The second report is an inventory, not a check.  ``check_gate_coverage.py``
(INVARIANT-31) makes every pull-request job reachable from an aggregating gate
on the premise that branch protection requires the gates.  Measured on
2026-09-24, the ruleset requires none of them, so a job that is reachable only
through a gate — the sanitizer lanes, the reproducible build, the ARM QEMU and
constant-time lanes — reports its red X without blocking a merge.  Closing
that needs the gate contexts added to the ruleset, which only an administrator
can do; until then the listing states the gap on every run (AGENTS.md section
10: where a blocking check would need an exemption list, the artefact is a
measurement producing a reviewed inventory).

Exit status
-----------
  0  every required context is produced by a pull-request job
  1  a required context has no producing job (or, with --live, the snapshot
     differs from the ruleset)
  2  the snapshot or a workflow could not be read
"""

from __future__ import annotations

import argparse
import itertools
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

import yaml

# Executed directly as a script, so `tools/` lands on sys.path but the repo root
# does not; the shared fetch policy lives in the root's `tools` package.
REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tools.http_fetch import fetch_bytes  # noqa: E402 -- repo-root path insert above (FETCH-003)

WORKFLOW_DIR = REPO / ".github" / "workflows"
SNAPSHOT = REPO / ".github" / "required-status-checks.json"
RULES_URL = "https://api.github.com/repos/Steel-SecAdv-LLC/AMA-Cryptography/rules/branches/main"

_MATRIX_REF = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}")
_ANY_EXPR = re.compile(r"\$\{\{.*?\}\}")


def _triggers(workflow: dict[Any, Any]) -> dict[Any, Any]:
    """The ``on:`` block; PyYAML reads the bare key ``on`` as ``True``."""
    raw = workflow.get(True, workflow.get("on"))
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        return {raw: None}
    if isinstance(raw, list):
        return dict.fromkeys(raw)
    return {}


def runs_on_pull_requests_to(workflow: dict[Any, Any], base: str = "main") -> bool:
    """Whether a pull request into ``base`` triggers this workflow."""
    triggers = _triggers(workflow)
    for event in ("pull_request", "pull_request_target"):
        if event not in triggers:
            continue
        config = triggers[event] or {}
        branches = config.get("branches") if isinstance(config, dict) else None
        if branches is None or base in branches or "**" in branches or "*" in branches:
            return True
    return False


def _value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def matrix_combinations(matrix: Any) -> list[dict[str, Any]] | None:
    """The combinations a ``strategy.matrix`` expands to, or ``None`` when the
    matrix is an expression (``fromJSON(...)``) that cannot be read statically.

    Follows GitHub's documented rules: the product of the base keys, minus
    every ``exclude`` entry that matches, then each ``include`` entry is merged
    into every combination whose ORIGINAL values it does not overwrite, or
    appended as a new combination when it fits none.
    """
    if matrix is None:
        return []
    if not isinstance(matrix, dict):
        return None
    base = {k: v for k, v in matrix.items() if k not in ("include", "exclude")}
    if any(not isinstance(v, list) for v in base.values()):
        return None
    keys = list(base)
    combos: list[dict[str, Any]] = (
        [dict(zip(keys, values)) for values in itertools.product(*base.values())] if keys else []
    )
    for entry in matrix.get("exclude") or []:
        combos = [c for c in combos if not all(c.get(k) == v for k, v in entry.items())]
    # An include merges only into the ORIGINAL combinations; one appended by an
    # earlier include is not a merge target (an include-only matrix is one
    # combination per entry).
    original = list(combos)
    for entry in matrix.get("include") or []:
        merged = False
        for combo in original:
            if all(combo.get(k) == v for k, v in entry.items() if k in base):
                combo.update(entry)
                merged = True
        if not merged:
            combos.append(dict(entry))
    return combos


def _render(name: str, combo: dict[str, Any]) -> str:
    """``name`` with each ``${{ matrix.KEY }}`` replaced by the combination's value."""
    return _MATRIX_REF.sub(lambda m: _value(combo[m.group(1)]), name)


def job_contexts(job_id: str, job: dict[str, Any]) -> tuple[set[str], list[str]]:
    """``(contexts, unresolved)`` — the check names one job reports, and a
    description of any name this reader could not expand."""
    name = str(job.get("name", job_id))
    combos = matrix_combinations((job.get("strategy") or {}).get("matrix"))
    if combos is None:
        return set(), [f"{job_id}: matrix is an expression; its names cannot be read statically"]
    if not combos:
        if _ANY_EXPR.search(name):
            return set(), [f"{job_id}: name {name!r} uses an expression outside a matrix"]
        return {name}, []
    contexts: set[str] = set()
    unresolved: list[str] = []
    for combo in combos:
        if _MATRIX_REF.search(name):
            missing = [k for k in _MATRIX_REF.findall(name) if k not in combo]
            if missing:
                unresolved.append(f"{job_id}: combination {combo} has no value for {missing}")
                continue
            rendered = _render(name, combo)
            if _ANY_EXPR.search(rendered):
                unresolved.append(f"{job_id}: name {name!r} uses a non-matrix expression")
                continue
            contexts.add(rendered)
        else:
            contexts.add(f"{name} ({', '.join(_value(v) for v in combo.values())})")
    return contexts, unresolved


def pull_request_contexts(
    workflows: Iterable[tuple[str, dict[Any, Any]]],
) -> tuple[dict[str, str], list[str]]:
    """``(context -> "workflow::job", unresolved)`` over every job a pull
    request into main runs."""
    produced: dict[str, str] = {}
    unresolved: list[str] = []
    for filename, workflow in workflows:
        if not runs_on_pull_requests_to(workflow):
            continue
        for job_id, job in (workflow.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            contexts, problems = job_contexts(str(job_id), job)
            unresolved.extend(f"{filename}::{p}" for p in problems)
            for context in contexts:
                produced.setdefault(context, f"{filename}::{job_id}")
    return produced, unresolved


def load_workflows(directory: Path = WORKFLOW_DIR) -> list[tuple[str, dict[Any, Any]]]:
    loaded = []
    for path in sorted(directory.glob("*.yml")) + sorted(directory.glob("*.yaml")):
        with path.open(encoding="utf-8") as handle:
            parsed = yaml.safe_load(handle)
        if isinstance(parsed, dict):
            loaded.append((path.name, parsed))
    return loaded


def load_snapshot(path: Path = SNAPSHOT) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    contexts = data.get("contexts")
    if not isinstance(contexts, list) or not all(isinstance(c, str) for c in contexts):
        raise ValueError(f"{path}: 'contexts' must be a list of strings")
    return contexts


def missing_contexts(required: Iterable[str], produced: dict[str, str]) -> list[str]:
    """Required contexts no pull-request job produces, in snapshot order."""
    return [c for c in required if c not in produced]


def unrequired_gates(
    workflows: Iterable[tuple[str, dict[Any, Any]]], required: Iterable[str]
) -> list[str]:
    """Aggregating gate jobs (id ending ``-gate``) whose context the ruleset
    does not require."""
    required_set = set(required)
    out = []
    for filename, workflow in workflows:
        if not runs_on_pull_requests_to(workflow):
            continue
        for job_id, job in (workflow.get("jobs") or {}).items():
            if not isinstance(job, dict) or not str(job_id).endswith("-gate"):
                continue
            name = str(job.get("name", job_id))
            if name not in required_set:
                out.append(f"{name}  ({filename}::{job_id})")
    return sorted(set(out))


def fetch_live(url: str = RULES_URL) -> list[str]:
    """Required contexts from the public rules endpoint (no credential needed
    for a public repository), through the tree's one HTTPS fetch helper."""
    rules = json.loads(fetch_bytes(url, user_agent="ama-cryptography-required-contexts"))
    contexts: list[str] = []
    for rule in rules:
        if rule.get("type") == "required_status_checks":
            for check in rule.get("parameters", {}).get("required_status_checks", []):
                contexts.append(str(check["context"]))
    return contexts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--snapshot", type=Path, default=SNAPSHOT)
    parser.add_argument("--workflows", type=Path, default=WORKFLOW_DIR)
    parser.add_argument(
        "--live", action="store_true", help="also compare the snapshot with the live ruleset"
    )
    parser.add_argument(
        "--write", action="store_true", help="with --live: rewrite the snapshot's contexts"
    )
    args = parser.parse_args(argv)

    try:
        required = load_snapshot(args.snapshot)
        workflows = load_workflows(args.workflows)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"REQUIRED-CONTEXT CHECK: cannot read inputs: {exc}", file=sys.stderr)
        return 2

    rc = 0
    produced, unresolved = pull_request_contexts(workflows)
    missing = missing_contexts(required, produced)
    for problem in unresolved:
        print(f"  note: {problem}")
    if missing:
        rc = 1
        print(
            f"REQUIRED-CONTEXT CHECK FAILED — {len(missing)} of {len(required)} required "
            "status context(s) are produced by no pull-request job, so a pull request "
            "cannot merge until the ruleset changes:",
            file=sys.stderr,
        )
        for context in missing:
            print(f"  {context}", file=sys.stderr)
    else:
        print(f"OK    {len(required)} required status context(s) each produced by a PR job")

    gates = unrequired_gates(workflows, required)
    if gates:
        print(
            f"INVENTORY  {len(gates)} aggregating gate(s) not required by the ruleset "
            "(their failure does not block a merge; adding them needs a ruleset change):"
        )
        for gate in gates:
            print(f"  {gate}")

    if args.live:
        try:
            live = fetch_live()
        except OSError as exc:
            print(f"REQUIRED-CONTEXT CHECK: live ruleset unreadable: {exc}", file=sys.stderr)
            return 2
        if sorted(live) != sorted(required):
            added = sorted(set(live) - set(required))
            removed = sorted(set(required) - set(live))
            print(f"DRIFT  live ruleset differs: +{added} -{removed}", file=sys.stderr)
            if args.write:
                data = json.loads(args.snapshot.read_text(encoding="utf-8"))
                data["contexts"] = live
                args.snapshot.write_text(
                    json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
                )
                print(f"wrote {args.snapshot}")
            else:
                rc = 1
        else:
            print("OK    snapshot matches the live ruleset")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
