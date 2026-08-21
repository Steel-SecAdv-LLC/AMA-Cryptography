#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — Aggregating Gate Coverage Verifier (INVARIANT-31)
====================================================================

Verifies that every job which runs on a pull request is actually capable of
blocking that pull request.

Why this exists
---------------
Branch protection on this repository requires the *aggregating gate* context
of each primary workflow (``ci-gate``, ``static-analysis-gate``,
``fuzzing-gate``, …) rather than the individual job names.  That design is
deliberate and documented in each gate's own comment: it means adding,
renaming, or matrix-expanding a job updates a ``needs:`` list under code
review instead of drifting the branch-protection configuration out of sync
(*required-context drift*).

The design has one failure mode, and it is silent in the worst possible
direction.  A job that is **not** listed in its workflow's gate ``needs:``
still runs, still reports its own red X on the pull request — and still
cannot block a merge, because branch protection never evaluates its context.
The pull request shows a failing check next to a green required gate, and
"all required checks passed" is true.

That is not hypothetical here.  ``c-library-no-native-pqc`` in
``ci-build-test.yml`` guards the ``AMA_USE_NATIVE_PQC=OFF`` configuration —
the build for consumers who take the library without native post-quantum
support.  It was absent from ``ci-gate``'s ``needs:`` while commit ``f3dd0c2``
of this branch had to repair that exact configuration after it broke
undetected.  The guard job existed, ran, and gated nothing.

Every gate comment in this repository asserts "every job in this workflow
runs unconditionally … so each MUST be ``success``".  This checker is what
makes that sentence true rather than aspirational.

What is checked
---------------
``gate presence``
    A workflow that triggers on ``pull_request`` and defines more than one
    job must define an aggregating gate job.  Single-job workflows are
    exempt: the job *is* its own status context, so there is nothing to
    aggregate.  Workflows that never trigger on ``pull_request`` (``release.yml``
    on a tag push, ``wiki-sync.yml`` on a push to main) are exempt: branch
    protection cannot require a context they never produce.

``gate coverage``
    Every non-gate job in a workflow must appear in the ``needs:`` of some
    gate job in that workflow.  ``needs:`` is workflow-local, so each
    workflow is checked independently.

``gate reachability``
    Every gate job must carry a job-level ``if: always()``.  Without it the
    gate is *skipped* when any dependency fails, and a required context that
    reports ``skipped`` never resolves — the pull request sits on "Expected —
    waiting for status check to be reported" indefinitely rather than going
    red.  A gate that cannot report red is not a gate.

Both directions are pinned by ``tests/test_gate_coverage.py``, so this gate
cannot silently degrade into a no-op.

Usage
-----
::

    python tools/check_gate_coverage.py

Exits 0 when every workflow satisfies the invariant, 1 otherwise.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

# A job is an aggregating gate iff its job id ends with this suffix.  Every
# gate in the repository follows the convention (`ci-gate`, `dudect-gate`,
# `static-analysis-gate`, …); enforcing the naming keeps detection mechanical
# rather than heuristic.
GATE_SUFFIX = "-gate"

WORKFLOW_DIR = Path(".github/workflows")


def _load(path: Path) -> dict[Any, Any]:
    """Parse a workflow file, returning ``{}`` for anything unparseable."""
    with path.open(encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)
    return loaded if isinstance(loaded, dict) else {}


def _triggers(workflow: dict[Any, Any]) -> dict[Any, Any]:
    """Return the ``on:`` block.

    PyYAML resolves the bare key ``on`` to the boolean ``True`` under the
    YAML 1.1 rules it implements, so the block has to be looked up under both
    keys — and the mapping is therefore genuinely ``dict[Any, Any]``, not
    ``dict[str, Any]``.  Reading only ``"on"`` silently reports every workflow
    as having no triggers, which would make this entire checker vacuous.
    """
    raw = workflow.get(True, workflow.get("on"))
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        return {raw: None}
    if isinstance(raw, list):
        return dict.fromkeys(raw)
    return {}


def _needs(job: dict[str, Any]) -> set[str]:
    """Normalise ``needs:``, which GitHub accepts as a string or a list."""
    raw = job.get("needs") or []
    if isinstance(raw, str):
        return {raw}
    return {entry for entry in raw if isinstance(entry, str)}


#: A gate step that consults ``needs.*.result`` evaluates EVERY dependency by
#: construction — adding a job to ``needs:`` extends the check with no further
#: edit.  Four of this repository's six aggregating gates are written that way.
_WILDCARD_NEEDS_RE = re.compile(r"needs\.\*\.(?:result|outputs|conclusion)")


def _gate_body_text(job: dict[str, Any]) -> str:
    """Everything in a gate job that could reference a dependency by name.

    Serialised rather than walked, because a reference can appear in a step's
    ``run``, its ``if``, its ``env`` values, a ``with:`` input or the job-level
    ``env`` — and the property being checked is only "is this id mentioned at
    all", for which the flattened text is exactly right and cannot go stale as
    the schema grows.

    ``needs:`` itself is REMOVED first.  Leaving it in makes the check a
    tautology — every id in the list appears in the serialisation of the list —
    which is the same shape of vacuity as ``check_ctypes_abi``'s floor test
    comparing REQUIRED_MODULES against a set that unions it in.
    """
    body = {key: value for key, value in job.items() if key != "needs"}
    return json.dumps(body, default=str)


def _unevaluated_needs(job: dict[str, Any]) -> list[str]:
    """Dependencies the gate lists but never looks at.

    ``needs:`` membership alone does not make a job blocking.  It makes the
    gate WAIT for the job; whether the gate goes red when that job fails is
    decided by the gate's own step, and two of this repository's gates —
    ``dudect-gate`` and ``static-analysis-gate`` — hand-enumerate each
    dependency into an ``env:`` block and call a shell ``check`` function once
    per job.  A job added to ``needs:`` but not to that hand-written list
    satisfies INVARIANT-31's coverage rule and is still never evaluated: the
    gate carries ``if: always()``, so it runs anyway, ``rc`` stays 0, and the
    final step prints that every job reached the state the trigger requires.
    """
    body = _gate_body_text(job)
    if _WILDCARD_NEEDS_RE.search(body):
        return []
    return sorted(need for need in _needs(job) if need not in body)


def _is_always(job: dict[str, Any]) -> bool:
    """True when the job carries a job-level condition equivalent to always()."""
    condition = job.get("if")
    if condition is None:
        return False
    # Accept `always()`, `${{ always() }}`, and surrounding whitespace.  Any
    # richer expression is rejected: a gate whose reachability depends on a
    # compound condition is exactly the ambiguity this check exists to remove.
    normalised = str(condition).strip()
    for wrapper in ("${{", "}}"):
        normalised = normalised.replace(wrapper, "")
    return normalised.strip() == "always()"


def check_workflow(path: Path) -> list[str]:
    """Return a list of human-readable failures for one workflow file."""
    return check_parsed(path.name, _load(path))


def check_parsed(name: str, workflow: dict[Any, Any]) -> list[str]:
    """Check an already-parsed workflow document.

    Split out from :func:`check_workflow` so the rules can be exercised
    against synthetic documents without writing files.
    """
    jobs: dict[str, Any] = workflow.get("jobs") or {}
    if not jobs:
        return []

    failures: list[str] = []

    gate_ids = {job_id for job_id in jobs if job_id.endswith(GATE_SUFFIX)}
    other_ids = set(jobs) - gate_ids

    on_pull_request = "pull_request" in _triggers(workflow)

    if not gate_ids:
        # Exempt when there is nothing an aggregating gate could add: a
        # single-job workflow is its own status context, and a workflow that
        # never runs on a pull request produces no context branch protection
        # could require.
        if on_pull_request and len(jobs) > 1:
            failures.append(
                f"{name}: {len(jobs)} jobs run on pull_request but the workflow "
                f"defines no aggregating gate job (expected a job id ending in "
                f"'{GATE_SUFFIX}'). Branch protection would have to require each "
                f"job by name, which is the required-context drift this "
                f"convention exists to prevent."
            )
        return failures

    covered: set[str] = set()
    for gate_id in sorted(gate_ids):
        gate = jobs[gate_id] or {}
        covered |= _needs(gate)
        if not _is_always(gate):
            failures.append(
                f"{name}: gate job '{gate_id}' has no job-level `if: always()`. "
                f"Without it the gate is skipped when a dependency fails, and a "
                f"required context reporting 'skipped' never resolves — the pull "
                f"request waits for a status that never arrives instead of going "
                f"red."
            )
        unevaluated = _unevaluated_needs(gate)
        if unevaluated:
            failures.append(
                f"{name}: gate job '{gate_id}' lists {len(unevaluated)} "
                f"dependenc(y/ies) it never evaluates — {', '.join(unevaluated)}. "
                f"`needs:` only makes the gate WAIT for a job; whether the gate "
                f"goes red when it fails is decided by the gate's own step. This "
                f"gate hand-enumerates its dependencies, so a job added to "
                f"`needs:` and not to that list runs, fails, and leaves the gate "
                f"green — with `if: always()` the gate runs regardless and its "
                f"exit status never sees the failure. Reference each dependency "
                f"in the gate's steps, or switch the gate to the "
                f"`contains(needs.*.result, 'failure')` form, which cannot go "
                f"stale."
            )

    missing = sorted(other_ids - covered)
    if missing:
        gate_label = "/".join(sorted(gate_ids))
        failures.append(
            f"{name}: {len(missing)} job(s) absent from the '{gate_label}' "
            f"needs: list — {', '.join(missing)}. Each still runs and still "
            f"reports its own result, but branch protection evaluates only the "
            f"gate context, so none of them can block a merge."
        )

    # A `needs:` entry naming a job that does not exist is a hard workflow
    # error at run time, but it surfaces as the gate never starting rather
    # than as a red gate — worth catching statically alongside the coverage.
    dangling = sorted(covered - set(jobs))
    if dangling:
        failures.append(
            f"{name}: gate needs: references undefined job(s) "
            f"{', '.join(dangling)}. The gate will fail to start rather than "
            f"report red."
        )

    return failures


def audit(workflow_dir: Path = WORKFLOW_DIR) -> tuple[list[str], int]:
    """Check every workflow. Returns (failures, number of files examined)."""
    paths = sorted(list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml")))
    failures: list[str] = []
    for path in paths:
        failures.extend(check_workflow(path))
    return failures, len(paths)


def main() -> int:
    if not WORKFLOW_DIR.is_dir():
        print(f"ERROR: {WORKFLOW_DIR} not found — run from the repository root.")
        return 1

    failures, examined = audit()

    print("INVARIANT-31: aggregating gate coverage")
    print(f"  workflows examined: {examined}")

    if failures:
        print(f"  FAIL — {len(failures)} finding(s):\n")
        for failure in failures:
            print(f"    ::error::{failure}\n")
        return 1

    print("  PASS — every pull-request job is reachable from its workflow's gate.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
