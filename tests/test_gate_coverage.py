#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Tests for the aggregating gate coverage verifier (``tools/check_gate_coverage.py``).

Branch protection on this repository requires each workflow's aggregating gate
context rather than the individual job names, which keeps the required-context
list under code review instead of in the branch-protection UI.  The cost of
that design is a silent failure mode: a job omitted from its gate's ``needs:``
still runs and still reports its own red X, but branch protection never
evaluates its context, so it cannot block a merge.  The pull request shows a
failing check beside a green required gate and reports that all required
checks passed.

``c-library-no-native-pqc`` sat in exactly that state — the guard for the
``AMA_USE_NATIVE_PQC=OFF`` build, omitted from ``ci-build-test.yml``'s gate
while that configuration broke and had to be repaired in commit ``f3dd0c2``.

Both directions are pinned here, because a checker that only ever reports
"clean" is indistinguishable from one that has stopped working:

* **Detection** — an uncovered job, a gate without ``if: always()``, a
  multi-job pull-request workflow with no gate at all, and a ``needs:`` entry
  naming a job that does not exist.
* **Non-detection** — the shapes this repository legitimately uses: single-job
  pull-request workflows (the job is its own status context), multi-job
  workflows that never trigger on ``pull_request`` (``release.yml``), and
  gates spread across more than one aggregating job.

The final test sweeps the repository's own workflows, so a future edit that
adds a job without wiring it into the gate fails on the pull request that
introduces it rather than silently stopping gating anything.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import yaml

from tools.check_gate_coverage import audit, check_parsed

REPO_ROOT = Path(__file__).resolve().parent.parent


def check(source: str, name: str = "test.yml") -> list[str]:
    """Parse a workflow fragment and run the gate-coverage rules over it."""
    return check_parsed(name, yaml.safe_load(textwrap.dedent(source)))


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------


def test_job_absent_from_gate_needs_is_reported() -> None:
    """The exact shape c-library-no-native-pqc was in."""
    failures = check("""
        on:
          pull_request:
        jobs:
          build:
            runs-on: ubuntu-latest
          build-no-native-pqc:
            runs-on: ubuntu-latest
          ci-gate:
            if: always()
            needs:
              - build
            runs-on: ubuntu-latest
        """)
    assert len(failures) == 1
    assert "build-no-native-pqc" in failures[0]
    assert "none of them can block a merge" in failures[0]
    # The covered job must not be named as missing.
    assert "— build," not in failures[0]


def test_gate_without_always_is_reported() -> None:
    """A gate that reports `skipped` never resolves as a required context."""
    failures = check("""
        on:
          pull_request:
        jobs:
          build:
            runs-on: ubuntu-latest
          ci-gate:
            needs: [build]
            runs-on: ubuntu-latest
        """)
    assert len(failures) == 1
    assert "always()" in failures[0]


def test_multi_job_pull_request_workflow_without_a_gate_is_reported() -> None:
    failures = check("""
        on:
          pull_request:
        jobs:
          alpha:
            runs-on: ubuntu-latest
          beta:
            runs-on: ubuntu-latest
        """)
    assert len(failures) == 1
    assert "no aggregating gate job" in failures[0]


def test_gate_needing_an_undefined_job_is_reported() -> None:
    """A dangling `needs:` makes the gate fail to start, not report red."""
    failures = check("""
        on:
          pull_request:
        jobs:
          build:
            runs-on: ubuntu-latest
          ci-gate:
            if: always()
            needs: [build, typoed-job]
            runs-on: ubuntu-latest
        """)
    assert len(failures) == 1
    assert "typoed-job" in failures[0]
    assert "undefined job" in failures[0]


# --------------------------------------------------------------------------
# Non-detection — shapes the repository legitimately uses
# --------------------------------------------------------------------------


def test_single_job_pull_request_workflow_is_exempt() -> None:
    """baseline-guard.yml: the one job IS the status context."""
    assert check("""
            on:
              pull_request:
                paths: ['benchmarks/baseline.json']
            jobs:
              baseline-justification:
                runs-on: ubuntu-latest
            """) == []


def test_workflow_that_never_runs_on_pull_request_is_exempt() -> None:
    """release.yml: eight jobs, tag-triggered, no context to require."""
    assert check("""
            on:
              push:
                tags: ['v*']
              workflow_dispatch:
            jobs:
              preflight:
                runs-on: ubuntu-latest
              build-wheels:
                runs-on: ubuntu-latest
              github-release:
                runs-on: ubuntu-latest
            """) == []


def test_always_accepts_the_expression_wrapped_form() -> None:
    assert check("""
            on:
              pull_request:
            jobs:
              build:
                runs-on: ubuntu-latest
              ci-gate:
                if: ${{ always() }}
                needs: [build]
                runs-on: ubuntu-latest
            """) == []


def test_needs_given_as_a_bare_string_is_accepted() -> None:
    """GitHub accepts `needs: build` as well as `needs: [build]`."""
    assert check("""
            on:
              pull_request:
            jobs:
              build:
                runs-on: ubuntu-latest
              ci-gate:
                if: always()
                needs: build
                runs-on: ubuntu-latest
            """) == []


def test_coverage_may_be_split_across_several_gates() -> None:
    assert check("""
            on:
              pull_request:
            jobs:
              alpha:
                runs-on: ubuntu-latest
              beta:
                runs-on: ubuntu-latest
              alpha-gate:
                if: always()
                needs: [alpha]
                runs-on: ubuntu-latest
              beta-gate:
                if: always()
                needs: [beta]
                runs-on: ubuntu-latest
            """) == []


# --------------------------------------------------------------------------
# The repository's own workflows
# --------------------------------------------------------------------------


def test_repository_workflows_satisfy_the_invariant() -> None:
    failures, examined = audit(REPO_ROOT / ".github" / "workflows")
    assert examined > 0, "no workflow files were examined"
    assert failures == [], "\n".join(failures)


def test_c_library_no_native_pqc_is_wired_into_its_gate() -> None:
    """Regression pin for the specific job this checker was written for.

    Guarding the general invariant is not enough: this job guards the
    AMA_USE_NATIVE_PQC=OFF build for consumers who take the library without
    native post-quantum support, and it silently gated nothing while that
    configuration broke.
    """
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "ci-build-test.yml").read_text(encoding="utf-8")
    )
    jobs = workflow["jobs"]
    assert "c-library-no-native-pqc" in jobs
    assert "c-library-no-native-pqc" in jobs["ci-gate"]["needs"]
