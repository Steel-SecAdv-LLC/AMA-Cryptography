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
from typing import Any

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
            steps:
              - if: contains(needs.*.result, 'failure')
                run: exit 1
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
            steps:
              - if: contains(needs.*.result, 'failure')
                run: exit 1
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
            steps:
              - if: contains(needs.*.result, 'failure')
                run: exit 1
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
                steps:
                  - if: contains(needs.*.result, 'failure')
                    run: exit 1
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
                steps:
                  - if: contains(needs.*.result, 'failure')
                    run: exit 1
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
                steps:
                  - if: contains(needs.*.result, 'failure')
                    run: exit 1
              beta-gate:
                if: always()
                needs: [beta]
                runs-on: ubuntu-latest
                steps:
                  - if: contains(needs.*.result, 'failure')
                    run: exit 1
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


# ---------------------------------------------------------------------------
# `needs:` membership is not evaluation
# ---------------------------------------------------------------------------
#
# Coverage used to be computed purely from `needs:`, and `needs:` only makes
# the gate WAIT for a job.  Whether the gate goes red when that job fails is
# decided by the gate's own step.  Four of this repository's six aggregating
# gates use `contains(needs.*.result, 'failure')`, which is self-maintaining;
# `dudect-gate` and `static-analysis-gate` instead hand-enumerate each
# dependency into an `env:` block and call a shell `check` function once per
# job.  A job added to `needs:` and not to that hand-written list satisfied
# INVARIANT-31 and was never evaluated — and because the gate carries
# `if: always()`, it ran anyway, `rc` stayed 0, and the gate printed that every
# job reached the state the trigger requires.
#
# Measured: adding an always-failing `newly-added-lane` to dudect-gate's
# `needs:` left the previous checker at exit 0.


def test_a_dependency_the_gate_never_looks_at_is_reported() -> None:
    failures = check("""
        on:
          pull_request:
        jobs:
          watched:
            runs-on: ubuntu-latest
          unwatched:
            runs-on: ubuntu-latest
          ci-gate:
            if: always()
            needs:
              - watched
              - unwatched
            runs-on: ubuntu-latest
            steps:
              - env:
                  R_WATCHED: ${{ needs.watched.result }}
                run: |
                  test "${R_WATCHED}" = success
        """)
    assert len(failures) == 1, failures
    assert "unwatched" in failures[0]
    assert "never evaluates" in failures[0]
    assert "watched," not in failures[0], "the evaluated job was named as unevaluated"


def test_the_wildcard_form_covers_every_dependency() -> None:
    """`needs.*.result` cannot go stale, so it satisfies the rule outright."""
    failures = check("""
        on:
          pull_request:
        jobs:
          one:
            runs-on: ubuntu-latest
          two:
            runs-on: ubuntu-latest
          ci-gate:
            if: always()
            needs: [one, two]
            runs-on: ubuntu-latest
            steps:
              - if: contains(needs.*.result, 'failure')
                run: exit 1
        """)
    assert failures == []


def test_a_dependency_named_only_in_a_run_body_counts() -> None:
    """The check is "is it referenced at all", not "is it in an env: block"."""
    failures = check("""
        on:
          pull_request:
        jobs:
          alpha:
            runs-on: ubuntu-latest
          ci-gate:
            if: always()
            needs: [alpha]
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo "alpha=${{ needs.alpha.result }}"
                  test "${{ needs.alpha.result }}" = success
        """)
    assert failures == []


def test_listing_a_job_in_needs_is_not_self_satisfying() -> None:
    """The tautology this check had to avoid.

    Serialising the whole job would include its own ``needs:`` list, so every
    id would trivially "appear" — the same shape of vacuity as a floor test
    comparing a required set against a set that unions it in.
    """
    failures = check("""
        on:
          pull_request:
        jobs:
          alpha:
            runs-on: ubuntu-latest
          ci-gate:
            if: always()
            needs: [alpha]
            runs-on: ubuntu-latest
            steps:
              - run: echo "the gate does nothing with its dependency"
        """)
    assert len(failures) == 1, failures
    assert "alpha" in failures[0] and "never evaluates" in failures[0]


def test_env_bound_dependency_never_read_in_run_is_reported() -> None:
    """H7: binding a dependency into env: is not evaluating it.

    dudect-gate / static-analysis-gate bind each dependency to a shell alias
    (``R_X: ${{ needs.x.result }}``) and decide ``rc`` in a ``run:`` script.  A
    job bound that way whose alias is never dereferenced runs, fails, and leaves
    the gate green — the previous whole-body substring test saw
    ``needs.planted.result`` in the env: value and called it evaluated.
    """
    failures = check("""
        on: { pull_request: }
        jobs:
          watched: { runs-on: ubuntu-latest }
          planted: { runs-on: ubuntu-latest }
          ci-gate:
            if: always()
            needs: [watched, planted]
            runs-on: ubuntu-latest
            steps:
              - env:
                  R_WATCHED: ${{ needs.watched.result }}
                  R_PLANTED: ${{ needs.planted.result }}
                run: |
                  test "${R_WATCHED}" = success
        """)
    assert len(failures) == 1, failures
    assert "planted" in failures[0] and "never evaluates" in failures[0]
    assert "watched," not in failures[0], "the read dependency was named as unevaluated"


def test_vacuity_floor_fails_on_an_empty_workflow_dir(tmp_path: Path) -> None:
    """H7: `rm .github/workflows/*.yml` must not leave the audit PASSing."""
    failures, examined = audit(tmp_path)
    assert examined == 0
    assert any("MIN_WORKFLOWS" in f or "workflow file(s) examined" in f for f in failures)


def test_the_repository_gates_all_evaluate_what_they_wait_for() -> None:
    """Non-vacuity for the rule against the real workflows."""
    problems, examined = audit()
    assert examined >= 10
    assert [p for p in problems if "never evaluates" in p] == []


class TestAMentionIsNotAnEvaluation:
    """``needs.<job>.result``, not the job's name appearing somewhere.

    ``_unevaluated_needs`` tested ``need not in body`` -- a substring search
    over the serialised gate.  A gate that merely echoes a job's name, or that
    happens to depend on a job whose name is a substring of another, counted it
    as evaluated.  That is the exact shape the function exists to reject: the
    gate waits for the job and then never looks at how it ended.

    Demonstrated against the substring version: a gate evaluating
    ``needs.lint.result`` and only echoing the word "build" reported nothing
    unevaluated.
    """

    @staticmethod
    def _gate() -> Any:
        import importlib.util

        repo_root = Path(__file__).resolve().parent.parent
        path = repo_root / "tools" / "check_gate_coverage.py"
        spec = importlib.util.spec_from_file_location("_gate_cov_mention", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_an_echoed_job_name_is_not_an_evaluation(self) -> None:
        gate = self._gate()
        job = {
            "needs": ["build", "lint"],
            "steps": [
                {
                    "run": 'echo "build is important"; '
                    'if [ "${{ needs.lint.result }}" != success ]; then exit 1; fi'
                }
            ],
        }
        assert gate._unevaluated_needs(job) == ["build"]

    def test_an_echoed_wildcard_is_not_an_evaluation(self) -> None:
        """`needs.*.result` in a `run:` disabled the whole per-dependency check.

        `_unevaluated_needs` returned `[]` as soon as the wildcard appeared
        anywhere in the JSON serialisation of the gate job — a
        `join(needs.*.result, ', ')` inside an `echo`, or the phrase inside a
        comment in a run script, was enough.  That is the same
        substring-vs-evaluation confusion this class rejects for NAMED
        dependencies, applied to the one construct that exempts all of them at
        once.
        """
        gate = self._gate()
        job = {
            "needs": ["build", "lint"],
            "steps": [
                {"run": "echo \"results: ${{ join(needs.*.result, ', ') }}\""},
            ],
        }
        assert gate._unevaluated_needs(job) == ["build", "lint"]

    def test_a_wildcard_in_the_gate_condition_still_exempts(self) -> None:
        """The control: a wildcard that IS evaluated must keep working."""
        gate = self._gate()
        job = {
            "needs": ["build", "lint"],
            "if": "always() && !contains(needs.*.result, 'failure')",
            "steps": [{"run": "true"}],
        }
        assert gate._unevaluated_needs(job) == []

    def test_a_wildcard_in_a_step_condition_still_exempts(self) -> None:
        gate = self._gate()
        job = {
            "needs": ["build", "lint"],
            "steps": [
                {"if": "contains(needs.*.result, 'failure')", "run": "exit 1"},
            ],
        }
        assert gate._unevaluated_needs(job) == []

    def test_a_real_result_reference_counts(self) -> None:
        gate = self._gate()
        job = {
            "needs": ["build"],
            "steps": [{"run": 'x=${{ needs.build.result }}; [ "$x" = success ]'}],
        }
        assert gate._unevaluated_needs(job) == []

    def test_the_bracket_and_outcome_spellings_count(self) -> None:
        """GitHub offers four spellings; all four are a real read."""
        gate = self._gate()
        for expr in (
            "needs.build.result",
            "needs.build.outcome",
            "needs['build'].result",
            'needs["build"].outcome',
        ):
            job = {"needs": ["build"], "steps": [{"run": "x=${{ " + expr + " }}"}]}
            assert gate._unevaluated_needs(job) == [], expr

    def test_a_substring_job_name_does_not_borrow_coverage(self) -> None:
        """`build` must not be satisfied by `needs.build-test.result`."""
        gate = self._gate()
        job = {
            "needs": ["build", "build-test"],
            "steps": [{"run": 'x=${{ needs.build-test.result }}; [ "$x" = success ]'}],
        }
        assert gate._unevaluated_needs(job) == ["build"]
