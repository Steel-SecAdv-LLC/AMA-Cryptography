# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""A gate is only as good as the environment it runs in.

Two checks in this repository silently do far less than they appear to when a
package they depend on is missing, and neither says so:

* ``mypy --strict ama_cryptography/ tests/``. ``pytest.*`` is listed under
  ``ignore_missing_imports`` in ``pyproject.toml``, which is correct — pytest
  ships no stubs and the override keeps the import from being an error. The
  cost is that with pytest *absent*, every ``pytest.raises``, ``pytest.skip``
  and ``@pytest.mark.*`` becomes ``Any``, so the test tree is nominally
  type-checked while most of what it does is invisible.

  Worse, the verdict then depends on the environment rather than on the code.
  ``pytest.skip`` is ``NoReturn``, so::

      if found is None:
          pytest.skip("...")
      a, b = found          # narrowed, or not

  type-checks on any machine with pytest installed (which is every developer
  machine, because it is in the ``dev`` extra) and fails in a lint job without
  it. That is how a green local ``mypy --strict`` reached a red CI: not a
  disagreement about the code, a disagreement about what was being read.

* ``tools/check_documented_counts.py``, which re-derives the test counts the
  documentation pins by running pytest's own collection. With no pytest it
  collects nothing, and reports that as drift — correctly, since a count that
  cannot be verified must not read as a count that is right, but the failure
  names the documentation rather than the missing dependency.

So the dependency is pinned in the jobs that need it, and this is what keeps it
pinned. Collection needs neither the native library nor an editable install
(verified against a pristine checkout), so this stays a fast, tool-only job.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

#: Commands whose result depends on pytest being importable by the tool, mapped
#: to why. Matched as substrings against each step's ``run`` script.
PYTEST_DEPENDENT = {
    "mypy --strict": (
        "`pytest.*` is under ignore_missing_imports, so without pytest installed "
        "every pytest call in tests/ types as Any and `pytest.skip`'s NoReturn "
        "stops narrowing — the check's verdict changes with the environment"
    ),
    "check_documented_counts.py": (
        "it re-derives documented test counts through pytest's own collection, "
        "and collects nothing without pytest"
    ),
}


def _jobs(path: Path) -> dict[str, Any]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    jobs = document.get("jobs") or {}
    assert isinstance(jobs, dict)
    return jobs


def _run_scripts(job: dict[str, Any]) -> list[str]:
    return [
        step["run"]
        for step in job.get("steps", [])
        if isinstance(step, dict) and isinstance(step.get("run"), str)
    ]


def _splice(script: str) -> list[str]:
    """Shell logical lines: backslash-continuations joined into one.

    A long ``pip install`` is normally wrapped across several lines, and a
    matcher that reads physical lines sees the package names on lines with no
    ``pip install`` on them — it would report a job that does install pytest as
    one that does not.
    """
    out: list[str] = []
    pending = ""
    for raw in script.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        out.append(pending + line)
        pending = ""
    if pending:
        out.append(pending)
    return out


def _installs_pytest(scripts: list[str]) -> bool:
    """True if some step in the job pip-installs pytest itself.

    ``pytest-cov`` and friends are not enough on their own — and are not what
    is matched — because the name has to be pytest for the import to resolve.
    An editable install of the ``dev`` extra counts, since pytest is in it.
    """
    for script in scripts:
        for line in _splice(script):
            if "pip install" not in line:
                continue
            if "[dev" in line:
                return True
            for token in line.split():
                if token.strip("\"'").split("==")[0] == "pytest":
                    return True
    return False


def _all_jobs() -> list[tuple[str, str, dict[str, Any]]]:
    out = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for name, job in _jobs(path).items():
            if isinstance(job, dict):
                out.append((path.name, name, job))
    return out


@pytest.mark.parametrize("command", sorted(PYTEST_DEPENDENT))
def test_every_job_running_it_installs_pytest(command: str) -> None:
    offenders = []
    ran_somewhere = False
    for workflow, job_name, job in _all_jobs():
        scripts = _run_scripts(job)
        if not any(command in script for script in scripts):
            continue
        ran_somewhere = True
        if not _installs_pytest(scripts):
            offenders.append(f"{workflow}::{job_name}")

    assert ran_somewhere, (
        f"no workflow job runs {command!r} any more — if it moved, update this test; "
        "if it was dropped, that is the thing to notice"
    )
    assert not offenders, (
        f"{command!r} runs without pytest installed in: {', '.join(offenders)}.\n"
        f"{PYTEST_DEPENDENT[command]}"
    )


def test_the_matcher_rejects_a_job_that_installs_nothing() -> None:
    """Negative control for ``_installs_pytest``.

    Without this the test above would pass for the wrong reason the moment the
    matcher stopped matching anything.
    """
    assert not _installs_pytest(["pip install ruff mypy"])
    assert not _installs_pytest(["pip install pytest-cov"])
    assert not _installs_pytest(["echo pytest"])
    assert _installs_pytest(['pip install "pytest==9.1.1"'])
    assert _installs_pytest(["pip install pytest"])
    assert _installs_pytest(['pip install -e ".[dev,legacy]"'])


def test_the_pinned_pytest_matches_the_lock_file() -> None:
    """A lint job on a different pytest from the test jobs is the same
    divergence in a new place."""
    lock = (REPO_ROOT / "requirements-lock.txt").read_text(encoding="utf-8")
    pinned = next(line.strip() for line in lock.splitlines() if line.strip().startswith("pytest=="))
    for path in sorted(WORKFLOWS.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            if "pytest==" not in line:
                continue
            version = line.split("pytest==")[1].split('"')[0].split("'")[0].strip()
            assert (
                f"pytest=={version}" == pinned
            ), f"{path.name} pins pytest=={version} but requirements-lock.txt says {pinned}"


# The tools whose verdicts gates execute, pinned in up to four places:
# requirements-lock.txt (the reference the assertions below read), the
# workflows' `pip install "tool==X"` lines, the pre-commit rev, and the [dev]
# extra's capped range in pyproject.toml and requirements-dev.txt.  8253023
# capped mypy after one CI run measured two mypys (the lint lane's pinned
# 2.3.1 and the test lanes' floated 2.4.0); the audit that followed measured
# bandit's nosec attribution moving INSIDE its then-floated >=1.7.0 range, and
# nothing tied any cap to the pins it tracks -- each cap's comment says "raise
# the cap with the pins", and a comment is not a gate.  The expected [dev]
# form is derived from the lock: floor exactly at the locked version, cap at
# the next minor -- except black, whose stable style moves on its calendar
# major, capped at the next major.  Raising a pin without the cap, or a cap
# without the pin, fails here.
_GATE_TOOL_CAPS: dict[str, str] = {
    "pytest": "minor",
    "mypy": "minor",
    "bandit": "minor",
    "ruff": "minor",
    "black": "major",
    # Gate-executed like the five above: INVARIANT-25's workflow parser runs
    # on PyYAML, and mypy --strict's verdicts move with the stub packages.
    "PyYAML": "minor",
    "types-PyYAML": "minor",
    "types-setuptools": "minor",
}
#: The pre-commit repository that pins each tool (pytest has no hook there).
_PRE_COMMIT_REPOS: dict[str, str] = {
    "black": "github.com/psf/black",
    "ruff": "github.com/astral-sh/ruff-pre-commit",
    "mypy": "github.com/pre-commit/mirrors-mypy",
    "bandit": "github.com/PyCQA/bandit",
}


def _locked_version(tool: str) -> str:
    lock = (REPO_ROOT / "requirements-lock.txt").read_text(encoding="utf-8")
    for line in lock.splitlines():
        if line.strip().startswith(f"{tool}=="):
            return line.strip().split("==", 1)[1]
    raise AssertionError(f"requirements-lock.txt does not pin {tool}")


def _expected_dev_spec(tool: str, locked: str) -> str:
    major, minor = (int(part) for part in locked.split(".")[:2])
    cap = f"{major + 1}" if _GATE_TOOL_CAPS[tool] == "major" else f"{major}.{minor + 1}"
    return f"{tool}>={locked},<{cap}"


@pytest.mark.parametrize("tool", sorted(_GATE_TOOL_CAPS))
def test_every_gate_tool_is_pinned_coherently(tool: str) -> None:
    locked = _locked_version(tool)

    # Every workflow pip-install pin of the tool equals the lock.  The tool
    # name is anchored on its left so "PyYAML==" does not also match inside
    # "types-PyYAML==...".
    pin_re = re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(tool)}==([^\"'\s]+)")
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for version in pin_re.findall(path.read_text(encoding="utf-8")):
            assert (
                version == locked
            ), f"{path.name} pins {tool}=={version} but requirements-lock.txt says {locked}"

    # The pre-commit rev equals the lock, for the tools pre-commit runs --
    # and so does every `tool==` among any hook's additional_dependencies
    # (the mypy hook carries PyYAML, types-PyYAML and pytest pins of its own).
    config = yaml.safe_load((REPO_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8"))
    repo_url = _PRE_COMMIT_REPOS.get(tool)
    if repo_url is not None:
        revs = [r["rev"] for r in config["repos"] if repo_url in r.get("repo", "")]
        assert revs, f".pre-commit-config.yaml no longer holds {repo_url}"
        for rev in revs:
            assert (
                rev.lstrip("v") == locked
            ), f".pre-commit-config.yaml pins {tool} at {rev} but the lock says {locked}"
    for repo in config["repos"]:
        for hook in repo.get("hooks", []):
            for dep in hook.get("additional_dependencies", []) or []:
                if not dep.startswith(f"{tool}=="):
                    continue
                version = dep.split("==", 1)[1]
                assert version == locked, (
                    f".pre-commit-config.yaml hook {hook.get('id')} pins {dep} "
                    f"but the lock says {tool}=={locked}"
                )

    # The [dev] extra floors at the lock and carries the derived cap, in both
    # declarations.  Exact-form comparison: a floor above or below the pin,
    # a missing cap, and a cap raised without the pin all fail.
    expected = _expected_dev_spec(tool, locked)
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert (
        f'"{expected}"' in pyproject
    ), f"pyproject.toml's dev extra must pin '{expected}' (lock: {tool}=={locked})"
    dev_txt = (REPO_ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
    assert any(
        line.strip() == expected for line in dev_txt.splitlines()
    ), f"requirements-dev.txt must pin '{expected}' (lock: {tool}=={locked})"


def test_workflow_only_pins_agree() -> None:
    """pip-audit is pinned per-workflow with no lock entry to anchor it, so
    the coherence it can have is that every workflow names one version."""
    pin_re = re.compile(r"(?<![A-Za-z0-9_-])pip-audit==([^\"'\s]+)")
    found: dict[str, list[str]] = {}
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for version in pin_re.findall(path.read_text(encoding="utf-8")):
            found.setdefault(version, []).append(path.name)
    assert found, "no workflow pins pip-audit any more"
    assert len(found) == 1, f"workflows disagree on pip-audit: {found}"
