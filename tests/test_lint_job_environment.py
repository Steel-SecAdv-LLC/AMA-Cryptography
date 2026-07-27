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
