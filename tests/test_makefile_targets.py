# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Every Makefile target is a command, and each one says what it does.

Three defects, all of them silent.

**``make docs`` did nothing.**  ``docs`` has no prerequisites and ``docs/`` is a
tracked directory, so GNU make treated the target as an up-to-date FILE and
skipped the recipe.  Measured on the Makefile as it stood::

    make -n docs
    -> make: 'docs' is up to date.

``docker`` and ``fuzz`` shadow directories the same way.  The recipe had just
been rewritten to route sphinx through ``$(RUN)``, under a comment asserting
"-W --keep-going turns every Sphinx warning into an error" — of a recipe that
never executed.

**``make security-audit`` ran the unscoped pip-audit** that the same commit
documents as broken two targets below: "a bare `pip-audit` reports CVEs in
packages this project does not ship (pip, urllib3 and whatever else the host
image carries), so the target went red for reasons nothing in this repository
can fix."

**``make c-api`` advertised a static library that is never produced.**
``CMakeLists.txt`` sets ``OUTPUT_NAME "ama_cryptography_static"``, so the
artefact is ``libama_cryptography_static.a``.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
MAKEFILE = REPO_ROOT / "Makefile"

#: `^name:` at column 0, excluding pattern rules and variable assignments.
_TARGET_RE = re.compile(r"^([a-z][a-z0-9_-]*):(?!=)", re.MULTILINE)


def _targets() -> list[str]:
    return _TARGET_RE.findall(MAKEFILE.read_text(encoding="utf-8"))


def _phony() -> set[str]:
    text = MAKEFILE.read_text(encoding="utf-8")
    match = re.search(r"^\.PHONY:((?:[^\n\\]*\\\n)*[^\n]*)", text, re.MULTILINE)
    assert match, ".PHONY is missing from the Makefile"
    return set(match.group(1).replace("\\\n", " ").split())


def test_the_sweep_finds_the_targets() -> None:
    """Non-vacuity: every assertion below iterates this list."""
    found = _targets()
    assert len(found) >= 20, found
    for expected in ("docs", "lint", "c-api", "security-audit"):
        assert expected in found, found


def test_every_target_is_phony() -> None:
    missing = sorted(set(_targets()) - _phony())
    assert not missing, (
        "Makefile targets that are not .PHONY — a directory of the same name "
        f"silently disables them: {missing}"
    )


@pytest.mark.parametrize("name", ["docs", "docker", "fuzz"])
def test_the_targets_that_shadow_a_directory_still_run(name: str) -> None:
    """The three that actually collide today, driven through make itself."""
    assert (REPO_ROOT / name).is_dir(), f"{name}/ is no longer a directory; drop this case"
    result = subprocess.run(
        ["make", "-n", name],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert "is up to date" not in result.stdout + result.stderr, (
        f"`make {name}` is a no-op: make resolved the target to the directory. "
        f"{result.stdout}{result.stderr}"
    )


def test_every_pip_audit_invocation_is_scoped() -> None:
    """An unscoped pip-audit reports CVEs in packages this project does not ship."""
    unscoped = [
        line.strip()
        for line in MAKEFILE.read_text(encoding="utf-8").splitlines()
        if "pip_audit" in line and "--requirement" not in line
    ]
    assert not unscoped, unscoped


def test_the_c_api_target_names_the_library_the_build_produces() -> None:
    makefile = MAKEFILE.read_text(encoding="utf-8")
    cmake = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    assert (
        'OUTPUT_NAME "ama_cryptography_static"' in cmake
    ), "the static target's OUTPUT_NAME moved; this test's premise needs rechecking"
    assert "build/lib/libama_cryptography_static.a" in makefile
    assert (
        "build/lib/libama_cryptography.a" not in makefile
    ), "`make c-api` advertises a static library path the build never produces"
