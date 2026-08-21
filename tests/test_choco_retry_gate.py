# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The Chocolatey retry policy, and the gate that keeps every call inside it.

Chocolatey v2 exits 0 when it installs nothing.  On 2026-08-21 the community
feed returned 503 and every Windows lane in both workflows went red on
PR #394::

    Failed to fetch results from V2 feed at '...' : 503 (Service Unavailable).
    Unable to find package 'softhsm.install'.
    Chocolatey installed 0/0 packages.

``$LASTEXITCODE`` was 0 for that run, and all four retry loops in the
workflows read ``if ($LASTEXITCODE -eq 0) { break }`` — so ``Attempt 1/5``
"succeeded", the loop broke, and the step failed one line later at its
post-condition with no retry ever attempted.

Both halves are pinned here: the gate that forbids a bare ``choco install``,
and the helper's actual behaviour, executed.  The second half is the one that
matters — a retry that cannot see the failure it exists for is decoration, and
only running it proves otherwise.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import stat
import subprocess
import sys
import textwrap
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "tools" / "check_choco_retry.py"
HELPER_PATH = REPO_ROOT / ".github" / "scripts" / "choco-install.ps1"


def _load_gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_choco_retry", GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


# --------------------------------------------------------------------------
# The repository itself
# --------------------------------------------------------------------------


def test_gate_passes_on_the_tree() -> None:
    assert gate.main(["--root", str(REPO_ROOT)]) == 0


def test_the_helper_exists() -> None:
    assert HELPER_PATH.is_file(), f"{HELPER_PATH} is the policy; the gate needs it to exist"


def test_no_workflows_fails_closed(tmp_path: Path) -> None:
    """A gate with no input must not pass: exit 2, not 0."""
    (tmp_path / ".github" / "scripts").mkdir(parents=True)
    (tmp_path / ".github" / "scripts" / "choco-install.ps1").write_text("", encoding="utf-8")
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    assert gate.main(["--root", str(tmp_path)]) == 2


def test_missing_helper_fails(tmp_path: Path) -> None:
    """The policy having nowhere to live is itself a failure."""
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("on: push\n", encoding="utf-8")
    assert gate.main(["--root", str(tmp_path)]) == 1


def test_a_yaml_workflow_is_scanned_too(tmp_path: Path) -> None:
    """`.yaml` is read by GitHub Actions exactly as `.yml` is.

    A gate that globs only one extension is bypassed by a workflow named the
    other way — silently, and in the direction that passes.
    """
    (tmp_path / ".github" / "scripts").mkdir(parents=True)
    (tmp_path / ".github" / "scripts" / "choco-install.ps1").write_text("", encoding="utf-8")
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "sneaky.yaml").write_text(
        textwrap.dedent("""\
            on: push
            jobs:
              j:
                steps:
                  - run: choco install cmake -y
            """),
        encoding="utf-8",
    )
    assert gate.main(["--root", str(tmp_path)]) == 1


@pytest.mark.parametrize(
    "line,expect_violation,label",
    [
        ("choco install cmake -y", True, "the bare spelling"),
        ("choco install softhsm.install -y --no-progress", True, "the site that went red"),
        ("choco -y install cmake", True, "options between binary and sub-command"),
        ("choco.exe install foo", True, "the .exe spelling"),
        ("cinst foo", True, "the cinst alias"),
        ("choco upgrade chocolatey -y", True, "upgrade reaches the feed too"),
        ("# choco install cmake  (explaining the outage)", False, "a comment is prose"),
        ("choco uninstall foo", False, "uninstall touches no feed"),
        (
            '& "$env:GITHUB_WORKSPACE/.github/scripts/choco-install.ps1" -Package cmake',
            False,
            "the helper itself",
        ),
        # This gate's own CI step is named for the thing it forbids, and the
        # first version of this file failed the build on that step's name.
        (
            '- name: "Chocolatey retry policy: no bare choco install in a workflow"',
            False,
            "a step name is a label, not a command",
        ),
        ("name: choco install something", False, "the unprefixed name: spelling"),
        # But a `run:` on one line still has to be caught — skipping `name:`
        # must not become skipping everything with a colon in it.
        ("run: choco install cmake -y", True, "an inline run: is still a command"),
    ],
)
def test_gate_verdicts(line: str, expect_violation: bool, label: str) -> None:
    fired = bool(gate.scan_text(line, "wf.yml"))
    assert fired is expect_violation, f"{label}: fired={fired}, expected={expect_violation}"


# --------------------------------------------------------------------------
# The helper, executed
# --------------------------------------------------------------------------

pwsh = shutil.which("pwsh")

#: These exercise the helper by shimming `choco` with a `#!/bin/sh` script on
#: PATH, which Windows cannot execute — `& choco` throws
#: CommandNotFoundException there and the helper (correctly) refuses to run.
#: The first version of this file did not skip, and all five failed on every
#: windows-latest lane for that reason alone.
#:
#: Skipping is not a coverage hole.  The logic under test is
#: platform-independent and PowerShell 7 evaluates it identically on Linux,
#: where these run; and the helper's real Windows exercise is the actual
#: install step in both workflows, which is not a fake — the run on 93ee3d9
#: shows it resolving SoftHSM2 at C:\SoftHSM2 through this very script.
#: Writing a second, batch-file shim to fake `choco` on Windows was the
#: alternative and was rejected: it could not be executed anywhere in this
#: environment, so it would be untested code written to test something.
_POSIX_SHIM = os.name != "nt"
requires_helper_run = pytest.mark.skipif(
    pwsh is None or not _POSIX_SHIM,
    # Names no cryptographic backend: this is a shell/platform condition, not
    # a missing kernel, and tests/conftest.py's CI backend-skip escalation
    # keys on backend words.
    reason=(
        "needs pwsh and a POSIX shell shim for `choco`; on Windows the shim "
        "cannot be executed, and the helper's real exercise there is the "
        "workflow install step rather than a fake"
    ),
)


def _fake_choco(tmp_path: Path, body: str) -> Path:
    """A `choco` on PATH that reproduces a specific Chocolatey behaviour."""
    d = tmp_path / "fakebin"
    d.mkdir(exist_ok=True)
    p = d / "choco"
    p.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return d


def _run_helper(tmp_path: Path, fakebin: Path, *args: str) -> subprocess.CompletedProcess[str]:
    assert pwsh is not None
    env = dict(os.environ, PATH=f"{fakebin}{os.pathsep}{os.environ['PATH']}")
    return subprocess.run(
        [pwsh, "-NoProfile", "-File", str(HELPER_PATH), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
    )


#: Chocolatey's own output for the 2026-08-21 outage: a 503 from the feed, no
#: package installed, and exit 0.
_OUTAGE = (
    "echo \"Failed to fetch results from V2 feed at '...' with following message : \"\n"
    'echo "Response status code does not indicate success: 503 (Service Unavailable)."\n'
    "echo \"Unable to find package 'softhsm.install'.\"\n"
    'echo "Chocolatey installed 0/0 packages."\n'
    "exit 0\n"
)


@requires_helper_run
def test_a_feed_outage_is_not_a_success(tmp_path: Path) -> None:
    """The exact CI failure: exit 0, nothing installed.

    This is the whole reason the helper exists.  The loop it replaced broke
    on attempt 1 here and reported success.
    """
    fakebin = _fake_choco(tmp_path, _OUTAGE)
    r = _run_helper(
        tmp_path,
        fakebin,
        "-Package",
        "softhsm.install",
        "-MaxAttempts",
        "3",
        "-BackoffSeconds",
        "0",
    )
    assert r.returncode == 1, f"a 503 outage was treated as success:\n{r.stdout}\n{r.stderr}"
    assert (
        r.stdout.count("Attempt ") == 3
    ), f"the retry did not retry — attempts seen: {r.stdout.count('Attempt ')}\n{r.stdout}"
    assert "0/0 packages" in r.stdout


@requires_helper_run
def test_a_transient_outage_recovers(tmp_path: Path) -> None:
    """Two 0/0 replies, then a real install: the job must go green."""
    counter = tmp_path / "n"
    fakebin = _fake_choco(
        tmp_path,
        f'N=$(cat "{counter}" 2>/dev/null || echo 0); N=$((N+1)); echo $N > "{counter}"\n'
        'if [ "$N" -lt 3 ]; then echo "Chocolatey installed 0/0 packages."; exit 0; fi\n'
        f'echo "Chocolatey installed 1/1 packages."; touch "{tmp_path}/payload"; exit 0\n',
    )
    r = _run_helper(
        tmp_path,
        fakebin,
        "-Package",
        "cmake",
        "-MaxAttempts",
        "5",
        "-BackoffSeconds",
        "0",
        "-RequirePath",
        str(tmp_path / "payload"),
    )
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert r.stdout.count("Attempt ") == 3


@requires_helper_run
def test_a_reported_success_without_the_payload_is_a_failure(tmp_path: Path) -> None:
    """`installed 1/1` to somewhere the caller cannot use is not success.

    The Disig SoftHSM2 MSI parents its directory to ROOTDRIVE, which on
    GitHub's Windows runners is D:, not C: — so a "successful" install can
    land where PKCS11_PATHS will never look.
    """
    fakebin = _fake_choco(tmp_path, 'echo "Chocolatey installed 1/1 packages."\nexit 0\n')
    r = _run_helper(
        tmp_path,
        fakebin,
        "-Package",
        "softhsm.install",
        "-MaxAttempts",
        "2",
        "-BackoffSeconds",
        "0",
        "-RequirePath",
        str(tmp_path / "absent" / "x.dll"),
    )
    assert r.returncode == 1
    assert "does not exist" in r.stdout


@requires_helper_run
def test_a_genuinely_missing_package_still_fails(tmp_path: Path) -> None:
    """The half that matters most: retries must never turn red into green."""
    fakebin = _fake_choco(tmp_path, 'echo "ERROR: not successful."\nexit 1\n')
    r = _run_helper(
        tmp_path, fakebin, "-Package", "nosuchpkg", "-MaxAttempts", "2", "-BackoffSeconds", "0"
    )
    assert r.returncode == 1
    assert r.stdout.count("Attempt ") == 2


@requires_helper_run
def test_a_clean_install_takes_one_attempt(tmp_path: Path) -> None:
    """No retry storm on the happy path."""
    fakebin = _fake_choco(tmp_path, 'echo "Chocolatey installed 1/1 packages."\nexit 0\n')
    r = _run_helper(
        tmp_path, fakebin, "-Package", "cmake", "-MaxAttempts", "3", "-BackoffSeconds", "0"
    )
    assert r.returncode == 0
    assert r.stdout.count("Attempt ") == 1
