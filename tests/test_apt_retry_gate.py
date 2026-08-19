# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for ``tools/check_apt_retry.py`` and ``.github/scripts/apt-install.sh``.

``apt-get`` hangs on hosted runners.  When it does, the step burns the job's
whole ``timeout-minutes`` and the job is cancelled — and a cancelled dependency
is not a success, so an aggregating gate goes red on a commit whose every real
check passed.  That happened three times in one push (Cppcheck, Validate fuzz
dictionaries, Fuzz Core Primitives/fuzz_aes_gcm) after the fix had been written
inline for exactly one of thirty-eight call sites.

So the properties under test are: the policy is reachable from every workflow,
the gate fails when a workflow bypasses it, and — the part that matters most —
the retry never converts a genuine failure into a pass.
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
GATE_PATH = REPO_ROOT / "tools" / "check_apt_retry.py"
HELPER_PATH = REPO_ROOT / ".github" / "scripts" / "apt-install.sh"


def _load_gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_apt_retry", GATE_PATH)
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


def test_helper_exists_and_is_executable() -> None:
    """A helper without the executable bit fails every job with EACCES.

    The bit has to survive `git checkout`, so it is git's recorded mode that
    matters, not just the working tree's.
    """
    assert HELPER_PATH.is_file()
    assert os.access(HELPER_PATH, os.X_OK), "working tree copy is not executable"

    mode = subprocess.run(
        ["git", "ls-files", "-s", HELPER_PATH.relative_to(REPO_ROOT).as_posix()],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    assert mode, "helper is not tracked by git"
    assert mode[0] == "100755", f"git records mode {mode[0]}, not 100755"


def test_no_workflows_fails_closed(tmp_path: Path) -> None:
    scripts = tmp_path / ".github" / "scripts"
    scripts.mkdir(parents=True)
    helper = scripts / "apt-install.sh"
    helper.write_text("#!/bin/sh\n")
    helper.chmod(helper.stat().st_mode | stat.S_IXUSR)
    (tmp_path / ".github" / "workflows").mkdir()
    assert gate.main(["--root", str(tmp_path)]) == 2


def test_a_yaml_workflow_is_scanned_too(tmp_path: Path) -> None:
    """GitHub Actions reads `.yml` and `.yaml` alike.

    A gate that globs only one extension is bypassed by a workflow named the
    other way — silently, and in the direction that passes. This gate globbed
    only `*.yml` on first writing while `check_action_pins.py` and
    `check_workflow_commands.py` next to it already globbed both.
    """
    scripts = tmp_path / ".github" / "scripts"
    scripts.mkdir(parents=True)
    helper = scripts / "apt-install.sh"
    helper.write_text("#!/bin/sh\n")
    helper.chmod(helper.stat().st_mode | stat.S_IXUSR)
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir()
    (workflows / "sneaky.yaml").write_text(
        "jobs:\n  a:\n    steps:\n" "      - run: sudo apt-get install -y cmake\n"
    )
    assert (
        gate.main(["--root", str(tmp_path)]) == 1
    ), "a raw apt call in a .yaml workflow must fail the gate"


def test_a_yaml_only_tree_is_not_vacuous(tmp_path: Path) -> None:
    """...and a tree whose workflows are all `.yaml` is scanned, not skipped."""
    scripts = tmp_path / ".github" / "scripts"
    scripts.mkdir(parents=True)
    helper = scripts / "apt-install.sh"
    helper.write_text("#!/bin/sh\n")
    helper.chmod(helper.stat().st_mode | stat.S_IXUSR)
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir()
    (workflows / "ok.yaml").write_text(
        "jobs:\n  a:\n    steps:\n" "      - run: .github/scripts/apt-install.sh cmake\n"
    )
    assert gate.main(["--root", str(tmp_path)]) == 0


def test_missing_helper_fails(tmp_path: Path) -> None:
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    assert gate.main(["--root", str(tmp_path)]) == 1


# --------------------------------------------------------------------------
# What the gate must reject and accept
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line,expect_violation,label",
    [
        ("          sudo apt-get install -y cmake", True, "bare apt-get install"),
        ("          sudo apt-get update", True, "bare apt-get update"),
        ("          apt install cmake", True, "interactive apt install"),
        ("          sudo apt-get dist-upgrade", True, "dist-upgrade"),
        ("          .github/scripts/apt-install.sh cmake", False, "the helper"),
        ("          # sudo apt-get install -y cmake", False, "a YAML comment"),
        ("      # This step has hung in `apt-get install` twice", False, "prose"),
        ("          apt-cache policy cmake", False, "apt-cache reads nothing remote"),
        ("          dpkg -l", False, "dpkg"),
    ],
)
def test_gate_verdicts(line: str, expect_violation: bool, label: str) -> None:
    violations = gate.scan_text(line + "\n", "synthetic.yml")
    if expect_violation:
        assert violations, f"gate accepted {label}, which it must reject"
    else:
        assert not violations, f"gate rejected {label}: {violations}"


# --------------------------------------------------------------------------
# The helper's own behaviour — the half that must never mask a failure
# --------------------------------------------------------------------------
#
# These run on Linux only, and that is a statement about the subject rather
# than a convenience: apt-install.sh drives `sudo`, `apt-get` and GNU
# `timeout`, none of which exist on the Windows or macOS runners, and it is
# invoked from Linux jobs exclusively.
#
# The first version of this file guarded them with `shutil.which("bash")`,
# which is present on the Windows runners via Git Bash — so the guard did not
# fire and all five failed with `[WinError 193] %1 is not a valid Win32
# application`, taking every Windows job in two workflows down with them. The
# script is now also invoked THROUGH bash rather than executed directly, so
# the test does not depend on the OS honouring a shebang.
#
# The platform-independent assertions above — the gate's verdicts, the
# helper's existence and its git-recorded executable bit — keep running
# everywhere, because those are the properties that can break on any runner.
_LINUX_ONLY = pytest.mark.skipif(
    not sys.platform.startswith("linux") or shutil.which("bash") is None,
    reason="apt-install.sh drives sudo/apt-get/timeout; only meaningful on Linux",
)


def _fake_sudo(tmp_path: Path) -> Path:
    """A `sudo` that stands in for apt, honouring FAKE_APT_FAIL."""
    binroot = tmp_path / "bin"
    binroot.mkdir(exist_ok=True)
    fake = binroot / "sudo"
    fake.write_text(textwrap.dedent("""\
            #!/usr/bin/env bash
            if [ "$1" = "timeout" ]; then shift 2; fi
            case "$1 $2" in
              "rm -f") exit 0 ;;
              "apt-get update") [ "${FAKE_APT_FAIL:-0}" = "1" ] && exit 100; exit 0 ;;
              "apt-get install")
                  [ "${FAKE_APT_FAIL:-0}" = "1" ] && exit 100
                  echo "installed: ${*:3}"; exit 0 ;;
            esac
            exit 0
            """))
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    return binroot


def _run_helper(tmp_path: Path, args: list[str], **env: str) -> subprocess.CompletedProcess[str]:
    binroot = _fake_sudo(tmp_path)
    e = dict(os.environ)
    e["PATH"] = f"{binroot}{os.pathsep}{e['PATH']}"
    e.update(env)
    return subprocess.run(["bash", str(HELPER_PATH), *args], capture_output=True, text=True, env=e)


@_LINUX_ONLY
def test_helper_installs_on_the_happy_path(tmp_path: Path) -> None:
    r = _run_helper(tmp_path, ["cppcheck"])
    assert r.returncode == 0, r.stderr
    assert "cppcheck" in r.stdout


@_LINUX_ONLY
def test_helper_refuses_an_empty_package_list(tmp_path: Path) -> None:
    """A step that installs nothing silently stopped installing something."""
    r = _run_helper(tmp_path, [])
    assert r.returncode == 2


@_LINUX_ONLY
def test_helper_still_fails_when_the_package_is_unavailable(tmp_path: Path) -> None:
    """The property that makes the retry safe.

    A retry that swallows a real failure would convert "this package does not
    exist" into a green job with the tool missing — the exact shape of silent
    gate erosion this repository's audit exists to remove.  The final attempt
    is unguarded and its exit status is the script's.
    """
    r = _run_helper(tmp_path, ["definitely-not-a-package"], FAKE_APT_FAIL="1", APT_ATTEMPTS="1")
    assert r.returncode != 0


@_LINUX_ONLY
def test_helper_retries_before_giving_up(tmp_path: Path) -> None:
    """Two bounded attempts, then one bare attempt whose failure is fatal."""
    r = _run_helper(
        tmp_path,
        ["cmake"],
        FAKE_APT_FAIL="1",
        APT_ATTEMPTS="3",
        APT_ATTEMPT_TIMEOUT="1",
    )
    assert r.returncode != 0
    assert "attempt 1 failed" in r.stdout
    assert "attempt 2 failed" in r.stdout
    assert "final attempt" in r.stdout


@_LINUX_ONLY
def test_helper_rejects_a_nonsense_attempt_count(tmp_path: Path) -> None:
    r = _run_helper(tmp_path, ["cmake"], APT_ATTEMPTS="0")
    assert r.returncode == 2
