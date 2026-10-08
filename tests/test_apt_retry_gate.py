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
import re
import shutil
import stat
import subprocess
import sys
import textwrap
import time
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
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
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
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    helper.chmod(helper.stat().st_mode | stat.S_IXUSR)
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir()
    (workflows / "sneaky.yaml").write_text(
        "jobs:\n  a:\n    steps:\n" "      - run: sudo apt-get install -y cmake\n", encoding="utf-8"
    )
    assert (
        gate.main(["--root", str(tmp_path)]) == 1
    ), "a raw apt call in a .yaml workflow must fail the gate"


def test_a_yaml_only_tree_is_not_vacuous(tmp_path: Path) -> None:
    """...and a tree whose workflows are all `.yaml` is scanned, not skipped."""
    scripts = tmp_path / ".github" / "scripts"
    scripts.mkdir(parents=True)
    helper = scripts / "apt-install.sh"
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    helper.chmod(helper.stat().st_mode | stat.S_IXUSR)
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir()
    (workflows / "ok.yaml").write_text(
        "jobs:\n  a:\n    steps:\n" "      - run: .github/scripts/apt-install.sh cmake\n",
        encoding="utf-8",
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
        # Options between the binary and the sub-command.  This is the NORMAL
        # spelling — the repository's own helper is invoked as
        # `apt-install.sh --no-install-recommends cmake ...` — and the gate's
        # pattern required the sub-command to follow the binary name
        # immediately, so every one of these raw calls passed.
        ("          sudo apt-get -y install cmake", True, "-y before install"),
        ("          sudo apt-get -qq -y install cmake", True, "two short options"),
        (
            "          apt-get --no-install-recommends install cmake",
            True,
            "long option before install",
        ),
        ("          apt-get -o Acquire::Retries=3 update", True, "-o Key=Value before update"),
        ("          apt-get -t bookworm-backports install cmake", True, "-t suite before install"),
        ("          sudo apt-get -y full-upgrade", True, "full-upgrade"),
        ("          aptitude -y install cmake", True, "the third front-end"),
        # Near misses that must stay accepted.
        ("          echo 'adapt-get install nothing'", False, "a word ending in apt-get"),
        ("          apt-mark hold cmake", False, "apt-mark touches no network"),
        # A trailing comment is not the helper running.  The exemption was a
        # substring test over the whole segment, comment included, so a raw
        # call was exempted by its own TODO.
        (
            "          sudo apt-get install -y libfoo"
            "  # TODO: move to .github/scripts/apt-install.sh",
            True,
            "a raw call whose trailing comment names the helper",
        ),
        (
            "          .github/scripts/apt-install.sh cmake  # was: sudo apt-get install cmake",
            False,
            "the helper, with a comment quoting the raw call it replaced",
        ),
        # Expansions in the option run.  The run consumed only `-` tokens, so
        # the sub-command never lined up and these were not seen as calls.
        ("          sudo apt-get $APT_OPTS install -y libfoo", True, "a $VAR option run"),
        ("          sudo apt-get ${APT_FLAGS} install cmake", True, "a ${VAR} option run"),
        ('          apt-get "${OPTS[@]}" update', True, "a quoted array expansion"),
        ('          apt-get -o "Acquire::Retries=3" update', True, "a quoted option value"),
        ("          apt-get $CMD cmake", True, "a sub-command held in a variable"),
        ("          sudo apt-get -y remove cmake", False, "remove after an option"),
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
    fake.write_text(
        textwrap.dedent("""\
            #!/usr/bin/env bash
            # Skip a leading `timeout [--kill-after=N] <secs>`, then drop any
            # `-o Key=Value` apt options, so the case below sees the verb.
            if [ "$1" = "timeout" ]; then
              shift
              case "$1" in --kill-after=*) shift ;; esac
              shift
            fi
            verb="$1"; shift
            args=()
            while [ "$#" -gt 0 ]; do
              case "$1" in -o) shift 2 ;; *) args+=("$1"); shift ;; esac
            done
            set -- "$verb" "${args[@]}"
            [ -n "${FAKE_APT_LOG:-}" ] && echo "$1 $2" >> "$FAKE_APT_LOG"
            case "$1 $2" in
              "rm -f") exit 0 ;;
              "dpkg --configure")
                  # Replays the journal; does not finish a half-unpacked
                  # package (measured against dpkg on noble).
                  [ -n "${FAKE_DPKG_STATE:-}" ] && rm -f "$FAKE_DPKG_STATE/journal"
                  exit 0 ;;
              "apt-get update")
                  [ "${FAKE_APT_FAIL:-0}" = "1" ] && exit 100
                  [ -n "${FAKE_APT_LOG:-}" ] && touch "${FAKE_APT_LOG}.updated"
                  exit 0 ;;
              "apt-get install")
                  [ "${FAKE_APT_FAIL:-0}" = "1" ] && exit 100
                  if [ -n "${FAKE_DPKG_STATE:-}" ]; then
                      st="$FAKE_DPKG_STATE"
                      # The first install is killed mid-unpack, as the
                      # attempt bound did to cmake-data on run 36739915970.
                      if [ ! -e "$st/killed" ]; then
                          touch "$st/killed" "$st/journal"
                          echo cmake-data > "$st/reinstreq"
                          exit 137
                      fi
                      if [ -e "$st/journal" ]; then
                          echo "E: dpkg was interrupted, you must manually" \
                               "run 'sudo dpkg --configure -a' to correct" \
                               "the problem." >&2
                          exit 100
                      fi
                      if [ -e "$st/reinstreq" ]; then
                          if [[ " ${*:3} " == *" --reinstall "* &&
                                " ${*:3} " == *" $(cat "$st/reinstreq") "* ]]; then
                              rm -f "$st/reinstreq"
                              echo "reinstalled: ${*:3}"; exit 0
                          fi
                          echo "dpkg: dependency problems prevent" \
                               "configuration of cmake" >&2
                          exit 100
                      fi
                  fi
                  # Stands in for lists that cannot resolve the request until
                  # they are refreshed.
                  if [ "${FAKE_APT_NEEDS_UPDATE:-0}" = "1" ] &&
                     [ ! -e "${FAKE_APT_LOG:-/nonexistent}.updated" ]; then
                      echo "E: Unable to locate package ${3:-}" >&2
                      exit 100
                  fi
                  echo "installed: ${*:3}"; exit 0 ;;
            esac
            exit 0
            """),
        encoding="utf-8",
    )
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    _fake_dpkg_query(binroot)
    return binroot


def _fake_dpkg_query(binroot: Path) -> None:
    """A `dpkg-query` in the helper's output shape, so no test reads the host's.

    It reports `cmake-data` as `reinstreq` while FAKE_DPKG_STATE says a killed
    unpack left it half-installed, and a clean database otherwise.
    """
    fake = binroot / "dpkg-query"
    fake.write_text(
        textwrap.dedent("""\
            #!/usr/bin/env bash
            echo "ok cmake"
            if [ -n "${FAKE_DPKG_STATE:-}" ] && [ -e "$FAKE_DPKG_STATE/reinstreq" ]; then
              echo "reinstreq $(cat "$FAKE_DPKG_STATE/reinstreq")"
            fi
            """),
        encoding="utf-8",
    )
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)


def _isolated_env() -> dict[str, str]:
    """The caller's environment minus the job-scoped budget state.

    The helper shares one deadline across every call in a CI job through
    ``$RUNNER_TEMP``.  This suite runs INSIDE such a job, after the job's own
    apt-install.sh calls, so inheriting ``RUNNER_TEMP`` would hand every test
    the job's real, partly spent deadline.  Each test gets its own budget
    unless it names a state file itself.
    """
    e = dict(os.environ)
    e.pop("RUNNER_TEMP", None)
    e.pop("APT_BUDGET_STATE", None)
    return e


def _run_helper(tmp_path: Path, args: list[str], **env: str) -> subprocess.CompletedProcess[str]:
    binroot = _fake_sudo(tmp_path)
    e = _isolated_env()
    e["PATH"] = f"{binroot}{os.pathsep}{e['PATH']}"
    e.update(env)
    # These tests exercise ordering, bounding and message content — not the
    # wall clock.  Without this override every retrying case sat through the
    # script's real 15s-per-attempt backoff, adding roughly a minute to every
    # full run; the 15s CI default itself is pinned by
    # test_the_backoff_default_is_fifteen_seconds below.
    e.setdefault("APT_RETRY_BACKOFF", "0")
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
def test_each_bounded_attempt_escalates_to_sigkill(tmp_path: Path) -> None:
    """The defect that made the bound advisory instead of binding.

    GNU `timeout` sends SIGTERM. `apt-get` blocked on a network read inside its
    http method child does not necessarily die on one, and without
    `--kill-after` nothing escalates. Measured consequence: two jobs stalled at
    the same Ubuntu mirror line within a second of each other, sat there for
    8m44s past a 300s bound with no retry line printed, and were killed by
    their 20-minute job caps — taking two aggregating gates red on a commit
    where every other job passed.
    """
    body = HELPER_PATH.read_text(encoding="utf-8")
    bounded = [ln for ln in body.splitlines() if "timeout" in ln and "sudo" in ln]
    assert bounded, "no bounded attempt found in the helper"
    for line in bounded:
        assert (
            "--kill-after=" in line
        ), f"bounded attempt does not escalate past SIGTERM: {line.strip()!r}"


@_LINUX_ONLY
def test_apt_carries_its_own_acquire_timeouts(tmp_path: Path) -> None:
    """Bound the transfer inside apt, not only around it.

    An external kill turns a hang into a dead process; an acquire timeout turns
    it into an ordinary, retriable apt failure with a real message — the
    difference between a job that reports what went wrong and one that reports
    a dead process.

    They are defence in depth rather than the bound. An earlier revision of
    this docstring said the final attempt was "unbounded in wall clock by
    design, so these are what stop it hanging forever"; that reasoning is
    withdrawn, and the measurement that withdrew it is in the helper's own
    header. `Acquire::*::Timeout` bounds a CONNECTION, not the operation, and
    the dpkg configure phase carries none at all — so two jobs sat in this
    script for twenty minutes and were cancelled. Every attempt is bounded now.
    """
    body = HELPER_PATH.read_text(encoding="utf-8")
    for opt in ("Acquire::http::Timeout", "Acquire::https::Timeout", "Acquire::Retries"):
        assert opt in body, f"helper does not set {opt}"


@_LINUX_ONLY
def test_a_sigterm_ignoring_apt_is_actually_killed(tmp_path: Path) -> None:
    """Behavioural, not textual: prove the escalation ends a wedged process.

    The other two tests assert `--kill-after` is spelled in the script. That is
    not the property that failed — the property that failed is that a bound
    which cannot be enforced is not a bound. So this drives the real GNU
    `timeout` against a fake `apt-get` that installs `trap '' TERM` and sleeps
    far longer than the bound, which is what a network-wedged apt behaves like.

    Without escalation, SIGTERM is ignored and the helper hangs until something
    outside it intervenes — on CI, the job's own timeout-minutes, which is
    exactly the 8m44s stall that took two aggregating gates red. With it,
    SIGKILL lands and the helper moves on. The assertion is wall-clock: the run
    must finish in far less than the fake's sleep.
    """
    binroot = tmp_path / "bin"
    binroot.mkdir(exist_ok=True)

    # `sudo` that simply runs what it is given, so the REAL timeout executes.
    sudo = binroot / "sudo"
    sudo.write_text('#!/usr/bin/env bash\nexec "$@"\n', encoding="utf-8")
    sudo.chmod(sudo.stat().st_mode | stat.S_IXUSR)

    # `apt-get` that refuses to die on SIGTERM on its FIRST call, like apt
    # blocked in its http method child, and fails fast afterwards. The first
    # call is the one under test; making later calls terminate keeps the test
    # short — the final attempt is bounded too, but by the remaining budget,
    # which in a real job is minutes.
    marker = tmp_path / "apt_was_called"
    apt = binroot / "apt-get"
    apt.write_text(
        "#!/usr/bin/env bash\n"
        f'if [ ! -f "{marker}" ]; then\n'
        f'  touch "{marker}"\n'
        '  trap "" TERM\n'
        "  sleep 120\n"
        "fi\n"
        "exit 100\n",
        encoding="utf-8",
    )
    apt.chmod(apt.stat().st_mode | stat.S_IXUSR)

    env = _isolated_env()
    env["PATH"] = f"{binroot}{os.pathsep}{env['PATH']}"
    env.update(
        APT_ATTEMPT_TIMEOUT="2",
        APT_ATTEMPT_KILL_AFTER="1",
        APT_ATTEMPTS="2",
        APT_RETRY_BACKOFF="1",
    )
    start = time.monotonic()
    proc = subprocess.run(
        ["bash", str(HELPER_PATH), "cppcheck"],
        capture_output=True,
        text=True,
        env=env,
        timeout=90,
    )
    elapsed = time.monotonic() - start

    # Attempt 1 is bounded at 2s with SIGKILL 1s later, then the (overridden,
    # 1s) backoff, then the final attempt, which now fails fast. Roughly 6s in
    # total; the fake's own sleep is 120s, so anything near that means the
    # kill did not land.
    assert (
        "attempt 1 failed or exceeded" in proc.stdout
    ), f"the bounded attempt never terminated; stdout={proc.stdout!r}"
    assert elapsed < 60, (
        f"took {elapsed:.1f}s against a 120s fake — the SIGTERM-ignoring " f"attempt was not killed"
    )
    # And the genuine failure still fails: the retry did not paper over it.
    assert proc.returncode != 0, "an apt that never succeeded must fail the job"


def test_the_backoff_default_is_fifteen_seconds() -> None:
    """The CI backoff policy, pinned at the source.

    ``_run_helper`` overrides ``APT_RETRY_BACKOFF`` to 0 so the behaviour
    tests do not sit through real sleeps — which means nothing above ever
    exercises the default.  This pins the default and its use, so the
    override cannot silently become the CI behaviour and the linear
    escalation cannot be dropped.
    """
    body = HELPER_PATH.read_text(encoding="utf-8")
    assert 'BACKOFF_UNIT="${APT_RETRY_BACKOFF:-15}"' in body, (
        "the 15s CI backoff default changed or moved; the retry-behaviour "
        "tests run with it overridden to 0 and rely on this pin"
    )
    assert "delay=$((attempt * BACKOFF_UNIT))" in body, (
        "the linear per-attempt escalation no longer uses the overridable " "backoff unit"
    )


@_LINUX_ONLY
def test_the_total_budget_bounds_the_whole_script(tmp_path: Path) -> None:
    """The property the previous version did not have.

    Bounding every attempt but the last is not a bound: the last one inherits
    whatever time the job has left, and a stalled mirror spends all of it. On
    the run that prompted this, `dudect - X25519 AVX2 4-way` and `Scalar
    AES-GCM instruction-count invariance` each sat in this script for 20
    minutes and were cancelled at their job timeouts with every later step
    skipped, taking `Constant-Time Gate` red — while sibling jobs on the same
    commit finished the same step in 14 seconds to 5 minutes.

    So this drives a fake apt that hangs on EVERY call, and requires the script
    to give up inside its own stated budget rather than run until something
    else stops it.
    """
    binroot = tmp_path / "bin"
    binroot.mkdir(exist_ok=True)

    sudo = binroot / "sudo"
    sudo.write_text('#!/usr/bin/env bash\nexec "$@"\n', encoding="utf-8")
    sudo.chmod(sudo.stat().st_mode | stat.S_IXUSR)

    # Hangs every time, and ignores SIGTERM, which is what a wedged apt does.
    apt = binroot / "apt-get"
    apt.write_text('#!/usr/bin/env bash\ntrap "" TERM\nsleep 600\n', encoding="utf-8")
    apt.chmod(apt.stat().st_mode | stat.S_IXUSR)

    env = _isolated_env()
    env["PATH"] = f"{binroot}{os.pathsep}{env['PATH']}"
    env.update(
        APT_ATTEMPT_TIMEOUT="2",
        APT_ATTEMPT_KILL_AFTER="1",
        APT_ATTEMPTS="3",
        APT_TOTAL_BUDGET="12",
    )
    start = time.monotonic()
    proc = subprocess.run(
        ["bash", str(HELPER_PATH), "cppcheck"],
        capture_output=True,
        text=True,
        env=env,
        timeout=180,
    )
    elapsed = time.monotonic() - start

    assert proc.returncode != 0, "an apt that never succeeded must fail the step"
    # The budget is 12s; allow generous slack for the kill escalation and
    # process teardown, but nothing like the 600s the fake would take.
    assert elapsed < 90, (
        f"took {elapsed:.1f}s against a 12s budget and a 600s fake — the total "
        f"bound is not being enforced"
    )


def _outside_double_quotes(line: str) -> str:
    """`line` with every double-quoted segment removed.

    Used to tell a command word from the same text inside a message string.
    """
    out: list[str] = []
    in_quotes = False
    escaped = False
    for ch in line:
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == '"':
            in_quotes = not in_quotes
            continue
        if not in_quotes:
            out.append(ch)
    return "".join(out)


def test_the_final_attempt_is_not_unbounded(tmp_path: Path) -> None:
    """No arm of the helper may run apt without a `timeout`.

    Textual, deliberately: the behavioural test above proves the bound holds
    for one configuration, and this proves there is no second path around it.
    """
    body = HELPER_PATH.read_text(encoding="utf-8")
    # Join backslash continuations first: the bound and the command it wraps
    # are one shell statement split across lines, and reading them separately
    # would report the second half as unbounded.
    joined = body.replace("\\\n", " ")
    invocations = 0
    for line in joined.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        # An INVOCATION has `apt-get` as a bare word.  The diagnostics this
        # script prints mention `apt-get update` inside their message strings,
        # and a substring match reported those as unbounded commands.
        code = _outside_double_quotes(stripped)
        if "apt-get" not in code:
            continue
        invocations += 1
        assert "timeout" in code, f"apt-get without a timeout bound: {stripped!r}"
    # Not vacuous, and not silently reduced: `attempt_install` runs `update`,
    # `install_only` runs `install`, and `recover_dpkg` runs the `--reinstall`
    # of what a killed attempt left half-installed.  A fourth call site has to
    # come here and be accounted for rather than inheriting a pass.
    assert invocations == 3, f"expected 3 apt-get invocations, found {invocations}"
    # The recovery's own dpkg call is bounded too: `dpkg --configure -a` runs
    # maintainer scripts, and nothing else in the script would stop it.
    code_lines = [line.strip() for line in joined.splitlines() if not line.strip().startswith("#")]
    configure = [line for line in code_lines if "dpkg --configure" in _outside_double_quotes(line)]
    assert configure, "recover_dpkg's `dpkg --configure -a` is gone"
    for line in configure:
        assert "timeout" in line, f"dpkg --configure without a timeout bound: {line.strip()!r}"
    assert 'attempt_install ""' not in body, "an unbounded attempt arm is still reachable"
    assert 'install_only ""' not in body, "an unbounded install arm is still reachable"


def test_the_total_budget_fits_inside_the_shortest_job_that_uses_it() -> None:
    """Read the shipped default, so raising it without re-checking fails here.

    The shortest job budget among the callers is 3 minutes (`Constant-Time
    Gate` itself); the shortest that actually installs packages is 10 minutes
    (Cppcheck). Half of that, at most, may go to dependencies — otherwise a
    stall leaves nothing for the work.
    """
    body = HELPER_PATH.read_text(encoding="utf-8")
    match = re.search(r'TOTAL_BUDGET="\$\{APT_TOTAL_BUDGET:-(\d+)\}"', body)
    assert match is not None, "could not find the total budget default"
    assert int(match.group(1)) <= 600, (
        f"total budget {match.group(1)}s leaves too little of a 10-minute job "
        f"for the work the job exists to do"
    )


def test_the_bounded_phase_fits_inside_a_job_budget() -> None:
    """Two bounded attempts plus backoff must leave the job time to do its work.

    At the previous 300s default the bounded phase alone could consume 10.75
    minutes of a 20-minute job, so one stall left nothing for the build and test
    the job exists to run. This reads the shipped default rather than a copy of
    it, so raising the constant without re-checking the budget fails here.
    """
    body = HELPER_PATH.read_text(encoding="utf-8")
    match = re.search(r'ATTEMPT_TIMEOUT="\$\{APT_ATTEMPT_TIMEOUT:-(\d+)\}"', body)
    assert match is not None, "could not find the per-attempt timeout default"
    assert (
        int(match.group(1)) <= 180
    ), f"per-attempt bound {match.group(1)}s is too large for a 20-minute job"


@_LINUX_ONLY
def test_helper_rejects_a_nonsense_attempt_count(tmp_path: Path) -> None:
    r = _run_helper(tmp_path, ["cmake"], APT_ATTEMPTS="0")
    assert r.returncode == 2


@_LINUX_ONLY
@pytest.mark.parametrize(
    "var", ["APT_ATTEMPT_TIMEOUT", "APT_ATTEMPT_KILL_AFTER", "APT_TOTAL_BUDGET"]
)
def test_helper_rejects_a_zero_duration(tmp_path: Path, var: str) -> None:
    """GNU ``timeout 0`` means NO bound, and ``--kill-after=0`` no SIGKILL.

    Measured before the guard existed: with a SIGTERM-trapping fake apt,
    ``APT_ATTEMPT_TIMEOUT=0`` ran the fake's full 30 seconds against a
    3-second total budget — every per-command bound silently gone, which is
    the exact hang this script exists to prevent.  A zero duration is
    refused like a zero attempt count, not honoured as an unbounded run.
    """
    r = _run_helper(tmp_path, ["cmake"], **{var: "0"})
    assert r.returncode == 2
    assert "at least 1" in r.stderr


# --------------------------------------------------------------------------
# `update` is the only step that has ever stalled, so it is not on the common
# path.  Measured, run 32304592250 / 32304592231 at b781706: `Fuzz PQC
# Primitives (fuzz_frost)` and `Python 3.12 on ubuntu-latest`, two workflows on
# two runners, both stalled at `Get:5 https://archive.ubuntu.com/ubuntu
# noble-security InRelease [126 kB]` and produced no further output until the
# bound fired 315s and 293s later.  Neither reached `install`.
# --------------------------------------------------------------------------


@_LINUX_ONLY
def test_the_image_lists_are_tried_before_the_network(tmp_path: Path) -> None:
    """The happy path must not run `apt-get update` at all."""
    log = tmp_path / "apt.log"
    r = _run_helper(tmp_path, ["cmake", "clang"], FAKE_APT_LOG=str(log))
    assert r.returncode == 0, r.stderr
    verbs = log.read_text(encoding="utf-8").split("\n")
    assert "apt-get update" not in verbs, f"update ran on the happy path: {verbs}"
    assert "apt-get install" in verbs
    assert "without apt-get update" in r.stdout


@_LINUX_ONLY
def test_stale_lists_still_fall_through_to_a_refresh(tmp_path: Path) -> None:
    """Skipping `update` must not skip the packages.

    If the image's lists cannot satisfy the request, the full bounded
    `update` + `install` still runs — otherwise this would be a fast path that
    quietly stopped installing things.
    """
    log = tmp_path / "apt.log"
    r = _run_helper(
        tmp_path,
        ["libclang-rt-dev"],
        FAKE_APT_LOG=str(log),
        FAKE_APT_NEEDS_UPDATE="1",
    )
    assert r.returncode == 0, r.stderr
    verbs = log.read_text(encoding="utf-8").split("\n")
    assert "apt-get update" in verbs, "the refresh arm never ran"
    assert "did not satisfy" in r.stdout
    assert "libclang-rt-dev" in r.stdout


@_LINUX_ONLY
def test_the_fast_path_cannot_mask_a_missing_package(tmp_path: Path) -> None:
    """A package that does not exist still fails the job, through both arms."""
    r = _run_helper(
        tmp_path,
        ["definitely-not-a-package"],
        FAKE_APT_FAIL="1",
        APT_ATTEMPTS="1",
        APT_ATTEMPT_TIMEOUT="1",
    )
    assert r.returncode != 0


# --------------------------------------------------------------------------
# A killed attempt must not poison the retries
#
# Measured, `Test ubuntu-latest / Python 3.14` on run 36739915970: the fast
# path's 120s bound fired while dpkg was unpacking cmake-data, and every retry
# then failed with "E: dpkg was interrupted, you must manually run 'sudo dpkg
# --configure -a'" and apt's exit 100.  Reproduced with real apt 2.8.3 and a
# local repository, where each of the helper's two recovery steps was measured
# to be insufficient alone; the fake below models exactly those two facts.
# --------------------------------------------------------------------------


@_LINUX_ONLY
def test_a_retry_recovers_from_an_unpack_the_bound_killed(tmp_path: Path) -> None:
    """PIN: removing either `dpkg --configure -a` or the reinstall fails this."""
    state = tmp_path / "dpkg"
    state.mkdir()
    log = tmp_path / "apt.log"
    r = _run_helper(
        tmp_path,
        ["cmake"],
        FAKE_DPKG_STATE=str(state),
        FAKE_APT_LOG=str(log),
        APT_ATTEMPTS="2",
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "installed on attempt 1: cmake" in r.stdout
    assert "half-installed: cmake-data" in r.stdout
    verbs = log.read_text(encoding="utf-8").split("\n")
    # The journal is replayed before anything else apt does on the retry.
    first_retry = verbs.index("dpkg --configure")
    assert verbs[:first_retry] == ["rm -f", "apt-get install"], verbs


@_LINUX_ONLY
def test_a_clean_database_reinstalls_nothing(tmp_path: Path) -> None:
    """The recovery is a no-op unless dpkg reports a `reinstreq` package."""
    log = tmp_path / "apt.log"
    r = _run_helper(
        tmp_path,
        ["libclang-rt-dev"],
        FAKE_APT_LOG=str(log),
        FAKE_APT_NEEDS_UPDATE="1",
    )
    assert r.returncode == 0, r.stderr
    assert "half-installed" not in r.stdout
    installs = [v for v in log.read_text(encoding="utf-8").split("\n") if v == "apt-get install"]
    # The fast path's install and the refresh arm's install; no reinstall.
    assert len(installs) == 2, installs


# --------------------------------------------------------------------------
# A failure has to say what it was
# --------------------------------------------------------------------------


@_LINUX_ONLY
def test_a_timed_out_final_attempt_is_diagnosed_not_a_bare_124(tmp_path: Path) -> None:
    """The output both stalled jobs produced was `exit code 124` and nothing else.

    That is indistinguishable from a missing package to anyone reading the
    log, which defeats the purpose of converting the hang into a failure.
    """
    binroot = tmp_path / "bin"
    binroot.mkdir(exist_ok=True)
    fake = binroot / "sudo"
    fake.write_text(
        textwrap.dedent("""\
            #!/usr/bin/env bash
            if [ "$1" = "timeout" ]; then
              shift
              case "$1" in --kill-after=*) shift ;; esac
              bound="$1"; shift
              if [ "$1" = "rm" ]; then exit 0; fi
              # Outlast the bound, as a stalled mirror does.
              exec timeout --kill-after=1 "$bound" sleep 300
            fi
            exit 0
            """),
        encoding="utf-8",
    )
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    e = _isolated_env()
    e["PATH"] = f"{binroot}{os.pathsep}{e['PATH']}"
    e.update(APT_ATTEMPTS="1", APT_ATTEMPT_TIMEOUT="1", APT_TOTAL_BUDGET="4")
    r = subprocess.run(["bash", str(HELPER_PATH), "cmake"], capture_output=True, text=True, env=e)
    assert r.returncode == 124, f"expected timeout's status to propagate, got {r.returncode}"
    assert "FAILED to install: cmake" in r.stderr
    assert "stalled mirror" in r.stderr
    assert "not a cancelled job" in r.stderr


# --------------------------------------------------------------------------
# The third-party source removal
# --------------------------------------------------------------------------


def test_the_third_party_source_removal_is_not_extension_specific() -> None:
    """It matched `.list` while the image had moved to deb822 `.sources`.

    Proof it was a no-op: in the fuzz_frost log the `rm` ran and `apt-get
    update` then still fetched
    `https://packages.microsoft.com/repos/azure-cli noble InRelease`.
    """
    body = HELPER_PATH.read_text(encoding="utf-8")
    assert "/etc/apt/sources.list.d/microsoft-prod.*" in body
    assert "/etc/apt/sources.list.d/azure-cli.*" in body
    assert "microsoft-prod.list " not in body, "the extension-specific form is back"


class TestLogicalLinesAndSegmentScopedExemption:
    """Two ways a raw apt call was invisible to this gate.

    ``scan_text`` iterated PHYSICAL lines and required the binary and the
    sub-command on the same one, so a POSIX backslash continuation split the
    invocation past the regex.  And ``if HELPER in raw: continue`` exempted the
    WHOLE line on substring presence, so a compound command that named the
    helper and then fell back to a raw call was skipped entirely.  Measured on
    the gate as it stood, both returned no violations.
    """

    def test_a_backslash_continuation_is_spliced(self) -> None:
        text = "  run: |\n    apt-get \\\n      install -y cmake\n"
        found = gate.scan_text(text, "w.yml")
        assert len(found) == 1, found
        assert found[0].startswith("w.yml:2:"), found[0]

    def test_a_comment_backslash_does_not_hide_the_next_line(self) -> None:
        """A comment never continues, so the apt call after it is a real call.

        In POSIX shell a comment runs to the end of the physical line; a
        trailing ``\\`` inside it is comment text, not a continuation.  The
        splicer joined ``# foo \\`` and the raw ``apt-get`` below it into one
        logical line starting with ``#``, which ``scan_text`` skipped while
        the shell EXECUTED the apt-get — a gate bypass.  Measured on the gate
        as it stood, this text returned no violations.
        """
        text = "  run: |\n    # refresh the lists first \\\n    apt-get install -y cmake\n"
        found = gate.scan_text(text, "w.yml")
        assert len(found) == 1, found
        assert found[0].startswith("w.yml:3:"), found[0]

    def test_a_raw_call_after_the_helper_is_not_exempt(self) -> None:
        text = "  run: .github/scripts/apt-install.sh cmake && apt-get install -y ninja\n"
        assert len(gate.scan_text(text, "w.yml")) == 1

    def test_the_helper_alone_is_still_exempt(self) -> None:
        text = "  run: .github/scripts/apt-install.sh --no-install-recommends cmake\n"
        assert gate.scan_text(text, "w.yml") == []

    def test_naming_the_helper_as_an_argument_does_not_exempt(self) -> None:
        """The helper has to be the command the segment runs, not a word in it."""
        text = "  run: sudo apt-get install -y x --reason .github/scripts/apt-install.sh\n"
        assert len(gate.scan_text(text, "w.yml")) == 1

    @pytest.mark.parametrize(
        "text",
        [
            "  run: .github/scripts/apt-install.sh apt $EXTRA\n",
            '  run: "$GITHUB_WORKSPACE/.github/scripts/apt-install.sh" apt $EXTRA\n',
            "  run: sudo -E bash ./.github/scripts/apt-install.sh apt ${EXTRA}\n",
        ],
    )
    def test_an_apt_shaped_helper_argument_is_exempt(self, text: str) -> None:
        """`apt $EXTRA` here is a package list the helper receives.

        It matches the call pattern (an expansion may be the sub-command), so
        this is what pins the exemption itself: with `_runs_through_helper`
        returning False it fails, which the plain helper lines above cannot
        show because they contain no call-shaped text.
        """
        assert gate.scan_text(text, "w.yml") == []

    def test_a_trailing_comment_does_not_splice_the_next_line(self) -> None:
        """A backslash inside a trailing comment is comment text.

        Spliced, the raw call on the next line joined the helper's segment and
        was exempted by it.
        """
        text = (
            "  run: |\n"
            "    .github/scripts/apt-install.sh cmake  # see note \\\n"
            "    sudo apt-get install -y ninja\n"
        )
        found = gate.scan_text(text, "w.yml")
        assert len(found) == 1, found
        assert found[0].startswith("w.yml:3:"), found[0]

    def test_a_comment_on_a_continued_line_does_not_exempt(self) -> None:
        """bash and dash both treat a word-initial `#` on a continued line as
        a comment, so the helper's path there is prose, not the command."""
        text = (
            "  run: |\n    sudo apt-get install -y x \\\n      # .github/scripts/apt-install.sh\n"
        )
        found = gate.scan_text(text, "w.yml")
        assert len(found) == 1, found
        assert found[0].startswith("w.yml:2:"), found[0]

    @pytest.mark.parametrize("token", ["$X", "-o $X", '-o "x', "--x -o y"])
    def test_expansion_tokens_keep_the_scan_linear(self, token: str) -> None:
        """Accepting an expansion as the sub-command must keep the scan linear."""
        line = "  run: apt-get " + " ".join([token] * 96) + " zzz\n"
        start = time.perf_counter()
        gate.scan_text(line, "w.yml")
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, f"96 {token!r} tokens took {elapsed:.2f}s"

    def test_the_option_run_is_not_exponential(self) -> None:
        """``-{1,2}[^\\s]+`` gave every ``--x`` token two parses, so n had 2^n.

        ``scan_text`` runs the search on EVERY non-comment line before any
        exemption, so no line could opt out.  Measured on the ambiguous form:
        1.96 ms / 30.1 ms / 447 ms / 7166 ms at n = 12 / 16 / 20 / 24; on the
        unambiguous one, 0.007 / 0.009 / 0.014 / 0.015 ms.
        """

        line = "  run: apt-get " + " ".join(["--x"] * 24) + " zzz\n"
        start = time.perf_counter()
        gate.scan_text(line, "w.yml")
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, f"24 option tokens took {elapsed:.2f}s"


# ---------------------------------------------------------------------------
# One budget per job
# ---------------------------------------------------------------------------


@_LINUX_ONLY
def test_the_first_call_in_a_job_writes_the_shared_deadline(tmp_path: Path) -> None:
    """The first call fixes the job's deadline at now + APT_TOTAL_BUDGET."""
    state = tmp_path / "deadline"
    before = int(time.time())
    r = _run_helper(tmp_path, ["cppcheck"], APT_BUDGET_STATE=str(state))
    assert r.returncode == 0, r.stderr
    deadline = int(state.read_text(encoding="utf-8"))
    assert before + 600 <= deadline <= int(time.time()) + 600


@_LINUX_ONLY
def test_a_later_call_draws_on_what_the_job_has_left(tmp_path: Path) -> None:
    """Calls in one job share one deadline instead of each getting a fresh one.

    The budget was per CALL, so a job's worst case grew with its call count:
    `Test ubuntu-latest / Python 3.10` (run 37786915916) calls the helper
    three times, spent 734 s in two retrying calls, and was cancelled at its
    30-minute timeout with pytest unfinished.  A call that finds the job's
    deadline already passed must fail at once with the diagnosis, not start a
    budget of its own (PIN: ignoring APT_BUDGET_STATE makes this install
    succeed).
    """
    state = tmp_path / "deadline"
    state.write_text(f"{int(time.time()) - 1}\n", encoding="utf-8")
    r = _run_helper(tmp_path, ["cppcheck"], APT_BUDGET_STATE=str(state))
    assert r.returncode == 1, f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    assert "shared by every" in r.stderr and "is exhausted" in r.stderr
    assert "installed" not in r.stdout


@_LINUX_ONLY
def test_a_corrupt_deadline_is_refused_not_guessed(tmp_path: Path) -> None:
    state = tmp_path / "deadline"
    state.write_text("soon\n", encoding="utf-8")
    r = _run_helper(tmp_path, ["cppcheck"], APT_BUDGET_STATE=str(state))
    assert r.returncode == 2
    assert "not a deadline" in r.stderr


def _timeout_floor_minutes(value: object) -> int | None:
    """The smallest timeout a job can run under: a literal, or the least
    integer literal in an expression such as
    ``${{ github.event_name == 'schedule' && 50 || 30 }}``."""
    if isinstance(value, int):
        return value
    # Quoted operands are labels, not durations: 'macos-15-intel' is no
    # 15-minute timeout.
    unquoted = re.sub(r"'[^']*'|\"[^\"]*\"", "", str(value))
    literals = [int(n) for n in re.findall(r"(?<![\w.-])(\d+)(?![\w.-])", unquoted)]
    return min(literals) if literals else None


def test_every_job_s_apt_budget_fits_inside_half_its_timeout() -> None:
    """A job may spend at most half its timeout on dependencies.

    With the budget shared across a job's calls, a job's worst case in the
    helper is its effective APT_TOTAL_BUDGET -- the job's (or workflow's) env
    override, or the script default -- however many calls it makes.  Thirteen
    jobs could not fit that worst case into half their timeout when this was
    first measured; each now sets its budget explicitly.  Reads the shipped
    default, so raising it re-checks every caller.
    """
    import yaml

    body = HELPER_PATH.read_text(encoding="utf-8")
    match = re.search(r'TOTAL_BUDGET="\$\{APT_TOTAL_BUDGET:-(\d+)\}"', body)
    assert match is not None, "could not find the total budget default"
    default = int(match.group(1))

    workflows = sorted((REPO_ROOT / ".github" / "workflows").glob("*.y*ml"))
    assert workflows, "no workflows found"
    checked = 0
    failures: list[str] = []
    for wf in workflows:
        doc = yaml.safe_load(wf.read_text(encoding="utf-8")) or {}
        wf_env = doc.get("env") or {}
        for job_id, job in (doc.get("jobs") or {}).items():
            steps = job.get("steps") or []
            calls = [st for st in steps if "apt-install.sh" in str(st.get("run", ""))]
            if not calls:
                continue
            checked += 1
            for st in calls:
                if "APT_TOTAL_BUDGET" in (st.get("env") or {}):
                    failures.append(
                        f"{wf.name}:{job_id}: APT_TOTAL_BUDGET set on a step; the "
                        "deadline is fixed by the job's first call, so set it on the job"
                    )
            job_env = job.get("env") or {}
            budget = int(job_env.get("APT_TOTAL_BUDGET", wf_env.get("APT_TOTAL_BUDGET", default)))
            floor = _timeout_floor_minutes(job.get("timeout-minutes"))
            if floor is None:
                failures.append(f"{wf.name}:{job_id}: installs packages with no timeout-minutes")
            elif budget > floor * 60 // 2:
                failures.append(
                    f"{wf.name}:{job_id}: apt budget {budget}s exceeds half of its "
                    f"{floor}-minute timeout ({floor * 30}s)"
                )
    assert checked >= 30, f"only {checked} jobs found calling the helper; the scan is broken"
    assert not failures, "\n".join(failures)
