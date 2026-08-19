#!/usr/bin/env bash
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
#
# Install apt packages with a bounded, retrying `update` + `install`.
#
# WHY THIS EXISTS
# ---------------
# `apt-get` on a hosted runner hangs.  Not often, but often enough: on one
# push to this branch, three jobs in three different workflows hung in their
# install step and were cancelled at their job timeouts — 10 minutes
# (Cppcheck), 15 (Validate fuzz dictionaries) and 20 (Fuzz Core Primitives,
# fuzz_aes_gcm) — while sibling jobs on the same commit completed the same
# step in 11 seconds to 5 minutes.  A cancelled job is not a success, so
# `Static Analysis Gate` and `Fuzzing Gate` both went red on a commit whose
# every real check had passed.
#
# That is worse than a wasted run.  As the commit that first fixed this for a
# single job (868c354) put it: a gate that goes red on an apt mirror hiccup
# trains reviewers to re-run without reading, which is exactly how a real
# failure gets waved through.
#
# 868c354 fixed one step.  There were 38, and the other 37 kept the defect —
# which is how the same failure came back in three new places.  The policy
# lives here once, and `tools/check_apt_retry.py` fails the build if a
# workflow adds an apt call that does not use it.
#
# WHAT IT DOES, AND WHAT IT DELIBERATELY DOES NOT
# -----------------------------------------------
# `timeout` bounds an attempt so a stalled mirror cannot consume the job's
# whole budget.  Attempts are retried with backoff, matching the pattern this
# repository already uses for the Windows Chocolatey install and for
# actions/setup-python.
#
# The final attempt runs WITHOUT `timeout` and its failure is this script's
# failure.  Nothing here is `|| true`: a genuinely unavailable package, a
# broken dependency or a repository that is really gone still fails the job.
# This converts a hang into either a success or an honest failure — it never
# converts a failure into a pass.
#
# Usage:
#   .github/scripts/apt-install.sh cmake clang
#   .github/scripts/apt-install.sh --no-install-recommends cmake ninja-build
#
# WHY `timeout` ALONE WAS NOT A BOUND
# -----------------------------------
# The first version of this script wrapped each attempt in `timeout "$bound"`
# and believed that bounded it.  It did not.  GNU `timeout` sends SIGTERM, and
# `apt-get` blocked on a network read inside its `/usr/lib/apt/methods/http`
# child does not necessarily die on SIGTERM — so the bound was advisory.
#
# Measured: on one push, `dudect - Utility Functions` and `clang-tidy` both
# stalled at `Get:5 https://archive.ubuntu.com/ubuntu noble-security InRelease`
# within one second of each other, sat there for 8m44s with no output, and were
# killed by their 20-minute job caps.  APT_ATTEMPT_TIMEOUT was 300, so SIGTERM
# had fired five minutes in and been ignored; no "attempt 1 failed" line was
# ever printed, and `Constant-Time Gate` and `Static Analysis Gate` both went
# red on a commit where every other job passed.
#
# So the bound is now enforced two ways, at different layers:
#   * `--kill-after` escalates to SIGKILL, which cannot be ignored.
#   * apt's OWN acquire timeouts fail the transfer fast and cleanly, so the
#     usual case is an honest error rather than a process that has to be shot.
#
# Environment:
#   APT_ATTEMPT_TIMEOUT   seconds to bound each non-final attempt (default 120)
#   APT_ATTEMPT_KILL_AFTER  seconds after SIGTERM before SIGKILL (default 30)
#   APT_ATTEMPTS          total attempts including the final bare one (default 3)

set -euo pipefail

if [ "$#" -eq 0 ]; then
    echo "apt-install.sh: no packages given" >&2
    echo "A step that installs nothing is a step that silently stopped " \
         "installing something." >&2
    exit 2
fi

# 120, not 300.  Two bounded attempts plus backoff has to fit inside the job
# budget with room for the work the job actually exists to do; at 300 the
# bounded phase alone could consume 10.75 minutes of a 20-minute job.  A healthy
# `apt-get update` on these runners takes 10-60 seconds.
ATTEMPT_TIMEOUT="${APT_ATTEMPT_TIMEOUT:-120}"
KILL_AFTER="${APT_ATTEMPT_KILL_AFTER:-30}"
ATTEMPTS="${APT_ATTEMPTS:-3}"

# Bound the transfer inside apt as well as around it.  These make a stalled
# mirror an ordinary apt failure — retriable, with a real message — instead of
# a wedged process that only a signal can end.
APT_NET_OPTS=(
    -o Acquire::http::Timeout=20
    -o Acquire::https::Timeout=20
    -o Acquire::ftp::Timeout=20
    -o Acquire::Retries=1
)

if [ "$ATTEMPTS" -lt 1 ]; then
    echo "apt-install.sh: APT_ATTEMPTS must be at least 1 (got $ATTEMPTS)" >&2
    exit 2
fi

# Azure/Microsoft package sources are the usual culprit for a stalled update on
# GitHub-hosted images and nothing in this repository needs them.  Removing
# them is best-effort: their absence is the desired state, so `|| true` here
# asserts nothing about the install that follows.
sudo rm -f /etc/apt/sources.list.d/microsoft-prod.list \
           /etc/apt/sources.list.d/azure-cli.list 2>/dev/null || true

attempt_install() {
    local bound="$1"
    shift
    if [ -n "$bound" ]; then
        # --kill-after is the load-bearing flag: SIGTERM is a request, SIGKILL
        # is not.  Without it a wedged apt outlives its own timeout.
        sudo timeout --kill-after="$KILL_AFTER" "$bound" \
            apt-get "${APT_NET_OPTS[@]}" update &&
            sudo timeout --kill-after="$KILL_AFTER" "$bound" \
                apt-get "${APT_NET_OPTS[@]}" install -y "$@"
    else
        # The final attempt is deliberately unbounded in WALL CLOCK so a genuine
        # failure is reported rather than truncated, but it still carries apt's
        # own acquire timeouts so it cannot hang forever on a dead mirror.
        sudo apt-get "${APT_NET_OPTS[@]}" update &&
            sudo apt-get "${APT_NET_OPTS[@]}" install -y "$@"
    fi
}

# Every attempt but the last is bounded and its failure is recoverable.
final=$((ATTEMPTS - 1))
for attempt in $(seq 1 "$final"); do
    if attempt_install "$ATTEMPT_TIMEOUT" "$@"; then
        echo "apt-install.sh: installed on attempt ${attempt}: $*"
        exit 0
    fi
    delay=$((attempt * 15))
    echo "apt-install.sh: attempt ${attempt} failed or exceeded" \
         "${ATTEMPT_TIMEOUT}s (SIGKILL ${KILL_AFTER}s later if it ignored" \
         "SIGTERM); retrying in ${delay}s"
    sleep "$delay"
done

# The last attempt is unbounded and unguarded: if apt is genuinely broken or a
# package genuinely does not exist, this is where the job finds out.
echo "apt-install.sh: final attempt (its failure fails this job): $*"
attempt_install "" "$@"
