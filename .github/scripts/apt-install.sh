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
# Environment:
#   APT_ATTEMPT_TIMEOUT   seconds to bound each non-final attempt (default 300)
#   APT_ATTEMPTS          total attempts including the final bare one (default 3)

set -euo pipefail

if [ "$#" -eq 0 ]; then
    echo "apt-install.sh: no packages given" >&2
    echo "A step that installs nothing is a step that silently stopped " \
         "installing something." >&2
    exit 2
fi

ATTEMPT_TIMEOUT="${APT_ATTEMPT_TIMEOUT:-300}"
ATTEMPTS="${APT_ATTEMPTS:-3}"

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
        sudo timeout "$bound" apt-get update &&
            sudo timeout "$bound" apt-get install -y "$@"
    else
        sudo apt-get update &&
            sudo apt-get install -y "$@"
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
         "${ATTEMPT_TIMEOUT}s; retrying in ${delay}s"
    sleep "$delay"
done

# The last attempt is unbounded and unguarded: if apt is genuinely broken or a
# package genuinely does not exist, this is where the job finds out.
echo "apt-install.sh: final attempt (its failure fails this job): $*"
attempt_install "" "$@"
