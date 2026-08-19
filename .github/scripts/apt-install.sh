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
# WHY THE FINAL ATTEMPT IS BOUNDED TOO
# ------------------------------------
# The version above bounded every attempt but the last, and left the last
# unbounded on the reasoning that apt's own acquire timeouts would stop it
# hanging forever.  They do not.  `Acquire::http::Timeout` bounds a single
# CONNECTION, not the operation: apt can retry across mirrors and packages,
# and the dpkg configure phase carries no acquire timeout at all.
#
# Measured, on the run that prompted this: two jobs on one commit
# (`dudect - X25519 AVX2 4-way` and `Scalar AES-GCM instruction-count
# invariance`) sat in this script for 20 minutes and were cancelled at their
# job timeouts, with every later step skipped — while sibling jobs on the same
# commit finished the same step in 14 seconds to 5 minutes.  `Constant-Time
# Gate` then went red, because a cancelled dependency is not a success.  That
# is the identical shape described at the top of this file, in the same
# script written to prevent it: the bounded phase was fixed and the tail was
# not.
#
# So the script now has a TOTAL wall-clock budget it cannot exceed.  Each
# attempt, including the last, is bounded by whichever is smaller — the
# per-attempt bound or what remains of the budget — and exhausting the budget
# is an explicit non-zero exit with a diagnosis.  A stalled mirror therefore
# produces a FAILED step that says what happened, inside a bound the job can
# plan around, instead of a cancelled job that reads as "this gate could not
# decide".
#
# Environment:
#   APT_ATTEMPT_TIMEOUT   seconds to bound each non-final attempt (default 120)
#   APT_ATTEMPT_KILL_AFTER  seconds after SIGTERM before SIGKILL (default 30)
#   APT_ATTEMPTS          total attempts including the final one (default 3)
#   APT_TOTAL_BUDGET      seconds this script may consume in total (default 600)

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

# 600, against the 20-minute job budget the shortest caller has: half the job
# for its dependencies is already generous, and it leaves the other half for
# the build and the measurement the job exists to perform.  The jobs that were
# cancelled had spent the WHOLE 20 minutes here and run none of their steps.
TOTAL_BUDGET="${APT_TOTAL_BUDGET:-600}"
SCRIPT_START="$SECONDS"

# Seconds left of TOTAL_BUDGET; never negative.
budget_left() {
    local used=$((SECONDS - SCRIPT_START))
    local left=$((TOTAL_BUDGET - used))
    if [ "$left" -lt 0 ]; then left=0; fi
    echo "$left"
}

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

# Third-party sources nothing in this repository needs.  Each one is another
# InRelease fetch on every `update`, so dropping them shortens the window in
# which a mirror can stall.  Removing them is best-effort: their absence is the
# desired state, so `|| true` here asserts nothing about the install that
# follows.
#
# Globbed, not named with `.list`.  The previous form removed
# `microsoft-prod.list` and `azure-cli.list`; the runner image has moved to
# deb822 (`.sources`), so it matched nothing.  Measured, in the fuzz_frost and
# `Python 3.12 on ubuntu-latest` logs of run 32304592250/32304592231: after the
# `rm` ran, `apt-get update` still fetched
# `https://packages.microsoft.com/repos/azure-cli noble InRelease`.  A
# best-effort mitigation that silently does nothing is worse than none, because
# its comment says the risk is handled.
sudo rm -f /etc/apt/sources.list.d/microsoft-prod.* \
           /etc/apt/sources.list.d/azure-cli.* \
           /etc/apt/sources.list.d/google-chrome.* 2>/dev/null || true

# Every attempt is bounded — there is no unbounded arm to fall through to.
# --kill-after is the load-bearing flag: SIGTERM is a request, SIGKILL is not.
# Without it a wedged apt outlives its own timeout.
attempt_install() {
    local bound="$1"
    shift
    sudo timeout --kill-after="$KILL_AFTER" "$bound" \
        apt-get "${APT_NET_OPTS[@]}" update &&
        install_only "$bound" "$@"
}

install_only() {
    local bound="$1"
    shift
    sudo timeout --kill-after="$KILL_AFTER" "$bound" \
        apt-get "${APT_NET_OPTS[@]}" install -y "$@"
}

# FIRST, WITHOUT `update`: every stall on record has been in `apt-get update`.
#
# Both failures on run 32304592250/32304592231 — `Fuzz PQC Primitives
# (fuzz_frost)` and `Python 3.12 on ubuntu-latest`, different workflows,
# different runners — stalled at the same point: every
# `azure.archive.ubuntu.com` entry `Ign`ed (the in-datacentre mirror the image
# prefers was unreachable), apt fell back to the public
# `https://archive.ubuntu.com`, announced
# `Get:5 ... noble-security InRelease [126 kB]` — so the connection was made and
# the headers arrived — and then produced no further output until the bound
# fired, 293s and 315s later.  All three attempts stalled identically, because
# retrying is the same request to the same mirror.  `Acquire::*::Timeout=20` did
# not stop it: those bound an idle socket, not a transfer that trickles.
#
# The lists shipped in the image already resolve every package these workflows
# ask for, so try `install` against them before refreshing.  That takes the
# whole `update` — the only step that has ever hung — out of the common path.
#
# This cannot turn a failure into a pass: if the image's lists cannot satisfy
# the request for any reason (package absent, version superseded and its .deb
# gone), this arm fails and the full bounded `update` + `install` runs below,
# with its failure still fatal.  What it trades is freshness: a package may be
# installed at the image's version rather than the mirror's newest.  These are
# build tools on an ephemeral runner — cmake, clang, ninja, the aarch64
# cross-toolchain — not anything shipped, and the refresh arm still runs
# whenever the pinned lists fall short.
left="$(budget_left)"
bound="$ATTEMPT_TIMEOUT"
if [ "$bound" -gt "$left" ]; then bound="$left"; fi
if [ "$bound" -gt 0 ] && install_only "$bound" "$@"; then
    echo "apt-install.sh: installed from the image's own package lists," \
         "without apt-get update: $*"
    exit 0
fi
echo "apt-install.sh: the image's package lists did not satisfy: $*" \
     "— refreshing them"

# Every attempt but the last is recoverable; all of them, including the last,
# are bounded by whichever is smaller — the per-attempt bound or what is left
# of the total budget.
final=$((ATTEMPTS - 1))
for attempt in $(seq 1 "$final"); do
    left="$(budget_left)"
    if [ "$left" -le 0 ]; then
        break
    fi
    bound="$ATTEMPT_TIMEOUT"
    if [ "$bound" -gt "$left" ]; then bound="$left"; fi
    if attempt_install "$bound" "$@"; then
        echo "apt-install.sh: installed on attempt ${attempt}: $*"
        exit 0
    fi
    delay=$((attempt * 15))
    left="$(budget_left)"
    if [ "$delay" -gt "$left" ]; then delay="$left"; fi
    echo "apt-install.sh: attempt ${attempt} failed or exceeded" \
         "${bound}s (SIGKILL ${KILL_AFTER}s later if it ignored" \
         "SIGTERM); retrying in ${delay}s"
    if [ "$delay" -gt 0 ]; then sleep "$delay"; fi
done

# The last attempt gets whatever remains.  If nothing remains, say so and fail
# — a job that is told its dependencies could not be installed within the
# budget can act on that; a job cancelled at its own timeout cannot.
left="$(budget_left)"
if [ "$left" -le 0 ]; then
    echo "apt-install.sh: exhausted its ${TOTAL_BUDGET}s total budget without" \
         "installing: $*" >&2
    echo "apt-install.sh: this is a FAILED step, not a cancelled job — apt did" \
         "not complete on this runner within the budget." >&2
    exit 1
fi
echo "apt-install.sh: final attempt, bounded by the ${left}s left of the" \
     "${TOTAL_BUDGET}s budget (its failure fails this job): $*"

# The failure must SAY what happened.  The version that introduced the budget
# diagnosed only the arm where the budget ran out before the final attempt
# started — the rarer one.  When the final attempt itself hit its bound, which
# is what both jobs on run 32304592250/32304592231 did, `timeout`'s bare 124
# propagated and the step's whole output was
# `##[error]Process completed with exit code 124.`  A reader then cannot tell a
# stalled mirror from a missing package, which is precisely the distinction
# this script exists to make.
status=0
attempt_install "$left" "$@" || status=$?
if [ "$status" -eq 0 ]; then
    echo "apt-install.sh: installed on the final attempt: $*"
    exit 0
fi
case "$status" in
    124) reason="it exceeded its ${left}s bound; apt did not complete on this runner" ;;
    137) reason="it ignored SIGTERM at its ${left}s bound and was SIGKILLed ${KILL_AFTER}s later" ;;
    *)   reason="apt-get exited ${status}" ;;
esac
echo "apt-install.sh: FAILED to install: $*" >&2
echo "apt-install.sh: the final attempt failed because ${reason}." >&2
echo "apt-install.sh: this is a FAILED step, not a cancelled job. Exit 124 or" \
     "137 above means a stalled mirror, not a missing package." >&2
exit "$status"
