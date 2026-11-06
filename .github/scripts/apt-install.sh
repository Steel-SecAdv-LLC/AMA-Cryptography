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
#   APT_TOTAL_BUDGET      seconds every call in one JOB may consume together
#                         (default 600; see "One budget per job" below)
#   APT_BUDGET_STATE      file holding the job's shared deadline (default
#                         $RUNNER_TEMP/ama-apt-install.deadline; empty means
#                         this call alone, which is what a local run gets)

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
# Seconds of backoff PER ATTEMPT NUMBER (attempt N sleeps N*this).  15 in CI;
# overridable so the retry-behaviour tests do not sit through real sleeps —
# they exercise ordering, bounding and message content, and the backoff
# POLICY (this default, and the budget clamp) is pinned by its own tests
# against the text and arithmetic, not by waiting it out.
BACKOFF_UNIT="${APT_RETRY_BACKOFF:-15}"

# Half the job, at most, may go to dependencies; the other half is for the
# build and the measurement the job exists to perform.  600 fits a 20-minute
# job.  A shorter job sets APT_TOTAL_BUDGET at job level, and
# tests/test_apt_retry_gate.py requires every job's budget to fit inside half
# of its timeout-minutes.
TOTAL_BUDGET="${APT_TOTAL_BUDGET:-600}"

# One budget per job.  The budget used to be per CALL, so a job's worst case
# grew with how many times it called this script: `Test ubuntu-latest /
# Python 3.10` (run 37786915916) calls it three times, and two calls that
# retried as designed -- 186 s and 548 s against a 5-13 s norm -- left pytest
# 16 minutes of a 30-minute job, which it needed 17 of.  Cancelled, `CI Gate`
# red, every check that ran green.  Thirteen jobs could spend more than half
# their timeout here.  Every call in a job now draws on one deadline, written
# by the first call into the job's own $RUNNER_TEMP, so the job's worst case
# is one TOTAL_BUDGET however many calls it makes.
BUDGET_STATE="${APT_BUDGET_STATE-${RUNNER_TEMP:+${RUNNER_TEMP}/ama-apt-install.deadline}}"
if [ -n "$BUDGET_STATE" ]; then
    if [ ! -s "$BUDGET_STATE" ]; then
        echo "$(($(date +%s) + TOTAL_BUDGET))" >"$BUDGET_STATE"
    fi
    DEADLINE="$(cat "$BUDGET_STATE")"
    if ! [[ "$DEADLINE" =~ ^[0-9]+$ ]]; then
        echo "apt-install.sh: the job's budget file $BUDGET_STATE holds" \
             "'$DEADLINE', not a deadline; refusing to guess one" >&2
        exit 2
    fi
else
    DEADLINE="$(($(date +%s) + TOTAL_BUDGET))"
fi

# Seconds left before the job's deadline; never negative.
budget_left() {
    local left=$((DEADLINE - $(date +%s)))
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

# WHY A RETRY MAY CHANGE MIRROR
# -----------------------------
# Every stall this script has recorded was a transfer that trickled or hung
# on the runner's in-datacentre mirror, and every retry so far was the same
# request to the same mirror -- the diagnosis the `update`-skipping arm
# above was written from, and still true of the arm it added.  Measured on
# 2026-11-06 (runs 42242159577, 42242159624, 42244243340, 42244243120): six
# lanes drew a runner whose fetch from azure.archive.ubuntu.com ran at a few
# hundred kB/s, each bounded attempt ended on the same multi-megabyte
# archive, and every retry re-fetched it from the same host while a sibling
# lane on the same commit installed the identical set at 31.9 MB/s.  The
# image lists that mirror first and the public archive and security hosts
# after it (actions/runner-images configure-apt-sources.sh), but apt's
# mirror method only moves down the list on an error, and a slow transfer
# is not an error.
#
# So once a bounded attempt has ended in a stall (exit 124 or 137), the
# attempts after it read a copy of the image's sources that lists every
# mirror BUT the one that stalled, written under the job's temp directory
# and handed to apt by option -- /etc/apt itself is never edited.  The copy
# is made from whatever the host has (deb822 `.sources`, one-line `.list`,
# the top-level sources.list), with only the mirror-list reference changed,
# so suites, components and signing keys are exactly the host's.  Where no
# mirror list exists, or nothing but the stalled host is on it, the retry
# says so and goes to the same mirror as before: this changes WHERE a
# retry fetches from, never whether it is bounded or whether its failure
# fails the job.
APT_ETC="${APT_ETC_DIR:-/etc/apt}"
APT_ALT_DIR="${APT_ALT_SOURCES_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/ama-apt-alt-sources}"
APT_ALT_OPTS=()
STALLED_HOST_PATTERN='azure\.archive\.ubuntu\.com'

prefer_other_mirrors() {
    local list="$APT_ETC/apt-mirrors.txt"
    local f
    if [ "${#APT_ALT_OPTS[@]}" -ne 0 ]; then return 0; fi
    if [ ! -s "$list" ]; then
        echo "apt-install.sh: no mirror list at $list to move down; the" \
             "retry fetches from the same mirror"
        return 0
    fi
    mkdir -p "$APT_ALT_DIR/sources.list.d"
    grep -v "$STALLED_HOST_PATTERN" "$list" >"$APT_ALT_DIR/apt-mirrors.txt" || true
    if [ ! -s "$APT_ALT_DIR/apt-mirrors.txt" ]; then
        echo "apt-install.sh: $list names only the mirror that stalled; the" \
             "retry fetches from it again"
        return 0
    fi
    for f in "$APT_ETC"/sources.list.d/*.sources "$APT_ETC"/sources.list.d/*.list; do
        [ -f "$f" ] || continue
        sed "s#mirror+file:$list#mirror+file:$APT_ALT_DIR/apt-mirrors.txt#g" "$f" \
            >"$APT_ALT_DIR/sources.list.d/$(basename "$f")"
    done
    if [ -f "$APT_ETC/sources.list" ]; then
        sed "s#mirror+file:$list#mirror+file:$APT_ALT_DIR/apt-mirrors.txt#g" \
            "$APT_ETC/sources.list" >"$APT_ALT_DIR/sources.list"
    else
        : >"$APT_ALT_DIR/sources.list"
    fi
    APT_ALT_OPTS=(
        -o "Dir::Etc::SourceList=$APT_ALT_DIR/sources.list"
        -o "Dir::Etc::SourceParts=$APT_ALT_DIR/sources.list.d"
    )
    echo "apt-install.sh: the stalled attempt fetched through $list; the" \
         "retries use the other mirrors on it:" \
         "$(awk '{print $1}' "$APT_ALT_DIR/apt-mirrors.txt" | tr '\n' ' ')"
}

if [ "$ATTEMPTS" -lt 1 ]; then
    echo "apt-install.sh: APT_ATTEMPTS must be at least 1 (got $ATTEMPTS)" >&2
    exit 2
fi

# GNU `timeout 0` DISABLES the bound ("If DURATION is 0, the associated
# timeout is disabled" — coreutils), and `--kill-after=0` disables the SIGKILL
# escalation the same way, so a zero in any of these knobs silently converts
# every bounded command into an unbounded one: measured with a SIGTERM-trapping
# fake apt, APT_ATTEMPT_TIMEOUT=0 ran 30 s against a 3 s total budget.  A zero
# is refused the way a zero attempt count is, not honoured as "no limit".
if [ "$ATTEMPT_TIMEOUT" -lt 1 ] || [ "$KILL_AFTER" -lt 1 ] || [ "$TOTAL_BUDGET" -lt 1 ]; then
    echo "apt-install.sh: APT_ATTEMPT_TIMEOUT, APT_ATTEMPT_KILL_AFTER and" \
         "APT_TOTAL_BUDGET must be at least 1" \
         "(got ${ATTEMPT_TIMEOUT}/${KILL_AFTER}/${TOTAL_BUDGET})" >&2
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
#
# WHY EVERY RETRY FIRST RECOVERS DPKG
# -----------------------------------
# The bound that ends a stalled attempt does not know which phase apt is in.
# When it fires after the download, it kills dpkg mid-unpack.  dpkg's journal
# (/var/lib/dpkg/updates) then makes every later apt-get refuse to run —
# "E: dpkg was interrupted, you must manually run 'sudo dpkg --configure -a'"
# — so the retries this script exists to make were all dead on arrival.
#
# Measured: `Test ubuntu-latest / Python 3.14` on run 36739915970 fetched
# cmake over a slow mirror in 1m57s, was killed at the fast path's 120s bound
# while unpacking cmake-data, and failed all three retries with exactly that
# line and apt's exit 100.
#
# Reproduced against apt 2.8.3 and dpkg on noble, with a local repository
# holding a package and one that depends on it, by SIGKILLing
# `apt-get install` mid-unpack.  The previous version of this script then
# failed every attempt with the line above.  Two steps are needed, and each
# was measured to be insufficient alone:
#   * `dpkg --configure -a` replays the journal, which is what clears the
#     refusal.  It does not finish the package the kill left half-unpacked:
#     that one stays `reinstreq half-installed`, and a plain `install` of the
#     dependent package then fails in dpkg's configure step (exit 100).
#   * `apt-get install --reinstall` of each `reinstreq` package unpacks it
#     again, after which its dependants configure and the install succeeds.
#
# On a clean dpkg database both are no-ops.  Neither failure is fatal here:
# the apt-get that follows reports what it makes of the database, and that
# failure is the attempt's.
# A wall-clock bound that reaches the whole process tree, not just the child.
#
# GNU timeout signals the process group it runs the command in.  The uutils
# coreutils `timeout` that ubuntu-latest ships from 26.04 (0.10.0) signals the
# direct child only.  Measured 2026-11-06 on that image, in the shape every
# call below has (elevated, bounded, a script as the command): a TERM-ignoring
# apt-get stand-in was SIGKILLed on schedule and its `sleep` child survived,
# holding the step's pipes open -- which is how a wedged apt's http method
# would outlive its bound and run the job into its own timeout, the stall
# this script exists to prevent.  tests/test_apt_retry_gate.py's two
# behavioural tests measured exactly that: the script exited inside its
# budget and pytest waited on the orphan until TimeoutExpired.
#
# So the bounded command is started in its own session (setsid: new session
# and process group, pgid = that pid; elevation keeps its children in it,
# measured on the same image), the bound is applied exactly as before, and
# whatever that group still holds afterwards is swept with SIGKILL.  The sweep
# is a shell BUILTIN run elevated, because the external kill, elevated,
# refused the group form (measured: `kill -KILL -- -<pgid>` exit 1 with
# the orphan alive; the builtin, exit 0 and none), and it needs the privilege
# the processes have.  The exit status is timeout's own: 124 on the bound,
# 137 after the SIGKILL escalation, the command's otherwise.
timeout_group() {
    local bound="$1"
    shift
    local pid rc
    setsid -w sudo timeout --kill-after="$KILL_AFTER" "$bound" "$@" &
    pid=$!
    wait "$pid"
    rc=$?
    # Sweep whatever the bound left in the session's process group.  The
    # group is gone in the common case (the command finished or died with
    # its children) and the look costs nothing.  Survivors we own die to the
    # builtin; survivors the elevation made root's refuse it with EPERM, and
    # only then is the elevated builtin asked -- so no elevated call happens
    # unless there is something only it can kill.
    if pgrep -g "$pid" >/dev/null 2>&1; then
        kill -KILL -- "-$pid" 2>/dev/null ||
            sudo bash -c 'kill -KILL -- "-$1"' _ "$pid" 2>/dev/null || true
    fi
    return "$rc"
}

recover_dpkg() {
    local bound="$1"
    local left
    local -a broken=()
    if ! timeout_group "$bound" dpkg --configure -a; then
        echo "apt-install.sh: dpkg --configure -a did not complete; the" \
             "apt-get below reports the state it leaves" >&2
    fi
    mapfile -t broken < <(
        dpkg-query -W -f='${db:Status-Eflag} ${binary:Package}\n' 2>/dev/null |
            awk '$1 == "reinstreq" { print $2 }'
    )
    if [ "${#broken[@]}" -eq 0 ]; then return 0; fi
    left="$(budget_left)"
    if [ "$left" -le 0 ]; then return 0; fi
    if [ "$bound" -gt "$left" ]; then bound="$left"; fi
    echo "apt-install.sh: reinstalling what an interrupted attempt left" \
         "half-installed: ${broken[*]}"
    if ! timeout_group "$bound" \
            apt-get "${APT_NET_OPTS[@]}" "${APT_ALT_OPTS[@]}" install -y --reinstall "${broken[@]}"; then
        echo "apt-install.sh: the reinstall did not complete; the apt-get" \
             "below reports the state it leaves" >&2
    fi
}

attempt_install() {
    local bound="$1"
    shift
    local rc
    local left
    recover_dpkg "$bound"
    # Recovery spends from the same budget; re-clamp before `update`.
    left="$(budget_left)"
    if [ "$left" -le 0 ]; then return 124; fi
    if [ "$bound" -gt "$left" ]; then bound="$left"; fi
    timeout_group "$bound" \
        apt-get "${APT_NET_OPTS[@]}" "${APT_ALT_OPTS[@]}" update
    rc=$?
    # Propagate update's own status (124/137 mean a stalled mirror, and the
    # final-attempt diagnosis below reads them), never collapse it to 1.
    if [ "$rc" -ne 0 ]; then return "$rc"; fi
    # Re-clamp before the install half.  `update` and `install` are two
    # separately bounded commands; giving EACH the full remaining budget let
    # one attempt legitimately spend close to twice it — the total-budget
    # contract stated at the top of this script held per command, not per
    # attempt, and the worst case re-created the cancelled-at-job-cap
    # failure this script exists to prevent.
    left="$(budget_left)"
    if [ "$left" -le 0 ]; then return 124; fi
    if [ "$bound" -gt "$left" ]; then bound="$left"; fi
    install_only "$bound" "$@"
}

install_only() {
    local bound="$1"
    shift
    timeout_group "$bound" \
        apt-get "${APT_NET_OPTS[@]}" "${APT_ALT_OPTS[@]}" install -y "$@"
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
fast_rc=0
if [ "$bound" -gt 0 ]; then
    install_only "$bound" "$@" && {
        echo "apt-install.sh: installed from the image's own package lists," \
             "without apt-get update: $*"
        exit 0
    }
    fast_rc=$?
fi
# Say which of two different things just happened.  This arm used to report
# every failure as "the image's package lists did not satisfy", including the
# one where the lists were fine and the mirror was not: on run 42242159577
# (`MemorySanitizer (fast KAT lane)`) and 42242159624 (`dudect - Legacy
# Harnesses`) the first attempt fetched its 27.5 MB / 14.1 MB archive at a few
# hundred kB/s, was ended by its bound, and the log then said the lists were
# stale and refreshed them -- a diagnosis the reader could only disprove by
# timing the lines.  124 and 137 are the bound's own exit statuses, and a
# bound that fired is a stall, not a resolution failure; the refresh still
# runs either way, because the refreshed install is also the retry.
case "$fast_rc" in
    124|137)
        echo "apt-install.sh: the first attempt, against the image's own" \
             "package lists, exceeded its ${bound}s bound (exit ${fast_rc}:" \
             "a stalled or slow mirror, not stale lists) — refreshing them" \
             "and retrying: $*"
        prefer_other_mirrors
        ;;
    *)
        echo "apt-install.sh: the image's package lists did not satisfy: $*" \
             "— refreshing them"
        ;;
esac

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
    attempt_rc=0
    attempt_install "$bound" "$@" || attempt_rc=$?
    if [ "$attempt_rc" -eq 0 ]; then
        echo "apt-install.sh: installed on attempt ${attempt}: $*"
        exit 0
    fi
    case "$attempt_rc" in 124|137) prefer_other_mirrors ;; esac
    delay=$((attempt * BACKOFF_UNIT))
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
    echo "apt-install.sh: the job's ${TOTAL_BUDGET}s apt budget (shared by every" \
         "apt-install.sh call in this job) is exhausted without installing: $*" >&2
    echo "apt-install.sh: this is a FAILED step, not a cancelled job — apt did" \
         "not complete on this runner within the budget." >&2
    exit 1
fi
echo "apt-install.sh: final attempt, bounded by the ${left}s left of the" \
     "job's ${TOTAL_BUDGET}s apt budget (its failure fails this job): $*"

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
