#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — apt retry-policy gate

Every ``apt-get`` call in a workflow must go through
``.github/scripts/apt-install.sh``.

Why this is a gate and not a convention
--------------------------------------
``apt-get`` on a hosted runner hangs.  When it does, the step consumes its
job's entire ``timeout-minutes`` and the job is *cancelled* — and a cancelled
dependency is not a success, so an aggregating gate goes red on a commit whose
every real check passed.

That was diagnosed once already, on this branch, and fixed with a
retry-with-backoff written inline in one step (868c354).  It was one of
thirty-eight ``apt-get`` call sites.  The other thirty-seven kept the defect,
and on a later push three of them hung at once — Cppcheck (10 minutes),
Validate fuzz dictionaries (15), Fuzz Core Primitives / fuzz_aes_gcm (20) —
turning both ``Static Analysis Gate`` and ``Fuzzing Gate`` red while sibling
jobs completed the same step in 11 seconds.

A fix applied to one of thirty-eight identical sites is not a fix, it is a
sample.  This gate is what makes it a fix: the policy lives in one script, and
a workflow that adds a bare ``apt-get`` fails here instead of failing months
later in a job nobody re-reads.

What counts as a violation
--------------------------
Any ``apt-get`` invocation in a workflow's YAML that is not inside a comment
and does not appear on a line that calls the helper.  ``apt-cache``,
``apt-key`` and ``dpkg`` are not covered: they do not perform the
network-bound update-and-install that hangs.

Exit status
-----------
0  every apt call goes through the helper
1  at least one raw apt call, or the helper is missing or not executable
2  no workflows found (fail closed — a gate with no input must not pass)
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

HELPER = ".github/scripts/apt-install.sh"
#: BOTH extensions.  GitHub Actions reads `.yml` and `.yaml` alike, so a gate
#: that globs only one of them is bypassed by a workflow named the other way —
#: silently, and in the direction that passes.  `check_action_pins.py` and
#: `check_workflow_commands.py` already glob both; this one did not.
WORKFLOW_GLOBS = (".github/workflows/*.yml", ".github/workflows/*.yaml")

#: An apt invocation that reaches the network: update, install, upgrade and
#: dist-upgrade.  `remove` and `purge` are deliberately NOT here — they touch
#: no archive, so a retry policy has nothing to retry, and listing them in this
#: comment while leaving them out of the pattern (which is what it used to do)
#: describes a gate this is not.  `apt` is the interactive spelling that should
#: never appear in CI but is caught here rather than left as a gap, and
#: `aptitude` is the third front-end for the same archive.
#:
#: OPTIONS BETWEEN THE BINARY AND THE SUB-COMMAND ARE THE NORMAL SPELLING, and
#: the previous pattern required the sub-command to follow the binary name
#: immediately:
#:
#:     \bapt(?:-get)?\s+(?:update|install|upgrade|dist-upgrade)\b
#:
#: so `apt-get -y install pkg`, `apt-get -qq -y install pkg`,
#: `apt-get --no-install-recommends install pkg` and
#: `apt-get -o Acquire::Retries=3 update` all slipped through — every one of
#: them a raw, unretried apt call, which is the single thing this gate exists
#: to refuse.  The binary and the sub-command are now matched separately, with
#: any run of option tokens (`-y`, `--no-install-recommends`,
#: `-o Key=Value`, `-t bookworm-backports`) allowed between them.
_APT_OPTION = r"(?:\s+-{1,2}[^\s]+(?:\s+[^\s-][^\s]*)?)*"
_APT_SUBCOMMAND = r"(?:update|install|reinstall|upgrade|dist-upgrade|full-upgrade|build-dep)"
_APT_CALL = re.compile(
    r"\b(?:apt|apt-get|aptitude)\b" + _APT_OPTION + r"\s+" + _APT_SUBCOMMAND + r"\b"
)


def scan_text(text: str, path: str) -> list[str]:
    """Return one message per raw apt call in `text`."""
    violations: list[str] = []
    for lineno, raw in enumerate(text.split("\n"), start=1):
        stripped = raw.strip()
        # A YAML comment, or a shell comment inside a `run:` block.  The
        # workflows explain this very failure mode in prose, and a gate that
        # fires on its own rationale is a gate that gets deleted.
        if stripped.startswith("#"):
            continue
        if not _APT_CALL.search(raw):
            continue
        if HELPER in raw:
            continue
        violations.append(f"{path}:{lineno}: raw apt call outside {HELPER}: {stripped[:90]}")
    return violations


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=".", help="repository root")
    args = ap.parse_args(argv)
    root = Path(args.root)

    helper = root / HELPER
    if not helper.is_file():
        print(f"FATAL: {HELPER} is missing; the retry policy has no home.")
        return 1
    if not os.access(helper, os.X_OK):
        print(
            f"FATAL: {HELPER} is not executable. A workflow step invoking it "
            f"would fail with 'Permission denied' on every job."
        )
        return 1

    workflows = sorted(q for g in WORKFLOW_GLOBS for q in root.glob(g))
    if not workflows:
        print(
            f"FATAL: no workflows matched {' or '.join(WORKFLOW_GLOBS)}; "
            f"refusing to pass vacuously."
        )
        return 2

    violations: list[str] = []
    for path in workflows:
        rel = str(path.relative_to(root)) if path.is_absolute() else str(path)
        violations.extend(scan_text(path.read_text(encoding="utf-8"), rel))

    if violations:
        print(f"FAIL: {len(violations)} raw apt call(s) bypassing the retry policy:")
        for v in violations:
            print(f"  - {v}")
        print(
            f"\nRoute them through {HELPER}, which bounds each attempt so a "
            f"stalled mirror cannot consume the job budget and still fails the "
            f"job if the package is genuinely unavailable."
        )
        return 1

    print(f"OK: {len(workflows)} workflow(s); every apt call goes through {HELPER}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
