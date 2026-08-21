#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — Chocolatey retry-policy gate

Every ``choco install`` in a workflow must go through
``.github/scripts/choco-install.ps1``.

Why this is a gate and not a convention
--------------------------------------
Chocolatey v2 exits 0 when it installs nothing.  On 2026-08-21 the community
feed returned 503 and every Windows lane in both workflows went red::

    Failed to fetch results from V2 feed at '...' : 503 (Service Unavailable).
    Unable to find package 'softhsm.install'.
    Chocolatey installed 0/0 packages.

``$LASTEXITCODE`` was 0 for that run.  All four retry loops in the workflows
were written as::

    choco install <pkg> ...
    if ($LASTEXITCODE -eq 0) { Write-Host "Successfully installed"; break }

so ``Attempt 1/5`` "succeeded", the loop broke, and the step failed one line
later at its post-condition with no retry ever attempted.  A five-way retry
that cannot see the failure it exists for is not a retry — it is decoration.

That is the same lesson ``check_apt_retry.py`` records for ``apt-get``, and
the same reasoning applies verbatim: a fix applied to one of four identical
sites is not a fix, it is a sample.  The policy lives in one script, and a
workflow that adds a bare ``choco install`` fails here instead of failing
months later in a job nobody re-reads.

There is one more turn of the screw worth recording.  ``apt-install.sh``'s own
header says it was modelled on "the pattern this repository already uses for
the Windows Chocolatey install".  The apt script checks real failure; the
Chocolatey pattern it cited trusts a lying exit code.  The model was the
broken one, and nothing checked it.

What counts as a violation
--------------------------
Any ``choco install`` (or ``choco.exe install``, or the ``cinst`` alias) in a
workflow's YAML that is not on a line naming the helper.

Two kinds of line are skipped, both because they are prose rather than
something a runner executes:

* comments — both workflows explain this very failure mode at length, and a
  gate that fires on its own rationale is a gate that gets deleted;
* YAML ``name:`` values — this gate's own CI step is called "Chocolatey retry
  policy: no bare choco install in a workflow", and the first version of this
  file failed the build on that step's name.  A ``name:`` is a label; it
  cannot install anything.

Skipping them is the fix rather than renaming the step, because the
alternative is an unwritten rule that every future step name must avoid
spelling the command it polices.

Exit codes
----------
0  every Chocolatey install goes through the helper
1  at least one raw choco call, or the helper is missing
2  no workflows found (fail closed — a gate with no input must not pass)
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

HELPER = ".github/scripts/choco-install.ps1"
#: BOTH extensions, for the reason check_apt_retry.py records: GitHub Actions
#: reads `.yml` and `.yaml` alike, so a gate that globs one is bypassed by a
#: workflow named the other way — silently, and in the direction that passes.
WORKFLOW_GLOBS = (".github/workflows/*.yml", ".github/workflows/*.yaml")

#: Options may sit between the binary and the sub-command — `choco -y install
#: pkg` and `choco --no-progress install pkg` are both normal spellings — so
#: the two halves are matched separately with any run of option tokens
#: between, exactly as the apt gate learned to do after `apt-get -y install`
#: slipped through a pattern that required the sub-command to follow the
#: binary immediately.
_CHOCO_OPTION = r"(?:\s+-{1,2}[^\s]+(?:\s+[^\s-][^\s]*)?)*"
#: `upgrade` and `install` both reach the feed, so both need the policy.
#: `uninstall` does not touch the network and is deliberately absent.
_CHOCO_SUBCOMMAND = r"(?:install|upgrade)"
_CHOCO_CALL = re.compile(
    r"\b(?:choco|choco\.exe|chocolatey)\b" + _CHOCO_OPTION + r"\s+" + _CHOCO_SUBCOMMAND + r"\b"
    r"|\bcinst\b"
)


#: `- name: "..."` and `name: "..."`, the two spellings a step label takes.
_YAML_NAME = re.compile(r"^-?\s*name\s*:")


def scan_text(text: str, path: str) -> list[str]:
    """Return one message per raw Chocolatey install in ``text``."""
    violations: list[str] = []
    for lineno, raw in enumerate(text.split("\n"), start=1):
        stripped = raw.strip()
        if stripped.startswith("#"):
            continue
        # A YAML `name:` is a label, not a command.  See the module docstring:
        # this gate's own step name spells `choco install`.
        if _YAML_NAME.match(stripped):
            continue
        if not _CHOCO_CALL.search(raw):
            continue
        if HELPER in raw:
            continue
        violations.append(f"{path}:{lineno}: raw choco call outside {HELPER}: {stripped[:90]}")
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", default=".", help="repository root to scan (default: current directory)"
    )
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()

    helper = root / HELPER
    if not helper.is_file():
        print(f"FAIL: {HELPER} is missing; the retry policy has nowhere to live.")
        return 1

    workflows: list[Path] = []
    for pattern in WORKFLOW_GLOBS:
        workflows.extend(sorted(root.glob(pattern)))
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
        print(f"FAIL: {len(violations)} raw Chocolatey call(s) bypassing the retry policy:")
        for v in violations:
            print(f"  - {v}")
        print(
            f"\nRoute them through {HELPER}, whose retries key on the OUTCOME "
            f"rather than on Chocolatey's exit code — which is 0 even when the "
            f"feed is down and nothing was installed."
        )
        return 1

    print(f"OK: {len(workflows)} workflow(s); every Chocolatey install goes through {HELPER}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
