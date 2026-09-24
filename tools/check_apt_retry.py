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
and is not an argument of the helper, i.e. its shell segment does not have the
helper as its command word.  ``apt-cache``, ``apt-key`` and ``dpkg`` are not
covered: they do not perform the network-bound update-and-install that hangs.

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
#: `-{1,2}[^\s]+` is AMBIGUOUS inside a repeated group: for a token
#: spelled `--x` the `-{1,2}` can take one dash or two and `[^\s]+`
#: absorbs the rest either way, so every token has two parses and a run
#: of n tokens has 2^n.  With the sub-command unmatched the engine
#: explores all of them, and `scan_text` runs this search on EVERY
#: non-comment line before any exemption, so no line can opt out.
#: Measured on `apt ` + n copies of `--x` + ` zzz`, the ambiguous form
#: took 1.96 ms / 30.1 ms / 447 ms / 7166 ms at n = 12 / 16 / 20 / 24;
#: the unambiguous one below took 0.007 / 0.009 / 0.014 / 0.015 ms.
#: Requiring a non-dash after the dashes leaves exactly one parse per
#: token and still matches `-y`, `--no-install-recommends`,
#: `-o Key=Value` and `-t bookworm-backports`.
#:
#: A SHELL EXPANSION WHERE THE SUB-COMMAND COULD BE COUNTS AS ONE.  The
#: option run consumes only tokens starting with `-`, so
#: `apt-get $APT_OPTS install x` and `apt-get "${OPTS[@]}" update` (the
#: helper's own idiom) never lined the sub-command up with the pattern and
#: passed as no call at all.  The gate cannot know what an expansion
#: (`$VAR`, `${...}`, `$(...)`, `"$VAR"`) holds — options, or the sub-command
#: itself, as in `apt-get $CMD pkg` — so an expansion in the sub-command slot
#: is counted as a call rather than guessed to be a harmless one.  Fail
#: closed: spell the options and the sub-command, or use the helper.
#:
#: Teaching the option run to consume expansions as well was tried first and
#: measured redundant: with the sub-command slot accepting an expansion,
#: removing it changed no verdict in tests/test_apt_retry_gate.py.  Only the
#: mechanism the tests pin is kept.  It cannot slow a failing match either: a
#: line with no `$` token fails exactly as before, and the first reachable
#: expansion token ends the search in a match.
_EXPANSION = r"(?:\$|\"\$)\S*"
_APT_OPTION = r"(?:\s+--?[^\s-][^\s]*(?:\s+[^\s-][^\s]*)?)*"
_APT_SUBCOMMAND = (
    r"(?:(?:update|install|reinstall|upgrade|dist-upgrade|full-upgrade|build-dep)\b|"
    + _EXPANSION
    + r")"
)
_APT_CALL = re.compile(r"\b(?:apt|apt-get|aptitude)\b" + _APT_OPTION + r"\s+" + _APT_SUBCOMMAND)


#: Shell separators that end one command and start another.  A logical line can
#: hold several; only the segment the match falls in decides whether it was the
#: helper that ran.
_SEGMENT_SPLIT = re.compile(r"(?:&&|\|\||;|\|)")

#: What may precede the helper's path in the segment it runs as: the YAML
#: list marker and `run:` key of a one-line step, `sudo`/`env` and their
#: options, `VAR=value` assignments, an interpreter (`bash`, `sh`, `pwsh`…)
#: and its options, the PowerShell call and dot-source operators, and the
#: shell keywords a command can follow.  No whitespace-terminated token is
#: matched by two alternatives (a keyword has no `=` and an assignment does; a
#: lone `-` needs the whitespace an option lacks), so a token has one parse
#: and a failing match is linear — measured at 4.4 ms for 16,000 tokens.
_LAUNCHER = (
    r"(?:-|run:|sudo|env|exec|command|time|then|do|else|bash|sh|pwsh|powershell"
    r"|\{|\(|&|\.|[A-Za-z_][A-Za-z0-9_]*=\S*|-\S+)"
)

#: The helper as the COMMAND WORD of its segment — optionally quoted, and
#: optionally rooted at `./` or a workspace variable (`$GITHUB_WORKSPACE/`,
#: `${GITHUB_WORKSPACE}/`, `$env:GITHUB_WORKSPACE/`).
_HELPER_COMMAND = re.compile(
    r"\s*(?:"
    + _LAUNCHER
    + r"\s+)*[\"']?(?:\$\{?[A-Za-z_][A-Za-z0-9_:]*\}?/|\./)?"
    + re.escape(HELPER)
    + r"[\"']?(?:\s|$)"
)


def _strip_comment(line: str, escape: str, quote: str) -> tuple[str, bool, str]:
    """Split a physical line at its shell comment: `(code, commented, quote)`.

    `#` opens a comment when it starts a word outside quotes — at the start of
    the line, after whitespace, or after `;`, `&`, `|` or `(`.  That is the
    POSIX shell rule, and PowerShell's for a `#` at the start of a token; YAML
    also ends a plain scalar at ` #`.  `escape` (`\\` for sh, the backtick
    for PowerShell) protects the character after it.  `quote` carries an open
    quotation in from a continued line, and the returned one carries it on.

    Only what the shell itself discards is dropped, so stripping can hide no
    command.  What it removes matters: `_runs_through_helper` used to test the
    whole segment for the helper's path, and a trailing comment is part of the
    segment — `apt-get install -y x  # TODO: .github/scripts/apt-install.sh`
    was exempted by its own TODO.
    """
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            if char == escape and quote == '"':
                index += 2
                continue
            if char == quote:
                quote = ""
        elif char == escape:
            index += 2
            continue
        elif char in "'\"":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace() or line[index - 1] in ";&|("):
            return line[:index], True, ""
        index += 1
    return line, False, quote


def _logical_lines(text: str, continuation: str) -> list[tuple[int, str]]:
    """`(first_physical_line_number, spliced_code)` for each logical line.

    `scan_text` iterated PHYSICAL lines and required the binary and the
    sub-command on the same one, so a POSIX `\\` (or PowerShell backtick)
    continuation split the invocation past the regex and the call was never
    seen.  Splicing first makes the scan see what the shell sees; the reported
    line number stays the first physical line, which is where a reader looks.

    Comments are removed per PHYSICAL line, before splicing (see
    `_strip_comment`).  A commented line never continues: the shell's comment
    runs to the end of the physical line, so a trailing continuation character
    inside it is comment text, not a continuation.  Splicing it anyway joined
    `# foo \\` and the `apt-get install x` below it into one logical line
    starting with `#`, which `scan_text` then skipped while the shell EXECUTED
    the apt-get — a gate bypass.  The same holds for a TRAILING comment after
    code (`helper cmake  # note \\`), which the previous version spliced onto
    the next line.

    Correction to the previous docstring, which said only the first physical
    line can start a comment and that a `#` on a continued line is an ordinary
    word.  Measured with bash 5.2.21 and dash: `printf '%s\\n' a \\` followed
    by a line `# b c` prints `a` alone, so a `#` that starts a word on a
    continued line DOES open a comment.  It is stripped like any other.
    """
    lines: list[tuple[int, str]] = []
    pending: list[str] = []
    quote = ""
    start = 1
    for number, raw in enumerate(text.split("\n"), start=1):
        if not pending:
            start = number
            quote = ""
        code, commented, quote = _strip_comment(raw.rstrip(), continuation, quote)
        if not commented and code.endswith(continuation):
            pending.append(code[: -len(continuation)])
            continue
        pending.append(code)
        lines.append((start, " ".join(part.strip() for part in pending)))
        pending = []
    if pending:
        lines.append((start, " ".join(part.strip() for part in pending)))
    return lines


def _runs_through_helper(logical: str, match_start: int) -> bool:
    """True when the command the match belongs to is the helper invocation.

    `if HELPER in raw: continue` exempted the WHOLE line on substring presence,
    so a compound command that named the helper and then fell back to a raw
    call was skipped entirely.  The exemption then applied to the segment the
    match sits in, but still on substring presence, so a raw call NAMING the
    helper anywhere in its segment — a trailing `# see <helper>` comment, or
    an argument — was exempt.  The helper must now be the segment's command
    word (`_HELPER_COMMAND`): only then is the matched text an argument the
    helper receives rather than a command the shell runs.
    """
    boundary = 0
    for separator in _SEGMENT_SPLIT.finditer(logical):
        if separator.start() > match_start:
            break
        boundary = separator.end()
    segment_end = len(logical)
    for separator in _SEGMENT_SPLIT.finditer(logical, match_start):
        segment_end = separator.start()
        break
    return _HELPER_COMMAND.match(logical[boundary:segment_end]) is not None


def scan_text(text: str, path: str) -> list[str]:
    """Return one message per raw apt call in `text`."""
    violations: list[str] = []
    # `_logical_lines` has already removed every YAML comment and every shell
    # comment inside a `run:` block.  The workflows explain this very failure
    # mode in prose, and a gate that fires on its own rationale is a gate that
    # gets deleted.
    for lineno, logical in _logical_lines(text, "\\"):
        stripped = logical.strip()
        for call in _APT_CALL.finditer(logical):
            if _runs_through_helper(logical, call.start()):
                continue
            violations.append(f"{path}:{lineno}: raw apt call outside {HELPER}: {stripped[:90]}")
            break
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
