#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Container base images must be digest-pinned and still supported.

Why this exists
---------------
``tools/check_action_pins.py`` requires every GitHub Action to be pinned to a
commit SHA, because a tag is a mutable pointer and a mutable dependency is an
unreviewed one.  Container base images are the other half of the same build
input, and nothing checked them: the published images built ``FROM
alpine:3.18`` and ``FROM ubuntu:22.04``, tags whose bytes change over the
release's life.

The second half is worse.  ``alpine:3.18`` left support on 2025-05-09 and the
Dockerfile kept building on it for fifteen months — a cryptography container
published on a base that no longer receives security updates.  Nothing said
so, because the tag kept resolving perfectly well; an end-of-life base is
indistinguishable from a healthy one until someone thinks to check.

Both properties are now enforced here, and the second is enforced *ahead of
time*: the gate fails while there is still a support window left to act in,
not once it has closed.

What is checked
---------------
``digest pin``
    Every ``FROM`` outside the exemption list must carry ``@sha256:`` with a
    64-hex digest.  Keeping the human-readable tag alongside it is encouraged
    and ignored here — Docker verifies the digest and the tag is a comment.

``declared support window``
    Every Dockerfile carrying a pinned base must declare ``# base-eol:
    YYYY-MM-DD``, the end-of-support date of the base release, taken from
    upstream's own published schedule (for Alpine that is
    ``alpinelinux.org/releases.json``).  The gate fails once that date is
    within ``GRACE_DAYS``, naming the remedy.  A date the gate cannot check
    against the network is still worth requiring: writing it down is what
    turns "nobody noticed" into "the gate told us in advance".

``documented exemptions``
    A Dockerfile may opt out of pinning only by appearing in ``EXEMPT`` *and*
    carrying prose that explains why, so an exemption cannot be silent.
    ``oss-fuzz/Dockerfile`` is the one entry: OSS-Fuzz builds it inside its
    own infrastructure against whatever ``base-builder`` it currently ships
    and rebuilds every project when that base moves, so the pin belongs to
    OSS-Fuzz rather than to this repository.

Exit status: 0 when clean, 1 on any finding, 2 on a usage error.  A scan that
finds no Dockerfiles is an error, not a pass.
"""

from __future__ import annotations

import datetime as _dt
import re
import sys
from pathlib import Path
from typing import NamedTuple, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Fail this many days before the declared end-of-support date, so the base
#: can be moved while the current one is still receiving fixes.
GRACE_DAYS = 60

#: Repo-relative Dockerfiles that may use an unpinned base, each of which must
#: also explain itself in prose. See the module docstring.
EXEMPT = {"oss-fuzz/Dockerfile"}

#: A word the explanation must use, searched in COMMENT LINES ONLY.
#:
#: The first version searched the whole file for "oss-fuzz"/"base-builder" and
#: was therefore vacuous: ``FROM gcr.io/oss-fuzz-base/base-builder`` contains
#: both, so every exemption explained itself by existing. Its own test caught
#: that. "pin" is used instead because it belongs to the explanation
#: ("deliberately not digest-pinned", "the pin belongs to OSS-Fuzz") and cannot
#: appear in the image reference being excused.
_EXEMPTION_PROSE = ("pin",)

_FROM_RE = re.compile(r"^\s*FROM\s+(?P<image>\S+)", re.IGNORECASE)
_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
_EOL_RE = re.compile(r"^\s*#\s*base-eol:\s*(?P<date>\d{4}-\d{2}-\d{2})\b")


class Finding(NamedTuple):
    path: Path
    line_no: int
    message: str

    def render(self) -> str:
        try:
            rel: Path | str = self.path.relative_to(REPO_ROOT)
        except ValueError:
            rel = self.path
        where = f"{rel}:{self.line_no}" if self.line_no else f"{rel}"
        return f"{where}: {self.message}"


def dockerfiles(root: Path | None = None) -> list[Path]:
    """Every Dockerfile in the tree, vendored and build trees excluded."""
    base = REPO_ROOT if root is None else root
    skip = {".git", "build", "build-arm", "node_modules", ".venv", "dist"}
    out: list[Path] = []
    for path in sorted(base.rglob("Dockerfile*")):
        if not path.is_file():
            continue
        if any(part in skip for part in path.relative_to(base).parts):
            continue
        out.append(path)
    return out


def _declared_eol(lines: Sequence[str]) -> tuple[_dt.date | None, int]:
    for i, line in enumerate(lines, start=1):
        match = _EOL_RE.match(line)
        if match:
            return _dt.date.fromisoformat(match.group("date")), i
    return None, 0


def scan(path: Path, text: str, today: _dt.date) -> list[Finding]:
    """Findings for one Dockerfile."""
    findings: list[Finding] = []
    try:
        rel = path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        rel = path.name
    lines = text.splitlines()

    if rel in EXEMPT:
        comments = " ".join(
            line.split("#", 1)[1].lower() for line in lines if line.lstrip().startswith("#")
        )
        if not any(word in comments for word in _EXEMPTION_PROSE):
            findings.append(
                Finding(
                    path,
                    0,
                    "is exempt from digest pinning but does not say why. An "
                    "undocumented exemption is indistinguishable from an "
                    "oversight; state the reason in a comment beside the FROM.",
                )
            )
        return findings

    froms = [
        (i, m.group("image"))
        for i, line in enumerate(lines, start=1)
        if (m := _FROM_RE.match(line))
    ]
    if not froms:
        return findings

    for line_no, image in froms:
        # A stage reference (`FROM builder AS x`) names an earlier stage in the
        # same file, not a registry image, and cannot carry a digest.
        if ":" not in image and "@" not in image:
            continue
        if not _DIGEST_RE.search(image):
            findings.append(
                Finding(
                    path,
                    line_no,
                    f"base image {image!r} is pinned by tag only. A tag is a "
                    f"mutable pointer: the same line resolves to different "
                    f"bytes over time, so the build is not reproducible and an "
                    f"upstream account takeover reaches this image directly. "
                    f"Pin it as name:tag@sha256:<digest> (keep the tag for "
                    f"readability; Docker verifies the digest).",
                )
            )

    eol, eol_line = _declared_eol(lines)
    if eol is None:
        findings.append(
            Finding(
                path,
                froms[0][0],
                "has no '# base-eol: YYYY-MM-DD' declaration. Record the base "
                "release's end-of-support date from upstream's published "
                "schedule so this gate can warn before it lapses — alpine:3.18 "
                "went unsupported for fifteen months precisely because nothing "
                "recorded the date.",
            )
        )
    elif today >= eol - _dt.timedelta(days=GRACE_DAYS):
        state = "is past end-of-support" if today >= eol else "reaches end-of-support"
        findings.append(
            Finding(
                path,
                eol_line,
                f"the pinned base {state} on {eol.isoformat()} "
                f"({(eol - today).days} day(s) from now; this gate fails within "
                f"{GRACE_DAYS} days so there is a window to act). Move to a "
                f"supported release, refresh the digest, and update the "
                f"'# base-eol:' line from upstream's schedule.",
            )
        )
    return findings


def audit(paths: Sequence[Path] | None = None, today: _dt.date | None = None) -> list[Finding]:
    targets = list(paths) if paths is not None else dockerfiles()
    when = today or _dt.date.today()
    findings: list[Finding] = []
    for path in targets:
        findings.extend(scan(path, path.read_text(encoding="utf-8", errors="replace"), when))
    return findings


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        targets = [Path(a).resolve() for a in args]
        missing = [t for t in targets if not t.is_file()]
        if missing:
            for path in missing:
                print(f"ERROR: not a file: {path}", file=sys.stderr)
            return 2
    else:
        targets = dockerfiles()
        if not targets:
            # Fail closed: an empty scan is a broken scan, not a clean tree.
            print(f"ERROR: no Dockerfiles found under {REPO_ROOT}", file=sys.stderr)
            return 2

    findings = audit(targets)
    if findings:
        print(f"FAIL  container base images ({len(findings)} finding(s)):\n", file=sys.stderr)
        for finding in findings:
            print(finding.render(), file=sys.stderr)
            print(file=sys.stderr)
        return 1

    print(f"OK    container base images pinned and supported ({len(targets)} Dockerfile(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
