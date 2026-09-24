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
    ``alpinelinux.org/releases.json``).  A date the gate cannot check against
    the network is still worth requiring: writing it down is what turns
    "nobody noticed" into "the gate told us in advance".

    Two distinct states fail, and they are reported as distinct kinds rather
    than one message with a conditional clause:

    ``EOL_APPROACHING``
        The date is within ``GRACE_DAYS``.  Act inside the remaining window.
    ``EOL_PASSED``
        The date has passed.  The image is already being published on an
        unsupported base — a shipped defect, not a reminder.

    Both fail.  ``GRACE_DAYS`` carries the reasoning for why the first one
    fails rather than warns, which was an open question in review.

``documented exemptions``
    A Dockerfile may opt out of pinning only by appearing in ``EXEMPT`` *and*
    carrying prose that explains why, so an exemption cannot be silent.
    ``oss-fuzz/Dockerfile`` and its ClusterFuzzLite twin
    ``.clusterfuzzlite/Dockerfile`` are the entries: OSS-Fuzz builds them inside its
    own infrastructure against whatever ``base-builder`` it currently ships
    and rebuilds every project when that base moves, so the pin belongs to
    OSS-Fuzz rather than to this repository.

``workflow images``
    A Dockerfile is not the only place an image is named.  A workflow job's
    ``container:`` (string or ``image:``), every ``services.<id>.image``, a
    step's ``uses: docker://…``, and a Docker container action's
    ``runs.image: docker://…`` all pull a registry image by reference and run
    it with the job's token.  The scan globbed ``Dockerfile*`` only, so a
    tag-only ``container: image: quay.io/pypa/manylinux_2_28_x86_64:<tag>`` in
    ``static-analysis.yml`` was never examined.  Each of these must carry
    ``@sha256:<64 hex>`` too; an image computed by a ``${{ }}`` expression
    cannot be verified and fails the same way.  The workflows are PARSED
    (``yaml.compose``) so every YAML spelling of those keys is seen.  No
    ``base-eol`` declaration is required of them: there is no Dockerfile to
    carry it, and the image's support window is the workflow's owner's to
    track.

Scope: the Dockerfiles git tracks (``tools/_repo.py``), not whatever a
filesystem walk finds under the root — an untracked checkout nested in the
tree is not this repository's build input.  See :func:`dockerfiles`.

Exit status: 0 when clean, 1 on any finding, 2 on a usage error or when git
cannot enumerate the tree.  A scan that finds no Dockerfiles is an error, not a
pass.
"""

from __future__ import annotations

import datetime as _dt
import re
import sys
from pathlib import Path
from typing import NamedTuple, Sequence

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Fail this many days before the declared end-of-support date, so the base
#: can be moved while the current one is still receiving fixes.
#:
#: Why this window fails rather than warns — the question left open in review.
#:
#: The objection is real: this is a red gate with no diff behind it, which can
#: appear on a pull request that has nothing to do with containers.  It is
#: nonetheless the correct behaviour, for a reason specific to what is being
#: gated.  The failure mode this replaces is not "someone forgot"; it is
#: ``alpine:3.18`` shipping in a published cryptography image for fifteen
#: months after leaving support, because an end-of-life base is
#: indistinguishable from a healthy one until something says otherwise.  A
#: warning is exactly the thing that said otherwise for fifteen months and
#: changed nothing.  By this repository's own standard — a gate that cannot
#: fail is worse than no gate — a warn-only support window is not a gate.
#:
#: The precedent is already set in-tree by
#: ``tests/test_benchmark_baseline_freshness.py``, which fails on a date for
#: the same reason: the thing being guarded decays with time rather than with
#: commits, so only time can trip the guard.
#:
#: 60 days is chosen against the shortest support window this repository's
#: bases actually have.  Alpine ships a release every ~6 months and supports
#: each for 2 years; Ubuntu LTS for 5.  Sixty days is therefore ~1% of the
#: shortest window: long enough that a base bump is ordinary scheduled work
#: (digest refresh, image rebuild, one CI cycle), short enough that the gate is
#: quiet for the other 99% of the base's life.  Two Findings are produced
#: instead of one so the two states are never confused: see EOL_APPROACHING
#: (act within the window) and EOL_PASSED (already shipping unsupported).
GRACE_DAYS = 60

#: Finding kinds.  Both fail the gate; they are distinguished because the
#: remedies differ in urgency and a reader must not have to parse prose to tell
#: "you have N days" from "this is already unsupported".
EOL_APPROACHING = "eol-approaching"
EOL_PASSED = "eol-passed"
EOL_UNDECLARED = "eol-undeclared"
NOT_DIGEST_PINNED = "not-digest-pinned"
UNDOCUMENTED_EXEMPTION = "undocumented-exemption"

#: Repo-relative Dockerfiles that may use an unpinned base, each of which must
#: also explain itself in prose. See the module docstring.
EXEMPT = {"oss-fuzz/Dockerfile", ".clusterfuzzlite/Dockerfile"}

#: A word the explanation must use, searched in COMMENT LINES ONLY.
#:
#: The first version searched the whole file for "oss-fuzz"/"base-builder" and
#: was therefore vacuous: ``FROM gcr.io/oss-fuzz-base/base-builder`` contains
#: both, so every exemption explained itself by existing. Its own test caught
#: that. "pin" is used instead because it belongs to the explanation
#: ("deliberately not digest-pinned", "the pin belongs to OSS-Fuzz") and cannot
#: appear in the image reference being excused.
_EXEMPTION_PROSE = ("pin",)

#: ``FROM`` may carry flags before the image (``--platform=$BUILDPLATFORM`` is
#: the standard multi-arch idiom).  Capturing the first token grabbed the flag,
#: which contains neither ':' nor '@', so the build-stage-reference shortcut
#: below treated it as a stage name and the unpinned base was never checked —
#: the gate reported "pinned" for a tag-only image.  Skip leading flags.
_FROM_RE = re.compile(r"^\s*FROM\s+(?:--[^\s]+\s+)*(?P<image>\S+)", re.IGNORECASE)
#: ``FROM x AS name`` declares a build stage.  Stage names are matched
#: case-insensitively because Docker treats them that way.
_STAGE_RE = re.compile(r"\bAS\s+(?P<stage>\S+)\s*$", re.IGNORECASE)
_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
_EOL_RE = re.compile(r"^\s*#\s*base-eol:\s*(?P<date>\d{4}-\d{2}-\d{2})\b")


class Finding(NamedTuple):
    path: Path
    line_no: int
    message: str
    #: One of the module-level kind constants. Every kind fails the gate; the
    #: label exists so a reader (and a test) can tell the states apart without
    #: pattern-matching on prose.
    kind: str = ""

    def render(self) -> str:
        try:
            rel: Path | str = self.path.relative_to(REPO_ROOT)
        except ValueError:
            rel = self.path
        where = f"{rel}:{self.line_no}" if self.line_no else f"{rel}"
        return f"{where}: {self.message}"


def dockerfiles(root: Path | None = None) -> list[Path]:
    """Every TRACKED Dockerfile in the tree, build trees excluded.

    Enumerated through ``tools/_repo.py`` (``git ls-files -z``), not by walking
    the filesystem.  The walk this replaced was ``base.rglob("Dockerfile*")``:
    any untracked checkout under the root — a ``.claude/worktrees/<copy>``, a
    developer's scratch clone — contributed its Dockerfiles, and the gate
    failed on files that are not part of the repository.  An untracked
    Dockerfile is not built, published or reviewed from this tree, so it is
    out of scope; a tracked one with working-tree edits is read as it is on
    disk.

    Raises ``TrackedFilesError`` (a ``RuntimeError``) when git cannot
    enumerate ``root``: a scope that cannot be established is not a clean one.
    """
    base = REPO_ROOT if root is None else root
    repo = str(Path(__file__).resolve().parent.parent)
    if repo not in sys.path:
        sys.path.insert(0, repo)
    from tools._repo import tracked_names

    skip = {".git", "build", "build-arm", "node_modules", ".venv", "dist"}
    out: list[Path] = []
    # `:(glob)` magic so `*` does not cross a `/`; the leading `**/` matches at
    # every depth including the root, which is what `rglob` did.
    for name in sorted(tracked_names(base, ":(glob)**/Dockerfile*")):
        if any(part in skip for part in name.split("/")):
            continue
        out.append(base / name)
    return out


def workflow_files(root: Path | None = None) -> list[Path]:
    """Every workflow and composite/container action definition under ``.github``."""
    base = REPO_ROOT if root is None else root
    github = base / ".github"
    out: list[Path] = []
    workflows = github / "workflows"
    if workflows.is_dir():
        out.extend(sorted(workflows.glob("*.yml")) + sorted(workflows.glob("*.yaml")))
    actions = github / "actions"
    if actions.is_dir():
        for pattern in ("action.yml", "action.yaml"):
            out.extend(sorted(path for path in actions.rglob(pattern) if path.is_file()))
    return out


def _get(node: yaml.Node | None, key: str) -> yaml.Node | None:
    """The value node for ``key`` in a mapping node, or ``None``."""
    if not isinstance(node, yaml.MappingNode):
        return None
    for key_node, value in node.value:
        if isinstance(key_node, yaml.ScalarNode) and key_node.value == key:
            found: yaml.Node = value
            return found
    return None


def _items(node: yaml.Node | None) -> list[tuple[str, yaml.Node]]:
    if not isinstance(node, yaml.MappingNode):
        return []
    return [
        (str(key.value), value) for key, value in node.value if isinstance(key, yaml.ScalarNode)
    ]


def _steps_images(steps: yaml.Node | None, where: str) -> list[tuple[str, yaml.ScalarNode]]:
    out: list[tuple[str, yaml.ScalarNode]] = []
    if isinstance(steps, yaml.SequenceNode):
        for step in steps.value:
            uses = _get(step, "uses")
            if isinstance(uses, yaml.ScalarNode) and str(uses.value).strip().startswith(
                "docker://"
            ):
                out.append((f"{where} step `uses: docker://`", uses))
    return out


def _workflow_image_nodes(root: yaml.Node) -> list[tuple[str, yaml.ScalarNode]]:
    """``(context, image scalar)`` for every image a workflow or action pulls."""
    images: list[tuple[str, yaml.ScalarNode]] = []
    for job_id, job in _items(_get(root, "jobs")):
        container = _get(job, "container")
        if isinstance(container, yaml.ScalarNode):
            images.append((f"job '{job_id}' container", container))
        else:
            image = _get(container, "image")
            if isinstance(image, yaml.ScalarNode):
                images.append((f"job '{job_id}' container", image))
        for service_id, service in _items(_get(job, "services")):
            image = service if isinstance(service, yaml.ScalarNode) else _get(service, "image")
            if isinstance(image, yaml.ScalarNode):
                images.append((f"job '{job_id}' service '{service_id}'", image))
        images.extend(_steps_images(_get(job, "steps"), f"job '{job_id}'"))
    runs = _get(root, "runs")
    images.extend(_steps_images(_get(runs, "steps"), "composite action"))
    runs_image = _get(runs, "image")
    if isinstance(runs_image, yaml.ScalarNode) and str(runs_image.value).strip().startswith(
        "docker://"
    ):
        images.append(("container action `runs.image`", runs_image))
    return images


def scan_workflow(path: Path, text: str) -> list[Finding]:
    """Findings for one workflow or action definition: every image digest-pinned."""
    try:
        root = yaml.compose(text)
    except yaml.YAMLError as exc:
        return [
            Finding(
                path,
                0,
                f"could not be parsed as YAML ({str(exc).splitlines()[0]}); an image "
                f"reference this gate cannot read is not one it has verified.",
                NOT_DIGEST_PINNED,
            )
        ]
    if root is None:
        return []
    findings: list[Finding] = []
    for context, node in _workflow_image_nodes(root):
        image = str(node.value).strip()
        reference = image.removeprefix("docker://")
        if _DIGEST_RE.search(reference):
            continue
        computed = "${{" in reference
        findings.append(
            Finding(
                path,
                node.start_mark.line + 1,
                f"{context} image {image!r} "
                + (
                    "is computed by an expression, so no digest can be verified here. "
                    if computed
                    else "is pinned by tag only. "
                )
                + "A tag is a mutable pointer: the job runs whatever bytes the "
                "registry serves under it today, with the job's token. Pin it as "
                "name:tag@sha256:<digest> (keep the tag for readability).",
                NOT_DIGEST_PINNED,
            )
        )
    return findings


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
                    UNDOCUMENTED_EXEMPTION,
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

    # Stage names declared by `FROM ... AS <name>`, collected in file order so
    # only a name declared BEFORE its use reads as a stage reference.  The
    # previous rule — skip any image containing neither ':' nor '@' — was
    # meant for `FROM builder`, but `FROM ubuntu` matches it too: an untagged
    # registry image, implicitly `:latest`, the MOST mutable pointer this gate
    # exists to refuse, and it sailed through unexamined.  A stage reference
    # is structurally identifiable (its name was declared above); everything
    # else is a registry image and must carry a digest, tag or no tag.
    declared_stages: set[str] = set()
    stage_by_line: dict[int, str | None] = {}
    for line_no, _image in froms:
        stage_match = _STAGE_RE.search(lines[line_no - 1])
        stage_by_line[line_no] = stage_match.group("stage").lower() if stage_match else None

    for line_no, image in froms:
        if ":" not in image and "@" not in image and image.lower() in declared_stages:
            # `FROM builder` naming an earlier `FROM ... AS builder` stage in
            # this same file: not a registry image, cannot carry a digest.
            if stage_by_line[line_no]:
                declared_stages.add(str(stage_by_line[line_no]))
            continue
        if not _DIGEST_RE.search(image):
            tagless = ":" not in image and "@" not in image
            findings.append(
                Finding(
                    path,
                    line_no,
                    (
                        f"base image {image!r} carries no tag at all — it resolves "
                        f"to :latest, the most mutable pointer there is, and it "
                        f"matches no build stage declared earlier in this file. "
                        if tagless
                        else f"base image {image!r} is pinned by tag only. "
                    )
                    + "A tag is a mutable pointer: the same line resolves to "
                    "different bytes over time, so the build is not reproducible "
                    "and an upstream account takeover reaches this image "
                    "directly. Pin it as name:tag@sha256:<digest> (keep the tag "
                    "for readability; Docker verifies the digest).",
                    NOT_DIGEST_PINNED,
                )
            )
        if stage_by_line[line_no]:
            declared_stages.add(str(stage_by_line[line_no]))

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
                EOL_UNDECLARED,
            )
        )
    elif today >= eol:
        findings.append(
            Finding(
                path,
                eol_line,
                f"the pinned base left support on {eol.isoformat()}, "
                f"{(today - eol).days} day(s) ago. This image is being "
                f"published on a base that no longer receives security "
                f"updates — a shipped defect, not a reminder. Move to a "
                f"supported release, refresh the digest, and update the "
                f"'# base-eol:' line from upstream's schedule.",
                EOL_PASSED,
            )
        )
    elif today >= eol - _dt.timedelta(days=GRACE_DAYS):
        findings.append(
            Finding(
                path,
                eol_line,
                f"the pinned base reaches end-of-support on {eol.isoformat()}, "
                f"in {(eol - today).days} day(s). This gate fails inside the "
                f"final {GRACE_DAYS} days deliberately, so the base moves while "
                f"it is still receiving fixes rather than after it stops "
                f"(see GRACE_DAYS for why this fails rather than warns). Move "
                f"to a supported release, refresh the digest, and update the "
                f"'# base-eol:' line from upstream's schedule.",
                EOL_APPROACHING,
            )
        )
    return findings


def _is_workflow(path: Path) -> bool:
    return path.suffix in (".yml", ".yaml")


def audit(paths: Sequence[Path] | None = None, today: _dt.date | None = None) -> list[Finding]:
    """Findings for the given files, or for every Dockerfile AND workflow in the tree.

    A ``.yml``/``.yaml`` path is read as a workflow or action definition;
    anything else as a Dockerfile.
    """
    targets = list(paths) if paths is not None else dockerfiles() + workflow_files()
    when = today or _dt.date.today()
    findings: list[Finding] = []
    for path in targets:
        text = path.read_text(encoding="utf-8", errors="replace")
        if _is_workflow(path):
            findings.extend(scan_workflow(path, text))
        else:
            findings.extend(scan(path, text, when))
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
        try:
            docker = dockerfiles()
        except RuntimeError as exc:  # TrackedFilesError: git could not enumerate
            print(f"ERROR: cannot enumerate the tracked Dockerfiles: {exc}", file=sys.stderr)
            return 2
        workflows = workflow_files()
        # Fail closed PER KIND: an empty scan of either is a broken scan, and
        # the other kind's files must not carry it to a pass.
        if not docker:
            print(f"ERROR: no Dockerfiles found under {REPO_ROOT}", file=sys.stderr)
            return 2
        if not workflows:
            print(f"ERROR: no workflow files found under {REPO_ROOT}/.github", file=sys.stderr)
            return 2
        targets = docker + workflows

    findings = audit(targets)
    if findings:
        print(f"FAIL  container base images ({len(findings)} finding(s)):\n", file=sys.stderr)
        for finding in findings:
            print(finding.render(), file=sys.stderr)
            print(file=sys.stderr)
        return 1

    print(
        f"OK    container images pinned (and Dockerfile bases supported) "
        f"({len(targets)} Dockerfile/workflow file(s))"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
