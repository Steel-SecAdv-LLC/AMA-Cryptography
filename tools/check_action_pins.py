#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — GitHub Actions Pin Verifier (INVARIANT-24)
=============================================================

Verifies that every SHA-pinned GitHub Action in ``.github/workflows/**``
**actually resolves upstream**, and that the version comment beside it names
the tag that SHA really belongs to.

Why this exists
---------------
SHA-pinning an action is a supply-chain control: it stops a mutable tag from
being repointed at malicious code.  But a pin is only a control if the SHA is
real.  A pin to a commit that does not exist is not "secure by accident" — it
is a **latent outage** that fires at the worst possible moment.

This is not hypothetical.  ``release.yml`` carried

    uses: pypa/cibuildwheel@e9c4a96e93b86beae8e0a78eef4b54cbc81e9a47  # v3.2.0

for multiple releases.  That SHA existed nowhere in ``pypa/cibuildwheel`` —
neither the ``v3.2.0`` tag object nor its dereferenced commit — so every wheel
job aborted immediately with::

    Unable to resolve action `pypa/cibuildwheel@e9c4a96e…`,
    unable to find version `e9c4a96e…`

Because ``release.yml`` only runs on a tag push, nothing exercised it until a
release was attempted, and the v3.2.0 and v3.3.0 releases both shipped with
zero binary artefacts as a result.  A pin that is never resolved until release
day is a pin that is never checked.

Method
------
For each ``owner/repo@<40-hex>`` pin, the repository's refs are listed with
``git ls-remote`` (unauthenticated, read-only, no clone) and the pinned SHA is
matched against every advertised ref — including ``^{}`` dereferenced tag
commits, which is the form an action pin normally takes.

A SHA that appears under no advertised ref is reported.  Note the converse is
not an error the other way round: a pin to a non-tag commit on a branch that
has since moved may legitimately not appear, so ``--strict`` is offered for
callers that want that treated as a failure too.

What is read
------------
Every ``uses:`` in ``.github/workflows/*.y{a,}ml`` AND in every action
definition — ``action.yml`` / ``action.yaml`` — ANYWHERE in the repository.
A composite action's steps run with the caller's token exactly as a
workflow's do, and ``uses: ./tools/setup`` runs ``tools/setup/action.yml``
from wherever it sits.  The scan used to stop at the workflows directory, and
then at ``.github/actions/**``, so a composite action one directory to the
side escaped INVARIANT-4 entirely.  In a git work tree the definitions come
from ``git ls-files --cached --others --exclude-standard`` (every file a
checkout carries, plus any not yet added); outside one, from a walk of the
tree.  References are collected by
PARSING the YAML (``yaml.compose``, which keeps line numbers), not by a
per-line regex: the regex matched only the block form ``- uses: x@y``, so the
flow form ``- {uses: actions/checkout@v4}`` was invisible to both halves of
this gate, and a folded scalar (``uses: >-`` with the ref on the next line)
was reported as the reference ``>-``.  A file that does not parse is a
finding, not a skip.

Exit status
-----------
``0`` when every pin resolves, ``1`` when any pin does not.  Network failure
against a host is reported and returns ``2`` — an unverifiable pin is NOT
silently treated as valid.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess  # nosec B404 -- fixed-argv git invocation only, never a shell (PIN-001)
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

import yaml

#: A SHA-pinned third-party reference, matched against the PARSED ``uses:``
#: value (see "What is read" in the module docstring).
_PIN_RE = re.compile(r"(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@(?P<sha>[0-9a-f]{40})")


@dataclass(frozen=True)
class Pin:
    """One SHA-pinned action reference."""

    workflow: str
    line_no: int
    action: str
    sha: str
    comment: Optional[str]

    @property
    def base_repo(self) -> str:
        """``owner/repo`` — strips any sub-path (e.g. codeql-action/init)."""
        return "/".join(self.action.split("/")[:2])


@dataclass(frozen=True)
class UsesRef:
    """One ``uses:`` value as parsed, with the line it sits on."""

    file: str
    line_no: int
    ref: str
    #: The source line(s) the value spans, for reading a trailing comment.
    source: str


#: The file names GitHub reads an action's definition from.  ``uses:
#: ./some/dir`` runs ``some/dir/action.yml`` (or ``.yaml``) from any directory
#: of the repository, not only from ``.github/actions``.
ACTION_FILE_NAMES = ("action.yml", "action.yaml")


def action_definition_files(root: Path) -> list[Path]:
    """Every ``action.yml`` / ``action.yaml`` under ``root``, sorted.

    In a git work tree (``root/.git`` exists) the listing is git's: every
    tracked file plus every untracked one that is not ignored — what a
    checkout carries, and what a pre-commit run is about to add — so a build
    tree or virtualenv full of third-party actions cannot produce findings.
    A listing failure there is an error, never an empty set.  Outside a work
    tree (a staged fixture, an unpacked sdist) the whole tree is walked,
    ``.git`` excepted, which can only see more files, never fewer.
    """
    if (root / ".git").exists():
        proc = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
                "--",
                *(f"*{name}" for name in ACTION_FILE_NAMES),
            ],
            capture_output=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"git ls-files failed under {root}: "
                f"{proc.stderr.decode('utf-8', 'replace').strip()[:200]}"
            )
        names = {name for name in proc.stdout.decode("utf-8").split("\0") if name}
        found = [root / name for name in names if Path(name).name in ACTION_FILE_NAMES]
        return sorted(path for path in found if path.is_file())
    out: list[Path] = []
    for directory, subdirs, files in os.walk(root):
        subdirs[:] = sorted(d for d in subdirs if d != ".git")
        out.extend(Path(directory) / name for name in files if name in ACTION_FILE_NAMES)
    return sorted(out)


def _default_root(workflows_dir: Path) -> Path:
    """The repository a workflows directory belongs to.

    ``<repo>/.github/workflows`` gives ``<repo>``.  A staged fixture that is
    not laid out that way (``<tmp>/workflows``) gives the fixture directory.
    """
    parent = workflows_dir.parent
    return parent.parent if parent.name == ".github" else parent


def pin_files(workflows_dir: Path, repo_root: Optional[Path] = None) -> list[tuple[str, Path]]:
    """``(display name, path)`` for every workflow and action definition.

    Workflows display by file name (as they always have); action definitions
    by their path relative to the repository root, so two ``action.yml``
    files are told apart.  Action definitions are collected from the whole
    repository (see :func:`action_definition_files`), not from one directory.
    """
    base = _default_root(workflows_dir) if repo_root is None else repo_root
    workflows = _workflow_files(workflows_dir)
    out: list[tuple[str, Path]] = [(path.name, path) for path in workflows]
    seen = {path.resolve() for path in workflows}
    for path in action_definition_files(base):
        if path.resolve() in seen:
            continue
        try:
            display = path.relative_to(base).as_posix()
        except ValueError:
            display = path.as_posix()
        out.append((display, path))
    return out


def _collect_uses(node: yaml.Node, found: list[yaml.ScalarNode]) -> None:
    """Every scalar value of a ``uses`` key, anywhere in the document."""
    if isinstance(node, yaml.MappingNode):
        for key, value in node.value:
            if isinstance(key, yaml.ScalarNode) and key.value == "uses":
                if isinstance(value, yaml.ScalarNode):
                    found.append(value)
            _collect_uses(value, found)
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            _collect_uses(item, found)


def uses_references(
    workflows_dir: Path, repo_root: Optional[Path] = None
) -> tuple[list[UsesRef], list[str]]:
    """``(every uses: reference, one message per file that did not parse)``."""
    refs: list[UsesRef] = []
    errors: list[str] = []
    for display, path in pin_files(workflows_dir, repo_root):
        try:
            text = path.read_text(encoding="utf-8")
            root = yaml.compose(text)
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            errors.append(f"{display}: could not be read as YAML ({str(exc).splitlines()[0]})")
            continue
        if root is None:
            continue
        lines = text.splitlines()
        nodes: list[yaml.ScalarNode] = []
        _collect_uses(root, nodes)
        for node in nodes:
            ref = str(node.value).strip()
            first, last = node.start_mark.line, max(node.end_mark.line, node.start_mark.line)
            span = lines[first : last + 1]
            # A block scalar starts on its indicator line (`uses: >-`); name the
            # line that actually carries the reference.
            offset = next((i for i, line in enumerate(span) if ref and ref in line), 0)
            refs.append(UsesRef(display, first + 1 + offset, ref, "\n".join(span)))
    return refs, errors


def find_pins(workflows_dir: Path, repo_root: Optional[Path] = None) -> list[Pin]:
    """Collect every SHA-pinned action across the workflows and action definitions."""
    pins: list[Pin] = []
    refs, _errors = uses_references(workflows_dir, repo_root)
    for use in refs:
        m = _PIN_RE.fullmatch(use.ref)
        if not m:
            continue
        comment = re.search(
            re.escape(m.group("sha")) + r"[\"'}\],\s]*#\s*(?P<comment>\S+)", use.source
        )
        pins.append(
            Pin(
                workflow=use.file,
                line_no=use.line_no,
                action=m.group("action"),
                sha=m.group("sha"),
                comment=comment.group("comment") if comment else None,
            )
        )
    return pins


#: Any ``uses:`` reference at all, pinned or not, is now collected by
#: :func:`uses_references`.  The line regex that did this before matched only
#: the already-correct block form: INVARIANT-4 had no enforcement at all until
#: it existed (INVARIANTS.md states the rule as "All third-party GitHub Actions
#: used in security workflows **must** be pinned to a full commit SHA, not a
#: mutable tag"), and once it did, the flow form ``- {uses: x@v4}`` still
#: walked past it.

#: References exempt from the SHA rule, each with the reason it cannot comply.
#: A path, not a prefix match, so a different workflow from the same generator
#: does not inherit the exemption silently.
_PIN_EXEMPT: dict[str, str] = {
    "slsa-framework/slsa-github-generator/.github/workflows/"
    "generator_generic_slsa3.yml": (
        "upstream REFUSES a SHA reference: the SLSA generator verifies that the "
        "caller referenced it by a semantic-version tag and fails the build "
        "otherwise, because the tag is what its own provenance attests. Pinning "
        "it by SHA would not harden the supply chain, it would break the "
        "attestation this workflow exists to produce."
    ),
}


@dataclass(frozen=True)
class Unpinned:
    """One ``uses:`` reference that is not pinned to a commit SHA."""

    workflow: str
    line_no: int
    ref: str


def _workflow_files(workflows_dir: Path) -> list[Path]:
    return sorted(workflows_dir.glob("*.yml")) + sorted(workflows_dir.glob("*.yaml"))


def find_unpinned(workflows_dir: Path, repo_root: Optional[Path] = None) -> list[Unpinned]:
    """Every third-party ``uses:`` reference that is not a 40-hex commit SHA.

    Local references (``./.github/workflows/x.yml``) are not third-party
    actions and carry no upstream ref to pin.  ``docker://`` references are
    container images, held to a digest pin by ``tools/check_docker_pins.py``.
    Entries in :data:`_PIN_EXEMPT` are named individually with the reason.  A
    file that does not parse is reported here too: a reference this gate
    cannot read is not a reference it has verified.
    """
    refs, errors = uses_references(workflows_dir, repo_root)
    out: list[Unpinned] = [
        Unpinned(workflow=error.split(":", 1)[0], line_no=0, ref=f"<{error.split(': ', 1)[1]}>")
        for error in errors
    ]
    for use in refs:
        ref = use.ref
        if ref.startswith("./") or ref.startswith("docker://"):
            continue
        action, _, version = ref.partition("@")
        if action in _PIN_EXEMPT:
            continue
        if re.fullmatch(r"[0-9a-f]{40}", version):
            continue
        out.append(Unpinned(workflow=use.file, line_no=use.line_no, ref=ref))
    return out


def list_remote_refs(base_repo: str, timeout: int = 60) -> Optional[dict[str, list[str]]]:
    """Return ``{sha: [refs]}`` advertised by ``base_repo``, or None on failure.

    Every ref pointing at a SHA is kept, not just the first: ``git ls-remote``
    advertises ``HEAD`` before the tags, so keeping only the first match made
    a correctly tag-pinned action report as "-> HEAD" and made the version
    comment impossible to verify.
    """
    try:
        out = subprocess.run(  # nosec B603 -- fixed argv, no shell, https URL built from repo slug (PIN-002)
            ["git", "ls-remote", f"https://github.com/{base_repo}.git"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None

    refs: dict[str, list[str]] = {}
    for row in out.splitlines():
        parts = row.split()
        if len(parts) == 2:
            refs.setdefault(parts[0], []).append(parts[1])
    return refs


def _display_ref(ref_names: list[str]) -> str:
    """Prefer a tag name over HEAD/branch when naming what a SHA points at."""
    tags = [r.replace("refs/tags/", "") for r in ref_names if r.startswith("refs/tags/")]
    if tags:
        return sorted(tags, key=len)[0].removesuffix("^{}")
    heads = [r.replace("refs/heads/", "") for r in ref_names if r.startswith("refs/heads/")]
    return heads[0] if heads else (ref_names[0] if ref_names else "<unknown>")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify every SHA-pinned GitHub Action resolves upstream."
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "also fail when a pin's trailing version comment (e.g. '# v3.2.0') "
            "does not match a tag the pinned SHA actually points at"
        ),
    )
    parser.add_argument(
        "--root",
        default=None,
        help=(
            "repository root to scan (default: this file's repository). Present "
            "so the fail-closed branches can be exercised against a staged tree "
            "-- without it the empty-pin-set path could only be asserted about, "
            "not run, and tests/test_action_pin_checks.py was doing exactly "
            "that. Every other gate in tools/ takes this option."
        ),
    )
    args = parser.parse_args(argv)

    repo_root = Path(args.root) if args.root else Path(__file__).resolve().parent.parent
    workflows_dir = repo_root / ".github" / "workflows"

    # INVARIANT-4 itself, checked before anything else: a reference with no SHA
    # is the violation, and no amount of verifying the OTHER references finds
    # it.  Reported even under --offline, since it needs no network.
    # ``<root>/.github/workflows`` resolves its action definitions against
    # ``<root>`` itself (see _default_root), so the whole repository is read.
    try:
        unpinned = find_unpinned(workflows_dir)
        pins = find_pins(workflows_dir)
    except RuntimeError as exc:
        # The action-definition listing failed: a scan that could not
        # enumerate the files is not a scan that found nothing.
        print(f"FATAL: {exc}")
        return 2
    if unpinned:
        print(f"INVARIANT-4 violation: {len(unpinned)} unpinned action reference(s):")
        for item in unpinned:
            print(f"  {item.workflow}:{item.line_no}: {item.ref}")
        print(
            "\nEvery third-party Action must be pinned to a full 40-character "
            "commit SHA. A tag is mutable: whoever controls the upstream "
            "repository can move it, and the workflow then runs different code "
            "with no diff in this repository. Add an exemption to _PIN_EXEMPT "
            "only when upstream makes a SHA reference impossible, with the "
            "reason written out."
        )
        return 1

    if not pins:
        # Fail closed, like every other gate in tools/.  An empty pin set on
        # this repository means the collector broke or the workflows moved; it
        # has never meant "there is nothing to check".
        print(
            "FATAL: no SHA-pinned actions found. This repository pins every "
            "third-party Action, so an empty scan is a checker fault, not a "
            "clean tree — refusing to pass vacuously."
        )
        return 1

    # One ls-remote per distinct repository, not per pin.
    ref_cache: dict[str, Optional[dict[str, list[str]]]] = {}
    missing: list[str] = []
    mislabelled: list[str] = []
    unreachable: list[str] = []
    verified = 0

    for pin in pins:
        base = pin.base_repo
        if base not in ref_cache:
            ref_cache[base] = list_remote_refs(base)
        refs = ref_cache[base]

        if refs is None:
            note = f"{pin.workflow}:{pin.line_no}: {base} — could not reach upstream"
            if note not in unreachable:
                unreachable.append(note)
            continue

        if pin.sha in refs:
            verified += 1
            ref_names = refs[pin.sha]
            display = _display_ref(ref_names)
            print(f"OK    {pin.action:<46s} {pin.sha[:12]} -> {display}")
            tags = {
                r.replace("refs/tags/", "").removesuffix("^{}")
                for r in ref_names
                if r.startswith("refs/tags/")
            }
            if args.strict:
                # `git ls-remote` advertises refs/pull/N/head for EVERY pull
                # request ever opened upstream, and every branch head.  "The
                # SHA resolves upstream" was therefore satisfied by a pin to
                # anybody's un-merged PR branch — the supply-chain shape
                # INVARIANT-24 exists to refuse — so a pin must resolve to a
                # RELEASE TAG, not merely to some ref.
                if not tags:
                    only_pull = ref_names and all(r.startswith("refs/pull/") for r in ref_names)
                    mislabelled.append(
                        f"{pin.workflow}:{pin.line_no}: {pin.action}@{pin.sha[:12]}\n"
                        f"      resolves upstream but is NOT tagged"
                        + (
                            " — it is only a pull-request head "
                            "(refs/pull/*), i.e. unreviewed upstream code"
                            if only_pull
                            else f" (refs: {sorted(ref_names)[:3]})"
                        )
                        + (
                            f"; the comment claims {pin.comment.lstrip('#').strip()!r}, "
                            "which no tag on this SHA supports"
                            if pin.comment
                            else ""
                        )
                    )
                elif pin.comment:
                    claimed = pin.comment.lstrip("#").strip()
                    if claimed and claimed not in tags:
                        mislabelled.append(
                            f"{pin.workflow}:{pin.line_no}: {pin.action}@{pin.sha[:12]}\n"
                            f"      comment claims {claimed!r} but the SHA is tagged "
                            f"{sorted(tags)}"
                        )
        else:
            missing.append(
                f"{pin.workflow}:{pin.line_no}: {pin.action}@{pin.sha}\n"
                f"      pin does not resolve to any ref in {base}"
                + (f" (comment claims {pin.comment})" if pin.comment else "")
            )

    if missing:
        print("\nACTION PIN CHECK FAILED — pinned SHA(s) do not exist upstream:\n")
        for row in missing:
            print(f"  {row}")
        print(
            "\nResolve the intended tag to its real commit and repin, e.g.:\n"
            "  git ls-remote https://github.com/<owner>/<repo>.git 'refs/tags/<tag>^{}'\n"
            "A pin to a nonexistent commit is not a security control — it is an\n"
            "outage that only fires when that workflow finally runs."
        )
        return 1

    if mislabelled:
        print("\nACTION PIN CHECK FAILED (--strict) — version comment does not match:\n")
        for row in mislabelled:
            print(f"  {row}")
        print(
            "\nA comment naming the wrong version is how a pin silently drifts from\n"
            "what a reviewer believes is running."
        )
        return 1

    if unreachable:
        print("\nACTION PIN CHECK INCONCLUSIVE — upstream unreachable:\n")
        for row in unreachable:
            print(f"  {row}")
        print("\nAn unverifiable pin is not treated as valid.")
        return 2

    print(f"\nAll {verified} pinned action reference(s) resolve upstream.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
