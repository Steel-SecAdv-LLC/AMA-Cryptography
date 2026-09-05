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

Exit status
-----------
``0`` when every pin resolves, ``1`` when any pin does not.  Network failure
against a host is reported and returns ``2`` — an unverifiable pin is NOT
silently treated as valid.
"""

from __future__ import annotations

import argparse
import re
import subprocess  # nosec B404 -- fixed-argv git invocation only, never a shell (PIN-001)
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

_PIN_RE = re.compile(
    r"uses:\s*(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@(?P<sha>[0-9a-f]{40})"
    r"(?:\s*#\s*(?P<comment>\S+))?"
)


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


def find_pins(workflows_dir: Path) -> list[Pin]:
    """Collect every SHA-pinned action across the workflow files."""
    pins: list[Pin] = []
    for path in sorted(workflows_dir.glob("*.yml")) + sorted(workflows_dir.glob("*.yaml")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), start=1):
            m = _PIN_RE.search(line)
            if m:
                pins.append(
                    Pin(
                        workflow=path.name,
                        line_no=i,
                        action=m.group("action"),
                        sha=m.group("sha"),
                        comment=m.group("comment"),
                    )
                )
    return pins


#: Any ``uses:`` reference at all, pinned or not.  ``_PIN_RE`` above matches
#: only the already-correct form, which is why nothing in this repository ever
#: enforced INVARIANT-4: the checker verified that SHA pins RESOLVE upstream and
#: was structurally blind to a reference that carried no SHA.  INVARIANTS.md
#: states the rule as "All third-party GitHub Actions used in security workflows
#: **must** be pinned to a full commit SHA, not a mutable tag (`@main`, `@v1`,
#: etc.)" and ARCHITECTURE.md restates it as enforced.  It was not enforced
#: anywhere, and ``tests/test_action_pin_checks.py`` recorded the gap in a
#: comment rather than closing it.
_USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<ref>\S+)")

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


def find_unpinned(workflows_dir: Path) -> list[Unpinned]:
    """Every third-party ``uses:`` reference that is not a 40-hex commit SHA.

    Local references (``./.github/workflows/x.yml``, ``docker://…``) are not
    third-party actions and carry no upstream ref to pin; entries in
    :data:`_PIN_EXEMPT` are named individually with the reason.
    """
    out: list[Unpinned] = []
    for path in _workflow_files(workflows_dir):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue
            m = _USES_RE.match(line)
            if not m:
                continue
            ref = m.group("ref").strip().strip("\"'")
            if ref.startswith("./") or ref.startswith("docker://"):
                continue
            action, _, version = ref.partition("@")
            if action in _PIN_EXEMPT:
                continue
            if re.fullmatch(r"[0-9a-f]{40}", version):
                continue
            out.append(Unpinned(workflow=path.name, line_no=i, ref=ref))
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
    unpinned = find_unpinned(workflows_dir)
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

    pins = find_pins(workflows_dir)
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
            if args.strict and pin.comment:
                claimed = pin.comment.lstrip("#").strip()
                tags = {
                    r.replace("refs/tags/", "").removesuffix("^{}")
                    for r in ref_names
                    if r.startswith("refs/tags/")
                }
                if claimed and tags and claimed not in tags:
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
