#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — Release Tag Shape Gate (INVARIANT-10)
========================================================

Refuses to release from a tag that is not an **annotated, signed** tag object.

Why this exists
---------------
INVARIANT-10 requires signed commits, and ``release.yml``'s operator runbook
has always said to tag with ``git tag -s``. Nothing checked that it happened,
and the repository's own history is what that gap looks like. Measured against
the eleven tags present when this gate was written::

    v1.0.0   commit   (lightweight — cannot carry a signature at all)
    v1.1     commit   (lightweight)
    v2.0.0   commit   (lightweight)
    v2.1.2   tag      no signature found
    v2.1.5   commit   (lightweight)
    v3.0.0   commit   (lightweight)
    v3.1.0   tag      no signature found
    v3.2.0   tag      no signature found
    v3.3.0   commit   (lightweight)
    v3.4.0   tag      no signature found
    v3.5.0   tag      no signature found

Not one is signed, and six are lightweight — a ref pointing straight at a
commit, with no tag object, therefore no place to put a signature and nothing
to fix after the fact. Every one of those releases went out through a pipeline
whose documentation described a signed tag.

The distinction matters beyond bookkeeping. A lightweight tag is a mutable
pointer: anyone who can push can move it, and the release pipeline will
happily rebuild from wherever it now points. An annotated tag is an object in
the object store with its own hash, and a signature over that object binds the
tag name, the target commit, the tagger and the date together. Only the second
one is evidence.

What is checked, and what deliberately is not
---------------------------------------------
Checked, fail-closed:

1. **The ref resolves.** A release cannot proceed from a tag that is not there.
2. **The ref names a tag object**, not a commit. This is the lightweight case.
3. **The tag object carries a signature block** — OpenPGP, SSH, or the
   ``SIGNED MESSAGE`` form ``gpg.format=x509``/gpgsm emits.

**Not** checked, and stated plainly rather than implied (INVARIANT-37): this
tool does **not** verify the signature. Verification needs a trust store — an
``allowed_signers`` file or a GPG keyring — holding the maintainer's public
key, and this repository ships neither, because publishing one would assert a
key binding that only the account owner can establish. What is checked here is
*shape*: the properties that were wrong on all eleven historical tags, that
need no key material to establish, and whose absence means no later
verification can ever succeed.

GitHub's own verified/unverified badge is the complementary half. It is
account-level state, not repository state — it turns on when the signing key
is registered under Settings -> SSH and GPG keys with type **Signing Key** —
so it is reported by ``release.yml`` for the operator to read, not gated here.

The fetch trap this gate would otherwise walk into
--------------------------------------------------
``actions/checkout`` at its default depth, on a tag-push trigger, fetches the
*commit* the tag resolves to and writes a local ``refs/tags/<name>`` pointing
at it. That local ref is lightweight even when the pushed tag is annotated, so
running this check straight after a bare checkout would report a false
lightweight verdict on a correctly signed tag. ``release.yml`` therefore
re-fetches the tag ref explicitly, with ``--force``, before invoking this tool;
see the step comment there. The lightweight failure message below repeats the
warning, because a false red on a release gate is how gates get switched off.

Usage
-----
::

    python tools/check_release_tag.py v4.0.0
    python tools/check_release_tag.py v4.0.0 --repo /path/to/checkout

Exits 0 when the tag is an annotated tag object carrying a signature block,
1 otherwise.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

#: Header lines that mark the start of a signature inside a tag object.
#: git writes the OpenPGP form for ``gpg.format=openpgp`` (the default), the
#: SSH form for ``gpg.format=ssh``, and the ``SIGNED MESSAGE`` form for
#: ``gpg.format=x509``. All three are accepted; which one a maintainer uses is
#: their choice, and refusing two of the three would push them toward the
#: unsigned path this gate exists to close.
SIGNATURE_HEADERS = (
    "-----BEGIN PGP SIGNATURE-----",
    "-----BEGIN SSH SIGNATURE-----",
    "-----BEGIN SIGNED MESSAGE-----",
)

_LIGHTWEIGHT_HINT = (
    "A lightweight tag is a ref pointing directly at a commit: there is no tag "
    "object, so there is nowhere for a signature to live and nothing to repair "
    'after the fact. Re-create it with `git tag -s -f <tag> -m "..."` and '
    "force-push the ref.\n"
    "    If this ran in CI: confirm the tag ref was fetched with "
    "`git fetch --force origin refs/tags/<tag>:refs/tags/<tag>` first. "
    "actions/checkout writes a lightweight local ref at the tag's name, which "
    "reads as this same failure on a correctly annotated tag."
)

_UNSIGNED_HINT = (
    "The tag object exists but carries no signature block. Re-create it with "
    '`git tag -s -f <tag> -m "..."` and force-push the ref. For the badge to '
    "read Verified on GitHub, the signing key must also be registered on the "
    "account under Settings -> SSH and GPG keys with type Signing Key."
)


def object_type(tag: str, repo: Path) -> str | None:
    """Return the git object type ``tag`` resolves to, or None if unresolvable.

    ``refs/tags/`` is spelled out rather than passing the bare name: a bare
    name would also match a branch or a file of the same name under git's
    disambiguation rules, and a release must not be able to proceed from a
    branch that happens to share a tag's name.
    """
    result = subprocess.run(
        ["git", "cat-file", "-t", f"refs/tags/{tag}"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def tag_object_body(tag: str, repo: Path) -> str:
    """Return the raw contents of the annotated tag object."""
    result = subprocess.run(
        ["git", "cat-file", "tag", f"refs/tags/{tag}"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return ""
    return result.stdout


def is_signed(body: str) -> bool:
    """True when the tag object body contains a signature block."""
    return any(header in body for header in SIGNATURE_HEADERS)


def check(tag: str, repo: Path) -> list[str]:
    """Return the list of problems with ``tag``; empty means it passes."""
    kind = object_type(tag, repo)
    if kind is None:
        return [f"tag `{tag}` does not resolve to any object in {repo}"]
    if kind != "tag":
        return [
            f"tag `{tag}` is a lightweight tag (points directly at a {kind}), "
            f"not an annotated tag object.\n    {_LIGHTWEIGHT_HINT}"
        ]
    if not is_signed(tag_object_body(tag, repo)):
        return [f"annotated tag `{tag}` carries no signature block.\n" f"    {_UNSIGNED_HINT}"]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[3])
    parser.add_argument("tag", help="tag name, e.g. v4.0.0")
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path("."),
        help="repository checkout to inspect (default: cwd)",
    )
    args = parser.parse_args(argv)

    problems = check(args.tag, args.repo)
    if problems:
        print(f"FAIL: release tag `{args.tag}` is not releasable:")
        for problem in problems:
            print(f"  - {problem}")
        print(
            "\nThis gate checks the tag's SHAPE only. It does not verify the "
            "signature —\nthat needs a trust store this repository "
            "deliberately does not ship."
        )
        return 1

    print(f"OK    `{args.tag}` is an annotated tag object carrying a signature.")
    print(
        "      Signature NOT verified here (no trust store); GitHub's "
        "verified/unverified\n      badge is the account-level check."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
