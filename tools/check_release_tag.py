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
3. **The tag object carries a complete signature block** — OpenPGP, SSH, or
   the ``SIGNED MESSAGE`` form ``gpg.format=x509``/gpgsm emits. A matched
   BEGIN/END pair on whole lines, in order; a marker quoted inside the tag
   *message* is prose and does not count. See ``is_signed`` for why that
   distinction is the difference between a gate and a substring search.
4. **The tag's commit is reachable from a trusted branch** — with
   ``--trust-config``; see the next section. The commit the tag object
   points at (``refs/tags/<tag>^{commit}``) must be an ancestor of a branch
   the configuration names, decided by ``git merge-base --is-ancestor``. A
   configuration file that is missing, unparseable or empty is a failure,
   never a pass.

**Not** checked, and stated plainly rather than implied (INVARIANT-37): this
tool does **not** verify the signature. What is checked here is *shape*: the
properties that were wrong on all eleven historical tags, that need no key
material to establish, and whose absence means no later verification can ever
succeed. Keeping verification out of this tool is what lets it run first, in
preflight, before anything is built — with no key material, no ``ssh-keygen``
and no network.

Verification is a separate check with a separate input, and it is not missing.
The trust store — the list binding a public key to a name, without which a
valid signature is unattributable — ships at ``.github/allowed_signers``.
``tests/test_release_tag_trust_store.py`` checks on every CI run that the key in
it is the key that signed v4.0.0, and ``README.md`` documents the
``git verify-tag`` invocation a consumer runs offline.

Earlier releases of this docstring said the repository shipped no trust store
"because publishing one would assert a key binding that only the account owner
can establish". The owner had already established it before that sentence was
written; INVARIANT-10's addendum records the correction and why the mistake is
worth keeping on the page.

GitHub's own verified/unverified badge is the complementary half. It is
account-level state, not repository state — it turns on when the signing key
is registered under Settings -> SSH and GPG keys with type **Signing Key** —
so it is reported by ``release.yml`` for the operator to read, not gated here.

Release provenance, and where "trusted" is defined
--------------------------------------------------
Checks 1-3 are about the tag *object*. They say nothing about the *commit* it
names: the maintainer's signing key signs a tag on any commit, including one
on a branch that never went through the review branch protection enforces on
``main`` (INVARIANT-10 is about protected branches for exactly that reason).
Check 4 closes the gap by requiring the commit to be an ancestor of a trusted
branch, so a signed, annotated tag on a side branch is refused in preflight
instead of becoming a signed, attested release of unreviewed code.

The list of trusted branches is deliberately **not** read from the checkout
this tool runs in. A tag is pushed together with a tree the tagger controls,
so a configuration file inside that tree would let the tagger define what
"trusted" means: a side branch could carry a ``release-trust.json`` naming
itself. ``release.yml`` therefore fetches ``refs/heads/main`` from origin and
reads ``.github/release-trust.json`` out of ``origin/main`` with ``git show``
— never from the working tree — and hands the result to ``--trust-config``.
That binds the definition of "trusted" to the branch protection on ``main``:
changing it takes a reviewed merge, not a tag push.

The branch is resolved by full ref name — ``refs/remotes/origin/<branch>``
for the default ``--branch-prefix origin/``, ``refs/heads/<branch>`` for an
empty prefix — so a tag that happens to be called ``origin/main`` cannot
shadow the remote-tracking ref under git's short-name lookup order.

What this does **not** defend against, stated plainly (INVARIANT-37): the
workflow file itself comes from the tag. Whoever can push a ``v*`` tag can
push one whose ``release.yml`` skips this step, reads a different file, or
resolves a different branch. The controls that make this gate binding are
administrative, not in this tree: the repository's tag ruleset (who may create
``v*`` tags, and that they be signed) and the deployment policy of the
environment holding the signing seed, which admits ``v*`` tags only. This gate
turns an honest mistake — tagging the wrong commit, tagging from a feature
branch — into a red preflight instead of a published release; it does not
constrain an adversary who already holds tag-push rights.

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
    python tools/check_release_tag.py v4.0.0 --trust-config release-trust.json
    python tools/check_release_tag.py v4.0.0 --trust-config t.json --branch-prefix ""

Exits 0 when the tag is an annotated tag object carrying a signature block
and, with ``--trust-config``, its commit is reachable from a trusted branch;
1 otherwise. Without ``--trust-config`` the verdict says provenance was not
checked.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

#: One-line summary, rendered by ``--help``.
#:
#: Spelled out rather than sliced out of ``__doc__``.  This used to read
#: ``description=__doc__.split("\n")[3]``, and index 3 of this module's
#: docstring is the blank line under the title underline — so ``--help``
#: printed a usage block, the two option rows, and no description of what the
#: tool does or when it fails.  Any edit to the header (a longer title, a
#: reflowed first paragraph) silently changed which line was picked, which is
#: what makes the slice the wrong construction rather than merely
#: off-by-three.  ``test_release_tag_gate.py`` asserts this string reaches the
#: rendered output.
DESCRIPTION = (
    "Refuse to release from a tag that is not an annotated, signed tag object, "
    "or whose commit is not reachable from a trusted branch (INVARIANT-10)."
)

#: Rendered under the options by ``--help``.  The verdicts and the CI trap are
#: what a reader hitting a red gate needs, and they are not discoverable from
#: the option list.
EPILOG = """\
checked, fail-closed:
  1. the ref resolves under refs/tags/ (a same-named branch does not count)
  2. it names a tag object, not a commit (the lightweight case)
  3. that object carries a complete OpenPGP, SSH or SIGNED MESSAGE block
  4. with --trust-config FILE: the tag's commit is an ancestor of a branch the
     file's "release_branches" list names (git merge-base --is-ancestor against
     refs/remotes/<--branch-prefix><branch>, i.e. origin/<branch> by default;
     an empty prefix resolves refs/heads/<branch>).  A missing, invalid or
     empty FILE fails.  release.yml reads FILE out of origin/main with
     `git show`, never from the tag's own tree, so the tagger cannot define
     what "trusted" means.

NOT checked: the signature is not verified here -- this gate needs no key
material by design, so it can run before anything is built (INVARIANT-37).
The trust store is .github/allowed_signers; tests/test_release_tag_trust_store.py
checks it, and README documents the git verify-tag command consumers run.
GitHub's verified/unverified badge is the complementary account-level check.
NOT checked without --trust-config: provenance (4); the verdict says so.

in CI: fetch the tag ref first --
  git fetch --force origin refs/tags/<tag>:refs/tags/<tag>
actions/checkout writes a lightweight local ref at the tag's name, which
reads as failure (2) on a correctly annotated tag.  For check 4 the branch
must be present too --
  git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main

exit status: 0 pass, 1 the tag is not releasable.
"""

#: The armour delimiters of each signature format git emits, as
#: ``(begin, end)`` pairs. git writes the OpenPGP form for
#: ``gpg.format=openpgp`` (the default), the SSH form for ``gpg.format=ssh``,
#: and the ``SIGNED MESSAGE`` form for ``gpg.format=x509``. All three are
#: accepted; which one a maintainer uses is their choice, and refusing two of
#: the three would push them toward the unsigned path this gate exists to
#: close.
SIGNATURE_DELIMITERS = (
    ("-----BEGIN PGP SIGNATURE-----", "-----END PGP SIGNATURE-----"),
    ("-----BEGIN SSH SIGNATURE-----", "-----END SSH SIGNATURE-----"),
    ("-----BEGIN SIGNED MESSAGE-----", "-----END SIGNED MESSAGE-----"),
)

#: Begin markers alone, kept for callers that only need to name the formats.
SIGNATURE_HEADERS = tuple(begin for begin, _ in SIGNATURE_DELIMITERS)

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
    """True when the tag object body contains a complete signature block.

    A **matched pair** on **whole lines**, in order, is required — not a
    substring hit on the BEGIN marker.

    Raised in review, and the reviewer was right. A tag message is free text;
    an annotated tag whose message quotes ``-----BEGIN PGP SIGNATURE-----``
    (a changelog entry about signing, a paste of a failure message, this
    module's own docstring in a tag body) would have satisfied a bare
    substring test while carrying no signature at all. That is a fail-open in
    a gate whose entire job is to fail closed, and the fact that it takes an
    unusual message to trigger is not a defence: the eleven tags this gate was
    written for are proof that unusual is what actually ships.

    Whole-line matching matters as much as the pairing. Armour delimiters
    occupy a line of their own in every format git emits, so a marker quoted
    inline — ``see the -----BEGIN SSH SIGNATURE----- block`` — is prose, and
    only a marker alone on its line is structure. Requiring both, and
    requiring END to follow BEGIN, means the message would have to reproduce
    a whole armour envelope line for line to pass. At that point it is
    indistinguishable from a signature by inspection, which is the honest
    limit of a shape check and is exactly what this module's header says it
    is.
    """
    lines = body.splitlines()
    for begin, end in SIGNATURE_DELIMITERS:
        if begin not in lines:
            continue
        if end in lines[lines.index(begin) + 1 :]:
            return True
    return False


def _rev_parse(revision: str, repo: Path) -> str | None:
    """The object id ``revision`` names, or None when it does not resolve.

    ``--verify --quiet`` makes an unresolvable name a nonzero exit with no
    output rather than the name echoed back, which is what a bare
    ``rev-parse`` does for text it cannot resolve.
    """
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", revision],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def tag_commit(tag: str, repo: Path) -> str | None:
    """The commit ``tag`` ultimately points at, or None if it does not peel to one.

    ``^{commit}`` peels an annotated tag — or a chain of them — down to the
    commit; ``refs/tags/`` is spelled out for the reason given on
    ``object_type``.
    """
    return _rev_parse(f"refs/tags/{tag}^{{commit}}", repo)


def branch_ref(branch: str, branch_prefix: str) -> str:
    """The full ref name a trusted branch is resolved by.

    Full, not short: ``git rev-parse origin/main`` consults ``refs/tags/`` before
    ``refs/remotes/``, so a tag pushed under the name ``origin/main`` would
    shadow the remote-tracking branch and decide what "trusted" resolves to.
    ``origin/`` (the default) means ``refs/remotes/origin/<branch>``, the ref
    ``release.yml`` fetches; the empty prefix means the local
    ``refs/heads/<branch>``; a prefix that already starts with ``refs/`` is
    used verbatim.
    """
    if branch_prefix.startswith("refs/"):
        return f"{branch_prefix}{branch}"
    if not branch_prefix:
        return f"refs/heads/{branch}"
    return f"refs/remotes/{branch_prefix}{branch}"


def is_ancestor(commit: str, tip: str, repo: Path) -> bool:
    """True iff ``commit`` is an ancestor of (or equal to) ``tip``.

    ``git merge-base --is-ancestor`` exits 0 for yes, 1 for no and 128 when it
    cannot answer; anything but 0 is read as "no", so an error is a refusal.
    """
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, tip],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0


def load_release_branches(config: Path) -> tuple[list[str], list[str]]:
    """``(branches, problems)`` from a trust configuration file.

    A file that cannot be read, is not JSON, or does not carry a non-empty
    ``"release_branches"`` list of names is a problem, never an empty list
    that a caller could mistake for "nothing to check".
    """
    try:
        text = config.read_text(encoding="utf-8")
    except OSError as exc:
        return [], [
            f"trust config `{config}` cannot be read ({exc.strerror or exc}); the "
            "provenance check cannot run, and a check that cannot run is a failure, "
            "not a pass. release.yml writes it with "
            "`git show origin/main:.github/release-trust.json`."
        ]
    try:
        document = json.loads(text)
    except ValueError as exc:
        return [], [f"trust config `{config}` is not valid JSON: {exc}"]
    branches = document.get("release_branches") if isinstance(document, dict) else None
    if (
        not isinstance(branches, list)
        or not branches
        or not all(isinstance(branch, str) and branch.strip() for branch in branches)
    ):
        return [], [
            f'trust config `{config}` must carry a non-empty "release_branches" list of '
            "branch names; an empty or missing list would trust nothing and release "
            "nothing, which is the intended reading."
        ]
    return [branch.strip() for branch in branches], []


def check_provenance(tag: str, repo: Path, trust_config: Path, branch_prefix: str) -> list[str]:
    """Problems with where ``tag`` points; empty means it descends from a trusted branch."""
    branches, problems = load_release_branches(trust_config)
    if problems:
        return problems
    commit = tag_commit(tag, repo)
    if commit is None:
        return [f"tag `{tag}` does not peel to a commit in {repo}"]
    refs = [branch_ref(branch, branch_prefix) for branch in branches]
    tips = {ref: _rev_parse(f"{ref}^{{commit}}", repo) for ref in refs}
    unresolved = [ref for ref, tip in tips.items() if tip is None]
    if unresolved:
        return [
            f"trusted branch `{ref}` does not resolve in {repo}; fetch it first "
            "(release.yml runs `git fetch --no-tags origin "
            "+refs/heads/main:refs/remotes/origin/main`) or fix the branch name in "
            "the trust config. Unresolvable is not the same as trusted."
            for ref in unresolved
        ]
    for ref, tip in tips.items():
        if tip is not None and is_ancestor(commit, tip, repo):
            return []
    return [
        f"tag `{tag}` (commit {commit[:12]}) is not reachable from any trusted branch "
        f"({', '.join(refs)}). A release is cut from a commit that is on the trusted "
        "branch; a tag on a side branch names code that never went through the "
        "branch protection on it. Merge first, then tag the merged commit."
    ]


def check(
    tag: str,
    repo: Path,
    trust_config: Path | None = None,
    branch_prefix: str = "origin/",
) -> list[str]:
    """Return the list of problems with ``tag``; empty means it passes.

    Shape first; provenance only when ``trust_config`` is given, and only for
    a tag whose shape passed — a lightweight tag has no object to attribute,
    so reporting its provenance would be noise beside the real defect.
    """
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
    if trust_config is None:
        return []
    return check_provenance(tag, repo, trust_config, branch_prefix)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("tag", help="tag name, e.g. v4.0.0")
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path("."),
        help="repository checkout to inspect (default: cwd)",
    )
    parser.add_argument(
        "--trust-config",
        type=Path,
        default=None,
        help=(
            'JSON file with a "release_branches" list; enables check 4. '
            "release.yml passes a copy read from origin/main."
        ),
    )
    parser.add_argument(
        "--branch-prefix",
        default="origin/",
        help=(
            "where trusted branches live: 'origin/' (default) resolves "
            "refs/remotes/origin/<branch>, '' resolves refs/heads/<branch>"
        ),
    )
    args = parser.parse_args(argv)

    problems = check(args.tag, args.repo, args.trust_config, args.branch_prefix)
    if problems:
        print(f"FAIL: release tag `{args.tag}` is not releasable:")
        for problem in problems:
            print(f"  - {problem}")
        print(
            "\nThis gate checks the tag's SHAPE and, with --trust-config, its "
            "PROVENANCE. It does not verify the signature —\nfor that, run:\n  git -c "
            "gpg.ssh.allowedSignersFile=.github/allowed_signers verify-tag "
            f"{args.tag}"
        )
        return 1

    print(f"OK    `{args.tag}` is an annotated tag object carrying a signature.")
    if args.trust_config is None:
        print(
            "      Provenance NOT checked (no --trust-config): whether the commit is "
            "reachable from a trusted branch is undecided here."
        )
    else:
        print(
            f"      Its commit is reachable from a trusted branch named in "
            f"{args.trust_config} (release provenance)."
        )
    print(
        "      Signature NOT verified here (shape gate). To verify it:\n"
        "        git -c gpg.ssh.allowedSignersFile=.github/allowed_signers "
        f"verify-tag {args.tag}\n"
        "      GitHub's verified/unverified badge is the account-level check."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
