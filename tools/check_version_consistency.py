#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Verify that the AMA Cryptography version string matches in every file that
declares it.  Run as part of CI to block releases where one version was
bumped without the others (audit 5a).

The canonical source is ``ama_cryptography/__init__.py``'s ``__version__``.
Every other occurrence must match literally (no range operators, etc.).

Also verifies that ``.github/INVARIANTS.md`` stays a short pointer to the
canonical root ``INVARIANTS.md``.  The root copy is the only canonical
document; CI fails if the pointer grows into a divergent duplicate.

Additionally enforces that no C source file under ``src/c/**/*.{c,h}``
embeds a hardcoded ``"X.Y.Z"`` version-string literal near a
``VERSION`` / ``version`` / ``Version`` identifier. The canonical
location for the C-side version is ``include/ama_cryptography.h``'s
``AMA_CRYPTOGRAPHY_VERSION_STRING`` macro (which the canonical-anchor
checks above already pin to the package version). The
``src/c/`` tree should *use* that macro, never re-declare a literal —
today the scan returns zero hits and that is the steady state. The
test (``tests/test_version_consistency.py``) writes a
synthetic C file with a fake version literal into a temp tree and
asserts the scanner flags it.

Exit code:
    0  all versions and invariants agree, no embedded C-source version literals
    1  a mismatch or stray C-source version literal was detected
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


_C_VERSION_LITERAL_RE = re.compile(r'"\d+\.\d+\.\d+"')
_C_VERSION_IDENT_RE = re.compile(
    # Two alternatives:
    #   1. `\b[A-Za-z_][A-Za-z0-9_]*[Vv][Ee][Rr][Ss][Ii][Oo][Nn]\w*\b`
    #      — matches identifiers with at least one prefix character
    #      before the `[Vv]ersion` substring (e.g., `MY_VERSION`,
    #      `LIB_Version`, `pkg_version_tag`).
    #   2. `\b[Vv][Ee][Rr][Ss][Ii][Oo][Nn]\b`
    #      — matches the bare identifiers `Version`, `version`, and
    #      (case-folded) `VERSION` standing alone, with no surrounding
    #      identifier characters. Without this branch the scanner
    #      escaped `#define VERSION "1.2.3"` and similar standalone
    #      uppercase / title-case identifiers (Devin Review
    #      2026-04-27).
    r"\b[A-Za-z_][A-Za-z0-9_]*[Vv][Ee][Rr][Ss][Ii][Oo][Nn]\w*\b"
    r"|\b[Vv][Ee][Rr][Ss][Ii][Oo][Nn]\b"
)


# Document-header shapes that declare the package version.  Group 1 is the
# version; group 2 is whatever trailed it on the same line, which is a
# finding in its own right — see the commentary at the use site in main().
# Module-level so tests/test_version_consistency.py can exercise them
# directly rather than only through a whole-tree run.
DOC_HEADER_PATTERNS = [
    re.compile(r"^\|\s*(?:Document )?Version\s*\|\s*(\d+\.\d+\.\d+)([^|]*)\|$", re.M),
    re.compile(r"^\*\*(?:Document )?Version:\*\*\s*(\d+\.\d+\.\d+)(.*)$", re.M),
    re.compile(r"^\*\*Project Release:\*\*\s*(\d+\.\d+\.\d+)(.*)$", re.M),
]

# Second, in-file version declarations that live ALONGSIDE the authoritative
# ``__version__`` / ``AMA_CRYPTOGRAPHY_VERSION_STRING`` in the very same file
# and must agree with it.  These were the blind spot: the package's own module
# docstring carried ``Version: 3.1.0`` while ``__version__`` was ``3.4.0`` a
# few lines below, and the public header's Doxygen ``@version`` tag sat on
# ``3.1.0`` while its macro was ``3.4.0`` — each canonical file contradicting
# itself while this script reported agreement, because it only ever read the
# one authoritative declaration per file.  Module-level (like
# ``DOC_HEADER_PATTERNS``) so tests can exercise the extraction directly.
PACKAGE_DOCSTRING_VERSION_RE = r"^Version:\s*(\d+\.\d+\.\d+)"
HEADER_DOXYGEN_VERSION_RE = r"^\s*\*\s*@version\s+(\d+\.\d+\.\d+)"


def scan_c_sources_for_version_literals(root: Path) -> list[str]:
    """Scan every ``*.c`` / ``*.h`` under ``root`` for hardcoded
    ``"X.Y.Z"`` literals that sit near a ``VERSION`` / ``version``
    identifier on the same line or the previous line.

    Returns a list of ``"<relpath>:<lineno>: <line>"`` hits — one entry
    per offending line. The canonical location for the C-side version
    is ``include/ama_cryptography.h``'s ``AMA_CRYPTOGRAPHY_VERSION_STRING``
    macro (already pinned by the canonical-anchor checks above), so
    ``src/c/`` files must reference that macro rather than re-declaring
    a literal.

    Lines inside C `// ...` line comments and `/* ... */` block comments
    are ignored — historical or annotation-only mentions of a version
    in a comment are not a code-shipped literal. (We're permissive here
    because the goal is to flag *executable* embedded version literals,
    not documentation.) The detection is intentionally line-oriented
    rather than full preprocessor-aware: it errs on the side of false
    positives, which is the right tradeoff for a CI safety net.
    """
    hits: list[str] = []
    if not root.exists():
        return hits

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix not in (".c", ".h"):
            continue

        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        # Strip /* ... */ block comments — but preserve the line count
        # by replacing each comment with the same number of newlines it
        # spanned. This keeps stripped_lines[i] in 1:1 correspondence
        # with original_lines[i], so reported line numbers and the
        # ident-window check on the previous line remain accurate even
        # when files contain multi-line block comments. (Devin Review
        # 2026-04-26: the previous re.sub(..., "", DOTALL) collapsed
        # multi-line comments to nothing, shifting subsequent lines up
        # and making stripped_lines[i] reference a different physical
        # line than original_lines[i].)
        stripped = re.sub(
            r"/\*.*?\*/",
            lambda m: "\n" * m.group(0).count("\n"),
            text,
            flags=re.DOTALL,
        )
        stripped_lines = stripped.splitlines()
        original_lines = text.splitlines()

        for i, line in enumerate(stripped_lines):
            # Drop // line comments before searching.
            code = re.sub(r"//.*$", "", line)
            if not _C_VERSION_LITERAL_RE.search(code):
                continue
            ident_window = code
            if i > 0:
                ident_window += " " + re.sub(r"//.*$", "", stripped_lines[i - 1])
            if not _C_VERSION_IDENT_RE.search(ident_window):
                continue
            # Report repo-relative paths so a CI failure reads
            # `src/c/foo.c:42:` (greppable from the repo root) rather
            # than `c/foo.c:42:` (which depends on the caller's
            # `root` argument and is ambiguous across runs).
            # Falls through to `relative_to(root.parent)` for callers
            # passing a `root` outside the repo (e.g. tmp paths from
            # the unit tests). (Copilot Review 2026-04-27.)
            if REPO in path.parents or path == REPO:
                rel = path.relative_to(REPO)
            elif root.parent in path.parents or path == root.parent:
                rel = path.relative_to(root.parent)
            else:
                rel = path
            hits.append(f"{rel}:{i + 1}: {original_lines[i].strip()}")

    return hits


def extract(file: str, pattern: str) -> str | None:
    """Return the single capture group from `pattern`, or None if not found.

    The regex is evaluated in ``re.MULTILINE`` mode so ``^`` / ``$`` match
    individual line boundaries.  Every pattern below anchors the
    declaration to the start of its own line — either directly with
    ``^<literal>`` (setup.py ``VERSION``, pyproject ``version``, docs
    ``version`` / ``release``, package ``__version__``,
    ``#define AMA_CRYPTOGRAPHY_VERSION_STRING``) or via a stanza opener
    (``^project`` in ``CMakeLists.txt``, whose lazy ``[^)]*?`` then spans
    newlines to reach ``VERSION`` inside the call without crossing ``)``).
    This avoids matching substrings of unrelated version references such
    as a changelog note that mentions ``version =`` in prose.
    """
    text = _read(REPO / file)
    match = re.search(pattern, text, re.MULTILINE)
    return match.group(1) if match else None


def main() -> int:
    canonical = extract("ama_cryptography/__init__.py", r'^__version__\s*=\s*"([^"]+)"')
    if canonical is None:
        print(
            "ERROR: could not locate __version__ in ama_cryptography/__init__.py", file=sys.stderr
        )
        return 1

    # (file, regex-with-one-capture-group, description)
    checks = [
        (
            # The package's own module docstring carries a `Version:` field in
            # its Organization/Author/Version block, a SECOND declaration from
            # the authoritative `__version__` a few lines below.  Nothing
            # compared them, so the docstring sat on 3.1.0 while `__version__`
            # was 3.4.0 — the canonical package file contradicting itself while
            # this script reported "All declarations agree".
            "ama_cryptography/__init__.py",
            PACKAGE_DOCSTRING_VERSION_RE,
            "ama_cryptography/__init__.py docstring Version field",
        ),
        (
            # The main public C header opens with a Doxygen file block whose
            # `@version` tag is a second version declaration from the
            # AMA_CRYPTOGRAPHY_VERSION_STRING macro checked below.  It sat on
            # 3.1.0 while the macro was 3.4.0 — the header disagreeing with
            # itself, invisible to a scan that only read the macro.
            "include/ama_cryptography.h",
            HEADER_DOXYGEN_VERSION_RE,
            "include/ama_cryptography.h @version tag",
        ),
        ("setup.py", r'^VERSION\s*=\s*"([^"]+)"', "setup.py VERSION literal"),
        ("pyproject.toml", r'^version\s*=\s*"([^"]+)"', "pyproject.toml [project].version"),
        (
            "CMakeLists.txt",
            # Anchored to the ``^project(...)`` stanza (start-of-line
            # ``project`` keyword) so an unrelated
            # ``cmake_minimum_required(VERSION X.Y.Z)`` (if ever written
            # in 3-part form) cannot match first. ``[^)]*?`` is lazy and
            # spans newlines, so the expression reaches into a multi-line
            # ``project(AmaCryptography\n    VERSION 3.0.0\n    ...)``
            # block without crossing the closing parenthesis.
            r"^project\s*\([^)]*?VERSION\s+(\d+\.\d+\.\d+)",
            "CMakeLists.txt project() VERSION",
        ),
        ("docs/conf.py", r'^version\s*=\s*"([^"]+)"', "docs/conf.py version"),
        ("docs/conf.py", r'^release\s*=\s*"([^"]+)"', "docs/conf.py release"),
        (
            "include/ama_cryptography.h",
            # Anchored to ``^#define AMA_CRYPTOGRAPHY_VERSION_STRING``
            # so a commented-out reference or a prose mention of the
            # macro name elsewhere in the header cannot match first.
            r'^\s*#\s*define\s+AMA_CRYPTOGRAPHY_VERSION_STRING\s+"([^"]+)"',
            "include/ama_cryptography.h AMA_CRYPTOGRAPHY_VERSION_STRING",
        ),
        (
            # CycloneDX SBOM for the native C library. Regenerated by
            # tools/generate_sbom.py from pyproject.toml, and enforced in CI by
            # `generate_sbom.py --check` (SBOM Generation job).
            #
            # Checked here TOO because this tool is what a maintainer runs
            # locally during a release bump: without it, the SBOM was the one
            # version-carrying artefact that could still be stale after this
            # script printed "All declarations agree", and the drift was only
            # discovered later in CI.  A completeness gate that is not itself
            # complete is worse than no gate, because it is believed.
            # (Observed on the 3.3.0 -> 3.4.0 bump.)
            "docs/compliance/sbom-c-library.json",
            r'"component"\s*:\s*\{[^}]*?"version"\s*:\s*"([^"]+)"',
            "docs/compliance/sbom-c-library.json metadata.component.version",
        ),
        (
            # OCI image label on the Python runtime image. Surfaced by
            # `docker inspect` and consumed by container registries for
            # release-tag matching, so it must track the canonical version.
            "docker/Dockerfile",
            r'^\s*LABEL\s+version\s*=\s*"([^"]+)"',
            "docker/Dockerfile LABEL version",
        ),
        (
            # OCI Image Spec annotation on the C-API image
            # (https://github.com/opencontainers/image-spec/blob/main/annotations.md).
            # Same release-tag alignment requirement as Dockerfile above.
            "docker/Dockerfile.c-api",
            r'^\s*LABEL\s+org\.opencontainers\.image\.version\s*=\s*"([^"]+)"',
            "docker/Dockerfile.c-api LABEL org.opencontainers.image.version",
        ),
        (
            # Release badge in the wiki footer, rendered on EVERY wiki page.
            # It is prose rather than a header field, so the *.md header
            # scan below cannot see it — and it sat on v3.0.0 across three
            # releases, making the most-viewed surface in the project the
            # most out of date. Named explicitly for that reason.
            "wiki/_Footer.md",
            r"Not externally audited\s*·\s*v(\d+\.\d+\.\d+)",
            "wiki/_Footer.md release badge",
        ),
    ]

    failures: list[str] = []
    for file, pattern, desc in checks:
        found = extract(file, pattern)
        if found is None:
            failures.append(f"  - {desc}: pattern not found in {file}")
        elif found != canonical:
            failures.append(f"  - {desc}: {found!r} != canonical {canonical!r} (in {file})")
        else:
            print(f"OK    {desc:<60s} = {found}")

    # -------------------------------------------------------------------
    # Documentation version headers.
    #
    # Every public document carries a "Document Version" / "Version" field in
    # its header block, and the project convention is that it tracks the
    # package version.  Nothing checked them, so on the 3.3.0 -> 3.4.0 bump
    # SEVENTEEN headers silently stayed on the old release while this script
    # reported "All declarations agree" — the same failure mode as the SBOM,
    # at seventeen times the blast radius.
    #
    # Discovered by scanning rather than declared by hand: any *.md carrying a
    # recognised header form is checked, so a NEW document is covered the day
    # it is added instead of the day someone remembers to list it here.
    # Historical rows (revision-history tables, CHANGELOG entries) are not
    # matched because they are not header fields — the patterns are anchored
    # to the document-header shapes only.
    #
    # The trailing group is captured rather than anchored away.  The
    # previous ``\s*$`` anchor meant a header carrying a *qualifier* —
    # ``**Version:** 3.1.0 + Unreleased``, which is what
    # docs/DESIGN_NOTES.md and docs/METRICS_REPORT.md both said — matched
    # no pattern at all and was therefore reported as neither stale nor
    # checked.  Two documents sat three releases behind while this script
    # printed "All declarations agree".  A qualifier is now a finding in
    # its own right: a version header states one version, not a version
    # and a mood.
    doc_header_pats = DOC_HEADER_PATTERNS
    doc_checked = 0
    doc_stale: list[str] = []
    for md in sorted(REPO.rglob("*.md")):
        if any(part in {".git", "build", "node_modules"} for part in md.parts):
            continue
        if md.name == "CHANGELOG.md":
            continue  # historical by definition
        if "compliance" in md.parts:
            # docs/compliance/** are DATED ATTESTATION RECORDS.  Their
            # "Version" field names the library version the attestation was
            # generated against — bound to an immutable upstream ACVP ref and
            # a generation date — NOT a document revision that tracks the
            # current release.  Auto-bumping them on a release would assert
            # validation that was never performed, which INVARIANT-16
            # (Honest Compliance and Audit Claims) prohibits.  Refreshing an
            # attestation is a deliberate act with its own procedure (see
            # acvp_attestation.json::acvp_ref_note).
            continue
        text = _read(md)
        if not text:
            continue
        for pat in doc_header_pats:
            for m in pat.finditer(text):
                doc_checked += 1
                rel = md.relative_to(REPO)
                if m.group(1) != canonical:
                    doc_stale.append(
                        f"{rel}: header version {m.group(1)!r} != canonical {canonical!r}"
                    )
                elif m.group(2).strip():
                    doc_stale.append(
                        f"{rel}: header version carries the trailing qualifier "
                        f"{m.group(2).strip()!r} — state one version, not a version and a mood"
                    )
    if doc_stale:
        failures.append(f"  - documentation version headers ({len(doc_stale)} stale):")
        for row in doc_stale:
            failures.append(f"      {row}")
    else:
        print(f"OK    documentation version headers ({doc_checked} checked)     = {canonical}")

    # Invariants pointer check (audit 6a).
    root_inv_path = REPO / "INVARIANTS.md"
    github_inv_path = REPO / ".github" / "INVARIANTS.md"
    if not root_inv_path.exists():
        failures.append("  - INVARIANTS.md missing: root canonical copy is required")
    expected_github_inv = "# AMA Cryptography invariants\n\nCanonical copy: ../INVARIANTS.md\n"
    github_inv = _read(github_inv_path)
    if github_inv != expected_github_inv:
        failures.append(
            "  - .github/INVARIANTS.md must remain the 3-line pointer to "
            "the canonical root INVARIANTS.md"
        )
    else:
        print("OK    .github/INVARIANTS.md -> ../INVARIANTS.md pointer")

    # C-source embedded-version-literal scan. The canonical anchor for
    # the C side is include/ama_cryptography.h's
    # AMA_CRYPTOGRAPHY_VERSION_STRING macro (verified above). Anything
    # under src/c/ that re-declares a "X.Y.Z" literal next to a
    # VERSION / version identifier is a future drift hazard — flag it.
    c_hits = scan_c_sources_for_version_literals(REPO / "src" / "c")
    if c_hits:
        failures.append(
            "  - src/c/ contains embedded version-string literals (use "
            "AMA_CRYPTOGRAPHY_VERSION_STRING from include/ama_cryptography.h):"
        )
        for hit in c_hits:
            failures.append(f"      {hit}")
    else:
        print("OK    src/c/ embedded-version-literal scan: 0 hits")

    if failures:
        print(
            f"\nFAIL: canonical version = {canonical!r}\n" f"Mismatches:\n" + "\n".join(failures),
            file=sys.stderr,
        )
        return 1

    print(f"\nAll declarations agree on version {canonical!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
