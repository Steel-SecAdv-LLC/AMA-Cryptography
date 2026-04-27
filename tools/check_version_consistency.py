#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Verify that the AMA Cryptography version string matches in every file that
declares it.  Run as part of CI to block releases where one version was
bumped without the others (audit 5a).

The canonical source is ``ama_cryptography/__init__.py``'s ``__version__``.
Every other occurrence must match literally (no range operators, etc.).

Also verifies that the root ``INVARIANTS.md`` stays byte-identical to
``.github/INVARIANTS.md`` — we inlined the content to remove the unhelpful
one-line pointer (audit 6a), so CI must catch any future drift.

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

    # Invariants sync check (audit 6a).
    root_inv = _read(REPO / "INVARIANTS.md")
    github_inv = _read(REPO / ".github" / "INVARIANTS.md")
    if root_inv != github_inv:
        failures.append(
            "  - INVARIANTS.md mismatch: root copy diverges from "
            ".github/INVARIANTS.md (see audit 6a)"
        )
    else:
        print("OK    INVARIANTS.md root <-> .github/INVARIANTS.md: identical")

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
