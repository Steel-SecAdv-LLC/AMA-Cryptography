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

import ast
import re
import sys
from pathlib import Path, PurePath

REPO = Path(__file__).resolve().parent.parent


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def repo_relative(path: PurePath, repo: PurePath) -> str:
    """``path`` relative to ``repo``, in POSIX form on every platform.

    ``str(Path.relative_to(...))`` yields ``ama_cryptography\\ascon.py`` on
    Windows and ``ama_cryptography/ascon.py`` everywhere else.  That difference
    is not cosmetic here: the string is used as half of the lookup key into
    :data:`C_CONSTANT_ALIASES`, whose keys are written with forward slashes, so
    on Windows every alias lookup missed and the aliased constants went
    unchecked while the gate still reported success.  It is also what a reviewer
    greps out of a CI log, and a path that changes shape with the runner is a
    path you cannot grep for.  Normalise once, here.
    """
    return path.relative_to(repo).as_posix()


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
            # `repo_relative` also normalises the separator, so the reported
            # path reads the same on a Windows runner as on a Linux one.
            if REPO in path.parents or path == REPO:
                rel = repo_relative(path, REPO)
            elif root.parent in path.parents or path == root.parent:
                rel = repo_relative(path, root.parent)
            else:
                rel = path.as_posix()
            hits.append(f"{rel}:{i + 1}: {original_lines[i].strip()}")

    return hits


_PY_DUNDER_RE = re.compile(r'^__version__\s*=\s*["\'](\d+\.\d+\.\d+)["\']', re.M)
_PY_DOCSTRING_RE = re.compile(r"^Version:\s*(\d+\.\d+\.\d+)\s*$", re.M)
_C_ATVERSION_RE = re.compile(r"@version\s+(\d+\.\d+\.\d+)")


def scan_declared_versions(repo: Path) -> list[tuple[str, int, str, str]]:
    """Find EVERY version declaration across the shipped Python and C trees.

    Covers ``__version__ = "X"`` and module-docstring ``Version: X`` under
    ``ama_cryptography/`` and ``tools/``, plus Doxygen ``@version X`` under
    ``src/c/`` and ``include/``.  Each must equal the canonical package
    version.  This is what stops a *per-module* stamp from silently drifting:
    thirteen files sat on ``3.0.0`` across four releases — a stamp the earlier,
    file-by-file checks never looked at — while this script reported "All
    declarations agree".  Returns ``(relpath, lineno, label, value)`` tuples;
    ``main()`` flags any whose value is not canonical.

    Vendored third-party trees are skipped: their version tags describe the
    upstream project, not this library (the same exemption
    ``tools/check_headers.py`` applies).
    """
    found: list[tuple[str, int, str, str]] = []

    def _skip(path: Path) -> bool:
        return any(p in {"__pycache__", "build", "vendor"} for p in path.parts)

    for root in (repo / "ama_cryptography", repo / "tools"):
        for path in sorted(root.rglob("*.py")):
            if _skip(path):
                continue
            text = path.read_text(encoding="utf-8")
            rel = repo_relative(path, repo)
            for pat, label in ((_PY_DUNDER_RE, "__version__"), (_PY_DOCSTRING_RE, "Version:")):
                for m in pat.finditer(text):
                    found.append((rel, text[: m.start()].count("\n") + 1, label, m.group(1)))

    for root in (repo / "src" / "c", repo / "include"):
        for path in sorted(root.rglob("*")):
            if path.suffix not in (".c", ".h") or not path.is_file() or _skip(path):
                continue
            text = path.read_text(encoding="utf-8")
            rel = repo_relative(path, repo)
            for m in _C_ATVERSION_RE.finditer(text):
                found.append((rel, text[: m.start()].count("\n") + 1, "@version", m.group(1)))

    return found


# ---------------------------------------------------------------------------
# C constant transcriptions
# ---------------------------------------------------------------------------
# The Python layer mirrors integer constants that are *defined* in
# include/ama_cryptography.h: error codes, key and tag sizes, algorithm and
# policy selectors. Each one is a second declaration of a value the C header
# owns, which is the same duplication this script exists to police — a version
# string is simply the one everybody notices when it drifts.
#
# Nothing checked these. `AMA_ERROR_INVALID_PARAM = -1` was transcribed into
# `pqc_backends.py` with no gate at all, and the same value appears again in
# `agent_binding.py`. Drift here is worse than a stale version badge: a Python
# module comparing a return code against the wrong number silently stops
# detecting the failure it was written to detect, and every test that exercises
# only the success path still passes.
#
# Matching is mechanical rather than curated so a *new* mirror is covered the
# day it is written: a module-level or class-level `NAME = <int>` in
# ama_cryptography/ is checked whenever `NAME` (leading underscores stripped),
# or `AMA_` + that name, is a constant the header defines. Names that do not
# correspond to anything in the header are ignored — a Python-only constant is
# not a transcription — except where C_CONSTANT_ALIASES says otherwise.

# Deliberate name changes across the boundary. The header spells Ascon's sizes
# `..._LEN` and prefixes them with the subsystem; the Python module drops the
# prefix and says `..._BYTES`, matching its sibling modules. Mechanically
# unrelatable, genuinely the same constant, and therefore worth pinning by hand
# rather than leaving unchecked.
C_CONSTANT_ALIASES = {
    ("ama_cryptography/ascon.py", "AEAD128_KEY_BYTES"): "AMA_ASCON_AEAD128_KEY_LEN",
    ("ama_cryptography/ascon.py", "AEAD128_NONCE_BYTES"): "AMA_ASCON_AEAD128_NONCE_LEN",
    ("ama_cryptography/ascon.py", "AEAD128_TAG_BYTES"): "AMA_ASCON_AEAD128_TAG_LEN",
    ("ama_cryptography/ascon.py", "HASH256_DIGEST_BYTES"): "AMA_ASCON_HASH256_DIGEST_LEN",
    (
        "ama_cryptography/agent_binding.py",
        "SIGNATURE_CONTEXT_BYTES",
    ): "AMA_AGENT_BINDING_CONTEXT_BYTES",
}

#: Non-vacuity floor for the transcription scan. 53 mirrors resolve today; the
#: floor sits below that so ordinary churn does not trip it, while a rename that
#: disconnects the name-matching rule does. See the use site in ``main()``.
_MIN_C_CONSTANT_TRANSCRIPTIONS = 40

_C_DEFINE_RE = re.compile(
    r"^\s*#\s*define\s+(AMA_[A-Za-z0-9_]+)\s+(0[xX][0-9a-fA-F]+|-?\d+)[uUlL]*\s*$", re.M
)
_C_ENUM_RE = re.compile(r"^\s*(AMA_[A-Za-z0-9_]+)\s*=\s*(0[xX][0-9a-fA-F]+|-?\d+)\s*[,}]", re.M)


def parse_c_constants(header: Path) -> dict[str, int]:
    """Every integer constant the public header defines, by name.

    Covers object-like ``#define``s and enumerator initialisers. Comments are
    stripped first so a value mentioned in prose cannot be mistaken for a
    definition; implicitly-numbered enumerators (``A, B, C``) are skipped
    deliberately, because their values depend on position and a transcription
    that got one wrong is a different bug from a transcription that drifted.
    """
    text = header.read_text(encoding="utf-8")
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.DOTALL)
    text = re.sub(r"//.*", "", text)
    found: dict[str, int] = {}
    for pattern in (_C_DEFINE_RE, _C_ENUM_RE):
        for match in pattern.finditer(text):
            found[match.group(1)] = int(match.group(2), 0)
    return found


def _int_literal(node: ast.expr) -> int | None:
    """The value of an integer literal, or None if this is not one.

    ``True``/``False`` are `int` subclasses in Python and are excluded: a flag
    is not a transcription of a C constant.
    """
    if (
        isinstance(node, ast.Constant)
        and isinstance(node.value, int)
        and not isinstance(node.value, bool)
    ):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        inner = _int_literal(node.operand)
        return None if inner is None else -inner
    return None


def _python_int_constants(path: Path) -> list[tuple[int, str, int]]:
    """``(lineno, name, value)`` for every module- or class-level int constant."""
    out: list[tuple[int, str, int]] = []

    def walk(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if (
                isinstance(child, ast.Assign)
                and len(child.targets) == 1
                and isinstance(child.targets[0], ast.Name)
            ):
                value = _int_literal(child.value)
                if value is not None:
                    out.append((child.lineno, child.targets[0].id, value))
            if isinstance(child, ast.ClassDef):
                walk(child)

    walk(ast.parse(path.read_text(encoding="utf-8")))
    return out


def scan_c_constant_transcriptions(repo: Path, header: Path | None = None) -> tuple[list[str], int]:
    """Check every Python mirror of a C header constant.

    Returns ``(problems, checked)`` — the second value is what makes this gate
    self-auditing: if a refactor renames the constants so that nothing matches
    any more, ``checked`` collapses to zero and ``main()`` reports that as a
    failure rather than printing a reassuring "0 mismatches".
    """
    header = header or (repo / "include" / "ama_cryptography.h")
    if not header.is_file():
        return ([f"  - {header} is missing; cannot check C constant transcriptions"], 0)
    c_constants = parse_c_constants(header)
    if not c_constants:
        return ([f"  - no integer constants parsed out of {header.name}"], 0)

    problems: list[str] = []
    checked = 0
    package = repo / "ama_cryptography"
    for path in sorted(package.rglob("*.py")):
        if any(part in {"__pycache__", "build", "vendor"} for part in path.parts):
            continue
        rel = repo_relative(path, repo)
        for lineno, name, value in _python_int_constants(path):
            bare = name.lstrip("_")
            candidates = [
                C_CONSTANT_ALIASES.get((rel, name)),
                bare if bare in c_constants else None,
                f"AMA_{bare}" if f"AMA_{bare}" in c_constants else None,
            ]
            c_name = next((c for c in candidates if c), None)
            if c_name is None:
                continue
            if c_name not in c_constants:
                problems.append(
                    f"      {rel}:{lineno}: {name} is aliased to {c_name}, which the "
                    "header does not define"
                )
                continue
            checked += 1
            if value != c_constants[c_name]:
                problems.append(
                    f"      {rel}:{lineno}: {name} = {value} but "
                    f"{c_name} = {c_constants[c_name]} in {header.name}"
                )
    return problems, checked


# --------------------------------------------------------------------------
# Invariant-register range claims.
#
# `INVARIANTS.md` is the canonical register, and five documents state its
# extent as "INVARIANT-1 through INVARIANT-N".  N is a count in prose, so it
# goes stale the way every other written-down count does — and this one did:
# the branch that took the register from 38 to 42 corrected three of the four
# files that named the old range, and `.github/copilot-instructions.md` was
# still saying 42 after the register reached 43.
#
# A range anchored at INVARIANT-1 is a claim about the WHOLE register and is
# checked.  Any other range — `INVARIANT-39 through INVARIANT-42` in
# CHANGELOG.md, describing one release's scope — is a claim about a subset and
# is deliberately left alone; forcing it to the register's maximum would make
# release history wrong.
#
# The register itself is checked for contiguity, because "1 through N" is only
# a true description of a set that has no gaps in it.
# --------------------------------------------------------------------------

#: `## INVARIANT-<n>` headings in the canonical register.
_INVARIANT_HEADING_RE = re.compile(r"(?m)^## INVARIANT-(\d+)\b")

#: A prose range whose lower bound is the first invariant.  Both dash forms and
#: both English spellings are accepted; the bound is captured so the message
#: can name what was written.  Bounded quantifiers only — no nested repetition
#: — so this stays linear on adversarial input.
_INVARIANT_RANGE_RE = re.compile(r"INVARIANT-1\s*(?:through|to|[-\u2013\u2014])\s*INVARIANT-(\d+)")


def invariant_register_extent(path: Path) -> tuple[int, list[str]]:
    """``(highest invariant, problems)`` for the canonical register.

    Problems are gaps and duplicate headings: "INVARIANT-1 through
    INVARIANT-N" describes a contiguous set, so a register with a hole in it
    makes every document that states the range wrong in a way no count check
    would catch.
    """
    text = _read(path)
    numbers = [int(m.group(1)) for m in _INVARIANT_HEADING_RE.finditer(text)]
    if not numbers:
        return 0, [
            f"  - {path.name} has no `## INVARIANT-<n>` headings; the register "
            f"cannot be read, so no document's range claim can be checked"
        ]
    highest = max(numbers)
    problems: list[str] = []
    missing = sorted(set(range(1, highest + 1)) - set(numbers))
    if missing:
        problems.append(
            f"  - {path.name}: the register is not contiguous — no heading for "
            f"{', '.join(f'INVARIANT-{n}' for n in missing)}"
        )
    duplicates = sorted({n for n in numbers if numbers.count(n) > 1})
    if duplicates:
        problems.append(
            f"  - {path.name}: duplicate heading(s) for "
            f"{', '.join(f'INVARIANT-{n}' for n in duplicates)}"
        )
    return highest, problems


def scan_invariant_range_claims(repo: Path, highest: int) -> tuple[list[str], int]:
    """``(problems, claims checked)`` over every tracked Markdown file."""
    problems: list[str] = []
    checked = 0
    for path in sorted(repo.rglob("*.md")):
        if ".git" in path.parts or "node_modules" in path.parts:
            continue
        text = _read(path)
        if not text:
            continue
        for match in _INVARIANT_RANGE_RE.finditer(text):
            checked += 1
            claimed = int(match.group(1))
            if claimed == highest:
                continue
            line = text[: match.start()].count("\n") + 1
            # Collapse the matched text: a claim that wrapped across a line
            # would otherwise be reported with a literal newline in it.
            quoted = " ".join(match.group(0).split())
            problems.append(
                f"  - {repo_relative(path, repo)}:{line}: claims "
                f"{quoted!r}, but INVARIANTS.md defines "
                f"INVARIANT-1 through INVARIANT-{highest}. If this is prose "
                f"QUOTING a range that used to be wrong rather than stating "
                f"the current one, write it as 'ending at INVARIANT-N' — this "
                f"check reads prose and cannot tell a quotation from a claim, "
                f"and that is the direction it should fail in."
            )
    return problems, checked


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
            # The Alpine variant carries the same LABEL and the same
            # release-tag alignment requirement as docker/Dockerfile, but was
            # never registered here — so it sat at 3.5.0 through a 4.0.0
            # release while this gate reported every declaration in agreement.
            # A version anchor that is not in this list is a version anchor
            # that drifts.
            "docker/Dockerfile.alpine",
            r'^\s*LABEL\s+version\s*=\s*"([^"]+)"',
            "docker/Dockerfile.alpine LABEL version",
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
        (
            # Doxygen-branded C API documentation.  PROJECT_NUMBER is the
            # version printed on every generated API page, and it is neither
            # Markdown nor code, so no other scan in this script could see
            # it.  It sat on "2.0" across three major generations while this
            # script printed "All declarations agree" (found in the 3.5.0
            # release polish).
            "docs/Doxyfile",
            r"^PROJECT_NUMBER\s*=\s*(\d+\.\d+(?:\.\d+)?)",
            "docs/Doxyfile PROJECT_NUMBER",
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
    # Git-tag install pins in Sphinx sources.
    #
    # The *.md sweep below cannot see docs/**/*.rst, so the Sphinx landing
    # page shipped a `pip install ...@v3.4.0` command into the 3.5.0
    # release while this script printed "All declarations agree".  Any
    # `@vX.Y.Z` git-tag pin in an .rst under docs/ must name the canonical
    # version — same contract as the README install pins (INVARIANT-32).
    for rst in sorted((REPO / "docs").rglob("*.rst")):
        text = _read(rst)
        if not text:
            continue
        for m in re.finditer(r"@v(\d+\.\d+\.\d+)", text):
            desc = f"{repo_relative(rst, REPO)} git-tag pin"
            if m.group(1) != canonical:
                failures.append(f"  - {desc}: @v{m.group(1)} != canonical {canonical!r}")
            else:
                print(f"OK    {desc:<60s} = {m.group(1)}")

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

    # Every document that states the register's extent must state the real one.
    highest_invariant, register_problems = invariant_register_extent(root_inv_path)
    failures.extend(register_problems)
    if highest_invariant:
        range_problems, ranges_checked = scan_invariant_range_claims(REPO, highest_invariant)
        if range_problems:
            failures.append(
                f"  - invariant-range claims disagree with INVARIANTS.md "
                f"({len(range_problems)} stale):"
            )
            failures.extend(f"    {row}" for row in range_problems)
        else:
            print(
                f"OK    invariant-range claims ({ranges_checked} checked)"
                f"      = INVARIANT-1 through INVARIANT-{highest_invariant}"
            )

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

    # Every declared version stamp across the Python and C trees — the whole-
    # tree sweep that the file-by-file checks above cannot be, so a per-module
    # `__version__` / docstring `Version:` / Doxygen `@version` cannot drift
    # unnoticed the way thirteen of them did (all stuck on 3.0.0).
    stamps = scan_declared_versions(REPO)
    stamp_offenders = [
        f"{rel}:{ln}: {label} = {val!r} != canonical {canonical!r}"
        for rel, ln, label, val in stamps
        if val != canonical
    ]
    if stamp_offenders:
        failures.append(f"  - declared version stamps out of sync ({len(stamp_offenders)}):")
        for row in stamp_offenders:
            failures.append(f"      {row}")
    else:
        print(f"OK    declared version stamps ({len(stamps)} checked)          = {canonical}")

    # Python mirrors of C header constants — error codes, key sizes, selectors.
    # `AMA_ERROR_INVALID_PARAM = -1` was transcribed into the Python layer with
    # nothing checking it; a wrong error code makes a module stop detecting the
    # failure it exists to detect, while every success-path test still passes.
    const_problems, const_checked = scan_c_constant_transcriptions(REPO)
    if const_problems:
        failures.append(
            f"  - Python constants disagree with include/ama_cryptography.h "
            f"({len(const_problems)}):"
        )
        failures.extend(const_problems)
    elif const_checked < _MIN_C_CONSTANT_TRANSCRIPTIONS:
        # A gate that silently stops matching anything is worse than no gate,
        # because it keeps reporting success. 53 mirrors exist today; the floor
        # is set below that so ordinary churn does not trip it, but a rename
        # that disconnects the scan does.
        failures.append(
            f"  - only {const_checked} C constant transcription(s) were matched, below "
            f"the floor of {_MIN_C_CONSTANT_TRANSCRIPTIONS}. The name-matching rule has "
            "probably stopped resolving; a check that matches nothing passes vacuously."
        )
    else:
        print(f"OK    C constant transcriptions ({const_checked} checked)")

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
