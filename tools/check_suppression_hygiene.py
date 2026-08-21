#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""INVARIANT-13 enforcement: scan for unjustified static-analysis suppressions.

Exit codes:
    0  — all suppressions are justified
    1  — one or more violations found

Usage (CI):
    python tools/check_suppression_hygiene.py
"""

from __future__ import annotations

import io
import ast
import os
import re
import sys
import tokenize
from pathlib import Path

# Suppression tokens to scan for.
#
# ``nosemgrep`` is included here because INVARIANT-13 is worded "any
# equivalent suppression marker"; semgrep is part of the same defence-in-
# depth stack as bandit/ruff/mypy and the same tracking-ID + justification
# requirements apply.  Devin reviews #19/#20/#21/#22 (PR #277) caught four
# ``nosemgrep`` markers that lacked tracking IDs; extending the scanner is
# the regression check that would have caught those at PR-review time.
#
# Two-stage matching:
#   1. ``_SUPPRESSION_RE`` matches *any* suppression marker — including a
#      bare ``# nosemgrep`` with no rule id — so the line is always
#      flagged for the tracking-ID + justification pass.
#   2. For the ``nosemgrep`` family specifically, ``_NOSEMGREP_STRICT_RE``
#      then asserts the line-targeted form ``# nosemgrep: <rule_id>``
#      (Copilot review @ tools/check_suppression_hygiene.py:34).  Bare
#      ``# nosemgrep`` blanket-suppresses every rule on the line, which
#      is exactly the kind of catch-all the INVARIANT-13 audit trail is
#      meant to prevent.  Semgrep itself accepts both forms; this repo
#      requires the colon + rule id form so reviewers can verify *which*
#      rule each suppression silences.
_SUPPRESSION_RE = re.compile(r"#\s*(noqa|nosec|nosemgrep|pylint:\s*disable|type:\s*ignore)")
_NOSEMGREP_STRICT_RE = re.compile(r"^:\s*\S+")

# The same requirement, for the two other markers that blanket-suppress a whole
# scanner when written bare.  Adding them is not symmetry for its own sake:
#
# ``nosec``  bandit resolves ``# nosec <text>`` by parsing <text> as test ids
#            (``NOSEC_COMMENT`` / ``NOSEC_COMMENT_TESTS`` in bandit's manager),
#            warns "Test in comment: X is not a test name or id, ignoring" for
#            every word it cannot resolve, and — this is the part that matters —
#            treats an EMPTY resolved set as "no specific tests", i.e. blanket.
#            So this repository's house style, ``# nosec -- reason (TAG-NNN)``,
#            would read to a reviewer as a targeted suppression carrying its
#            justification while silencing every bandit test on the line.  A
#            ``B``-code makes the resolved set non-empty and the marker means
#            what it looks like.  Verified against bandit 1.9.2.
#
# ``noqa``   ruff (and flake8) treat a bare ``# noqa`` as "all rules on this
#            line"; only ``# noqa: <CODE>`` targets one.  Same catch-all, same
#            audit-trail problem.
#
# ``type: ignore`` and ``pylint: disable`` are deliberately NOT held to this,
# and the reason is stated rather than left as an omission: mypy's file-level
# ``# type: ignore`` on line 1 is a legitimate bare form that
# ``effective_suppressions`` keeps in scope on purpose, and mypy --strict's
# ``warn_unused_ignores`` already reports an ignore that suppresses nothing.
# Neither family has a bare occurrence in the tree today.
_NOSEC_STRICT_RE = re.compile(r"^:?\s*B\d+", re.IGNORECASE)
_NOQA_STRICT_RE = re.compile(r"^:\s*[A-Z]+\d+", re.IGNORECASE)

#: Marker -> (pattern its targeted form must match, the form to write instead).
_STRICT_FORMS: dict[str, tuple[re.Pattern[str], str]] = {
    "nosemgrep": (_NOSEMGREP_STRICT_RE, "# nosemgrep: <rule_id> -- justification (TAG-NNN)"),
    "nosec": (_NOSEC_STRICT_RE, "# nosec B105 -- justification (TAG-NNN)"),
    "noqa": (_NOQA_STRICT_RE, "# noqa: S310 -- justification (TAG-NNN)"),
}

# Tracking ID pattern: parenthesised alphanumeric tag, e.g. (KM-001), (FIN-002)
_TRACKING_ID_RE = re.compile(r"\([A-Z]+-\d+\)")

# Justification: an em-dash, double-hyphen, or inline comment (# ...) followed by text.
# The inline-comment form is required for ``type: ignore`` because mypy >=1.20
# rejects em-dashes inside the ``# type: ignore[code]`` directive.
_JUSTIFICATION_RE = re.compile(r"[\u2014\u2013]|--|#\s*\S")

# Forbidden directories: suppressions are absolutely prohibited here
_FORBIDDEN_DIRS: tuple[str, ...] = (
    "src/c/",
    "ama_cryptography/_primitive",
    "ama_cryptography/backend",
    "include/",
)


def _is_forbidden(filepath: str) -> bool:
    """Return True if the file lives under a forbidden directory."""
    for d in _FORBIDDEN_DIRS:
        if filepath.startswith(d) or f"/{d}" in filepath:
            return True
    return False


def effective_suppressions(source: str) -> list[tuple[int, str]]:
    """Return ``(lineno, comment_text)`` for comments that actually suppress.

    Two filters, both of which the previous line-oriented scan lacked.

    **Comment text, not the whole line.** The scan used to collect the line
    *numbers* carrying a comment and then run the marker regex over the entire
    raw line, which put every string literal on such a line back in scope — the
    exact thing tokenizing was supposed to rule out. The comment token's own
    text is used here instead.

    **Trailing comments only.** ``bandit``, ``ruff`` and ``mypy`` all anchor a
    suppression to the line of the finding, so a full-line comment suppresses
    nothing; it is prose. That distinction never mattered while the scan
    covered only ``ama_cryptography/`` and ``tests/``, where nothing discusses
    markers in a comment. It matters immediately in ``tools/``, where the
    checkers *document their own subject matter*: eight comments explaining
    what a ``# nosec`` is were reported as unjustified suppressions the moment
    that tree was included. A gate that fires on its own documentation is one
    people learn to route around.

    The single standalone form that is real — mypy's file-level
    ``# type: ignore``, which must be the first line — is kept in scope
    explicitly rather than lost to the rule.
    """
    results: list[tuple[int, str]] = []
    try:
        lines = source.splitlines()
        readline = io.StringIO(source).readline
        for tok in tokenize.generate_tokens(readline):
            if tok.type != tokenize.COMMENT:
                continue
            lineno, col = tok.start
            physical = lines[lineno - 1] if lineno - 1 < len(lines) else ""
            trailing = bool(physical[:col].strip())
            file_level_type_ignore = lineno == 1 and tok.string.strip().startswith("# type: ignore")
            if trailing or file_level_type_ignore:
                results.append((lineno, tok.string))
    except (tokenize.TokenError, SyntaxError, IndentationError):
        return results  # unparseable file: report what was seen before the error
    return results


def check_source(filepath: str, source: str) -> list[str]:
    """Return violation messages for already-loaded Python ``source``."""
    violations: list[str] = []
    for lineno, comment in effective_suppressions(source):
        for m in _SUPPRESSION_RE.finditer(comment):
            tag = f"{filepath}:{lineno}"
            if _is_forbidden(filepath):
                violations.append(f"{tag}: suppression in forbidden directory")
                break
            rest = comment[m.end() :]
            # Strict form: the marker must name the rule it silences, so a
            # reviewer can verify WHICH check each suppression turns off.  A
            # bare marker blanket-suppresses its whole scanner on that line,
            # which is the catch-all the INVARIANT-13 audit trail exists to
            # prevent.  See _STRICT_FORMS for why each family is or is not
            # held to this.
            marker = m.group(1)
            strict = _STRICT_FORMS.get(marker)
            if strict is not None and not strict[0].match(rest):
                violations.append(
                    f"{tag}: suppression '{marker}' missing rule id "
                    f"(expected '{strict[1]}'); written bare it suppresses "
                    f"every rule on the line"
                )
                continue
            if not _JUSTIFICATION_RE.search(rest):
                violations.append(
                    f"{tag}: suppression '{m.group()}' missing justification "
                    f"(expected em-dash, --, or # followed by reason and tracking ID)"
                )
            elif not _TRACKING_ID_RE.search(rest):
                violations.append(
                    f"{tag}: suppression '{m.group()}' missing tracking ID "
                    f"(expected e.g. (KM-001))"
                )
    return violations


def _scan_file(filepath: str) -> list[str]:
    """Return a list of violation messages for the given file."""
    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            source = fh.read()
    except (OSError, UnicodeDecodeError):
        return []  # skip unreadable files
    return check_source(filepath, source)


#: Trees where INVARIANT-13 states suppressions are "**absolutely forbidden**
#: ... regardless of justification".  Scanned by :func:`scan_c_tree` below.
#:
#: They had never been scanned.  ``_FORBIDDEN_DIRS`` above listed them and
#: ``_is_forbidden()`` reported on them, but ``main()`` only ever collected
#: ``ama_cryptography/**/*.py``, ``tests/**/*.py`` and ``tools/**/*.py`` — no
#: path under ``src/c/`` or ``include/`` could reach that branch, so it was
#: dead code for every entry, and INVARIANTS.md's "CI scans the repository for
#: suppression tokens and **must** fail if a suppression appears in a forbidden
#: directory" was false.  A live suppression sat in ``src/c/`` while the gate
#: printed "all suppressions are properly justified" and exited 0.
_C_FORBIDDEN_ROOTS: tuple[str, ...] = ("src/c", "include")

#: Vendored trees are excluded.  They are third-party code carried verbatim;
#: INVARIANT-13 governs what THIS project writes, and rewriting a vendor
#: comment would defeat the "no project-side modifications" property the
#: vendor-isolation gate enforces separately.
_C_VENDOR_MARKER = "vendor"

#: Suppression markers recognised by the C/C++ analysers this project runs.
#: ``NOLINT`` covers ``NOLINT``, ``NOLINTNEXTLINE`` and ``NOLINTBEGIN`` in one
#: pattern because clang-tidy matches the token anywhere inside a comment —
#: which is also why it is spelled here as a regex and never as prose in a C
#: comment: writing it in a source comment ARMS it.
_C_SUPPRESSION_RE = re.compile(
    r"NOLINT(?:NEXTLINE|BEGIN|END)?\b|cppcheck-suppress|nosemgrep|coverity\s*\[|/\*\s*LINTED"
)


def c_tree_files(repo_root: Path) -> list[Path]:
    """Every non-vendored ``.c``/``.h`` under the forbidden roots.

    The same enumeration the clang-tidy CI job performs, so "the gate scans
    what the analyser scans" is true by construction rather than by hope.
    """
    out: list[Path] = []
    for root in _C_FORBIDDEN_ROOTS:
        base = repo_root / root
        if not base.is_dir():
            continue
        for pattern in ("**/*.c", "**/*.h"):
            for path in base.glob(pattern):
                if _C_VENDOR_MARKER in path.relative_to(repo_root).parts:
                    continue
                out.append(path)
    return sorted(set(out))


def scan_c_tree(repo_root: Path) -> list[str]:
    """Violations in the trees where suppressions are absolutely forbidden.

    No justification pass here, deliberately.  For the Python trees the rule
    is "justified and tracked"; for these it is "none, regardless of
    justification", so a well-argued suppression is still a violation and the
    only correct outcomes are fixing the code or dropping the check category
    in ``.clang-tidy`` — which is what that file's own header says.
    """
    violations: list[str] = []
    files = c_tree_files(repo_root)
    if not files:
        # Fail closed: an empty scope means the layout moved or the glob broke,
        # and reporting "clean" over nothing is how this gate was wrong before.
        return [
            "src/c and include contain no non-vendored .c/.h files — the scan "
            "scope is empty, which is a checker fault, not a clean tree"
        ]
    for path in files:
        rel = path.relative_to(repo_root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:  # pragma: no cover - unreadable file
            violations.append(f"{rel}: cannot be read ({exc})")
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            match = _C_SUPPRESSION_RE.search(line)
            if match:
                violations.append(
                    f"{rel}:{lineno}: suppression marker {match.group(0)!r} in a "
                    "tree where INVARIANT-13 forbids suppressions regardless of "
                    "justification — fix the code or drop the check category"
                )
    return violations


# ---------------------------------------------------------------------------
# Third pass: environment-dependent `type: ignore` in optional-import blocks
# ---------------------------------------------------------------------------
#
# A `# type: ignore` inside an `except ImportError:` handler cannot be correct
# in both of the environments this project type-checks in.  Where the optional
# package IS installed, the name bound by the `try` has the imported module's
# type and `name = None` needs the ignore.  Where it is NOT — the CI
# type-check image carries the pinned tools and nothing else — the import
# resolves to `Any` through `ignore_missing_imports`, `name = None` is fine,
# and the same ignore is an ERROR under `warn_unused_ignores`.
#
# So the marker makes the file green in one place and red in the other, which
# is the "green local mypy --strict reached a red CI" failure the type-check
# step already warns about.  It appeared four times in this tree
# (`setup.py` twice, `benchmarks/benchmark_suite.py`,
# `examples/python/complete_demo.py`), each a latent CI break.
#
# The fix is never another suppression: DECLARE the name before the `try`
# (`np: Any`) and import under an alias, which makes the verdict the same in
# both environments.

#: Files this pass reads.  Wider than the justification pass above, because
#: the hazard is about where mypy runs, not about which tree the file is in.
_OPTIONAL_IMPORT_SCAN_DIRS = (
    "ama_cryptography",
    "tests",
    "tools",
    "benchmarks",
    "examples",
    "fuzz",
    "nist_vectors",
    "schemas",
    "wycheproof_vectors",
)

_TYPE_IGNORE_RE = re.compile(r"#\s*type:\s*ignore")


#: Import prefixes that resolve identically in every environment this project
#: type-checks in, because they live in this repository.  A fallback for one of
#: these is not the hazard below: mypy finds the module either way, so an
#: ignore that is needed is needed everywhere.
_FIRST_PARTY_PREFIXES = ("ama_cryptography", "ama_cryptography_monitor", "tools", "tests")


def _may_hold_a_guarded_import(source: str) -> bool:
    """Cheap pre-filter: could this file possibly hold a guarded optional import?

    It must name at least one of the two spellings the AST pass accepts, and
    carry a suppression at all.  The filter used to test
    ``"ImportError" not in source``, and
    ``"ModuleNotFoundError"`` does not contain that substring — so a module
    whose optional import is guarded by the ``ModuleNotFoundError`` spelling
    was dropped here and never reached
    :func:`_third_party_import_fallback_lines`, which handles both.  The hazard
    this pass exists for — a ``# type: ignore`` that is required where the
    package is installed and an error under ``warn_unused_ignores`` where it is
    not — is identical for either spelling.
    """
    if "type:" not in source:
        return False
    return "ImportError" in source or "ModuleNotFoundError" in source


def _third_party_import_fallback_lines(source: str) -> set[int]:
    """1-based line numbers inside an ``except ImportError`` whose ``try``
    imports a module that is NOT first-party.

    The first-party restriction is what makes this precise.
    ``crypto_api.py`` guards ``from ama_cryptography.rfc3161_timestamp import
    …`` — an in-tree module that mypy resolves in every environment — so the
    three ignores in that handler are needed unconditionally and are not a
    portability problem.  Flagging them would be a gate crying wolf on correct
    code, which is how a gate stops being read.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()

    covered: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue

        third_party = False
        for stmt in ast.walk(ast.Module(body=node.body, type_ignores=[])):
            if isinstance(stmt, ast.Import):
                modules = [alias.name for alias in stmt.names]
            elif isinstance(stmt, ast.ImportFrom):
                # A relative import (level > 0) is first-party by construction.
                modules = [] if stmt.level else [stmt.module or ""]
            else:
                continue
            for module in modules:
                head = module.split(".", 1)[0]
                if head and head not in _FIRST_PARTY_PREFIXES:
                    third_party = True
        if not third_party:
            continue

        for handler in node.handlers:
            names: list[str] = []
            exc = handler.type
            if isinstance(exc, ast.Name):
                names = [exc.id]
            elif isinstance(exc, ast.Tuple):
                names = [e.id for e in exc.elts if isinstance(e, ast.Name)]
            if not any(n in ("ImportError", "ModuleNotFoundError") for n in names):
                continue
            for stmt in handler.body:
                end = getattr(stmt, "end_lineno", stmt.lineno) or stmt.lineno
                covered.update(range(stmt.lineno, end + 1))
    return covered


def scan_optional_imports(repo_root: Path) -> list[str]:
    """Every ``type: ignore`` sitting inside an optional-import fallback."""
    violations: list[str] = []
    for directory in _OPTIONAL_IMPORT_SCAN_DIRS:
        root = repo_root / directory
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.py")):
            try:
                source = path.read_text(encoding="utf-8")
            except OSError:
                continue
            if not _may_hold_a_guarded_import(source):
                continue
            covered = _third_party_import_fallback_lines(source)
            if not covered:
                continue
            for lineno, line in enumerate(source.splitlines(), start=1):
                if lineno in covered and _TYPE_IGNORE_RE.search(line):
                    violations.append(
                        f"{path.relative_to(repo_root).as_posix()}:{lineno}: "
                        f"`type: ignore` inside an except ImportError block — this "
                        f"marker is REQUIRED where the optional package is installed "
                        f"and an ERROR where it is not, so the file cannot be green "
                        f"in both. Declare the name before the `try` "
                        f"(e.g. `np: Any`) and import under an alias instead."
                    )
    for path in (repo_root / "setup.py", repo_root / "ama_cryptography_monitor.py"):
        if not path.is_file():
            continue
        source = path.read_text(encoding="utf-8")
        if not _may_hold_a_guarded_import(source):
            continue
        covered = _third_party_import_fallback_lines(source)
        for lineno, line in enumerate(source.splitlines(), start=1):
            if lineno in covered and _TYPE_IGNORE_RE.search(line):
                violations.append(
                    f"{path.name}:{lineno}: `type: ignore` inside an except "
                    f"ImportError block — see the note in this gate."
                )
    return violations


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    os.chdir(repo_root)

    # Collect all Python files under ama_cryptography/, tests/ and tools/.
    #
    # ``tools/`` was outside the scan until it was noticed that it holds the
    # gates themselves — the scripts whose whole purpose is to enforce this
    # repository's security policy. A suppression there silences a static
    # analyser inside the enforcement layer, which is the last place an
    # unexplained one belongs, and it was the only tree where they went
    # unpoliced. Two bare ``noqa: S310`` markers were sitting in the corpus
    # fetchers when the scan was widened: no reason, no tracking ID, over
    # (the leading hash is omitted above deliberately — ruff parses a real
    # directive out of prose that spells one, which is the same false-positive
    # class ``effective_suppressions`` exists to avoid)
    # ``urllib`` calls that accepted ``file:`` and ``ftp:`` URLs. They now
    # check the scheme, so the suppression states a fact.
    targets = (
        list(Path("ama_cryptography").rglob("*.py"))
        + list(Path("tests").rglob("*.py"))
        + list(Path("tools").rglob("*.py"))
    )

    all_violations: list[str] = []
    for path in sorted(targets):
        filepath = str(path)
        all_violations.extend(_scan_file(filepath))

    # The trees INVARIANT-13 calls absolute.  Separate pass, separate rule:
    # presence alone is the violation there.
    all_violations.extend(scan_c_tree(repo_root))

    # Suppressions that cannot be right in both type-check environments.
    all_violations.extend(scan_optional_imports(repo_root))

    if all_violations:
        print(f"INVARIANT-13 violations ({len(all_violations)}):\n")
        for v in all_violations:
            print(f"  {v}")
        print(
            f"\n{len(all_violations)} suppression violation(s). Python-tree markers "
            "need a justification and a tracking ID; markers under src/c or "
            "include must be removed outright."
        )
        return 1

    print(
        "INVARIANT-13: all suppressions are properly justified "
        f"({len(targets)} Python files), and the {len(c_tree_files(repo_root))} "
        "non-vendored C/H files under src/c and include carry none at all."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
