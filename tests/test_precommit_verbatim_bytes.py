# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The pre-commit fixers must not rewrite bytes that have to stay verbatim.

``trailing-whitespace`` and ``end-of-file-fixer`` do not report — they
REWRITE.  Unscoped, ``pre-commit run --all-files`` on this tree modified 150
files: 94 binary seeds under ``fuzz/seed_corpus/``, all 32 vendored
ed25519-donna headers, 19 NIST/Ascon KAT vector files, the FIPS 140-3
power-on self-test KAT JSON, and generated charts and benchmark JSON.

Nothing in CI catches that.  Measured on the rewritten tree, the corpus
generators' ``--check``, ``check_corpus_originality.py``,
``check_vendor_isolation.py`` and all 135 KAT tests still passed.  A
corruption that every gate calls clean is the kind worth a test of its own.

The last test here is the one that matters: it proves the exclusions are
load-bearing by showing the protected files really do contain bytes those
hooks would change.  An exclude list that guards nothing would pass a
regex-shaped test and still be worthless.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG = REPO_ROOT / ".pre-commit-config.yaml"

#: Hooks that modify the files they run on.
REWRITING_HOOKS = ("trailing-whitespace", "end-of-file-fixer")

#: Roots whose bytes are published or generated, with why they cannot be
#: reformatted.  Each is checked to contain a real tracked file.
PROTECTED_ROOTS = {
    "fuzz/seed_corpus": "binary fuzzer inputs; whitespace is content",
    "tests/kat": "NIST/Ascon reference vectors as published",
    "src/c/vendor": "third-party source, INVARIANT-1 keeps it diffable against upstream",
    "ama_cryptography/_post_kats": "FIPS 140-3 power-on self-test vectors",
}

#: Paths the hooks must still run on.  Excluding everything would also make
#: the fixers stop reporting, which is the other way to get a green hook.
MUST_STILL_BE_COVERED = (
    "README.md",
    "ama_cryptography/__init__.py",
    "tools/check_vendor_isolation.py",
    "tests/conftest.py",
    ".github/workflows/ci.yml",
)


def _hooks() -> dict[str, dict[str, Any]]:
    config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    found: dict[str, dict[str, Any]] = {}
    for repo in config["repos"]:
        for hook in repo.get("hooks", []):
            if hook["id"] in REWRITING_HOOKS:
                found[hook["id"]] = hook
    return found


@pytest.fixture(scope="module")
def hooks() -> dict[str, dict[str, Any]]:
    found = _hooks()
    missing = set(REWRITING_HOOKS) - set(found)
    assert not missing, f"rewriting hook(s) {sorted(missing)} are no longer configured"
    return found


@pytest.fixture(scope="module")
def excludes(hooks: dict[str, dict[str, Any]]) -> dict[str, re.Pattern[str]]:
    compiled: dict[str, re.Pattern[str]] = {}
    for name, hook in hooks.items():
        pattern = hook.get("exclude")
        assert isinstance(pattern, str) and pattern.strip(), (
            f"{name} has no `exclude`. It rewrites every file it is given, so "
            f"an unscoped run reformats the KAT vectors and the fuzz corpus."
        )
        compiled[name] = re.compile(pattern)
    return compiled


@pytest.mark.parametrize("hook_id", REWRITING_HOOKS)
@pytest.mark.parametrize(("root", "reason"), sorted(PROTECTED_ROOTS.items()))
def test_protected_roots_are_excluded(
    excludes: dict[str, re.Pattern[str]], hook_id: str, root: str, reason: str
) -> None:
    directory = REPO_ROOT / root
    assert directory.is_dir(), f"{root} has moved; this test guards nothing as written"
    sample = next((p for p in sorted(directory.rglob("*")) if p.is_file()), None)
    assert sample is not None, f"{root} is empty; this test guards nothing"
    relative = sample.relative_to(REPO_ROOT).as_posix()
    assert excludes[hook_id].match(relative), f"{hook_id} would rewrite {relative} — {reason}"


@pytest.mark.parametrize("hook_id", REWRITING_HOOKS)
@pytest.mark.parametrize("path", MUST_STILL_BE_COVERED)
def test_ordinary_sources_are_still_checked(
    excludes: dict[str, re.Pattern[str]], hook_id: str, path: str
) -> None:
    """The exclusion must be a scope, not an off switch."""
    assert (REPO_ROOT / path).is_file(), f"{path} has moved; pick another representative"
    assert not excludes[hook_id].match(
        path
    ), f"{hook_id} no longer runs on {path}; the hook has been disabled rather than scoped"


def test_markdown_hard_line_breaks_are_preserved(hooks: dict[str, dict[str, Any]]) -> None:
    """Two trailing spaces are a hard line break, not stray whitespace.

    Without this flag the hook silently changes how the documentation renders.
    """
    args = hooks["trailing-whitespace"].get("args") or []
    assert any(
        isinstance(a, str) and a.startswith("--markdown-linebreak-ext") for a in args
    ), "trailing-whitespace would strip Markdown hard line breaks"


def test_the_exclusions_are_load_bearing(excludes: dict[str, re.Pattern[str]]) -> None:
    """Each protected root really does hold bytes the hooks would change.

    Without this, the exclude list could name roots that never needed
    protecting and read as though the risk were handled.  Recorded here as
    counts so a corpus that later stops needing the guard shows up as a
    failure to re-examine rather than as silence.
    """
    would_be_rewritten: dict[str, int] = {}
    for root in PROTECTED_ROOTS:
        count = 0
        for path in sorted((REPO_ROOT / root).rglob("*")):
            if not path.is_file():
                continue
            data = path.read_bytes()
            if not data:
                continue
            # end-of-file-fixer: a missing or repeated final newline.
            if not data.endswith(b"\n") or data.endswith(b"\n\n"):
                count += 1
                continue
            # trailing-whitespace: a space or tab before any newline.
            if re.search(rb"[ \t]+\r?\n", data):
                count += 1
        would_be_rewritten[root] = count

    unaffected = [root for root, n in would_be_rewritten.items() if n == 0]
    assert not unaffected, (
        f"these roots are excluded but hold nothing the hooks would touch: "
        f"{unaffected}. Either the guard is unnecessary or the check above is "
        f"no longer measuring what the hooks do. Counts: {would_be_rewritten}"
    )
