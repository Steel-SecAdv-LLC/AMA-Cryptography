"""
Unit tests for tools/check_version_consistency.py.

Focused on the C-source scan extension: a synthetic C file with a fake
version literal must be flagged, and a real-tree scan against the
checked-in src/c/ tree must continue to return zero hits (so the
default safety-net assertion is durable).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "check_version_consistency.py"


@pytest.fixture(scope="module")
def tool_module() -> ModuleType:
    """Load tools/check_version_consistency.py as a module so we can
    call its scan function directly. The script lives in a non-package
    directory and isn't on sys.path, so importlib.util is the cleanest
    handle that doesn't require modifying the tool layout."""
    spec = importlib.util.spec_from_file_location("check_version_consistency", TOOL_PATH)
    assert spec is not None, f"could not build a ModuleSpec for {TOOL_PATH}"
    assert spec.loader is not None, f"ModuleSpec for {TOOL_PATH} has no loader"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_real_tree_returns_zero_hits(tool_module: ModuleType) -> None:
    """The shipped src/c/ tree must contain *no* embedded
    "X.Y.Z" version-string literals near a VERSION/version
    identifier — that's the steady-state invariant the check enforces.
    If this assertion ever fires, a stray literal slipped in and the
    canonical AMA_CRYPTOGRAPHY_VERSION_STRING macro should be used
    instead."""
    hits = tool_module.scan_c_sources_for_version_literals(REPO_ROOT / "src" / "c")
    assert hits == [], f"unexpected version literals in src/c/: {hits}"


def test_synthetic_c_file_is_flagged(tool_module: ModuleType, tmp_path: Path) -> None:
    """Drop a fake `#define MY_VERSION "9.9.9"` into a temp directory
    and confirm the scanner picks it up. Mirrors the pattern a future
    accidental commit would take."""
    src_dir = tmp_path / "c"
    src_dir.mkdir()
    fake = src_dir / "fake_module.c"
    fake.write_text(
        "/* synthetic test fixture */\n"
        '#define MY_VERSION "9.9.9"\n'
        'static const char *version = "0.1.2";\n'
    )

    hits = tool_module.scan_c_sources_for_version_literals(src_dir)
    assert len(hits) == 2, f"expected 2 flagged lines, got: {hits}"
    joined = "\n".join(hits)
    assert "9.9.9" in joined
    assert "0.1.2" in joined
    assert "fake_module.c" in joined


def test_c_comments_are_ignored(tool_module: ModuleType, tmp_path: Path) -> None:
    """Version literals embedded in `/* ... */` block comments or `//`
    line comments are documentation, not code-shipped values, and
    should not trip the scanner. This avoids false positives on
    historical change-log notes inside source headers."""
    src_dir = tmp_path / "c"
    src_dir.mkdir()
    f = src_dir / "comments_only.c"
    f.write_text(
        '/* Released in version "1.2.3" — historical note */\n'
        '// const char *legacy_version = "0.0.1";\n'
        "int main(void) { return 0; }\n"
    )
    assert tool_module.scan_c_sources_for_version_literals(src_dir) == []


def test_literal_without_version_identifier_is_ignored(
    tool_module: ModuleType, tmp_path: Path
) -> None:
    """A `"X.Y.Z"` literal that's not anywhere near a VERSION/version
    identifier (e.g. a protocol-spec quote) should not be flagged.
    The check is targeted at the identifier-and-literal coupling, not
    at any three-dotted-numbers string anywhere in C."""
    src_dir = tmp_path / "c"
    src_dir.mkdir()
    f = src_dir / "no_version_ident.c"
    f.write_text('static const char *rfc_section = "5.2.1";\n' "int main(void) { return 0; }\n")
    assert tool_module.scan_c_sources_for_version_literals(src_dir) == []


def test_header_files_are_scanned(tool_module: ModuleType, tmp_path: Path) -> None:
    """Both `*.c` and `*.h` are in scope per the task spec — make sure
    a literal hidden in a header is also reported."""
    src_dir = tmp_path / "c"
    src_dir.mkdir()
    h = src_dir / "fake_module.h"
    h.write_text('#define FAKE_VERSION "2.5.0"\n')
    hits = tool_module.scan_c_sources_for_version_literals(src_dir)
    assert any("fake_module.h" in hit and "2.5.0" in hit for hit in hits)
