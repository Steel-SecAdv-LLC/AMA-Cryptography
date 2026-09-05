# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Both directions of INVARIANT-43 (``tools/check_log_message_encodability.py``).

The gate exists because ``logging`` fails *closed and silent*: a record whose
text a handler's encoding cannot represent is discarded inside
``Handler.handleError``, and the call site is told nothing.  On Windows that
handler encoding is ``cp1252`` by default, and this library had shipped a ``→``
inside the two records that report a signing-key rotation and an algorithm
switch — so the audit trail lost exactly the events it existed to record.

A gate that only ever passes proves nothing, so the failing direction is
asserted here as explicitly as the passing one, including the two ways this
check could be wrong in the other direction: flagging text that cp1252 *can*
encode, and missing an emission site because of how the logger was named.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_tool_module(name: str) -> ModuleType:
    """Import ``tools/<name>.py`` by path (``tools/`` is not on ``sys.path``)."""
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / "tools" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    return _load_tool_module("check_log_message_encodability")


def _synthetic_package(tmp_path: Path, body: str) -> Path:
    """Write ``body`` into a throwaway tree shaped like the real package."""
    pkg = tmp_path / "ama_cryptography"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "sample.py").write_text(body, encoding="utf-8")
    return tmp_path


class TestTheGateIsNotVacuousOnThisRepository:
    def test_the_real_package_has_no_unencodable_log_text(self, tool: ModuleType) -> None:
        """The shipped tree must pass; this is the assertion that regresses."""
        failures, files_scanned, sites_scanned = tool.audit(REPO_ROOT)
        assert failures == []
        assert files_scanned > 0, "scanned nothing — the glob or layout changed"
        assert sites_scanned > 0, "found no logging calls — the detector is broken"

    def test_the_rotation_records_are_ascii(self) -> None:
        """The two records the original defect silently dropped, pinned by content.

        Scoped to emission lines on purpose.  ``adaptive_posture.py`` still uses
        ``→`` in its module docstring's dataflow diagram and in the posture
        threshold table, and that is correct: a comment is never handed to a
        handler, so rewriting prose to satisfy an encoding rule that only binds
        emitted text would cost readability and buy nothing.
        """
        path = REPO_ROOT / "ama_cryptography" / "adaptive_posture.py"
        source = path.read_text(encoding="utf-8")
        assert "Posture-triggered key rotation: %s -> %s" in source
        assert "Posture-triggered algorithm switch: %s -> %s" in source

        offending = [
            line
            for line in source.splitlines()
            if ("logger." in line or "warnings.warn" in line) and "→" in line
        ]
        assert offending == []


class TestTheFailingDirection:
    @pytest.mark.parametrize(
        "char",
        ["\u2192", "\u2713", "\u2717", "\u03c3", "\u2265", "\u2080"],
        ids=["arrow", "check", "cross", "sigma", "ge", "subscript-zero"],
    )
    def test_unencodable_character_in_a_log_call_is_caught(
        self, tool: ModuleType, tmp_path: Path, char: str
    ) -> None:
        root = _synthetic_package(
            tmp_path,
            f"import logging\nlogger = logging.getLogger(__name__)\n"
            f'logger.info("rotated {char} done")\n',
        )
        failures, _, _ = tool.audit(root)
        assert len(failures) == 1
        assert f"U+{ord(char):04X}" in failures[0]

    def test_unencodable_character_in_a_warning_is_caught(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        root = _synthetic_package(
            tmp_path, 'import warnings\nwarnings.warn("degraded \u2192 fallback")\n'
        )
        failures, _, _ = tool.audit(root)
        assert len(failures) == 1
        assert "warnings.warn" in failures[0]

    def test_fstring_literal_parts_are_checked(self, tool: ModuleType, tmp_path: Path) -> None:
        """The original defect's siblings were f-strings, not plain constants."""
        root = _synthetic_package(
            tmp_path,
            "import logging\nlogger = logging.getLogger(__name__)\n"
            'value = 1\nlogger.info(f"  \u2713 threshold: {value}")\n',
        )
        failures, _, _ = tool.audit(root)
        assert len(failures) == 1
        assert "U+2713" in failures[0]

    def test_self_dot_logger_is_detected(self, tool: ModuleType, tmp_path: Path) -> None:
        """An attribute receiver must not let a site slip past the detector."""
        root = _synthetic_package(
            tmp_path,
            "class C:\n"
            "    def m(self) -> None:\n"
            '        self.logger.error("bad \u2192 worse")\n',
        )
        failures, _, _ = tool.audit(root)
        assert len(failures) == 1

    def test_main_returns_nonzero_from_a_dirty_tree(
        self, tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _synthetic_package(
            tmp_path,
            'import logging\nlogger = logging.getLogger(__name__)\nlogger.info("a \u2192 b")\n',
        )
        monkeypatch.chdir(root)
        assert tool.main() == 1


class TestTheGateIsNotOverTightened:
    @pytest.mark.parametrize(
        "char",
        ["\u2014", "\u00a7", "\u2026", "\u00d7", "\u00b2", "\u2013"],
        ids=["em-dash", "section", "ellipsis", "times", "superscript-2", "en-dash"],
    )
    def test_cp1252_encodable_characters_are_allowed(
        self, tool: ModuleType, tmp_path: Path, char: str
    ) -> None:
        """cp1252, not ASCII, is the boundary — the library's em dashes are fine."""
        root = _synthetic_package(
            tmp_path,
            f"import logging\nlogger = logging.getLogger(__name__)\n"
            f'logger.info("POST {char} complete")\n',
        )
        failures, _, _ = tool.audit(root)
        assert failures == []

    def test_clean_tree_returns_zero(
        self, tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _synthetic_package(
            tmp_path,
            'import logging\nlogger = logging.getLogger(__name__)\nlogger.info("a -> b")\n',
        )
        monkeypatch.chdir(root)
        assert tool.main() == 0

    def test_non_logging_calls_are_not_policed(self, tool: ModuleType, tmp_path: Path) -> None:
        """``print`` to a stream the module reconfigured is out of scope by design."""
        root = _synthetic_package(tmp_path, 'print("banner \u2713 ok")\n')
        failures, _, _ = tool.audit(root)
        assert failures == []


class TestUnencodableCharacters:
    def test_returns_only_the_offending_characters_once(self, tool: ModuleType) -> None:
        assert tool.unencodable_characters("a \u2192 b \u2192 c") == ["\u2192"]

    def test_ascii_and_cp1252_text_is_clean(self, tool: ModuleType) -> None:
        assert tool.unencodable_characters("plain ASCII \u2014 and a section \u00a7") == []


class TestInlineGetLoggerIdiom:
    """``logging.getLogger(__name__).critical(...)`` — the idiom the gate missed.

    The receiver of the level method is a Call node, which the dotted-name
    walk renders as an empty string, so the first version of this gate
    skipped every such site while reporting PASS over the files containing
    them — 15 real emission sites in the shipped package, including the
    POST-failure criticals in ``__init__``.  These pin the fix in both
    directions and for the aliased-module spelling ``__init__`` actually
    uses.
    """

    def test_inline_getlogger_with_unencodable_text_is_caught(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        root = _synthetic_package(
            tmp_path,
            'import logging\nlogging.getLogger(__name__).critical("POST → FAILED")\n',
        )
        failures, _, sites = tool.audit(root)
        assert len(failures) == 1
        assert "U+2192" in failures[0]
        assert sites == 1

    def test_aliased_module_inline_getlogger_is_caught(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """``import logging as _logging`` — the spelling ``__init__`` uses."""
        root = _synthetic_package(
            tmp_path,
            "import logging as _logging\n"
            '_logging.getLogger(__name__).critical("refused ✗ tampered")\n',
        )
        failures, _, _ = tool.audit(root)
        assert len(failures) == 1
        assert "U+2717" in failures[0]

    def test_inline_getlogger_with_clean_text_passes(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        root = _synthetic_package(
            tmp_path,
            'import logging\nlogging.getLogger(__name__).warning("plain -> ok")\n',
        )
        failures, _, sites = tool.audit(root)
        assert failures == []
        assert sites == 1

    def test_getlogger_itself_is_not_an_emission_site(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """The factory call alone emits nothing; only a level method does."""
        root = _synthetic_package(
            tmp_path,
            'import logging\nlogger = logging.getLogger("app → name")\n',
        )
        failures, _, sites = tool.audit(root)
        assert failures == []
        assert sites == 0
