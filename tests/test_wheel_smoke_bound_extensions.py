# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The release smoke test's binding-coverage assertion must count, not match.

``tools/wheel_smoke_test.py::check_integrity_and_bindings`` documents itself as
distinguishing three outcomes: a digest MISMATCH (tampering), PARTIAL coverage,
and "uncovered (the wheel was built without ``--bind-extensions``)".  Its third
assertion tested ``"binding extension(s) verified" in detail``.

``_self_test._check_binding_extensions`` returns
``f"{len(binding_digests)} binding extension(s) verified"``, so an artefact that
binds NOTHING yields ``"0 binding extension(s) verified"`` — which contains that
substring.  The two assertions above it pass on the same string as well
("MISMATCH" absent, "PARTIALLY covered" and "not covered by the signed
artefact" absent).  All three were therefore green for exactly the pipeline
fault the function exists to catch, on a release wheel.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "wheel_smoke_test.py"


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("wheel_smoke_test", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("detail", "expected"),
    [
        ("0 binding extension(s) verified", 0),
        ("6 binding extension(s) verified", 6),
        ("signed integrity verified; 3 binding extension(s) verified", 3),
        ("signed integrity verified", None),
        ("", None),
    ],
)
def test_the_count_is_parsed_out_of_the_sentence(
    tool: ModuleType, detail: str, expected: int | None
) -> None:
    assert tool._bound_extension_count(detail) == expected


def test_zero_bound_extensions_is_not_a_pass(tool: ModuleType) -> None:
    """The defect, stated as the property it violated.

    A substring test cannot tell 0 from 6; a count can, and 0 is the state a
    release wheel must never ship in.
    """
    zero = tool._bound_extension_count("0 binding extension(s) verified")
    assert zero == 0
    assert not (
        zero is not None and zero > 0
    ), "an artefact that binds no extension satisfied the 'binds at least one' check"


def test_an_unreadable_detail_is_not_a_pass(tool: ModuleType) -> None:
    """Fail-closed: a smoke test that cannot read the count must not pass."""
    missing = tool._bound_extension_count("integrity verified (no count here)")
    assert missing is None
    assert not (missing is not None and missing > 0)


def test_a_real_count_still_passes(tool: ModuleType) -> None:
    """The control: the assertion must still accept a correctly built wheel."""
    six = tool._bound_extension_count("6 binding extension(s) verified")
    assert six is not None and six > 0


def _install_self_test_stub(
    monkeypatch: pytest.MonkeyPatch,
    *,
    anchor_hex: str | None,
    error: str | None,
    required: bool,
) -> None:
    """Put a stub ``ama_cryptography._self_test`` where the smoke test finds it.

    ``check_integrity_anchoring`` does ``from ama_cryptography import _self_test``
    inside the function and consults that module's own anchor resolver and
    env-flag helper.  ``from ama_cryptography import _self_test`` resolves the
    submodule as ``getattr(ama_cryptography, "_self_test")``, so setting that
    attribute is enough to redirect it; the stub runs the check with no native
    library and no POST, since the branches are what is under test.

    A ``SimpleNamespace`` carries the three names as constructor kwargs, so the
    stub needs no per-attribute assignment and therefore no ``# type: ignore``
    (INVARIANT-13: this repository ships no unjustified suppressions, and a
    suppression a ModuleType stub could avoid is not justified).
    """
    pkg = sys.modules.get("ama_cryptography")
    if pkg is None:
        pkg = ModuleType("ama_cryptography")
        monkeypatch.setitem(sys.modules, "ama_cryptography", pkg)
    stub = SimpleNamespace(
        _INTEGRITY_REQUIRE_TRUST_ANCHOR_ENV="AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR",
        _load_integrity_trust_anchor=lambda: (anchor_hex, error),
        _env_flag_enabled=lambda _name: required,
    )
    monkeypatch.setattr(pkg, "_self_test", stub, raising=False)


class TestIntegrityAnchoring:
    """The release wheel must not silently ship unanchored (audit H3).

    Anchoring is enforced only when ``AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR`` is set
    — release.yml sets it iff the trust-anchor variable is configured, so forks
    (which build unanchored) are unaffected while the canonical repository is.
    """

    def test_required_and_unanchored_fails(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_self_test_stub(monkeypatch, anchor_hex=None, error=None, required=True)
        tool._FAILURES.clear()
        tool.check_integrity_anchoring()
        assert tool._FAILURES, "an unanchored wheel passed while anchoring was required"

    def test_required_and_anchored_passes(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_self_test_stub(monkeypatch, anchor_hex="ab" * 32, error=None, required=True)
        tool._FAILURES.clear()
        tool.check_integrity_anchoring()
        assert tool._FAILURES == [], "a correctly anchored wheel was rejected"

    def test_not_required_and_unanchored_passes(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The fork / pre-anchor path: unanchored is allowed when not required.
        _install_self_test_stub(monkeypatch, anchor_hex=None, error=None, required=False)
        tool._FAILURES.clear()
        tool.check_integrity_anchoring()
        assert tool._FAILURES == [], "unanchored must be allowed when not required"

    def test_required_and_resolver_error_fails(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_self_test_stub(
            monkeypatch, anchor_hex=None, error="library could not answer", required=True
        )
        tool._FAILURES.clear()
        tool.check_integrity_anchoring()
        assert tool._FAILURES, "a resolver error must fail when anchoring is required"

    def test_unreadable_status_fails_even_when_not_required(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Fail-closed: even off the canonical path, a status that cannot be read
        # (a malformed anchor, a library that could not answer) is a real fault.
        _install_self_test_stub(
            monkeypatch, anchor_hex=None, error="integrity trust anchor is not hex", required=False
        )
        tool._FAILURES.clear()
        tool.check_integrity_anchoring()
        assert tool._FAILURES, "an unreadable anchor status must not pass"
