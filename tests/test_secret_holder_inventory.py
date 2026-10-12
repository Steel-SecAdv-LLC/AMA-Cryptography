# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""``docs/SECRET_HOLDER_INVENTORY.md`` matches the tree.

PR #415's ``7a9283a8`` round found three holders that dropped their secret
unzeroed through two scratch scans that were never committed, so no
mechanism held the property.  ``tools/measure_secret_holders.py`` is those
scans committed, and this gate pins the AGENTS.md §10 arrangement: the
committed page is the reviewed inventory, so a new candidate row — a new
holder class outside ``SecretMaterial`` or a new bare-local producer
binding — cannot land without its diff coming up for review.  The scans
over-report by design; a row is a reviewed candidate, not a finding.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from tools.measure_secret_holders import DOC, render

REPO = Path(__file__).resolve().parents[1]


def test_the_committed_inventory_is_at_fixpoint() -> None:
    """PIN: a new candidate holder or producer binding anywhere in the
    package changes the rendered page, and this fails until the regenerated
    page — the new row visible in the diff — is committed with it."""
    assert DOC.exists(), (
        "docs/SECRET_HOLDER_INVENTORY.md is missing; regenerate with: "
        "python tools/measure_secret_holders.py --write"
    )
    assert DOC.read_text(encoding="utf-8") == render(REPO), (
        "docs/SECRET_HOLDER_INVENTORY.md does not match the tree; a new or "
        "moved candidate row needs review — regenerate with: "
        "python tools/measure_secret_holders.py --write"
    )


def _package(tmp_path: Path, body: str) -> Path:
    pkg = tmp_path / "ama_cryptography"
    pkg.mkdir(parents=True)
    (pkg / "mod.py").write_text(textwrap.dedent(body), encoding="utf-8")
    return tmp_path


def test_the_scan_sees_a_holder_class(tmp_path: Path) -> None:
    """PIN for scan 1: a secret-named ``self`` attribute outside
    ``SecretMaterial`` is a row; the same class subclassing it is not, and a
    public-named attribute never is."""
    page = render(
        _package(
            tmp_path,
            """
            class Holder:
                def __init__(self) -> None:
                    self._session_secret = b""
                    self.public_key = b""
            """,
        )
    )
    assert "`Holder`" in page and "`_session_secret`" in page
    assert "public_key" not in page

    covered = render(
        _package(
            tmp_path / "covered",
            """
            class SecretMaterial: ...

            class Holder(SecretMaterial):
                def __init__(self) -> None:
                    self._session_secret = b""
            """,
        )
    )
    assert "`Holder`" not in covered


def test_the_scan_sees_a_bare_local_producer_binding(tmp_path: Path) -> None:
    """PIN for scan 2: ``name = secure_token_bytearray(...)`` is a row, and
    an attribute target is not (an owner adopted it)."""
    page = render(
        _package(
            tmp_path,
            """
            def mint():
                raw = secure_token_bytearray(32)
                return raw

            class Owner:
                def __init__(self) -> None:
                    self.key = secure_token_bytearray(32)
            """,
        )
    )
    assert "`raw`" in page
    assert "Bare-local producer bindings: **1**" in page
