# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Every instrumented operation name has an anomaly profile.

``ResonanceTimingMonitor.DEFAULT_ANOMALY_PROFILES`` carries a comment asserting that
its keys "cover BOTH instrumentation vocabularies that exist in this package".
That was prose, checked by nothing, and it was false: ``hmac_verify`` — named
inside the sentence making the claim — had no profile, and neither did the
other two ``legacy_compat`` emitters ``hmac_auth`` and ``sha3_256_hash``.

Nothing crashed.  ``_record_timing_locked`` does
``self.anomaly_profiles.get(operation, {})``, so an unprofiled name silently
takes the global floor.  That is exactly why a missing profile is invisible
without a gate: the failure mode of this defect is a threshold nobody chose.

This module is the gate.  It parses every ``monitor_crypto_operation("...")``
call site in the shipped package and requires a profile for each name, and it
requires every profile key to be either an emitted name or on the short
explicit list of profiles kept for external callers.  Both directions matter:
the first stops an emitter being added without a profile, the second stops the
table accumulating dead configuration of the kind the same comment block says
``aes_gcm_encrypt`` / ``aes_gcm_decrypt`` already were.
"""

from __future__ import annotations

import ast
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent.parent / "ama_cryptography"

#: Profiles deliberately kept for callers outside this package.  The comment
#: on DEFAULT_ANOMALY_PROFILES records that no in-tree call site has ever
#: emitted these two names; they stay so an external instrumentation caller
#: does not silently lose its tuning.
EXTERNAL_ONLY_PROFILES = frozenset({"aes_gcm_encrypt", "aes_gcm_decrypt"})


def _emitted_operation_names() -> set[str]:
    """Every literal name passed to ``monitor_crypto_operation``."""
    names: set[str] = set()
    for path in sorted(PACKAGE_DIR.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover - a broken source is its own test
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            attr = func.attr if isinstance(func, ast.Attribute) else None
            if attr != "monitor_crypto_operation" or not node.args:
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                names.add(first.value)
    return names


def _profile_keys() -> set[str]:
    from ama_cryptography.monitoring import ResonanceTimingMonitor

    return set(ResonanceTimingMonitor.DEFAULT_ANOMALY_PROFILES)


def test_the_sweep_finds_the_emitters() -> None:
    """Non-vacuity: the AST sweep must actually find call sites.

    An empty sweep would make every assertion below pass over nothing, which
    is the failure mode this file exists to avoid in the code it checks.
    """
    emitted = _emitted_operation_names()
    assert len(emitted) >= 10, f"the sweep found only {sorted(emitted)}"
    assert "hmac_verify" in emitted
    assert "sign" in emitted


def test_every_emitted_operation_has_a_profile() -> None:
    missing = sorted(_emitted_operation_names() - _profile_keys())
    assert not missing, (
        "operations instrumented with no anomaly profile, so they silently "
        f"take the global floor instead of a chosen threshold: {missing}"
    )


def test_every_profile_is_emitted_or_declared_external() -> None:
    dead = sorted(_profile_keys() - _emitted_operation_names() - EXTERNAL_ONLY_PROFILES)
    assert not dead, (
        "anomaly profiles for names nothing emits and that are not on the "
        f"external-caller list — dead configuration: {dead}"
    )
