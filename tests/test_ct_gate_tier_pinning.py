# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The constant-time gate must be able to say which tier it measured.

KCT-3.  Every deterministic lane ran ``check_ghash_constant_time.py`` with no
way to select an implementation, so the numbers described whatever the
dispatcher picked on that runner.  The scalar kernels -- what a pre-AVX2 host,
a container with AVX2 masked off, or an ``AMA_DISPATCH_NO_*_AVX2`` opt-out
actually executes -- were never measured by these gates.

``--dispatch-only`` pins the tier through the dispatcher's own
``AMA_DISPATCH_ONLY`` contract.  The half that makes it worth having is the
refusal: an unrecognised or unavailable slot leaves EVERY kernel at its scalar
fallback, and without the check below the gate would print a clean PASS while
claiming to have measured a tier it never selected.
"""

from __future__ import annotations

import importlib.util
import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "tools" / "check_ghash_constant_time.py"


def _gate():  # type: ignore[no-untyped-def]  # module object, not a typed API (KCT-003)
    spec = importlib.util.spec_from_file_location("ct_gate", GATE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestTheFlagExists:
    def test_the_parser_accepts_dispatch_only(self) -> None:
        text = GATE.read_text(encoding="utf-8")
        assert '"--dispatch-only"' in text

    def test_one_place_builds_the_driver_environment(self) -> None:
        """Three call sites used to set the env separately; drift there is
        how the AVX2-only coverage stayed invisible."""
        text = GATE.read_text(encoding="utf-8")
        assert text.count('env["AMA_DISPATCH_NO_AUTOTUNE"] = "1"') == 1
        assert text.count("_driver_env()") >= 3


class TestThePinReachesTheDriver:
    def test_unset_leaves_the_environment_alone(self) -> None:
        gate = _gate()
        gate._DISPATCH_ONLY = None
        env = gate._driver_env()
        assert env["AMA_DISPATCH_NO_AUTOTUNE"] == "1"
        assert "AMA_DISPATCH_ONLY" not in env

    def test_a_pin_is_exported(self) -> None:
        gate = _gate()
        gate._DISPATCH_ONLY = "kyber-ntt-avx2"
        assert gate._driver_env()["AMA_DISPATCH_ONLY"] == "kyber-ntt-avx2"


class TestAnUnhonouredPinIsRefused:
    """The property that stops the flag from being decorative."""

    REFUSAL = (
        "[AMA Dispatch] ERROR: AMA_DISPATCH_ONLY='sha3-scalar' is not a "
        "recognised slot name.  Dispatch left at scalar fallback"
    )

    def test_a_refusal_line_is_detected(self) -> None:
        gate = _gate()
        gate._DISPATCH_ONLY = "sha3-scalar"
        assert gate._dispatch_pin_was_honoured([self.REFUSAL]) == self.REFUSAL

    def test_clean_wiring_is_accepted(self) -> None:
        gate = _gate()
        gate._DISPATCH_ONLY = "kyber-ntt-avx2"
        wiring = ["[AMA Dispatch] kyber_ntt -> avx2", "[AMA Dispatch] keccak_f1600 -> scalar"]
        assert gate._dispatch_pin_was_honoured(wiring) is None

    def test_nothing_is_checked_when_no_pin_was_asked_for(self) -> None:
        gate = _gate()
        gate._DISPATCH_ONLY = None
        assert gate._dispatch_pin_was_honoured([self.REFUSAL]) is None

    def test_the_refusal_marker_matches_the_dispatchers_wording(self) -> None:
        """If the dispatcher's message changes, this gate goes blind."""
        dispatch = (REPO_ROOT / "src" / "c" / "dispatch" / "ama_dispatch.c").read_text(
            encoding="utf-8"
        )
        gate = _gate()
        assert gate._DISPATCH_ONLY_REFUSED.replace("ERROR: ", "") in dispatch or (
            "AMA_DISPATCH_ONLY=" in dispatch
        )


class TestTheGateStillRefusesToGuess:
    def test_main_returns_inconclusive_not_pass_on_a_refused_pin(self) -> None:
        """rc 2 is INCONCLUSIVE; rc 0 would be a false clean bill of health."""
        text = GATE.read_text(encoding="utf-8")
        block = text[text.index("_dispatch_pin_was_honoured(wiring)") :][:600]
        assert "return 2" in block
        assert "refused" in block
