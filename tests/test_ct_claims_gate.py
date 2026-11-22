# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for ``tools/check_ct_claims.py``.

The gate holds every constant-time claim in ``include/*.h`` to a measurement:
a dudect lane under the calibrated threshold that calls the function, and a
blocking deterministic target wherever every lane is info-only.  A gate is
worth its runtime only if it fails on what it claims to catch, so each case
below is a mutation of the real tree -- a new unregistered claim, a withdrawn
claim re-added, a lane renamed away, a lane that never calls its function, an
info-only lane left with no blocking target, a driver that does not call the
function, a forwarder that does more than forward, and a claim attached to
nothing -- and the real tree must pass.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from dataclasses import replace
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "tools" / "check_ct_claims.py"
HEADER = Path("include") / "ama_cryptography.h"
DUDECT = Path("tests") / "c" / "test_dudect.c"


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gate() -> ModuleType:
    return _load("check_ct_claims", GATE_PATH)


@pytest.fixture(scope="module")
def ct_tool() -> ModuleType:
    return _load("_ct_claims_test_ghash", REPO_ROOT / "tools" / "check_ghash_constant_time.py")


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    """A writable copy of what the gate reads; src/c is read-only, so linked."""
    shutil.copytree(REPO_ROOT / "include", tmp_path / "include")
    (tmp_path / DUDECT).parent.mkdir(parents=True)
    shutil.copy(REPO_ROOT / DUDECT, tmp_path / DUDECT)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "c").symlink_to(REPO_ROOT / "src" / "c", target_is_directory=True)
    return tmp_path


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert text.count(old) == 1, old
    path.write_text(text.replace(old, new), encoding="utf-8")


def _errors(gate: ModuleType, root: Path, ct_tool: ModuleType, **kw: object) -> list[str]:
    registry = kw.get("registry", gate.REGISTRY)
    withdrawn = kw.get("withdrawn", gate.WITHDRAWN)
    return list(gate.check(root, registry, withdrawn, ct_tool))


def test_the_tree_passes(gate: ModuleType, ct_tool: ModuleType) -> None:
    assert _errors(gate, REPO_ROOT, ct_tool) == []


def test_main_exits_zero_on_the_tree(gate: ModuleType) -> None:
    assert gate.main([]) == 0


class TestTheClassifier:
    @pytest.mark.parametrize(
        "sentence",
        [
            "@brief Constant-time memory comparison",
            "Constant time in the key; only the verdict is public.",
            "Implicit rejection is unconditional and constant time: a malformed ciphertext.",
            "Encode the input, in constant time with respect to its contents.",
        ],
    )
    def test_a_claim_is_a_claim(self, gate: ModuleType, sentence: str) -> None:
        assert gate.sentence_claims(sentence)

    @pytest.mark.parametrize(
        "sentence",
        [
            "SECURITY: This function is NOT constant-time.",
            "This is intentionally non-constant-time (vartime) because ...",
            "Not constant time — an encapsulation key is public by definition.",
            "verification carries no timing obligation and is not constant time:",
            'The "(constant-time)" this brief used to carry was withdrawn on 2026-11-22.',
            "Exists so the deterministic constant-time gates can measure the SSE2 fold.",
            "so verification does not carry a constant-time obligation",
        ],
    )
    def test_a_negation_or_an_instrument_is_not(self, gate: ModuleType, sentence: str) -> None:
        assert not gate.sentence_claims(sentence)


class TestEachFailureMode:
    def test_a_new_claim_with_no_registry_entry_fails(
        self, gate: ModuleType, ct_tool: ModuleType, tree: Path
    ) -> None:
        _edit(
            tree / HEADER,
            " * @brief AES-256-GCM authenticated encryption\n",
            " * @brief AES-256-GCM authenticated encryption, in constant time\n",
        )
        errors = _errors(gate, tree, ct_tool)
        assert any(
            "ama_aes256_gcm_encrypt claims constant time and has no entry" in e for e in errors
        )

    def test_re_adding_a_withdrawn_claim_fails(
        self, gate: ModuleType, ct_tool: ModuleType, tree: Path
    ) -> None:
        _edit(
            tree / HEADER,
            " * @brief Sign a message\n",
            " * @brief Sign a message (constant-time)\n",
        )
        errors = _errors(gate, tree, ct_tool)
        assert any("ama_sign claims constant time again" in e for e in errors)

    def test_a_withdrawal_the_header_does_not_state_fails(
        self, gate: ModuleType, ct_tool: ModuleType, tree: Path
    ) -> None:
        _edit(
            tree / HEADER,
            " * was false for ML-DSA-65 and was withdrawn on 2026-11-22 (INVARIANT-16).",
            " * was false for ML-DSA-65 (INVARIANT-16).",
        )
        errors = _errors(gate, tree, ct_tool)
        assert any("ama_sign's documentation does not say" in e for e in errors)

    def test_a_removed_claim_left_in_the_registry_fails(
        self, gate: ModuleType, ct_tool: ModuleType, tree: Path
    ) -> None:
        _edit(
            tree / HEADER,
            " * @brief Constant-time conditional swap",
            " * @brief Conditional swap",
        )
        errors = _errors(gate, tree, ct_tool)
        assert any("ama_consttime_swap no longer claims constant time" in e for e in errors)

    def test_a_lane_renamed_away_fails(
        self, gate: ModuleType, ct_tool: ModuleType, tree: Path
    ) -> None:
        _edit(tree / DUDECT, '        "ama_base64_decode",\n', '        "base64 decode",\n')
        errors = _errors(gate, tree, ct_tool)
        assert any("lane 'ama_base64_decode' is not registered" in e for e in errors)

    def test_a_lane_that_never_calls_the_function_fails(
        self, gate: ModuleType, ct_tool: ModuleType, tree: Path
    ) -> None:
        registry = dict(gate.REGISTRY)
        registry["ama_base64_decode"] = replace(
            registry["ama_base64_decode"], lanes=("ama_consttime_copy",)
        )
        errors = _errors(gate, tree, ct_tool, registry=registry)
        assert any(
            "lane 'ama_consttime_copy'" in e and "never calls ama_base64_decode" in e
            for e in errors
        )

    def test_an_info_only_lane_with_no_blocking_target_fails(
        self, gate: ModuleType, ct_tool: ModuleType, tree: Path
    ) -> None:
        registry = dict(gate.REGISTRY)
        registry["ama_secp256k1_point_mul"] = replace(
            registry["ama_secp256k1_point_mul"], counts=(), taints=()
        )
        errors = _errors(gate, tree, ct_tool, registry=registry)
        assert any("every lane is info-only" in e for e in errors)

    def test_a_driver_that_never_calls_the_function_fails(
        self, gate: ModuleType, ct_tool: ModuleType, tree: Path
    ) -> None:
        registry = dict(gate.REGISTRY)
        registry["ama_base64_encode"] = replace(registry["ama_base64_encode"], counts=("ghash",))
        errors = _errors(gate, tree, ct_tool, registry=registry)
        assert any("count driver 'ghash' never calls ama_base64_encode" in e for e in errors)

    def test_an_unknown_target_fails(
        self, gate: ModuleType, ct_tool: ModuleType, tree: Path
    ) -> None:
        registry = dict(gate.REGISTRY)
        registry["ama_base64_encode"] = replace(registry["ama_base64_encode"], taints=("nope",))
        errors = _errors(gate, tree, ct_tool, registry=registry)
        assert any("taint target 'nope' does not exist" in e for e in errors)

    def test_a_forwarder_that_is_not_one_fails(
        self, gate: ModuleType, ct_tool: ModuleType, tree: Path
    ) -> None:
        registry = dict(gate.REGISTRY)
        registry["ama_ml_kem_decapsulate"] = replace(
            registry["ama_ml_kem_decapsulate"], via=("ama_kyber_encapsulate",)
        )
        errors = _errors(gate, tree, ct_tool, registry=registry)
        assert any("via ama_kyber_encapsulate" in e for e in errors)

    def test_a_claim_attached_to_nothing_fails(
        self, gate: ModuleType, ct_tool: ModuleType, tree: Path
    ) -> None:
        path = tree / "include" / "ama_cpuid.h"
        text = path.read_text(encoding="utf-8")
        path.write_text(text + "\n/* Everything here runs in constant time. */\n", encoding="utf-8")
        errors = _errors(gate, tree, ct_tool)
        assert any("names no public function" in e for e in errors)


def test_the_forwarder_the_registry_relies_on_is_one(gate: ModuleType) -> None:
    sources = sorted((REPO_ROOT / "src" / "c").rglob("*.c"))
    assert gate.forwarder_ok(sources, "ama_kyber_decapsulate", "ama_ml_kem_decapsulate")
    assert not gate.forwarder_ok(sources, "ama_kyber_encapsulate", "ama_ml_kem_decapsulate")


def test_every_registered_lane_runs_in_the_dudect_workflow() -> None:
    """The lanes live in test_dudect, which dudect.yml runs on every trigger."""
    workflow = (REPO_ROOT / ".github" / "workflows" / "dudect.yml").read_text(encoding="utf-8")
    assert "./build/bin/test_dudect --measurements" in workflow


def test_ci_runs_the_gate() -> None:
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "python tools/check_ct_claims.py" in workflow
