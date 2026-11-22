# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for ``tools/check_ct_markers.py``.

Each case is a mutation of a copy of ``src/c``: a declassification point moved
above the write that computes its value (twice, through an assignment and
through an output parameter), a declassified variable reused for a later
value, a point stripped of its argument, a new point, and a removed optimizer
barrier.  The gate must fail on every one and pass on the tree.  A moved point
is the case the secret-taint gate cannot see -- Memcheck re-taints bytes a
later secret write touches -- so this gate is what makes it fail.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "tools" / "check_ct_markers.py"


@pytest.fixture(scope="module")
def gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_ct_markers", GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_ct_markers"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    shutil.copytree(REPO_ROOT / "src" / "c", tmp_path / "src" / "c")
    shutil.copytree(REPO_ROOT / "include", tmp_path / "include")
    return tmp_path


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert text.count(old) == 1, old
    path.write_text(text.replace(old, new), encoding="utf-8")


def _errors(gate: ModuleType, root: Path) -> list[str]:
    return list(gate.check(root, gate.DECLASSIFY_SITES, gate.BARRIER_SITES))


def test_the_tree_passes(gate: ModuleType) -> None:
    assert _errors(gate, REPO_ROOT) == []
    assert gate.main([]) == 0


def test_a_point_moved_above_its_assignment_fails(gate: ModuleType, tree: Path) -> None:
    path = tree / "src" / "c" / "ama_ascon.c"
    _edit(
        path,
        "    mismatch = ama_consttime_memcmp(computed_tag, tag,\n"
        "                                    AMA_ASCON_AEAD128_TAG_LEN);\n",
        "    AMA_CT_DECLASSIFY(&mismatch, sizeof(mismatch));\n"
        "    mismatch = ama_consttime_memcmp(computed_tag, tag,\n"
        "                                    AMA_ASCON_AEAD128_TAG_LEN);\n",
    )
    _edit(
        path,
        "     * constant time -- and the key, the state and both tags stay secret. */\n"
        "    AMA_CT_DECLASSIFY(&mismatch, sizeof(mismatch));\n",
        "     * constant time -- and the key, the state and both tags stay secret. */\n",
    )
    errors = _errors(gate, tree)
    assert any(
        "ama_ascon.c" in e and "`mismatch` is declassified and then written" in e for e in errors
    )


def test_a_point_moved_above_the_call_that_writes_it_fails(gate: ModuleType, tree: Path) -> None:
    """r and s reach nistp_sign_dispatch as its (non-const) output parameters."""
    path = tree / "src" / "c" / "ama_nistp.c"
    _edit(
        path,
        "    rc = nistp_sign_dispatch(c, digest, digest_len, private_key, flags, r, s);\n"
        "    if (rc == AMA_SUCCESS) {\n",
        "    AMA_CT_DECLASSIFY(r, c->nbytes);  /* public signature */\n"
        "    rc = nistp_sign_dispatch(c, digest, digest_len, private_key, flags, r, s);\n"
        "    if (rc == AMA_SUCCESS) {\n",
    )
    _edit(
        path,
        "        AMA_CT_DECLASSIFY(r, c->nbytes);\n        AMA_CT_DECLASSIFY(s",
        "        AMA_CT_DECLASSIFY(s",
    )
    errors = _errors(gate, tree)
    assert any(
        "ama_nistp.c" in e and "`r` is declassified and then written (`nistp_sign_dispatch" in e
        for e in errors
    )


def test_a_declassified_variable_reused_fails(gate: ModuleType, tree: Path) -> None:
    path = tree / "src" / "c" / "ama_kyber.c"
    _edit(
        path,
        "    AMA_CT_DECLASSIFY(&mismatch, sizeof(mismatch));\n    ama_secure_memzero(ss_enc",
        "    AMA_CT_DECLASSIFY(&mismatch, sizeof(mismatch));\n"
        "    mismatch |= ss_dec[0];\n    ama_secure_memzero(ss_enc",
    )
    errors = _errors(gate, tree)
    assert any(
        "ama_kyber.c" in e and "`mismatch` is declassified and then written" in e for e in errors
    )


def test_a_point_without_its_argument_fails(gate: ModuleType, tree: Path) -> None:
    path = tree / "src" / "c" / "ama_secp256k1.c"
    _edit(
        path,
        "    /* The range verdict is the return code: public by contract\n"
        "     * (internal/ama_ct_declassify.h).  The key stays secret. */\n",
        "",
    )
    errors = _errors(gate, tree)
    assert any(
        "ama_secp256k1.c" in e and "no comment stating why `ok` is public" in e for e in errors
    )


def test_a_new_point_changes_the_inventory(gate: ModuleType, tree: Path) -> None:
    path = tree / "src" / "c" / "ama_hkdf.c"
    path.write_text(
        path.read_text(encoding="utf-8")
        + "\nstatic void probe(int v) { /* public verdict */ AMA_CT_DECLASSIFY(&v, sizeof v); }\n",
        encoding="utf-8",
    )
    errors = _errors(gate, tree)
    assert any("ama_hkdf.c: 1 declassification point(s)" in e and "pins 0" in e for e in errors)


def test_a_removed_barrier_changes_the_inventory(gate: ModuleType, tree: Path) -> None:
    path = tree / "src" / "c" / "ama_consttime.c"
    text = path.read_text(encoding="utf-8")
    code = gate.blank_comments(text)
    start = code.index("ama_ct_value_barrier_u64(")
    end = start + len("ama_ct_value_barrier_u64")
    path.write_text(text[:start] + "(uint64_t)" + text[end:], encoding="utf-8")
    errors = _errors(gate, tree)
    assert any("ama_consttime.c: 0 optimizer barrier(s)" in e and "pins 1" in e for e in errors)


def test_const_parameters_are_reads(gate: ModuleType) -> None:
    sources = sorted((REPO_ROOT / "src" / "c").rglob("*.c"))
    table = gate.param_writability(sources)
    # kyber_gen_matrix(a, rho, transposed, P): writes `a`, reads `rho`.
    assert table["kyber_gen_matrix"][0] is True
    assert table["kyber_gen_matrix"][1] is False


def test_ci_runs_the_gate() -> None:
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "python tools/check_ct_markers.py" in workflow
