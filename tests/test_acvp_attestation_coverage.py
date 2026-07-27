# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
The compliance attestation must describe the coverage that actually exists.

``docs/compliance/acvp_attestation.json`` named ML-DSA-65 and ML-KEM-1024 only,
while the library implements and validates all six PQ parameter sets and three
NIST curves. That is a document *under*-describing its evidence — the opposite
of the usual compliance failure, and still a defect: a reader takes the
attestation as the coverage map, and a maintainer takes it as the list of things
that must keep passing.

Fixing it by adding the new sets to the attestation proper would have been
worse. The `algorithms` array is an immutable ACVP self-attestation: 1,215
vectors against ACVP-Server release tag ``v1.1.0.42``, reproducible byte-for-byte
by an auditor and gated by ``EXPECTED_VECTORS``. The new sets do not have that
property — ML-KEM-512/768 are validated against *Wycheproof*, which is not ACVP
at all, and ML-DSA-44/87 came from ACVP-Server's mutable ``master``. Merging them
would have stated that ML-KEM-512 is ACVP-attested when it is not, which
INVARIANT-16 (Honest Compliance and Audit Claims) forbids.

So the coverage lives in ``additional_validated_coverage``, separately and with
each entry's real source, and these tests keep it true: every corpus it names
exists, every record count matches the file, every gate it names is a real test,
and nothing in that list claims ACVP attestation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
ATTESTATION = REPO_ROOT / "docs" / "compliance" / "acvp_attestation.json"

DATA: dict[str, Any] = json.loads(ATTESTATION.read_text())
COVERAGE: list[dict[str, Any]] = DATA.get("additional_validated_coverage", [])


def _record_count(path: Path) -> int:
    """Records in a ``.kat`` file, counted by its per-record leading field."""
    markers = ("seed = ", "d = ")
    text = path.read_text().splitlines()
    for marker in markers:
        found = sum(1 for line in text if line.startswith(marker))
        if found:
            return found
    return 0


def test_the_coverage_map_is_not_empty() -> None:
    """An emptied map would make every test below pass vacuously."""
    assert COVERAGE, "additional_validated_coverage is missing or empty"
    assert len(COVERAGE) >= 5, f"only {len(COVERAGE)} coverage entries"


def test_the_immutable_attestation_is_untouched() -> None:
    """The 1,215-vector attestation is pinned by an EXPECTED_VECTORS floor in
    acvp_validation.yml. Adding coverage must not perturb it."""
    assert DATA["acvp_ref"] == "v1.1.0.42"
    assert DATA["total_vectors_tested"] == 1215
    assert DATA["total_vectors_failed"] == 0
    assert len(DATA["algorithms"]) == 12


@pytest.mark.parametrize("entry", COVERAGE, ids=[e["name"] for e in COVERAGE])
def test_every_coverage_entry_names_a_real_corpus(entry: dict[str, Any]) -> None:
    for part in entry["corpus"].split(" + "):
        path = REPO_ROOT / part.strip()
        assert path.exists(), f"{entry['name']}: {part} does not exist"


#: Entries whose corpus is a single ``.kat`` file, so the record count is
#: directly re-derivable. The composite entries (Wycheproof plus an RFC corpus)
#: have their counts checked by ``tools/check_documented_counts.py`` against the
#: Wycheproof manifest instead.
_SINGLE_KAT = [e for e in COVERAGE if e["corpus"].endswith(".kat") and " + " not in e["corpus"]]


@pytest.mark.parametrize("entry", _SINGLE_KAT, ids=[e["name"] for e in _SINGLE_KAT])
def test_every_record_count_matches_the_corpus(entry: dict[str, Any]) -> None:
    """The number in the document is re-derived from the file, not trusted.

    This is the check that would have caught "301 tests" in the key-format
    documentation, applied to a compliance artefact where a stale number is
    considerably more consequential.
    """
    path = REPO_ROOT / entry["corpus"]
    actual = _record_count(path)
    assert actual == entry["records"], (
        f"{entry['name']}: the attestation says {entry['records']} records, "
        f"{entry['corpus']} has {actual}"
    )


def test_the_single_corpus_list_is_not_empty() -> None:
    """The count check above is parametrised over this; an empty list would make
    it disappear silently."""
    assert len(_SINGLE_KAT) >= 4, f"only {len(_SINGLE_KAT)} single-corpus entries"


@pytest.mark.parametrize("entry", COVERAGE, ids=[e["name"] for e in COVERAGE])
def test_every_gate_names_a_test_that_exists(entry: dict[str, Any]) -> None:
    """A named gate that does not exist is a compliance claim with no evidence."""
    for gate in entry["gate"].split("; "):
        module, _, test_name = gate.partition("::")
        path = REPO_ROOT / module.strip()
        assert path.is_file(), f"{entry['name']}: gate module {module} does not exist"
        if test_name:
            source = path.read_text()
            assert f"def {test_name}" in source, f"{entry['name']}: {module} has no {test_name}"


@pytest.mark.parametrize("entry", COVERAGE, ids=[e["name"] for e in COVERAGE])
def test_nothing_in_the_coverage_map_claims_acvp_attestation(entry: dict[str, Any]) -> None:
    """The load-bearing honesty check.

    Every entry here is validated but *not* ACVP-attested, and each must say why.
    If one ever becomes genuinely attestable — an immutable upstream ref plus a
    matching EXPECTED_VECTORS bump — it belongs in the `algorithms` array, not
    here with the flag flipped.
    """
    assert entry["acvp_attested"] is False, (
        f"{entry['name']}: claims ACVP attestation from the non-attested list. "
        "Promote it into `algorithms` with an immutable ref, or leave the flag "
        "false."
    )
    assert entry[
        "reason_not_attested"
    ].strip(), f"{entry['name']}: no reason given for not being attested"


def test_every_implemented_pq_parameter_set_appears_somewhere() -> None:
    """The gap that started this: the document named two of six PQ sets.

    Derived from the library's own registry rather than a hand-written list, so
    a parameter set added tomorrow fails this until it is documented.
    """
    import ama_cryptography.key_formats as kf

    described = " ".join(
        [a["parameter_set"] for a in DATA["algorithms"]] + [e["parameter_set"] for e in COVERAGE]
    )
    missing = [
        name for name, alg in kf.ALGORITHMS.items() if alg.kind == "pq" and name not in described
    ]
    assert not missing, (
        f"the compliance attestation describes no coverage for {missing}. Every "
        "implemented parameter set must appear, either as an ACVP-attested "
        "algorithm or in additional_validated_coverage with its real source."
    )


def test_every_implemented_nist_curve_appears() -> None:
    described = " ".join(e["parameter_set"] for e in COVERAGE)
    for curve in ("secp256r1", "secp384r1", "secp521r1"):
        assert curve in described, f"{curve} has no described validation coverage"
