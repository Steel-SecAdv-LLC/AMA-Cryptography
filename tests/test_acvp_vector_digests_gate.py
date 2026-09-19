# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The ACVP projections the harness validates against must be the attested bytes.

``nist_vectors/fetch_vectors.py`` pinned its download to the ACVP-Server tag
``v1.1.0.42`` and to nothing else.  A tag is a name for a snapshot, not a fix on
its bytes; a file already on disk was used as found; and the fetcher
re-serialised what arrived, so the on-disk bytes could never have been compared
with upstream.  ``docs/compliance/acvp_vector_digests.json`` now pins the bytes,
and ``tools/acvp_vector_pin.py`` is what refuses anything else — in the
fetcher before a write, in the harness before a read, and in the workflow
between the two.

These tests hold three independently produced records to agreement, pin a few
digests in this source away from the manifest so a regenerated manifest alone
cannot make a corrupted corpus verify, and drive every refusal with a negative
control: bytes that do not match are not written, a local file that does not
match is not trusted, a foreign ref is not accepted, the harness refuses a
tampered projection, and the pin cannot be moved from inside CI.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import acvp_vector_pin as acvp_manifest  # noqa: E402 -- path insert above (ACVP-001)

MANIFEST_PATH = REPO_ROOT / "docs" / "compliance" / "acvp_vector_digests.json"
ATTESTATION_PATH = REPO_ROOT / "docs" / "compliance" / "acvp_attestation.json"
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "acvp_validation.yml"
PROVENANCE_PATH = REPO_ROOT / "tests" / "kat" / "PROVENANCE.json"
ML_KEM_DERIVATIVE = REPO_ROOT / "tests" / "kat" / "fips203" / "acvp" / "ml_kem_acvp_v1.1.0.42.json"

#: Digests pinned HERE, away from the manifest.  Regenerating the manifest over
#: a corrupted or re-cut corpus leaves these assertions failing; the same shape
#: ``tests/test_vector_provenance_gate.py`` uses for the vendored vectors.  Four
#: files spanning three standards, including the two whose digests other
#: records in this tree carry independently.
ANCHOR_DIGESTS: dict[str, tuple[str, int]] = {
    "SHA3-256-2.0.json": (
        "dba4689436c7e440e61dc517210def3e8e09e50c0e9eff29ea66d89bdd0f2c63",
        1217364,
    ),
    "ML-KEM-keyGen-FIPS203.json": (
        "d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b",
        558841,
    ),
    "ML-DSA-sigVer-FIPS204.json": (
        "85827fd9f058d617b956301d342f2792d66ff188987ccce87f014f0bdb282457",
        4523114,
    ),
    "SLH-DSA-sigVer-FIPS205.json": (
        "a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792",
        30731848,
    ),
}


def _load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


fetcher = _load_script("acvp_gate_fetch_vectors", REPO_ROOT / "nist_vectors" / "fetch_vectors.py")
harness = _load_script("acvp_gate_run_vectors", REPO_ROOT / "nist_vectors" / "run_vectors.py")


@pytest.fixture(scope="module")
def manifest() -> acvp_manifest.Manifest:
    return acvp_manifest.load_manifest()


def _fake_manifest(entries: dict[str, bytes], ref: str = "v1.1.0.42") -> acvp_manifest.Manifest:
    """A manifest over small synthetic projections, for the negative controls."""
    return acvp_manifest.Manifest(
        acvp_ref=ref,
        base_url=acvp_manifest.base_url_for_ref(ref),
        entries={
            name: acvp_manifest.Entry(
                name=name,
                algo_dir=name.removesuffix(".json"),
                sha256=hashlib.sha256(data).hexdigest(),
                size=len(data),
            )
            for name, data in entries.items()
        },
    )


# ---------------------------------------------------------------------------
# The three records agree, and the fetch list is exactly what is pinned
# ---------------------------------------------------------------------------
def test_the_manifest_pins_exactly_the_fetch_list(manifest: acvp_manifest.Manifest) -> None:
    listed = dict(fetcher.ACVP_FETCH_LIST)
    assert set(manifest.entries) == set(listed), (
        "the manifest and ACVP_FETCH_LIST disagree about which projections exist; "
        "a fetched file with no pin is validated against without a byte-level record"
    )
    for name, entry in manifest.entries.items():
        assert entry.algo_dir == listed[name], f"{name}: pinned from a different upstream directory"


def test_the_ref_is_locked_across_the_fetcher_the_harness_the_workflow_and_the_attestation(
    manifest: acvp_manifest.Manifest,
) -> None:
    workflow: dict[str, Any] = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    attestation = json.loads(ATTESTATION_PATH.read_text(encoding="utf-8"))
    refs = {
        "manifest": manifest.acvp_ref,
        "fetch_vectors.DEFAULT_ACVP_REF": fetcher.DEFAULT_ACVP_REF,
        "run_vectors._DEFAULT_ACVP_REF": harness._DEFAULT_ACVP_REF,
        "acvp_validation.yml env.ACVP_REF": str(workflow["env"]["ACVP_REF"]),
        "acvp_attestation.json acvp_ref": attestation["acvp_ref"],
    }
    assert len(set(refs.values())) == 1, f"the pinned ref is not one value: {refs}"


def test_the_base_url_is_https_and_names_an_immutable_ref(
    manifest: acvp_manifest.Manifest,
) -> None:
    assert manifest.base_url.startswith("https://")
    assert f"/{manifest.acvp_ref}/" in manifest.base_url
    for segment in acvp_manifest.MUTABLE_REF_SEGMENTS:
        assert segment not in manifest.base_url


@pytest.mark.parametrize(("name", "expected"), sorted(ANCHOR_DIGESTS.items()))
def test_anchor_digests_pinned_in_this_source_match_the_manifest(
    manifest: acvp_manifest.Manifest, name: str, expected: tuple[str, int]
) -> None:
    entry = manifest.entries[name]
    assert (entry.sha256, entry.size) == expected, (
        f"{name}: the manifest no longer carries the digest pinned in this test. "
        f"If the pin was deliberately advanced, update ANCHOR_DIGESTS in the same "
        f"commit; if it was not, the manifest was regenerated over the wrong bytes."
    )


def test_the_manifest_agrees_with_the_vendored_slh_dsa_projection(
    manifest: acvp_manifest.Manifest,
) -> None:
    """tests/kat/PROVENANCE.json pins the vendored copy of the same upstream file."""
    provenance = json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))
    vendored = provenance["files"]["tests/kat/fips205/SLH-DSA-sigVer-FIPS205.json"]
    entry = manifest.entries["SLH-DSA-sigVer-FIPS205.json"]
    assert (vendored["sha256"], vendored["bytes"]) == (entry.sha256, entry.size), (
        "the fetched SLH-DSA sigVer projection and the vendored copy under tests/kat "
        "claim the same upstream ref but not the same bytes"
    )


def test_the_manifest_agrees_with_the_ml_kem_derivative_source_digests(
    manifest: acvp_manifest.Manifest,
) -> None:
    """The ML-KEM derivative records the SHA-256 of each upstream input it was built from."""
    source = json.loads(ML_KEM_DERIVATIVE.read_text(encoding="utf-8"))["source"]
    assert source["keyGen_internalProjection_sha256"] == (
        manifest.entries["ML-KEM-keyGen-FIPS203.json"].sha256
    )
    assert source["encapDecap_internalProjection_sha256"] == (
        manifest.entries["ML-KEM-encapDecap-FIPS203.json"].sha256
    )


def test_the_manifest_is_where_the_provenance_gate_cannot_mistake_it_for_a_vector() -> None:
    """A .json under nist_vectors/ would be swept up as a published vector and
    demanded in PROVENANCE.json; the manifest lives beside the attestation whose
    numbers it underwrites instead."""
    assert MANIFEST_PATH.parent == ATTESTATION_PATH.parent
    assert acvp_manifest.MANIFEST_PATH == MANIFEST_PATH


# ---------------------------------------------------------------------------
# Negative controls on the fetcher
# ---------------------------------------------------------------------------
def test_a_download_with_the_wrong_digest_is_refused_and_not_written(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = _fake_manifest({"A.json": b'{"a": 1}\n'})
    monkeypatch.setattr(fetcher, "VECTORS_DIR", tmp_path)
    monkeypatch.setattr(fetcher, "ACVP_FETCH_LIST", [("A.json", "A")])
    monkeypatch.setattr(fetcher, "_load_manifest", lambda: fake)
    monkeypatch.delenv("ACVP_REF", raising=False)
    monkeypatch.setattr(fetcher, "fetch_acvp_file", lambda algo, fn: b'{"a": 2}\n')

    assert fetcher.fetch_acvp_vectors() == ["A"]
    assert not (tmp_path / "A.json").exists(), "bytes that failed the pin reached disk"


def test_a_download_that_matches_is_written_verbatim(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    body = b'{\n  "vsId": 1,\n  "testGroups": []\n}\n'
    fake = _fake_manifest({"A.json": body})
    monkeypatch.setattr(fetcher, "VECTORS_DIR", tmp_path)
    monkeypatch.setattr(fetcher, "ACVP_FETCH_LIST", [("A.json", "A")])
    monkeypatch.setattr(fetcher, "_load_manifest", lambda: fake)
    monkeypatch.delenv("ACVP_REF", raising=False)
    monkeypatch.setattr(fetcher, "fetch_acvp_file", lambda algo, fn: body)

    assert fetcher.fetch_acvp_vectors() == []
    assert (tmp_path / "A.json").read_bytes() == body, "the fetcher re-serialised upstream's bytes"


def test_a_local_file_that_does_not_match_is_not_trusted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    good = b'{"a": 1}\n'
    fake = _fake_manifest({"A.json": good})
    (tmp_path / "A.json").write_bytes(b'{"a": "edited"}\n')
    monkeypatch.setattr(fetcher, "VECTORS_DIR", tmp_path)
    monkeypatch.setattr(fetcher, "ACVP_FETCH_LIST", [("A.json", "A")])
    monkeypatch.setattr(fetcher, "_load_manifest", lambda: fake)
    monkeypatch.delenv("ACVP_REF", raising=False)

    # A fresh download that verifies replaces the edited copy...
    monkeypatch.setattr(fetcher, "fetch_acvp_file", lambda algo, fn: good)
    assert fetcher.fetch_acvp_vectors() == []
    assert (tmp_path / "A.json").read_bytes() == good

    # ...and one that does not leaves the step failed by name.
    (tmp_path / "A.json").write_bytes(b'{"a": "edited again"}\n')
    monkeypatch.setattr(fetcher, "fetch_acvp_file", lambda algo, fn: b'{"a": "still wrong"}\n')
    assert fetcher.fetch_acvp_vectors() == ["A"]


def test_a_local_file_that_matches_is_kept_without_a_fetch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    good = b'{"a": 1}\n'
    fake = _fake_manifest({"A.json": good})
    (tmp_path / "A.json").write_bytes(good)
    monkeypatch.setattr(fetcher, "VECTORS_DIR", tmp_path)
    monkeypatch.setattr(fetcher, "ACVP_FETCH_LIST", [("A.json", "A")])
    monkeypatch.setattr(fetcher, "_load_manifest", lambda: fake)
    monkeypatch.delenv("ACVP_REF", raising=False)

    def no_network(algo: str, fn: str) -> bytes:
        raise AssertionError("a verified local file must not be re-fetched")

    monkeypatch.setattr(fetcher, "fetch_acvp_file", no_network)
    assert fetcher.fetch_acvp_vectors() == []


def test_a_ref_the_manifest_was_not_taken_at_fails_closed_before_any_fetch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = _fake_manifest({"A.json": b'{"a": 1}\n'})
    monkeypatch.setattr(fetcher, "VECTORS_DIR", tmp_path)
    monkeypatch.setattr(fetcher, "ACVP_FETCH_LIST", [("A.json", "A")])
    monkeypatch.setattr(fetcher, "_load_manifest", lambda: fake)
    monkeypatch.setenv("ACVP_REF", "master")

    def no_network(algo: str, fn: str) -> bytes:
        raise AssertionError("no fetch may happen against a ref the pin does not cover")

    monkeypatch.setattr(fetcher, "fetch_acvp_file", no_network)
    assert fetcher.fetch_acvp_vectors() == ["A"]


def test_an_unpinned_entry_in_the_fetch_list_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = _fake_manifest({"A.json": b'{"a": 1}\n'})
    monkeypatch.setattr(fetcher, "VECTORS_DIR", tmp_path)
    monkeypatch.setattr(fetcher, "ACVP_FETCH_LIST", [("A.json", "A"), ("B.json", "B")])
    monkeypatch.setattr(fetcher, "_load_manifest", lambda: fake)
    monkeypatch.delenv("ACVP_REF", raising=False)
    monkeypatch.setattr(fetcher, "fetch_acvp_file", lambda algo, fn: b'{"a": 1}\n')
    assert fetcher.fetch_acvp_vectors() == ["B"]


@pytest.fixture
def real_manifest_untouched() -> Any:
    """Fail loudly if a test writes the real manifest — the defect this guards
    against was a definition-time default path that ignored the monkeypatch."""
    before = MANIFEST_PATH.read_bytes()
    yield None
    assert MANIFEST_PATH.read_bytes() == before, "a test rewrote the real manifest"


def test_the_pin_cannot_be_moved_from_inside_github_actions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, real_manifest_untouched: Any
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setattr(acvp_manifest, "MANIFEST_PATH", tmp_path / "manifest.json")

    def no_network(algo: str, fn: str) -> bytes:
        raise AssertionError("a refused refresh must not fetch")

    monkeypatch.setattr(fetcher, "fetch_acvp_file", no_network)
    assert fetcher.main(["--refresh-manifest"]) == 1
    assert not (tmp_path / "manifest.json").exists()


#: A shell line that RUNS the refresh: an optional interpreter, then the fetcher
#: by any path, then the flag.  Prose that names the flag inside a diagnostic
#: string (the summary step's error message does) is not an invocation.
_REFRESH_INVOCATION = re.compile(
    r"^\s*(?:python3?\s+)?(?:\S*/)?fetch_vectors\.py\b[^\n]*--refresh-manifest", re.M
)


def test_no_workflow_step_invokes_the_refresh() -> None:
    """Comments and messages may DESCRIBE the refresh; no step may run it."""
    for path in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")):
        document: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_id, job in (document.get("jobs") or {}).items():
            for step in job.get("steps") or []:
                assert not _REFRESH_INVOCATION.search(
                    str(step.get("run", ""))
                ), f"{path.name}:{job_id} moves the pin from CI; the pin is a reviewed record"


def test_the_invocation_pattern_recognises_a_real_invocation() -> None:
    """The negative control for the test above: the pattern must be able to fire."""
    assert _REFRESH_INVOCATION.search("  python3 nist_vectors/fetch_vectors.py --refresh-manifest")
    assert _REFRESH_INVOCATION.search("./fetch_vectors.py  --refresh-manifest\n")
    assert not _REFRESH_INVOCATION.search(
        'f"(re-pin with `nist_vectors/fetch_vectors.py --refresh-manifest`)"'
    )


def test_the_refresh_rewrites_the_manifest_from_what_arrived(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, real_manifest_untouched: Any
) -> None:
    body = b'{"new": true}\n'
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("ACVP_REF", "v9.9.9.9")
    monkeypatch.setattr(fetcher, "VECTORS_DIR", tmp_path)
    monkeypatch.setattr(fetcher, "ACVP_FETCH_LIST", [("A.json", "A")])
    monkeypatch.setattr(acvp_manifest, "MANIFEST_PATH", tmp_path / "manifest.json")
    monkeypatch.setattr(fetcher, "fetch_acvp_file", lambda algo, fn: body)

    assert fetcher.main(["--refresh-manifest"]) == 0
    written = acvp_manifest.load_manifest(tmp_path / "manifest.json")
    assert written.acvp_ref == "v9.9.9.9"
    assert written.base_url == acvp_manifest.base_url_for_ref("v9.9.9.9")
    assert written.entries["A.json"].sha256 == hashlib.sha256(body).hexdigest()
    assert (tmp_path / "A.json").read_bytes() == body


# ---------------------------------------------------------------------------
# Negative controls on the harness and the check CLI
# ---------------------------------------------------------------------------
def test_the_harness_refuses_a_tampered_projection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    good = b'{"testGroups": []}\n'
    fake = _fake_manifest({"A.json": good})
    monkeypatch.setattr(harness, "_MANIFEST", fake)
    (tmp_path / "A.json").write_bytes(b'{"testGroups": [{"tests": []}]}\n')
    with pytest.raises(acvp_manifest.AcvpVectorIntegrityError):
        harness._load_vector_file(tmp_path / "A.json")

    (tmp_path / "A.json").write_bytes(good)
    assert harness._load_vector_file(tmp_path / "A.json") == {"testGroups": []}


def test_the_harness_leaves_its_own_tracked_vectors_to_the_provenance_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """SHA-256-FIPS180-4.json and the AES-GCM file are not fetched; PROVENANCE.json pins them."""
    fake = _fake_manifest({"A.json": b"{}\n"})
    monkeypatch.setattr(harness, "_MANIFEST", fake)
    (tmp_path / "SHA-256-FIPS180-4.json").write_text('{"local": 1}', encoding="utf-8")
    assert harness._load_vector_file(tmp_path / "SHA-256-FIPS180-4.json") == {"local": 1}


def test_the_harness_refuses_to_run_against_a_ref_the_pin_does_not_cover(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(harness, "_MANIFEST", _fake_manifest({"A.json": b"{}\n"}))
    monkeypatch.setenv("ACVP_REF", "master")

    def no_library() -> Any:
        raise AssertionError("the library must not be loaded before the pin is checked")

    monkeypatch.setattr(harness, "load_library", no_library)
    assert harness.main() == 2


def test_the_check_cli_fails_on_a_missing_or_edited_projection(tmp_path: Path) -> None:
    good = b'{"a": 1}\n'
    fake = _fake_manifest({"A.json": good})
    manifest_path = tmp_path / "manifest.json"
    acvp_manifest.write_manifest(fake, manifest_path)
    vectors = tmp_path / "vectors"
    vectors.mkdir()

    argv = ["--check", "--manifest", str(manifest_path), "--vectors-dir", str(vectors)]
    assert acvp_manifest.main(argv) == 1, "a missing projection must fail the check"

    (vectors / "A.json").write_bytes(b'{"a": 2}\n')
    assert acvp_manifest.main(argv) == 1, "an edited projection must fail the check"

    (vectors / "A.json").write_bytes(good)
    assert acvp_manifest.main(argv) == 0


def test_a_malformed_manifest_is_an_error_not_a_default(tmp_path: Path) -> None:
    cases: dict[str, dict[str, Any]] = {
        "no files": {
            "acvp_ref": "v1",
            "base_url": acvp_manifest.base_url_for_ref("v1"),
            "files": {},
        },
        "moving ref": {
            "acvp_ref": "master",
            "base_url": acvp_manifest.base_url_for_ref("master"),
            "files": {"A.json": {"algo_dir": "A", "bytes": 1, "sha256": "0" * 64}},
        },
        "base_url not derived from ref": {
            "acvp_ref": "v1",
            "base_url": "https://example.invalid/x",
            "files": {"A.json": {"algo_dir": "A", "bytes": 1, "sha256": "0" * 64}},
        },
        "short digest": {
            "acvp_ref": "v1",
            "base_url": acvp_manifest.base_url_for_ref("v1"),
            "files": {"A.json": {"algo_dir": "A", "bytes": 1, "sha256": "0" * 63}},
        },
        "zero bytes": {
            "acvp_ref": "v1",
            "base_url": acvp_manifest.base_url_for_ref("v1"),
            "files": {"A.json": {"algo_dir": "A", "bytes": 0, "sha256": "0" * 64}},
        },
    }
    for label, payload in cases.items():
        path = tmp_path / f"{label.replace(' ', '_')}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(acvp_manifest.AcvpVectorIntegrityError):
            acvp_manifest.load_manifest(path)
        assert acvp_manifest.main(["--check", "--manifest", str(path)]) == 2, label
    assert acvp_manifest.main(["--check", "--manifest", str(tmp_path / "absent.json")]) == 2


def test_the_workflow_checks_the_pin_between_the_fetch_and_the_run() -> None:
    workflow: dict[str, Any] = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["acvp-vectors"]["steps"]
    runs = [str(step.get("run", "")) for step in steps]
    fetch = next(i for i, r in enumerate(runs) if "nist_vectors/fetch_vectors.py" in r)
    check = next(i for i, r in enumerate(runs) if "tools/acvp_vector_pin.py --check" in r)
    run = next(i for i, r in enumerate(runs) if "nist_vectors/run_vectors.py" in r)
    assert fetch < check < run, "the digest check must sit between the fetch and the harness run"
    summary = next(r for r in runs if "validation_summary.json" in r and "acvp_vector_digests" in r)
    assert "digest_manifest_mismatch" in summary
