# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Automated provenance checks for the vendored key-format conformance corpus.

``tools/build_keyformat_corpus.py`` re-derives ``tests/kat/keyformats/`` from
the documents the bytes came from. Its ``--verify`` half runs offline and
checks the properties ``tests/test_key_formats.py`` cannot: that every corpus
file is *present*, that each one records the exact document revision it was
extracted from, that every record's PEM body is well-formed DER, and that the
deliberately-inconsistent PQ records still exist.

Until this module was written that verifier ran only when a human typed the
command. ``tools/refresh_wycheproof_corpus.py`` has had
``tests/test_wycheproof_corpus_provenance.py`` driving its offline half since
the Wycheproof corpus landed; this is the same contract for the same class of
artefact, and it is deliberately written to the same shape.

Both directions are pinned. A provenance check that cannot fail is not a
provenance check, so every class of problem the verifier reports is reproduced
here against a scratch copy of the corpus and required to be caught.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import shutil
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "build_keyformat_corpus.py"
CORPUS = REPO_ROOT / "tests" / "kat" / "keyformats"


def _load_tool() -> ModuleType:
    """Load tools/build_keyformat_corpus.py — tools/ is not on sys.path, so
    importlib.util is the cleanest handle (mirrors tests/test_headers.py)."""
    spec = importlib.util.spec_from_file_location("build_keyformat_corpus", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    return _load_tool()


@pytest.fixture
def scratch(tmp_path: Path) -> Path:
    """A writable copy of the real corpus, so failure directions are exercised
    against the real bytes rather than a synthetic stand-in."""
    target = tmp_path / "keyformats"
    shutil.copytree(CORPUS, target)
    return target


# ---------------------------------------------------------------------------
# The anchor: the vendored corpus verifies clean, on every run, without network
# ---------------------------------------------------------------------------
def test_vendored_corpus_verifies_offline(tool: ModuleType) -> None:
    problems = tool.verify_offline()
    assert problems == [], "the vendored key-format corpus did not verify:\n" + "\n".join(problems)


def test_the_scratch_copy_also_verifies_clean(tool: ModuleType, scratch: Path) -> None:
    """The failure-direction tests below all corrupt ``scratch``; if a pristine
    copy did not verify, every one of them would pass for the wrong reason."""
    assert tool.verify_offline(scratch) == []


def test_the_cli_entry_point_agrees_with_the_library_one(
    tool: ModuleType, scratch: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``report_offline`` is what CI runs; it must not diverge from what the
    tests drive. Checked in both directions — clean and dirty."""
    assert tool.report_offline(scratch) == 0
    (scratch / "rfc8410_okp.json").unlink()
    assert tool.report_offline(scratch) == 1
    assert "PROBLEM" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Failure directions — one per class of problem the verifier claims to catch
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "filename",
    sorted(("rfc9881_ml_dsa.json", "lamps_ml_kem.json", "rfc8410_okp.json", "jose_cose.json")),
)
def test_a_missing_corpus_file_is_caught(tool: ModuleType, scratch: Path, filename: str) -> None:
    (scratch / filename).unlink()
    problems = tool.verify_offline(scratch)
    assert any(filename in p and "missing" in p for p in problems), problems


def test_an_absent_source_revision_is_caught(tool: ModuleType, scratch: Path) -> None:
    """The provenance property proper: bytes whose origin revision is not
    recorded cannot be re-derived from the document they claim to come from."""
    path = scratch / "rfc9881_ml_dsa.json"
    data = json.loads(path.read_text())
    del data["source"]["revision"]
    path.write_text(json.dumps(data))
    problems = tool.verify_offline(scratch)
    assert any("source.revision" in p for p in problems), problems


def test_an_entirely_absent_source_block_is_caught(tool: ModuleType, scratch: Path) -> None:
    path = scratch / "lamps_ml_kem.json"
    data = json.loads(path.read_text())
    del data["source"]
    path.write_text(json.dumps(data))
    problems = tool.verify_offline(scratch)
    assert any("no 'source' block" in p for p in problems), problems


def test_corrupt_base64_is_caught(tool: ModuleType, scratch: Path) -> None:
    path = scratch / "rfc9881_ml_dsa.json"
    data = json.loads(path.read_text())
    data["records"][0]["pem_b64"] = "!!!not base64!!!"
    path.write_text(json.dumps(data))
    problems = tool.verify_offline(scratch)
    assert any("bad base64" in p for p in problems), problems


def test_a_body_that_is_not_der_is_caught(tool: ModuleType, scratch: Path) -> None:
    """Valid base64 of the wrong thing is the shape a page-furniture bug
    produces: it decodes cleanly and is not a key."""
    path = scratch / "rfc8410_okp.json"
    data = json.loads(path.read_text())
    data["records"][0]["pem_b64"] = base64.b64encode(b"RFC 8410  Ed25519").decode()
    path.write_text(json.dumps(data))
    problems = tool.verify_offline(scratch)
    assert any("DER SEQUENCE" in p for p in problems), problems


def test_an_empty_record_list_is_caught(tool: ModuleType, scratch: Path) -> None:
    path = scratch / "jose_cose.json"
    data = json.loads(path.read_text())
    data["records"] = []
    path.write_text(json.dumps(data))
    problems = tool.verify_offline(scratch)
    assert any("'records' is missing or empty" in p for p in problems), problems


@pytest.mark.parametrize("filename", ["rfc9881_ml_dsa.json", "lamps_ml_kem.json"])
def test_an_emptied_negative_corpus_is_caught(
    tool: ModuleType, scratch: Path, filename: str
) -> None:
    """The regression this check exists for.

    ``extract_pem_blocks`` once relabelled the deliberately-inconsistent
    Appendix C.4 keys as valid ones, because indented numbered list items
    matched the section-heading pattern. The negative corpus emptied itself and
    every gate consuming it went vacuous — while still reporting green, because
    the remaining records all parsed.
    """
    path = scratch / filename
    data = json.loads(path.read_text())
    data["records"] = [r for r in data["records"] if r.get("kind") != "inconsistent"]
    path.write_text(json.dumps(data))
    problems = tool.verify_offline(scratch)
    assert any("no 'inconsistent' records" in p for p in problems), problems


# ---------------------------------------------------------------------------
# The tool's own expectations must stay tied to what is on disk
# ---------------------------------------------------------------------------
def test_every_expected_json_file_is_actually_produced(tool: ModuleType) -> None:
    """``EXPECTED_JSON`` drives the presence check, and ``SOURCES`` plus the
    transcribed ``JOSE_COSE`` block drive generation. If they drift apart the
    presence check either demands a file nothing writes or ignores one that
    exists."""
    generated = set(tool.SOURCES) | {"jose_cose.json"}
    assert set(tool.EXPECTED_JSON) == generated
    on_disk = {p.name for p in CORPUS.glob("*.json")}
    assert set(tool.EXPECTED_JSON) == on_disk


def test_the_corpus_contains_no_third_party_key_material(tool: ModuleType) -> None:
    """Every vendored record traces to a standards document, and nothing else.

    This corpus once carried key files generated by another cryptographic
    product, as a stand-in for the EC examples RFC 5915 and RFC 5480 do not
    publish. RFC 9500 §2.3 supplies those directly, so the stand-in is gone —
    and this asserts it stays gone, because "just this once, to cover a gap" is
    exactly how it arrived the first time. Where a document still publishes
    nothing, the substitute is ``tests/ref_keyformat.py``: a second encoder
    written from the RFCs' own ASN.1, which is AMA's work.
    """
    for filename in tool.EXPECTED_JSON:
        data = json.loads((CORPUS / filename).read_text())
        url = data["source"].get("url", "")
        assert any(
            host in url for host in ("rfc-editor.org", "ietf.org")
        ), f"{filename} claims a source outside the RFC/IETF archives: {url!r}"
    strays = [p.name for p in CORPUS.iterdir() if p.is_dir()]
    assert strays == [], (
        f"unexpected subdirectories in the corpus: {strays}. Every record lives "
        "in a JSON file naming the document it came from."
    )
