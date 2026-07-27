#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
The Python parser fuzz harness must itself work (INVARIANT-33, Python lane).

``fuzz/python/fuzz_key_formats.py`` runs in ``fuzzing.yml`` for a time budget,
which means nothing in the ordinary test suite would notice if it quietly
stopped detecting anything: a harness whose contract check had been broken
would run its millions of executions and report success for ever. That is the
same failure shape INVARIANT-33 exists for — a harness nobody runs, or that runs
and cannot fail, is indistinguishable from one that finds nothing.

So this module drives the harness in-process: a short campaign must pass, the
seed corpus must actually be built, and each contract the harness claims to
enforce is violated deliberately and required to be caught.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import ama_cryptography.pqc_backends as pb  # noqa: E402 -- import follows the repo-root sys.path insert above (PFH-001)

HARNESS_PATH = REPO_ROOT / "fuzz" / "python" / "fuzz_key_formats.py"

pytestmark = pytest.mark.skipif(
    pb._native_lib is None, reason="native library not built"
)


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("fuzz_key_formats", HARNESS_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def harness() -> ModuleType:
    return _load()


# ---------------------------------------------------------------------------
# The harness runs, and finds nothing on a healthy tree
# ---------------------------------------------------------------------------
def test_a_short_campaign_passes(harness: ModuleType, tmp_path: Path) -> None:
    """Two seconds is not a fuzz campaign; it is a smoke test that the engine,
    the corpus and every target still work together."""
    assert harness.run_campaign(2.0, 0x9881_C4, tmp_path, None) == 0


def test_the_seed_corpus_is_built_and_covers_every_algorithm(
    harness: ModuleType
) -> None:
    """A fuzzer starting from an empty corpus spends its budget rediscovering
    that a key file begins with 0x30 — the defect the C lane had before its seed
    corpora were wired up."""
    import ama_cryptography.key_formats as kf

    seeds = harness.build_seed_corpus(None)
    assert len(seeds) > 100, f"only {len(seeds)} seeds"
    targets = {target for target, _ in seeds}
    assert "spki" in targets and "pkcs8" in targets and "cose_public" in targets

    # Every algorithm must contribute at least one seed, or a whole family is
    # being fuzzed only through cross-target confusion.
    blob = b"".join(data for _, data in seeds)
    for name in kf.ALGORITHMS:
        alg = kf.ALGORITHMS[name]
        oid_marker = kf.oid_from_string(alg.curve_oid if alg.kind == "ec" else alg.oid)
        assert oid_marker in blob, f"{name} contributes no seed"


def test_every_target_is_reachable(harness: ModuleType) -> None:
    """A target absent from ``TARGETS`` is never driven, however good it is."""
    assert set(harness.TARGETS) >= {
        "spki", "pkcs8", "pem_public", "pem_private",
        "cose_public", "cose_private", "cbor",
        "jwk_public", "jwk_private", "thumbprint",
    }
    for name, fn in harness.TARGETS.items():
        assert callable(fn), name


def test_the_mutator_never_raises_and_respects_the_size_cap(
    harness: ModuleType
) -> None:
    """A mutator that throws stops the campaign at the first awkward input, and
    a mutator that grows without bound turns the fuzzer into a memory test."""
    import random

    rng = random.Random(1234)
    pool = [b"", b"\x30\x03\x02\x01\x00", bytes(range(256))]
    for _ in range(5000):
        out = harness.mutate(rng, rng.choice(pool), pool)
        assert isinstance(out, bytes)
        assert len(out) <= harness.MAX_INPUT_BYTES


# ---------------------------------------------------------------------------
# Failure directions — each contract the harness claims, violated on purpose
# ---------------------------------------------------------------------------
def test_an_unexpected_exception_is_a_finding(
    harness: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The contract that found the UnicodeDecodeError and the TypeError."""
    def explode(_data: bytes) -> None:
        raise ZeroDivisionError("not a KeyFormatError")

    monkeypatch.setitem(harness.TARGETS, "spki", explode)
    with pytest.raises(harness.Finding, match="ZeroDivisionError"):
        harness.run_one("spki", b"anything")


def test_a_keyformaterror_is_not_a_finding(harness: ModuleType) -> None:
    """Refusing malformed input is the *correct* behaviour, not a crash."""
    harness.run_one("spki", b"\x30\x00")
    harness.run_one("pkcs8", b"not der at all")
    harness.run_one("cbor", b"\xff\xff\xff")


def test_a_non_canonical_acceptance_is_a_finding(
    harness: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The contract that found the trailing-0x1F PEM and the OKP `y` label."""
    import ama_cryptography.key_formats as kf

    public, _ = _make_ed25519()
    spki = public.to_spki()
    harness.run_one("spki", spki)  # honest input passes

    # A parser that accepted a second encoding of the same key must be caught.
    monkeypatch.setattr(kf, "load_spki", lambda _data: public)
    with pytest.raises(harness.Finding, match="non-canonical"):
        harness.run_one("spki", spki + b"\x00")


def test_a_slow_parse_is_a_finding(
    harness: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A quadratic blowup on a crafted length field should be attributable, not
    a CI timeout nobody explains."""
    import time

    def crawl(_data: bytes) -> None:
        time.sleep(harness.MAX_SECONDS_PER_INPUT + 0.2)

    monkeypatch.setitem(harness.TARGETS, "cbor", crawl)
    with pytest.raises(harness.Finding, match="ceiling"):
        harness.run_one("cbor", b"\xa0")


def test_a_finding_writes_a_reproducible_artifact(
    harness: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A campaign that found something must leave the input behind; a report
    without the bytes is not reproducible."""
    def explode(_data: bytes) -> None:
        raise RuntimeError("boom")

    monkeypatch.setitem(harness.TARGETS, "spki", explode)
    assert harness.run_campaign(1.0, 7, tmp_path, None) == 1
    artifacts = list(tmp_path.glob("crash-*.bin"))
    assert artifacts, "a finding produced no artifact"
    assert artifacts[0].read_bytes(), "the artifact is empty"


def test_replaying_an_artifact_reproduces_the_finding(
    harness: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--input`` is the documented reproduction path and must work."""
    path = tmp_path / "input.bin"
    path.write_text("-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n")
    assert harness.run_input(path) == 0
    assert "violates nothing" in capsys.readouterr().out


def test_the_attribute_and_label_exemptions_are_narrow(harness: ModuleType) -> None:
    """The two documented lossy fields, and only those.

    PKCS#8 attributes and unconsumed COSE labels are dropped on re-encoding,
    which the canonicality checks allow for explicitly. If that allowance ever
    widened, a real non-canonical acceptance would stop being a finding.
    """
    assert harness._COSE_EMITTED_LABELS == frozenset({1, -1, -2, -3, -4})
    # Stripping attributes must be surgical: an input without them is unchanged.
    plain = b"\x30\x06\x02\x01\x00\x04\x01\x00"
    assert harness._strip_pkcs8_attributes(plain) == plain
    # …and one with them loses exactly that element.
    with_attrs = b"\x30\x0b\x02\x01\x00\x04\x01\x00\xa0\x03\x02\x01\x01"
    stripped = harness._strip_pkcs8_attributes(with_attrs)
    assert stripped == plain, stripped.hex()


def _make_ed25519():  # type: ignore[no-untyped-def] -- annotating the two-tuple of key_formats dataclasses would force a module-scope import, before the native-library skipif runs (PFH-002)
    import ama_cryptography.key_formats as kf

    public, secret = pb.native_ed25519_keypair()
    return kf.PublicKey("Ed25519", public), kf.PrivateKey("Ed25519", secret[:32], public)
