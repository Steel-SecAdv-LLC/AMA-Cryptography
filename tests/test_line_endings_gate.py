#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Tests for the checkout byte-identity gate (``tools/check_line_endings.py``).

The gate exists because several of this repository's controls measure the bytes
on disk — corpus digests, structural record sizes, reproducible-build artefact
comparison, and the note detector's fixed 8 KiB sample window — and git's
default configuration on Windows rewrites those bytes on checkout.  That
divergence failed all ten Windows CI jobs on this branch.

Both directions are pinned here, because a gate that only ever reports "clean"
is indistinguishable from one that has stopped working:

* **Detection** — a CRLF or mixed blob in the index is reported, and so is a
  tree where the ``text`` attribute no longer resolves to unset (i.e. the
  ``* -text`` rule was narrowed or removed).
* **Non-detection** — binary blobs are exempt (two fuzzer seed corpora carry
  CRLF as opaque input data), and this repository as it stands passes.

The rejection direction is exercised against synthetic records rather than a
committed defective file, on purpose: committing a CRLF blob to prove the gate
notices CRLF blobs would be the very drift the gate exists to prevent.
"""

from __future__ import annotations

import subprocess  # nosec B404 -- fixed-argv git invocations only, never a shell (EOL-001)
from pathlib import Path

from tools.check_line_endings import (
    EolRecord,
    check_attributes,
    check_records,
    main,
    parse_eol_output,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _record(path: str, index_eol: str = "lf") -> EolRecord:
    return EolRecord(index_eol=index_eol, worktree_eol=index_eol, attrs="-text", path=path)


class TestParsing:
    """``git ls-files --eol`` output is column-padded; the path may contain spaces."""

    def test_parses_the_documented_shape(self) -> None:
        text = "i/lf    w/lf    attr/-text            \tama_cryptography/monitoring.py\n"
        (record,) = parse_eol_output(text)
        assert record.index_eol == "lf"
        assert record.worktree_eol == "lf"
        assert record.attrs == "-text"
        assert record.path == "ama_cryptography/monitoring.py"

    def test_path_containing_spaces_survives(self) -> None:
        text = "i/lf    w/lf    attr/            \tdocs/a file with spaces.md\n"
        (record,) = parse_eol_output(text)
        assert record.path == "docs/a file with spaces.md"

    def test_blank_and_malformed_lines_are_skipped(self) -> None:
        assert parse_eol_output("\n   \nnot-a-record\ni/lf w/lf\n") == []

    def test_real_repository_output_parses_completely(self) -> None:
        # The parser must not silently drop records: a gate that parses half
        # the tree reports clean for the half it never saw.
        out = subprocess.run(  # nosec B603 -- fixed argv, no shell, trusted git binary (EOL-001)
            ["git", "ls-files", "--eol"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        ).stdout
        records = parse_eol_output(out)
        assert len(records) == len([ln for ln in out.splitlines() if ln.strip()])
        assert all(r.path for r in records)


class TestDetectsDirtyBlobs:
    def test_crlf_blob_is_reported(self) -> None:
        (violation,) = check_records([_record("docs/GUIDE.md", "crlf")])
        assert violation.path == "docs/GUIDE.md"
        assert "CRLF" in violation.reason

    def test_mixed_blob_is_reported(self) -> None:
        (violation,) = check_records([_record("docs/GUIDE.md", "mixed")])
        assert "MIXED" in violation.reason

    def test_lone_cr_blob_is_reported(self) -> None:
        assert check_records([_record("docs/GUIDE.md", "cr")])

    def test_one_dirty_file_among_many_clean_ones_is_still_found(self) -> None:
        records = [_record(f"a/{i}.py") for i in range(200)]
        records.insert(137, _record("a/needle.md", "crlf"))
        (violation,) = check_records(records)
        assert violation.path == "a/needle.md"


class TestExemptions:
    def test_binary_blob_with_crlf_data_is_exempt(self) -> None:
        # fuzz/seed_corpus/fuzz_ed25519/sequential_32 genuinely contains \r\n
        # as input octets.  A seed corpus that had to avoid a byte value would
        # be a worse corpus.
        seed = "fuzz/seed_corpus/fuzz_ed25519/sequential_32"
        assert check_records([_record(seed, "-text")]) == []

    def test_file_without_any_terminator_is_clean(self) -> None:
        assert check_records([_record("ama_cryptography/py.typed", "none")]) == []

    def test_lf_is_clean(self) -> None:
        assert check_records([_record("README.md", "lf")]) == []


class TestDetectsDisabledMechanism:
    """The blanket ``* -text`` rule is the fix; removing it must be noticed."""

    def test_unspecified_text_attribute_is_reported(self) -> None:
        records = [_record("README.md")]
        (violation,) = check_attributes({"README.md": "unspecified"}, records)
        assert "unspecified" in violation.reason
        assert ".gitattributes" in violation.reason

    def test_text_set_is_reported(self) -> None:
        # `text` set (rather than unset) means git normalises on commit and
        # converts on checkout — the platform divergence returns.
        assert check_attributes({"README.md": "set"}, [_record("README.md")])

    def test_text_auto_is_reported(self) -> None:
        assert check_attributes({"README.md": "auto"}, [_record("README.md")])

    def test_unset_is_accepted(self) -> None:
        assert check_attributes({"README.md": "unset"}, [_record("README.md")]) == []

    def test_binary_paths_are_exempt_from_the_attribute_check(self) -> None:
        records = [_record("assets/logo.png", "-text")]
        assert check_attributes({"assets/logo.png": "unspecified"}, records) == []


class TestThisRepository:
    def test_repository_passes_the_gate(self) -> None:
        assert main([]) == 0

    def test_gate_is_not_vacuous(self) -> None:
        # A gate that inspected nothing would also return 0.  Assert it saw a
        # realistic share of the tree.
        out = subprocess.run(  # nosec B603 -- fixed argv, no shell, trusted git binary (EOL-001)
            ["git", "ls-files", "--eol"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        ).stdout
        assert len(parse_eol_output(out)) > 300

    def test_every_tracked_text_blob_is_lf(self) -> None:
        # The property, asserted directly against the real index rather than
        # only through the checker that is meant to assert it.
        out = subprocess.run(  # nosec B603 -- fixed argv, no shell, trusted git binary (EOL-001)
            ["git", "ls-files", "--eol"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        ).stdout
        dirty = [r.path for r in parse_eol_output(out) if r.index_eol in {"crlf", "cr", "mixed"}]
        assert dirty == []

    def test_the_byte_sensitive_corpora_resolve_to_no_conversion(self) -> None:
        # Named explicitly: these are the paths whose bytes are hashed or
        # windowed, so their attribute is the one that must never regress.
        for path in (
            "wycheproof_vectors/manifest.json",
            "IMPLEMENTATION_GUIDE.md",
            "INVARIANTS.md",
            "CHANGELOG.md",
        ):
            value = (
                subprocess.run(  # nosec B603 -- fixed argv, no shell, trusted git binary (EOL-001)
                    ["git", "check-attr", "text", "--", path],
                    cwd=str(REPO_ROOT),
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=True,
                ).stdout.strip()
            )
            assert value.endswith(": unset"), f"{path} resolves to {value!r}"
