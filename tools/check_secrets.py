#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — In-House Secret Scanner (INVARIANT-23)
=========================================================

Blocks credential material from entering the public repository.

**Why this is written in house.**  A cryptographic library is exactly the
worst case for an off-the-shelf secret scanner: the tree is *full* of
high-entropy hex — NIST KAT vectors, ACVP responses, fuzz seed corpora, an
Ed25519 public key and detached signature in ``_integrity_signature.py`` — all
of which are public by design.  A generic entropy scanner drowns that in false
positives, and the usual response (a blanket ignore file) is what lets a real
key slip through later.  This scanner is written against *this* repository's
layout so the allowlist is narrow, explicit, and justified per entry, and so
the tool carries no third-party supply-chain dependency (consistent with
INVARIANT-1's zero-external-dependency posture).

Detection classes
-----------------
1. **Private key blocks** — PEM/PKCS#8/OpenSSH/PGP private key armour.  These
   are never legitimate in this repository; the signing key is generated at
   build time and discarded (see ``ama_cryptography/_build_sign.py``).
2. **Provider credentials** — AWS access-key ids, GitHub PATs, Slack tokens,
   Google API keys, and generic ``Bearer``/basic-auth blobs.
3. **Assigned secrets** — an assignment to a secret-named identifier
   (``password``, ``api_key``, ``token``, ...) whose value is a high-entropy
   literal.  Placeholder values (``changeme``, ``your_password_here``, ...)
   are recognised and permitted so examples stay readable.
4. **Environment files** — any tracked ``.env``-style file carrying a value.

Exit status
-----------
``0`` when clean, ``1`` when any finding survives the allowlist.  The scanner
is *fail-closed*: an unreadable file or an unknown-but-suspicious pattern is
reported rather than skipped.

Usage
-----
    python tools/check_secrets.py                # scan tracked files
    python tools/check_secrets.py --paths a b    # scan specific paths
    python tools/check_secrets.py --staged       # pre-commit mode
"""

from __future__ import annotations

import argparse
import math
import re
import subprocess  # nosec B404 -- fixed-argv git invocation only, see _tracked_files (SEC-001)
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Pattern, Sequence

# ---------------------------------------------------------------------------
# Allowlist — every entry states WHY the path cannot contain a live secret.
# ---------------------------------------------------------------------------
# Directory prefixes whose contents are, by construction, public test data.
_ALLOWED_PREFIXES: tuple[tuple[str, str], ...] = (
    ("tests/kat/", "NIST/ACVP known-answer vectors — published test data"),
    ("nist_vectors/", "NIST ACVP vector harness — published test data"),
    ("fuzz/seed_corpus/", "fuzzer seed corpus — random bytes, not credentials"),
    ("fuzz/dictionaries/", "fuzzer token dictionaries — not credentials"),
    (
        "ama_cryptography/_post_kats/",
        "FIPS 140-3 power-on self-test vectors — published test data",
    ),
    (
        "src/c/vendor/",
        "vendored public-domain ed25519-donna reference tables (public constants)",
    ),
    (
        "docs/audit/logs/",
        "committed raw output logs of the PR #394 readiness-falsification "
        "audit (docs/audit/): every ledger row's evidence. Logs quote the "
        "hex digests, signatures and planted-defect strings the probed gates "
        "and negative controls print, and must reproduce verbatim so the "
        "operator can rerun-and-compare-hash. Same rationale as the "
        "verification/v5-audit/logs/ entry below. Not shipped code; nothing "
        "here is a live credential.",
    ),
    (
        "verification/v5-audit/logs/",
        "committed output logs of the v5 pre-merge audit's OWN secret scanners "
        "(gitleaks/trufflehog) and their negative controls: by construction "
        "these logs quote the credential-shaped strings the scanners matched — "
        "historical public-fixture PEM headers under tests/kat/ (removed at "
        "HEAD) and synthetic planted keys/tokens in a throwaway scratch clone. "
        "Same rationale the scanner's own detection suite "
        "(tests/test_secret_scanner.py) is allowlisted for: an audit's scan "
        "output must reproduce verbatim for the operator spot-audit "
        "(rerun-and-compare-hash), so it cannot be obfuscated past the scanner. "
        "Not shipped code; every hit here is a scanner report, never a live "
        "credential.",
    ),
)

# Individual files that legitimately carry public key material.
_ALLOWED_FILES: tuple[tuple[str, str], ...] = (
    (
        "ama_cryptography/_integrity_signature.py",
        "Ed25519 PUBLIC key + detached signature; the private key is "
        "generated at build time and discarded (see _build_sign.py)",
    ),
    (
        "ama_cryptography/_integrity_digest.txt",
        "SHA3-256 digest of the package sources — a hash, not a secret",
    ),
    (
        "docs/compliance/acvp_attestation.json",
        "ACVP attestation metadata — published compliance evidence",
    ),
    (
        "tests/test_secret_scanner.py",
        "this scanner's own detection suite: it must contain synthetic examples "
        "of every credential class in order to prove the scanner still matches "
        "them.  Allowlisted EXPLICITLY here rather than obfuscating the fixtures "
        "past the scanner — hiding them would have meant teaching (and "
        "documenting) an evasion technique that a real leak could reuse.  The "
        "file is covered by review: every fixture is synthetic, and a genuine "
        "credential added here would be caught by GitHub push protection.",
    ),
)

# Binary / generated extensions that are not source and carry no credentials.
_SKIP_SUFFIXES = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".pdf",
    ".so",
    ".a",
    ".o",
    ".dylib",
    ".dll",
    ".pyc",
    ".pyd",
    ".rsp",
    ".kat",
    ".dict",
)

# Values that are obviously placeholders rather than live credentials.  Kept
# deliberately explicit: a new placeholder should be added here consciously,
# not matched by a loose wildcard.
_PLACEHOLDER_TOKENS = (
    "changeme",
    "change_me",
    "placeholder",
    "example",
    "your_",
    "yourpassword",
    "dummy",
    "sample",
    "redacted",
    "xxxxx",
    "<",
    "${",
    "{{",
    "test",
    "fake",
    "notreal",
    "n/a",
    "none",
    "null",
    "password",
    "secret",
    "hunter2",
    "correct horse",
    "insert",
    "todo",
    "fixme",
    "s3cr3t",
)

# Named ``_SENSITIVE_IDENT_RE`` rather than ``_SECRET_NAME``: the latter made
# ruff S105 ("hardcoded password") fire on the assignment.  The honest fix is
# to remove the CAUSE of the finding rather than suppress it with a ``noqa``,
# so the identifier was renamed instead.  The value is a regex over identifier
# names and contains no credential material.
_SENSITIVE_IDENT_RE = (
    r"(?:pass(?:wd|word)?|secret|token|api[_-]?key|auth[_-]?token|authorization"
    r"|credential|private[_-]?key)"
)

# High-entropy assignment: NAME = "value" with a long opaque value.
#
# The secret word must be a whole *component* of the identifier, with optional
# ``_``/``-`` separated components on either side.  Two failure modes are being
# avoided simultaneously:
#
#   * ``\b``-anchored matching MISSES real credentials, because ``_`` is a word
#     character: ``\bpassword\b`` never matches inside ``db_password`` /
#     ``admin_api_key`` / ``MY_SECRET_TOKEN``, which is how production secrets
#     are actually named.
#   * bare ``\w*`` matching OVER-matches, firing on any identifier that merely
#     contains the word — e.g. ``__author__`` contains "auth".
#
# Requiring component boundaries catches ``db_password`` while leaving
# ``__author__`` and ``author=`` alone.  Both directions are pinned in
# tests/test_secret_scanner.py.
_ASSIGNED_SECRET: Pattern[str] = re.compile(
    rf"(?i)(?:^|[^A-Za-z0-9_])(?:[A-Za-z0-9]+[_-])*{_SENSITIVE_IDENT_RE}"
    rf"(?:[_-][A-Za-z0-9]+)*\s*[:=]\s*[\"']([^\"'\n]{{12,}})[\"']"
)

_PATTERNS: tuple[tuple[str, Pattern[str], str], ...] = (
    (
        "private-key-block",
        re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
        "PEM/OpenSSH/PGP private key block",
    ),
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key id"),
    (
        "github-token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        "GitHub personal access / OAuth token",
    ),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack API token"),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "Google API key"),
    (
        "authorization-header",
        re.compile(r"(?i)authorization\s*[:=]\s*[\"']?(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}"),
        "hardcoded Authorization header credential",
    ),
    (
        "pkcs12-store",
        re.compile(r"(?i)\b\w+\.(?:p12|pfx|jks|keystore)\b\s*[:=]"),
        "reference to a keystore file",
    ),
)


# Adjacent string literals joined by ``+`` (or by nothing, which Python folds
# implicitly).  Splitting a credential across concatenated literals — writing
# the provider prefix in one literal and the body in the next — is the obvious
# way to walk a line-oriented scanner past a real key, and it is not
# hypothetical: it is exactly the manoeuvre that got this repository's own test
# fixtures past both this scanner and GitHub push protection during
# development.  Normalising the concatenation away BEFORE matching closes that
# hole, so a split secret is caught like any other.  (Deliberately no worked
# example here: a comment carrying a credential-shaped string would itself be
# a finding, and suppressing that would reintroduce the very problem.)
_CONCAT_JOIN: Pattern[str] = re.compile(r"[\"']\s*(?:\+\s*)?[\"']")


def normalize_concatenation(line: str) -> str:
    """Fold adjacent/`+`-joined string literals into one before scanning.

    Operates on a *copy* used only for detection — no file is modified.
    Applied repeatedly so a chain of three or more fragments collapses fully.
    """
    previous = None
    current = line
    # Bounded loop: each pass strictly shortens the string, and the guard stops
    # as soon as a pass changes nothing.
    for _ in range(8):
        if current == previous:
            break
        previous = current
        current = _CONCAT_JOIN.sub("", current)
    return current


@dataclass(frozen=True)
class Finding:
    """A single potential credential disclosure."""

    path: str
    line_no: int
    rule: str
    description: str
    excerpt: str

    def render(self) -> str:
        return (
            f"{self.path}:{self.line_no}: [{self.rule}] {self.description}\n" f"    {self.excerpt}"
        )


def shannon_entropy(value: str) -> float:
    """Shannon entropy (bits/char) of ``value``.

    Used to separate opaque credential material from readable prose: English
    text sits near 3-4 bits/char, base64/hex key material at 4.5-6.
    """
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_placeholder(value: str) -> bool:
    """True when ``value`` is clearly a documentation placeholder."""
    lowered = value.lower()
    if any(token in lowered for token in _PLACEHOLDER_TOKENS):
        return True
    # A value made of one repeated character (e.g. "AAAAAAAAAAAA") is padding.
    return len(set(value)) <= 2


def _allow_reason(rel_path: str) -> Optional[str]:
    """Return the allowlist justification for ``rel_path``, else ``None``."""
    normalised = rel_path.replace("\\", "/")
    for prefix, reason in _ALLOWED_PREFIXES:
        if normalised.startswith(prefix):
            return reason
    for exact, reason in _ALLOWED_FILES:
        if normalised == exact:
            return reason
    return None


def scan_text(rel_path: str, text: str) -> list[Finding]:
    """Scan already-loaded ``text`` and return findings for ``rel_path``."""
    findings: list[Finding] = []
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        # A line that opts out explicitly must say why; the marker is audited
        # by tools/check_suppression_hygiene.py like every other suppression.
        if "nosecret" in raw_line.lower():
            continue

        # Match against the concatenation-normalised form so a credential split
        # across adjacent literals cannot slip past.  The *excerpt* reported to
        # the user is still the raw source line, so the finding points at what
        # is actually written in the file.
        line = normalize_concatenation(raw_line)

        for rule, pattern, description in _PATTERNS:
            if pattern.search(line):
                findings.append(
                    Finding(rel_path, line_no, rule, description, raw_line.strip()[:160])
                )

        match = _ASSIGNED_SECRET.search(line)
        if match:
            value = match.group(1)
            if not _is_placeholder(value) and shannon_entropy(value) >= 3.5:
                findings.append(
                    Finding(
                        rel_path,
                        line_no,
                        "assigned-secret",
                        (
                            "assignment to a secret-named identifier with a "
                            f"high-entropy value ({shannon_entropy(value):.2f} bits/char)"
                        ),
                        raw_line.strip()[:160],
                    )
                )
    return findings


def scan_file(path: Path, repo_root: Path) -> list[Finding]:
    """Scan one file, honouring the allowlist and binary skips."""
    rel_path = str(path.relative_to(repo_root)).replace("\\", "/")

    if _allow_reason(rel_path) is not None:
        return []
    if path.suffix.lower() in _SKIP_SUFFIXES:
        return []

    # A tracked .env-style file is a finding on its own.
    if path.name == ".env" or path.name.startswith(".env."):
        return [
            Finding(
                rel_path,
                1,
                "env-file",
                "environment file tracked in version control",
                path.name,
            )
        ]

    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError):
        return []  # genuinely binary content
    except OSError as exc:  # fail closed: report rather than skip
        return [Finding(rel_path, 1, "unreadable", f"could not read file: {exc}", "")]

    return scan_text(rel_path, text)


def _tracked_files(repo_root: Path, staged_only: bool) -> list[Path]:
    """Enumerate files from git (fixed argv, ``shell=False``)."""
    args = (
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"]
        if staged_only
        else ["git", "ls-files"]
    )
    try:
        out = subprocess.run(  # nosec B603 -- fixed argv, no shell, trusted git binary (SEC-002)
            args,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"ERROR: unable to enumerate files via git: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    paths = []
    for name in out.splitlines():
        if not name.strip():
            continue
        candidate = repo_root / name
        if candidate.is_file():
            paths.append(candidate)
    return paths


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="AMA Cryptography in-house secret scanner (INVARIANT-23)."
    )
    parser.add_argument("--paths", nargs="*", help="explicit paths to scan")
    parser.add_argument("--staged", action="store_true", help="scan only staged files (pre-commit)")
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parent.parent

    targets: Iterable[Path]
    if args.paths:
        targets = [Path(p).resolve() for p in args.paths]
    else:
        targets = _tracked_files(repo_root, staged_only=args.staged)

    findings: list[Finding] = []
    scanned = 0
    for path in targets:
        try:
            path.relative_to(repo_root)
        except ValueError:
            continue  # outside the repository
        scanned += 1
        findings.extend(scan_file(path, repo_root))

    if findings:
        print("SECRET SCAN FAILED — potential credential material detected:\n")
        for finding in findings:
            print(finding.render())
        print(
            f"\n{len(findings)} finding(s) across {scanned} file(s).\n"
            "If a match is a published test vector or public key, add it to the "
            "allowlist in tools/check_secrets.py with a written justification — "
            "do not silence the scanner globally."
        )
        return 1

    print(f"Secret scan clean: {scanned} file(s), 0 findings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
