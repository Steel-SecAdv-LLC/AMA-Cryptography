#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Run the vendored Project Wycheproof corpus against AMA Cryptography.

Wycheproof is a corpus of *adversarial* test vectors — the cases that
break implementations rather than the cases that exercise them.  Running
it against this library for the first time found a real defect in the
first primitive tested (Ed25519 signature malleability, RFC 8032 §5.1.7,
fixed in `src/c/internal/ama_ed25519_canonical.h`).  This harness is what
stops that from being a one-off: it is a standing gate over every vector,
run on every pull request.

Offline by construction.  The corpus is vendored under ``vectors/`` and
pinned by ``manifest.json`` — upstream commit, per-file SHA-256, and
per-file vector count.  Nothing is fetched at test time, and a vendored
file that is edited, truncated, or swapped fails the digest check before
a single vector runs.

Every vector lands in exactly one bucket
========================================

``PASSED``
    The library's behaviour matches the vector's expected result.

``FAIL``
    It does not.  Any FAIL fails the build, named with its tcId.

``ACCEPTABLE``
    The vector's own ``result`` is ``acceptable`` — Wycheproof's marker
    for a case where more than one behaviour is defensible — *and* the
    library's behaviour matches a policy in ``ACCEPTABLE_POLICIES``
    below.  Each policy carries the reason the behaviour is defensible
    and the exact number of vectors it covers.  There is no blanket
    "ignore acceptable" bucket: an ``acceptable`` vector that no policy
    claims is a FAIL, and a policy whose count changes is a FAIL.

``OUT_OF_SCOPE``
    The vector exercises an algorithm variant this library does not
    implement — AES-128-GCM, for instance, in a library that ships
    AES-256-GCM only.  Covered by ``SCOPE_POLICIES``, each with a
    reason and an exact expected count, for the same reason as above.

``POLICY_DIVERGENCE``
    The library deliberately disagrees with the corpus.  There is
    exactly one such policy today: Wycheproof scores a high-``s`` ECDSA
    signature ``valid``, because plain X9.62 ECDSA accepts it, and AMA
    rejects it because accepting it is signature malleability.  A
    divergence is only legitimate when it is *stated*, so
    ``DIVERGENCE_POLICIES`` records the reason, pins the exact count,
    and asserts a property every member must have — here, that the
    signature really does carry a high ``s``.  A divergence that starts
    covering a vector for some other reason fails the build.

The three policy tables are the whole point.  A skipped vector with no
stated reason is indistinguishable from a vector that fails, so nothing
is skipped: every one of the vendored vectors is claimed by name or by
an explicit, counted rule, and the totals are asserted.

Exit codes:
    0  every vector accounted for; no failures
    1  a vector failed, a digest or count drifted, a policy went stale,
       or a vector matched no bucket

Usage (CI):
    python wycheproof_vectors/run_wycheproof.py

Usage (developer, one file):
    python wycheproof_vectors/run_wycheproof.py --only x25519
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

VECTORS_DIR = Path(__file__).resolve().parent
REPO_ROOT = VECTORS_DIR.parent

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ama_cryptography.pqc_backends import (  # noqa: E402
    native_aes256_gcm_decrypt,
    native_chacha20poly1305_decrypt,
    native_ed25519_verify,
    native_hkdf_sha256,
    native_hkdf_sha384,
    native_hkdf_sha512,
    native_hmac_sha3_256,
    native_hmac_sha256,
    native_hmac_sha384,
    native_hmac_sha512,
    native_secp256k1_ecdsa_verify,
    native_x25519_key_exchange,
)

PASSED = "pass"
FAIL = "fail"
ACCEPTABLE = "acceptable"
OUT_OF_SCOPE = "out-of-scope"
POLICY_DIVERGENCE = "policy-divergence"

# Order of the secp256k1 group.  Used to recognise a high-`s` signature.
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


# ---------------------------------------------------------------------------
# Vector context
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Case:
    """One test case, with the group parameters it was declared under."""

    file: str
    group: dict[str, Any]
    test: dict[str, Any]

    @property
    def tc_id(self) -> int:
        return int(self.test["tcId"])

    @property
    def result(self) -> str:
        return str(self.test["result"])

    @property
    def flags(self) -> list[str]:
        return list(self.test.get("flags", []))

    @property
    def comment(self) -> str:
        return str(self.test.get("comment", ""))

    def hexf(self, name: str) -> bytes:
        return bytes.fromhex(self.test.get(name) or "")

    def __str__(self) -> str:
        return f"{self.file}#tc{self.tc_id}"


@dataclass(frozen=True)
class Policy:
    """A named, counted rule that claims a set of vectors.

    ``expected`` is asserted exactly.  A policy that stops matching, or
    starts matching more than it did, is itself a failure — that is how
    a corpus refresh or a behaviour change surfaces instead of being
    quietly absorbed.
    """

    name: str
    reason: str
    applies: Callable[[Case], bool]
    expected: int


# ---------------------------------------------------------------------------
# Scope policies — vectors for algorithm variants this library does not ship
# ---------------------------------------------------------------------------
def _aes_key_not_256(c: Case) -> bool:
    return c.file == "aes_gcm_test.json" and c.group["keySize"] != 256


def _aes_iv_not_96_expecting_success(c: Case) -> bool:
    return (
        c.file == "aes_gcm_test.json"
        and c.group["keySize"] == 256
        and c.group["ivSize"] != 96
        and c.result == "valid"
    )


SCOPE_POLICIES: tuple[Policy, ...] = (
    Policy(
        name="aes-gcm/key-size-not-256",
        reason=(
            "AMA ships AES-256-GCM only — there is no AES-128 or AES-192 key "
            "schedule in the library, so these vectors address an algorithm "
            "that is not present rather than one that is wrong. "
            "`native_aes256_gcm_decrypt` rejects the key length outright."
        ),
        applies=_aes_key_not_256,
        expected=211,
    ),
    Policy(
        name="aes-gcm/iv-size-not-96-expecting-success",
        reason=(
            "AMA requires the 96-bit IV that SP 800-38D §5.2.1.1 recommends "
            "and does not implement the GHASH-based derivation GCM defines "
            "for other IV lengths. A vector that expects a *successful* "
            "decryption under a non-96-bit IV therefore cannot be driven at "
            "all. The corresponding `invalid` vectors are NOT in this bucket: "
            "they are run, and AMA's rejection of the IV length is scored as "
            "a genuine pass."
        ),
        applies=_aes_iv_not_96_expecting_success,
        expected=37,
    ),
)


# ---------------------------------------------------------------------------
# Acceptable policies — Wycheproof `acceptable` cases, decided explicitly
# ---------------------------------------------------------------------------
def _x25519_zero_shared_secret(c: Case) -> bool:
    return c.file == "x25519_test.json" and "ZeroSharedSecret" in c.flags


X25519_ZERO_SHARED_SECRET = Policy(
    name="x25519/zero-shared-secret-rejected",
    reason=(
        "The public key has low order, so the shared secret is the all-zero "
        "value and carries no contribution from our private key. RFC 7748 "
        "§6.1 explicitly permits rejecting this, and AMA does: "
        "`ama_x25519_key_exchange` returns an error rather than a usable-"
        "looking 32 zero bytes. Wycheproof scores the case `acceptable` "
        "because returning the zeros is also permitted; rejecting is the "
        "stronger behaviour and is what this library commits to. Pinned by "
        "tests/test_x25519_canonical_u.py."
    ),
    applies=_x25519_zero_shared_secret,
    expected=31,
)

ACCEPTABLE_POLICIES: tuple[Policy, ...] = (X25519_ZERO_SHARED_SECRET,)


# ---------------------------------------------------------------------------
# Per-schema drivers
#
# Each driver answers one question: does the library's behaviour match
# what this vector says should happen?  Drivers return (ok, detail).
# ---------------------------------------------------------------------------
def _expect(result: str, matched: bool) -> bool:
    """True when observed behaviour agrees with the declared result.

    `valid`      -> must verify / match
    `invalid`    -> must not
    `acceptable` -> either, decided by an ACCEPTABLE_POLICIES entry
    """
    if result == "valid":
        return matched
    if result == "invalid":
        return not matched
    return True


def drive_eddsa_verify(c: Case) -> tuple[bool, str]:
    pk = bytes.fromhex(c.group["publicKey"]["pk"])
    try:
        ok = native_ed25519_verify(c.hexf("sig"), c.hexf("msg"), pk)
    except Exception as exc:  # a malformed signature length is a rejection
        ok, detail = False, f"rejected: {type(exc).__name__}"
    else:
        detail = f"verify={ok}"
    return _expect(c.result, ok), detail


def drive_xdh_comp(c: Case) -> tuple[bool, str]:
    try:
        shared = native_x25519_key_exchange(c.hexf("private"), c.hexf("public"))
    except Exception as exc:
        return _expect(c.result, False), f"rejected: {type(exc).__name__}"
    matched = shared == c.hexf("shared")
    return _expect(c.result, matched), f"shared={'match' if matched else 'MISMATCH'}"


_AEAD_DECRYPT: dict[str, Callable[..., bytes]] = {
    "aes_gcm_test.json": native_aes256_gcm_decrypt,
    "chacha20_poly1305_test.json": native_chacha20poly1305_decrypt,
}


def drive_aead(c: Case) -> tuple[bool, str]:
    decrypt = _AEAD_DECRYPT[c.file]
    try:
        pt = decrypt(c.hexf("key"), c.hexf("iv"), c.hexf("ct"), c.hexf("tag"), c.hexf("aad"))
    except Exception as exc:
        return _expect(c.result, False), f"rejected: {type(exc).__name__}"
    matched = pt == c.hexf("msg")
    return _expect(c.result, matched), f"plaintext={'match' if matched else 'MISMATCH'}"


_MAC: dict[str, Callable[[bytes, bytes], bytes]] = {
    "hmac_sha256_test.json": native_hmac_sha256,
    "hmac_sha384_test.json": native_hmac_sha384,
    "hmac_sha512_test.json": native_hmac_sha512,
    "hmac_sha3_256_test.json": native_hmac_sha3_256,
}


def drive_mac(c: Case) -> tuple[bool, str]:
    mac = _MAC[c.file]
    try:
        full = mac(c.hexf("key"), c.hexf("msg"))
    except Exception as exc:
        return _expect(c.result, False), f"rejected: {type(exc).__name__}"
    # Wycheproof truncates the tag to the group's tagSize; AMA always
    # returns the full-width tag, so compare the same prefix the vector
    # declares rather than the whole thing.
    width = int(c.group["tagSize"]) // 8
    matched = full[:width] == c.hexf("tag")
    return _expect(c.result, matched), f"tag[:{width}]={'match' if matched else 'MISMATCH'}"


_HKDF: dict[str, Callable[..., bytes]] = {
    "hkdf_sha256_test.json": native_hkdf_sha256,
    "hkdf_sha384_test.json": native_hkdf_sha384,
    "hkdf_sha512_test.json": native_hkdf_sha512,
}


def drive_hkdf(c: Case) -> tuple[bool, str]:
    hkdf = _HKDF[c.file]
    try:
        okm = hkdf(c.hexf("ikm"), int(c.test["size"]), c.hexf("salt"), c.hexf("info"))
    except Exception as exc:
        return _expect(c.result, False), f"rejected: {type(exc).__name__}"
    matched = okm == c.hexf("okm")
    return _expect(c.result, matched), f"okm={'match' if matched else 'MISMATCH'}"


def _der_s_value(sig: bytes) -> int | None:
    """`s` from a DER ECDSA signature, or None when it will not parse.

    Deliberately permissive — it is only used to *classify* a vector the
    strict C parser has already judged, so it must be able to read the
    encodings that parser rejects.
    """
    try:
        if len(sig) < 8 or sig[0] != 0x30:
            return None
        i = 2
        if sig[i] != 0x02:
            return None
        i += 2 + sig[i + 1]
        if sig[i] != 0x02:
            return None
        return int.from_bytes(sig[i + 2 : i + 2 + sig[i + 1]], "big")
    except (IndexError, ValueError):
        return None


def drive_ecdsa_verify(c: Case) -> tuple[bool, str]:
    import hashlib

    pub = bytes.fromhex(c.group["publicKey"]["uncompressed"])
    if pub[:1] != b"\x04" or len(pub) != 65:
        return False, "public key is not an uncompressed SEC 1 point"
    digest = hashlib.sha256(c.hexf("msg")).digest()
    try:
        ok = native_secp256k1_ecdsa_verify(c.hexf("sig"), digest, pub[1:])
    except Exception as exc:
        ok, detail = False, f"rejected: {type(exc).__name__}"
    else:
        detail = f"verify={ok}"
    return _expect(c.result, ok), detail


DRIVERS: dict[str, Callable[[Case], tuple[bool, str]]] = {
    "eddsa_verify_schema_v1.json": drive_eddsa_verify,
    "xdh_comp_schema_v1.json": drive_xdh_comp,
    "aead_test_schema_v1.json": drive_aead,
    "mac_test_schema_v1.json": drive_mac,
    "hkdf_test_schema_v1.json": drive_hkdf,
    "ecdsa_verify_schema_v1.json": drive_ecdsa_verify,
}


# ---------------------------------------------------------------------------
# Divergence policies — where this library deliberately disagrees
# ---------------------------------------------------------------------------
def _ecdsa_high_s_valid(c: Case) -> bool:
    if c.file != "ecdsa_secp256k1_sha256_test.json" or c.result != "valid":
        return False
    s = _der_s_value(c.hexf("sig"))
    return s is not None and s > (SECP256K1_N - 1) // 2


ECDSA_LOW_S = Policy(
    name="ecdsa/high-s-rejected",
    reason=(
        "Wycheproof scores these `valid` because plain X9.62 ECDSA accepts "
        "either of `s` and `n - s`. That is precisely signature "
        "malleability: given any valid (r, s), anyone can emit (r, n - s) — "
        "a different byte string that also verifies for the same message, "
        "with no access to the private key. It is the same defect class as "
        "the Ed25519 non-canonical-S bug this branch fixed. "
        "`ama_secp256k1_ecdsa_verify` therefore rejects high `s`, and "
        "`ama_secp256k1_ecdsa_sign` never emits it. Note tc5's own comment "
        "is 'signature malleability' — Wycheproof is describing the case "
        "accurately and scoring it against the weaker standard. The stricter "
        "policy is stated in include/ama_cryptography.h and pinned by "
        "tests/test_secp256k1_ecdsa.py."
    ),
    applies=_ecdsa_high_s_valid,
    expected=72,
)

DIVERGENCE_POLICIES: tuple[Policy, ...] = (ECDSA_LOW_S,)


# ---------------------------------------------------------------------------
# Corpus loading with integrity verification
# ---------------------------------------------------------------------------
@dataclass
class Outcome:
    counts: Counter[str] = field(default_factory=Counter)
    failures: list[str] = field(default_factory=list)
    policy_hits: Counter[str] = field(default_factory=Counter)


def load_manifest() -> dict[str, Any]:
    return json.loads((VECTORS_DIR / "manifest.json").read_text(encoding="utf-8"))


def verify_and_load(manifest: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Load every vendored file after checking its digest and vector count.

    The manifest is authoritative in BOTH directions.  Loading iterates the
    manifest, so a vendored file that is deleted or truncated is caught (its
    digest/count no longer matches, and the total falls short).  The reverse
    hole — a ``.json`` dropped into ``vectors/`` but never listed in the
    manifest — would be silently un-run: no digest, no count, no vectors, and
    nothing to notice.  So the directory is enumerated too, and any unlisted
    corpus file is a hard problem rather than a blind spot.
    """
    problems: list[str] = []
    corpora: dict[str, Any] = {}

    listed = set(manifest["files"])
    present = {p.name for p in sorted((VECTORS_DIR / "vectors").glob("*.json"))}
    for name in sorted(present - listed):
        problems.append(
            f"{name}: present under vectors/ but absent from manifest.json — "
            "add it (with its sha256 and vector count) or remove it; an "
            "unlisted corpus file is never run and would otherwise go uncovered"
        )

    for name, meta in sorted(manifest["files"].items()):
        path = VECTORS_DIR / "vectors" / name
        if not path.is_file():
            problems.append(f"{name}: vendored file is missing")
            continue
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if digest != meta["sha256"]:
            problems.append(
                f"{name}: SHA-256 {digest} != manifest {meta['sha256']} "
                "— the vendored corpus was modified"
            )
            continue
        data = json.loads(raw)
        actual = sum(len(g["tests"]) for g in data["testGroups"])
        if actual != meta["actualTests"]:
            problems.append(
                f"{name}: {actual} vectors present, manifest declares "
                f"{meta['actualTests']} — vectors appeared or vanished"
            )
            continue
        corpora[name] = data
    return corpora, problems


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def classify(c: Case) -> tuple[str, str]:
    """Return ``(bucket, detail)`` for one case."""
    for policy in SCOPE_POLICIES:
        if policy.applies(c):
            return OUT_OF_SCOPE, policy.name

    driver = DRIVERS.get(c.group.get("_schema", ""))
    if driver is None:
        return FAIL, f"no driver for schema {c.group.get('_schema')!r}"

    ok, detail = driver(c)

    if c.result == "acceptable":
        for policy in ACCEPTABLE_POLICIES:
            if policy.applies(c):
                return ACCEPTABLE, policy.name
        # An `acceptable` vector that no policy claims is only a pass if
        # the library agreed with the vector's stated shared value; if it
        # diverged, that divergence is undeclared and must be decided.
        if "MISMATCH" in detail or "rejected" in detail:
            return FAIL, f"undeclared `acceptable` divergence ({detail})"
        return PASSED, detail

    if ok:
        return PASSED, detail

    # The library disagreed with the corpus.  That is a failure unless a
    # divergence policy claims it *and* the vector really has the property
    # the policy is about.
    for policy in DIVERGENCE_POLICIES:
        if policy.applies(c):
            return POLICY_DIVERGENCE, policy.name
    return FAIL, detail


ALL_POLICIES: tuple[Policy, ...] = (
    *ACCEPTABLE_POLICIES,
    *SCOPE_POLICIES,
    *DIVERGENCE_POLICIES,
)


def score(corpora: dict[str, Any], only: str | None) -> tuple[Outcome, list[str]]:
    """Classify every vector in ``corpora``; return the tally and the files run."""
    outcome = Outcome()
    ran_files: list[str] = []

    for name, data in sorted(corpora.items()):
        if only and only not in name:
            continue
        ran_files.append(name)
        schema = data["schema"]
        for raw_group in data["testGroups"]:
            group = dict(raw_group, _schema=schema)
            for test in group["tests"]:
                case = Case(file=name, group=group, test=test)
                bucket, detail = classify(case)
                outcome.counts[bucket] += 1
                if bucket in (OUT_OF_SCOPE, ACCEPTABLE, POLICY_DIVERGENCE):
                    outcome.policy_hits[detail] += 1
                if bucket == FAIL:
                    outcome.failures.append(
                        f"{case}: result={case.result} "
                        f"flags={','.join(case.flags) or '-'} "
                        f"comment={case.comment!r} -> {detail}"
                    )
    return outcome, ran_files


def report(manifest: dict[str, Any], outcome: Outcome, ran_files: list[str], partial: bool) -> None:
    """Print the human-readable summary, including every policy's reason."""
    print(f"Wycheproof corpus — upstream {manifest['upstream']['repository']}")
    print(f"  commit {manifest['upstream']['commit']}")
    print(f"  {len(ran_files)} vendored file(s), {sum(outcome.counts.values())} vectors run\n")

    for name in ran_files:
        print(f"  {manifest['files'][name]['actualTests']:5d}  {name}")
    print()

    for bucket in (PASSED, ACCEPTABLE, OUT_OF_SCOPE, POLICY_DIVERGENCE, FAIL):
        print(f"  {bucket:<18s} {outcome.counts[bucket]:5d}")
    print()

    if not outcome.policy_hits:
        return
    print("Policy buckets (each vector claimed by a named, counted rule):")
    for policy in ALL_POLICIES:
        hits = outcome.policy_hits.get(policy.name, 0)
        if not hits and partial:
            continue
        print(f"  {policy.name}: {hits} vector(s)")
        print(f"      {policy.reason}")
    print()


def audit(manifest: dict[str, Any], outcome: Outcome, partial: bool) -> list[str]:
    """Every policy must claim exactly what it says, and every vector must run."""
    problems: list[str] = []
    for policy in ALL_POLICIES:
        hits = outcome.policy_hits.get(policy.name, 0)
        if partial and hits == 0:
            continue  # --only ran a different file
        if hits != policy.expected:
            problems.append(
                f"policy {policy.name!r} claimed {hits} vectors, expected "
                f"{policy.expected} — the corpus or the library's behaviour "
                "changed; re-read the reason and update it deliberately"
            )
    if not partial:
        total_run = sum(outcome.counts.values())
        if total_run != manifest["totalVectors"]:
            problems.append(
                f"ran {total_run} vectors, manifest declares {manifest['totalVectors']}"
            )
    return problems


def run(only: str | None = None) -> int:
    manifest = load_manifest()
    corpora, problems = verify_and_load(manifest)
    partial = bool(only)

    outcome, ran_files = score(corpora, only)
    report(manifest, outcome, ran_files, partial)
    problems += audit(manifest, outcome, partial)

    if outcome.failures:
        print(f"FAILURES ({len(outcome.failures)}):", file=sys.stderr)
        for line in outcome.failures:
            print(f"  - {line}", file=sys.stderr)
        print(file=sys.stderr)

    if problems:
        print(f"CORPUS / POLICY PROBLEMS ({len(problems)}):", file=sys.stderr)
        for line in problems:
            print(f"  - {line}", file=sys.stderr)
        print(file=sys.stderr)

    if outcome.failures or problems:
        print("FAIL: Wycheproof gate is red.", file=sys.stderr)
        return 1

    print("OK: every vendored Wycheproof vector is accounted for.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--only",
        metavar="SUBSTRING",
        help="run only vendored files whose name contains SUBSTRING",
    )
    args = parser.parse_args(argv)
    return run(only=args.only)


if __name__ == "__main__":
    raise SystemExit(main())
