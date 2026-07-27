#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Rebuild the vendored key-format conformance corpus from its upstream sources.

``tests/test_key_formats.py`` runs **offline** against a fixed corpus under
``tests/kat/keyformats/``. This tool is the other half of that contract: it
re-derives that corpus from the documents it came from, so a reviewer can prove
the vendored bytes are the specifications' own, and can regenerate them when a
document is revised.

One kind of source, and only one: **the standards bodies' own answer keys**.
RFC 9881 Appendix C, draft-ietf-lamps-kyber-certificates Appendix C, RFC 8410
§10, RFC 8037 Appendix A, RFC 8152 Appendix C.7 and RFC 9500 §2.3 all publish
worked examples — vectors published so an implementer needs no second party to
check against. They are fetched from ``rfc-editor.org`` / ``ietf.org``, parsed
out of the running text, and written as JSON.

This corpus deliberately contains **no output from any other cryptographic
product**. Where a specification publishes no vector, the substitute is a
reference encoder written from the specification's own ASN.1 text
(``tests/ref_keyformat.py``), which is AMA's work and stands on the document
rather than on another implementation's behaviour. RFC 5915 and RFC 5480 were
long the gap here, and RFC 9500 — "Standard Public Key Cryptography (PKCS) Test
Keys", December 2023 — closed it: its §2.3 prints P-256/P-384/P-521 keys in
exactly the RFC 5915 ``ECPrivateKey`` form AMA embeds in PKCS#8.

Nothing here is a runtime dependency. These are checked-in data consumed by CI,
exactly as ``wycheproof_vectors/`` is.

Where this runs
---------------
``--verify`` is not a command a reviewer has to remember. It is driven on every
pull request from two directions: ``tests/test_keyformat_corpus_provenance.py``
calls :func:`verify_offline` directly (and pins each failure direction, so the
check cannot decay into one that always passes), and the ``code-quality`` job in
``ci.yml`` runs the CLI. ``--verify-upstream`` needs the network, so it runs
where the Wycheproof corpus's equivalent does: ``corpus-provenance.yml``, on a
monthly drift watch and on any pull request that touches the corpus or this
tool.

Usage::

    python3 tools/build_keyformat_corpus.py --specs           # refresh from RFCs
    python3 tools/build_keyformat_corpus.py --verify          # offline: re-parse only
    python3 tools/build_keyformat_corpus.py --verify-upstream # online: vs. the documents
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "tests" / "kat" / "keyformats"

# Every source document, with the exact revision the vendored bytes came from.
SOURCES = {
    "rfc9881_ml_dsa.json": {
        "url": "https://www.rfc-editor.org/rfc/rfc9881.txt",
        "title": "RFC 9881 (X.509 algorithm identifiers for ML-DSA), Appendix C",
        "revision": "RFC 9881, October 2025",
    },
    "lamps_ml_kem.json": {
        "url": "https://www.ietf.org/archive/id/draft-ietf-lamps-kyber-certificates-11.txt",
        "title": "draft-ietf-lamps-kyber-certificates-11 (X.509 for ML-KEM), Appendix C",
        "revision": "draft-ietf-lamps-kyber-certificates-11, 22 July 2025",
    },
    "rfc8410_okp.json": {
        "url": "https://www.rfc-editor.org/rfc/rfc8410.txt",
        "title": "RFC 8410 (Ed25519/X25519 in X.509), Section 10",
        "revision": "RFC 8410, August 2018",
    },
    "rfc9500_ec.json": {
        "url": "https://www.rfc-editor.org/rfc/rfc9500.txt",
        "title": "RFC 9500 (Standard Public Key Cryptography Test Keys), Section 2.3",
        "revision": "RFC 9500, December 2023",
    },
    "rfc8554_hss_lms.json": {
        "url": "https://www.rfc-editor.org/rfc/rfc8554.txt",
        "title": "RFC 8554 (Leighton-Micali Hash-Based Signatures), Appendix F",
        "revision": "RFC 8554, April 2019",
    },
}


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310 -- fixed https URLs from the SOURCES table, not caller input (KFC-001)
        return response.read().decode("utf-8", "replace")


def strip_page_furniture(text: str) -> str:
    """Remove the running headers, footers and form feeds RFC text carries.

    Left in place they land in the middle of a base64 body and truncate it — a
    failure that looks like a corrupt vector rather than a parsing bug.
    """
    kept = []
    for line in text.replace("\r\n", "\n").split("\n"):
        if "\f" in line:
            continue
        if re.match(r"^\S.*\[Page \d+\]\s*$", line):
            continue
        if re.match(r"^(RFC \d+|Internet-Draft)\s+\S.*\d{4}\s*$", line):
            continue
        kept.append(line)
    return "\n".join(kept)


def extract_pem_blocks(text: str) -> list[dict]:
    """Pull every PEM block out of RFC running text, tagged with its section."""
    lines = strip_page_furniture(text).split("\n")
    section = ""
    blocks: list[dict] = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        # Appendix headings ("C.1.1.2.  Expanded Format") and numbered ones
        # ("10.3.  Examples of Ed25519 Private Key") both name a section, and
        # both must reach the record so a vector can be attributed.
        #
        # The match is against the *unindented* line deliberately. RFC section
        # headings sit at column 0; numbered list items ("3.  The third
        # ML-DSA-PrivateKey example ...") are indented and look identical once
        # stripped. Matching the stripped form let those list items overwrite
        # the enclosing "C.4." heading, which silently relabelled the
        # deliberately-inconsistent keys as valid ones — the negative corpus
        # emptied itself and the gate that consumes it went vacuous.
        if raw[:1] not in (" ", "\t") and re.match(
            r"^(Appendix [A-Z]\.|[A-Z]\.[0-9][0-9.]*\.?|[0-9]+\.[0-9.]*)\s+\S", stripped
        ):
            section = stripped
        if stripped.startswith("-----BEGIN "):
            label = stripped[len("-----BEGIN "):].rstrip("-").strip()
            body: list[str] = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("-----END"):
                if lines[i].strip():
                    body.append(lines[i].strip())
                i += 1
            blocks.append({"section": section, "label": label, "pem_b64": "".join(body)})
        i += 1
    return blocks


def classify_pq(section: str, label: str) -> tuple[str, str]:
    """Map an Appendix C section heading to (kind, arm).

    ``kind`` is ``valid`` or ``inconsistent``; ``arm`` names the private-key
    CHOICE arm so the round-trip test knows which one to re-emit.
    """
    if ".4" in section:
        return "inconsistent", "unknown"
    if label == "PUBLIC KEY":
        return "valid", "n/a"
    for name in ("Seed", "Expanded", "Both"):
        if name in section:
            return "valid", {"Seed": "seed", "Expanded": "expandedKey", "Both": "both"}[name]
    # Never fall through to a placeholder: a record whose section could not be
    # identified is one whose valid/inconsistent classification is a guess, and
    # guessing "valid" on a deliberately-bad key turns the negative gate into a
    # test that asserts the bad key imports cleanly.
    raise ValueError(
        f"cannot classify a {label!r} record in section {section!r}; the section "
        "heading did not parse. Fix extract_pem_blocks rather than defaulting."
    )


def build_pq(filename: str) -> dict:
    meta = SOURCES[filename]
    blocks = extract_pem_blocks(fetch(meta["url"]))
    records = []
    for block in blocks:
        if block["label"] == "CERTIFICATE":
            continue  # certificates are out of this module's scope
        kind, arm = classify_pq(block["section"], block["label"])
        records.append({
            "section": block["section"],
            "label": block["label"],
            "kind": kind,
            "arm": arm,
            "pem_b64": block["pem_b64"],
        })
    return {"source": meta, "records": records}


def build_okp() -> dict:
    """RFC 8410 §10: the two Ed25519 private-key forms and the public key.

    §10.3's second example is the valuable one — it carries a PKCS#8 attribute
    (a "Curdle Chairs" friendly name) and a ``[1] publicKey`` in the primitive
    ``0x81`` form, at version 1. A parser that skips attributes or assumes the
    constructed tag fails on it, and third-party key files do carry both.
    """
    meta = SOURCES["rfc8410_okp.json"]
    blocks = extract_pem_blocks(fetch(meta["url"]))
    records = []
    for block in blocks:
        if not block["section"].startswith("10.") or block["label"] == "CERTIFICATE":
            continue
        records.append({
            "section": block["section"],
            "label": block["label"],
            "algorithm": "Ed25519",
            "pem_b64": block["pem_b64"],
        })
    return {"source": meta, "records": records}


# RFC 8037 Appendix A and RFC 8152 Appendix C.7.1 publish their examples as
# prose — a JSON object and CBOR diagnostic notation respectively — not as PEM,
# so they are transcribed here rather than parsed out of the running text. Each
# value is copied verbatim from the document named in "source"; the tests
# re-derive everything else (the public key from the private one, the
# thumbprint from the members) rather than trusting a second transcription.
JOSE_COSE = {
    "source": {
        "title": "RFC 8037 Appendix A (JWK) and RFC 8152 Appendix C.7.1 (COSE_Key)",
        "revision": "RFC 8037, January 2017; RFC 8152, July 2017",
        "url": "https://www.rfc-editor.org/rfc/rfc8037.txt",
        "note": "Transcribed from the running text; these appendices are prose, not PEM.",
    },
    "records": [
        {
            "section": "RFC 8037 A.1",
            "format": "jwk",
            "kind": "private",
            "algorithm": "Ed25519",
            "jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            },
            # RFC 8037 A.1 prints both halves in hexadecimal; kept so the test
            # checks the base64url decode rather than assuming it.
            "d_hex": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "x_hex": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            # RFC 8037 A.3.
            "thumbprint_sha256_hex":
                "90facafea9b1556698540f70c0117a22ea37bd5cf3ed3c47093c1707282b4b89",
            "thumbprint_b64u": "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
            "thumbprint_input":
                '{"crv":"Ed25519","kty":"OKP",'
                '"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}',
        },
        {
            "section": "RFC 8037 A.2",
            "format": "jwk",
            "kind": "public",
            "algorithm": "Ed25519",
            "jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            },
        },
        {
            "section": "RFC 8152 C.7.1 (meriadoc.brandybuck@buckland.example)",
            "format": "cose",
            "kind": "public",
            "algorithm": "P-256",
            # Labels: 1=kty (2=EC2), -1=crv (1=P-256), -2=x, -3=y, 2=kid.
            # The kid is deliberately kept: a COSE_Key is an open map and a
            # parser that chokes on a label it does not consume rejects most
            # real-world keys.
            "cose_labels": {"1": 2, "-1": 1, "2": "meriadoc.brandybuck@buckland.example"},
            "x_hex": "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d",
            "y_hex": "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c",
        },
        {
            "section": "RFC 8152 C.7.1 (bilbo.baggins@hobbiton.example)",
            "format": "cose",
            "kind": "public",
            "algorithm": "P-521",
            "cose_labels": {"1": 2, "-1": 3, "2": "bilbo.baggins@hobbiton.example"},
            # 66 octets with a leading zero — the width case a naive
            # big-integer round trip silently shortens.
            "x_hex": "0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de79866"
                     "71eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8"
                     "f42ad",
            "y_hex": "01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa"
                     "55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1"
                     "d9475",
        },
    ],
}


#: RFC 9500 §2.3 publishes three EC keys, identified by the length of the
#: ``ECPrivateKey`` DER rather than by any label the document carries, because
#: the document identifies them only in prose. The lengths are structural: the
#: RFC 5915 encoding of a curve's key is a fixed size for that curve.
RFC9500_EC_BY_LENGTH = {121: "P-256", 167: "P-384", 223: "P-521"}


def build_rfc9500_ec() -> dict:
    """RFC 9500 §2.3 — the IETF's own EC test keys.

    This is the answer key that was thought not to exist. RFC 5915 defines
    ``ECPrivateKey`` and publishes no example of it; RFC 5480 does the same for
    the SPKI side. RFC 9500 (December 2023) was written precisely to fill that
    kind of gap — "Standard Public Key Cryptography (PKCS) Test Keys" — and its
    §2.3 prints P-256, P-384 and P-521 private keys as ``EC PRIVATE KEY`` PEM,
    which *is* an RFC 5915 ``ECPrivateKey``: the exact structure AMA places
    inside the PKCS#8 ``privateKey`` OCTET STRING.

    So the EC half of this corpus is a standards-body answer key like every
    other half, rather than a second vendor's output. The section is quoted in
    the record so a reviewer can go and read it.
    """
    meta = SOURCES["rfc9500_ec.json"]
    blocks = extract_pem_blocks(fetch(meta["url"]))
    records = []
    for block in blocks:
        if block["label"] != "EC PRIVATE KEY":
            continue
        der = base64.b64decode(block["pem_b64"], validate=True)
        curve = RFC9500_EC_BY_LENGTH.get(len(der))
        if curve is None:
            raise ValueError(
                f"RFC 9500 §2.3 EC key of {len(der)} octets does not match any "
                f"known curve; expected one of {sorted(RFC9500_EC_BY_LENGTH)}"
            )
        records.append({
            "section": block["section"],
            "label": block["label"],
            "algorithm": curve,
            "pem_b64": block["pem_b64"],
        })
    if len(records) != len(RFC9500_EC_BY_LENGTH):
        raise ValueError(
            f"expected {len(RFC9500_EC_BY_LENGTH)} EC keys in RFC 9500 §2.3, "
            f"found {len(records)}"
        )
    return {"source": meta, "records": records}


# Every JSON corpus this tool writes, and what it must contain to be doing its
# job. ``needs_negative`` marks the two PQ corpora, whose value is *entirely* in
# the deliberately-inconsistent keys: if the extractor mis-sections a heading
# the negative half empties itself and every gate that consumes it goes vacuous
# while still reporting green. That failure has happened once already (see
# ``extract_pem_blocks``), so it is asserted rather than assumed.
EXPECTED_JSON = {
    "rfc9881_ml_dsa.json": {"needs_negative": True},
    "lamps_ml_kem.json": {"needs_negative": True},
    "rfc8410_okp.json": {"needs_negative": False},
    "rfc9500_ec.json": {"needs_negative": False},
    "rfc8554_hss_lms.json": {"needs_negative": False},
    "jose_cose.json": {"needs_negative": False},
}

def verify_offline(corpus: Path = CORPUS) -> list[str]:
    """Re-check everything vendored, without the network.

    Returns a list of human-readable problems — empty means the corpus is
    internally sound. Structured as a list rather than a printed count so the
    same function backs both the CLI and ``tests/test_keyformat_corpus_provenance.py``;
    a verifier only a human can run is a verifier that does not run.

    Four classes of check, each one a failure this corpus can actually have:

    1. **Presence.** Every file this tool writes must exist. A corpus file that
       silently disappears turns its whole test group into a collection error
       at best and a skip at worst.
    2. **Provenance.** Every record set must carry a ``source`` naming the exact
       document revision the bytes came from. Vendored cryptographic vectors
       whose origin is not recorded cannot be re-derived or audited.
    3. **Shape.** Every ``pem_b64`` must be valid, non-empty base64 whose first
       octet opens a DER SEQUENCE, and every record carrying PEM bytes must name
       its label.
    4. **Non-vacuity.** The two PQ corpora must retain both valid and
       deliberately-inconsistent records.
    """
    problems: list[str] = []

    for filename, spec in sorted(EXPECTED_JSON.items()):
        path = corpus / filename
        if not path.is_file():
            problems.append(
                f"{filename}: missing from {corpus} — regenerate with "
                "tools/build_keyformat_corpus.py --specs"
            )
            continue
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            problems.append(f"{filename}: not valid JSON: {exc}")
            continue

        source = data.get("source")
        if not isinstance(source, dict):
            problems.append(f"{filename}: has no 'source' block naming its origin document")
            source = {}
        for field in ("title", "revision"):
            if not str(source.get(field, "")).strip():
                problems.append(
                    f"{filename}: source.{field} is missing or empty — a vendored "
                    "vector whose source revision is not recorded cannot be re-derived"
                )

        records = data.get("records")
        if not isinstance(records, list) or not records:
            problems.append(f"{filename}: 'records' is missing or empty")
            continue

        kinds: set[str] = set()
        for index, record in enumerate(records):
            where = f"{filename}: record {index} ({record.get('section', '?')})"
            kinds.add(str(record.get("kind", "")))
            if "pem_b64" not in record:
                continue  # a JWK/COSE record, checked by the test suite itself
            if not str(record.get("label", "")).strip():
                problems.append(f"{where}: has PEM bytes but no label")
            try:
                der = base64.b64decode(record["pem_b64"], validate=True)
            except (ValueError, binascii.Error) as exc:
                problems.append(f"{where}: bad base64: {exc}")
                continue
            if not der:
                problems.append(f"{where}: empty body")
            elif der[0] != 0x30:
                # Every vendored record is a DER SEQUENCE (SPKI or PKCS#8).
                # A body that decodes but does not start a SEQUENCE is page
                # furniture that survived extraction, not a key.
                problems.append(
                    f"{where}: does not begin with a DER SEQUENCE (0x30); first "
                    f"octet is 0x{der[0]:02X}"
                )

        if spec["needs_negative"] and "inconsistent" not in kinds:
            problems.append(
                f"{filename}: carries no 'inconsistent' records. The negative half "
                "of this corpus is what proves the consistency checks fire at all; "
                "without it every gate over it passes vacuously."
            )

    return problems


#: Expected sizes for RFC 8554 Appendix F, derived from the structures rather
#: than copied from a claim. An HSS public key is `u32 levels || LMS public key`
#: and an LMS public key is `u32 type || u32 otstype || I[16] || K[32]`, so 60
#: octets for a two-level tree. The signature sizes follow from the parameter
#: sets each test case names and are asserted rather than assumed, because a
#: vector whose size is wrong is one the extractor mis-assembled.
RFC8554_PUBLIC_KEY_BYTES = 60
RFC8554_SIGNATURE_BYTES = (2644, 3860)

_HEX_RE = re.compile(r"\A(?:[0-9a-f]{2})+\Z")


def _appendix_f_hex(lines: list[str]) -> str:
    """Concatenate the hexadecimal values in one Appendix F block.

    RFC 8554 Appendix F states the rule this implements: "the concatenation of
    all of the values within a public key or signature produces that public key
    or signature, and values that do not fit within a single line are listed
    across successive lines".

    The lines carry three kinds of decoration that are not values — an ASCII
    gutter (``|The powers not d|``), a parameter-set comment
    (``# LMOTS_SHA256_N32_W8``) and rules of dashes — plus a label column whose
    entries include ``I`` and ``K``. Rather than trying to recognise labels,
    this takes the *trailing run of even-length hexadecimal tokens*: a label is
    either not hex (``levels``, ``Message``, ``q``) or is a single character and
    therefore odd-length (``I``, ``K``, ``C``).
    """
    out: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("-"):
            continue
        line = re.sub(r"\|.*\|\s*$", "", line)   # ASCII gutter
        line = re.sub(r"#.*$", "", line)         # parameter-set comment
        tokens = line.split()
        run: list[str] = []
        for token in reversed(tokens):
            if _HEX_RE.match(token):
                run.append(token)
            else:
                break
        out.extend(reversed(run))
    return "".join(out)


def build_rfc8554_hss_lms() -> dict:
    """RFC 8554 Appendix F — the HSS/LMS answer key.

    Vendored so that the reference for any future LMS work is a checked-in,
    verifiable artefact rather than a claim. Nothing in AMA implements HSS/LMS
    today; this is the specification's own test data, extracted through exactly
    the same provenance path as every other corpus here and subject to the same
    ``--verify`` and ``--verify-upstream`` gates.

    Deliberately *only* what RFC 8554 publishes. SP 800-208's approved parameter
    sets and its §6.2 key-derivation method are **not** here: the published PDF
    did not yield reliable text, and guessing an approved parameter set is
    exactly the kind of speculative standards work this repository refuses.
    """
    meta = SOURCES["rfc8554_hss_lms.json"]
    lines = strip_page_furniture(fetch(meta["url"])).split("\n")

    start = next(
        (i for i, line in enumerate(lines)
         if line.startswith("Appendix F.") and "Test Cases" in line and i > 300),
        None,
    )
    if start is None:
        raise ValueError("RFC 8554 Appendix F heading not found")

    # Any "Test Case N <something>" heading ends the previous block. Matching
    # only the three kinds wanted would let "Test Case 2 Private Key" fall
    # *inside* Test Case 1's signature — which it did, adding exactly the 96
    # octets of two SEED/I pairs and producing a 2740-octet "signature" that
    # still looked plausible. The size assertion below is what caught it.
    heading = re.compile(r"^\s{3}Test Case (\d+) (.+?)\s*$")
    wanted = {"Public Key", "Message", "Signature"}
    blocks: dict[tuple[str, str], list[str]] = {}
    current: tuple[str, str] | None = None
    for line in lines[start:]:
        match = heading.match(line)
        if match:
            current = (match.group(1), match.group(2)) if match.group(2) in wanted else None
            if current is not None:
                blocks[current] = []
            continue
        if line.startswith("Acknowledgements") or line.startswith("Authors' Addresses"):
            current = None
        if current is not None:
            blocks[current].append(line)

    records = []
    for (case, kind), body in sorted(blocks.items(), key=lambda kv: (int(kv[0][0]), kv[0][1])):
        value = _appendix_f_hex(body)
        if not value:
            raise ValueError(f"Test Case {case} {kind}: no hexadecimal value extracted")
        records.append({
            "section": f"Appendix F, Test Case {case}",
            "case": int(case),
            "kind": kind.lower().replace(" ", "_"),
            "hex": value,
            "bytes": len(value) // 2,
        })

    # Structural self-check: the extractor is what could be wrong here, and a
    # mis-assembled vector is worse than a missing one because it looks usable.
    for record in records:
        if record["kind"] == "public_key" and record["bytes"] != RFC8554_PUBLIC_KEY_BYTES:
            raise ValueError(
                f"Test Case {record['case']} public key is {record['bytes']} octets, "
                f"expected {RFC8554_PUBLIC_KEY_BYTES}"
            )
        if record["kind"] == "signature" and record["bytes"] not in RFC8554_SIGNATURE_BYTES:
            raise ValueError(
                f"Test Case {record['case']} signature is {record['bytes']} octets, "
                f"expected one of {RFC8554_SIGNATURE_BYTES}"
            )
    if not records:
        raise ValueError("RFC 8554 Appendix F produced no records")
    return {"source": meta, "records": records}


def verify_upstream(corpus: Path = CORPUS) -> list[str]:
    """Provenance: the vendored records are still what the documents publish.

    Needs the network. This is the half that proves the bytes are the standards
    bodies' own rather than merely self-consistent — re-derive each corpus from
    the document named in its own ``source`` block and require the vendored
    records to match record-for-record.

    ``jose_cose.json`` is deliberately out of scope: RFC 8037 Appendix A and
    RFC 8152 Appendix C.7.1 publish their examples as prose, so that file is a
    hand transcription with nothing to re-extract. The test suite checks it the
    other way — it re-derives the public key from the private one and the
    thumbprint from the members, so a transcription error cannot pass.
    """
    problems: list[str] = []
    builders = {
        "rfc9881_ml_dsa.json": lambda: build_pq("rfc9881_ml_dsa.json"),
        "lamps_ml_kem.json": lambda: build_pq("lamps_ml_kem.json"),
        "rfc8410_okp.json": build_okp,
        "rfc9500_ec.json": build_rfc9500_ec,
        "rfc8554_hss_lms.json": build_rfc8554_hss_lms,
    }
    for filename, builder in sorted(builders.items()):
        path = corpus / filename
        if not path.is_file():
            problems.append(f"{filename}: missing; cannot compare against upstream")
            continue
        vendored = json.loads(path.read_text())
        try:
            fresh = builder()
        except Exception as exc:  # noqa: BLE001 -- any fetch/parse failure is a finding, reported not raised
            problems.append(f"{filename}: could not re-derive ({type(exc).__name__}: {exc})")
            continue
        if vendored.get("source", {}).get("revision") != fresh["source"]["revision"]:
            problems.append(
                f"{filename}: vendored source revision "
                f"{vendored.get('source', {}).get('revision')!r} != "
                f"{fresh['source']['revision']!r}"
            )
        def _key(record: dict) -> tuple:
            # RFC 8554's appendix publishes labelled hexadecimal rather than
            # PEM, so its records carry `hex`/`kind` where the others carry
            # `pem_b64`/`label`. One comparison covers both.
            return (
                record["section"],
                record.get("label", record.get("kind", "")),
                record.get("pem_b64", record.get("hex", "")),
            )

        old = {_key(r) for r in vendored["records"]}
        new = {_key(r) for r in fresh["records"]}
        for section, label, _ in sorted(old - new):
            problems.append(
                f"{filename}: vendored record {section!r} ({label}) is not in the "
                "upstream document at this revision"
            )
        for section, label, _ in sorted(new - old):
            problems.append(
                f"{filename}: upstream publishes {section!r} ({label}) and the "
                "vendored corpus does not carry it"
            )
    return problems


def report_offline(corpus: Path = CORPUS) -> int:
    """CLI wrapper around :func:`verify_offline` — prints, returns an exit code."""
    problems = verify_offline(corpus)
    for filename in sorted(EXPECTED_JSON):
        path = corpus / filename
        if not path.is_file():
            continue
        data = json.loads(path.read_text())
        revision = data.get("source", {}).get("revision", "<unrecorded>")
        print(f"{filename}: {len(data.get('records', []))} records, source={revision}")
    for problem in problems:
        print(f"  PROBLEM: {problem}")
    print(f"{'FAIL' if problems else 'OK'}: {len(problems)} problem(s)")
    return 1 if problems else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--specs", action="store_true",
                        help="refresh the RFC/I-D answer keys from upstream")
    parser.add_argument("--verify", action="store_true",
                        help="offline: re-parse the vendored corpus")
    parser.add_argument("--verify-upstream", action="store_true",
                        help="online: re-derive from the source documents and compare")
    args = parser.parse_args()
    if not (args.specs or args.verify or args.verify_upstream):
        args.verify = True

    if args.specs:
        CORPUS.mkdir(parents=True, exist_ok=True)
        for filename in ("rfc9881_ml_dsa.json", "lamps_ml_kem.json"):
            data = build_pq(filename)
            (CORPUS / filename).write_text(json.dumps(data, indent=1) + "\n")
            print(f"wrote {filename}: {len(data['records'])} records")
        data = build_okp()
        (CORPUS / "rfc8410_okp.json").write_text(json.dumps(data, indent=1) + "\n")
        print(f"wrote rfc8410_okp.json: {len(data['records'])} records")
        data = build_rfc9500_ec()
        (CORPUS / "rfc9500_ec.json").write_text(json.dumps(data, indent=1) + "\n")
        print(f"wrote rfc9500_ec.json: {len(data['records'])} records")
        data = build_rfc8554_hss_lms()
        (CORPUS / "rfc8554_hss_lms.json").write_text(json.dumps(data, indent=1) + "\n")
        print(f"wrote rfc8554_hss_lms.json: {len(data['records'])} records")
        (CORPUS / "jose_cose.json").write_text(json.dumps(JOSE_COSE, indent=1) + "\n")
        print(f"wrote jose_cose.json: {len(JOSE_COSE['records'])} records")

    status = 0
    if args.verify:
        status |= report_offline()

    if args.verify_upstream:
        problems = verify_upstream()
        for problem in problems:
            print(f"  PROBLEM: {problem}")
        print(f"upstream: {'FAIL' if problems else 'OK'}: {len(problems)} problem(s)")
        status |= 1 if problems else 0

    return status


if __name__ == "__main__":
    sys.exit(main())
