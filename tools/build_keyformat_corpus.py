#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Rebuild the vendored key-format conformance corpus from its upstream sources.

``tests/test_key_formats.py`` runs **offline** against a fixed corpus under
``tests/kat/keyformats/``. This tool is the other half of that contract: it
re-derives that corpus from the documents it came from, so a reviewer can prove
the vendored bytes are the specifications' own, and can regenerate them when a
document is revised.

Two kinds of source, and the difference matters:

**Specification answer keys** (``--specs``). RFC 9881 Appendix C,
draft-ietf-lamps-kyber-certificates Appendix C, RFC 8410 §10, RFC 8037
Appendix A and RFC 8152 Appendix C.7 all publish worked examples. These are not
"some other implementation's output" — they are the standards bodies' own
answer keys, published so an implementer needs no second party to check against.
They are fetched from ``rfc-editor.org`` / ``ietf.org``, parsed out of the
running text, and written as JSON.

**Independent-implementation output** (``--openssl``). RFC 5915 and RFC 5480
publish no worked examples for EC PKCS#8 or SPKI, so for those the substitute is
key files produced by a second implementation. Regenerating this half produces
*different keys* every time — key generation is random — so the vendored files
are generated once and then frozen. Pass ``--openssl`` only to produce a fresh
independent sample when re-verifying by hand; do not commit the result unless
you intend to replace the corpus, and record the new OpenSSL version in
``tests/kat/keyformats/README.md`` in the same commit.

Neither half is a runtime dependency. Nothing AMA ships links OpenSSL or reads
these files; they are checked-in data consumed by CI, exactly as
``wycheproof_vectors/`` is.

Usage::

    python3 tools/build_keyformat_corpus.py --specs      # refresh from RFCs
    python3 tools/build_keyformat_corpus.py --openssl    # fresh EC/OKP sample
    python3 tools/build_keyformat_corpus.py --verify     # offline: re-parse only
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
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
}

# The OpenSSL half: algorithm -> (openssl genpkey arguments, AMA algorithm name).
OPENSSL_KEYS = {
    "P-256": (["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1",
               "-pkeyopt", "ec_param_enc:named_curve"], "prime256v1"),
    "P-384": (["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:secp384r1",
               "-pkeyopt", "ec_param_enc:named_curve"], "secp384r1"),
    "P-521": (["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:secp521r1",
               "-pkeyopt", "ec_param_enc:named_curve"], "secp521r1"),
    "secp256k1": (["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:secp256k1",
                   "-pkeyopt", "ec_param_enc:named_curve"], "secp256k1"),
    "Ed25519": (["-algorithm", "ED25519"], "ED25519"),
    "X25519": (["-algorithm", "X25519"], "X25519"),
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


def build_openssl(out_dir: Path) -> None:
    version = subprocess.run(
        ["openssl", "version"], capture_output=True, text=True, check=True
    ).stdout.strip()
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, (args, _curve) in OPENSSL_KEYS.items():
        priv = out_dir / f"{name}.key.pem"
        subprocess.run(
            ["openssl", "genpkey", *args, "-out", str(priv)],
            capture_output=True, check=True,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(priv), "-pubout", "-out",
             str(out_dir / f"{name}.pub.pem")],
            capture_output=True, check=True,
        )
    (out_dir / "PROVENANCE.txt").write_text(
        f"Generated by tools/build_keyformat_corpus.py --openssl using {version}.\n"
        "Key generation is random, so regenerating replaces the sample rather\n"
        "than reproducing it. These files are development-time evidence only:\n"
        "nothing AMA ships links or invokes OpenSSL.\n"
    )
    print(f"wrote {len(OPENSSL_KEYS) * 2} files to {out_dir} using {version}")


def verify_offline() -> int:
    """Re-parse everything vendored, without the network."""
    problems = 0
    for path in sorted(CORPUS.glob("*.json")):
        data = json.loads(path.read_text())
        for record in data["records"]:
            if "pem_b64" not in record:
                continue  # a JWK/COSE record, checked by the test suite itself
            try:
                der = base64.b64decode(record["pem_b64"], validate=True)
            except Exception as exc:
                print(f"{path.name}: {record.get('section')}: bad base64: {exc}")
                problems += 1
                continue
            if not der:
                print(f"{path.name}: {record.get('section')}: empty body")
                problems += 1
        print(f"{path.name}: {len(data['records'])} records, source={data['source']['revision']}")
    for path in sorted((CORPUS / "openssl").glob("*.pem")):
        if not path.read_text().startswith("-----BEGIN "):
            print(f"{path.name}: not a PEM block")
            problems += 1
    print(f"{'FAIL' if problems else 'OK'}: {problems} problem(s)")
    return 1 if problems else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--specs", action="store_true",
                        help="refresh the RFC/I-D answer keys from upstream")
    parser.add_argument("--openssl", action="store_true",
                        help="generate a fresh independent EC/OKP sample (replaces it)")
    parser.add_argument("--verify", action="store_true",
                        help="offline: re-parse the vendored corpus")
    args = parser.parse_args()
    if not (args.specs or args.openssl or args.verify):
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
        (CORPUS / "jose_cose.json").write_text(json.dumps(JOSE_COSE, indent=1) + "\n")
        print(f"wrote jose_cose.json: {len(JOSE_COSE['records'])} records")

    if args.openssl:
        build_openssl(CORPUS / "openssl")

    if args.verify:
        return verify_offline()
    return 0


if __name__ == "__main__":
    sys.exit(main())
