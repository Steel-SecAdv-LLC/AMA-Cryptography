# Adversarial security review — `rfc3161-timestamp`

**File:** `ama_cryptography/rfc3161_timestamp.py` (+ `_asn1.py` DER codec, `secure_memory`, `_module_state.secure_token_bytes`)
**Branch:** `steel/systempqc-maint1` (HEAD `a14cc83`)
**Scope:** RFC 3161 request/verify, TSA response parsing, nonce binding, hash-OID handling, `tsa_mode` strictness, mock-TSA guard.
**Disposition:** READ-ONLY. No files modified, no builds/jobs run.

## 1. Threat model

**Assets.** (1) Integrity of the message-imprint binding verdict (`verify_token_binding` / `verify_timestamp_binding` / `describe_token_verification`): `True` must mean *this token's `TSTInfo.messageImprint` is the digest of this data under the algorithm the token names*. (2) The honesty boundary — a binding result must never be readable as TSA attestation, and any argument requesting an unimplemented check must raise. (3) Process availability (no unbounded memory/CPU/time from a network peer, no uncaught exceptions past the documented boundary). (4) The mock-TSA facility must never be a production trust path.

**Trust boundaries.** The module explicitly does **not** verify the CMS `SignerInfo` signature over `TSTInfo` or any X.509 chain (`RFC3161_CAPABILITIES`: `tsa_signature=False`, `tsa_certificate_chain=False`, `gen_time=False`). Therefore every token/response/`TimestampResult` handed to it is untrusted, and `TSTInfo.genTime` is attacker-chosen. The only transport-authenticated element is the TLS identity of `tsa_url`; response *content* is unauthenticated. Provenance is asserted to be carried by an outer control (HMAC layer / signed transport / trusted store).

**Adversary (assumed maximal).** Controls full bytes of any offline-parsed token/response and any `TimestampResult` passed to verify. On the online path is the TSA, an attacker-chosen https `tsa_url`, or a TLS-identity compromise of the TSA — i.e. controls the ≤256 KiB `TimeStampResp` and has seen the request nonce. Has source read access and may set env/files, but cannot execute in-process code (so cannot flip `_MOCK_TSA_ALLOWED` or the thread-local mock flag). A purely passive network attacker against the default `https://freetsa.org/tsr` is limited to replay/caching-proxy behaviour (cannot break TLS).

## 2. Attacks attempted

### 2.1 FINDING (low) — nonce-echo mismatch str()s an attacker-influenced integer past the exception boundary
`tst_info_nonce` (`:643-658`) returns `int(info.read_integer())` with **no size bound**; `read_integer` accepts a minimally-encoded INTEGER up to the 256 KiB response cap. In `parse_timestamp_response` the mismatch branch formats it:

```
raise TimestampError("TSA response does not echo the request's nonce "
    f"(sent {expected_nonce}, token carries "
    f"{'none' if echoed is None else echoed}). ...")     # :296-300  -> str(echoed)
```

A nonce > ~1786 bytes decodes to an integer with > 4300 decimal digits. On the deployed interpreter (**Python 3.11.15, `sys.get_int_max_str_digits()==4300`**) I confirmed `str()`/f-string over a ~300 KB int raises `ValueError: Exceeds the limit (4300 digits)...`. A huge echoed nonce always mismatches the client's 64-bit nonce, so the branch is always taken. Both the `raise` (`:295`) and the call site `token = parse_timestamp_response(raw, expected_nonce=nonce)` in `request_timestamp_exchange` (`:589`) are **outside any `try/except`**, so a raw `ValueError` propagates out of `get_timestamp`, whose contract promises `TimestampError` for protocol failures (and `ValueError` only for bad `hash_algorithm`/`tsa_mode`); the public `parse_timestamp_response` docstring promises only `TimestampError`.

This is the **same defect class the module deliberately closed elsewhere**: PKIStatus is enumeration-checked before any formatting (`:252-263`), Content-Length wraps `int()` in `except ValueError` (`:571-578`), and OID bodies are bounded (`_asn1._OID_MAX_BODY`). It was left open on the nonce path. It **fails closed** (no token is accepted; it raises), so the impact is a mis-typed exception / minor DoS triggerable by a malicious-or-compromised TSA — not a binding/authenticity bypass. **Fix:** bound the nonce size, or format without `str()`, or move the nonce check inside a `try` that maps to `TimestampError` — mirroring the PKIStatus guard.

### 2.2 Forged offline token satisfies the binding — DEFENDED (by honesty; intentional)
`verify_token_binding` accepts an unsigned, zero-signature, arbitrary-`genTime` token (proven by `test_a_token_with_a_nonsense_signature_still_satisfies_the_binding`). This is the documented scope, not a defect: `RFC3161_CAPABILITIES` records the false capabilities; `TokenVerification.signature_verified/chain_verified` are `Literal[False]`; `__bool__` raises to block `if describe...():` fail-open; `certificate_file`/`tsa_cert_path` raise rather than silently doing something weaker; and `extract_tst_info` still refuses empty `digestAlgorithms`/`signerInfos` sets (`:382`, `:404`). No claim exceeds behaviour. Residual risk is caller misuse (binding read as attestation), extensively warned against.

### 2.3 Replay (caching proxy / rolled-back TSA) — DEFENDED
Fresh 64-bit nonce via `secure_token_bytes(8)` (health-tested DRBG), echoed and checked (`parse_timestamp_response:292-300`); different/absent echo raises. Pinned by `test_a_nonce_is_sent_and_its_echo_is_required`. Does not (and does not claim to) stop an active forger who has seen the nonce.

### 2.4 Nonce-mismatch acceptance — DEFENDED
`echoed != expected_nonce` raises; `None` (nonce omitted) also raises. Positional walk to the nonce cannot mistake `accuracy` (SEQUENCE 0x30) or `ordering` (BOOLEAN 0x01) for the nonce (INTEGER 0x02). Fail-closed.

### 2.5 Hash-algorithm downgrade — DEFENDED
Algorithm is taken from the token's own imprint OID via `_HASH_BY_OID`, which contains only SHA-2/SHA-3 (no MD5/SHA-1); an unknown OID → `name is None` → raise "does not implement" (`test_a_token_naming_an_unknown_hash_raises_rather_than_passing`). Strict OID decoding blocks aliasing. Online path additionally cross-checks `_tst_info_imprint == (requested_oid, requested_digest)`.

### 2.6 Mock-mode leak into production — DEFENDED
`_is_mock_token` (magic prefix) alone does not admit a token; `verify_timestamp_binding` also requires `_mock_tsa_enabled()` (thread-local set by `allow_mock_tsa`/`tsa_mode="mock"`, or module-global `_MOCK_TSA_ALLOWED`), both default `False` and unsettable without code execution. Outside a testing context a mock token is logged and returns `False`. Pinned by `test_mock_token_refused_outside_testing_context` (a correctly-HMAC'd forged mock token with epoch `genTime` is refused with mock disabled, honoured only inside `allow_mock_tsa`). Creation is gated identically.

### 2.7 PKIStatus / rejection confusion — DEFENDED
`status` is enumeration-checked (0..5), required to be `granted`/`grantedWithMods`, and a granted-with-no-token is refused; `outer.finish()`/`body.finish()` reject trailing data and a second token. Pinned online and offline.

### 2.8 Unrelated-imprint acceptance (online) — DEFENDED
`request_timestamp_exchange:591-597` requires the returned token's imprint to equal `(TSA_HASH_OIDS[hash_name], digest)` (`test_a_token_that_binds_other_data_is_refused`).

### 2.9 ASN.1 DoS (nested response, huge int/OID, drip/oversize body) — DEFENDED
Response unwrap is an iterative loop bounded to `_MAX_TSR_UNWRAP=2` (not recursion); huge-PKIStatus `str()` escape closed by the pre-format enumeration check; OID body/arc bounded; online reads capped at 256 KiB with a monotonic total deadline over chunked reads. All pinned. (Offline verify has no explicit token-size cap, but parsing is linear and the caller already holds the bytes — informational.)

### 2.10 Response malleability — DEFENDED
`outer.finish()` + `body.finish()` + strict DER (definite/minimal length, no high-tag/indefinite) reject second encodings and trailing data at the response level.

### 2.11 Disabled-result confusion — DEFENDED (informational)
A `tsa_url="disabled"`, empty-token result returns `True` iff the stored `data_hash` matches `data` — it asserts only hash-match, no token/time/TSA, by design (`:1320-1324`, `test_verify_disabled_token_valid_with_matching_data`). Safe within the stated trust model (the `TimestampResult` is untrusted unless an outer control protects it). Unlike the mock path this branch is ungated; residual risk is a caller reading `True` without inspecting `tsa_url`/`token`, though a disabled result is self-evidently a non-timestamp.

### 2.12 Token-level non-canonicalisation — INCONCLUSIVE (informational, low)
`extract_tst_info` descends `ContentInfo`→`SignedData` without a final `finish()`, so trailing TLVs inside a `ContentInfo` are ignored, permitting byte-distinct tokens binding the same data. Impact is bounded (no signature is verified over the token; response-level `finish()` prevents response malleability; binding stays correct). Matters only if an outer system treats raw token byte-identity as trust — outside this subsystem's claims.

### 2.13 SSRF / header injection / plaintext downgrade via `tsa_url` — DEFENDED
Non-https or host-less URLs raise `ValueError` pre-socket (`test_http_url_is_refused`); `http.client` rejects CR/LF in host/path. `tsa_url` is configuration; an attacker-chosen https TSA reduces to the documented no-signature limitation.

## 3. Verdict

**Sound, with one low-severity robustness defect.** The subsystem's security-relevant checks — imprint binding (constant-time, token-named algorithm), PKIStatus, fresh-nonce echo, signer-present, DoS bounds, and the mock gate — are correctly implemented, fail-closed, and pinned by focused tests. The central "no signature verification" is intentional, documented, and structurally guarded against fail-open misreads. The only genuine finding (2.1) is an exception-contract violation of the very class the module closed elsewhere: a malicious/compromised TSA can emit a >4300-digit nonce so the mismatch branch `str()`s it and raises a raw `ValueError` past `get_timestamp`'s documented boundary (`:296-300`, reached from `:589`). It fails closed — a mis-typed exception / minor DoS, not a binding or authenticity bypass. No high/critical issues. Do not read `verify_timestamp_binding()==True` as third-party time attestation.