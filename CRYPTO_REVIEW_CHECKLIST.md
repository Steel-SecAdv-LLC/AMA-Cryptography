# Cryptographic Review Checklist

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 3.3.0 |
| Last Updated | 2026-07-24 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

## Purpose

This checklist is the **required review gate for any change that touches
cryptographic code** in AMA Cryptography. It exists so that security review is
a repeatable engineering procedure rather than a matter of whichever reviewer
happens to look at the diff.

It is a *forward-looking control*, not a report: every item is phrased as a
question a reviewer must be able to answer **from the diff and its tests**, and
most items name the automated gate that already enforces them, so a reviewer
can check the box by pointing at evidence instead of by opinion.

**Scope — this checklist is mandatory when a change touches any of:**

- `src/c/**` — native primitives, SIMD kernels, dispatch
- `ama_cryptography/{crypto_api,pqc_backends,key_management,secure_channel,secure_memory,hybrid_combiner,legacy_compat}.py`
- `include/**`, `src/cython/**`
- any KAT vector, fuzz harness, or constant-time harness

Changes limited to documentation, benchmarks, or non-cryptographic tooling do
not require it.

**How to use it:** copy the relevant sections into the pull-request
description and answer each item. "N/A" is an acceptable answer *with a
reason*. An unanswered item blocks merge.

---

## 1. Algorithm and Parameter Selection

- [ ] **Standardized primitive only.** The change introduces no custom cipher,
      hash, KDF, MAC, or signature scheme. Every primitive traces to a NIST
      FIPS/SP or IETF RFC. *(INVARIANT-2; see `CRYPTOGRAPHY.md`.)*
- [ ] **Parameter set is at or above the project floor.** ML-DSA-65,
      ML-KEM-1024, SLH-DSA (SHA2-256f / SHAKE-128s), Ed25519, X25519,
      AES-256-GCM, ChaCha20-Poly1305, SHA3-256/512, Argon2id (RFC 9106
      minimums). Downgrades require an explicit, written justification.
- [ ] **Key sizes are not reduced** anywhere in the diff, including defaults,
      examples, and test fixtures that downstream users copy.
- [ ] **No deprecated construction is reintroduced** (e.g. unauthenticated
      AES-CFB, PBKDF2 below the documented iteration floor, SHA-1).
- [ ] **Hybrid composition preserved.** Where the design pairs a classical and
      a post-quantum primitive, verification still requires **both** to
      succeed — a change must not make either leg optional.

## 2. Randomness

- [ ] **All key, nonce, salt, and IV material comes from a CSPRNG** — the
      native platform RNG (`ama_platform_rand.c`) or `secrets`/`os.urandom`.
- [ ] **No `random` module, `rand()`, time-seeded, or PID-seeded source** is
      used for any value with a security role. *(The `random` usage in
      `_numeric.py` / `double_helix_engine.py` is non-cryptographic modelling
      and must stay out of key paths.)*
- [ ] **RNG failure is fail-closed** — a short read or error raises rather
      than silently returning weak or partial output.
- [ ] **Nonce/IV uniqueness argument is written down** for any new AEAD use:
      random-96-bit with a usage bound, or a counter with persistence and
      overflow handling. State which, and where the bound is enforced.

## 3. Key Management Lifecycle

- [ ] **Generation** uses the approved CSPRNG path and correct sizes.
- [ ] **Storage** is authenticated (AES-256-GCM with the key id bound as AAD),
      written atomically, and created `0o600` with no world-readable window;
      the containing directory is `0o700`.
- [ ] **Caller-supplied identifiers are validated** before use in a filesystem
      path (path-traversal guard applies to *every* accessor — store,
      retrieve, and delete alike).
- [ ] **Rotation / migration is crash-safe**: an interrupted operation leaves
      the store readable under the *previous* key, and in-memory key **and**
      salt are restored together on rollback.
- [ ] **Destruction** wipes key material via `secure_memzero` on every path,
      including error and finalizer paths.
- [ ] **No key material reaches logs, exception messages, or `__repr__`.**

## 4. Constant-Time and Side-Channel Requirements

- [ ] **No secret-dependent branch** — no `if` on key, plaintext, MAC, tag,
      signature, or scalar bits.
- [ ] **No secret-dependent memory index** — no table lookup or array index
      derived from secret data (this is why the bitsliced AES S-box is the
      default; see `AMA_AES_CONSTTIME`).
- [ ] **No early-exit comparison on secrets.** All MAC/tag/signature/secret
      comparisons go through `ama_consttime_memcmp` /
      `constant_time_compare` — never `==` or `memcmp`.
- [ ] **No secret-dependent loop bound** or variable-time division/modulo on
      secret values.
- [ ] **Error paths are indistinguishable**: decryption/verification failures
      return one uniform error, with no distinguishing message, timing, or
      exception type between "bad tag" and "malformed input".
- [ ] **A dudect lane exists** for any newly added secret-processing function,
      and `tests/c/test_dudect.c` passes locally on quiet hardware
      (`taskset -c 0 ./build/bin/test_dudect --measurements 100000`).
- [ ] **Compiler cannot optimize the protection away** — `volatile` or a
      memory barrier is used where a scrub or oblivious access must survive.

## 5. Memory Safety (C layer)

- [ ] **Every buffer write is bounds-checked**; lengths are validated before
      use, and no `strcpy`/`sprintf`/unbounded `memcpy` is introduced.
- [ ] **No integer overflow** in a length or index computation, including on
      32-bit targets; shifts stay within type width and out of
      implementation-defined territory.
- [ ] **All allocations are checked**; no use-after-free or double-free.
- [ ] **Sanitizers pass** — ASan+UBSan, MSan, and Valgrind lanes are green.
- [ ] **Secrets are scrubbed before the frame is released.**

## 6. API Contract and Input Validation

- [ ] **Every public entry point validates length, type, and range** before
      touching the input.
- [ ] **Failure raises** (or returns a documented error) — a function that
      documents "raises on failure" never returns `None`/`0` instead.
- [ ] **Deserialization is bounds-checked** against a maximum field size, with
      no allocation driven by an unvalidated attacker-supplied length.
- [ ] **Trust boundaries are explicit.** If a function verifies against a key
      supplied *inside* the object being verified, the docstring must state
      that this attests validity, **not** origin authenticity.
- [ ] **Replay/ordering protection** is stated for any protocol change: window
      size, monotonic base, and the double-accept argument.

## 7. Testing Evidence

- [ ] **Known-answer vectors** from the standard pass for any new or modified
      primitive (FIPS 203/204/205, FIPS 202, SP 800-38D, RFC 8032/8439/9106).
- [ ] **A regression test pins the specific defect** this change fixes, and it
      fails without the fix.
- [ ] **Negative tests exist**: wrong key, tampered ciphertext, tampered tag,
      truncated input, replayed message.
- [ ] **Property-based coverage** for round-trip and separation invariants
      (`tests/test_property_based_crypto.py`).
- [ ] **Differential coverage** against an independent implementation where
      one exists (`tests/test_differential.py` — PyCA, PyNaCl, pycryptodome).
- [ ] **A fuzz target covers any new parser or deserializer** (`fuzz/`).
- [ ] **SIMD parity**: a new vector kernel is byte-equivalence tested against
      the scalar path.

## 8. Build, Dependency, and Supply Chain

- [ ] **No new runtime cryptographic dependency.** INVARIANT-1 prohibits a
      third-party crypto package in the production path.
- [ ] **Any new dependency is pinned** and reflected in `requirements-lock.txt`,
      with the audit (`pip-audit --strict --requirement requirements-lock.txt`)
      clean.
- [ ] **Build-dependency floors stay consistent** across
      `pyproject.toml [build-system]`, `setup.py`'s preflight, and the
      workflow pre-installs.
- [ ] **Reproducible build lane is green** (byte-equal artefact across two
      passes).
- [ ] **SBOM regenerated** if component metadata changed.

## 9. Secrets Hygiene

- [ ] **No credential material is added to the tree** — the in-house scanner
      (`python tools/check_secrets.py`, INVARIANT-23) is clean.
- [ ] **Examples and fixtures use obvious placeholders**, never a value that
      could be mistaken for a live credential.
- [ ] **Any new allowlist entry in the scanner carries a written
      justification** for why that path cannot contain a live secret.

## 10. Documentation Duties

- [ ] **Security-relevant behaviour change is documented** in `SECURITY.md`
      and/or `THREAT_MODEL.md`.
- [ ] **`CHANGELOG.md` records the change** under `[Unreleased]`, with the
      security impact stated plainly.
- [ ] **Claims match reality.** No documented guarantee (forward secrecy,
      constant-time, authenticity) is asserted that the code does not deliver;
      where a property is intentionally *not* provided, that is stated.
- [ ] **Demonstration code carries a "not for production" warning** naming the
      specific unsafe patterns it contains.

---

## Automated Gates Backing This Checklist

Many items above are enforced mechanically. A reviewer may satisfy an item by
citing the passing gate.

| Concern | Automated gate |
|---|---|
| Lint / typing | `ruff`, `black --check`, `mypy --strict` (pinned in `requirements-lock.txt`) |
| Python security lint | `bandit`, `semgrep` (`.semgrep.yml`) |
| C static analysis | `clang-tidy` (fail-closed), `cppcheck`, Clang Static Analyzer, CodeQL |
| Memory safety | ASan+UBSan, MemorySanitizer, ThreadSanitizer, Valgrind |
| Constant-time | `tests/c/test_dudect.c`, `tools/constant_time/`, dudect SIMD sweep |
| Known-answer vectors | `tests/kat/**`, `nist_vectors/`, ACVP validation workflow |
| Differential testing | `tests/test_differential.py` + PyCA/PyNaCl/pycryptodome interop lanes |
| Property-based invariants | `tests/test_property_based_crypto.py` |
| Fuzzing | `fuzz/` (12 targets), OSS-Fuzz integration |
| Dependency audit | `pip-audit --strict --requirement requirements-lock.txt` |
| Secret scanning | `tools/check_secrets.py` (INVARIANT-23) |
| Suppression hygiene | `tools/check_suppression_hygiene.py` (INVARIANT-13) |
| Version consistency | `tools/check_version_consistency.py` |
| Reproducible build | byte-equality lane in `static-analysis.yml` |

---

## Reviewer Sign-Off

```
Change:            <PR number and title>
Scope triggered:   <which sections of this checklist applied>
Sections answered: <list>
Residual risk:     <what remains, and why it is acceptable>
Reviewer:          <name>            Date: <YYYY-MM-DD>
```

A change that cannot honestly complete this block should not be merged.

---

Copyright 2025-2026 Steel Security Advisors LLC. Licensed under Apache License 2.0.
