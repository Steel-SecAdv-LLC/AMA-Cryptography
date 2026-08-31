## Adversarial Security Review — Subsystem: integrity-chain

**Branch:** steel/systempqc-maint1  **Scope:** `_self_test.py`, `_build_sign.py`, `_integrity_signature.py`, `integrity.py`, `__init__.py` (POST/import gating), plus the trust dependencies in `pqc_backends.py`, `_module_state.py`, `_artefact_source.py` that the chain rests on. Read-only review.

### 1. Threat model

**Assets.** (A1) Only genuinely-signed source+native-lib+bindings reach `OPERATIONAL`. (A2) The compiled trust anchor, which upgrades a signature from *internally consistent* to *authentic*. (A3) The FIPS §4.9.2 guarantee that a failed POST inhibits all crypto.

**Trust roots.** The v3 Ed25519 signature over `SHA3-256(domain_v3 ‖ py_digest ‖ native_digest ‖ serialized_binding_digests)` is the in-tree root; the compiled anchor `ama_integrity_trust_anchor_pubkey_hex` (read from the loaded native library) is the authenticity root.

**Adversary.** File write to the installed tree; import hijack; environment control; a partial build; source read. Two tiers: a **partial** attacker who cannot forge a signature under the release anchor (must be fully defended), and a **full** file-write attacker who replaces the native library and re-anchors under their own key (explicitly out of in-tree scope, met out-of-band).

### 2. Attacks attempted (evidence at the line level)

| # | Attack | Outcome | Sev |
|---|--------|---------|-----|
| 1 | `AMA_BUILD_PIPELINE=1` env-var alone buys unverified map / import-through-failed-POST | **Defended** | n/a |
| 2 | Signer repair carve-out → OPERATIONAL over failed POST | **Defended** | n/a |
| 3 | Delete artefact → digest-only fallback on anchored build | **Defended** | n/a |
| 4 | Poison artefact `__pycache__` `.pyc`, leave `.py` valid | **Defended** | n/a |
| 5 | Replace native lib only; map via binding `DT_NEEDED` | **Defended** | n/a |
| 6 | Replace one signed binding `.so` | **Defended** | n/a |
| 7 | Edit `.py` only + build-pipeline env | **Defended** | n/a |
| 8 | Re-sign artefact with attacker key on anchored build | **Defended** | n/a |
| 9 | Concatenation-collision / cross-schema field grafting | **Defended** | n/a |
| 10 | Poison a checker module's own `.pyc` (`_self_test`/`__init__`/`pqc_backends`) | Inconclusive (documented boundary) | low |
| 11 | Full coherent replacement (re-anchor) | Inconclusive (by-design boundary) | medium |
| 12 | `AMA_CRYPTO_LIB_PATH` backend substitution downgrades anchored build in non-strict mode | Inconclusive (residual) | low |
| 13 | TOCTOU on pre-import binding gate (hash-by-path, import-by-path) | Inconclusive (residual) | low |
| 14 | Disable timing-oracle / swap KAT vector | **Defended** | n/a |

**Defended, key evidence.**
- **Env-var fail-open closed (1):** `_process_is_the_integrity_signer` (`pqc_backends.py:514`) now requires `AMA_BUILD_PIPELINE=1` **and** launch identity via `sys.orig_argv`/`__main__.__spec__` in a *writing* subcommand (`:584-693`); pre-load map at `:825-827` gates on identity/override **and not** secure-exec. An env-only attacker cannot alter `orig_argv`/`__main__`. Pinned by `test_trust_anchor_pinning.py::TestSignerIdentityRunpyWindow`.
- **Carve-out never reaches OPERATIONAL (2):** the signer branch (`__init__.py:459-494`) skips the raise but leaves the module in ERROR (set during POST); `check_crypto_permitted` (`_module_state.py:169-175`) refuses in ERROR. OPERATIONAL is set only when `all_passed` (`_self_test.py:3139`). A broken KAT/RNG/timing hard-fails regardless (`__init__.py:437-449`).
- **Anchor closes the digest-only fallback (3):** `verify_module_integrity` reads the compiled anchor and refuses fallback when anchored (`_self_test.py:1789-1831`), failing closed on an unresolvable anchor (`:1783-1788`).
- **Artefact-as-data poisoning closed (4):** all three pre-bytecode readers use `_artefact_source.load_artefact_fields` (`ast` parse of source text, non-literal nodes rejected) — `__init__.py:175`, `pqc_backends.py:451`, `_self_test.py:1409` — so a poisoned `.pyc` is never consulted. `test_artefact_cache_poisoning.py`.
- **Native lib never mapped unverified (5):** `_try_load_library` refuses **before** mapping on digest mismatch and fd-pins via `/proc/self/fd` (`pqc_backends.py:812-858`); `_binding_imports_permitted` (`:4954`) blocks binding probes until the library is verified+loaded, so `DT_NEEDED` can't map a refused object. `test_native_library_never_mapped_unverified.py` (asserts `MAPPED=no`).
- **Injective framing (9):** length-prefixed/section-tagged/version-prefixed digest (`_self_test.py:730-833`) and count/length-prefixed binding serialization (`:478-498`); distinct v2/v3 domains make field grafting a signature failure (`:1254-1287`). Mirrored byte-for-byte in `_build_sign.py`, pinned equal by tests.

**Residuals (real, but correctly scoped / disclosed).**
- **(11) Coherent re-anchoring** is the fundamental limit: the anchor is read from the very library a full-write attacker replaces. Not claimed defended — `__init__.py:143-151` and `SECURITY.md:391-467` state *"internal consistency, not authenticity"* and ship `tools/verify_install_oob.py`, whose checker lives outside the tree and **requires an externally-held `--expected-pubkey`**.
- **(10) Checker `.pyc` poisoning** — `execution-integrity` (`_self_test.py:868-1203`) catches poisoned bytecode of *not-yet-executed* modules (incl. `co_exceptiontable`, `:903`), but is post-load for the checkers themselves. Disclosed (`SECURITY.md:391-419`); mitigated by read-only install / `PYTHONDONTWRITEBYTECODE` / OS code signing.
- **(12) `AMA_CRYPTO_LIB_PATH` downgrade** — because the anchor is read from the loaded library, an override with no compiled anchor makes an anchored release read `unanchored`; the real signature still verifies, the native lib is recorded `UNVERIFIED` skip, and **non-strict** POST reaches OPERATIONAL on the substituted backend. *Mitigations:* revoked under secure-execution mode (`pqc_backends.py:1095-1107`, `_in_secure_execution_mode` `:1001-1048`), escalated to a hard failure by `AMA_FIPS_STRICT=1` (`_self_test.py:2819-2823`), surfaced by `module_attestation()[anchored/fully_verified/integrity_strength]`, logged WARNING, and requires env+file capability that already grants `LD_PRELOAD`-class code execution. A documented, layered-mitigated developer override — not a silent anchor forgery.
- **(13) Binding-gate TOCTOU** — bindings are imported by CPython (no fd-pinning), so a hash-then-load swap is theoretically possible; needs file-write + a startup race, strictly weaker than (11).

### 3. Verdict

The chain defends every **partial-attacker** path with a concrete, tested control and correctly moves security decisions onto structured state rather than prose. The two hard boundaries (full re-anchoring; checker-bytecode poisoning) are inherent to in-process self-checking, are honestly documented, and are met out-of-band by `verify_install_oob.py`. **No novel bypass to OPERATIONAL over tampered code was found for the partial adversary.**

**Operator actions (deployment, not code):** set `AMA_FIPS_STRICT=1`; assert `module_attestation()['anchored'] is True`; install read-only or with `PYTHONDONTWRITEBYTECODE=1`; gate release acceptance on `tools/verify_install_oob.py --expected-pubkey <out-of-band key>`. No code change is required to close a defect.