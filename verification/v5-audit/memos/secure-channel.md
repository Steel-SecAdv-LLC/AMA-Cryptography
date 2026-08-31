# Adversarial Security Review — `secure-channel` subsystem

**Target:** `ama_cryptography/secure_channel.py` (branch `steel/systempqc-maint1`, HEAD `a14cc83`)
**Scope:** PQ Noise-NK handshake, `SecureSession` AEAD transport, epoch rekeying (`MAX_ENCRYPTIONS_PER_EPOCH`, `REKEY_INTERVAL`), nonce management, replay window, `ChannelState` machine.
**Method:** Full line-level read of the target plus its dependencies (`_module_state.secure_token_bytes`, `pqc_backends` AES-GCM/HKDF, `crypto_api` Hybrid KEM/Sig, `hybrid_combiner`) and the pinning tests (`test_secure_channel_comprehensive`, `test_session_comprehensive`, `test_handshake_failure_clears_state`, `test_trust_anchor_pinning`, `test_pr224_followup`, `test_gap_closure_review`). READ-ONLY; no files modified, no jobs run.

## Threat model

**Assets:** application plaintext over an established session; the session secret and derived per-direction AES-256 keys; the AES-GCM `(key, nonce)` uniqueness invariant; the responder's static KEM/sig private keys (NK trust root); endpoint availability.

**Trust boundaries:** the wire is fully attacker-controlled. Every field crossing `*.deserialize`, `handle_handshake`, `complete_handshake`, and `decrypt` is untrusted. The responder static **KEM public key** is the initiator's out-of-band trust anchor (constructor arg). `expected_responder_sig_pk`, when supplied, is the out-of-band **signature** pin. The local `SecureSession` object and its public fields are not attacker-reachable without code execution (out of scope).

**Adversary:** active on-path MITM — read/drop/reorder/replay/tamper/inject; reads source and the cleartext 32-byte `session_id` from any frame; controls frame size/timing; may be a malicious legitimate peer. Cannot break AES-256-GCM, HKDF-SHA3-256, X25519, Kyber-1024, Ed25519, ML-DSA-65, and does not hold the responder private keys.

## Attacks attempted (focus areas in bold)

| # | Attack | Outcome | Sev |
|---|--------|---------|-----|
| 1 | **Nonce reuse across rekey epochs** | Defended | n/a |
| 2 | **Nonce collision within one epoch (birthday)** | Defended | n/a |
| 3 | **Replay** (in-window duplicate / altered seq) | Defended | n/a |
| 4 | **Replay** of evicted seq incl. large-gap base-jump | Defended | n/a |
| 5 | **Cross-epoch replay** after rekey | Defended | n/a |
| 6 | Reflection / cross-direction confusion | Defended | n/a |
| 7 | **Downgrade / version rollback** | Defended | n/a |
| 8 | **State-machine confusion** | Defended | n/a |
| 9 | **Key reuse after rekey (H2)** | Defended | n/a |
| 10 | Decrypt-path resource exhaustion (size-cap asymmetry) | **VULNERABLE** | Low |
| 11 | Handshake replay → unbounded responder sessions | **VULNERABLE** | Low |
| 12 | Active MITM / unauthenticated responder default | Defended* | Low |
| 13 | KEM decapsulation error oracle | Defended | n/a |
| 14 | Responder does not validate shared-secret length | Defended | n/a |
| 15 | AAD counter overflow (epoch `>I`, seq `>Q`) | Defended | n/a |

\*confidentiality unconditional; responder *identity* requires the optional pin.

### Defended — key evidence

- **Nonce reuse across epochs (1):** `rekey()` (L727-765) HKDF-derives fresh `send`/`recv` keys, wipes the old bytearrays in place (L754), and bumps `rekey_epoch` (L760). Distinct key per epoch ⇒ a repeated 96-bit nonce is still a distinct `(key,nonce)`. GCM uniqueness is per-key.
- **Within-epoch birthday (2):** nonce is CSPRNG-drawn per message (L633). Before the draw, `encrypt` fails **closed** with `RekeyRequiredError` once `sends_since_rekey >= 2^20` (L622-629), consuming no seq (pinned: `test_encrypt_refuses_past_epoch_budget`). 2²⁰ nonces ⇒ collision ≈ 2⁻⁵⁷ per key; only `encrypt` draws (one direction per key).
- **Replay (3-5):** `seq` is in the AAD (L640/705) so it cannot be altered without failing the tag; duplicate seqs are rejected below-base or in-set; the window/base mutate only **after** AEAD success (L714-721), all under `self._lock`, so garbage/forged frames cannot poison the window. Base invariant proven: every evicted (seen) seq is `< base`, every retained seq is `>= base`; the gap-jump only skips **never-seen** seqs. Cross-epoch replays are additionally killed by the epoch in the AAD.
- **Reflection (6):** the two directions use different keys (`initiator.send_key == responder.recv_key`, and vice-versa, from distinct HKDF `info` at L1060-1069 / L1220-1229), so the identical AAD at equal seq is harmless.
- **Downgrade (7):** `handle_handshake` hard-rejects any non-matching `protocol_name`/`version` (L1135-1142) before key work; no negotiation/fallback exists. v1 (epoch-less AAD) cannot be forced.
- **State machine (8):** `SecureSession` starts ESTABLISHED; encrypt/decrypt assert it (L610/687). Initiator guards `INITIATOR_START`/`HANDSHAKE_SENT`; any completion failure routes through `_abandon_handshake` (L966-998) which drops the shared secret and latches **CLOSED**, so no second attempt — even with the legitimate response — can resurrect the channel (pinned: `test_handshake_failure_clears_state`).
- **Key reuse after rekey (9):** new HKDF keys + old-key wipe + epoch-in-AAD + budget reset. Audit fix H2 is present and effective.
- **KEM oracle (13):** all decap failures collapse to one `HandshakeError("Handshake failed")` `from None`, detail logged at WARNING only (L1157-1165; pinned: `test_gap_closure_review` Item 4).

### VULNERABLE — findings to fix

**F1 (Low, DoS / defense-in-depth) — receive path does not bound ciphertext size.**
`encrypt` refuses plaintext > `MAX_MESSAGE_SIZE` (L601-605) but `decrypt` (L663-708) performs **no** symmetric check before calling `native_aes256_gcm_decrypt`, which allocates a plaintext buffer the size of the ciphertext and runs full GHASH+CTR before the tag is checked. `ChannelMessage.deserialize` bounds `ct_len` (a 32-bit field) only by the actual buffer (L220) — unlike `HandshakeMessage`/`HandshakeResponse`, it applies **no `_MAX_FIELD_BYTES` ceiling** and does not reject trailing bytes. An on-path attacker who read the cleartext `session_id` (passing the L692 check) can force proportional allocation + AEAD work per oversized fresh-seq frame. Bounded (~1:1 bytes, requires the correct 256-bit session_id and actually sending the payload), so it is a robustness asymmetry, not a confidentiality/integrity break. *Fix:* reject `len(msg.ciphertext) > MAX_MESSAGE_SIZE` early in `decrypt`, and add a `_MAX_FIELD_BYTES`/`MAX_MESSAGE_SIZE` cap (and trailing-byte rejection) to `ChannelMessage.deserialize`.

**F2 (Low, DoS) — unbounded responder session creation on replayed handshakes.**
`handle_handshake` (L1114-1208) is stateless with no seen-ciphertext cache or rate limit: a captured `HandshakeMessage` replayed K times triggers K hybrid decapsulate+sign operations and K sessions. No key reuse results (fresh CSPRNG `session_id` ⇒ distinct keys), and the attacker still cannot derive keys, so impact is CPU plus memory **if** the caller retains sessions. Mitigation (rate-limit, session-store cap) is left to the integrator; the library offers none itself.

### Integration hazard (documented, not a hidden flaw)

**Unauthenticated responder by default.** Confidentiality against a MITM is unconditional (secret is encapsulated to the responder's static KEM key). But responder **identity** is only established when `expected_responder_sig_pk` is pinned (constant-time compare at L1024-1032, pinned by `test_trust_anchor_pinning`). The pin is optional for backwards compatibility; an unpinned caller verifies the signature against a peer-chosen key, which authenticates nothing. Deployments needing responder authentication MUST pin.

## Verdict

The cryptographic core of the subsystem is **sound**. All focus attacks — nonce reuse across/within epochs, replay (every variant analysed, including the large-gap base-jump), downgrade, state-machine confusion, and key reuse after rekey — are **DEFENDED** with concrete line-level evidence, and the referenced prior audit fixes (H2 epoch-in-AAD, C1 encap validation) are in place. The residual issues are two **Low**-severity availability/robustness gaps (F1 receive-side size caps, F2 responder replay/rate limit) plus the documented optional-pin hazard. Recommended hardening: mirror `MAX_MESSAGE_SIZE` on `decrypt`, add the `_MAX_FIELD_BYTES` cap and trailing-byte rejection to `ChannelMessage.deserialize`, provide/encourage a responder-side handshake rate limit and session cap, and document `expected_responder_sig_pk` as mandatory for authenticated deployments. No changes made (read-only review).