# Cryptography Algorithms

Complete reference for all cryptographic algorithms used in AMA Cryptography, their security properties, key sizes, standards, and native C implementations.

> **Design Principle:** AMA Cryptography is built exclusively from standardized cryptographic primitives (NIST FIPS, IETF RFC). No custom ciphers, hash functions, or signature schemes. The composition protocol is an original design by Steel Security Advisors LLC.

---

## Algorithm Summary

| Algorithm | Type | Security Level | Standard | C Source | Status |
|-----------|------|---------------|----------|----------|--------|
| ML-DSA-65 (Dilithium) | Digital Signature | NIST Level 3 (192-bit quantum) | FIPS 204 | `ama_dilithium.c` | Primary PQC |
| ML-KEM-1024 (Kyber) | Key Encapsulation | NIST Level 5 (256-bit quantum) | FIPS 203 | `ama_kyber.c` | Available |
| SPHINCS+-SHA2-256f | Hash-Based Signature | NIST Level 5 (256-bit quantum) | FIPS 205 | `ama_sphincs.c` | Available |
| Ed25519 | Digital Signature | 128-bit classical | RFC 8032 | `ama_ed25519.c` | Classical + Hybrid |
| AES-256-GCM | Authenticated Encryption | 256-bit key / 128-bit quantum | SP 800-38D | `ama_aes_gcm.c` | Full |
| ChaCha20-Poly1305 | Authenticated Encryption | 256-bit key / 128-bit security | RFC 8439 | `ama_chacha20poly1305.c` | Full |
| SHA3-256 | Hash Function | 128-bit collision | FIPS 202 | `ama_sha3.c` | Full |
| HMAC-SHA3-256 | MAC | 256-bit PRF security | RFC 2104 | `ama_hkdf.c` | Full |
| HKDF-SHA3-256 | Key Derivation | 256-bit derived keys | RFC 5869 | `ama_hkdf.c` | Full |
| X25519 | Key Exchange | 128-bit classical | RFC 7748 | `ama_x25519.c` | Full |
| Argon2id | Password Hashing | Memory-hard KDF | RFC 9106 | `ama_argon2.c` | Full |
| secp256k1 | Elliptic Curve Ops | 128-bit classical | SEC 2 | `ama_secp256k1.c` | HD key derivation |

---

## Post-Quantum Cryptography

### ML-DSA-65 (CRYSTALS-Dilithium)

The **primary post-quantum signature algorithm** in AMA Cryptography.

| Property | Value |
|----------|-------|
| Standard | NIST FIPS 204 (2024) |
| Security Level | NIST Level 3 |
| Classical Security | ~2^170 operations |
| Quantum Security | ~2^190 operations (Grover-BKZ) |
| Public Key | 1,952 bytes |
| Secret Key | 4,032 bytes |
| Signature | 3,309 bytes |
| Hardness | Module Learning With Errors (MLWE) |
| Security Model | EUF-CMA in QROM |

**Performance (native C, 2026-04-06):**
- Key generation: ~0.18 ms (5,536 ops/sec)
- Signing: ~0.27 ms (3,639 ops/sec)
- Verification: ~0.15 ms (6,490 ops/sec)

**Usage:**
```python
from ama_cryptography.pqc_backends import (
    generate_dilithium_keypair,
    dilithium_sign,
    dilithium_verify,
)

kp  = generate_dilithium_keypair()            # DilithiumKeyPair
sig = dilithium_sign(b"message", kp.secret_key)
assert dilithium_verify(b"message", sig, kp.public_key)
```

---

### ML-KEM-1024 (Kyber)

**Post-quantum key encapsulation mechanism** for establishing shared secrets.

| Property | Value |
|----------|-------|
| Standard | NIST FIPS 203 (2024) |
| Security Level | NIST Level 5 |
| Quantum Security | ~2^256 operations |
| Public Key | 1,568 bytes |
| Secret Key | 3,168 bytes |
| Ciphertext | 1,568 bytes |
| Shared Secret | 32 bytes |
| Hardness | Module Learning With Errors (MLWE) |
| Security Model | IND-CCA2 in QROM |

**Usage:**
```python
from ama_cryptography.pqc_backends import (
    generate_kyber_keypair,
    kyber_encapsulate,
    kyber_decapsulate,
)

kp  = generate_kyber_keypair()                 # KyberKeyPair
enc = kyber_encapsulate(kp.public_key)         # KyberEncapsulation
recovered = kyber_decapsulate(enc.ciphertext, kp.secret_key)
assert recovered == enc.shared_secret
```

---

### SPHINCS+-SHA2-256f

**Stateless hash-based signature scheme** — security based only on hash function properties (no lattice assumptions).

| Property | Value |
|----------|-------|
| Standard | NIST FIPS 205 (2024) |
| Security Level | NIST Level 5 |
| Quantum Security | ~2^256 operations |
| Public Key | 64 bytes |
| Secret Key | 128 bytes |
| Signature | 49,856 bytes |
| Hardness | SHA-256 collision/preimage resistance |
| State | Stateless (no key state required) |

**Usage:**
```python
from ama_cryptography.pqc_backends import (
    generate_sphincs_keypair,
    sphincs_sign,
    sphincs_verify,
)

kp  = generate_sphincs_keypair()              # SphincsKeyPair
sig = sphincs_sign(b"message", kp.secret_key)
assert sphincs_verify(b"message", sig, kp.public_key)
```

> **Note:** SPHINCS+ signatures are large (≈49 KB). Use ML-DSA-65 for most applications; SPHINCS+ provides a conservative fallback with no lattice assumptions.

---

## Classical Cryptography

### Ed25519

**Classical digital signature** providing compact signatures for hybrid schemes.

| Property | Value |
|----------|-------|
| Standard | RFC 8032 |
| Curve | Edwards25519 (twisted Edwards form) |
| Security | 128-bit classical (NOT quantum-resistant) |
| Public Key | 32 bytes |
| Secret Key | 32 bytes (seed) |
| Signature | 64 bytes |
| Signing | Deterministic (RFC 8032) |

**C Implementation Features (`ama_ed25519.c`):**
- Dedicated `fe25519_sq()` field squaring (~55 multiplications vs ~100)
- C11 `_Atomic` with `memory_order_acquire`/`memory_order_release` for thread-safe initialization
- Validated against RFC 8032 Test Vector 1 (12 test vectors)
- MSVC compatibility via volatile fallback for pre-C11 compilers

**Performance** (Python/ctypes on x86-64 Linux, refreshed 2026-04-21):
- Key generation: ~0.11 ms (≈ 9,100 ops/sec)
- Signing: ~0.09 ms (≈ 10,600 ops/sec with the expanded `seed || pk` cache)
- Verification: ~0.14 ms (≈ 7,400 ops/sec)

Raw C throughput from `benchmark_c_raw` is slightly higher (~10,400
keygen / 9,700 sign / 7,200 verify ops/sec) because it bypasses the
ctypes marshaling layer.

**Usage:**
```python
from ama_cryptography.crypto_api import AmaCryptography, AlgorithmType

crypto = AmaCryptography(algorithm=AlgorithmType.ED25519)
kp = crypto.generate_keypair()
sig = crypto.sign(b"message", kp.secret_key)
assert crypto.verify(b"message", sig, kp.public_key)
```

---

### AES-256-GCM

**Authenticated encryption with associated data (AEAD)**.

| Property | Value |
|----------|-------|
| Standard | NIST SP 800-38D |
| Key | 256 bits |
| Nonce/IV | 96 bits |
| Authentication Tag | 128 bits |
| Security | 256-bit key, 128-bit quantum (Grover) |
| Forgery Probability | ≤ 2^-128 |

> **Side-Channel Note:** The default build uses the constant-time bitsliced AES S-box (`AMA_AES_CONSTTIME=ON`). Disabling it (e.g., `-DAMA_AES_CONSTTIME=OFF`) reverts to a 256-byte lookup table S-box that is **not** constant-time with respect to cache-timing and is unsafe in shared-tenant environments (cloud VMs, containers).

**Usage:**
```python
from ama_cryptography.crypto_api import AESGCMProvider
import os

aead = AESGCMProvider()
key  = os.urandom(32)                                     # 256-bit key

# Encrypt → dict: {'ciphertext', 'nonce', 'tag', 'aad', 'backend'}
out  = aead.encrypt(b"plaintext", key, aad=b"")

# Decrypt — pass nonce and tag back in; raises on tag mismatch
pt   = aead.decrypt(out["ciphertext"], key, out["nonce"], out["tag"], aad=b"")
```

---

### ChaCha20-Poly1305

**Stream cipher-based AEAD** — constant-time by design, suitable for all environments.

| Property | Value |
|----------|-------|
| Standard | RFC 8439 |
| Key | 256 bits |
| Nonce | 96 bits |
| Tag | 128 bits |
| Security | 256-bit key, 128-bit security |
| Timing | Constant-time (no table lookups) |

ChaCha20-Poly1305 is preferred over AES-GCM in environments without hardware AES-NI, or when `AMA_AES_CONSTTIME` has been explicitly disabled.

---

### X25519 (ECDH)

**Elliptic-curve Diffie-Hellman key exchange**.

| Property | Value |
|----------|-------|
| Standard | RFC 7748 |
| Curve | Curve25519 |
| Security | 128-bit classical |
| Public/Private Key | 32 bytes each |
| Shared Secret | 32 bytes |

Used in hybrid KEM constructions (paired with ML-KEM-1024 for post-quantum hybrid).

---

## Key Derivation

### HKDF-SHA3-256

**HMAC-based Key Derivation Function** — derive domain-separated subkeys from master secrets.

| Property | Value |
|----------|-------|
| Standard | RFC 5869 |
| Construction | Extract-then-Expand |
| Output Length | Variable (up to 255 × 32 bytes) |
| Domain Separation | Via `info` parameter |

**Usage:**
```python
# HKDF-SHA3-256 is driven through HDKeyDerivation for deterministic seeds,
# and through the native-C HKDF binding when derivation is invoked via
# the crypto_api / pqc_backends layer.
from ama_cryptography.key_management import HDKeyDerivation

hd = HDKeyDerivation(seed=b"\x00" * 32)
subkey = hd.derive_key(purpose=44, account=0, change=0, index=0)
```

---

### Argon2id

**Memory-hard password hashing** — resistant to GPU and ASIC brute-force attacks.

| Property | Value |
|----------|-------|
| Standard | RFC 9106 |
| Mode | Argon2id (hybrid time/memory-hard) |
| Use Case | Password hashing, key derivation from passwords |
| Tuning | Memory cost, time cost, parallelism configurable |
| Output cap (3.0.0+) | `AMA_ARGON2ID_MAX_TAG_LEN = 1024` bytes (32× the 32-byte default) |

#### Output length cap (3.0.0+)

`out_len` / `tag_len` is capped at **1024 bytes** at every public
Argon2id entry point — `ama_argon2id` (C),
`ama_cryptography.pqc_backends.native_argon2id` (Python), and the two
legacy-shim entry points below.  Calls with `out_len > 1024` return
`AMA_ERROR_INVALID_PARAM` from C and raise `ValueError` from Python:

```text
ValueError: Argon2id out_len must be in [4, 1024] bytes, got N
```

The cap is exposed as `AMA_ARGON2ID_MAX_TAG_LEN` in
`include/ama_cryptography.h` and as
`ama_cryptography.pqc_backends._ARGON2ID_MAX_TAG_LEN` so callers can
gate on it at compile or import time.  The previous unbounded surface
(`UINT32_MAX`, RFC 9106's 4 GiB theoretical maximum) was a
caller-controlled memory-exhaustion / DoS vector — callers running
inside a multi-tenant process that accepted untrusted `out_len` could
exhaust heap by passing a large value to `ama_argon2id_legacy_verify`,
which heap-allocates `computed[tag_len]` to hold the freshly-derived
tag.  Argon2id tags are universally 16-64 bytes in the wild and any
size above ~128 bytes is cryptographically indistinguishable from 64,
so the new ceiling does not constrain any spec-compliant deployment.

#### RFC 9106 conformance fix and the legacy-shim migration path

Releases ≤ 2.1.5 contained a pre-existing bug in
`blake2b_long` (H' / variable-output BLAKE2b, RFC 9106 §3.2): the
tail-bytes loop ran one iteration too far and re-hashed `V_{r+1}` to
produce the trailing 32 bytes instead of writing `V_{r+1}`'s output
verbatim.  Every memory block produced during the fill — and the final
tag — therefore had its trailing 32 bytes set to
`BLAKE2b-32(V_{r+1})` rather than `V_{r+1}[32..63]`, so AMA's Argon2id
output diverged from the spec for **every** parameter combination.
3.0.0 fixes the loop and brings AMA byte-for-byte in line with RFC 9106
(verified against `argon2-cffi` 25.1.0 and `phc-winner-argon2`'s
master).

**Migration is required for any system storing AMA-derived Argon2id
hashes.**  Tags produced by AMA ≤ 2.1.5 sit in the prior non-spec
bit-space and will not verify against post-fix AMA — or against any
other RFC 9106 implementation.  The release ships a
forward-compatible legacy path under two new symbols so downstream
consumers can verify stored tags without forking the old code.

**C API** (`include/ama_cryptography.h`):

```c
/* Derive using the pre-2.1.5 buggy blake2b_long loop. */
ama_error_t ama_argon2id_legacy(
    const uint8_t *password, size_t pwd_len,
    const uint8_t *salt,     size_t salt_len,
    uint32_t t_cost, uint32_t m_cost, uint32_t p_cost,
    uint8_t *out, size_t out_len);

/* Constant-time compare expected_tag against the legacy derivation. */
ama_error_t ama_argon2id_legacy_verify(
    const uint8_t *password, size_t pwd_len,
    const uint8_t *salt,     size_t salt_len,
    uint32_t t_cost, uint32_t m_cost, uint32_t p_cost,
    const uint8_t *expected_tag, size_t tag_len);
```

**Python API** (`ama_cryptography.pqc_backends`):

```python
from ama_cryptography.pqc_backends import (
    native_argon2id,
    native_argon2id_legacy,
    native_argon2id_legacy_verify,
)

# 1. On the next successful login, verify against the stored legacy tag.
ok = native_argon2id_legacy_verify(
    password, salt, expected_tag,
    t_cost=t, m_cost=m, p_cost=p,
)

# 2. On match, re-derive with the post-fix path and rewrite the store
#    in the same transaction.
if ok:
    new_tag = native_argon2id(password, salt, t_cost=t, m_cost=m, p_cost=p)
    storage.update_password_hash(user_id, new_tag, kdf_version=3)
```

`native_argon2id_legacy` emits an
`ama_cryptography.exceptions.SecurityWarning` on every call so
accidental use in a production code path is loud at runtime; migration
tooling can suppress the warning explicitly via
`warnings.catch_warnings()`.  `native_argon2id_legacy_verify` does NOT
emit a warning — it is the intended migration-verification path, so
spamming a warning on every login during rotation would drown
operators in noise.

**Recommended migration plan:**

1. On the next successful login, call
   `ama_argon2id_legacy_verify` (C) or `native_argon2id_legacy_verify`
   (Python) with the stored tag.
2. On match, re-derive with the post-fix `ama_argon2id` /
   `native_argon2id` and overwrite the stored hash in the same
   transaction.
3. After a deprecation window appropriate for the deployment's login
   frequency (typically 90-180 days for consumer auth, longer for B2B
   logins), remove calls to the legacy path.  The symbols remain
   exported for binary compatibility until the next major bump.

No other public API or output format changes — ChaCha20-Poly1305,
Ed25519, X25519, AES-256-GCM, SHA-3, ML-KEM, ML-DSA, and SPHINCS+
outputs are unaffected.  See `CHANGELOG.md` §3.0.0 BREAKING for the
full conformance / sweep matrix
(`t ∈ {1,2,3,4}`, `m ∈ {8,32,64,128,1024} KiB`, `p ∈ {1,2,4}`,
`out_len ∈ {16,32,64,128}`).

---

### secp256k1

**Elliptic curve operations** for BIP32-compatible HD key derivation.

| Property | Value |
|----------|-------|
| Standard | SEC 2 |
| Curve | secp256k1 (Bitcoin curve) |
| Security | 128-bit classical |
| Use Case | HD key derivation path support |

---

## Hash Functions

### SHA3-256

| Property | Value |
|----------|-------|
| Standard | NIST FIPS 202 |
| Construction | Keccak sponge (Keccak-f[1600]) |
| Output | 256 bits |
| Collision Resistance | 128-bit |
| Preimage Resistance | 256-bit |

**Performance:** ~1,046,450 ops/sec (1 µs per hash).

---

## Hybrid Constructions

### Hybrid Signature Scheme

Combining Ed25519 (classical) with ML-DSA-65 (quantum-resistant):

```
HybridSign(message, sk_ed25519, sk_dilithium):
    sig_ed25519   = Ed25519.Sign(message, sk_ed25519)
    sig_dilithium = ML-DSA-65.Sign(message, sk_dilithium)
    return sig_ed25519 || sig_dilithium

HybridVerify(message, signature, pk_ed25519, pk_dilithium):
    sig_ed, sig_dil = Split(signature)
    return Ed25519.Verify(message, sig_ed, pk_ed25519) AND
           ML-DSA-65.Verify(message, sig_dil, pk_dilithium)
```

**Security:** Secure against both classical and quantum adversaries. Both signatures must verify for acceptance.

---

### Hybrid KEM Combiner

Combining X25519 (classical) with ML-KEM-1024 (post-quantum) using a binding construction per Bindel et al. (PQCrypto 2019):

```
combined_ss = HKDF-SHA3-256(
    salt = classical_ct || pqc_ct,           # Ciphertext binding
    ikm  = classical_ss || pqc_ss,           # Combined key material
    info = label || classical_pk || pqc_pk   # Context binding
)
```

**Security:** IND-CCA2 under assumption that at least one component KEM is IND-CCA2. Secure against both classical and quantum adversaries.

See [Hybrid Cryptography](Hybrid-Cryptography) for implementation details.

---

## Key Sizes Reference

| Component | Size |
|-----------|------|
| Master Secret | 32 bytes (256 bits) |
| HMAC Key | 32 bytes (256 bits) |
| Ed25519 Private Key | 32 bytes |
| Ed25519 Public Key | 32 bytes |
| Ed25519 Signature | 64 bytes |
| ML-DSA-65 Private Key | 4,032 bytes |
| ML-DSA-65 Public Key | 1,952 bytes |
| ML-DSA-65 Signature | 3,309 bytes |
| ML-KEM-1024 Public Key | 1,568 bytes |
| ML-KEM-1024 Secret Key | 3,168 bytes |
| ML-KEM-1024 Ciphertext | 1,568 bytes |
| ML-KEM-1024 Shared Secret | 32 bytes |
| SPHINCS+ Public Key | 64 bytes |
| SPHINCS+ Secret Key | 128 bytes |
| SPHINCS+ Signature | 49,856 bytes |
| AES-256-GCM Key | 32 bytes |
| AES-256-GCM Nonce | 12 bytes |
| AES-256-GCM Tag | 16 bytes |

---

*See [Post-Quantum Cryptography](Post-Quantum-Cryptography) for in-depth PQC details, or [Performance Benchmarks](Performance-Benchmarks) for timing data.*
