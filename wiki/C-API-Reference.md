# C API Reference

Reference documentation for the AMA Cryptography native C library (`include/ama_cryptography.h`). This library provides all cryptographic primitives with zero external dependencies.

---

## Overview

The C library is built as both a shared library (`.so`/`.dll`) and static library (`.a`/`.lib`). It requires C11 (`-std=c11`).

**Include path:**
```c
#include "../include/ama_cryptography.h"
```

**Link flags:**
```bash
# Shared library
-L./build -lama_cryptography

# Static library
-L./build -lama_cryptography_static
```

---

## Context Management

### `ama_context_init()`

Initialize a cryptographic context for one algorithm.

```c
ama_context_t* ama_context_init(ama_algorithm_t algorithm);
```

`algorithm` is one of `AMA_ALG_ML_DSA_65`, `AMA_ALG_KYBER_1024`,
`AMA_ALG_SPHINCS_256F`, `AMA_ALG_ED25519`, `AMA_ALG_HYBRID`. Returns `NULL` on
allocation failure or an unknown algorithm.

### `ama_context_free()`

Securely free a context (zeroes internal key material).

```c
void ama_context_free(ama_context_t *ctx);
```

---

## Random Number Generation

### `ama_randombytes()`

Fill a buffer with cryptographically secure random bytes.

```c
ama_error_t ama_randombytes(uint8_t *buf, size_t len);
```

Uses the platform-native CSPRNG:
- Linux 3.17+: `getrandom(2)`, blocking semantics
- macOS 10.12+: `getentropy(3)` in 256-byte chunks
- Windows Vista+: `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG`
- BSD fallback: `/dev/urandom`

**Returns:** `AMA_SUCCESS`, or `AMA_ERROR_CRYPTO` if the OS CSPRNG failed.

**Header:** this one is declared in `src/c/ama_platform_rand.h`, which is *not*
part of the installed public header set — `include/ama_cryptography.h` does not
declare it. The symbol is exported from the shared library (the version script
in `cmake/ama_exports.map` exports `ama_*`), so an out-of-tree caller that wants
it must declare the prototype itself:

```c
extern ama_error_t ama_randombytes(uint8_t *buf, size_t len);

uint8_t key[32];
if (ama_randombytes(key, sizeof(key)) != AMA_SUCCESS) {
    /* handle error */
}
```

---

## Hash Functions

### SHA3-256

```c
// One-shot hash; `output` receives 32 bytes
ama_error_t ama_sha3_256(const uint8_t* input, size_t input_len, uint8_t* output);

// Streaming API (the context type is `ama_sha3_ctx`, not a `_t` alias)
ama_error_t ama_sha3_init(ama_sha3_ctx* ctx);
ama_error_t ama_sha3_update(ama_sha3_ctx* ctx, const uint8_t* data, size_t len);
ama_error_t ama_sha3_final(ama_sha3_ctx* ctx, uint8_t* output);
```

**Example:**
```c
ama_sha3_ctx ctx;
uint8_t digest[32];

ama_sha3_init(&ctx);
ama_sha3_update(&ctx, data, len);
ama_sha3_final(&ctx, digest);
```

SHA3-512 has the same three-call shape: `ama_sha3_512_init`,
`ama_sha3_512_update`, `ama_sha3_512_final`, reusing `ama_sha3_ctx`.

### SHAKE256 (XOF)

The XOF reuses `ama_sha3_ctx` — SHAKE256's rate equals SHA3-256's — so there is
no separate context type and nothing to release: the context is a plain struct
the caller owns.

```c
ama_error_t ama_shake256_inc_init(ama_sha3_ctx* ctx);
ama_error_t ama_shake256_inc_absorb(ama_sha3_ctx* ctx, const uint8_t* data, size_t len);
ama_error_t ama_shake256_inc_finalize(ama_sha3_ctx* ctx);
ama_error_t ama_shake256_inc_squeeze(ama_sha3_ctx* ctx, uint8_t* output, size_t outlen);
```

`ama_shake128_inc_*` provides the same four calls for SHAKE128.

---

## Message Authentication

### HMAC-SHA3-256

```c
ama_error_t ama_hmac_sha3_256(
    const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t out[32]             // Output: 32 bytes
);
```

---

## Key Derivation

### HKDF-SHA3-256

```c
ama_error_t ama_hkdf(
    const uint8_t *salt, size_t salt_len,   // Optional salt (NULL for zero salt)
    const uint8_t *ikm, size_t ikm_len,     // Input key material
    const uint8_t *info, size_t info_len,   // Context info
    uint8_t *okm, size_t okm_len            // Output: derived key
);
```

**Example:**
```c
uint8_t derived_key[32];
const char *info = "ama-hmac-key-v1";
ama_hkdf(
    NULL, 0,                          // no salt
    master_secret, 32,                // input key material
    (uint8_t *)info, strlen(info),    // context
    derived_key, 32                   // output
);
```

### Agent-Bound HKDF (INVARIANT-30)

Binds derived material to a named agent instance. Non-`EPHEMERAL` lifetimes and
restricted capabilities (`PERSISTENCE`, `SELF_REPLICATE`, `DELEGATE`) require an
operator-held authority key; otherwise the call refuses and writes nothing.

```c
typedef struct {
    uint8_t version;      // AMA_AGENT_BINDING_VERSION
    uint8_t lifetime;     // ama_agent_lifetime_t (EPHEMERAL/SESSION/PERSISTENT)
    uint8_t capabilities; // bitmask of AMA_AGENT_CAP_*
    uint8_t reserved;     // MUST be zero
    uint8_t instance_id[AMA_AGENT_INSTANCE_ID_BYTES];
    uint8_t ethical_profile[AMA_ETHICAL_PROFILE_BYTES];  // all-zero = absent
    uint8_t authorization[AMA_AGENT_BINDING_TAG_BYTES];  // all-zero = absent
} ama_agent_binding_t;

ama_error_t ama_agent_binding_init(ama_agent_binding_t *b,
                                   ama_agent_lifetime_t lifetime,
                                   uint8_t capabilities,
                                   const uint8_t instance_id[AMA_AGENT_INSTANCE_ID_BYTES],
                                   const uint8_t *ethical_profile);  // or NULL

ama_error_t ama_agent_binding_authorize(ama_agent_binding_t *b,      // operator-side
                                        const uint8_t *authority_key,
                                        size_t key_len);             // >= 32

ama_error_t ama_agent_binding_check(const ama_agent_binding_t *b,    // constant-time
                                    const uint8_t *authority_key,
                                    size_t key_len);

ama_error_t ama_agent_binding_context(const ama_agent_binding_t *b,  // ML-DSA/SLH-DSA ctx
                                      const uint8_t *authority_key,
                                      size_t key_len,
                                      uint8_t out_ctx[AMA_AGENT_BINDING_CONTEXT_BYTES]);

ama_error_t ama_hkdf_agent_bound(const ama_agent_binding_t *b,
                                 const uint8_t *authority_key, size_t key_len,
                                 const uint8_t *salt, size_t salt_len,
                                 const uint8_t *ikm,  size_t ikm_len,
                                 const uint8_t *info, size_t info_len,
                                 uint8_t *okm, size_t okm_len);
```

**Example — ordinary ephemeral use needs no authority key:**
```c
ama_agent_binding_t b;
uint8_t session_key[32];

ama_agent_binding_init(&b, AMA_AGENT_LIFETIME_EPHEMERAL,
                       AMA_AGENT_CAP_DATA_SIGN, instance_id, NULL);

if (ama_hkdf_agent_bound(&b, NULL, 0,
                         NULL, 0,
                         ikm, sizeof(ikm),
                         (const uint8_t *)"session", 7,
                         session_key, sizeof(session_key)) != AMA_SUCCESS) {
    /* refused: no bytes written */
}
```

Requesting `AMA_AGENT_CAP_PERSISTENCE` (or any non-`EPHEMERAL` lifetime) without
a verifying `authorization` tag returns `AMA_ERROR_ETHICAL_BINDING` and writes
nothing. The layer needs only SHA3/HMAC/HKDF, so it is available in the
`AMA_USE_NATIVE_PQC=OFF` build as well.

---

## Digital Signatures

### Ed25519

The secret key is **64 bytes**, not 32: RFC 8032's expanded form, seed followed
by the public key (`AMA_ED25519_SECRET_KEY_BYTES`). Sizing that buffer at 32
overflows it on every call.

```c
// Generate key pair
// public_key: 32 bytes, secret_key: 64 bytes (seed || public key)
ama_error_t ama_ed25519_keypair(uint8_t public_key[32], uint8_t secret_key[64]);

// Sign a message
ama_error_t ama_ed25519_sign(
    uint8_t signature[64],
    const uint8_t *message, size_t message_len,
    const uint8_t secret_key[64]
);

// Verify a signature
// Returns: AMA_SUCCESS if valid, AMA_ERROR_VERIFY_FAILED if not
ama_error_t ama_ed25519_verify(
    const uint8_t signature[64],
    const uint8_t *message, size_t message_len,
    const uint8_t public_key[32]
);
```

**Example:**
```c
uint8_t pk[AMA_ED25519_PUBLIC_KEY_BYTES];   /* 32 */
uint8_t sk[AMA_ED25519_SECRET_KEY_BYTES];   /* 64 */
ama_ed25519_keypair(pk, sk);

uint8_t sig[AMA_ED25519_SIGNATURE_BYTES];   /* 64 */
const uint8_t *msg = (const uint8_t *)"Hello";
ama_ed25519_sign(sig, msg, 5, sk);

int valid = (ama_ed25519_verify(sig, msg, 5, pk) == AMA_SUCCESS);
```

---

### ML-DSA-65 (Dilithium — FIPS 204)

Buffer sizes come from the header's parameter-set macros. There is no
`AMA_DILITHIUM_*` shorthand family:

```c
#define AMA_ML_DSA_65_PUBLIC_KEY_BYTES 1952
#define AMA_ML_DSA_65_SECRET_KEY_BYTES 4032
#define AMA_ML_DSA_65_SIGNATURE_BYTES  3309
```

Note the argument order of `verify`: **message first, signature second**.

```c
// Generate key pair
ama_error_t ama_dilithium_keypair(uint8_t *public_key, uint8_t *secret_key);

// Deterministic variant from a 32-byte seed (FIPS 204 xi)
ama_error_t ama_dilithium_keypair_from_seed(
    const uint8_t xi[32], uint8_t *public_key, uint8_t *secret_key
);

// Sign a message; *signature_len is in/out
ama_error_t ama_dilithium_sign(
    uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *secret_key
);

// Verify a signature
// Returns: AMA_SUCCESS if valid, AMA_ERROR_VERIFY_FAILED if not
ama_error_t ama_dilithium_verify(
    const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *public_key
);
```

The `ama_ml_dsa_*` entry points take an explicit `ama_ml_dsa_param_set_t`
(`AMA_ML_DSA_44`, `AMA_ML_DSA_65`, `AMA_ML_DSA_87`); the `ama_dilithium_*` names
above are the ML-DSA-65 shorthand.

---

### ML-KEM-1024 (Kyber — FIPS 203)

Buffer sizes come from the header's parameter-set macros. There is no
`AMA_KYBER_*` shorthand family:

```c
#define AMA_KYBER_1024_PUBLIC_KEY_BYTES    1568
#define AMA_KYBER_1024_SECRET_KEY_BYTES    3168
#define AMA_KYBER_1024_CIPHERTEXT_BYTES    1568
#define AMA_KYBER_1024_SHARED_SECRET_BYTES   32
```

Every buffer is passed with its length; the entry points are
`encapsulate`/`decapsulate`, not `enc`/`dec`.

```c
// Generate key pair
ama_error_t ama_kyber_keypair(
    uint8_t *pk, size_t pk_len,
    uint8_t *sk, size_t sk_len
);

// Encapsulate: produces ciphertext and shared secret from the peer public key
ama_error_t ama_kyber_encapsulate(
    const uint8_t *pk, size_t pk_len,
    uint8_t *ct, size_t *ct_len,
    uint8_t *ss, size_t ss_len
);

// Decapsulate: recovers the shared secret from the ciphertext
ama_error_t ama_kyber_decapsulate(
    const uint8_t *ct, size_t ct_len,
    const uint8_t *sk, size_t sk_len,
    uint8_t *ss, size_t ss_len
);
```

The `ama_ml_kem_*` entry points take an explicit `ama_ml_kem_param_set_t`
(`AMA_ML_KEM_512`, `AMA_ML_KEM_768`, `AMA_ML_KEM_1024`); the `ama_kyber_*` names
above are the ML-KEM-1024 shorthand.

---

### SPHINCS+-SHA2-256f (FIPS 205)

Buffer sizes come from the header's parameter-set macros. There is no
`AMA_SPHINCS_*` shorthand family:

```c
#define AMA_SPHINCS_256F_PUBLIC_KEY_BYTES     64
#define AMA_SPHINCS_256F_SECRET_KEY_BYTES    128
#define AMA_SPHINCS_256F_SIGNATURE_BYTES   49856
```

As with ML-DSA, `verify` takes the **message first, signature second**, and
`sign` writes the signature length through a `size_t *`.

```c
// Generate key pair
ama_error_t ama_sphincs_keypair(uint8_t *public_key, uint8_t *secret_key);

// Sign; *signature_len is in/out
ama_error_t ama_sphincs_sign(
    uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *secret_key
);

// Verify
// Returns: AMA_SUCCESS if valid, AMA_ERROR_VERIFY_FAILED if not
ama_error_t ama_sphincs_verify(
    const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *public_key
);
```

---

## Authenticated Encryption

### AES-256-GCM

**Key and nonce come first.** Both AEADs in this library take
`(key, nonce, payload, ...)`; a caller that puts the payload first is passing
plaintext where the key is expected, and every one of those parameters is a
`const uint8_t *`, so the compiler will not catch it.

```c
// Encrypt
// Returns: AMA_SUCCESS, or a negative ama_error_t
ama_error_t ama_aes256_gcm_encrypt(
    const uint8_t key[32],                  // 256-bit key
    const uint8_t nonce[12],                // 96-bit nonce/IV
    const uint8_t *plaintext, size_t pt_len,
    const uint8_t *aad, size_t aad_len,     // Additional authenticated data
    uint8_t *ciphertext,                    // Output: pt_len bytes
    uint8_t tag[16]                         // Output: 16-byte GCM tag
);

// Decrypt and authenticate
// Returns: AMA_SUCCESS, or AMA_ERROR_VERIFY_FAILED if the tag does not match
ama_error_t ama_aes256_gcm_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *ciphertext, size_t ct_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t tag[16],
    uint8_t *plaintext                      // Output: ct_len bytes
);
```

### ChaCha20-Poly1305

```c
// Encrypt
ama_error_t ama_chacha20poly1305_encrypt(
    const uint8_t key[32],                  // 256-bit key
    const uint8_t nonce[12],                // 96-bit nonce
    const uint8_t *plaintext, size_t pt_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *ciphertext,                    // Output: pt_len bytes
    uint8_t tag[16]                         // Output: 16-byte Poly1305 tag
);

// Decrypt and authenticate
ama_error_t ama_chacha20poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *ciphertext, size_t ct_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t tag[16],
    uint8_t *plaintext
);
```

---

## Key Exchange

### X25519

```c
// Generate key pair
// secret_key: 32 bytes (random scalar), public_key: 32 bytes (Curve25519 point)
ama_error_t ama_x25519_keypair(uint8_t public_key[32], uint8_t secret_key[32]);

// Compute shared secret
// shared_secret = X25519(our_secret_key, their_public_key)
ama_error_t ama_x25519_key_exchange(
    uint8_t shared_secret[32],
    const uint8_t our_secret_key[32],
    const uint8_t their_public_key[32]
);
```

---

## Password Hashing

### Argon2id

```c
ama_error_t ama_argon2id(
    const uint8_t *password, size_t pwd_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t t_cost,          // Time cost (iterations)
    uint32_t m_cost,          // Memory cost (KiB)
    uint32_t parallelism,     // Parallelism degree
    uint8_t *output, size_t out_len  // Output hash
);
```

---

## Constant-Time Operations

`condition` is the **first** parameter of the two conditional operations, not
the last.

```c
// Constant-time memory comparison (timing-safe)
// Returns: 0 if equal, non-zero if different
int ama_consttime_memcmp(const void *a, const void *b, size_t len);

// Constant-time conditional swap (no branch)
void ama_consttime_swap(int condition, void *a, void *b, size_t len);

// Constant-time copy (no branch on condition)
void ama_consttime_copy(int condition, void *dst, const void *src, size_t len);
```

---

## Error Codes

The canonical definition is the `ama_error_t` enum in
[`include/ama_cryptography.h`](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/blob/main/include/ama_cryptography.h):

```c
typedef enum {
    AMA_SUCCESS               =  0,
    AMA_ERROR_INVALID_PARAM   = -1,  // NULL pointer, bad length, out-of-range argument
    AMA_ERROR_MEMORY          = -2,  // Allocation failure
    AMA_ERROR_CRYPTO          = -3,  // Primitive-level failure
    AMA_ERROR_VERIFY_FAILED   = -4,  // Signature or authentication tag rejected
    AMA_ERROR_NOT_IMPLEMENTED = -5,  // Entry point compiled out of this build
    AMA_ERROR_TIMING_ATTACK   = -6,  // Timing-guard tripped
    AMA_ERROR_SIDE_CHANNEL    = -7,  // Side-channel guard tripped
    AMA_ERROR_OVERFLOW        = -8,  // Arithmetic/buffer overflow prevented
    AMA_ERROR_ETHICAL_BINDING = -9   // Agent-instance binding policy refused (INVARIANT-30)
} ama_error_t;
```

`AMA_ERROR_ETHICAL_BINDING` is deliberately distinct from
`AMA_ERROR_INVALID_PARAM`: the arguments were well-formed, the *policy* refused.
New codes are appended, so existing values never change.

---

## Build Requirements

- **C Standard:** C11 (`CMAKE_C_STANDARD 11`, no extensions)
- **CMake:** 3.15+
- **Compiler:** GCC 7+, Clang 6+, MSVC 2019+
- **Platforms:** Linux, macOS, Windows

See [Installation](Installation) for build instructions.

---

*See [Cryptography Algorithms](Cryptography-Algorithms) for algorithm specifications, or [Installation](Installation) for build instructions.*
