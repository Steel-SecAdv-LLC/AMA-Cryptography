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

Initialize a cryptographic context.

```c
ama_context_t *ama_context_init(void);
```

### `ama_context_free()`

Securely free a context (zeroes internal key material).

```c
void ama_context_free(ama_context_t *ctx);
```

---

## Random Number Generation

### `ama_random_bytes()`

Generate cryptographically secure random bytes.

```c
int ama_random_bytes(uint8_t *buf, size_t len);
```

Uses platform-native CSPRNG:
- Linux: `getrandom()` syscall (kernel ≥ 3.17)
- macOS: `getentropy()`
- Windows: `BCryptGenRandom()`

**Returns:** 0 on success, negative on error.

```c
uint8_t key[32];
if (ama_random_bytes(key, 32) != 0) {
    // handle error
}
```

---

## Hash Functions

### SHA3-256

```c
// One-shot hash
int ama_sha3_256(
    const uint8_t *message, size_t message_len,
    uint8_t digest[32]          // Output: 32 bytes
);

// Streaming API
ama_sha3_ctx_t ctx;
ama_sha3_256_init(&ctx);
ama_sha3_256_update(&ctx, data, len);
ama_sha3_256_final(&ctx, digest);
```

### SHAKE256 (XOF)

```c
void ama_shake256_inc_init(ama_shake256incctx *ctx);
void ama_shake256_inc_absorb(ama_shake256incctx *ctx, const uint8_t *in, size_t inlen);
void ama_shake256_inc_finalize(ama_shake256incctx *ctx);
void ama_shake256_inc_squeeze(uint8_t *out, size_t outlen, ama_shake256incctx *ctx);
void ama_shake256_inc_ctx_release(ama_shake256incctx *ctx);
```

---

## Message Authentication

### HMAC-SHA3-256

```c
int ama_hmac_sha3_256(
    const uint8_t *key, size_t key_len,
    const uint8_t *message, size_t message_len,
    uint8_t tag[32]             // Output: 32 bytes
);
```

---

## Key Derivation

### HKDF-SHA3-256

```c
int ama_hkdf(
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

---

## Digital Signatures

### Ed25519

```c
// Generate key pair
// pk: 32 bytes, sk: 32 bytes (seed)
int ama_ed25519_keypair(uint8_t pk[32], uint8_t sk[32]);

// Sign a message
// sig: 64 bytes output
int ama_ed25519_sign(
    uint8_t sig[64],
    const uint8_t *message, size_t message_len,
    const uint8_t sk[32]
);

// Verify a signature
// Returns: 0 if valid, non-zero if invalid
int ama_ed25519_verify(
    const uint8_t sig[64],
    const uint8_t *message, size_t message_len,
    const uint8_t pk[32]
);
```

**Example:**
```c
uint8_t pk[32], sk[32];
ama_ed25519_keypair(pk, sk);

uint8_t sig[64];
const uint8_t *msg = (uint8_t *)"Hello";
ama_ed25519_sign(sig, msg, 5, sk);

int valid = (ama_ed25519_verify(sig, msg, 5, pk) == 0);
```

---

### ML-DSA-65 (Dilithium — FIPS 204)

```c
// Key sizes
#define AMA_DILITHIUM_PK_BYTES   1952
#define AMA_DILITHIUM_SK_BYTES   4032
#define AMA_DILITHIUM_SIG_BYTES  3309

// Generate key pair
int ama_dilithium_keypair(
    uint8_t pk[AMA_DILITHIUM_PK_BYTES],
    uint8_t sk[AMA_DILITHIUM_SK_BYTES]
);

// Sign a message
int ama_dilithium_sign(
    uint8_t *sig, size_t *sig_len,          // sig_len output ≤ AMA_DILITHIUM_SIG_BYTES
    const uint8_t *message, size_t msg_len,
    const uint8_t sk[AMA_DILITHIUM_SK_BYTES]
);

// Verify a signature
// Returns: 0 if valid, non-zero if invalid
int ama_dilithium_verify(
    const uint8_t *sig, size_t sig_len,
    const uint8_t *message, size_t msg_len,
    const uint8_t pk[AMA_DILITHIUM_PK_BYTES]
);
```

---

### ML-KEM-1024 (Kyber — FIPS 203)

```c
// Key sizes
#define AMA_KYBER_PK_BYTES   1568
#define AMA_KYBER_SK_BYTES   3168
#define AMA_KYBER_CT_BYTES   1568
#define AMA_KYBER_SS_BYTES   32

// Generate key pair
int ama_kyber_keypair(
    uint8_t pk[AMA_KYBER_PK_BYTES],
    uint8_t sk[AMA_KYBER_SK_BYTES]
);

// Encapsulate: generates ciphertext and shared secret
int ama_kyber_enc(
    uint8_t ct[AMA_KYBER_CT_BYTES],
    uint8_t ss[AMA_KYBER_SS_BYTES],
    const uint8_t pk[AMA_KYBER_PK_BYTES]
);

// Decapsulate: recovers shared secret from ciphertext
int ama_kyber_dec(
    uint8_t ss[AMA_KYBER_SS_BYTES],
    const uint8_t ct[AMA_KYBER_CT_BYTES],
    const uint8_t sk[AMA_KYBER_SK_BYTES]
);
```

---

### SPHINCS+-SHA2-256f (FIPS 205)

```c
// Key sizes
#define AMA_SPHINCS_PK_BYTES   64
#define AMA_SPHINCS_SK_BYTES   128
#define AMA_SPHINCS_SIG_BYTES  49856

// Generate key pair
int ama_sphincs_keypair(
    uint8_t pk[AMA_SPHINCS_PK_BYTES],
    uint8_t sk[AMA_SPHINCS_SK_BYTES]
);

// Sign
int ama_sphincs_sign(
    uint8_t sig[AMA_SPHINCS_SIG_BYTES],
    const uint8_t *message, size_t msg_len,
    const uint8_t sk[AMA_SPHINCS_SK_BYTES]
);

// Verify
// Returns: 0 if valid, non-zero if invalid
int ama_sphincs_verify(
    const uint8_t sig[AMA_SPHINCS_SIG_BYTES],
    const uint8_t *message, size_t msg_len,
    const uint8_t pk[AMA_SPHINCS_PK_BYTES]
);
```

---

## Authenticated Encryption

### AES-256-GCM

```c
// Encrypt
// Returns: 0 on success, negative on error
int ama_aes256_gcm_encrypt(
    const uint8_t *plaintext, size_t pt_len,
    const uint8_t *aad, size_t aad_len,     // Additional authenticated data
    const uint8_t key[32],                  // 256-bit key
    const uint8_t iv[12],                   // 96-bit nonce/IV
    uint8_t *ciphertext,                    // Output: pt_len bytes
    uint8_t tag[16]                         // Output: 16-byte GCM tag
);

// Decrypt and authenticate
// Returns: 0 on success, AMA_ERR_AUTH_FAILED if tag mismatch
int ama_aes256_gcm_decrypt(
    const uint8_t *ciphertext, size_t ct_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t key[32],
    const uint8_t iv[12],
    const uint8_t tag[16],
    uint8_t *plaintext                      // Output: ct_len bytes
);
```

### ChaCha20-Poly1305

```c
// Encrypt
int ama_chacha20poly1305_encrypt(
    const uint8_t *plaintext, size_t pt_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t key[32],                  // 256-bit key
    const uint8_t nonce[12],                // 96-bit nonce
    uint8_t *ciphertext,                    // Output: pt_len bytes
    uint8_t tag[16]                         // Output: 16-byte Poly1305 tag
);

// Decrypt and authenticate
int ama_chacha20poly1305_decrypt(
    const uint8_t *ciphertext, size_t ct_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t tag[16],
    uint8_t *plaintext
);
```

---

## Key Exchange

### X25519

```c
// Generate key pair
// sk: 32 bytes (random scalar), pk: 32 bytes (Curve25519 public key)
int ama_x25519_keypair(uint8_t pk[32], uint8_t sk[32]);

// Compute shared secret
// shared_secret = X25519(sk, peer_pk)
int ama_x25519_key_exchange(
    uint8_t shared_secret[32],
    const uint8_t sk[32],
    const uint8_t peer_pk[32]
);
```

---

## Password Hashing

### Argon2id

```c
int ama_argon2id(
    const uint8_t *password, size_t pwd_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t t_cost,          // Time cost (iterations)
    uint32_t m_cost,          // Memory cost (KiB)
    uint32_t parallelism,     // Parallelism degree
    uint8_t *output, size_t output_len  // Output hash
);
```

---

## Constant-Time Operations

```c
// Constant-time memory comparison (timing-safe)
// Returns: 0 if equal, non-zero if different
int ama_consttime_memcmp(const void *a, const void *b, size_t len);

// Constant-time conditional swap (no branch)
void ama_consttime_swap(void *a, void *b, size_t len, int condition);

// Constant-time copy (no branch on condition)
void ama_consttime_copy(void *dst, const void *src, size_t len, int condition);
```

---

## Error Codes

```c
#define AMA_OK              0   // Success
#define AMA_ERR_INVALID    -1   // Invalid parameter
#define AMA_ERR_AUTH_FAILED -2  // Authentication tag mismatch
#define AMA_ERR_KEYGEN     -3   // Key generation failure
#define AMA_ERR_SIGN       -4   // Signing failure
#define AMA_ERR_VERIFY     -5   // Verification failure
#define AMA_ERR_RANDOM     -6   // RNG failure
#define AMA_ERR_OVERFLOW   -7   // Buffer overflow prevented
```

---

## Build Requirements

- **C Standard:** C11 (`CMAKE_C_STANDARD 11`, no extensions)
- **CMake:** 3.15+
- **Compiler:** GCC 7+, Clang 6+, MSVC 2019+
- **Platforms:** Linux, macOS, Windows

See [Installation](Installation) for build instructions.

---

*See [Cryptography Algorithms](Cryptography-Algorithms) for algorithm specifications, or [Installation](Installation) for build instructions.*
