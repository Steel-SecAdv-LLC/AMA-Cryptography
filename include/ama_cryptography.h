/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file ama_cryptography.h
 * @brief AMA Cryptography - Core C API for Post-Quantum Cryptography
 * @version 2.1.2
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-04-06
 *
 * High-performance C implementation of quantum-resistant cryptographic primitives.
 */

#ifndef AMA_CRYPTOGRAPHY_H
#define AMA_CRYPTOGRAPHY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* DLL export/import macro for Windows.
 *
 * When compiling the library itself (shared or static), AMA_API is either
 * __declspec(dllexport) or empty.  Only external consumers of the shared
 * DLL get __declspec(dllimport). */
#if defined(_WIN32) || defined(_WIN64)
  #ifdef AMA_BUILDING_SHARED
    #define AMA_API __declspec(dllexport)
  #elif defined(AMA_BUILDING_STATIC) || defined(AMA_TESTING_MODE)
    #define AMA_API  /* static library or test build — no dllimport */
  #else
    #define AMA_API __declspec(dllimport)
  #endif
#else
  #define AMA_API
#endif

/* ============================================================================
 * VERSION INFORMATION
 * ============================================================================ */

#define AMA_CRYPTOGRAPHY_VERSION_MAJOR 2
#define AMA_CRYPTOGRAPHY_VERSION_MINOR 1
#define AMA_CRYPTOGRAPHY_VERSION_PATCH 2
#define AMA_CRYPTOGRAPHY_VERSION_STRING "2.1.2"

/* ============================================================================
 * ALGORITHM IDENTIFIERS
 * ============================================================================ */

typedef enum {
    AMA_ALG_ML_DSA_65 = 0,    /**< CRYSTALS-Dilithium (ML-DSA-65) */
    AMA_ALG_KYBER_1024 = 1,   /**< CRYSTALS-Kyber (Kyber-1024) */
    AMA_ALG_SPHINCS_256F = 2, /**< SPHINCS+-256f */
    AMA_ALG_ED25519 = 3,      /**< Ed25519 (classical) */
    AMA_ALG_HYBRID = 4        /**< Hybrid mode (classical + PQC) */
} ama_algorithm_t;

/* ============================================================================
 * ERROR CODES
 * ============================================================================ */

typedef enum {
    AMA_SUCCESS = 0,
    AMA_ERROR_INVALID_PARAM = -1,
    AMA_ERROR_MEMORY = -2,
    AMA_ERROR_CRYPTO = -3,
    AMA_ERROR_VERIFY_FAILED = -4,
    AMA_ERROR_NOT_IMPLEMENTED = -5,
    AMA_ERROR_TIMING_ATTACK = -6,
    AMA_ERROR_SIDE_CHANNEL = -7,
    AMA_ERROR_OVERFLOW = -8
} ama_error_t;

/* ============================================================================
 * KEY SIZES (bytes)
 * ============================================================================ */

/* ML-DSA-65 (Dilithium3) - FIPS 204 */
#define AMA_ML_DSA_65_PUBLIC_KEY_BYTES 1952
#define AMA_ML_DSA_65_SECRET_KEY_BYTES 4032
#define AMA_ML_DSA_65_SIGNATURE_BYTES 3309

/* Kyber-1024 */
#define AMA_KYBER_1024_PUBLIC_KEY_BYTES 1568
#define AMA_KYBER_1024_SECRET_KEY_BYTES 3168
#define AMA_KYBER_1024_CIPHERTEXT_BYTES 1568
#define AMA_KYBER_1024_SHARED_SECRET_BYTES 32

/* SPHINCS+-256f */
#define AMA_SPHINCS_256F_PUBLIC_KEY_BYTES 64
#define AMA_SPHINCS_256F_SECRET_KEY_BYTES 128
#define AMA_SPHINCS_256F_SIGNATURE_BYTES 49856

/* Ed25519 */
#define AMA_ED25519_PUBLIC_KEY_BYTES 32
#define AMA_ED25519_SECRET_KEY_BYTES 64
#define AMA_ED25519_SIGNATURE_BYTES 64

/* ============================================================================
 * OPAQUE TYPES
 * ============================================================================ */

typedef struct ama_context_t ama_context_t;
typedef struct ama_keypair_t ama_keypair_t;
typedef struct ama_signature_t ama_signature_t;

/* ============================================================================
 * CONTEXT MANAGEMENT
 * ============================================================================ */

/**
 * @brief Initialize AMA Cryptography context
 * @param algorithm Algorithm to use
 * @return Opaque context pointer, NULL on failure
 */
AMA_API ama_context_t* ama_context_init(ama_algorithm_t algorithm);

/**
 * @brief Free AMA Cryptography context and scrub memory
 * @param ctx Context to free
 */
AMA_API void ama_context_free(ama_context_t* ctx);

/* ============================================================================
 * KEY GENERATION
 * ============================================================================ */

/**
 * @brief Generate a new keypair (constant-time)
 *
 * Generates a cryptographic keypair for the algorithm specified in the context.
 * Supports ML-DSA-65, Kyber-1024, SPHINCS+-256f, Ed25519, and hybrid modes.
 * All algorithms use native implementations (no external PQC dependencies).
 *
 * @param ctx Initialized context
 * @param public_key Output buffer for public key
 * @param public_key_len Length of public key buffer
 * @param secret_key Output buffer for secret key
 * @param secret_key_len Length of secret key buffer
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_keypair_generate(
    ama_context_t* ctx,
    uint8_t* public_key,
    size_t public_key_len,
    uint8_t* secret_key,
    size_t secret_key_len
);

/* ============================================================================
 * SIGNATURE OPERATIONS
 * ============================================================================ */

/**
 * @brief Sign a message (constant-time)
 *
 * Signs a message using the algorithm specified in the context.
 * Supports ML-DSA-65, SPHINCS+-256f, and Ed25519 natively.
 *
 * @param ctx Initialized context
 * @param message Message to sign
 * @param message_len Length of message
 * @param secret_key Secret key
 * @param secret_key_len Length of secret key
 * @param signature Output buffer for signature
 * @param signature_len Pointer to signature length (in/out)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_sign(
    ama_context_t* ctx,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* signature,
    size_t* signature_len
);

/**
 * @brief Verify a signature (constant-time)
 *
 * Verifies a signature using the algorithm specified in the context.
 * Supports ML-DSA-65, SPHINCS+-256f, and Ed25519 natively.
 *
 * @param ctx Initialized context
 * @param message Message to verify
 * @param message_len Length of message
 * @param signature Signature to verify
 * @param signature_len Length of signature
 * @param public_key Public key
 * @param public_key_len Length of public key
 * @return AMA_SUCCESS if valid, AMA_ERROR_VERIFY_FAILED if invalid
 */
AMA_API ama_error_t ama_verify(
    ama_context_t* ctx,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,
    size_t signature_len,
    const uint8_t* public_key,
    size_t public_key_len
);

/* ============================================================================
 * KEY ENCAPSULATION (Kyber-1024)
 * ============================================================================ */

/**
 * @brief Encapsulate a shared secret
 *
 * Performs KEM encapsulation using Kyber-1024 (ML-KEM-1024).
 * Generates a random shared secret and ciphertext using the recipient's public key.
 * Uses native implementation (FIPS 203 compliant).
 *
 * @param ctx Initialized context (must be Kyber-1024)
 * @param public_key Recipient's public key
 * @param public_key_len Length of public key
 * @param ciphertext Output buffer for ciphertext
 * @param ciphertext_len Pointer to ciphertext length (in/out)
 * @param shared_secret Output buffer for shared secret
 * @param shared_secret_len Length of shared secret buffer
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_kem_encapsulate(
    ama_context_t* ctx,
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* ciphertext,
    size_t* ciphertext_len,
    uint8_t* shared_secret,
    size_t shared_secret_len
);

/**
 * @brief Decapsulate a shared secret
 *
 * Performs KEM decapsulation using Kyber-1024 (ML-KEM-1024).
 * Recovers the shared secret from ciphertext using the recipient's secret key.
 * Uses implicit rejection for IND-CCA2 security (FIPS 203 compliant).
 *
 * @param ctx Initialized context (must be Kyber-1024)
 * @param ciphertext Ciphertext to decapsulate
 * @param ciphertext_len Length of ciphertext
 * @param secret_key Recipient's secret key
 * @param secret_key_len Length of secret key
 * @param shared_secret Output buffer for shared secret
 * @param shared_secret_len Length of shared secret buffer
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_kem_decapsulate(
    ama_context_t* ctx,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* shared_secret,
    size_t shared_secret_len
);

/* ============================================================================
 * CONSTANT-TIME UTILITIES
 * ============================================================================ */

/**
 * @brief Constant-time memory comparison
 * @param a First buffer
 * @param b Second buffer
 * @param len Length to compare
 * @return 0 if equal, non-zero otherwise (timing-safe)
 */
AMA_API int ama_consttime_memcmp(const void* a, const void* b, size_t len);

/**
 * @brief Secure memory scrubbing
 * @param ptr Memory to scrub
 * @param len Length to scrub
 */
AMA_API void ama_secure_memzero(void* ptr, size_t len);

/**
 * @brief Lock memory pages to prevent swapping to disk.
 * @param ptr Pointer to memory region
 * @param len Length of memory region
 * @return AMA_SUCCESS or AMA_ERROR_MEMORY
 */
AMA_API ama_error_t ama_secure_mlock(void* ptr, size_t len);

/**
 * @brief Unlock previously locked memory pages.
 * @param ptr Pointer to memory region
 * @param len Length of memory region
 * @return AMA_SUCCESS or AMA_ERROR_MEMORY
 */
AMA_API ama_error_t ama_secure_munlock(void* ptr, size_t len);

/**
 * @brief Allocate a secure buffer with mlock and DONTDUMP.
 * @param size Number of bytes to allocate
 * @return Pointer to locked, zeroed memory, or NULL on failure
 */
AMA_API void* ama_secure_alloc(size_t size);

/**
 * @brief Free a secure buffer with guaranteed zeroization and munlock.
 * @param ptr Pointer from ama_secure_alloc
 * @param size Size of the allocation
 */
AMA_API void ama_secure_free(void* ptr, size_t size);

/**
 * @brief Constant-time conditional swap
 * @param condition Swap if non-zero
 * @param a First buffer
 * @param b Second buffer
 * @param len Length to swap
 */
AMA_API void ama_consttime_swap(int condition, void* a, void* b, size_t len);

/**
 * @brief Constant-time table lookup
 * @param table Table to lookup from
 * @param table_len Number of elements in table
 * @param elem_size Size of each element in bytes
 * @param index Index to lookup (may be secret)
 * @param output Output buffer for selected element
 */
AMA_API void ama_consttime_lookup(
    const void* table,
    size_t table_len,
    size_t elem_size,
    size_t index,
    void* output
);

/**
 * @brief Constant-time conditional copy
 * @param condition Copy if non-zero
 * @param dst Destination buffer
 * @param src Source buffer
 * @param len Length to copy
 */
AMA_API void ama_consttime_copy(int condition, void* dst, const void* src, size_t len);

/* ============================================================================
 * HASHING AND KEY DERIVATION
 * ============================================================================ */

/**
 * @brief SHA3-256 hash (FIPS 202)
 *
 * Computes the SHA3-256 cryptographic hash of the input data.
 * Uses the Keccak-f[1600] sponge construction with rate 136 and capacity 64.
 *
 * @param input Input data
 * @param input_len Length of input
 * @param output Output buffer (32 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_sha3_256(
    const uint8_t* input,
    size_t input_len,
    uint8_t* output
);

/**
 * @brief SHA3-512 hash (FIPS 202)
 *
 * Computes the SHA3-512 cryptographic hash of the input data.
 * Uses the Keccak-f[1600] sponge construction with rate 72 and capacity 128.
 * Required by FIPS 203 (ML-KEM) as the G function.
 *
 * @param input Input data
 * @param input_len Length of input
 * @param output Output buffer (64 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_sha3_512(
    const uint8_t* input,
    size_t input_len,
    uint8_t* output
);

/* ============================================================================
 * STREAMING SHA3-256 API (init/update/final)
 * Enables hashing of large data streams without loading everything into memory
 * ============================================================================ */

/**
 * @brief SHA3-256 streaming context
 */
typedef struct {
    uint64_t state[25];     /**< Keccak state (1600 bits) */
    uint8_t buffer[168];    /**< Rate buffer (168 bytes max for SHAKE128; 136 for SHA3-256/SHAKE256) */
    size_t buffer_len;      /**< Current bytes in buffer */
    int finalized;          /**< Set to 1 after final() called */
} ama_sha3_ctx;

/**
 * @brief Initialize SHA3-256 streaming context
 *
 * @param ctx Context to initialize
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_sha3_init(ama_sha3_ctx* ctx);

/**
 * @brief Update SHA3-256 with additional data
 *
 * Can be called multiple times to process data in chunks.
 *
 * @param ctx Initialized context
 * @param data Data to absorb
 * @param len Length of data in bytes
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_sha3_update(ama_sha3_ctx* ctx, const uint8_t* data, size_t len);

/**
 * @brief Finalize SHA3-256 and output digest
 *
 * After calling this, the context cannot be used again without re-initializing.
 *
 * @param ctx Context to finalize
 * @param output Output buffer (32 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_sha3_final(ama_sha3_ctx* ctx, uint8_t* output);

/* ============================================================================
 * STREAMING SHAKE256 API (init/absorb/finalize/squeeze)
 * Enables incremental absorb and multi-block squeeze for SHAKE256 (XOF)
 * Reuses ama_sha3_ctx since SHAKE256 rate = 136 = SHA3-256 rate
 * ============================================================================ */

/**
 * @brief Initialize SHAKE256 incremental context
 */
AMA_API ama_error_t ama_shake256_inc_init(ama_sha3_ctx* ctx);

/**
 * @brief Absorb data into SHAKE256 incremental context
 */
AMA_API ama_error_t ama_shake256_inc_absorb(ama_sha3_ctx* ctx, const uint8_t* data, size_t len);

/**
 * @brief Finalize SHAKE256 absorption (apply padding). Must be called before squeeze.
 */
AMA_API ama_error_t ama_shake256_inc_finalize(ama_sha3_ctx* ctx);

/**
 * @brief Squeeze output bytes from finalized SHAKE256 context. Can be called multiple times.
 */
AMA_API ama_error_t ama_shake256_inc_squeeze(ama_sha3_ctx* ctx, uint8_t* output, size_t outlen);

/* ============================================================================
 * STREAMING SHAKE128 API (init/absorb/finalize/squeeze)
 * Enables incremental absorb and multi-block squeeze for SHAKE128 (XOF)
 * SHAKE128 rate = 168 bytes
 * ============================================================================ */

/**
 * @brief Initialize SHAKE128 incremental context
 */
AMA_API ama_error_t ama_shake128_inc_init(ama_sha3_ctx* ctx);

/**
 * @brief Absorb data into SHAKE128 incremental context
 */
AMA_API ama_error_t ama_shake128_inc_absorb(ama_sha3_ctx* ctx, const uint8_t* data, size_t len);

/**
 * @brief Finalize SHAKE128 absorption (apply padding). Must be called before squeeze.
 */
AMA_API ama_error_t ama_shake128_inc_finalize(ama_sha3_ctx* ctx);

/**
 * @brief Squeeze output bytes from finalized SHAKE128 context. Can be called multiple times.
 */
AMA_API ama_error_t ama_shake128_inc_squeeze(ama_sha3_ctx* ctx, uint8_t* output, size_t outlen);

/**
 * @brief HMAC-SHA3-256 per RFC 2104 using AMA's native SHA3-256 implementation.
 *
 * @param key       Pointer to key bytes
 * @param key_len   Key length in bytes (any length; keys >136 bytes are hashed)
 * @param msg       Pointer to message bytes
 * @param msg_len   Message length in bytes
 * @param out       Output buffer, must be at least 32 bytes
 * @return          AMA_SUCCESS on success, AMA_ERROR_MEMORY on allocation failure
 *
 * INVARIANT-1 compliant: uses only ama_sha3.c — zero external crypto dependencies.
 * Constant-time: output comparison must use ama_consttime_memcmp, not memcmp.
 */
AMA_API ama_error_t ama_hmac_sha3_256(
    const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t out[32]
);

/**
 * @brief HMAC-SHA-512 (RFC 2104)
 *
 * Computes HMAC using SHA-512 for BIP32 key derivation and general-purpose
 * keyed authentication.
 *
 * @param key       HMAC key
 * @param key_len   Length of key in bytes
 * @param msg       Message to authenticate
 * @param msg_len   Length of message in bytes
 * @param out       Output buffer (must be at least 64 bytes)
 * @return          AMA_SUCCESS on success, AMA_ERROR_INVALID_PARAM if key or out
 *                  is NULL (or msg is NULL with msg_len > 0),
 *                  AMA_ERROR_MEMORY on allocation failure
 *
 * INVARIANT-1 compliant: uses only ama_sha2.h — zero external crypto dependencies.
 */
AMA_API ama_error_t ama_hmac_sha512(
    const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t out[64]
);

/**
 * @brief HKDF key derivation (RFC 5869)
 *
 * Derives key material using HKDF with HMAC-SHA3-256.
 * Implements Extract-then-Expand paradigm for secure key derivation.
 * Maximum output length: 255 * 32 = 8160 bytes.
 *
 * @param salt Salt value (can be NULL for zero-length salt)
 * @param salt_len Length of salt
 * @param ikm Input key material
 * @param ikm_len Length of IKM
 * @param info Context information (can be NULL)
 * @param info_len Length of info
 * @param okm Output key material
 * @param okm_len Desired length of OKM
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_hkdf(
    const uint8_t* salt,
    size_t salt_len,
    const uint8_t* ikm,
    size_t ikm_len,
    const uint8_t* info,
    size_t info_len,
    uint8_t* okm,
    size_t okm_len
);

/* ============================================================================
 * ED25519 STANDALONE API
 * ============================================================================ */

/**
 * @brief Generate Ed25519 keypair
 *
 * Generates an Ed25519 keypair. The caller must provide 32 bytes of random
 * seed data in secret_key[0..31] before calling. The function will compute
 * the public key and store it in both public_key and secret_key[32..63].
 *
 * @param public_key Output: 32-byte public key
 * @param secret_key Input/Output: 64-byte buffer (seed in, seed||pk out)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_ed25519_keypair(uint8_t public_key[32], uint8_t secret_key[64]);

/**
 * @brief Sign a message with Ed25519
 *
 * Creates an Ed25519 signature for a message using the secret key.
 * Implements RFC 8032 Ed25519 (pure EdDSA).
 *
 * @param signature Output: 64-byte signature
 * @param message Message to sign
 * @param message_len Length of message
 * @param secret_key 64-byte secret key (seed || public_key)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_ed25519_sign(
    uint8_t signature[64],
    const uint8_t *message,
    size_t message_len,
    const uint8_t secret_key[64]
);

/**
 * @brief Verify an Ed25519 signature
 *
 * Verifies an Ed25519 signature on a message.
 * Implements RFC 8032 Ed25519 verification.
 *
 * @param signature 64-byte signature
 * @param message Message to verify
 * @param message_len Length of message
 * @param public_key 32-byte public key
 * @return AMA_SUCCESS if valid, AMA_ERROR_VERIFY_FAILED if invalid
 */
AMA_API ama_error_t ama_ed25519_verify(
    const uint8_t signature[64],
    const uint8_t *message,
    size_t message_len,
    const uint8_t public_key[32]
);

/* ============================================================================
 * AES-256-GCM AUTHENTICATED ENCRYPTION (NIST SP 800-38D)
 * ============================================================================ */

#define AMA_AES256_KEY_BYTES   32
#define AMA_AES256_GCM_NONCE_BYTES 12
#define AMA_AES256_GCM_TAG_BYTES   16

/**
 * @brief AES-256-GCM authenticated encryption
 *
 * Encrypts plaintext and produces ciphertext + 16-byte authentication tag.
 * Conforms to NIST SP 800-38D.
 *
 * @param key        32-byte AES-256 key
 * @param nonce      12-byte nonce (IV)
 * @param plaintext  Plaintext to encrypt (can be NULL if pt_len == 0)
 * @param pt_len     Length of plaintext
 * @param aad        Additional authenticated data (can be NULL if aad_len == 0)
 * @param aad_len    Length of AAD
 * @param ciphertext Output: ciphertext (same length as plaintext)
 * @param tag        Output: 16-byte authentication tag
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_aes256_gcm_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *plaintext,
    size_t pt_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *ciphertext,
    uint8_t tag[16]
);

/**
 * @brief AES-256-GCM authenticated decryption
 *
 * Verifies authentication tag and decrypts ciphertext.
 * Returns AMA_ERROR_VERIFY_FAILED if tag mismatch.
 *
 * @param key        32-byte AES-256 key
 * @param nonce      12-byte nonce (IV)
 * @param ciphertext Ciphertext to decrypt
 * @param ct_len     Length of ciphertext
 * @param aad        Additional authenticated data (can be NULL if aad_len == 0)
 * @param aad_len    Length of AAD
 * @param tag        16-byte authentication tag to verify
 * @param plaintext  Output: decrypted plaintext (same length as ciphertext)
 * @return AMA_SUCCESS or AMA_ERROR_VERIFY_FAILED
 */
AMA_API ama_error_t ama_aes256_gcm_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *ciphertext,
    size_t ct_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t tag[16],
    uint8_t *plaintext
);

/* ============================================================================
 * SECP256K1 ELLIPTIC CURVE (BIP32 HD KEY DERIVATION)
 * ============================================================================ */

#define AMA_SECP256K1_PRIVKEY_BYTES  32
#define AMA_SECP256K1_PUBKEY_BYTES   33  /* SEC1 compressed */

/**
 * @brief Scalar multiplication on secp256k1
 *
 * Computes out = scalar * (point_x, point_y) using a constant-time Montgomery ladder.
 *
 * @param scalar    32-byte big-endian scalar
 * @param point_x   32-byte big-endian X coordinate of input point
 * @param point_y   32-byte big-endian Y coordinate of input point
 * @param out_x     Output: 32-byte big-endian X coordinate of result
 * @param out_y     Output: 32-byte big-endian Y coordinate of result
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_secp256k1_point_mul(
    const uint8_t scalar[32],
    const uint8_t point_x[32],
    const uint8_t point_y[32],
    uint8_t out_x[32],
    uint8_t out_y[32]
);

/**
 * @brief Compute compressed SEC1 public key from private key
 *
 * Performs constant-time Montgomery ladder scalar multiplication on secp256k1.
 * Output is 33 bytes: 0x02 or 0x03 prefix + 32-byte X coordinate.
 *
 * @param privkey 32-byte private key (must be in [1, N-1])
 * @param compressed_pubkey Output: 33-byte compressed public key
 * @return AMA_SUCCESS or AMA_ERROR_INVALID_PARAM
 */
AMA_API ama_error_t ama_secp256k1_pubkey_from_privkey(
    const uint8_t privkey[32],
    uint8_t compressed_pubkey[33]
);

/* ============================================================================
 * X25519 KEY EXCHANGE (RFC 7748)
 * ============================================================================ */

#define AMA_X25519_KEY_BYTES 32

/**
 * @brief Generate X25519 keypair
 *
 * Generates a random secret key (clamped per RFC 7748) and computes
 * the corresponding public key via scalar multiplication with base point 9.
 *
 * @param public_key Output: 32-byte public key
 * @param secret_key Output: 32-byte secret key (clamped)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_x25519_keypair(
    uint8_t public_key[32],
    uint8_t secret_key[32]
);

/**
 * @brief X25519 Diffie-Hellman key exchange
 *
 * Computes shared_secret = X25519(our_secret_key, their_public_key).
 * Returns AMA_ERROR_CRYPTO if result is all-zero (low-order point rejection).
 *
 * @param shared_secret Output: 32-byte shared secret
 * @param our_secret_key Our 32-byte secret key
 * @param their_public_key Their 32-byte public key
 * @return AMA_SUCCESS or AMA_ERROR_CRYPTO
 */
AMA_API ama_error_t ama_x25519_key_exchange(
    uint8_t shared_secret[32],
    const uint8_t our_secret_key[32],
    const uint8_t their_public_key[32]
);

/* ============================================================================
 * ARGON2ID KEY DERIVATION (RFC 9106)
 * ============================================================================ */

#define AMA_ARGON2_SALT_BYTES  16
#define AMA_ARGON2_TAG_BYTES   32

/**
 * @brief Argon2id password hashing / key derivation (RFC 9106)
 *
 * Memory-hard KDF with resistance to GPU/ASIC attacks.
 * Single-threaded execution (parallelism affects block layout only).
 *
 * @param password    Password bytes
 * @param pwd_len     Password length
 * @param salt        Salt (16+ bytes recommended)
 * @param salt_len    Salt length
 * @param t_cost      Time cost (iterations, >= 1)
 * @param m_cost      Memory cost in KiB (>= 8 * parallelism)
 * @param parallelism Degree of parallelism (lanes)
 * @param output      Output tag buffer
 * @param out_len     Desired output length (>= 4)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_argon2id(
    const uint8_t *password, size_t pwd_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    uint8_t *output, size_t out_len
);

/* ============================================================================
 * CHACHA20-POLY1305 AEAD (RFC 8439)
 * ============================================================================ */

#define AMA_CHACHA20_KEY_BYTES    32
#define AMA_CHACHA20_NONCE_BYTES  12
#define AMA_POLY1305_TAG_BYTES    16

/**
 * @brief ChaCha20-Poly1305 AEAD encryption (RFC 8439)
 *
 * Encrypts plaintext and produces ciphertext + 16-byte authentication tag.
 *
 * @param key        32-byte key
 * @param nonce      12-byte nonce
 * @param plaintext  Plaintext to encrypt (can be NULL if pt_len == 0)
 * @param pt_len     Length of plaintext
 * @param aad        Additional authenticated data (can be NULL if aad_len == 0)
 * @param aad_len    Length of AAD
 * @param ciphertext Output: ciphertext (same length as plaintext)
 * @param tag        Output: 16-byte authentication tag
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_chacha20poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *plaintext, size_t pt_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *ciphertext,
    uint8_t tag[16]
);

/**
 * @brief ChaCha20-Poly1305 AEAD decryption (RFC 8439)
 *
 * Verifies tag and decrypts. Fail-closed: zeros plaintext on tag mismatch.
 *
 * @param key        32-byte key
 * @param nonce      12-byte nonce
 * @param ciphertext Ciphertext to decrypt
 * @param ct_len     Length of ciphertext
 * @param aad        Additional authenticated data (can be NULL if aad_len == 0)
 * @param aad_len    Length of AAD
 * @param tag        16-byte authentication tag to verify
 * @param plaintext  Output: decrypted plaintext (same length as ciphertext)
 * @return AMA_SUCCESS or AMA_ERROR_VERIFY_FAILED
 */
AMA_API ama_error_t ama_chacha20poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *ciphertext, size_t ct_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t tag[16],
    uint8_t *plaintext
);

/* ============================================================================
 * DIRECT PQC ALGORITHM ACCESS
 * ============================================================================ */

/**
 * @brief Generate ML-DSA-65 (Dilithium) keypair
 *
 * @param public_key Output: public key (1952 bytes)
 * @param secret_key Output: secret key (4032 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_dilithium_keypair(
    uint8_t *public_key, uint8_t *secret_key
);

/**
 * @brief Sign message with ML-DSA-65 (Dilithium)
 *
 * @param signature     Output: signature buffer
 * @param signature_len Output: actual signature length
 * @param message       Message to sign
 * @param message_len   Length of message
 * @param secret_key    Secret key (4032 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_dilithium_sign(
    uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *secret_key
);

/**
 * @brief Verify ML-DSA-65 (Dilithium) signature
 *
 * @param message       Message to verify
 * @param message_len   Length of message
 * @param signature     Signature to verify
 * @param signature_len Length of signature
 * @param public_key    Public key (1952 bytes)
 * @return AMA_SUCCESS if valid, AMA_ERROR_VERIFY_FAILED if invalid
 */
AMA_API ama_error_t ama_dilithium_verify(
    const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *public_key
);

/**
 * @brief Verify ML-DSA-65 signature with context (FIPS 204 external/pure)
 *
 * Applies domain-separation wrapper M' = 0x00 || len(ctx) || ctx || M
 * before delegating to ama_dilithium_verify().
 *
 * @param message       Message to verify
 * @param message_len   Length of message
 * @param ctx           Context string (0–255 bytes)
 * @param ctx_len       Length of context (must be <= 255)
 * @param signature     Signature to verify (3309 bytes)
 * @param signature_len Length of signature
 * @param public_key    Public key (1952 bytes)
 * @return AMA_SUCCESS if valid, AMA_ERROR_VERIFY_FAILED if invalid
 */
AMA_API ama_error_t ama_dilithium_verify_ctx(
    const uint8_t *message, size_t message_len,
    const uint8_t *ctx, size_t ctx_len,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *public_key
);

/**
 * @brief Generate Kyber-1024 keypair
 *
 * @param pk     Output: public key buffer
 * @param pk_len Public key buffer length
 * @param sk     Output: secret key buffer
 * @param sk_len Secret key buffer length
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_kyber_keypair(
    uint8_t *pk, size_t pk_len,
    uint8_t *sk, size_t sk_len
);

/**
 * @brief Kyber-1024 key encapsulation
 *
 * @param pk     Public key
 * @param pk_len Public key length
 * @param ct     Output: ciphertext buffer
 * @param ct_len Output: ciphertext length
 * @param ss     Output: shared secret buffer
 * @param ss_len Shared secret buffer length
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_kyber_encapsulate(
    const uint8_t *pk, size_t pk_len,
    uint8_t *ct, size_t *ct_len,
    uint8_t *ss, size_t ss_len
);

/**
 * @brief Kyber-1024 key decapsulation
 *
 * @param ct     Ciphertext
 * @param ct_len Ciphertext length
 * @param sk     Secret key
 * @param sk_len Secret key length
 * @param ss     Output: shared secret buffer
 * @param ss_len Shared secret buffer length
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_kyber_decapsulate(
    const uint8_t *ct, size_t ct_len,
    const uint8_t *sk, size_t sk_len,
    uint8_t *ss, size_t ss_len
);

/**
 * @brief Generate SPHINCS+-256f keypair
 *
 * @param public_key Output: public key (64 bytes)
 * @param secret_key Output: secret key (128 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_sphincs_keypair(
    uint8_t *public_key, uint8_t *secret_key
);

/**
 * @brief Sign message with SPHINCS+-256f
 *
 * @param signature     Output: signature buffer
 * @param signature_len Output: actual signature length
 * @param message       Message to sign
 * @param message_len   Length of message
 * @param secret_key    Secret key (128 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_sphincs_sign(
    uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *secret_key
);

/**
 * @brief Verify SPHINCS+-256f signature
 *
 * @param message       Message to verify
 * @param message_len   Length of message
 * @param signature     Signature to verify
 * @param signature_len Length of signature
 * @param public_key    Public key (64 bytes)
 * @return AMA_SUCCESS if valid, AMA_ERROR_VERIFY_FAILED if invalid
 */
AMA_API ama_error_t ama_sphincs_verify(
    const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *public_key
);

/**
 * @brief Verify SPHINCS+-256f signature with context (FIPS 205 external/pure)
 *
 * Applies domain-separation wrapper M' = 0x00 || len(ctx) || ctx || M
 * before delegating to ama_sphincs_verify().
 *
 * @param message       Message to verify
 * @param message_len   Length of message
 * @param ctx           Context string (0–255 bytes)
 * @param ctx_len       Length of context (must be <= 255)
 * @param signature     Signature to verify (49856 bytes)
 * @param signature_len Length of signature
 * @param public_key    Public key (64 bytes)
 * @return AMA_SUCCESS if valid, AMA_ERROR_VERIFY_FAILED if invalid
 */
AMA_API ama_error_t ama_sphincs_verify_ctx(
    const uint8_t *message, size_t message_len,
    const uint8_t *ctx, size_t ctx_len,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *public_key
);

/* ============================================================================
 * DETERMINISTIC KEYGEN FROM SEED (KAT TESTING)
 * ============================================================================ */

/**
 * @brief Deterministic Kyber-1024 keypair from seed
 *
 * Generates keypair from provided seeds, bypassing RNG.
 * Used for NIST KAT validation.
 *
 * @param d   32-byte seed for key generation
 * @param z   32-byte seed for implicit rejection
 * @param pk  Output: public key (1568 bytes)
 * @param sk  Output: secret key (3168 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_kyber_keypair_from_seed(
    const uint8_t d[32], const uint8_t z[32],
    uint8_t *pk, uint8_t *sk
);

/**
 * @brief Deterministic ML-DSA-65 keypair from seed
 *
 * Generates keypair from provided seed, bypassing RNG.
 * Used for NIST KAT validation.
 *
 * @param xi          32-byte seed
 * @param public_key  Output: public key (1952 bytes)
 * @param secret_key  Output: secret key (4032 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_dilithium_keypair_from_seed(
    const uint8_t xi[32],
    uint8_t *public_key, uint8_t *secret_key
);

/* ============================================================================
 * CONSTANT-TIME AES S-BOX (bitsliced / algebraic decomposition)
 * ============================================================================ */

/**
 * @brief Constant-time AES S-box substitution
 *
 * Computes the AES SubBytes transformation using algebraic decomposition
 * in GF((2^4)^2) tower field arithmetic. No lookup tables are used —
 * all operations are bitwise, eliminating cache-timing side channels.
 *
 * When AMA_AES_CONSTTIME is defined, the AES-GCM implementation uses
 * this function instead of the standard 256-byte S-box table.
 *
 * @param x Input byte
 * @return S-box output byte
 */
AMA_API uint8_t ama_aes_sbox_consttime(uint8_t x);

/**
 * @brief AES-256 key expansion using constant-time S-box
 */
AMA_API void ama_aes256_key_expansion_consttime(
    const uint8_t key[32], uint8_t round_keys[240]);

/**
 * @brief AES-256 block encryption using constant-time S-box
 */
AMA_API void ama_aes256_encrypt_block_consttime(
    const uint8_t round_keys[240], const uint8_t in[16], uint8_t out[16]);

/* ============================================================================
 * VERSIONING
 * ============================================================================ */

/**
 * @brief Get library version string
 * @return Version string (e.g., "1.0.0")
 */
AMA_API const char* ama_version_string(void);

/**
 * @brief Get library version number
 * @param major Output for major version
 * @param minor Output for minor version
 * @param patch Output for patch version
 */
AMA_API void ama_version_number(int* major, int* minor, int* patch);

#ifdef __cplusplus
}
#endif

#endif /* AMA_CRYPTOGRAPHY_H */
