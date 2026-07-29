// Copyright (C) 2025-2026 Steel Security Advisors LLC
// SPDX-License-Identifier: Apache-2.0
//
// Full-surface multi-library throughput harness.
//
// Measures every AMA primitive that at least one other library also exposes,
// against every such library available on the host, in one process, on one
// set of buffers, with identical iteration counts and best-of-N round
// selection. Emits both a text table and JSON.
//
// Libraries: AMA, OpenSSL, libsodium, wolfSSL, Botan-2, Nettle, libgcrypt,
// mbedTLS. Each is behind a HAVE_* guard so a host missing one still builds;
// the JSON records which were compiled in, so an absent library reads as
// absent rather than as a silent gap in the table.
//
// INVARIANT-36 scope note: no library here is consulted as a correctness
// oracle. Every peer is a *speed reference only* — outputs are never compared
// for correctness, and AMA's own test suite (NIST ACVP / Wycheproof vectors)
// remains the sole source of correctness truth. That invariant governs
// ground-truth for correctness, not the existence of a stopwatch.
//
// Crypto++ is deliberately absent: wolfssl/options.h defines byte/word32
// macros that collide with crypto++/cryptlib.h in the same translation unit.
// Including it would need a separate TU; not done, and not silently implied.

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <string>
#include <algorithm>

extern "C" {
#include "ama_cryptography.h"
}

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#endif

#ifdef HAVE_SODIUM
#include <sodium.h>
#endif

#ifdef HAVE_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#endif

#ifdef HAVE_BOTAN
#include <botan/aead.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/pubkey.h>
#include <botan/ed25519.h>
#include <botan/ecdsa.h>
#include <botan/ec_group.h>
#include <botan/auto_rng.h>
#include <botan/curve25519.h>
#include <botan/pwdhash.h>
#endif

#ifdef HAVE_NETTLE
#include <nettle/sha3.h>
#include <nettle/gcm.h>
#include <nettle/aes.h>
#include <nettle/chacha-poly1305.h>
#include <nettle/eddsa.h>
#include <nettle/curve25519.h>
#endif

#ifdef HAVE_GCRYPT
#include <gcrypt.h>
#endif

#ifdef HAVE_MBEDTLS
#include <mbedtls/gcm.h>
#include <mbedtls/chachapoly.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#endif

// ── Timing ────────────────────────────────────────────────────────────────
static double now_us() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static inline uint64_t rdtsc() {
#if defined(__x86_64__)
    uint32_t lo, hi;
    __asm__ __volatile__("lfence\n\trdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#else
    return 0;
#endif
}

// Measured, not assumed. The previous revision hardcoded 2.80264e9, which
// silently mis-scales every cycles/byte figure on any other host.
static double measure_freq_hz() {
    double best = 0;
    for (int r = 0; r < 5; r++) {
        uint64_t c0 = rdtsc();
        double t0 = now_us();
        struct timespec req = {0, 30 * 1000 * 1000};  // 30 ms
        nanosleep(&req, nullptr);
        double dt = (now_us() - t0) * 1e-6;
        uint64_t dc = rdtsc() - c0;
        double hz = dc / dt;
        if (hz > best) best = hz;  // best-of: scheduler steals time, never adds it
    }
    return best;
}

static double FREQ = 0;

// ── Host identity ─────────────────────────────────────────────────────────
//
// A clock speed alone does not identify the machine a row was measured on,
// and for this table that is not a cosmetic gap. The peer AES-GCM figures
// move by roughly 4x depending on whether the host implements VAES +
// VPCLMULQDQ: an implementation with a 512-bit AES-GCM kernel reaches ~0.2
// cycles/byte where the same source on a host without those instructions
// reaches ~0.79. Comparing a number measured on one against a number
// measured on the other, with only "measured clock 2.8 GHz" printed beside
// them, silently attributes a 4x ISA difference to the implementations.
//
// So the JSON records the CPU brand string and the feature bits that decide
// which kernel each library selects. Nothing here is used to gate AMA's own
// dispatch; this is provenance for the artifact.
struct HostInfo {
    char brand[64];
    int aes_ni, pclmulqdq, vaes, vpclmulqdq;
    int avx2, avx512f, sha_ni, bmi2, adx;
};

static HostInfo probe_host() {
    HostInfo h;
    memset(&h, 0, sizeof(h));
    snprintf(h.brand, sizeof(h.brand), "unknown");
#if defined(__x86_64__)
    unsigned int r[4];
    // Brand string: CPUID leaves 0x80000002..0x80000004, 16 bytes each.
    __asm__ __volatile__("cpuid" : "=a"(r[0]), "=b"(r[1]), "=c"(r[2]), "=d"(r[3])
                         : "a"(0x80000000u), "c"(0));
    if (r[0] >= 0x80000004u) {
        char b[49];
        for (unsigned leaf = 0; leaf < 3; leaf++) {
            __asm__ __volatile__("cpuid" : "=a"(r[0]), "=b"(r[1]), "=c"(r[2]), "=d"(r[3])
                                 : "a"(0x80000002u + leaf), "c"(0));
            memcpy(b + leaf * 16 + 0,  &r[0], 4);
            memcpy(b + leaf * 16 + 4,  &r[1], 4);
            memcpy(b + leaf * 16 + 8,  &r[2], 4);
            memcpy(b + leaf * 16 + 12, &r[3], 4);
        }
        b[48] = '\0';
        // Collapse runs of spaces so the JSON string is tidy.
        char* w = h.brand; const char* rd = b; int sp = 0; size_t cap = sizeof(h.brand) - 1;
        while (*rd == ' ') rd++;
        for (; *rd && (size_t)(w - h.brand) < cap; rd++) {
            if (*rd == ' ') { sp = 1; continue; }
            if (sp && w != h.brand) *w++ = ' ';
            sp = 0;
            if ((size_t)(w - h.brand) < cap) *w++ = *rd;
        }
        *w = '\0';
    }
    __asm__ __volatile__("cpuid" : "=a"(r[0]), "=b"(r[1]), "=c"(r[2]), "=d"(r[3])
                         : "a"(1u), "c"(0));
    h.aes_ni     = (r[2] >> 25) & 1;
    h.pclmulqdq  = (r[2] >> 1)  & 1;
    __asm__ __volatile__("cpuid" : "=a"(r[0]), "=b"(r[1]), "=c"(r[2]), "=d"(r[3])
                         : "a"(7u), "c"(0));
    h.avx2       = (r[1] >> 5)  & 1;
    h.bmi2       = (r[1] >> 8)  & 1;
    h.avx512f    = (r[1] >> 16) & 1;
    h.adx        = (r[1] >> 19) & 1;
    h.sha_ni     = (r[1] >> 29) & 1;
    h.vaes       = (r[2] >> 9)  & 1;
    h.vpclmulqdq = (r[2] >> 10) & 1;
#endif
    return h;
}

// ── Result rows ───────────────────────────────────────────────────────────
struct Row {
    std::string prim, lib, unit;
    double us;      // microseconds per operation
    double bytes;   // 0 for asymmetric ops (no cycles/byte)
};
static std::vector<Row> rows;

static void rec_bulk(const char* prim, const char* lib, double us, size_t bytes) {
    rows.push_back({prim, lib, "bulk", us, (double)bytes});
}
static void rec_op(const char* prim, const char* lib, double us) {
    rows.push_back({prim, lib, "op", us, 0.0});
}

// Best-of-R: the minimum is the round least disturbed by scheduling noise.
#define BEST(ITERS, BODY) ({ double best = 1e18;                         \
    for (int r = 0; r < 5; r++) { double t0 = now_us();                  \
        for (int i = 0; i < (ITERS); i++) { BODY; }                      \
        double d = (now_us() - t0) / (ITERS); if (d < best) best = d; } best; })

int main(int argc, char** argv) {
    const size_t N = (argc > 1) ? (size_t)atoi(argv[1]) : 65536;
    const int IT = (N >= 65536) ? 200 : 2000;
    const int AIT = 300;  // asymmetric iterations

    FREQ = measure_freq_hz();

    std::vector<uint8_t> pt(N, 0xA5), ct(N + 64), aad(16, 0x11);
    uint8_t key[32], nonce[12], tag[16], dig[32], mac[32];
    memset(key, 0x2B, 32);
    memset(nonce, 0x7E, 12);

#ifdef HAVE_SODIUM
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }
#endif
#ifdef HAVE_GCRYPT
    gcry_check_version(nullptr);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
#endif

    // ═══════════════════ SHA3-256 ═══════════════════
    { double us = BEST(IT, { ama_sha3_256(pt.data(), N, dig); });
      rec_bulk("SHA3-256", "AMA", us, N); }
#ifdef HAVE_OPENSSL
    { EVP_MD_CTX* m = EVP_MD_CTX_new(); unsigned int dl = 0;
      double us = BEST(IT, { EVP_DigestInit_ex(m, EVP_sha3_256(), nullptr);
                             EVP_DigestUpdate(m, pt.data(), N);
                             EVP_DigestFinal_ex(m, dig, &dl); });
      rec_bulk("SHA3-256", "OpenSSL", us, N); EVP_MD_CTX_free(m); }
#endif
#ifdef HAVE_WOLFSSL
    { wc_Sha3 s;
      double us = BEST(IT, { wc_InitSha3_256(&s, nullptr, INVALID_DEVID);
                             wc_Sha3_256_Update(&s, pt.data(), (word32)N);
                             wc_Sha3_256_Final(&s, dig); });
      rec_bulk("SHA3-256", "wolfSSL", us, N); }
#endif
#ifdef HAVE_BOTAN
    { auto h = Botan::HashFunction::create("SHA-3(256)");
      double us = BEST(IT, { h->update(pt.data(), N); h->final(dig); });
      rec_bulk("SHA3-256", "Botan", us, N); }
#endif
#ifdef HAVE_NETTLE
    { struct sha3_256_ctx c;
      double us = BEST(IT, { sha3_256_init(&c);
                             sha3_256_update(&c, N, pt.data());
                             sha3_256_digest(&c, 32, dig); });
      rec_bulk("SHA3-256", "Nettle", us, N); }
#endif
#ifdef HAVE_GCRYPT
    { double us = BEST(IT, { gcry_md_hash_buffer(GCRY_MD_SHA3_256, dig, pt.data(), N); });
      rec_bulk("SHA3-256", "libgcrypt", us, N); }
#endif

    // ═══════════════════ HMAC-SHA3-256 ═══════════════════
    { double us = BEST(IT, { ama_hmac_sha3_256(key, 32, pt.data(), N, mac); });
      rec_bulk("HMAC-SHA3-256", "AMA", us, N); }
#ifdef HAVE_OPENSSL
    { size_t ml = 32;
      EVP_MAC* alg = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
      EVP_MAC_CTX* c = EVP_MAC_CTX_new(alg);
      OSSL_PARAM pp[] = { OSSL_PARAM_construct_utf8_string(
                              "digest", (char*)"SHA3-256", 0),
                          OSSL_PARAM_construct_end() };
      double us = BEST(IT, { EVP_MAC_init(c, key, 32, pp);
                             EVP_MAC_update(c, pt.data(), N);
                             EVP_MAC_final(c, mac, &ml, 32); });
      rec_bulk("HMAC-SHA3-256", "OpenSSL", us, N);
      EVP_MAC_CTX_free(c); EVP_MAC_free(alg); }
#endif
#ifdef HAVE_BOTAN
    { auto m = Botan::MessageAuthenticationCode::create("HMAC(SHA-3(256))");
      m->set_key(key, 32);
      double us = BEST(IT, { m->update(pt.data(), N); m->final(mac); });
      rec_bulk("HMAC-SHA3-256", "Botan", us, N); }
#endif
#ifdef HAVE_GCRYPT
    { gcry_mac_hd_t h; gcry_mac_open(&h, GCRY_MAC_HMAC_SHA3_256, 0, nullptr);
      size_t ml = 32;
      double us = BEST(IT, { gcry_mac_setkey(h, key, 32);
                             gcry_mac_write(h, pt.data(), N);
                             ml = 32; gcry_mac_read(h, mac, &ml);
                             gcry_mac_reset(h); });
      rec_bulk("HMAC-SHA3-256", "libgcrypt", us, N); gcry_mac_close(h); }
#endif

    // ═══════════════════ AES-256-GCM ═══════════════════
    { double us = BEST(IT, { ama_aes256_gcm_encrypt(key, nonce, pt.data(), N,
                                                    aad.data(), aad.size(),
                                                    ct.data(), tag); });
      rec_bulk("AES-256-GCM", "AMA", us, N); }
#ifdef HAVE_OPENSSL
    { EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new(); int ol = 0;
      double us = BEST(IT, { EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, key, nonce);
                             EVP_EncryptUpdate(c, nullptr, &ol, aad.data(), (int)aad.size());
                             EVP_EncryptUpdate(c, ct.data(), &ol, pt.data(), (int)N);
                             EVP_EncryptFinal_ex(c, ct.data() + ol, &ol); });
      rec_bulk("AES-256-GCM", "OpenSSL", us, N); EVP_CIPHER_CTX_free(c); }
#endif
#ifdef HAVE_SODIUM
    if (crypto_aead_aes256gcm_is_available()) {
        unsigned long long cl = 0;
        double us = BEST(IT, { crypto_aead_aes256gcm_encrypt(
                                   ct.data(), &cl, pt.data(), N,
                                   aad.data(), aad.size(), nullptr, nonce, key); });
        rec_bulk("AES-256-GCM", "libsodium", us, N);
    }
#endif
#ifdef HAVE_WOLFSSL
    { Aes aes; wc_AesInit(&aes, nullptr, INVALID_DEVID); wc_AesGcmSetKey(&aes, key, 32);
      double us = BEST(IT, { wc_AesGcmEncrypt(&aes, ct.data(), pt.data(), (word32)N,
                                              nonce, 12, tag, 16,
                                              aad.data(), (word32)aad.size()); });
      rec_bulk("AES-256-GCM", "wolfSSL", us, N); wc_AesFree(&aes); }
#endif
#ifdef HAVE_BOTAN
    { auto enc = Botan::AEAD_Mode::create("AES-256/GCM", Botan::ENCRYPTION);
      enc->set_key(std::vector<uint8_t>(key, key + 32));
      double us = BEST(IT, { Botan::secure_vector<uint8_t> buf(pt.begin(), pt.end());
                             enc->set_associated_data(aad.data(), aad.size());
                             enc->start(nonce, 12); enc->finish(buf); });
      rec_bulk("AES-256-GCM", "Botan", us, N); }
#endif
#ifdef HAVE_NETTLE
    { struct gcm_aes256_ctx c; gcm_aes256_set_key(&c, key);
      double us = BEST(IT, { gcm_aes256_set_iv(&c, 12, nonce);
                             gcm_aes256_update(&c, aad.size(), aad.data());
                             gcm_aes256_encrypt(&c, N, ct.data(), pt.data());
                             gcm_aes256_digest(&c, 16, tag); });
      rec_bulk("AES-256-GCM", "Nettle", us, N); }
#endif
#ifdef HAVE_GCRYPT
    { gcry_cipher_hd_t h;
      gcry_cipher_open(&h, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 0);
      gcry_cipher_setkey(h, key, 32);
      double us = BEST(IT, { gcry_cipher_reset(h);
                             gcry_cipher_setiv(h, nonce, 12);
                             gcry_cipher_authenticate(h, aad.data(), aad.size());
                             gcry_cipher_encrypt(h, ct.data(), N, pt.data(), N);
                             gcry_cipher_gettag(h, tag, 16); });
      rec_bulk("AES-256-GCM", "libgcrypt", us, N); gcry_cipher_close(h); }
#endif
#ifdef HAVE_MBEDTLS
    { mbedtls_gcm_context g; mbedtls_gcm_init(&g);
      mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 256);
      double us = BEST(IT, { mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, N,
                                                       nonce, 12, aad.data(), aad.size(),
                                                       pt.data(), ct.data(), 16, tag); });
      rec_bulk("AES-256-GCM", "mbedTLS", us, N); mbedtls_gcm_free(&g); }
#endif

    // ═══════════════════ ChaCha20-Poly1305 ═══════════════════
    { double us = BEST(IT, { ama_chacha20poly1305_encrypt(key, nonce, pt.data(), N,
                                                          aad.data(), aad.size(),
                                                          ct.data(), tag); });
      rec_bulk("ChaCha20-Poly1305", "AMA", us, N); }
#ifdef HAVE_OPENSSL
    { EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new(); int ol = 0;
      double us = BEST(IT, { EVP_EncryptInit_ex(c, EVP_chacha20_poly1305(), nullptr, key, nonce);
                             EVP_EncryptUpdate(c, nullptr, &ol, aad.data(), (int)aad.size());
                             EVP_EncryptUpdate(c, ct.data(), &ol, pt.data(), (int)N);
                             EVP_EncryptFinal_ex(c, ct.data() + ol, &ol); });
      rec_bulk("ChaCha20-Poly1305", "OpenSSL", us, N); EVP_CIPHER_CTX_free(c); }
#endif
#ifdef HAVE_SODIUM
    { unsigned long long cl = 0;
      double us = BEST(IT, { crypto_aead_chacha20poly1305_ietf_encrypt(
                                 ct.data(), &cl, pt.data(), N,
                                 aad.data(), aad.size(), nullptr, nonce, key); });
      rec_bulk("ChaCha20-Poly1305", "libsodium", us, N); }
#endif
#ifdef HAVE_WOLFSSL
    { double us = BEST(IT, { wc_ChaCha20Poly1305_Encrypt(key, nonce,
                                                         aad.data(), (word32)aad.size(),
                                                         pt.data(), (word32)N,
                                                         ct.data(), tag); });
      rec_bulk("ChaCha20-Poly1305", "wolfSSL", us, N); }
#endif
#ifdef HAVE_BOTAN
    { auto enc = Botan::AEAD_Mode::create("ChaCha20Poly1305", Botan::ENCRYPTION);
      enc->set_key(std::vector<uint8_t>(key, key + 32));
      double us = BEST(IT, { Botan::secure_vector<uint8_t> buf(pt.begin(), pt.end());
                             enc->set_associated_data(aad.data(), aad.size());
                             enc->start(nonce, 12); enc->finish(buf); });
      rec_bulk("ChaCha20-Poly1305", "Botan", us, N); }
#endif
#ifdef HAVE_NETTLE
    { struct chacha_poly1305_ctx c; chacha_poly1305_set_key(&c, key);
      double us = BEST(IT, { chacha_poly1305_set_nonce(&c, nonce);
                             chacha_poly1305_update(&c, aad.size(), aad.data());
                             chacha_poly1305_encrypt(&c, N, ct.data(), pt.data());
                             chacha_poly1305_digest(&c, 16, tag); });
      rec_bulk("ChaCha20-Poly1305", "Nettle", us, N); }
#endif
#ifdef HAVE_MBEDTLS
    { mbedtls_chachapoly_context c; mbedtls_chachapoly_init(&c);
      mbedtls_chachapoly_setkey(&c, key);
      double us = BEST(IT, { mbedtls_chachapoly_encrypt_and_tag(
                                 &c, N, nonce, aad.data(), aad.size(),
                                 pt.data(), ct.data(), tag); });
      rec_bulk("ChaCha20-Poly1305", "mbedTLS", us, N); mbedtls_chachapoly_free(&c); }
#endif

    // ═══════════════════ Ascon-128 AEAD (NIST SP 800-232) ═══════════════════
    // No peer here implements it. Recorded so the coverage gap is visible in
    // the data rather than inferred from the table's shape.
    { uint8_t akey[AMA_ASCON_AEAD128_KEY_LEN], anon[AMA_ASCON_AEAD128_NONCE_LEN];
      uint8_t atag[AMA_ASCON_AEAD128_TAG_LEN];
      memset(akey, 0x3C, sizeof akey); memset(anon, 0x5A, sizeof anon);
      double us = BEST(IT, { ama_ascon_aead128_encrypt(akey, anon, pt.data(), N,
                                                       aad.data(), aad.size(),
                                                       ct.data(), atag); });
      rec_bulk("Ascon-128 AEAD", "AMA", us, N); }

    // ═══════════════════ Asymmetric ═══════════════════
    //
    // Two rules apply to every block below, because breaking either one
    // produces a fast number that is not a measurement:
    //
    //  1. The signature handed to the verify loop is produced ONCE, into a
    //     buffer the sign loop never touches, and its length is captured with
    //     it. The first revision reused one buffer and one length variable:
    //     the timed sign loop overwrote the bytes while the length stayed at
    //     the *first* signature's value, and DER-encoded ECDSA signatures vary
    //     between 70 and 72 bytes. Verify then rejected on a length mismatch
    //     in a few hundred cycles and the table reported 8.5 M verifies/sec
    //     for wolfSSL P-256 and 307 K/sec for OpenSSL secp256k1 -- both of
    //     them a rejection path being timed, not a verification.
    //
    //  2. Every verify is checked for SUCCESS before it is timed. A verify
    //     that returns "invalid" is not a fast verify, and CHECK() drops the
    //     row rather than publishing it.
    //
    // Context and key objects are hoisted out of the timed region wherever the
    // API allows reuse, so no library pays for an allocation the others avoid.
    const size_t MSG = 32;

#define CHECK(cond, prim, lib)                                             \
    do { if (!(cond)) {                                                    \
        fprintf(stderr, "  ! %s / %s: verify did not succeed - row dropped\n", \
                (prim), (lib)); skip = true; } else skip = false; } while (0)

    bool skip = false;

    // ── Ed25519 ────────────────────────────────────────────────────────
    {
        uint8_t pk[32], sk[64], vsig[64], ssig[64];
        ama_ed25519_keypair(pk, sk);
        ama_ed25519_sign(vsig, pt.data(), MSG, sk);
        CHECK(ama_ed25519_verify(vsig, pt.data(), MSG, pk) == AMA_SUCCESS,
              "Ed25519 verify", "AMA");
        double sg = BEST(AIT, { ama_ed25519_sign(ssig, pt.data(), MSG, sk); });
        double vf = BEST(AIT, { ama_ed25519_verify(vsig, pt.data(), MSG, pk); });
        rec_op("Ed25519 sign", "AMA", sg);
        if (!skip) rec_op("Ed25519 verify", "AMA", vf);
    }
#ifdef HAVE_OPENSSL
    {
        EVP_PKEY* k = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
        uint8_t vsig[64], ssig[64]; size_t vl = 64;
        EVP_MD_CTX* sc = EVP_MD_CTX_new();
        EVP_MD_CTX* vc = EVP_MD_CTX_new();
        EVP_DigestSignInit(sc, nullptr, nullptr, nullptr, k);
        EVP_DigestSign(sc, vsig, &vl, pt.data(), MSG);
        EVP_DigestVerifyInit(vc, nullptr, nullptr, nullptr, k);
        CHECK(EVP_DigestVerify(vc, vsig, vl, pt.data(), MSG) == 1,
              "Ed25519 verify", "OpenSSL");
        double sg = BEST(AIT, { size_t l = 64;
                                EVP_DigestSignInit(sc, nullptr, nullptr, nullptr, k);
                                EVP_DigestSign(sc, ssig, &l, pt.data(), MSG); });
        double vf = BEST(AIT, { EVP_DigestVerifyInit(vc, nullptr, nullptr, nullptr, k);
                                EVP_DigestVerify(vc, vsig, vl, pt.data(), MSG); });
        rec_op("Ed25519 sign", "OpenSSL", sg);
        if (!skip) rec_op("Ed25519 verify", "OpenSSL", vf);
        EVP_MD_CTX_free(sc); EVP_MD_CTX_free(vc); EVP_PKEY_free(k);
    }
#endif
#ifdef HAVE_SODIUM
    {
        uint8_t pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
        uint8_t vsig[crypto_sign_BYTES], ssig[crypto_sign_BYTES];
        unsigned long long vl = 0;
        crypto_sign_keypair(pk, sk);
        crypto_sign_detached(vsig, &vl, pt.data(), MSG, sk);
        CHECK(crypto_sign_verify_detached(vsig, pt.data(), MSG, pk) == 0,
              "Ed25519 verify", "libsodium");
        double sg = BEST(AIT, { unsigned long long l;
                                crypto_sign_detached(ssig, &l, pt.data(), MSG, sk); });
        double vf = BEST(AIT, { crypto_sign_verify_detached(vsig, pt.data(), MSG, pk); });
        rec_op("Ed25519 sign", "libsodium", sg);
        if (!skip) rec_op("Ed25519 verify", "libsodium", vf);
    }
#endif
#ifdef HAVE_WOLFSSL
    {
        WC_RNG rng; wc_InitRng(&rng);
        ed25519_key k; wc_ed25519_init(&k);
        wc_ed25519_make_key(&rng, 32, &k);
        uint8_t vsig[64], ssig[64]; word32 vl = 64; int ok = 0;
        wc_ed25519_sign_msg(pt.data(), (word32)MSG, vsig, &vl, &k);
        wc_ed25519_verify_msg(vsig, vl, pt.data(), (word32)MSG, &ok, &k);
        CHECK(ok == 1, "Ed25519 verify", "wolfSSL");
        double sg = BEST(AIT, { word32 l = 64;
                                wc_ed25519_sign_msg(pt.data(), (word32)MSG, ssig, &l, &k); });
        double vf = BEST(AIT, { int o = 0;
                                wc_ed25519_verify_msg(vsig, vl, pt.data(),
                                                      (word32)MSG, &o, &k); });
        rec_op("Ed25519 sign", "wolfSSL", sg);
        if (!skip) rec_op("Ed25519 verify", "wolfSSL", vf);
        wc_ed25519_free(&k); wc_FreeRng(&rng);
    }
#endif
#ifdef HAVE_BOTAN
    {
        Botan::AutoSeeded_RNG rng;
        Botan::Ed25519_PrivateKey k(rng);
        // Hoisted: the first revision constructed PK_Signer/PK_Verifier inside
        // the timed loop, so Botan alone paid an object-construction cost per
        // operation and its verify read 160 us against libsodium's 57.
        Botan::PK_Signer sg_o(k, rng, "Pure");
        Botan::PK_Verifier vf_o(k, "Pure");
        std::vector<uint8_t> vsig = sg_o.sign_message(pt.data(), MSG, rng);
        CHECK(vf_o.verify_message(pt.data(), MSG, vsig.data(), vsig.size()),
              "Ed25519 verify", "Botan");
        double sg = BEST(AIT, { auto z = sg_o.sign_message(pt.data(), MSG, rng); (void)z; });
        double vf = BEST(AIT, { bool z = vf_o.verify_message(pt.data(), MSG,
                                                             vsig.data(), vsig.size());
                                (void)z; });
        rec_op("Ed25519 sign", "Botan", sg);
        if (!skip) rec_op("Ed25519 verify", "Botan", vf);
    }
#endif
#ifdef HAVE_NETTLE
    {
        uint8_t pub[ED25519_KEY_SIZE], priv[ED25519_KEY_SIZE];
        uint8_t vsig[ED25519_SIGNATURE_SIZE], ssig[ED25519_SIGNATURE_SIZE];
        memset(priv, 0x4D, sizeof priv);
        ed25519_sha512_public_key(pub, priv);
        ed25519_sha512_sign(pub, priv, MSG, pt.data(), vsig);
        CHECK(ed25519_sha512_verify(pub, MSG, pt.data(), vsig) == 1,
              "Ed25519 verify", "Nettle");
        double sg = BEST(AIT, { ed25519_sha512_sign(pub, priv, MSG, pt.data(), ssig); });
        double vf = BEST(AIT, { ed25519_sha512_verify(pub, MSG, pt.data(), vsig); });
        rec_op("Ed25519 sign", "Nettle", sg);
        if (!skip) rec_op("Ed25519 verify", "Nettle", vf);
    }
#endif

    // ── X25519 ─────────────────────────────────────────────────────────
    {
        uint8_t apk[32], ask[32], bpk[32], bsk[32], ss[32];
        ama_x25519_keypair(apk, ask); ama_x25519_keypair(bpk, bsk);
        double us = BEST(AIT, { ama_x25519_key_exchange(ss, ask, bpk); });
        rec_op("X25519 scalar-mult", "AMA", us);
    }
#ifdef HAVE_OPENSSL
    {
        EVP_PKEY* a = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
        EVP_PKEY* b = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
        uint8_t ss[32];
        EVP_PKEY_CTX* c = EVP_PKEY_CTX_new(a, nullptr);
        EVP_PKEY_derive_init(c);
        EVP_PKEY_derive_set_peer(c, b);
        double us = BEST(AIT, { size_t l = 32; EVP_PKEY_derive(c, ss, &l); });
        rec_op("X25519 scalar-mult", "OpenSSL", us);
        EVP_PKEY_CTX_free(c); EVP_PKEY_free(a); EVP_PKEY_free(b);
    }
#endif
#ifdef HAVE_SODIUM
    {
        uint8_t apk[32], ask[32], bpk[32], bsk[32], ss[32];
        crypto_box_keypair(apk, ask); crypto_box_keypair(bpk, bsk);
        double us = BEST(AIT, { crypto_scalarmult(ss, ask, bpk); });
        rec_op("X25519 scalar-mult", "libsodium", us);
    }
#endif
#ifdef HAVE_WOLFSSL
    {
        WC_RNG rng; wc_InitRng(&rng);
        curve25519_key a, b; wc_curve25519_init(&a); wc_curve25519_init(&b);
        wc_curve25519_make_key(&rng, 32, &a); wc_curve25519_make_key(&rng, 32, &b);
        uint8_t ss[32];
        double us = BEST(AIT, { word32 l = 32;
                                wc_curve25519_shared_secret(&a, &b, ss, &l); });
        rec_op("X25519 scalar-mult", "wolfSSL", us);
        wc_curve25519_free(&a); wc_curve25519_free(&b); wc_FreeRng(&rng);
    }
#endif
#ifdef HAVE_NETTLE
    {
        uint8_t ask[CURVE25519_SIZE], apk[CURVE25519_SIZE];
        uint8_t bsk[CURVE25519_SIZE], bpk[CURVE25519_SIZE], ss[CURVE25519_SIZE];
        memset(ask, 0x11, sizeof ask); memset(bsk, 0x22, sizeof bsk);
        curve25519_mul_g(apk, ask); curve25519_mul_g(bpk, bsk);
        double us = BEST(AIT, { curve25519_mul(ss, ask, bpk); });
        rec_op("X25519 scalar-mult", "Nettle", us);
    }
#endif

    // ── NIST P-256 ECDSA ───────────────────────────────────────────────
    {
        uint8_t priv[32], pub[64], vsig[64], ssig[64];
        ama_nistp_keypair(AMA_NIST_CURVE_P256, priv, pub);
        ama_nistp_ecdsa_sign_raw(AMA_NIST_CURVE_P256, dig, 32, priv, vsig);
        CHECK(ama_nistp_ecdsa_verify_raw(AMA_NIST_CURVE_P256, dig, 32,
                                         pub, vsig, 64) == AMA_SUCCESS,
              "P-256 ECDSA verify", "AMA");
        double sg = BEST(AIT, { ama_nistp_ecdsa_sign_raw(AMA_NIST_CURVE_P256,
                                                         dig, 32, priv, ssig); });
        double vf = BEST(AIT, { ama_nistp_ecdsa_verify_raw(AMA_NIST_CURVE_P256,
                                                           dig, 32, pub, vsig, 64); });
        rec_op("P-256 ECDSA sign", "AMA", sg);
        if (!skip) rec_op("P-256 ECDSA verify", "AMA", vf);
    }
#ifdef HAVE_OPENSSL
    {
        EVP_PKEY* k = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
        uint8_t vsig[128], ssig[128]; size_t vl = sizeof vsig;
        EVP_MD_CTX* sc = EVP_MD_CTX_new();
        EVP_MD_CTX* vc = EVP_MD_CTX_new();
        EVP_DigestSignInit(sc, nullptr, EVP_sha256(), nullptr, k);
        EVP_DigestSign(sc, vsig, &vl, pt.data(), MSG);
        EVP_DigestVerifyInit(vc, nullptr, EVP_sha256(), nullptr, k);
        CHECK(EVP_DigestVerify(vc, vsig, vl, pt.data(), MSG) == 1,
              "P-256 ECDSA verify", "OpenSSL");
        double sg = BEST(AIT, { size_t l = sizeof ssig;
                                EVP_DigestSignInit(sc, nullptr, EVP_sha256(), nullptr, k);
                                EVP_DigestSign(sc, ssig, &l, pt.data(), MSG); });
        double vf = BEST(AIT, { EVP_DigestVerifyInit(vc, nullptr, EVP_sha256(), nullptr, k);
                                EVP_DigestVerify(vc, vsig, vl, pt.data(), MSG); });
        rec_op("P-256 ECDSA sign", "OpenSSL", sg);
        if (!skip) rec_op("P-256 ECDSA verify", "OpenSSL", vf);
        EVP_MD_CTX_free(sc); EVP_MD_CTX_free(vc); EVP_PKEY_free(k);
    }
#endif
#ifdef HAVE_WOLFSSL
    {
        WC_RNG rng; wc_InitRng(&rng);
        ecc_key k; wc_ecc_init(&k);
        wc_ecc_make_key(&rng, 32, &k);
        uint8_t vsig[128], ssig[128]; word32 vl = sizeof vsig; int ok = 0;
        wc_ecc_sign_hash(dig, 32, vsig, &vl, &rng, &k);
        wc_ecc_verify_hash(vsig, vl, dig, 32, &ok, &k);
        CHECK(ok == 1, "P-256 ECDSA verify", "wolfSSL");
        double sg = BEST(AIT, { word32 l = sizeof ssig;
                                wc_ecc_sign_hash(dig, 32, ssig, &l, &rng, &k); });
        double vf = BEST(AIT, { int o = 0;
                                wc_ecc_verify_hash(vsig, vl, dig, 32, &o, &k); });
        rec_op("P-256 ECDSA sign", "wolfSSL", sg);
        if (!skip) rec_op("P-256 ECDSA verify", "wolfSSL", vf);
        wc_ecc_free(&k); wc_FreeRng(&rng);
    }
#endif
#ifdef HAVE_BOTAN
    {
        Botan::AutoSeeded_RNG rng;
        Botan::EC_Group grp("secp256r1");
        Botan::ECDSA_PrivateKey k(rng, grp);
        Botan::PK_Signer sg_o(k, rng, "EMSA1(SHA-256)");
        Botan::PK_Verifier vf_o(k, "EMSA1(SHA-256)");
        auto vsig = sg_o.sign_message(pt.data(), MSG, rng);
        CHECK(vf_o.verify_message(pt.data(), MSG, vsig.data(), vsig.size()),
              "P-256 ECDSA verify", "Botan");
        double sg = BEST(AIT, { auto z = sg_o.sign_message(pt.data(), MSG, rng); (void)z; });
        double vf = BEST(AIT, { bool z = vf_o.verify_message(pt.data(), MSG,
                                                             vsig.data(), vsig.size());
                                (void)z; });
        rec_op("P-256 ECDSA sign", "Botan", sg);
        if (!skip) rec_op("P-256 ECDSA verify", "Botan", vf);
    }
#endif

    // ── secp256k1 ECDSA ────────────────────────────────────────────────
    {
        // verify() takes the *uncompressed* 64-byte point; from_privkey emits
        // the 33-byte compressed form, so the decompression is required and is
        // done once, outside the timed loop.
        uint8_t priv[32], cpub[33], pub[64];
        uint8_t vsig[AMA_SECP256K1_ECDSA_MAX_SIG_LEN], ssig[AMA_SECP256K1_ECDSA_MAX_SIG_LEN];
        size_t vl = sizeof vsig;
        memset(priv, 0x5E, 32);
        ama_secp256k1_pubkey_from_privkey(priv, cpub);
        ama_secp256k1_pubkey_decompress(cpub, pub);
        ama_secp256k1_ecdsa_sign(vsig, &vl, dig, priv);
        CHECK(ama_secp256k1_ecdsa_verify(vsig, vl, dig, pub) == AMA_SUCCESS,
              "secp256k1 ECDSA verify", "AMA");
        double sg = BEST(AIT, { size_t l = sizeof ssig;
                                ama_secp256k1_ecdsa_sign(ssig, &l, dig, priv); });
        double vf = BEST(AIT, { ama_secp256k1_ecdsa_verify(vsig, vl, dig, pub); });
        rec_op("secp256k1 ECDSA sign", "AMA", sg);
        if (!skip) rec_op("secp256k1 ECDSA verify", "AMA", vf);
    }
#ifdef HAVE_OPENSSL
    {
        EVP_PKEY* k = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "secp256k1");
        if (k) {
            uint8_t vsig[128], ssig[128]; size_t vl = sizeof vsig;
            EVP_MD_CTX* sc = EVP_MD_CTX_new();
            EVP_MD_CTX* vc = EVP_MD_CTX_new();
            EVP_DigestSignInit(sc, nullptr, EVP_sha256(), nullptr, k);
            EVP_DigestSign(sc, vsig, &vl, pt.data(), MSG);
            EVP_DigestVerifyInit(vc, nullptr, EVP_sha256(), nullptr, k);
            CHECK(EVP_DigestVerify(vc, vsig, vl, pt.data(), MSG) == 1,
                  "secp256k1 ECDSA verify", "OpenSSL");
            double sg = BEST(AIT, { size_t l = sizeof ssig;
                                    EVP_DigestSignInit(sc, nullptr, EVP_sha256(), nullptr, k);
                                    EVP_DigestSign(sc, ssig, &l, pt.data(), MSG); });
            double vf = BEST(AIT, { EVP_DigestVerifyInit(vc, nullptr, EVP_sha256(), nullptr, k);
                                    EVP_DigestVerify(vc, vsig, vl, pt.data(), MSG); });
            rec_op("secp256k1 ECDSA sign", "OpenSSL", sg);
            if (!skip) rec_op("secp256k1 ECDSA verify", "OpenSSL", vf);
            EVP_MD_CTX_free(sc); EVP_MD_CTX_free(vc); EVP_PKEY_free(k);
        } else {
            fprintf(stderr, "  ! secp256k1 / OpenSSL: curve unavailable in this build\n");
        }
    }
#endif
#ifdef HAVE_BOTAN
    {
        Botan::AutoSeeded_RNG rng;
        Botan::EC_Group grp("secp256k1");
        Botan::ECDSA_PrivateKey k(rng, grp);
        Botan::PK_Signer sg_o(k, rng, "EMSA1(SHA-256)");
        Botan::PK_Verifier vf_o(k, "EMSA1(SHA-256)");
        auto vsig = sg_o.sign_message(pt.data(), MSG, rng);
        CHECK(vf_o.verify_message(pt.data(), MSG, vsig.data(), vsig.size()),
              "secp256k1 ECDSA verify", "Botan");
        double sg = BEST(AIT, { auto z = sg_o.sign_message(pt.data(), MSG, rng); (void)z; });
        double vf = BEST(AIT, { bool z = vf_o.verify_message(pt.data(), MSG,
                                                             vsig.data(), vsig.size());
                                (void)z; });
        rec_op("secp256k1 ECDSA sign", "Botan", sg);
        if (!skip) rec_op("secp256k1 ECDSA verify", "Botan", vf);
    }
#endif

    // ── Output ────────────────────────────────────────────────────────────
    printf("# CPU frequency measured: %.5f GHz\n", FREQ / 1e9);
    printf("# message size: %zu bytes\n\n", N);
    printf("%-24s %-12s %12s %12s %12s\n",
           "primitive", "library", "us/op", "MB/s", "cycles/byte");
    printf("%s\n", std::string(78, '-').c_str());
    for (const auto& r : rows) {
        if (r.bytes > 0) {
            double Bps = r.bytes / (r.us * 1e-6);
            printf("%-24s %-12s %12.3f %12.1f %12.3f\n",
                   r.prim.c_str(), r.lib.c_str(), r.us, Bps / 1e6, FREQ / Bps);
        } else {
            printf("%-24s %-12s %12.3f %12s %12.0f\n",
                   r.prim.c_str(), r.lib.c_str(), r.us, "-", 1e6 / r.us);
        }
    }

    // JSON for the report generator.
    FILE* j = fopen("multi_library_results.json", "w");
    if (j) {
        HostInfo h = probe_host();
        fprintf(j, "{\n  \"freq_hz\": %.1f,\n  \"message_bytes\": %zu,\n", FREQ, N);
        fprintf(j, "  \"host\": {\n");
        fprintf(j, "    \"cpu\": \"%s\",\n", h.brand);
        fprintf(j, "    \"note\": \"Feature bits are recorded because they decide which kernel each library selects; peer AES-GCM in particular moves ~4x with VAES+VPCLMULQDQ. Rows from hosts with different feature sets are not directly comparable.\",\n");
        fprintf(j, "    \"aes_ni\": %d, \"pclmulqdq\": %d, \"vaes\": %d, \"vpclmulqdq\": %d,\n",
                h.aes_ni, h.pclmulqdq, h.vaes, h.vpclmulqdq);
        fprintf(j, "    \"avx2\": %d, \"avx512f\": %d, \"sha_ni\": %d, \"bmi2\": %d, \"adx\": %d\n",
                h.avx2, h.avx512f, h.sha_ni, h.bmi2, h.adx);
        fprintf(j, "  },\n");
        fprintf(j, "  \"libraries_compiled\": [\"AMA\"");
#ifdef HAVE_OPENSSL
        fprintf(j, ", \"OpenSSL\"");
#endif
#ifdef HAVE_SODIUM
        fprintf(j, ", \"libsodium\"");
#endif
#ifdef HAVE_WOLFSSL
        fprintf(j, ", \"wolfSSL\"");
#endif
#ifdef HAVE_BOTAN
        fprintf(j, ", \"Botan\"");
#endif
#ifdef HAVE_NETTLE
        fprintf(j, ", \"Nettle\"");
#endif
#ifdef HAVE_GCRYPT
        fprintf(j, ", \"libgcrypt\"");
#endif
#ifdef HAVE_MBEDTLS
        fprintf(j, ", \"mbedTLS\"");
#endif
        fprintf(j, "],\n  \"results\": [\n");
        for (size_t i = 0; i < rows.size(); i++) {
            const Row& r = rows[i];
            double Bps = r.bytes > 0 ? r.bytes / (r.us * 1e-6) : 0;
            fprintf(j, "    {\"primitive\": \"%s\", \"library\": \"%s\", "
                       "\"us_per_op\": %.6f, \"ops_per_sec\": %.2f",
                    r.prim.c_str(), r.lib.c_str(), r.us, 1e6 / r.us);
            if (r.bytes > 0)
                fprintf(j, ", \"mb_per_sec\": %.3f, \"cycles_per_byte\": %.4f",
                        Bps / 1e6, FREQ / Bps);
            fprintf(j, "}%s\n", i + 1 < rows.size() ? "," : "");
        }
        fprintf(j, "  ]\n}\n");
        fclose(j);
        printf("\nwrote multi_library_results.json (%zu rows)\n", rows.size());
    }
    return 0;
}
