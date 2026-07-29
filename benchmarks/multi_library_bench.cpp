// Multi-library throughput harness: AMA vs wolfSSL vs Botan vs OpenSSL.
//
// Primitives chosen because all four expose them natively: AES-256-GCM (bulk
// AEAD) and SHA3-256 (bulk hash). Same host, same process, same buffers, same
// iteration counts, best-of-5 rounds. Reports MB/s and cycles/byte.
//
// Crypto++ is deliberately absent: wolfssl/options.h defines byte/word32
// macros that break crypto++/cryptlib.h in the same translation unit.
// Including it would need a separate TU; not done, and not silently implied.
//
// Speed reference only - no library here is used as a correctness oracle.
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <vector>
#include <string>

extern "C" {
#include "ama_cryptography.h"
}

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha3.h>

#include <botan/aead.h>
#include <botan/hash.h>

#include <openssl/evp.h>

static const double FREQ = 2.80264e9;

static double now_us() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

struct Row { std::string prim, lib; double us, mbps, cpb; };
static std::vector<Row> rows;

static void rec(const char* prim, const char* lib, double us, size_t bytes) {
    double Bps = bytes / (us * 1e-6);
    rows.push_back({prim, lib, us, Bps / 1e6, FREQ / Bps});
}

#define BEST(ITERS, BODY) ({ double best = 1e18;                        \
    for (int r = 0; r < 5; r++) { double t0 = now_us();                 \
        for (int i = 0; i < (ITERS); i++) { BODY; }                     \
        double d = (now_us() - t0) / (ITERS); if (d < best) best = d; } best; })

int main() {
    const size_t N = 65536;
    std::vector<uint8_t> pt(N, 0xA5), ct(N + 16);
    uint8_t key[32], nonce[12], tag[16], dig[32];
    memset(key, 0x2B, 32);
    memset(nonce, 0x7E, 12);
    const int IT = 200;

    /* ---------------- AES-256-GCM ---------------- */
    {
        double us = BEST(IT, {
            ama_aes256_gcm_encrypt(key, nonce, pt.data(), N, nullptr, 0, ct.data(), tag);
        });
        rec("AES-256-GCM", "AMA", us, N);
    }
    {
        Aes aes;
        wc_AesInit(&aes, nullptr, INVALID_DEVID);
        wc_AesGcmSetKey(&aes, key, 32);
        double us = BEST(IT, {
            wc_AesGcmEncrypt(&aes, ct.data(), pt.data(), N, nonce, 12, tag, 16, nullptr, 0);
        });
        rec("AES-256-GCM", "wolfSSL", us, N);
        wc_AesFree(&aes);
    }
    {
        auto enc = Botan::AEAD_Mode::create("AES-256/GCM", Botan::ENCRYPTION);
        enc->set_key(std::vector<uint8_t>(key, key + 32));
        double us = BEST(IT, {
            Botan::secure_vector<uint8_t> buf(pt.begin(), pt.end());
            enc->start(nonce, 12);
            enc->finish(buf);
        });
        rec("AES-256-GCM", "Botan", us, N);
    }
    {
        EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
        int ol = 0;
        double us = BEST(IT, {
            EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, key, nonce);
            EVP_EncryptUpdate(c, ct.data(), &ol, pt.data(), (int)N);
            EVP_EncryptFinal_ex(c, ct.data() + ol, &ol);
        });
        rec("AES-256-GCM", "OpenSSL", us, N);
        EVP_CIPHER_CTX_free(c);
    }

    /* ---------------- SHA3-256 ---------------- */
    {
        double us = BEST(IT, { ama_sha3_256(pt.data(), N, dig); });
        rec("SHA3-256", "AMA", us, N);
    }
    {
        wc_Sha3 s;
        double us = BEST(IT, {
            wc_InitSha3_256(&s, nullptr, INVALID_DEVID);
            wc_Sha3_256_Update(&s, pt.data(), N);
            wc_Sha3_256_Final(&s, dig);
        });
        rec("SHA3-256", "wolfSSL", us, N);
    }
    {
        auto h = Botan::HashFunction::create("SHA-3(256)");
        double us = BEST(IT, { h->update(pt.data(), N); h->final(dig); });
        rec("SHA3-256", "Botan", us, N);
    }
    {
        EVP_MD_CTX* m = EVP_MD_CTX_new();
        unsigned int dl = 0;
        double us = BEST(IT, {
            EVP_DigestInit_ex(m, EVP_sha3_256(), nullptr);
            EVP_DigestUpdate(m, pt.data(), N);
            EVP_DigestFinal_ex(m, dig, &dl);
        });
        rec("SHA3-256", "OpenSSL", us, N);
        EVP_MD_CTX_free(m);
    }

    printf("%-14s %-10s %10s %10s %12s\n", "primitive", "library", "us/op", "MB/s", "cycles/byte");
    printf("%s\n", std::string(60, '-').c_str());
    for (const auto& r : rows)
        printf("%-14s %-10s %10.2f %10.1f %12.3f\n",
               r.prim.c_str(), r.lib.c_str(), r.us, r.mbps, r.cpb);
    return 0;
}
