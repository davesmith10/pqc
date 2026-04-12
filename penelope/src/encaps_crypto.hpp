#pragma once
// Scrypt KDF wrapper for padme encaps/decaps.
// AES-256-GCM helpers re-use the same symmetric.hpp used by obi-wan.

#include <crystals/crystals.hpp>    // aes256gcm_encrypt_aad / _decrypt_aad

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <array>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

// ── Constants ─────────────────────────────────────────────────────────────────

static constexpr int  ENCAPS_N_LOG2 = 19;        // N = 2^19 = 524 288
static constexpr int  ENCAPS_R      = 8;
static constexpr int  ENCAPS_P      = 1;
static constexpr size_t ENCAPS_SALT_LEN  = 16;
static constexpr size_t ENCAPS_KEY_LEN   = 32;

// ── Random bytes ──────────────────────────────────────────────────────────────

inline std::vector<uint8_t> encaps_rand(size_t n) {
    std::vector<uint8_t> buf(n);
    if (RAND_bytes(buf.data(), (int)n) != 1)
        throw std::runtime_error("RAND_bytes failed");
    return buf;
}

// ── Scrypt KDF ────────────────────────────────────────────────────────────────

// Returns a 32-byte key derived from password + salt using scrypt(N=2^n_log2, r=8, p=1).
// maxmem is set to 1 GiB to allow N up to 2^23.
inline std::vector<uint8_t> encaps_derive_key(const std::string& password,
                                               const std::vector<uint8_t>& salt,
                                               int n_log2 = ENCAPS_N_LOG2)
{
    uint64_t N      = (uint64_t)1 << n_log2;
    uint64_t maxmem = (uint64_t)1 << 30;   // 1 GiB upper bound

    std::vector<uint8_t> key(ENCAPS_KEY_LEN);
    int rc = EVP_PBE_scrypt(
        password.c_str(), password.size(),
        salt.data(),      salt.size(),
        N, (uint64_t)ENCAPS_R, (uint64_t)ENCAPS_P,
        maxmem,
        key.data(), ENCAPS_KEY_LEN);
    if (rc != 1)
        throw std::runtime_error("scrypt KDF failed");
    return key;
}

// ── AES-256-GCM convenience wrappers ─────────────────────────────────────────
//
// These thin wrappers delegate to symmetric.hpp.
// Wire format: nonce(12) ∥ tag(16) ∥ ciphertext(N)

inline std::vector<uint8_t> encaps_aes_enc(const std::vector<uint8_t>& key,
                                            const std::vector<uint8_t>& plaintext)
{
    if (key.size() != 32)
        throw std::runtime_error("encaps_aes_enc: key must be 32 bytes");
    return aes256gcm_encrypt_aad(key.data(), plaintext, nullptr, 0);
}

inline std::vector<uint8_t> encaps_aes_dec(const std::vector<uint8_t>& key,
                                            const std::vector<uint8_t>& nonce_tag_ct)
{
    if (key.size() != 32)
        throw std::runtime_error("encaps_aes_dec: key must be 32 bytes");
    return aes256gcm_decrypt_aad(key.data(), nonce_tag_ct, nullptr, 0);
}
