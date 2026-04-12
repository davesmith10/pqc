#pragma once
#include "base64.hpp"
#include <vector>
#include <cstdint>
#include <string>
#include <stdexcept>
#include <cstring>
#include <sstream>

// PWENC Bundle Wire Format (binary, before base64 armoring):
//
// Offset   Size  Field
// -------  ----  -----
//  0        4    Magic: "OBWE"
//  4        1    Version: 0x01
//  5        2    Level: big-endian uint16 (512, 768, or 1024)
//  7       32    salt (random, 32 bytes)
// 39        1    scrypt_n_log2 (e.g. 20 → N=2^20)
// 40        1    scrypt_r
// 41        1    scrypt_p
// 42     pk_sz   pk  (800/1184/1568 bytes for Kyber 512/768/1024)
// 42+pk  ct_sz   ct  (768/1088/1568 bytes)
// ...      12    wrap_nonce
// ...      16    wrap_tag
// ...     sk_sz  sk_enc (1632/2400/3168 bytes, encrypted sk)
// ...      12    data_nonce
// ...      16    data_tag
// ...       M    ciphertext (plaintext encrypted)
//
// AAD for both AEAD operations = first 7 bytes: magic(4) || version(1) || level(2)

struct PwBundle {
    int     level;          // 512, 768, or 1024
    uint8_t salt[32];
    uint8_t scrypt_n_log2;  // e.g. 20 → N=2^20
    uint8_t scrypt_r;
    uint8_t scrypt_p;
    std::vector<uint8_t> pk;
    std::vector<uint8_t> ct;
    std::vector<uint8_t> wrap_nonce_tag_sk_enc;  // 12+16+sk_size blob
    std::vector<uint8_t> data_nonce_tag_ct;      // 12+16+M blob
};

static constexpr char kPwArmorBegin[] = "-----BEGIN ZORRO PW ENCRYPTED FILE-----";
static constexpr char kPwArmorEnd[]   = "-----END ZORRO PW ENCRYPTED FILE-----";

// ── Wire format helpers ───────────────────────────────────────────────────────

static inline void pw_push_u16be(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back((v >> 8) & 0xFF);
    buf.push_back((v >> 0) & 0xFF);
}

static inline uint16_t pw_read_u16be(const uint8_t* p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

// ── AAD ──────────────────────────────────────────────────────────────────────

// Returns the 7-byte AAD prefix: magic(4) || version(1) || level_be(2)
inline std::vector<uint8_t> pw_bundle_aad(int level) {
    std::vector<uint8_t> aad;
    aad.reserve(7);
    aad.push_back('O'); aad.push_back('B'); aad.push_back('W'); aad.push_back('E');
    aad.push_back(0x01);
    pw_push_u16be(aad, (uint16_t)level);
    return aad;
}

// ── Pack ─────────────────────────────────────────────────────────────────────

inline std::vector<uint8_t> pack_pw_bundle(const PwBundle& b) {
    std::vector<uint8_t> buf;
    buf.reserve(7 + 32 + 3 + b.pk.size() + b.ct.size() +
                b.wrap_nonce_tag_sk_enc.size() + b.data_nonce_tag_ct.size());

    // Magic (4 bytes)
    buf.push_back('O'); buf.push_back('B'); buf.push_back('W'); buf.push_back('E');

    // Version (1 byte)
    buf.push_back(0x01);

    // Level (2 bytes big-endian)
    pw_push_u16be(buf, (uint16_t)b.level);

    // Salt (32 bytes)
    buf.insert(buf.end(), b.salt, b.salt + 32);

    // scrypt params (3 bytes)
    buf.push_back(b.scrypt_n_log2);
    buf.push_back(b.scrypt_r);
    buf.push_back(b.scrypt_p);

    // pk
    buf.insert(buf.end(), b.pk.begin(), b.pk.end());

    // ct
    buf.insert(buf.end(), b.ct.begin(), b.ct.end());

    // wrap_nonce(12) + wrap_tag(16) + sk_enc
    buf.insert(buf.end(), b.wrap_nonce_tag_sk_enc.begin(), b.wrap_nonce_tag_sk_enc.end());

    // data_nonce(12) + data_tag(16) + ciphertext
    buf.insert(buf.end(), b.data_nonce_tag_ct.begin(), b.data_nonce_tag_ct.end());

    return buf;
}

// ── Parse ─────────────────────────────────────────────────────────────────────

inline PwBundle parse_pw_bundle(const std::vector<uint8_t>& wire) {
    static const size_t kMinFixed = 7 + 32 + 3; // magic+ver+level + salt + params
    if (wire.size() < kMinFixed)
        throw std::runtime_error("PWENC wire too short");

    const uint8_t* p   = wire.data();
    const uint8_t* end = wire.data() + wire.size();

    // Magic
    if (std::memcmp(p, "OBWE", 4) != 0)
        throw std::runtime_error("PWENC wire: invalid magic");
    p += 4;

    // Version
    if (*p != 0x01)
        throw std::runtime_error("PWENC wire: unsupported version " + std::to_string((int)*p));
    p += 1;

    // Level
    uint16_t level_raw = pw_read_u16be(p); p += 2;
    PwBundle b;
    b.level = (int)level_raw;

    // Validate level and get sizes
    size_t pk_sz, ct_sz, sk_sz;
    if (b.level == 512)      { pk_sz = 800;  ct_sz = 768;  sk_sz = 1632; }
    else if (b.level == 768) { pk_sz = 1184; ct_sz = 1088; sk_sz = 2400; }
    else if (b.level == 1024){ pk_sz = 1568; ct_sz = 1568; sk_sz = 3168; }
    else throw std::runtime_error("PWENC wire: unknown level " + std::to_string(b.level));

    // Salt (32 bytes)
    if (p + 32 > end) throw std::runtime_error("PWENC wire: truncated salt");
    std::memcpy(b.salt, p, 32); p += 32;

    // scrypt params
    if (p + 3 > end) throw std::runtime_error("PWENC wire: truncated scrypt params");
    b.scrypt_n_log2 = *p++;
    b.scrypt_r      = *p++;
    b.scrypt_p      = *p++;

    // pk
    if (p + pk_sz > end) throw std::runtime_error("PWENC wire: truncated pk");
    b.pk.assign(p, p + pk_sz); p += pk_sz;

    // ct
    if (p + ct_sz > end) throw std::runtime_error("PWENC wire: truncated ct");
    b.ct.assign(p, p + ct_sz); p += ct_sz;

    // wrap_nonce(12) + wrap_tag(16) + sk_enc(sk_sz)
    size_t wrap_blob_sz = 12 + 16 + sk_sz;
    if (p + wrap_blob_sz > end) throw std::runtime_error("PWENC wire: truncated wrap blob");
    b.wrap_nonce_tag_sk_enc.assign(p, p + wrap_blob_sz); p += wrap_blob_sz;

    // data_nonce(12) + data_tag(16) + rest = ciphertext
    size_t data_blob_sz = (size_t)(end - p);
    if (data_blob_sz < 12 + 16) throw std::runtime_error("PWENC wire: truncated data blob");
    b.data_nonce_tag_ct.assign(p, end);

    return b;
}

// ── Armor / Dearmor ──────────────────────────────────────────────────────────

inline std::string armor_pw(const std::vector<uint8_t>& wire) {
    std::string b64 = base64_encode(wire.data(), wire.size());

    std::string out;
    out.reserve(sizeof(kPwArmorBegin) + b64.size() + b64.size() / 64 +
                sizeof(kPwArmorEnd) + 4);
    out += kPwArmorBegin;
    out += '\n';

    for (size_t i = 0; i < b64.size(); i += 64) {
        out += b64.substr(i, 64);
        out += '\n';
    }

    out += kPwArmorEnd;
    out += '\n';
    return out;
}

inline std::vector<uint8_t> dearmor_pw(const std::string& text) {
    std::string b64;
    std::istringstream ss(text);
    std::string line;
    bool in_body = false;

    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line == kPwArmorBegin) { in_body = true;  continue; }
        if (line == kPwArmorEnd)   { in_body = false; continue; }
        if (in_body) b64 += line;
    }

    if (b64.empty())
        throw std::runtime_error("dearmor_pw: no base64 data found (missing armor markers?)");

    return base64_decode(b64);
}
