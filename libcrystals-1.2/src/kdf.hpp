#pragma once
#include <vector>
#include <cstdint>
#include <array>
#include <stdexcept>
#include <cstring>

extern "C" {
#include "SimpleFIPS202.h"
#include "SP800-185.h"
}

// Helper: encode a 4-byte big-endian length prefix + data into buf
static inline void append_len32(std::vector<uint8_t>& buf,
                                 const std::vector<uint8_t>& data)
{
    uint32_t n = (uint32_t)data.size();
    buf.push_back((n >> 24) & 0xFF);
    buf.push_back((n >> 16) & 0xFF);
    buf.push_back((n >>  8) & 0xFF);
    buf.push_back((n >>  0) & 0xFF);
    buf.insert(buf.end(), data.begin(), data.end());
}

// SHAKE256 KDF
// buf = len32(SS_classical)||SS_classical || len32(SS_pq)||SS_pq
//     || len32(CT_classical)||CT_classical || len32(CT_pq)||CT_pq
// SHAKE256(out_key, 32, buf, buf_len)
inline std::array<uint8_t, 32> derive_key_shake(
    const std::vector<uint8_t>& ss_classical,
    const std::vector<uint8_t>& ss_pq,
    const std::vector<uint8_t>& ct_classical,
    const std::vector<uint8_t>& ct_pq)
{
    std::vector<uint8_t> buf;
    buf.reserve(8 + ss_classical.size() + 8 + ss_pq.size() +
                8 + ct_classical.size() + 8 + ct_pq.size());
    append_len32(buf, ss_classical);
    append_len32(buf, ss_pq);
    append_len32(buf, ct_classical);
    append_len32(buf, ct_pq);

    std::array<uint8_t, 32> key;
    if (SHAKE256(key.data(), 32, buf.data(), buf.size()) != 0)
        throw std::runtime_error("SHAKE256 KDF failed");
    return key;
}

// KMAC256 KDF
// key     = SS_classical
// message = len32(SS_pq)||SS_pq || len32(CT_classical)||CT_classical || len32(CT_pq)||CT_pq
// custom  = "hybrid-kem-file-encryption-v1"
// NOTE: XKCP KMAC256 takes lengths in BITS
inline std::array<uint8_t, 32> derive_key_kmac(
    const std::vector<uint8_t>& ss_classical,
    const std::vector<uint8_t>& ss_pq,
    const std::vector<uint8_t>& ct_classical,
    const std::vector<uint8_t>& ct_pq)
{
    static const char* kCustom = "hybrid-kem-file-encryption-v1";
    static const size_t kCustomLen = 30; // strlen(kCustom)

    std::vector<uint8_t> msg;
    msg.reserve(8 + ss_pq.size() + 8 + ct_classical.size() + 8 + ct_pq.size());
    append_len32(msg, ss_pq);
    append_len32(msg, ct_classical);
    append_len32(msg, ct_pq);

    std::array<uint8_t, 32> key;
    if (KMAC256(ss_classical.data(), ss_classical.size() * 8,
                msg.data(),          msg.size() * 8,
                key.data(),          256,
                (const uint8_t*)kCustom, kCustomLen * 8) != 0)
        throw std::runtime_error("KMAC256 KDF failed");
    return key;
}

// HYKE KMAC256 KDF (for sign/verify commands)
// key     = SS_classical
// message = SS_pq || CT_classical || CT_pq || salt   (raw concat, no len prefixes)
// custom  = "zorro-hybrid-sig-v1"
// outlen  = 256 bits → 32 bytes
inline std::array<uint8_t, 32> derive_key_hyke(
    const std::vector<uint8_t>& ss_classical,
    const std::vector<uint8_t>& ss_pq,
    const std::vector<uint8_t>& ct_classical,
    const std::vector<uint8_t>& ct_pq,
    const uint8_t salt[32])
{
    static const char* kCustom = "zorro-hybrid-sig-v1";
    static const size_t kCustomLen = 19; // strlen("zorro-hybrid-sig-v1")

    std::vector<uint8_t> msg;
    msg.reserve(ss_pq.size() + ct_classical.size() + ct_pq.size() + 32);
    msg.insert(msg.end(), ss_pq.begin(),        ss_pq.end());
    msg.insert(msg.end(), ct_classical.begin(),  ct_classical.end());
    msg.insert(msg.end(), ct_pq.begin(),         ct_pq.end());
    msg.insert(msg.end(), salt,                  salt + 32);

    std::array<uint8_t, 32> key;
    if (KMAC256(ss_classical.data(), ss_classical.size() * 8,
                msg.data(),          msg.size() * 8,
                key.data(),          256,
                (const uint8_t*)kCustom, kCustomLen * 8) != 0)
        throw std::runtime_error("derive_key_hyke: KMAC256 failed");
    return key;
}

// HYKE context binding (key-substitution prevention)
// ctx = KMAC256(key=pk_classical, msg=pk_pq || "zorro-hybrid-sig-v1", outlen=512 bits)
// Returns 64-byte context vector committed to both public keys.
inline std::vector<uint8_t> compute_hyke_ctx(
    const std::vector<uint8_t>& pk_classical,
    const std::vector<uint8_t>& pk_pq)
{
    static const char* kDomain    = "zorro-hybrid-sig-v1";
    static const size_t kDomainLen = 19;

    std::vector<uint8_t> msg;
    msg.reserve(pk_pq.size() + kDomainLen);
    msg.insert(msg.end(), pk_pq.begin(), pk_pq.end());
    msg.insert(msg.end(), kDomain, kDomain + kDomainLen);

    std::vector<uint8_t> ctx(64);
    if (KMAC256(pk_classical.data(), pk_classical.size() * 8,
                msg.data(),          msg.size() * 8,
                ctx.data(),          512,
                (const uint8_t*)"",  0) != 0)
        throw std::runtime_error("compute_hyke_ctx: KMAC256 failed");
    return ctx;
}
