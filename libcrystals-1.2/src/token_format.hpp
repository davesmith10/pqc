#pragma once
#include "base64.hpp"
#include <vector>
#include <cstdint>
#include <string>
#include <stdexcept>
#include <cstring>
#include <set>

// Token Wire Format:
//
// [MAGIC 8B "zorro\0\0\0"][VERSION 2B: 0x01 0x00]
// [TLV fields in ascending tag order]
// [SIG_LEN 4B BE uint32][SIG_BYTES SIG_LEN B]
//
// TLV: [TAG 1B][LENGTH 2B BE uint16][VALUE LENGTH B]
//
// Tag 0x01: Data        (1–256 bytes)
// Tag 0x02: Issued At   (8 bytes int64 BE Unix epoch)
// Tag 0x03: Expires At  (8 bytes int64 BE Unix epoch)
// Tag 0x04: Tray ID     (16 bytes binary UUID)
// Tag 0x05: Algorithm   (1 byte: 0x03 = ECDSA-P256-SHA256)
// Tag 0x06: Token UUID  (16 bytes random UUID v4)
//
// Signed bytes: MAGIC(8) || VERSION(2) || TLV[0x01..0x06] (no sig trailer)
// Algorithm 0x03 (ECDSA-P256-SHA256) → SIG_LEN = 64 bytes

static constexpr uint8_t kTokenMagic[8] = {'z','o','r','r','o','\0','\0','\0'};

// Algorithm byte values
static constexpr uint8_t kTokenAlgECDSAP256 = 0x03;

struct Token {
    std::vector<uint8_t> data;
    int64_t issued_at  = 0;
    int64_t expires_at = 0;
    uint8_t tray_uuid[16]  = {};
    uint8_t token_uuid[16] = {};
    uint8_t algorithm  = kTokenAlgECDSAP256;
    std::vector<uint8_t> signature;
};

// ── Wire helpers ──────────────────────────────────────────────────────────────

static inline void tok_push_u16be(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back((v >> 8) & 0xFF);
    buf.push_back((v >> 0) & 0xFF);
}

static inline void tok_push_u32be(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back((v >> 24) & 0xFF);
    buf.push_back((v >> 16) & 0xFF);
    buf.push_back((v >>  8) & 0xFF);
    buf.push_back((v >>  0) & 0xFF);
}

static inline void tok_push_i64be(std::vector<uint8_t>& buf, int64_t v) {
    uint64_t u = (uint64_t)v;
    buf.push_back((u >> 56) & 0xFF);
    buf.push_back((u >> 48) & 0xFF);
    buf.push_back((u >> 40) & 0xFF);
    buf.push_back((u >> 32) & 0xFF);
    buf.push_back((u >> 24) & 0xFF);
    buf.push_back((u >> 16) & 0xFF);
    buf.push_back((u >>  8) & 0xFF);
    buf.push_back((u >>  0) & 0xFF);
}

static inline uint16_t tok_read_u16be(const uint8_t* p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

static inline uint32_t tok_read_u32be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) | (uint32_t)p[3];
}

static inline int64_t tok_read_i64be(const uint8_t* p) {
    uint64_t u = ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
                 ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
                 ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
                 ((uint64_t)p[6] <<  8) | (uint64_t)p[7];
    return (int64_t)u;
}

// ── Expected sig size for algorithm ──────────────────────────────────────────

static inline uint32_t token_sig_size(uint8_t alg) {
    if (alg == kTokenAlgECDSAP256) return 64;
    throw std::runtime_error("token: unsupported algorithm byte: " + std::to_string((int)alg));
}

// ── TLV push helper ───────────────────────────────────────────────────────────

static inline void tok_push_tlv(std::vector<uint8_t>& buf, uint8_t tag,
                                  const uint8_t* value, uint16_t len) {
    buf.push_back(tag);
    tok_push_u16be(buf, len);
    buf.insert(buf.end(), value, value + len);
}

// ── Canonical bytes (signed region: magic+version+6 TLVs, no sig trailer) ────

inline std::vector<uint8_t> token_canonical_bytes(const Token& tok) {
    std::vector<uint8_t> buf;
    buf.reserve(10 + (3 + tok.data.size()) + (3 + 8) + (3 + 8) + (3 + 16) + (3 + 1) + (3 + 16));

    // Magic (8 bytes)
    buf.insert(buf.end(), kTokenMagic, kTokenMagic + 8);

    // Version 0x01 0x00
    buf.push_back(0x01);
    buf.push_back(0x00);

    // TLV 0x01: data
    tok_push_tlv(buf, 0x01, tok.data.data(), (uint16_t)tok.data.size());

    // TLV 0x02: issued_at (8 bytes int64 BE)
    uint8_t ts[8];
    uint64_t isu = (uint64_t)tok.issued_at;
    for (int i = 7; i >= 0; --i) { ts[i] = isu & 0xFF; isu >>= 8; }
    tok_push_tlv(buf, 0x02, ts, 8);

    // TLV 0x03: expires_at (8 bytes int64 BE)
    uint64_t exu = (uint64_t)tok.expires_at;
    for (int i = 7; i >= 0; --i) { ts[i] = exu & 0xFF; exu >>= 8; }
    tok_push_tlv(buf, 0x03, ts, 8);

    // TLV 0x04: tray_uuid (16 bytes)
    tok_push_tlv(buf, 0x04, tok.tray_uuid, 16);

    // TLV 0x05: algorithm (1 byte)
    tok_push_tlv(buf, 0x05, &tok.algorithm, 1);

    // TLV 0x06: token_uuid (16 bytes)
    tok_push_tlv(buf, 0x06, tok.token_uuid, 16);

    return buf;
}

// ── Full wire bytes (canonical + sig trailer) ─────────────────────────────────

inline std::vector<uint8_t> token_pack(const Token& tok) {
    auto canonical = token_canonical_bytes(tok);

    std::vector<uint8_t> wire;
    wire.reserve(canonical.size() + 4 + tok.signature.size());
    wire.insert(wire.end(), canonical.begin(), canonical.end());

    tok_push_u32be(wire, (uint32_t)tok.signature.size());
    wire.insert(wire.end(), tok.signature.begin(), tok.signature.end());

    return wire;
}

// ── Unpack: parse wire bytes into Token ───────────────────────────────────────

inline Token token_unpack(const std::vector<uint8_t>& wire) {
    const uint8_t* p   = wire.data();
    const uint8_t* end = wire.data() + wire.size();

    // Magic (8 bytes)
    if ((size_t)(end - p) < 10)
        throw std::runtime_error("token: wire too short");
    if (std::memcmp(p, kTokenMagic, 8) != 0)
        throw std::runtime_error("token: invalid magic");
    p += 8;

    // Version: major must be 0x01
    uint8_t major = *p++;
    p++; // minor (ignored)
    if (major != 0x01)
        throw std::runtime_error("token: unsupported major version: " + std::to_string((int)major));

    // Parse TLV fields (expect tags 0x01–0x05 in ascending order)
    Token tok;
    std::set<uint8_t> seen_tags;
    uint8_t expected_tag = 0x01;

    while (p < end) {
        // Need at least 3 bytes for tag+length
        if ((size_t)(end - p) < 3) {
            // Could be sig trailer: need at least 4 bytes
            break;
        }

        uint8_t tag = *p;

        // If all 6 tags seen, stop TLV parsing
        if (seen_tags.size() == 6) break;

        p++; // consume tag
        uint16_t len = tok_read_u16be(p); p += 2;

        if ((size_t)(end - p) < len)
            throw std::runtime_error("token: TLV value truncated (tag=0x" +
                                     std::to_string((int)tag) + ")");

        // Validate ordering
        if (tag != expected_tag)
            throw std::runtime_error("token: unexpected tag 0x" +
                                     std::to_string((int)tag) +
                                     " (expected 0x" + std::to_string((int)expected_tag) + ")");

        if (seen_tags.count(tag))
            throw std::runtime_error("token: duplicate tag 0x" + std::to_string((int)tag));

        switch (tag) {
            case 0x01: // data
                if (len < 1 || len > 256)
                    throw std::runtime_error("token: tag 0x01 length out of range [1,256]: " +
                                             std::to_string(len));
                tok.data.assign(p, p + len);
                break;

            case 0x02: // issued_at
                if (len != 8)
                    throw std::runtime_error("token: tag 0x02 must be 8 bytes");
                tok.issued_at = tok_read_i64be(p);
                break;

            case 0x03: // expires_at
                if (len != 8)
                    throw std::runtime_error("token: tag 0x03 must be 8 bytes");
                tok.expires_at = tok_read_i64be(p);
                break;

            case 0x04: // tray_uuid
                if (len != 16)
                    throw std::runtime_error("token: tag 0x04 must be 16 bytes");
                std::memcpy(tok.tray_uuid, p, 16);
                break;

            case 0x05: // algorithm
                if (len != 1)
                    throw std::runtime_error("token: tag 0x05 must be 1 byte");
                tok.algorithm = *p;
                // Validate algorithm is known
                token_sig_size(tok.algorithm); // throws if unknown
                break;

            case 0x06: // token_uuid
                if (len != 16)
                    throw std::runtime_error("token: tag 0x06 must be 16 bytes");
                std::memcpy(tok.token_uuid, p, 16);
                break;

            default:
                throw std::runtime_error("token: unknown tag 0x" + std::to_string((int)tag));
        }

        seen_tags.insert(tag);
        p += len;
        expected_tag++;
    }

    // Verify all 6 mandatory tags present
    for (uint8_t t = 0x01; t <= 0x06; ++t) {
        if (!seen_tags.count(t))
            throw std::runtime_error("token: missing mandatory tag 0x" + std::to_string((int)t));
    }

    // Validate issued_at <= expires_at
    if (tok.issued_at > tok.expires_at)
        throw std::runtime_error("token: issued_at > expires_at");

    // Parse sig trailer: SIG_LEN (4B BE) + SIG_BYTES
    if ((size_t)(end - p) < 4)
        throw std::runtime_error("token: missing signature length field");
    uint32_t sig_len = tok_read_u32be(p); p += 4;

    uint32_t expected_sig_len = token_sig_size(tok.algorithm);
    if (sig_len != expected_sig_len)
        throw std::runtime_error("token: SIG_LEN " + std::to_string(sig_len) +
                                 " does not match expected " + std::to_string(expected_sig_len) +
                                 " for algorithm 0x" + std::to_string((int)tok.algorithm));

    if ((size_t)(end - p) < sig_len)
        throw std::runtime_error("token: signature bytes truncated");
    tok.signature.assign(p, p + sig_len);
    p += sig_len;

    if (p != end)
        throw std::runtime_error("token: trailing bytes after signature");

    return tok;
}

// ── Armor / Dearmor ───────────────────────────────────────────────────────────

inline std::string token_armor(const std::vector<uint8_t>& wire) {
    return base64_encode(wire.data(), wire.size()) + '\n';
}

inline std::vector<uint8_t> token_dearmor(const std::string& text) {
    // Strip any surrounding whitespace/newlines before decoding
    std::string b64;
    b64.reserve(text.size());
    for (char c : text) {
        if (c != '\n' && c != '\r' && c != ' ' && c != '\t')
            b64 += c;
    }
    if (b64.empty())
        throw std::runtime_error("token_dearmor: empty input");
    return base64_decode(b64);
}
