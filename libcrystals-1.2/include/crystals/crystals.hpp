#pragma once
// crystals/crystals.hpp — libcrystals v1.2 public API
//
// This is the ONLY header consumers should include.
// All declarations marked @api-stable v1.0 are frozen.
// Do NOT include internal src/ headers from consuming code.

#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <set>

#include <openssl/evp.h>
#include <openssl/rand.h>

extern "C" {
#include "SimpleFIPS202.h"
#include "SP800-185.h"
}

// ── Base64 (declared early — used by inline functions below) ─────────────────

std::string base64_encode(const uint8_t* data, size_t len); // @api-stable v1.0
std::vector<uint8_t> base64_decode(const std::string& encoded); // @api-stable v1.0

// ── Tray domain model ─────────────────────────────────────────────────────────

enum class TrayType {
    // crystals group (Kyber + Dilithium)   @api-stable v1.0
    Level0, Level1, Level2_25519, Level2, Level3, Level5,
    // mceliece+slhdsa group               @api-stable v1.0, @api-stable v1.1
    McEliece_Level1, McEliece_Level2, McEliece_Level3, McEliece_Level4, McEliece_Level5,
    // mlkem+mldsa group (ML-KEM + ML-DSA) @api-candidate-1.2
    MlKem_Level1, MlKem_Level2, MlKem_Level3, MlKem_Level4,
    // frodokem+falcon group               @api-candidate-1.2
    FrodoFalcon_Level1, FrodoFalcon_Level2, FrodoFalcon_Level3, FrodoFalcon_Level4
};

struct Slot {                          // @api-stable v1.0
    std::string alg_name;             // e.g. "X25519", "Kyber768", "ECDSA P-384", "Dilithium3"
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;          // empty if public-only tray
};

struct Tray {                          // @api-stable v1.0
    int version = 1;
    std::string alias;
    TrayType tray_type;
    std::string profile_group;
    std::string type_str;             // "tray" or "secure-tray"
    std::string id;                   // UUID v8
    bool is_public = false;
    std::vector<Slot> slots;
    std::string created;              // ISO 8601 UTC
    std::string expires;              // ISO 8601 UTC (created + 2 years)
};

// Generate a full tray with keyed material.
Tray make_tray(TrayType t, const std::string& alias);       // @api-stable v1.0

// Copy src, clear all sk fields, assign a fresh UUID, append ".pub" to alias.
Tray make_public_tray(const Tray& src);                      // @api-stable v1.0

// Returns true if tray.id matches the UUID derived from its public keys.
bool validate_tray_uuid(const Tray& tray);                   // @api-stable v1.0

// ── mcs namespace: McEliece + SLH-DSA keygen ─────────────────────────────────

namespace mcs {

struct McElieceKeys {              // @api-stable v1.1
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;
};

struct SlhDsaKeys {                // @api-stable v1.1
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;
};

McElieceKeys keygen_mceliece(const std::string& param_set); // @api-stable v1.1
SlhDsaKeys   keygen_slhdsa(const std::string& alg_name);   // @api-stable v1.1

} // namespace mcs

// ── mceliece_kem namespace: McEliece KEM encapsulation/decapsulation ─────────

namespace mceliece_kem {                           // @api-stable v1.1

// Encapsulate: generate ciphertext ct and shared secret ss against public key pk.
// param_set: "mceliece348864f", "mceliece460896f", "mceliece6688128f",
//            "mceliece6960119f", or "mceliece8192128f"
void encaps(const std::string& param_set,
            const std::vector<uint8_t>& pk,
            std::vector<uint8_t>& ct_out,
            std::vector<uint8_t>& ss_out);         // @api-stable v1.1

// Decapsulate: recover shared secret ss from ciphertext ct and secret key sk.
void decaps(const std::string& param_set,
            const std::vector<uint8_t>& sk,
            const std::vector<uint8_t>& ct,
            std::vector<uint8_t>& ss_out);         // @api-stable v1.1

} // namespace mceliece_kem

// ── slhdsa_sig namespace: SLH-DSA signatures ─────────────────────────────────

namespace slhdsa_sig {                             // @api-stable v1.1

// Returns true if alg_name starts with "SLH-DSA"
bool is_slhdsa_sig(const std::string& alg_name);  // @api-stable v1.1

// Returns the fixed signature size in bytes for the given SLH-DSA algorithm.
size_t sig_bytes(const std::string& alg_name);    // @api-stable v1.1

// Sign msg with sk; fills sig_out with the signature.
void sign(const std::string& alg_name,
          const std::vector<uint8_t>& sk,
          const std::vector<uint8_t>& msg,
          std::vector<uint8_t>& sig_out);          // @api-stable v1.1

// Verify sig against pk and msg. Returns true if valid.
bool verify(const std::string& alg_name,
            const std::vector<uint8_t>& pk,
            const std::vector<uint8_t>& msg,
            const std::vector<uint8_t>& sig);      // @api-stable v1.1

} // namespace slhdsa_sig

// ── oqs_kem namespace: liboqs KEM operations ─────────────────────────────────

namespace oqs_kem {  // @api-candidate-1.2

struct Keys {                          // @api-candidate-1.2
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;
};

// Generate a keypair for the named algorithm (e.g. "ML-KEM-512", "FrodoKEM-640-AES").
// Throws std::runtime_error if alg_name is unknown or liboqs returns an error.
Keys keygen(const std::string& alg_name);  // @api-candidate-1.2

// Encapsulate against pk; fills ct_out and ss_out.
void encaps(const std::string& alg_name,
            const std::vector<uint8_t>& pk,
            std::vector<uint8_t>& ct_out,
            std::vector<uint8_t>& ss_out);  // @api-candidate-1.2

// Decapsulate ct with sk; fills ss_out.
void decaps(const std::string& alg_name,
            const std::vector<uint8_t>& sk,
            const std::vector<uint8_t>& ct,
            std::vector<uint8_t>& ss_out);  // @api-candidate-1.2

// Returns true if alg_name is handled by this namespace (ML-KEM-* or FrodoKEM-*).
bool is_oqs_kem(const std::string& alg_name);  // @api-candidate-1.2

} // namespace oqs_kem

// ── oqs_sig namespace: liboqs signature operations ───────────────────────────

namespace oqs_sig {  // @api-candidate-1.2

struct Keys {                          // @api-candidate-1.2
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;
};

// Generate a keypair for the named algorithm (e.g. "ML-DSA-44", "Falcon-512").
// Throws std::runtime_error if alg_name is unknown or liboqs returns an error.
Keys keygen(const std::string& alg_name);  // @api-candidate-1.2

// Returns true if alg_name is handled by this namespace (ML-DSA-* or Falcon-*).
bool is_oqs_sig(const std::string& alg_name);  // @api-candidate-1.2

// Maximum signature size in bytes for the given algorithm.
size_t sig_bytes(const std::string& alg_name);  // @api-candidate-1.2

// Sign msg with sk; fills sig_out.
void sign(const std::string& alg_name,
          const std::vector<uint8_t>& sk,
          const std::vector<uint8_t>& msg,
          std::vector<uint8_t>& sig_out);  // @api-candidate-1.2

// Verify sig against pk and msg. Returns true if valid.
bool verify(const std::string& alg_name,
            const std::vector<uint8_t>& pk,
            const std::vector<uint8_t>& msg,
            const std::vector<uint8_t>& sig);  // @api-candidate-1.2

} // namespace oqs_sig

// ── Secure tray (protect / unprotect) ─────────────────────────────────────────

struct ScryptParams {                  // @api-stable v1.0
    std::vector<uint8_t> salt;
    int n_log2 = 19;
    int r = 8;
    int p = 1;
};

struct KemBlock {                      // @api-stable v1.0
    std::vector<uint8_t> nonce;       // 12 bytes
    std::vector<uint8_t> tag;         // 16 bytes
    std::vector<uint8_t> ct;          // 32 bytes
};

struct EncryptionEnvelope {            // @api-stable v1.0
    ScryptParams scrypt;
    KemBlock kem;
};

struct SecureTray : public Tray {      // @api-stable v1.0
    EncryptionEnvelope enc;
    SecureTray() { type_str = "secure-tray"; }
};

// YAML I/O — load a plain (unencrypted) tray from a YAML file.
// Throws std::runtime_error if the file is already a secure-tray.
Tray        load_tray_yaml       (const std::string& path); // @api-stable v1.0

// Load an encrypted secure-tray from a YAML file.
// Throws std::runtime_error if the file is not a secure-tray.
SecureTray  load_secure_tray_yaml(const std::string& path); // @api-stable v1.0

// Emit an encrypted secure-tray as a YAML string.
std::string emit_secure_tray_yaml(const SecureTray& st);    // @api-stable v1.0

// Core crypto — no interactive I/O, no file access.
// Throws std::runtime_error on failure (bad UUID, crypto error, etc.).
SecureTray protect_tray  (const Tray&       tray,   const char* passwd, size_t passwd_len); // @api-stable v1.0
Tray       unprotect_tray(const SecureTray& st,     const char* passwd, size_t passwd_len); // @api-stable v1.0

// ── OBIWAN wire format ────────────────────────────────────────────────────────

enum class KDFAlg   : uint8_t { SHAKE256 = 0, KMAC256 = 1 };         // @api-stable v1.0
enum class CipherAlg: uint8_t { AES256GCM = 0, ChaCha20Poly1305 = 1 }; // @api-stable v1.0

static constexpr char kArmorBegin[] = "-----BEGIN OBIWAN ENCRYPTED FILE-----";
static constexpr char kArmorEnd[]   = "-----END OBIWAN ENCRYPTED FILE-----";

struct WireHeader {                    // @api-stable v1.0
    KDFAlg    kdf;
    CipherAlg cipher;
    std::vector<uint8_t> ct_classical;
    std::vector<uint8_t> ct_pq;
};

// Pack header + payload into wire bytes, then base64-armor them.
std::string armor_pack(const WireHeader& hdr,                // @api-stable v1.0
                        const std::vector<uint8_t>& payload);

// Dearmor base64 and unpack wire header + payload.
// Throws on malformed input.
WireHeader armor_unpack(const std::string& armored,          // @api-stable v1.0
                        std::vector<uint8_t>& payload_out);

// ── HYKE signed file wire format ──────────────────────────────────────────────

struct HykeHeader {                    // @api-stable v1.0
    uint8_t  tray_id = 0;
    uint8_t  tray_uuid[16] = {};
    uint8_t  salt[32] = {};
    std::vector<uint8_t> ct_classical;
    std::vector<uint8_t> ct_pq;
    std::vector<uint8_t> sig_classical;
    std::vector<uint8_t> sig_pq;
};

static constexpr char kHykeArmorBegin[] = "-----BEGIN HYKE SIGNED FILE-----";
static constexpr char kHykeArmorEnd[]   = "-----END HYKE SIGNED FILE-----";

// TrayID mapping
inline uint8_t tray_id_byte(TrayType t) {                    // @api-stable v1.0
    switch (t) {
        case TrayType::Level2_25519:       return 0x01;
        case TrayType::Level2:             return 0x02;
        case TrayType::Level3:             return 0x03;
        case TrayType::Level5:             return 0x04;
        case TrayType::MlKem_Level1:       return 0x11;
        case TrayType::MlKem_Level2:       return 0x12;
        case TrayType::MlKem_Level3:       return 0x13;
        case TrayType::MlKem_Level4:       return 0x14;
        case TrayType::FrodoFalcon_Level1: return 0x21;
        case TrayType::FrodoFalcon_Level2: return 0x22;
        case TrayType::FrodoFalcon_Level3: return 0x23;
        case TrayType::FrodoFalcon_Level4: return 0x24;
        case TrayType::McEliece_Level1:    return 0x31;
        case TrayType::McEliece_Level2:    return 0x32;
        case TrayType::McEliece_Level3:    return 0x33;
        case TrayType::McEliece_Level4:    return 0x34;
        case TrayType::McEliece_Level5:    return 0x35;
        default: throw std::invalid_argument("Unknown TrayType");
    }
}

inline TrayType tray_type_from_id(uint8_t id) {             // @api-stable v1.0
    switch (id) {
        case 0x01: return TrayType::Level2_25519;
        case 0x02: return TrayType::Level2;
        case 0x03: return TrayType::Level3;
        case 0x04: return TrayType::Level5;
        case 0x11: return TrayType::MlKem_Level1;
        case 0x12: return TrayType::MlKem_Level2;
        case 0x13: return TrayType::MlKem_Level3;
        case 0x14: return TrayType::MlKem_Level4;
        case 0x21: return TrayType::FrodoFalcon_Level1;
        case 0x22: return TrayType::FrodoFalcon_Level2;
        case 0x23: return TrayType::FrodoFalcon_Level3;
        case 0x24: return TrayType::FrodoFalcon_Level4;
        case 0x31: return TrayType::McEliece_Level1;
        case 0x32: return TrayType::McEliece_Level2;
        case 0x33: return TrayType::McEliece_Level3;
        case 0x34: return TrayType::McEliece_Level4;
        case 0x35: return TrayType::McEliece_Level5;
        default: throw std::runtime_error("Unknown HYKE TrayID: " + std::to_string((int)id));
    }
}

inline bool is_tray_complete(TrayType t) {              // @api-stable v1.2
    switch (t) {
        case TrayType::Level0:          return false;   // crystals, classical-only
        case TrayType::Level1:          return false;   // crystals, PQ-only
        case TrayType::McEliece_Level1: return false;   // mceliece+slhdsa, PQ-only
        default:                        return true;
    }
}

// Parse 36-char RFC 4122 UUID string to 16 bytes
inline void parse_uuid(const std::string& uuid_str, uint8_t uuid_bytes[16]) { // @api-stable v1.0
    std::string hex;
    hex.reserve(32);
    for (char c : uuid_str) {
        if (c != '-') hex += c;
    }
    if (hex.size() != 32)
        throw std::runtime_error("Invalid UUID (expected 32 hex chars without dashes): " + uuid_str);
    for (int i = 0; i < 16; ++i) {
        unsigned int byte_val = 0;
        std::istringstream ss(hex.substr(i * 2, 2));
        ss >> std::hex >> byte_val;
        uuid_bytes[i] = (uint8_t)byte_val;
    }
}

static inline void hyke_push_u16be(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back((v >> 8) & 0xFF);
    buf.push_back((v >> 0) & 0xFF);
}

static inline void hyke_push_u32be(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back((v >> 24) & 0xFF);
    buf.push_back((v >> 16) & 0xFF);
    buf.push_back((v >>  8) & 0xFF);
    buf.push_back((v >>  0) & 0xFF);
}

static inline uint16_t hyke_read_u16be(const uint8_t* p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

static inline uint32_t hyke_read_u32be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) | (uint32_t)p[3];
}

inline std::vector<uint8_t> hyke_partial_header(                // @api-stable v1.0
    const HykeHeader& hdr,
    uint32_t payload_len,
    uint32_t sig_cl_len,
    uint32_t sig_pq_len)
{
    const uint32_t header_len = 80
                              + (uint32_t)hdr.ct_classical.size()
                              + (uint32_t)hdr.ct_pq.size()
                              + sig_cl_len
                              + sig_pq_len;

    std::vector<uint8_t> buf;
    buf.reserve(80 + hdr.ct_classical.size() + hdr.ct_pq.size());

    buf.push_back('H'); buf.push_back('Y'); buf.push_back('K'); buf.push_back('E');
    hyke_push_u16be(buf, 0x0001);
    buf.push_back(hdr.tray_id);
    buf.push_back(0x00);
    hyke_push_u32be(buf, header_len);
    hyke_push_u32be(buf, payload_len);
    buf.insert(buf.end(), hdr.tray_uuid, hdr.tray_uuid + 16);
    buf.insert(buf.end(), hdr.salt, hdr.salt + 32);
    hyke_push_u32be(buf, (uint32_t)hdr.ct_classical.size());
    hyke_push_u32be(buf, (uint32_t)hdr.ct_pq.size());
    hyke_push_u32be(buf, sig_cl_len);
    hyke_push_u32be(buf, sig_pq_len);
    buf.insert(buf.end(), hdr.ct_classical.begin(), hdr.ct_classical.end());
    buf.insert(buf.end(), hdr.ct_pq.begin(), hdr.ct_pq.end());

    return buf;
}

inline std::vector<uint8_t> hyke_pack(const HykeHeader& hdr,   // @api-stable v1.0
                                       const std::vector<uint8_t>& payload)
{
    auto partial = hyke_partial_header(hdr, (uint32_t)payload.size(),
                                       (uint32_t)hdr.sig_classical.size(),
                                       (uint32_t)hdr.sig_pq.size());
    std::vector<uint8_t> wire;
    wire.reserve(partial.size() + hdr.sig_classical.size() + hdr.sig_pq.size() + payload.size());
    wire.insert(wire.end(), partial.begin(),          partial.end());
    wire.insert(wire.end(), hdr.sig_classical.begin(), hdr.sig_classical.end());
    wire.insert(wire.end(), hdr.sig_pq.begin(),        hdr.sig_pq.end());
    wire.insert(wire.end(), payload.begin(),           payload.end());
    return wire;
}

inline HykeHeader hyke_unpack(const std::vector<uint8_t>& wire, // @api-stable v1.0
                                std::vector<uint8_t>& payload_out)
{
    static const size_t kMinWire = 80;
    if (wire.size() < kMinWire)
        throw std::runtime_error("HYKE wire too short");

    const uint8_t* p   = wire.data();
    const uint8_t* end = wire.data() + wire.size();

    if (std::memcmp(p, "HYKE", 4) != 0)
        throw std::runtime_error("HYKE wire: invalid magic");
    p += 4;

    uint16_t version = hyke_read_u16be(p); p += 2;
    if (version != 0x0001)
        throw std::runtime_error("HYKE wire: unsupported version " + std::to_string(version));

    HykeHeader hdr;
    hdr.tray_id = *p++;
    p++;

    uint32_t header_len  = hyke_read_u32be(p); p += 4;
    uint32_t payload_len = hyke_read_u32be(p); p += 4;

    if (p + 16 > end) throw std::runtime_error("HYKE wire: truncated uuid");
    std::memcpy(hdr.tray_uuid, p, 16); p += 16;

    if (p + 32 > end) throw std::runtime_error("HYKE wire: truncated salt");
    std::memcpy(hdr.salt, p, 32); p += 32;

    if (p + 16 > end) throw std::runtime_error("HYKE wire: truncated length fields");
    uint32_t ct_cl_len  = hyke_read_u32be(p); p += 4;
    uint32_t ct_pq_len  = hyke_read_u32be(p); p += 4;
    uint32_t sig_cl_len = hyke_read_u32be(p); p += 4;
    uint32_t sig_pq_len = hyke_read_u32be(p); p += 4;

    uint64_t expected_hdr = 80ULL + ct_cl_len + ct_pq_len + sig_cl_len + sig_pq_len;
    if ((uint64_t)header_len != expected_hdr)
        throw std::runtime_error("HYKE wire: header_len inconsistent with field lengths");
    if ((size_t)header_len > wire.size())
        throw std::runtime_error("HYKE wire: header_len exceeds wire size");

    const uint8_t* header_end = wire.data() + header_len;

    if (p + ct_cl_len > header_end) throw std::runtime_error("HYKE wire: truncated ct_classical");
    hdr.ct_classical.assign(p, p + ct_cl_len); p += ct_cl_len;

    if (p + ct_pq_len > header_end) throw std::runtime_error("HYKE wire: truncated ct_pq");
    hdr.ct_pq.assign(p, p + ct_pq_len); p += ct_pq_len;

    if (p + sig_cl_len > header_end) throw std::runtime_error("HYKE wire: truncated sig_classical");
    hdr.sig_classical.assign(p, p + sig_cl_len); p += sig_cl_len;

    if (p + sig_pq_len > header_end) throw std::runtime_error("HYKE wire: truncated sig_pq");
    hdr.sig_pq.assign(p, p + sig_pq_len); p += sig_pq_len;

    if (p != header_end)
        throw std::runtime_error("HYKE wire: header parse ended before header_end");

    if (wire.data() + header_len + (size_t)payload_len > end)
        throw std::runtime_error("HYKE wire: payload extends beyond wire data");

    payload_out.assign(header_end, header_end + payload_len);
    return hdr;
}

inline std::string hyke_armor(const std::vector<uint8_t>& wire) { // @api-stable v1.0
    // base64_encode declared below
    std::string b64 = base64_encode(wire.data(), wire.size());
    std::string out;
    out.reserve(sizeof(kHykeArmorBegin) + b64.size() + b64.size() / 64 + sizeof(kHykeArmorEnd) + 4);
    out += kHykeArmorBegin;
    out += '\n';
    for (size_t i = 0; i < b64.size(); i += 64) {
        out += b64.substr(i, 64);
        out += '\n';
    }
    out += kHykeArmorEnd;
    out += '\n';
    return out;
}

inline std::vector<uint8_t> hyke_dearmor(const std::string& text) { // @api-stable v1.0
    std::string b64;
    std::istringstream ss(text);
    std::string line;
    bool in_body = false;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line == kHykeArmorBegin) { in_body = true;  continue; }
        if (line == kHykeArmorEnd)   { in_body = false; continue; }
        if (in_body) b64 += line;
    }
    if (b64.empty())
        throw std::runtime_error("hyke_dearmor: no base64 data found (missing armor markers?)");
    return base64_decode(b64);
}

// ── PWENC bundle wire format ──────────────────────────────────────────────────

struct PwBundle {                      // @api-stable v1.0
    int     level;                    // 512, 768, or 1024
    uint8_t salt[32];
    uint8_t scrypt_n_log2;
    uint8_t scrypt_r;
    uint8_t scrypt_p;
    std::vector<uint8_t> pk;
    std::vector<uint8_t> ct;
    std::vector<uint8_t> wrap_nonce_tag_sk_enc;
    std::vector<uint8_t> data_nonce_tag_ct;
};

static constexpr char kPwArmorBegin[] = "-----BEGIN OBIWAN PW ENCRYPTED FILE-----";
static constexpr char kPwArmorEnd[]   = "-----END OBIWAN PW ENCRYPTED FILE-----";

static inline void pw_push_u16be(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back((v >> 8) & 0xFF);
    buf.push_back((v >> 0) & 0xFF);
}

static inline uint16_t pw_read_u16be(const uint8_t* p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

inline std::vector<uint8_t> pw_bundle_aad(int level) {         // @api-stable v1.0
    std::vector<uint8_t> aad;
    aad.reserve(7);
    aad.push_back('O'); aad.push_back('B'); aad.push_back('W'); aad.push_back('E');
    aad.push_back(0x01);
    pw_push_u16be(aad, (uint16_t)level);
    return aad;
}

inline std::vector<uint8_t> pack_pw_bundle(const PwBundle& b) { // @api-stable v1.0
    std::vector<uint8_t> buf;
    buf.reserve(7 + 32 + 3 + b.pk.size() + b.ct.size() +
                b.wrap_nonce_tag_sk_enc.size() + b.data_nonce_tag_ct.size());

    buf.push_back('O'); buf.push_back('B'); buf.push_back('W'); buf.push_back('E');
    buf.push_back(0x01);
    pw_push_u16be(buf, (uint16_t)b.level);
    buf.insert(buf.end(), b.salt, b.salt + 32);
    buf.push_back(b.scrypt_n_log2);
    buf.push_back(b.scrypt_r);
    buf.push_back(b.scrypt_p);
    buf.insert(buf.end(), b.pk.begin(), b.pk.end());
    buf.insert(buf.end(), b.ct.begin(), b.ct.end());
    buf.insert(buf.end(), b.wrap_nonce_tag_sk_enc.begin(), b.wrap_nonce_tag_sk_enc.end());
    buf.insert(buf.end(), b.data_nonce_tag_ct.begin(), b.data_nonce_tag_ct.end());
    return buf;
}

inline PwBundle parse_pw_bundle(const std::vector<uint8_t>& wire) { // @api-stable v1.0
    static const size_t kMinFixed = 7 + 32 + 3;
    if (wire.size() < kMinFixed)
        throw std::runtime_error("PWENC wire too short");

    const uint8_t* p   = wire.data();
    const uint8_t* end = wire.data() + wire.size();

    if (std::memcmp(p, "OBWE", 4) != 0)
        throw std::runtime_error("PWENC wire: invalid magic");
    p += 4;

    if (*p != 0x01)
        throw std::runtime_error("PWENC wire: unsupported version " + std::to_string((int)*p));
    p += 1;

    uint16_t level_raw = pw_read_u16be(p); p += 2;
    PwBundle b;
    b.level = (int)level_raw;

    size_t pk_sz, ct_sz, sk_sz;
    if (b.level == 512)      { pk_sz = 800;  ct_sz = 768;  sk_sz = 1632; }
    else if (b.level == 768) { pk_sz = 1184; ct_sz = 1088; sk_sz = 2400; }
    else if (b.level == 1024){ pk_sz = 1568; ct_sz = 1568; sk_sz = 3168; }
    else throw std::runtime_error("PWENC wire: unknown level " + std::to_string(b.level));

    if (p + 32 > end) throw std::runtime_error("PWENC wire: truncated salt");
    std::memcpy(b.salt, p, 32); p += 32;

    if (p + 3 > end) throw std::runtime_error("PWENC wire: truncated scrypt params");
    b.scrypt_n_log2 = *p++;
    b.scrypt_r      = *p++;
    b.scrypt_p      = *p++;

    if (p + pk_sz > end) throw std::runtime_error("PWENC wire: truncated pk");
    b.pk.assign(p, p + pk_sz); p += pk_sz;

    if (p + ct_sz > end) throw std::runtime_error("PWENC wire: truncated ct");
    b.ct.assign(p, p + ct_sz); p += ct_sz;

    size_t wrap_blob_sz = 12 + 16 + sk_sz;
    if (p + wrap_blob_sz > end) throw std::runtime_error("PWENC wire: truncated wrap blob");
    b.wrap_nonce_tag_sk_enc.assign(p, p + wrap_blob_sz); p += wrap_blob_sz;

    size_t data_blob_sz = (size_t)(end - p);
    if (data_blob_sz < 12 + 16) throw std::runtime_error("PWENC wire: truncated data blob");
    b.data_nonce_tag_ct.assign(p, end);

    return b;
}

inline std::string armor_pw(const std::vector<uint8_t>& wire) { // @api-stable v1.0
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

inline std::vector<uint8_t> dearmor_pw(const std::string& text) { // @api-stable v1.0
    std::string b64;
    std::istringstream ss(text);
    std::string line;
    bool in_body = false;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line == kPwArmorBegin) { in_body = true;  continue; }
        if (line == kPwArmorEnd)   { in_body = false; continue; }
        if (in_body) b64 += line;
    }
    if (b64.empty())
        throw std::runtime_error("dearmor_pw: no base64 data found (missing armor markers?)");
    return base64_decode(b64);
}

// ── Token wire format ─────────────────────────────────────────────────────────

static constexpr uint8_t kTokenMagic[8] = {'o','b','i','-','w','a','n','\0'}; // @api-stable v1.0
static constexpr uint8_t kTokenAlgECDSAP256 = 0x03;                           // @api-stable v1.0

struct Token {                         // @api-stable v1.0
    std::vector<uint8_t> data;
    int64_t issued_at  = 0;
    int64_t expires_at = 0;
    uint8_t tray_uuid[16]  = {};
    uint8_t token_uuid[16] = {};
    uint8_t algorithm  = kTokenAlgECDSAP256;
    std::vector<uint8_t> signature;
};

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

static inline uint32_t token_sig_size(uint8_t alg) {
    if (alg == kTokenAlgECDSAP256) return 64;
    throw std::runtime_error("token: unsupported algorithm byte: " + std::to_string((int)alg));
}

static inline void tok_push_tlv(std::vector<uint8_t>& buf, uint8_t tag,
                                  const uint8_t* value, uint16_t len) {
    buf.push_back(tag);
    tok_push_u16be(buf, len);
    buf.insert(buf.end(), value, value + len);
}

inline std::vector<uint8_t> token_canonical_bytes(const Token& tok) { // @api-stable v1.0
    std::vector<uint8_t> buf;
    buf.reserve(10 + (3 + tok.data.size()) + (3 + 8) + (3 + 8) + (3 + 16) + (3 + 1) + (3 + 16));

    buf.insert(buf.end(), kTokenMagic, kTokenMagic + 8);
    buf.push_back(0x01);
    buf.push_back(0x00);

    tok_push_tlv(buf, 0x01, tok.data.data(), (uint16_t)tok.data.size());

    uint8_t ts[8];
    uint64_t isu = (uint64_t)tok.issued_at;
    for (int i = 7; i >= 0; --i) { ts[i] = isu & 0xFF; isu >>= 8; }
    tok_push_tlv(buf, 0x02, ts, 8);

    uint64_t exu = (uint64_t)tok.expires_at;
    for (int i = 7; i >= 0; --i) { ts[i] = exu & 0xFF; exu >>= 8; }
    tok_push_tlv(buf, 0x03, ts, 8);

    tok_push_tlv(buf, 0x04, tok.tray_uuid, 16);
    tok_push_tlv(buf, 0x05, &tok.algorithm, 1);
    tok_push_tlv(buf, 0x06, tok.token_uuid, 16);

    return buf;
}

inline std::vector<uint8_t> token_pack(const Token& tok) {   // @api-stable v1.0
    auto canonical = token_canonical_bytes(tok);
    std::vector<uint8_t> wire;
    wire.reserve(canonical.size() + 4 + tok.signature.size());
    wire.insert(wire.end(), canonical.begin(), canonical.end());
    tok_push_u32be(wire, (uint32_t)tok.signature.size());
    wire.insert(wire.end(), tok.signature.begin(), tok.signature.end());
    return wire;
}

inline Token token_unpack(const std::vector<uint8_t>& wire) { // @api-stable v1.0
    const uint8_t* p   = wire.data();
    const uint8_t* end = wire.data() + wire.size();

    if ((size_t)(end - p) < 10)
        throw std::runtime_error("token: wire too short");
    if (std::memcmp(p, kTokenMagic, 8) != 0)
        throw std::runtime_error("token: invalid magic");
    p += 8;

    uint8_t major = *p++;
    p++;
    if (major != 0x01)
        throw std::runtime_error("token: unsupported major version: " + std::to_string((int)major));

    Token tok;
    std::set<uint8_t> seen_tags;
    uint8_t expected_tag = 0x01;

    while (p < end) {
        if ((size_t)(end - p) < 3) break;
        uint8_t tag = *p;
        if (seen_tags.size() == 6) break;
        p++;
        uint16_t len = tok_read_u16be(p); p += 2;

        if ((size_t)(end - p) < len)
            throw std::runtime_error("token: TLV value truncated (tag=0x" +
                                     std::to_string((int)tag) + ")");
        if (tag != expected_tag)
            throw std::runtime_error("token: unexpected tag 0x" +
                                     std::to_string((int)tag) +
                                     " (expected 0x" + std::to_string((int)expected_tag) + ")");
        if (seen_tags.count(tag))
            throw std::runtime_error("token: duplicate tag 0x" + std::to_string((int)tag));

        switch (tag) {
            case 0x01:
                if (len < 1 || len > 256)
                    throw std::runtime_error("token: tag 0x01 length out of range [1,256]: " +
                                             std::to_string(len));
                tok.data.assign(p, p + len);
                break;
            case 0x02:
                if (len != 8) throw std::runtime_error("token: tag 0x02 must be 8 bytes");
                tok.issued_at = tok_read_i64be(p);
                break;
            case 0x03:
                if (len != 8) throw std::runtime_error("token: tag 0x03 must be 8 bytes");
                tok.expires_at = tok_read_i64be(p);
                break;
            case 0x04:
                if (len != 16) throw std::runtime_error("token: tag 0x04 must be 16 bytes");
                std::memcpy(tok.tray_uuid, p, 16);
                break;
            case 0x05:
                if (len != 1) throw std::runtime_error("token: tag 0x05 must be 1 byte");
                tok.algorithm = *p;
                token_sig_size(tok.algorithm);
                break;
            case 0x06:
                if (len != 16) throw std::runtime_error("token: tag 0x06 must be 16 bytes");
                std::memcpy(tok.token_uuid, p, 16);
                break;
            default:
                throw std::runtime_error("token: unknown tag 0x" + std::to_string((int)tag));
        }

        seen_tags.insert(tag);
        p += len;
        expected_tag++;
    }

    for (uint8_t t = 0x01; t <= 0x06; ++t) {
        if (!seen_tags.count(t))
            throw std::runtime_error("token: missing mandatory tag 0x" + std::to_string((int)t));
    }

    if (tok.issued_at > tok.expires_at)
        throw std::runtime_error("token: issued_at > expires_at");

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

inline std::string token_armor(const std::vector<uint8_t>& wire) { // @api-stable v1.0
    return base64_encode(wire.data(), wire.size()) + '\n';
}

inline std::vector<uint8_t> token_dearmor(const std::string& text) { // @api-stable v1.0
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

// ── EC operations ─────────────────────────────────────────────────────────────

namespace ec {

enum class Algorithm {                 // @api-stable v1.0
    X25519,
    Ed25519,
    P256,
    P384,
    P521
};

struct KeyPair {                       // @api-stable v1.0
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;
};

KeyPair keygen(Algorithm alg);         // @api-stable v1.0

} // namespace ec

// ── EC KEM ────────────────────────────────────────────────────────────────────

namespace ec_kem {

bool is_classical_kem(const std::string& alg_name); // @api-stable v1.0

void encaps(const std::string& alg_name,             // @api-stable v1.0
            const std::vector<uint8_t>& pk,
            std::vector<uint8_t>& ct_out,
            std::vector<uint8_t>& ss_out);

void decaps(const std::string& alg_name,             // @api-stable v1.0
            const std::vector<uint8_t>& sk,
            const std::vector<uint8_t>& ct,
            std::vector<uint8_t>& ss_out);

} // namespace ec_kem

// ── EC signatures ─────────────────────────────────────────────────────────────

namespace ec_sig {

bool is_classical_sig(const std::string& alg_name); // @api-stable v1.0
size_t sig_bytes(const std::string& alg_name);       // @api-stable v1.0

void sign(const std::string& alg_name,               // @api-stable v1.0
          const std::vector<uint8_t>& sk,
          const std::vector<uint8_t>& msg,
          std::vector<uint8_t>& sig_out);

bool verify(const std::string& alg_name,             // @api-stable v1.0
            const std::vector<uint8_t>& pk,
            const std::vector<uint8_t>& msg,
            const std::vector<uint8_t>& sig);

} // namespace ec_sig

// ── Dilithium API (C bindings) ────────────────────────────────────────────────

extern "C" {

int pqcrystals_dilithium2_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_dilithium3_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_dilithium5_ref_keypair(uint8_t *pk, uint8_t *sk);

int pqcrystals_dilithium2_ref_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *ctx, size_t ctxlen,
                                        const uint8_t *sk);
int pqcrystals_dilithium2_ref_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk);

int pqcrystals_dilithium3_ref_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *ctx, size_t ctxlen,
                                        const uint8_t *sk);
int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk);

int pqcrystals_dilithium5_ref_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *ctx, size_t ctxlen,
                                        const uint8_t *sk);
int pqcrystals_dilithium5_ref_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk);

} // extern "C"

struct DilithiumSizes {               // @api-stable v1.0
    size_t pk_bytes;
    size_t sk_bytes;
};

inline DilithiumSizes dilithium_sizes(int mode) {   // @api-stable v1.0
    switch (mode) {
        case 2: return {1312, 2560};
        case 3: return {1952, 4032};
        case 5: return {2592, 4896};
        default: throw std::invalid_argument("Invalid Dilithium mode: must be 2, 3, or 5");
    }
}

static constexpr size_t DILITHIUM2_SIG_BYTES = 2420; // @api-stable v1.0
static constexpr size_t DILITHIUM3_SIG_BYTES = 3309; // @api-stable v1.0
static constexpr size_t DILITHIUM5_SIG_BYTES = 4627; // @api-stable v1.0

// ── Dilithium keygen ──────────────────────────────────────────────────────────

namespace dilithium {

void keygen(int mode, std::vector<uint8_t>& pk, std::vector<uint8_t>& sk); // @api-stable v1.0

} // namespace dilithium

// ── Dilithium signatures ──────────────────────────────────────────────────────

namespace dilithium_sig {

bool is_pq_sig(const std::string& alg_name);          // @api-stable v1.0
int  mode_from_alg(const std::string& alg_name);      // @api-stable v1.0
size_t sig_bytes_for_mode(int mode);                   // @api-stable v1.0

void sign(int mode,                                    // @api-stable v1.0
          const std::vector<uint8_t>& sk,
          const std::vector<uint8_t>& msg,
          std::vector<uint8_t>& sig_out);

bool verify(int mode,                                  // @api-stable v1.0
            const std::vector<uint8_t>& pk,
            const std::vector<uint8_t>& msg,
            const std::vector<uint8_t>& sig);

} // namespace dilithium_sig

// ── Kyber API (C bindings) ────────────────────────────────────────────────────

extern "C" {

int pqcrystals_kyber512_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber512_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber512_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

int pqcrystals_kyber768_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber768_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber768_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

int pqcrystals_kyber1024_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber1024_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber1024_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

} // extern "C"

struct KyberSizes {                    // @api-stable v1.0
    size_t pk_bytes;
    size_t sk_bytes;
};

struct KyberKEMSizes {                 // @api-stable v1.0
    size_t pk_bytes;
    size_t sk_bytes;
    size_t ct_bytes;
    size_t ss_bytes = 32;
};

inline KyberSizes kyber_sizes(int level) {            // @api-stable v1.0
    switch (level) {
        case 512:  return {800,  1632};
        case 768:  return {1184, 2400};
        case 1024: return {1568, 3168};
        default:   throw std::invalid_argument("Invalid Kyber level: must be 512, 768, or 1024");
    }
}

inline KyberKEMSizes kyber_kem_sizes(int level) {     // @api-stable v1.0
    switch (level) {
        case 512:  return {800,  1632, 768,  32};
        case 768:  return {1184, 2400, 1088, 32};
        case 1024: return {1568, 3168, 1568, 32};
        default:   throw std::invalid_argument("Invalid Kyber level: must be 512, 768, or 1024");
    }
}

// ── Kyber keygen ──────────────────────────────────────────────────────────────

namespace kyber {

void keygen(int level, std::vector<uint8_t>& pk, std::vector<uint8_t>& sk); // @api-stable v1.0

} // namespace kyber

// ── Kyber KEM ─────────────────────────────────────────────────────────────────

namespace kyber_kem {

int  level_from_alg(const std::string& alg_name);    // @api-stable v1.0

void encaps(int level,                                // @api-stable v1.0
            const std::vector<uint8_t>& pk,
            std::vector<uint8_t>& ct_out,
            std::vector<uint8_t>& ss_out);

void decaps(int level,                                // @api-stable v1.0
            const std::vector<uint8_t>& sk,
            const std::vector<uint8_t>& ct,
            std::vector<uint8_t>& ss_out);

} // namespace kyber_kem

// ── KDF (SHAKE256 / KMAC256) ──────────────────────────────────────────────────

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

inline std::array<uint8_t, 32> derive_key_shake(            // @api-stable v1.0
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

inline std::array<uint8_t, 32> derive_key_kmac(              // @api-stable v1.0
    const std::vector<uint8_t>& ss_classical,
    const std::vector<uint8_t>& ss_pq,
    const std::vector<uint8_t>& ct_classical,
    const std::vector<uint8_t>& ct_pq)
{
    static const char* kCustom = "hybrid-kem-file-encryption-v1";
    static const size_t kCustomLen = 30;

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

inline std::array<uint8_t, 32> derive_key_hyke(              // @api-stable v1.0
    const std::vector<uint8_t>& ss_classical,
    const std::vector<uint8_t>& ss_pq,
    const std::vector<uint8_t>& ct_classical,
    const std::vector<uint8_t>& ct_pq,
    const uint8_t salt[32])
{
    static const char* kCustom = "obi-wan-hybrid-sig-v1";
    static const size_t kCustomLen = 21;

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

inline std::vector<uint8_t> compute_hyke_ctx(                // @api-stable v1.0
    const std::vector<uint8_t>& pk_classical,
    const std::vector<uint8_t>& pk_pq)
{
    static const char* kDomain    = "obi-wan-hybrid-sig-v1";
    static const size_t kDomainLen = 21;

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

// ── AES-256-GCM + ChaCha20-Poly1305 AEAD helpers ─────────────────────────────
// All functions output/expect: nonce(12) || tag(16) || ciphertext(N)

static constexpr int AEAD_NONCE_LEN = 12; // @api-stable v1.0
static constexpr int AEAD_TAG_LEN   = 16; // @api-stable v1.0

inline std::vector<uint8_t> aes256gcm_encrypt_aad(           // @api-stable v1.0
    const uint8_t key[32],
    const std::vector<uint8_t>& plaintext,
    const uint8_t* aad, size_t aad_len)
{
    uint8_t nonce[AEAD_NONCE_LEN];
    if (RAND_bytes(nonce, AEAD_NONCE_LEN) != 1)
        throw std::runtime_error("RAND_bytes failed");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AEAD_NONCE_LEN, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-256-GCM encrypt init failed");
    }

    if (aad && aad_len > 0) {
        int aad_out = 0;
        if (EVP_EncryptUpdate(ctx, nullptr, &aad_out, aad, (int)aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AES-256-GCM AAD inject failed");
        }
    }

    std::vector<uint8_t> ct(plaintext.size());
    int len = 0;
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx, ct.data(), &len,
                              plaintext.data(), (int)plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AES-256-GCM EncryptUpdate failed");
        }
    }
    int flen = 0;
    if (EVP_EncryptFinal_ex(ctx, ct.data() + len, &flen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-256-GCM EncryptFinal failed");
    }
    ct.resize((size_t)(len + flen));

    uint8_t tag[AEAD_TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AEAD_TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-256-GCM GET_TAG failed");
    }
    EVP_CIPHER_CTX_free(ctx);

    std::vector<uint8_t> out;
    out.reserve(AEAD_NONCE_LEN + AEAD_TAG_LEN + ct.size());
    out.insert(out.end(), nonce, nonce + AEAD_NONCE_LEN);
    out.insert(out.end(), tag,   tag   + AEAD_TAG_LEN);
    out.insert(out.end(), ct.begin(), ct.end());
    return out;
}

inline std::vector<uint8_t> aes256gcm_decrypt_aad(           // @api-stable v1.0
    const uint8_t key[32],
    const std::vector<uint8_t>& nonce_tag_ct,
    const uint8_t* aad, size_t aad_len)
{
    if (nonce_tag_ct.size() < (size_t)(AEAD_NONCE_LEN + AEAD_TAG_LEN))
        throw std::runtime_error("AES-256-GCM input too short");

    const uint8_t* nonce = nonce_tag_ct.data();
    const uint8_t* tag   = nonce_tag_ct.data() + AEAD_NONCE_LEN;
    const uint8_t* ct    = nonce_tag_ct.data() + AEAD_NONCE_LEN + AEAD_TAG_LEN;
    size_t ct_len        = nonce_tag_ct.size() - AEAD_NONCE_LEN - AEAD_TAG_LEN;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AEAD_NONCE_LEN, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-256-GCM decrypt init failed");
    }

    if (aad && aad_len > 0) {
        int aad_out = 0;
        if (EVP_DecryptUpdate(ctx, nullptr, &aad_out, aad, (int)aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AES-256-GCM AAD inject failed");
        }
    }

    std::vector<uint8_t> pt(ct_len);
    int len = 0;
    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, pt.data(), &len, ct, (int)ct_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AES-256-GCM DecryptUpdate failed");
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AEAD_TAG_LEN,
                             const_cast<uint8_t*>(tag)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-256-GCM SET_TAG failed");
    }

    int flen = 0;
    int rc = EVP_DecryptFinal_ex(ctx, pt.data() + len, &flen);
    EVP_CIPHER_CTX_free(ctx);
    if (rc != 1)
        throw std::runtime_error("AES-256-GCM authentication failed");

    pt.resize((size_t)(len + flen));
    return pt;
}

inline std::vector<uint8_t> aes256gcm_encrypt(               // @api-stable v1.0
    const uint8_t key[32],
    const std::vector<uint8_t>& plaintext)
{
    return aes256gcm_encrypt_aad(key, plaintext, nullptr, 0);
}

inline std::vector<uint8_t> aes256gcm_decrypt(               // @api-stable v1.0
    const uint8_t key[32],
    const std::vector<uint8_t>& nonce_tag_ct)
{
    return aes256gcm_decrypt_aad(key, nonce_tag_ct, nullptr, 0);
}

inline std::vector<uint8_t> chacha20poly1305_encrypt(         // @api-stable v1.0
    const uint8_t key[32],
    const std::vector<uint8_t>& plaintext)
{
    uint8_t nonce[AEAD_NONCE_LEN];
    if (RAND_bytes(nonce, AEAD_NONCE_LEN) != 1)
        throw std::runtime_error("RAND_bytes failed");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, AEAD_NONCE_LEN, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("ChaCha20-Poly1305 encrypt init failed");
    }

    std::vector<uint8_t> ct(plaintext.size());
    int len = 0;
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx, ct.data(), &len,
                              plaintext.data(), (int)plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("ChaCha20-Poly1305 EncryptUpdate failed");
        }
    }
    int flen = 0;
    if (EVP_EncryptFinal_ex(ctx, ct.data() + len, &flen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("ChaCha20-Poly1305 EncryptFinal failed");
    }
    ct.resize((size_t)(len + flen));

    uint8_t tag[AEAD_TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AEAD_TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("ChaCha20-Poly1305 GET_TAG failed");
    }
    EVP_CIPHER_CTX_free(ctx);

    std::vector<uint8_t> out;
    out.reserve(AEAD_NONCE_LEN + AEAD_TAG_LEN + ct.size());
    out.insert(out.end(), nonce, nonce + AEAD_NONCE_LEN);
    out.insert(out.end(), tag,   tag   + AEAD_TAG_LEN);
    out.insert(out.end(), ct.begin(), ct.end());
    return out;
}

inline std::vector<uint8_t> chacha20poly1305_decrypt(         // @api-stable v1.0
    const uint8_t key[32],
    const std::vector<uint8_t>& nonce_tag_ct)
{
    if (nonce_tag_ct.size() < (size_t)(AEAD_NONCE_LEN + AEAD_TAG_LEN))
        throw std::runtime_error("ChaCha20-Poly1305 input too short");

    const uint8_t* nonce = nonce_tag_ct.data();
    const uint8_t* tag   = nonce_tag_ct.data() + AEAD_NONCE_LEN;
    const uint8_t* ct    = nonce_tag_ct.data() + AEAD_NONCE_LEN + AEAD_TAG_LEN;
    size_t ct_len        = nonce_tag_ct.size() - AEAD_NONCE_LEN - AEAD_TAG_LEN;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, AEAD_NONCE_LEN, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("ChaCha20-Poly1305 decrypt init failed");
    }

    std::vector<uint8_t> pt(ct_len);
    int len = 0;
    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, pt.data(), &len, ct, (int)ct_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("ChaCha20-Poly1305 DecryptUpdate failed");
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AEAD_TAG_LEN,
                             const_cast<uint8_t*>(tag)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("ChaCha20-Poly1305 SET_TAG failed");
    }

    int flen = 0;
    int rc = EVP_DecryptFinal_ex(ctx, pt.data() + len, &flen);
    EVP_CIPHER_CTX_free(ctx);
    if (rc != 1)
        throw std::runtime_error("ChaCha20-Poly1305 authentication failed");

    pt.resize((size_t)(len + flen));
    return pt;
}

// ── YAML I/O ──────────────────────────────────────────────────────────────────

std::string emit_tray_yaml(const Tray& tray);               // @api-stable v1.0

// ── Tray reader ───────────────────────────────────────────────────────────────

Tray load_tray(const std::string& path);                    // @api-stable v1.0

// ── Password encrypt / decrypt commands ──────────────────────────────────────

int cmd_pwencrypt(int argc, char* argv[]);                  // @api-stable v1.0
int cmd_pwdecrypt(int argc, char* argv[]);                  // @api-stable v1.0

// ── Token commands ────────────────────────────────────────────────────────────

void cmd_gentok(const std::string& tray_path, const std::string& data_str, int64_t ttl_secs); // @api-stable v1.0
void cmd_valtok(const std::string& tray_path, const std::string& token_file);                 // @api-stable v1.0

// ── BLAKE3 digest ─────────────────────────────────────────────────────────────

namespace blake3 {  // @api-candidate-1.2

// Hash data with plain BLAKE3. Returns a 32-byte digest.
std::array<uint8_t, 32> digest(const std::vector<uint8_t>& data); // @api-candidate-1.2

// Recompute the BLAKE3 digest of data and compare to expected in constant time.
// Returns true if they match.
bool verify(const std::vector<uint8_t>& data,
            const std::array<uint8_t, 32>& expected);             // @api-candidate-1.2

// Hash data with BLAKE3 in keyed mode. key must be exactly 32 bytes.
std::array<uint8_t, 32> keyed_digest(const std::array<uint8_t, 32>& key,
                                     const std::vector<uint8_t>& data); // @api-candidate-1.2

// Recompute the keyed BLAKE3 digest and compare to expected in constant time.
// Returns true if they match.
bool keyed_verify(const std::array<uint8_t, 32>& key,
                  const std::vector<uint8_t>& data,
                  const std::array<uint8_t, 32>& expected);       // @api-candidate-1.2

} // namespace blake3
