#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include <array>

// Wire format (binary, before base64 armoring):
//   Magic:          8 bytes  "ZORRO001"
//   KDF:            1 byte   0=SHAKE256, 1=KMAC256
//   Cipher:         1 byte   0=AES-256-GCM, 1=ChaCha20-Poly1305
//   CT_classic_len: 4 bytes  big-endian uint32
//   CT_classical:   <CT_classic_len> bytes
//   CT_pq_len:      4 bytes  big-endian uint32
//   CT_pq:          <CT_pq_len> bytes
//   Payload:        nonce(12) || tag(16) || ciphertext

enum class KDFAlg   : uint8_t { SHAKE256 = 0, KMAC256 = 1 };
enum class CipherAlg: uint8_t { AES256GCM = 0, ChaCha20Poly1305 = 1 };

static constexpr char kArmorBegin[] = "-----BEGIN ZORRO ENCRYPTED FILE-----";
static constexpr char kArmorEnd[]   = "-----END ZORRO ENCRYPTED FILE-----";

struct WireHeader {
    KDFAlg    kdf;
    CipherAlg cipher;
    std::vector<uint8_t> ct_classical;
    std::vector<uint8_t> ct_pq;
};

// Pack header + payload into wire bytes, then base64-armor them.
std::string armor_pack(const WireHeader& hdr,
                        const std::vector<uint8_t>& payload);

// Dearmor base64 and unpack wire header + payload.
// Throws on malformed input.
WireHeader armor_unpack(const std::string& armored,
                        std::vector<uint8_t>& payload_out);
