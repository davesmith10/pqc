#include "armor.hpp"
#include "base64.hpp"
#include <stdexcept>
#include <cstring>
#include <sstream>

static void push_u32be(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back((v >> 24) & 0xFF);
    buf.push_back((v >> 16) & 0xFF);
    buf.push_back((v >>  8) & 0xFF);
    buf.push_back((v >>  0) & 0xFF);
}

static uint32_t read_u32be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) | ((uint32_t)p[3]);
}

std::string armor_pack(const WireHeader& hdr,
                        const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> wire;
    wire.reserve(10 + 8 + hdr.ct_classical.size() + hdr.ct_pq.size() + payload.size());

    // Magic
    const char* magic = "ZORRO001";
    wire.insert(wire.end(), magic, magic + 8);

    // KDF + Cipher
    wire.push_back((uint8_t)hdr.kdf);
    wire.push_back((uint8_t)hdr.cipher);

    // CT_classical
    push_u32be(wire, (uint32_t)hdr.ct_classical.size());
    wire.insert(wire.end(), hdr.ct_classical.begin(), hdr.ct_classical.end());

    // CT_pq
    push_u32be(wire, (uint32_t)hdr.ct_pq.size());
    wire.insert(wire.end(), hdr.ct_pq.begin(), hdr.ct_pq.end());

    // Payload (nonce || tag || ciphertext)
    wire.insert(wire.end(), payload.begin(), payload.end());

    // Base64 encode at 64 chars/line
    std::string b64 = base64_encode(wire.data(), wire.size());

    std::string out;
    out.reserve(sizeof(kArmorBegin) + b64.size() + b64.size() / 64 + sizeof(kArmorEnd) + 4);
    out += kArmorBegin;
    out += '\n';

    for (size_t i = 0; i < b64.size(); i += 64) {
        out += b64.substr(i, 64);
        out += '\n';
    }

    out += kArmorEnd;
    out += '\n';
    return out;
}

WireHeader armor_unpack(const std::string& armored,
                         std::vector<uint8_t>& payload_out)
{
    // Strip armor headers and collect base64 lines
    std::string b64;
    std::istringstream ss(armored);
    std::string line;
    bool in_body = false;
    while (std::getline(ss, line)) {
        // Trim CR
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line == kArmorBegin) {
            in_body = true;
            continue;
        }
        if (line == kArmorEnd) {
            in_body = false;
            continue;
        }
        if (in_body)
            b64 += line;
    }

    if (b64.empty())
        throw std::runtime_error("armor_unpack: no base64 data found");

    std::vector<uint8_t> wire = base64_decode(b64);

    const size_t min_hdr = 8 + 1 + 1 + 4 + 4; // magic+kdf+cipher+len+len
    if (wire.size() < min_hdr)
        throw std::runtime_error("armor_unpack: wire data too short");

    const uint8_t* p = wire.data();

    // Check magic
    if (std::memcmp(p, "ZORRO001", 8) != 0)
        throw std::runtime_error("armor_unpack: invalid magic");
    p += 8;

    WireHeader hdr;
    hdr.kdf    = (KDFAlg)*p++;
    hdr.cipher = (CipherAlg)*p++;

    const uint8_t* end = wire.data() + wire.size();

    // CT_classical
    if (p + 4 > end) throw std::runtime_error("armor_unpack: truncated ct_classical len");
    uint32_t ct_cl_len = read_u32be(p); p += 4;
    if (p + ct_cl_len > end) throw std::runtime_error("armor_unpack: truncated ct_classical");
    hdr.ct_classical.assign(p, p + ct_cl_len); p += ct_cl_len;

    // CT_pq
    if (p + 4 > end) throw std::runtime_error("armor_unpack: truncated ct_pq len");
    uint32_t ct_pq_len = read_u32be(p); p += 4;
    if (p + ct_pq_len > end) throw std::runtime_error("armor_unpack: truncated ct_pq");
    hdr.ct_pq.assign(p, p + ct_pq_len); p += ct_pq_len;

    // Remaining = payload
    payload_out.assign(p, end);

    return hdr;
}
