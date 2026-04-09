#include "tray_reader.hpp"
#include "base64.hpp"
#include "blake3.h"
#include <yaml-cpp/yaml.h>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <string>

// ── YAML parser ───────────────────────────────────────────────────────────────

static std::vector<uint8_t> decode_b64_yaml(const YAML::Node& node) {
    std::string raw = node.as<std::string>();
    // Strip embedded newlines (literal block scalars have them)
    std::string clean;
    clean.reserve(raw.size());
    for (char c : raw) {
        if (c != '\n' && c != '\r' && c != ' ')
            clean += c;
    }
    return base64_decode(clean);
}

static Tray load_tray_yaml(const std::string& path) {
    YAML::Node doc = YAML::LoadFile(path);

    Tray tray;
    tray.version = doc["version"].as<int>(1);
    tray.alias   = doc["alias"].as<std::string>();

    // Validate document type discriminator
    std::string doc_type = doc["type"].as<std::string>("");
    if (doc_type != "tray")
        throw std::runtime_error("YAML tray: 'type' field must be 'tray' (got '" + doc_type + "')");

    tray.profile_group = doc["profile-group"].as<std::string>("");
    tray.type_str      = doc["profile"].as<std::string>();
    tray.id            = doc["id"].as<std::string>();
    tray.created       = doc["created"].as<std::string>("");
    tray.expires       = doc["expires"].as<std::string>("");

    tray.tray_type = tray_type_from_str(tray.type_str);

    YAML::Node tray_seq = doc["slots"];
    if (!tray_seq || !tray_seq.IsSequence())
        throw std::runtime_error("YAML tray: missing 'slots' sequence");

    for (const auto& slot_node : tray_seq) {
        Slot s;
        s.alg_name = slot_node["alg"].as<std::string>();
        s.pk = decode_b64_yaml(slot_node["pk"]);
        if (slot_node["sk"])
            s.sk = decode_b64_yaml(slot_node["sk"]);
        tray.slots.push_back(std::move(s));
    }

    return tray;
}

// ── UUID self-verification ────────────────────────────────────────────────────
// Recomputes the tray UUID from public key material using the same BLAKE3
// key-derivation algorithm as scotty.  Rejects trays whose stored UUID does
// not match the derived value, detecting accidental corruption or key substitution.

static std::string derive_uuid(const std::vector<Slot>& slots) {
    blake3_hasher h;
    blake3_hasher_init_derive_key(&h, "Crystals scotty tray-uuid v1");

    for (const auto& slot : slots) {
        uint32_t name_len = static_cast<uint32_t>(slot.alg_name.size());
        uint8_t  name_len_le[4] = {
            static_cast<uint8_t>( name_len        & 0xFF),
            static_cast<uint8_t>((name_len >>  8) & 0xFF),
            static_cast<uint8_t>((name_len >> 16) & 0xFF),
            static_cast<uint8_t>((name_len >> 24) & 0xFF),
        };
        blake3_hasher_update(&h, name_len_le, 4);
        blake3_hasher_update(&h, slot.alg_name.data(), slot.alg_name.size());

        uint32_t pk_len = static_cast<uint32_t>(slot.pk.size());
        uint8_t  pk_len_le[4] = {
            static_cast<uint8_t>( pk_len        & 0xFF),
            static_cast<uint8_t>((pk_len >>  8) & 0xFF),
            static_cast<uint8_t>((pk_len >> 16) & 0xFF),
            static_cast<uint8_t>((pk_len >> 24) & 0xFF),
        };
        blake3_hasher_update(&h, pk_len_le, 4);
        blake3_hasher_update(&h, slot.pk.data(), slot.pk.size());
    }

    uint8_t out[16];
    blake3_hasher_finalize(&h, out, 16);

    // UUID v8 bit-twiddling (RFC 9562)
    out[6] = (out[6] & 0x0F) | 0x80;  // version nibble = 8
    out[8] = (out[8] & 0x3F) | 0x80;  // variant = 10xxxxxx

    char buf[37];
    std::snprintf(buf, sizeof(buf),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        out[0],  out[1],  out[2],  out[3],
        out[4],  out[5],
        out[6],  out[7],
        out[8],  out[9],
        out[10], out[11], out[12], out[13], out[14], out[15]);
    return std::string(buf);
}

static void verify_tray_uuid(const Tray& tray) {
    // Skip check for pre-v8 trays (UUID v4 or other formats)
    if (tray.id.size() < 15 || tray.id[14] != '8')
        return;
    std::string derived = derive_uuid(tray.slots);
    if (derived != tray.id)
        throw std::runtime_error(
            "tray UUID mismatch: stored " + tray.id +
            " but derived " + derived + " from public keys");
}

// ── Entry point ───────────────────────────────────────────────────────────────

Tray load_tray(const std::string& path) {
    Tray tray = load_tray_yaml(path);
    verify_tray_uuid(tray);
    return tray;
}
