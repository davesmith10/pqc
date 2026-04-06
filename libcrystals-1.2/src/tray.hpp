#pragma once
#include <string>
#include <vector>
#include <cstdint>

enum class TrayType {
    // crystals group
    Level0, Level1, Level2_25519, Level2, Level3, Level5,
    // mceliece+slhdsa group
    McEliece_Level1, McEliece_Level2, McEliece_Level3, McEliece_Level4, McEliece_Level5,
    // mlkem+mldsa group (ML-KEM + ML-DSA) @api-candidate-1.2
    MlKem_Level1, MlKem_Level2, MlKem_Level3, MlKem_Level4,
    // frodokem+falcon group               @api-candidate-1.2
    FrodoFalcon_Level1, FrodoFalcon_Level2, FrodoFalcon_Level3, FrodoFalcon_Level4
};

struct Slot {
    std::string alg_name;       // e.g. "X25519", "Kyber768", "ECDSA P-384", "Dilithium3"
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;    // empty if public-only tray
};

struct Tray {
    int version = 1;
    std::string alias;
    TrayType tray_type;
    std::string profile_group;  // one of the defined groups above
    std::string type_str;       // must be "tray", overridden in SecureTray to "secure-tray"
    std::string id;             // UUID v8
    bool is_public = false;
    std::vector<Slot> slots;
    std::string created;        // ISO 8601 UTC
    std::string expires;        // ISO 8601 UTC (by default, created + 2 years)
};

// Generate a full tray with keyed material.
Tray make_tray(TrayType t, const std::string& alias);

// Current UTC time as ISO 8601 string (e.g. "2026-04-06T12:00:00Z").
std::string iso8601_now();

// Pure hybrid digital signature document.
struct Signature {
    int version = 1;
    std::string id;            // signature UUID
    std::string created;       // ISO 8601 UTC
    std::string tray_id;
    std::string tray_alias;
    std::string profile_group;
    std::string profile;       // e.g. "level2-25519"
    std::string input;         // path to signed file
    std::vector<uint8_t> composite; // raw composite signature bytes
};

// Copy src, clear all sk fields, assign a fresh UUID, append ".pub" to alias.
Tray make_public_tray(const Tray& src);

// Returns true if tray.id matches the UUID derived from its public keys.
bool validate_tray_uuid(const Tray& tray);
