// api_stability_test-1.2.cpp — compile-time enforcement of the v1.2 public API.
//
// IMPORTANT: This file MUST compile cleanly.
// DO NOT modify it when adding features — only ADD to it.
// A compile failure here means a breaking API change was introduced.
//
// Only includes crystals/crystals.hpp — no internal headers.

#include "crystals/crystals.hpp"
#include <type_traits>
#include <cassert>

// ── TrayType enumerators added in API 1.2 ────────────────────────────────────
static_assert(std::is_same_v<decltype(TrayType::MlKem_Level1),    TrayType>);
static_assert(std::is_same_v<decltype(TrayType::MlKem_Level2),    TrayType>);
static_assert(std::is_same_v<decltype(TrayType::MlKem_Level3),    TrayType>);
static_assert(std::is_same_v<decltype(TrayType::MlKem_Level4),    TrayType>);
static_assert(std::is_same_v<decltype(TrayType::FrodoFalcon_Level1), TrayType>);
static_assert(std::is_same_v<decltype(TrayType::FrodoFalcon_Level2), TrayType>);
static_assert(std::is_same_v<decltype(TrayType::FrodoFalcon_Level3), TrayType>);
static_assert(std::is_same_v<decltype(TrayType::FrodoFalcon_Level4), TrayType>);

// ── oqs_kem::Keys struct ─────────────────────────────────────────────────────
static_assert(std::is_same_v<decltype(oqs_kem::Keys::pk), std::vector<uint8_t>>);
static_assert(std::is_same_v<decltype(oqs_kem::Keys::sk), std::vector<uint8_t>>);

// ── oqs_kem function signatures ──────────────────────────────────────────────
static_assert(std::is_same_v<
    decltype(&oqs_kem::keygen),
    oqs_kem::Keys (*)(const std::string&)>);

static_assert(std::is_same_v<
    decltype(&oqs_kem::encaps),
    void (*)(const std::string&, const std::vector<uint8_t>&,
             std::vector<uint8_t>&, std::vector<uint8_t>&)>);

static_assert(std::is_same_v<
    decltype(&oqs_kem::decaps),
    void (*)(const std::string&, const std::vector<uint8_t>&,
             const std::vector<uint8_t>&, std::vector<uint8_t>&)>);

// ── oqs_sig::Keys struct ─────────────────────────────────────────────────────
static_assert(std::is_same_v<decltype(oqs_sig::Keys::pk), std::vector<uint8_t>>);
static_assert(std::is_same_v<decltype(oqs_sig::Keys::sk), std::vector<uint8_t>>);

// ── oqs_sig function signatures ──────────────────────────────────────────────
static_assert(std::is_same_v<
    decltype(&oqs_sig::keygen),
    oqs_sig::Keys (*)(const std::string&)>);

static_assert(std::is_same_v<
    decltype(&oqs_sig::is_oqs_sig),
    bool (*)(const std::string&)>);

static_assert(std::is_same_v<
    decltype(&oqs_sig::sig_bytes),
    size_t (*)(const std::string&)>);

static_assert(std::is_same_v<
    decltype(&oqs_sig::sign),
    void (*)(const std::string&, const std::vector<uint8_t>&,
             const std::vector<uint8_t>&, std::vector<uint8_t>&)>);

static_assert(std::is_same_v<
    decltype(&oqs_sig::verify),
    bool (*)(const std::string&, const std::vector<uint8_t>&,
             const std::vector<uint8_t>&, const std::vector<uint8_t>&)>);

// ── blake3 namespace (@api-candidate-1.2 — promote to @api-stable before v1.2 release) ──
// Enforcing signatures here ensures candidate changes are deliberate, not accidental.
static_assert(std::is_same_v<
    decltype(&blake3::digest),
    std::array<uint8_t, 32> (*)(const std::vector<uint8_t>&)>);

static_assert(std::is_same_v<
    decltype(&blake3::verify),
    bool (*)(const std::vector<uint8_t>&,
             const std::array<uint8_t, 32>&)>);

static_assert(std::is_same_v<
    decltype(&blake3::keyed_digest),
    std::array<uint8_t, 32> (*)(const std::array<uint8_t, 32>&,
                                 const std::vector<uint8_t>&)>);

static_assert(std::is_same_v<
    decltype(&blake3::keyed_verify),
    bool (*)(const std::array<uint8_t, 32>&,
             const std::vector<uint8_t>&,
             const std::array<uint8_t, 32>&)>);

// ── McEliece TrayType enumerators (@api-stable v1.1, verified in v1.2 for completeness) ──
static_assert(std::is_same_v<decltype(TrayType::McEliece_Level1), TrayType>);
static_assert(std::is_same_v<decltype(TrayType::McEliece_Level2), TrayType>);
static_assert(std::is_same_v<decltype(TrayType::McEliece_Level3), TrayType>);
static_assert(std::is_same_v<decltype(TrayType::McEliece_Level4), TrayType>);
static_assert(std::is_same_v<decltype(TrayType::McEliece_Level5), TrayType>);

// ── is_tray_complete (@api-stable v1.2) ──────────────────────────────────────
static_assert(std::is_same_v<
    decltype(&is_tray_complete),
    bool (*)(TrayType)>);

int main() {
    // McEliece tray ID byte round-trips (from Task 1)
    assert(tray_id_byte(TrayType::McEliece_Level1) == 0x31);
    assert(tray_id_byte(TrayType::McEliece_Level2) == 0x32);
    assert(tray_id_byte(TrayType::McEliece_Level3) == 0x33);
    assert(tray_id_byte(TrayType::McEliece_Level4) == 0x34);
    assert(tray_id_byte(TrayType::McEliece_Level5) == 0x35);
    assert(tray_type_from_id(0x31) == TrayType::McEliece_Level1);
    assert(tray_type_from_id(0x32) == TrayType::McEliece_Level2);
    assert(tray_type_from_id(0x33) == TrayType::McEliece_Level3);
    assert(tray_type_from_id(0x34) == TrayType::McEliece_Level4);
    assert(tray_type_from_id(0x35) == TrayType::McEliece_Level5);

    // is_tray_complete: partial trays return false
    assert(!is_tray_complete(TrayType::Level0));
    assert(!is_tray_complete(TrayType::Level1));
    assert(!is_tray_complete(TrayType::McEliece_Level1));

    // is_tray_complete: full trays return true
    assert(is_tray_complete(TrayType::Level2_25519));
    assert(is_tray_complete(TrayType::Level2));
    assert(is_tray_complete(TrayType::Level3));
    assert(is_tray_complete(TrayType::Level5));
    assert(is_tray_complete(TrayType::McEliece_Level2));
    assert(is_tray_complete(TrayType::McEliece_Level3));
    assert(is_tray_complete(TrayType::McEliece_Level4));
    assert(is_tray_complete(TrayType::McEliece_Level5));
    assert(is_tray_complete(TrayType::MlKem_Level2));
    assert(is_tray_complete(TrayType::FrodoFalcon_Level2));
    return 0;
}
