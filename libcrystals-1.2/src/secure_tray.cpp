#include "secure_tray.hpp"
#include "base64.hpp"
#include "symmetric.hpp"

#include <yaml-cpp/yaml.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <string>
#include <vector>
#include <cstring>
#include <cmath>
#include <stdexcept>

extern "C" {
#include "scrypt-kdf.h"
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Strip newlines from a base64 string (YAML literal block scalars embed \n)
static std::string strip_newlines(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s)
        if (c != '\n' && c != '\r') out += c;
    return out;
}

static std::vector<uint8_t> b64dec(const std::string& s) {
    return base64_decode(strip_newlines(s));
}

// ── scrypt KDF ────────────────────────────────────────────────────────────────

static void run_scrypt(const char* passwd, size_t passwd_len,
                       const uint8_t* salt, size_t salt_len,
                       int n_log2, int r, int p,
                       uint8_t* out, size_t out_len)
{
    uint64_t N = (uint64_t)1 << n_log2;
    if (scrypt_kdf((const uint8_t*)passwd, passwd_len,
                   salt, salt_len,
                   N, (uint32_t)r, (uint32_t)p,
                   out, out_len) != 0)
        throw std::runtime_error("scrypt KDF failed");
}

// ── YAML base64 emit helpers ──────────────────────────────────────────────────

static std::string b64_for_yaml(const std::vector<uint8_t>& data) {
    std::string b64 = base64_encode(data.data(), data.size());
    if (b64.size() <= 64)
        return b64;

    std::string out;
    out.reserve(b64.size() + b64.size() / 64);
    for (size_t i = 0; i < b64.size(); i += 64) {
        if (i > 0) out += '\n';
        out += b64.substr(i, 64);
    }
    return out;  // no trailing '\n' → yaml-cpp picks '|-'
}

static void emit_b64_key(YAML::Emitter& out, const char* key,
                         const std::vector<uint8_t>& data)
{
    std::string val = b64_for_yaml(data);
    out << YAML::Key << key << YAML::Value;
    if (val.find('\n') != std::string::npos)
        out << YAML::Literal;
    out << val;
}

// ── YAML I/O ──────────────────────────────────────────────────────────────────

Tray load_tray_yaml(const std::string& path) {
    YAML::Node node;
    try {
        node = YAML::LoadFile(path);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("YAML parse error: ") + e.what());
    }

    if (node["type"] && node["type"].as<std::string>() == "secure-tray")
        throw std::runtime_error("input is already a secure-tray");

    Tray tray;
    tray.version       = node["version"]       ? node["version"].as<int>() : 1;
    tray.alias         = node["alias"]         ? node["alias"].as<std::string>() : "";
    tray.profile_group = node["profile-group"] ? node["profile-group"].as<std::string>() : "";
    tray.type_str      = node["profile"]       ? node["profile"].as<std::string>() : "";
    tray.id            = node["id"]            ? node["id"].as<std::string>() : "";
    tray.created       = node["created"]       ? node["created"].as<std::string>() : "";
    tray.expires       = node["expires"]       ? node["expires"].as<std::string>() : "";

    tray.tray_type = tray_type_from_str(tray.type_str);

    if (node["slots"]) {
        for (const auto& s : node["slots"]) {
            Slot slot;
            slot.alg_name = s["alg"] ? s["alg"].as<std::string>() : "";
            if (s["pk"]) slot.pk = b64dec(s["pk"].as<std::string>());
            if (s["sk"] && s["sk"].as<std::string>().size() > 0)
                slot.sk = b64dec(s["sk"].as<std::string>());
            tray.slots.push_back(std::move(slot));
        }
    }

    return tray;
}

SecureTray load_secure_tray_yaml(const std::string& path) {
    YAML::Node node;
    try {
        node = YAML::LoadFile(path);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("YAML parse error: ") + e.what());
    }

    if (!node["type"] || node["type"].as<std::string>() != "secure-tray")
        throw std::runtime_error("input is not a secure-tray");

    SecureTray st;
    st.version       = node["version"]       ? node["version"].as<int>() : 1;
    st.alias         = node["alias"]         ? node["alias"].as<std::string>() : "";
    st.profile_group = node["profile-group"] ? node["profile-group"].as<std::string>() : "";
    st.type_str      = node["profile"]       ? node["profile"].as<std::string>() : "";
    st.id            = node["id"]            ? node["id"].as<std::string>() : "";
    st.created       = node["created"]       ? node["created"].as<std::string>() : "";
    st.expires       = node["expires"]       ? node["expires"].as<std::string>() : "";

    // Parse enc block
    if (node["enc"]) {
        auto enc = node["enc"];
        if (enc["scrypt"]) {
            auto sc = enc["scrypt"];
            if (sc["salt"])   st.enc.scrypt.salt   = b64dec(sc["salt"].as<std::string>());
            if (sc["n_log2"]) st.enc.scrypt.n_log2 = sc["n_log2"].as<int>();
            if (sc["r"])      st.enc.scrypt.r       = sc["r"].as<int>();
            if (sc["p"])      st.enc.scrypt.p       = sc["p"].as<int>();
        }
        if (enc["kem"]) {
            auto km = enc["kem"];
            if (km["nonce"]) st.enc.kem.nonce = b64dec(km["nonce"].as<std::string>());
            if (km["tag"])   st.enc.kem.tag   = b64dec(km["tag"].as<std::string>());
            if (km["ct"])    st.enc.kem.ct    = b64dec(km["ct"].as<std::string>());
        }
    }

    if (node["slots"]) {
        for (const auto& s : node["slots"]) {
            Slot slot;
            slot.alg_name = s["alg"] ? s["alg"].as<std::string>() : "";
            if (s["pk"]) slot.pk = b64dec(s["pk"].as<std::string>());
            if (s["sk"] && s["sk"].as<std::string>().size() > 0)
                slot.sk = b64dec(s["sk"].as<std::string>());
            st.slots.push_back(std::move(slot));
        }
    }

    return st;
}

std::string emit_secure_tray_yaml(const SecureTray& st) {
    YAML::Emitter out;

    out << YAML::BeginDoc;
    out << YAML::BeginMap;

    out << YAML::Key << "version"       << YAML::Value << st.version;
    out << YAML::Key << "alias"         << YAML::Value << st.alias;
    out << YAML::Key << "profile-group" << YAML::Value << st.profile_group;
    out << YAML::Key << "profile"       << YAML::Value << st.type_str;
    out << YAML::Key << "type"          << YAML::Value << "secure-tray";
    out << YAML::Key << "id"            << YAML::Value << st.id;

    // enc block
    out << YAML::Key << "enc" << YAML::Value;
    out << YAML::BeginMap;

    out << YAML::Key << "scrypt" << YAML::Value;
    out << YAML::BeginMap;
    emit_b64_key(out, "salt", st.enc.scrypt.salt);
    out << YAML::Key << "n_log2" << YAML::Value << st.enc.scrypt.n_log2;
    out << YAML::Key << "r"      << YAML::Value << st.enc.scrypt.r;
    out << YAML::Key << "p"      << YAML::Value << st.enc.scrypt.p;
    out << YAML::EndMap;

    out << YAML::Key << "kem" << YAML::Value;
    out << YAML::BeginMap;
    emit_b64_key(out, "nonce", st.enc.kem.nonce);
    emit_b64_key(out, "tag",   st.enc.kem.tag);
    emit_b64_key(out, "ct",    st.enc.kem.ct);
    out << YAML::EndMap;

    out << YAML::EndMap;  // end enc

    // slots
    out << YAML::Key << "slots" << YAML::Value;
    out << YAML::BeginSeq;
    for (size_t i = 0; i < st.slots.size(); ++i) {
        const auto& slot = st.slots[i];
        out << YAML::BeginMap;
        out << YAML::Key << "slot" << YAML::Value << (int)i;
        out << YAML::Key << "alg"  << YAML::Value << slot.alg_name;
        emit_b64_key(out, "pk", slot.pk);
        if (!slot.sk.empty())
            emit_b64_key(out, "sk", slot.sk);
        out << YAML::EndMap;
    }
    out << YAML::EndSeq;

    out << YAML::Key << "created" << YAML::Value << st.created;
    out << YAML::Key << "expires" << YAML::Value << st.expires;

    out << YAML::EndMap;
    out << YAML::EndDoc;

    return std::string(out.c_str()) + "\n";
}

// ── protect_tray ──────────────────────────────────────────────────────────────

SecureTray protect_tray(const Tray& tray, const char* passwd, size_t passwd_len) {
    if (!validate_tray_uuid(tray))
        throw std::runtime_error("UUID mismatch: tray may be corrupted or tampered");

    // Generate random salt and data_key
    uint8_t salt[16];
    uint8_t data_key[32];
    if (RAND_bytes(salt, sizeof(salt)) != 1)
        throw std::runtime_error("RAND_bytes failed");
    if (RAND_bytes(data_key, sizeof(data_key)) != 1)
        throw std::runtime_error("RAND_bytes failed");

    // Derive wrap_key via scrypt
    uint8_t wrap_key[32];
    run_scrypt(passwd, passwd_len, salt, sizeof(salt), 19, 8, 1, wrap_key, sizeof(wrap_key));

    // Encrypt data_key with wrap_key → 60-byte blob (nonce[12]||tag[16]||ct[32])
    std::vector<uint8_t> dk_vec(data_key, data_key + 32);
    auto kem_blob = aes256gcm_encrypt_aad(wrap_key, dk_vec, nullptr, 0);

    // Build SecureTray
    SecureTray st;
    static_cast<Tray&>(st) = tray;

    st.enc.scrypt.salt   = std::vector<uint8_t>(salt, salt + 16);
    st.enc.scrypt.n_log2 = 19;
    st.enc.scrypt.r      = 8;
    st.enc.scrypt.p      = 1;

    // Split kem_blob: nonce[0:12], tag[12:28], ct[28:60]
    st.enc.kem.nonce = std::vector<uint8_t>(kem_blob.begin(),      kem_blob.begin() + 12);
    st.enc.kem.tag   = std::vector<uint8_t>(kem_blob.begin() + 12, kem_blob.begin() + 28);
    st.enc.kem.ct    = std::vector<uint8_t>(kem_blob.begin() + 28, kem_blob.end());

    // Encrypt each slot's sk with data_key
    for (size_t i = 0; i < tray.slots.size(); ++i) {
        const auto& slot = tray.slots[i];
        if (slot.sk.empty()) continue;

        std::string aad_str = tray.id + ":" + std::to_string(i) + ":" + slot.alg_name;
        auto blob = aes256gcm_encrypt_aad(data_key,
                                          slot.sk,
                                          (const uint8_t*)aad_str.data(),
                                          aad_str.size());
        st.slots[i].sk = std::move(blob);
    }

    OPENSSL_cleanse(data_key, sizeof(data_key));
    OPENSSL_cleanse(wrap_key, sizeof(wrap_key));
    OPENSSL_cleanse(dk_vec.data(), dk_vec.size());

    return st;
}

// ── unprotect_tray ────────────────────────────────────────────────────────────

Tray unprotect_tray(const SecureTray& st, const char* passwd, size_t passwd_len) {
    if (!validate_tray_uuid(st))
        throw std::runtime_error("UUID mismatch: tray may be corrupted or tampered");

    // Derive wrap_key via scrypt
    uint8_t wrap_key[32];
    run_scrypt(passwd, passwd_len,
               st.enc.scrypt.salt.data(), st.enc.scrypt.salt.size(),
               st.enc.scrypt.n_log2, st.enc.scrypt.r, st.enc.scrypt.p,
               wrap_key, sizeof(wrap_key));

    // Reassemble kem blob: nonce || tag || ct
    std::vector<uint8_t> kem_blob;
    kem_blob.reserve(st.enc.kem.nonce.size() + st.enc.kem.tag.size() + st.enc.kem.ct.size());
    kem_blob.insert(kem_blob.end(), st.enc.kem.nonce.begin(), st.enc.kem.nonce.end());
    kem_blob.insert(kem_blob.end(), st.enc.kem.tag.begin(),   st.enc.kem.tag.end());
    kem_blob.insert(kem_blob.end(), st.enc.kem.ct.begin(),    st.enc.kem.ct.end());

    // Decrypt data_key
    std::vector<uint8_t> dk_vec;
    try {
        dk_vec = aes256gcm_decrypt_aad(wrap_key, kem_blob, nullptr, 0);
    } catch (...) {
        OPENSSL_cleanse(wrap_key, sizeof(wrap_key));
        throw std::runtime_error("wrong password or corrupted key envelope");
    }
    OPENSSL_cleanse(wrap_key, sizeof(wrap_key));

    if (dk_vec.size() != 32)
        throw std::runtime_error("unexpected data_key size");

    uint8_t data_key[32];
    std::memcpy(data_key, dk_vec.data(), 32);
    OPENSSL_cleanse(dk_vec.data(), dk_vec.size());

    // Decrypt each slot
    Tray result = static_cast<const Tray&>(st);
    for (size_t i = 0; i < st.slots.size(); ++i) {
        const auto& slot = st.slots[i];
        if (slot.sk.empty()) continue;

        std::string aad_str = st.id + ":" + std::to_string(i) + ":" + slot.alg_name;
        try {
            result.slots[i].sk = aes256gcm_decrypt_aad(data_key,
                                                         slot.sk,
                                                         (const uint8_t*)aad_str.data(),
                                                         aad_str.size());
        } catch (...) {
            OPENSSL_cleanse(data_key, sizeof(data_key));
            throw std::runtime_error("wrong password or corrupted slot " +
                                     std::to_string(i) + " (" + slot.alg_name + ")");
        }
    }

    OPENSSL_cleanse(data_key, sizeof(data_key));
    return result;
}
