#include "yaml_io.hpp"
#include "base64.hpp"
#include <yaml-cpp/yaml.h>
#include <string>

// ── Base64 helpers ────────────────────────────────────────────────────────────

// Returns base64 wrapped at 64 chars. If it fits on one line, returns a plain
// string (no newlines). If multi-line, lines are joined with '\n' and there is
// NO trailing newline — this makes yaml-cpp emit '|-' (strip), avoiding the
// blank line that '|' (clip) would produce between keys.
static std::string b64_for_yaml(const std::vector<uint8_t>& data) {
    std::string b64 = base64_encode(data.data(), data.size());
    if (b64.size() <= 64)
        return b64;  // single line — plain scalar

    std::string out;
    out.reserve(b64.size() + b64.size() / 64);
    for (size_t i = 0; i < b64.size(); i += 64) {
        if (i > 0) out += '\n';
        out += b64.substr(i, 64);
    }
    return out;  // no trailing '\n' → yaml-cpp picks '|-'
}

// Emit a key/value where value is base64. Uses literal block only if multi-line.
static void emit_b64_key(YAML::Emitter& out, const char* key,
                         const std::vector<uint8_t>& data)
{
    std::string val = b64_for_yaml(data);
    out << YAML::Key << key << YAML::Value;
    if (val.find('\n') != std::string::npos)
        out << YAML::Literal;
    out << val;
}

// ── YAML emission ─────────────────────────────────────────────────────────────

std::string emit_tray_yaml(const Tray& tray) {
    YAML::Emitter out;

    out << YAML::BeginDoc;
    out << YAML::BeginMap;

    out << YAML::Key << "version"       << YAML::Value << tray.version;
    out << YAML::Key << "alias"         << YAML::Value << tray.alias;
    out << YAML::Key << "profile-group" << YAML::Value << tray.profile_group;
    out << YAML::Key << "profile"       << YAML::Value << tray.type_str;
    out << YAML::Key << "type"          << YAML::Value << "tray";
    out << YAML::Key << "id"            << YAML::Value << tray.id;

    out << YAML::Key << "slots" << YAML::Value;
    out << YAML::BeginSeq;

    for (size_t i = 0; i < tray.slots.size(); ++i) {
        const auto& slot = tray.slots[i];
        out << YAML::BeginMap;
        out << YAML::Key << "slot" << YAML::Value << (int)i;
        out << YAML::Key << "alg"  << YAML::Value << slot.alg_name;
        emit_b64_key(out, "pk", slot.pk);
        if (!slot.sk.empty())
            emit_b64_key(out, "sk", slot.sk);
        out << YAML::EndMap;
    }

    out << YAML::EndSeq;

    out << YAML::Key << "created" << YAML::Value << tray.created;
    out << YAML::Key << "expires" << YAML::Value << tray.expires;

    out << YAML::EndMap;
    out << YAML::EndDoc;

    return std::string(out.c_str()) + "\n";
}

// ── Signature YAML ────────────────────────────────────────────────────────────

std::string emit_signature_yaml(const Signature& sig) {
    YAML::Emitter out;

    out << YAML::BeginDoc;
    out << YAML::BeginMap;

    out << YAML::Key << "version"       << YAML::Value << sig.version;
    out << YAML::Key << "id"            << YAML::Value << sig.id;
    out << YAML::Key << "created"       << YAML::Value << sig.created;
    out << YAML::Key << "tray-id"       << YAML::Value << sig.tray_id;
    out << YAML::Key << "tray-alias"    << YAML::Value << sig.tray_alias;
    out << YAML::Key << "profile-group" << YAML::Value << sig.profile_group;
    out << YAML::Key << "profile"       << YAML::Value << sig.profile;
    out << YAML::Key << "input"         << YAML::Value << sig.input;

    out << YAML::Key << "composite-sig" << YAML::Value;
    {
        std::string val = b64_for_yaml(sig.composite);
        if (val.find('\n') != std::string::npos)
            out << YAML::Literal;
        out << val;
    }

    out << YAML::EndMap;
    out << YAML::EndDoc;

    return std::string(out.c_str()) + "\n";
}

Signature parse_sig_yaml(const std::string& text) {
    YAML::Node doc = YAML::Load(text);
    Signature sig;
    if (doc["version"])       sig.version       = doc["version"].as<int>();
    if (doc["id"])            sig.id            = doc["id"].as<std::string>();
    if (doc["created"])       sig.created       = doc["created"].as<std::string>();
    if (doc["tray-id"])       sig.tray_id       = doc["tray-id"].as<std::string>();
    if (doc["tray-alias"])    sig.tray_alias    = doc["tray-alias"].as<std::string>();
    if (doc["profile-group"]) sig.profile_group = doc["profile-group"].as<std::string>();
    if (doc["profile"])       sig.profile       = doc["profile"].as<std::string>();
    if (doc["input"])         sig.input         = doc["input"].as<std::string>();
    if (doc["composite-sig"]) sig.composite = base64_decode(doc["composite-sig"].as<std::string>());

    if (sig.tray_id.empty())
        throw std::runtime_error("sig YAML missing required field: tray-id");
    if (sig.composite.empty())
        throw std::runtime_error("sig YAML missing required field: composite-sig");
    return sig;
}

std::string emit_verify_yaml(const Signature& sig) {
    YAML::Emitter out;

    out << YAML::BeginDoc;
    out << YAML::BeginMap;

    out << YAML::Key << "verified"      << YAML::Value << true;
    out << YAML::Key << "id"            << YAML::Value << sig.id;
    out << YAML::Key << "tray-id"       << YAML::Value << sig.tray_id;
    out << YAML::Key << "tray-alias"    << YAML::Value << sig.tray_alias;
    out << YAML::Key << "profile-group" << YAML::Value << sig.profile_group;
    out << YAML::Key << "profile"       << YAML::Value << sig.profile;
    out << YAML::Key << "input"         << YAML::Value << sig.input;

    out << YAML::EndMap;
    out << YAML::EndDoc;

    return std::string(out.c_str()) + "\n";
}
