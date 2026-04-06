#pragma once
#include "tray.hpp"
#include <string>

// Emit the full tray as YAML to a string.
std::string emit_tray_yaml(const Tray& tray);

// Emit a hybrid digital signature document as YAML.
std::string emit_signature_yaml(const Signature& sig);

// Parse YAML produced by emit_signature_yaml.
// Throws std::runtime_error if tray-id or composite-sig are missing.
Signature parse_sig_yaml(const std::string& text);

// Emit a signature verification result as YAML (composite omitted, verified:true added).
std::string emit_verify_yaml(const Signature& sig);
