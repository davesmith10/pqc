// oqs_ops.hpp — private header for liboqs KEM and signature operations.
// Mirrors the oqs_kem and oqs_sig declarations in crystals/crystals.hpp.
// Include this in .cpp files within src/; never expose it to consumers.

#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace oqs_kem {

struct Keys {
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;
};

Keys keygen(const std::string& alg_name);
void encaps(const std::string& alg_name,
            const std::vector<uint8_t>& pk,
            std::vector<uint8_t>& ct_out,
            std::vector<uint8_t>& ss_out);
void decaps(const std::string& alg_name,
            const std::vector<uint8_t>& sk,
            const std::vector<uint8_t>& ct,
            std::vector<uint8_t>& ss_out);
bool is_oqs_kem(const std::string& alg_name);

} // namespace oqs_kem

namespace oqs_sig {

struct Keys {
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;
};

Keys keygen(const std::string& alg_name);
bool is_oqs_sig(const std::string& alg_name);
size_t sig_bytes(const std::string& alg_name);
void sign(const std::string& alg_name,
          const std::vector<uint8_t>& sk,
          const std::vector<uint8_t>& msg,
          std::vector<uint8_t>& sig_out);
bool verify(const std::string& alg_name,
            const std::vector<uint8_t>& pk,
            const std::vector<uint8_t>& msg,
            const std::vector<uint8_t>& sig);

} // namespace oqs_sig
