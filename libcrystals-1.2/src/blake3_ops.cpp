// blake3_ops.cpp — implementation of namespace blake3 (crystals/crystals.hpp)
// blake3.h is a private include; it must not appear in the public header.

#include "blake3.h"
#include <openssl/crypto.h>
#include "crystals/crystals.hpp"

namespace blake3 {

std::array<uint8_t, 32> digest(const std::vector<uint8_t>& data) {
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, data.data(), data.size());
    std::array<uint8_t, 32> out;
    blake3_hasher_finalize(&h, out.data(), 32);
    return out;
}

bool verify(const std::vector<uint8_t>& data,
            const std::array<uint8_t, 32>& expected) {
    auto actual = digest(data);
    return CRYPTO_memcmp(actual.data(), expected.data(), 32) == 0;
}

std::array<uint8_t, 32> keyed_digest(const std::array<uint8_t, 32>& key,
                                     const std::vector<uint8_t>& data) {
    blake3_hasher h;
    blake3_hasher_init_keyed(&h, key.data());
    blake3_hasher_update(&h, data.data(), data.size());
    std::array<uint8_t, 32> out;
    blake3_hasher_finalize(&h, out.data(), 32);
    return out;
}

bool keyed_verify(const std::array<uint8_t, 32>& key,
                  const std::vector<uint8_t>& data,
                  const std::array<uint8_t, 32>& expected) {
    auto actual = keyed_digest(key, data);
    return CRYPTO_memcmp(actual.data(), expected.data(), 32) == 0;
}

} // namespace blake3
