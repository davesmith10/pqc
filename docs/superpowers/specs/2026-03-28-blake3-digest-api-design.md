# BLAKE3 Digest API — libcrystals-1.2 Design Spec

**Date:** 2026-03-28
**Status:** @api-candidate-1.2
**Scope:** Additive — no existing functionality is changed.

---

## 1. Purpose

Expose BLAKE3 hashing as a first-class public capability in `libcrystals-1.2` for use by
downstream consumers (scotty, obi-wan, padme, and external code). BLAKE3 is already a build
dependency (used internally for tray UUID derivation), but currently exposes zero public surface.

This spec covers plain hashing and keyed hashing. Key derivation mode is explicitly excluded —
`derive_key_shake` / `derive_key_kmac` already cover that use case. Validation (digest
comparison) is a first-class operation using constant-time comparison to prevent timing
side-channels.

---

## 2. Public API

Declared in `crystals/crystals.hpp`, inside `namespace blake3`. All four functions are marked
`@api-candidate-1.2`.

```cpp
namespace blake3 {

// Hash data with plain BLAKE3. Returns 32-byte digest.
std::array<uint8_t, 32> digest(const std::vector<uint8_t>& data); // @api-candidate-1.2

// Recompute BLAKE3 digest of data and compare to expected in constant time.
// Returns true if they match.
bool verify(const std::vector<uint8_t>& data,
            const std::array<uint8_t, 32>& expected);             // @api-candidate-1.2

// Hash data with BLAKE3 in keyed mode. key must be exactly 32 bytes.
std::array<uint8_t, 32> keyed_digest(const std::array<uint8_t, 32>& key,
                                     const std::vector<uint8_t>& data); // @api-candidate-1.2

// Recompute keyed BLAKE3 digest and compare to expected in constant time.
bool keyed_verify(const std::array<uint8_t, 32>& key,
                  const std::vector<uint8_t>& data,
                  const std::array<uint8_t, 32>& expected);       // @api-candidate-1.2

} // namespace blake3
```

### Design decisions

- **Namespace `blake3`** — consistent with `oqs_kem`, `oqs_sig`, `ec_sig` etc.; avoids
  polluting the global namespace; call sites read naturally as `blake3::digest(data)`.
- **Fixed 32-byte output (`std::array<uint8_t, 32>`)** — consistent with `derive_key_shake`
  and `derive_key_kmac`; BLAKE3's standard output length; compile-time size guarantee.
- **Key type `std::array<uint8_t, 32>`** — BLAKE3 keyed mode requires exactly 32 bytes;
  encoding this as a fixed-size array is preferable to a runtime size check on `vector`.
- **Constant-time verify** — `CRYPTO_memcmp` (OpenSSL, already a dependency). Callers must
  not be required to remember to use constant-time comparison in a crypto library.
- **No key derivation mode** — excluded; `derive_key_shake` / `derive_key_kmac` cover that
  surface. Adding it here would be redundant.

---

## 3. Implementation

### New file: `src/blake3_ops.cpp`

```cpp
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

bool verify(const std::vector<uint8_t>& data, const std::array<uint8_t, 32>& expected) {
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
```

### `blake3.h` inclusion

`blake3.h` is a private header (included only from `src/`). It must **not** appear in
`crystals/crystals.hpp`. Consumers see only the `std::array`/`std::vector` interface.

### CMakeLists.txt

Add `src/blake3_ops.cpp` to the `crystals` STATIC target source list. No new dependencies —
`BLAKE3::blake3` and `OpenSSL::Crypto` are already linked.

---

## 4. Testing

### 4a. API stability test (`test/api_stability_test-1.2.cpp`)

Add `static_assert` blocks enforcing all four function signatures, consistent with the existing
pattern for `oqs_kem` and `oqs_sig`. API stability testing is the primary guard against
accidental breaking changes between library versions.

Assertions to add:

```cpp
// ── blake3 namespace ────────────────────────────────────────────────────────
static_assert(std::is_same_v<
    decltype(&blake3::digest),
    std::array<uint8_t, 32> (*)(const std::vector<uint8_t>&)>);

static_assert(std::is_same_v<
    decltype(&blake3::verify),
    bool (*)(const std::vector<uint8_t>&, const std::array<uint8_t, 32>&)>);

static_assert(std::is_same_v<
    decltype(&blake3::keyed_digest),
    std::array<uint8_t, 32> (*)(const std::array<uint8_t, 32>&,
                                 const std::vector<uint8_t>&)>);

static_assert(std::is_same_v<
    decltype(&blake3::keyed_verify),
    bool (*)(const std::array<uint8_t, 32>&,
             const std::vector<uint8_t>&,
             const std::array<uint8_t, 32>&)>);
```

### 4b. Functional tests (`test/test_crystals.cpp`)

Add a `blake3` section covering:

| Test | Assertion |
|------|-----------|
| Determinism | `digest(data) == digest(data)` |
| Sensitivity | `digest(data) != digest(modified_data)` |
| verify — match | `verify(data, digest(data)) == true` |
| verify — tamper | `verify(tampered, digest(data)) == false` |
| keyed vs plain | `keyed_digest(key, data) != digest(data)` |
| keyed — key sensitivity | `keyed_digest(key1, data) != keyed_digest(key2, data)` |
| keyed_verify — match | `keyed_verify(key, data, keyed_digest(key, data)) == true` |
| keyed_verify — tamper | `keyed_verify(key, tampered, keyed_digest(key, data)) == false` |
| keyed_verify — wrong key | `keyed_verify(key2, data, keyed_digest(key1, data)) == false` |

No new test binaries — both test files are already built by CMake.

---

## 5. Files Changed

| File | Change |
|------|--------|
| `include/crystals/crystals.hpp` | Add `namespace blake3` block with 4 function declarations |
| `src/blake3_ops.cpp` | New file — implementation |
| `CMakeLists.txt` | Add `src/blake3_ops.cpp` to `crystals` sources |
| `test/api_stability_test-1.2.cpp` | Add 4 `static_assert` blocks for `blake3::` signatures |
| `test/test_crystals.cpp` | Add `blake3` functional test section (9 assertions) |
