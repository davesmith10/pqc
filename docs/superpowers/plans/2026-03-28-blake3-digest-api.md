# BLAKE3 Digest API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `namespace blake3` to `crystals/crystals.hpp` exposing `digest`, `verify`, `keyed_digest`, and `keyed_verify` as a public `@api-candidate-1.2` API backed by a new `src/blake3_ops.cpp`.

**Architecture:** Four functions in a new `namespace blake3` declared in the public header and implemented in a dedicated source file. Plain hashing uses `blake3_hasher_init`; keyed hashing uses `blake3_hasher_init_keyed`. Verification recomputes and compares with `CRYPTO_memcmp` for constant-time safety. `blake3.h` is private — it does not appear in the public header.

**Tech Stack:** C++17, BLAKE3 C API (`blake3.h`, already a build dep via `BLAKE3::blake3`), OpenSSL `CRYPTO_memcmp` (already a build dep via `OpenSSL::Crypto`).

---

## File Map

| File | Change |
|------|--------|
| `include/crystals/crystals.hpp` | Add `namespace blake3` block with 4 declarations |
| `src/blake3_ops.cpp` | New file — full implementation |
| `CMakeLists.txt` | Add `src/blake3_ops.cpp` to `crystals` sources |
| `test/api_stability_test-1.2.cpp` | Add 4 `static_assert` blocks for `blake3::` signatures |
| `test/test_crystals.cpp` | Add Section 17: `blake3` with 9 functional assertions |

---

## Task 1: Declare the public API in the header

**Files:**
- Modify: `include/crystals/crystals.hpp` (append before the final blank line / EOF)

- [ ] **Step 1: Add the `namespace blake3` block to `crystals/crystals.hpp`**

Append the following block at the end of `include/crystals/crystals.hpp`, after the existing
`cmd_gentok` / `cmd_valtok` declarations and before EOF:

```cpp
// ── BLAKE3 digest ─────────────────────────────────────────────────────────────

namespace blake3 {

// Hash data with plain BLAKE3. Returns a 32-byte digest.
std::array<uint8_t, 32> digest(const std::vector<uint8_t>& data); // @api-candidate-1.2

// Recompute the BLAKE3 digest of data and compare to expected in constant time.
// Returns true if they match.
bool verify(const std::vector<uint8_t>& data,
            const std::array<uint8_t, 32>& expected);             // @api-candidate-1.2

// Hash data with BLAKE3 in keyed mode. key must be exactly 32 bytes.
std::array<uint8_t, 32> keyed_digest(const std::array<uint8_t, 32>& key,
                                     const std::vector<uint8_t>& data); // @api-candidate-1.2

// Recompute the keyed BLAKE3 digest and compare to expected in constant time.
// Returns true if they match.
bool keyed_verify(const std::array<uint8_t, 32>& key,
                  const std::vector<uint8_t>& data,
                  const std::array<uint8_t, 32>& expected);       // @api-candidate-1.2

} // namespace blake3
```

- [ ] **Step 2: Verify the header compiles in isolation**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/libcrystals-1.2
g++ -std=c++17 -fsyntax-only \
    -Iinclude \
    -I/usr/local/include \
    include/crystals/crystals.hpp
```

Expected: no output (clean compile). If there are errors, fix them before proceeding.

- [ ] **Step 3: Commit**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc
git add pqc/libcrystals-1.2/include/crystals/crystals.hpp
git commit -m "feat(libcrystals-1.2): declare namespace blake3 public API (@api-candidate-1.2)"
```

---

## Task 2: Implement `src/blake3_ops.cpp`

**Files:**
- Create: `pqc/libcrystals-1.2/src/blake3_ops.cpp`

- [ ] **Step 1: Create the implementation file**

Create `pqc/libcrystals-1.2/src/blake3_ops.cpp` with the following content:

```cpp
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
```

- [ ] **Step 2: Register the new source file in `CMakeLists.txt`**

In `pqc/libcrystals-1.2/CMakeLists.txt`, find the `add_library(crystals STATIC` block. Add
`src/blake3_ops.cpp` to the source list, after `src/token_cmd.cpp`:

```cmake
    src/token_cmd.cpp
    src/blake3_ops.cpp
```

- [ ] **Step 3: Build the library to confirm it compiles**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/libcrystals-1.2
cmake -S . -B build -DCMAKE_PREFIX_PATH=/mnt/c/Users/daves/OneDrive/Desktop/Crystals/local
cmake --build build -j$(nproc) 2>&1 | tail -20
```

Expected: build succeeds with no errors. Warnings are acceptable.

- [ ] **Step 4: Commit**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc
git add pqc/libcrystals-1.2/src/blake3_ops.cpp pqc/libcrystals-1.2/CMakeLists.txt
git commit -m "feat(libcrystals-1.2): implement namespace blake3 digest/verify/keyed_digest/keyed_verify"
```

---

## Task 3: Add API stability assertions

**Files:**
- Modify: `pqc/libcrystals-1.2/test/api_stability_test-1.2.cpp`

The API stability test compiles only against the public header. A compile failure here means a
breaking API change was introduced. Add assertions after the existing `oqs_sig` block and
before `int main()`.

- [ ] **Step 1: Add the `blake3` static_assert block**

In `test/api_stability_test-1.2.cpp`, insert the following before `int main() { return 0; }`:

```cpp
// ── blake3 namespace ─────────────────────────────────────────────────────────
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
```

- [ ] **Step 2: Build and run the API stability test**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/libcrystals-1.2
cmake --build build --target api_stability_test_12 -j$(nproc)
./build/api_stability_test_12
```

Expected: binary builds and exits 0 with no output. A compile error means the declared
signatures in the header don't match what's in the assert — fix the assert or the header
until they agree.

- [ ] **Step 3: Commit**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc
git add pqc/libcrystals-1.2/test/api_stability_test-1.2.cpp
git commit -m "test(libcrystals-1.2): add API stability assertions for namespace blake3"
```

---

## Task 4: Add functional tests

**Files:**
- Modify: `pqc/libcrystals-1.2/test/test_crystals.cpp`

The test follows the established pattern: a `static void test_blake3()` function, called from
`main()`, using the `CHECK` macro already defined at the top of the file.

- [ ] **Step 1: Add the `test_blake3` function**

In `test/test_crystals.cpp`, add the following function before the `// ── main ──` comment:

```cpp
// ── Section 17: BLAKE3 digest ─────────────────────────────────────────────────

static void test_blake3() {
    std::printf("=== Section 17: BLAKE3 digest ===\n");

    const std::vector<uint8_t> data  = {0x01, 0x02, 0x03, 0x04, 0x05};
    const std::vector<uint8_t> data2 = {0x01, 0x02, 0x03, 0x04, 0x06}; // one byte differs

    std::array<uint8_t, 32> key1{};
    std::array<uint8_t, 32> key2{};
    key1.fill(0xAA);
    key2.fill(0xBB);

    // digest is deterministic
    CHECK(blake3::digest(data) == blake3::digest(data));
    std::printf("  digest deterministic: OK\n");

    // digest is sensitive to input
    CHECK(blake3::digest(data) != blake3::digest(data2));
    std::printf("  digest input sensitivity: OK\n");

    // verify returns true on matching digest
    CHECK(blake3::verify(data, blake3::digest(data)) == true);
    std::printf("  verify match: OK\n");

    // verify returns false on tampered data
    CHECK(blake3::verify(data2, blake3::digest(data)) == false);
    std::printf("  verify tamper detection: OK\n");

    // keyed_digest differs from plain digest on same input
    CHECK(blake3::keyed_digest(key1, data) != blake3::digest(data));
    std::printf("  keyed_digest differs from plain digest: OK\n");

    // keyed_digest is sensitive to key
    CHECK(blake3::keyed_digest(key1, data) != blake3::keyed_digest(key2, data));
    std::printf("  keyed_digest key sensitivity: OK\n");

    // keyed_verify returns true on matching digest
    CHECK(blake3::keyed_verify(key1, data, blake3::keyed_digest(key1, data)) == true);
    std::printf("  keyed_verify match: OK\n");

    // keyed_verify returns false on tampered data
    CHECK(blake3::keyed_verify(key1, data2, blake3::keyed_digest(key1, data)) == false);
    std::printf("  keyed_verify tamper detection: OK\n");

    // keyed_verify returns false on wrong key
    CHECK(blake3::keyed_verify(key2, data, blake3::keyed_digest(key1, data)) == false);
    std::printf("  keyed_verify wrong key detection: OK\n");
}
```

- [ ] **Step 2: Register `test_blake3` in `main()`**

In `test/test_crystals.cpp`, find the `main()` function. Add `test_blake3();` after
`test_oqs_groups();` and before the closing results print:

```cpp
        test_oqs_groups();
        test_blake3();
```

- [ ] **Step 3: Build and run the full test suite**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/libcrystals-1.2
cmake --build build --target test_crystals -j$(nproc)
./build/test_crystals
```

Expected output includes:
```
=== Section 17: BLAKE3 digest ===
  digest deterministic: OK
  digest input sensitivity: OK
  verify match: OK
  verify tamper detection: OK
  keyed_digest differs from plain digest: OK
  keyed_digest key sensitivity: OK
  keyed_verify match: OK
  keyed_verify tamper detection: OK
  keyed_verify wrong key detection: OK
```

Final line must be: `Results: N passed, 0 failed`

- [ ] **Step 4: Commit**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc
git add pqc/libcrystals-1.2/test/test_crystals.cpp
git commit -m "test(libcrystals-1.2): add Section 17 functional tests for namespace blake3"
```

---

## Task 5: Install and smoke-test

- [ ] **Step 1: Install the updated library**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals
sudo bash pqc/libcrystals-1.2/install.sh
```

Expected: installs fat archive and headers to `/usr/local`. Should complete without errors.

- [ ] **Step 2: Verify downstream tools still build**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals
cmake --build pqc/scotty/build -j$(nproc)
cmake --build pqc/obi-wan/build -j$(nproc)
```

Expected: both build cleanly. These tools consume `Crystals::crystals` and must not be
broken by the additive change.

- [ ] **Step 3: Commit**

No new files changed — this step is verification only. If the install or downstream builds
fail, investigate before marking complete.

---

## Self-Review

**Spec coverage:**
- ✅ `namespace blake3` declared in public header — Task 1
- ✅ `digest` / `verify` / `keyed_digest` / `keyed_verify` implemented — Task 2
- ✅ `blake3.h` kept private (not in public header) — Task 2 implementation
- ✅ `CRYPTO_memcmp` for constant-time comparison — Task 2 implementation
- ✅ `src/blake3_ops.cpp` registered in `CMakeLists.txt` — Task 2
- ✅ API stability `static_assert` blocks for all 4 signatures — Task 3
- ✅ 9 functional test assertions in `test_crystals.cpp` Section 17 — Task 4
- ✅ Downstream build smoke-test — Task 5

**Placeholder scan:** No TBDs, no "similar to above", all code is complete and explicit.

**Type consistency:** `std::array<uint8_t, 32>` and `std::vector<uint8_t>` used consistently
across declaration (Task 1), implementation (Task 2), stability assertions (Task 3), and tests
(Task 4). `blake3::digest`, `blake3::verify`, `blake3::keyed_digest`, `blake3::keyed_verify`
named identically in all tasks.
