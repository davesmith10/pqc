# Tray UUID Derivation Scheme

## Why derived instead of random?

A random UUID (v4) is operationally weak: a recipient must trust that the UUID in the tray
file was faithfully preserved, and cannot independently verify it without a registry.

A UUID derived from the public keys is **self-verifying** — any party holding the public keys
can recompute the identifier from scratch.  This provides two additional properties:

1. **Content-addressable key selector**: the UUID is a stable fingerprint of the key material,
   not an arbitrary label.
2. **Private/public tray consistency**: a full tray and its companion public tray (same public
   keys, sk fields cleared) will produce the same UUID, so the UUID is a reliable link between
   the two artifacts.

---

## BLAKE3 mode and context string

The UUID is derived using **BLAKE3 key-derivation mode** (`blake3_hasher_init_derive_key`).

Context string (exact UTF-8 bytes, no null terminator):
```
Crystals hybrid tray-uuid v1
```

BLAKE3's key-derivation mode domain-separates this derivation from any other BLAKE3 use in
the codebase.  The context string encodes the application, component, and version so future
changes to the scheme produce a different UUID namespace.

---

## Canonical input encoding

Feed the hasher with each slot in **slot order** (the order slots appear in the tray):

```
for each slot in slots:
    uint32_t  name_len   (little-endian, 4 bytes)  ← byte length of alg_name
    uint8_t[] alg_name   (UTF-8 bytes, no null)
    uint32_t  pk_len     (little-endian, 4 bytes)  ← byte length of pk
    uint8_t[] pk         (raw public-key bytes)
```

**What is NOT included**: alias, timestamps (created/expires), tray type string, version,
is_public flag, secret keys.  Only the public key bytes and their algorithm labels are hashed.

The length prefix on each field prevents boundary ambiguity (e.g. `"AB" + "C"` from being
confused with `"A" + "BC"`).

---

## UUID v8 bit-twiddling (RFC 9562)

`blake3_hasher_finalize` produces 16 output bytes.  Two bits of structure are stamped in:

| Byte | Operation                   | Effect                                   |
|------|-----------------------------|------------------------------------------|
| 6    | `(out[6] & 0x0F) \| 0x80`  | Sets the high nibble to `8` (version 8) |
| 8    | `(out[8] & 0x3F) \| 0x80`  | Sets the two high bits to `10` (variant) |

These are the same masks used by all UUID versions — only the version nibble value differs.
The remaining 122 bits are raw BLAKE3 output.

---

## Expected output format

A standard 36-character UUID string with lowercase hex digits:

```
xxxxxxxx-xxxx-8xxx-{8|9|a|b}xxx-xxxxxxxxxxxx
```

- The 13th hex character (high nibble of byte 6) is always `8`.
- The 17th hex character (high nibble of byte 8) is always one of `{8, 9, a, b}`.
- All existing UUID parsers accept UUID v8 strings — the format is identical to v4.

---

## C++ reference implementation

```cpp
#include "blake3.h"
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

// Slot as defined in pq/include/tray.hpp:
//   std::string alg_name;
//   std::vector<uint8_t> pk;

static std::string derive_uuid(const std::vector<Slot>& slots) {
    blake3_hasher h;
    blake3_hasher_init_derive_key(&h, "Crystals hybrid tray-uuid v1");

    for (const auto& slot : slots) {
        // Length-prefix the algorithm name (little-endian uint32_t)
        uint32_t name_len = static_cast<uint32_t>(slot.alg_name.size());
        uint8_t  name_len_le[4] = {
            static_cast<uint8_t>( name_len        & 0xFF),
            static_cast<uint8_t>((name_len >>  8) & 0xFF),
            static_cast<uint8_t>((name_len >> 16) & 0xFF),
            static_cast<uint8_t>((name_len >> 24) & 0xFF),
        };
        blake3_hasher_update(&h, name_len_le, 4);
        blake3_hasher_update(&h, slot.alg_name.data(), slot.alg_name.size());

        // Length-prefix the public key (little-endian uint32_t)
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
        out[0], out[1], out[2],  out[3],
        out[4], out[5],
        out[6], out[7],
        out[8], out[9],
        out[10], out[11], out[12], out[13], out[14], out[15]);
    return std::string(buf);
}
```

---

## Guidance for zorro: adding UUID self-verification on tray load

When zorro loads a tray it can independently recompute the UUID and reject tampered files.

**Where**: `zorro/src/tray_reader.cpp`, at the end of the load function (after slots are
populated), before the tray is returned to the caller.

**Slots available**: at that point `tray.slots` is fully populated with `alg_name` and `pk`.
Secret keys are not present in public trays but are not needed — derive_uuid uses only `pk`.

**What to call**: reimplement or extract `derive_uuid()` (identical algorithm, same context
string) and compare:

```cpp
std::string derived = derive_uuid(tray.slots);
if (derived != tray.id) {
    throw std::runtime_error(
        "tray UUID mismatch: stored " + tray.id +
        " but derived " + derived + " from public keys");
}
```

**Error handling**: throw `std::runtime_error` (caught by main and reported as exit code 2,
crypto failure) so the error is visible and the process does not silently continue with a
tray whose identity cannot be verified.

**Note**: trays generated before this scheme (UUID v4) will fail verification.  If
backward-compatibility with old trays is needed, check the UUID version nibble first:
if `tray.id[14] != '8'` then skip verification (or warn and skip).
