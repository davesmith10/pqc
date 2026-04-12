# Remove msgpack Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove all msgpack-c read/write support from libcrystals-1.2, hybrid, zorro, penelope, and the standalone pqc/msgpack library — trays are YAML-only going forward.

**Architecture:** The msgpack-c header-only library is used in two places: `libcrystals-1.2/src/tray_pack.cpp` (compiled into the fat archive) and the standalone `pqc/msgpack/` CMake project. Consumers (zorro, penelope) reach msgpack through the `Crystals::crystals` imported target. Removal touches the library source, the public header, the generated install scripts, two consumer tools, and the standalone library. `load_tray()` stays in the public API (same signature) but becomes YAML-only. The `tray_mp` namespace must be removed from `crystals.hpp` — this is a breaking change to `@api-stable v1.0` that is intentional per user direction.

**Tech Stack:** C++17, CMake 3.16, OpenSSL, yaml-cpp, BLAKE3

---

## ⚠️ API-Break Notice

`crystals.hpp` **does** need a small change contrary to the initial assumption: the `tray_mp` namespace block (lines 1417–1424) must be removed. `load_tray()` itself stays (same signature, YAML-only internally). The api_stability_test-1.0.cpp static-asserts for `tray_mp::pack/unpack` must also be removed. This is intentional and approved.

---

## File Map

| File | Action |
|---|---|
| `pqc/libcrystals-1.2/src/tray_pack.hpp` | **Delete** |
| `pqc/libcrystals-1.2/src/tray_pack.cpp` | **Delete** |
| `pqc/libcrystals-1.2/src/tray_reader.hpp` | Modify — update doc comment |
| `pqc/libcrystals-1.2/src/tray_reader.cpp` | Modify — remove `#include "tray_pack.hpp"`, simplify `load_tray()` |
| `pqc/libcrystals-1.2/CMakeLists.txt` | Modify — remove MSGPACK_INC vars, include path, `tray_pack.cpp` source, `MSGPACK_NO_BOOST` |
| `pqc/libcrystals-1.2/include/crystals/crystals.hpp` | Modify — remove `tray_mp` namespace block, update `load_tray` comment |
| `pqc/libcrystals-1.2/install.sh` | Modify — remove `MSGPACK_NO_BOOST` from generated CMake config and pkg-config |
| `pqc/libcrystals-1.2/test/test_crystals.cpp` | Modify — remove `test_msgpack_roundtrip`, rewrite `test_uuid_verification` |
| `pqc/libcrystals-1.2/test/api_stability_test-1.0.cpp` | Modify — remove tray_mp static-asserts |
| `pqc/zorro/src/main.cpp` | Modify — update one help-text line |
| `pqc/penelope/src/main.cpp` | Modify — remove `has_yaml_ext`, rewrite `write_tray_file`, update help text |
| `pqc/msgpack/` | **Delete entire directory** |
| `pqc/CLAUDE.md` | Modify — remove msgpack sections |

---

## Task 1: libcrystals-1.2 — Remove msgpack from library source

**Files:**
- Delete: `pqc/libcrystals-1.2/src/tray_pack.hpp`
- Delete: `pqc/libcrystals-1.2/src/tray_pack.cpp`
- Modify: `pqc/libcrystals-1.2/src/tray_reader.hpp`
- Modify: `pqc/libcrystals-1.2/src/tray_reader.cpp`
- Modify: `pqc/libcrystals-1.2/CMakeLists.txt`

- [ ] **Step 1.1: Delete tray_pack source files**

```bash
rm pqc/libcrystals-1.2/src/tray_pack.hpp
rm pqc/libcrystals-1.2/src/tray_pack.cpp
```

- [ ] **Step 1.2: Update tray_reader.hpp — fix doc comment**

Current file (`pqc/libcrystals-1.2/src/tray_reader.hpp`):
```cpp
#pragma once
#include "tray.hpp"
#include <string>

// Load a Tray from a file path.
// Auto-detects format: if first byte is '-' (0x2D) → YAML, else → msgpack.
// Throws std::runtime_error on failure.
Tray load_tray(const std::string& path);
```

Replace the two comment lines so the file reads:
```cpp
#pragma once
#include "tray.hpp"
#include <string>

// Load a Tray from a YAML file path.
// Throws std::runtime_error on failure.
Tray load_tray(const std::string& path);
```

- [ ] **Step 1.3: Update tray_reader.cpp — remove msgpack branch**

The current `load_tray()` at the bottom of `pqc/libcrystals-1.2/src/tray_reader.cpp`:

```cpp
#include "tray_reader.hpp"
#include "base64.hpp"
#include "tray_pack.hpp"        // ← REMOVE this include
#include "blake3.h"
#include <yaml-cpp/yaml.h>
...

Tray load_tray(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        throw std::runtime_error("Cannot open tray file: " + path);

    int first = f.get();
    if (first == EOF)
        throw std::runtime_error("Tray file is empty: " + path);

    Tray tray = (first == 0x2D) ? load_tray_yaml(path) : tray_mp::unpack_from_file(path);
    verify_tray_uuid(tray);
    return tray;
}
```

Make two edits:

*Edit A* — Remove the `#include "tray_pack.hpp"` line (line 3).

*Edit B* — Replace the entire `load_tray()` function body:

```cpp
Tray load_tray(const std::string& path) {
    Tray tray = load_tray_yaml(path);
    verify_tray_uuid(tray);
    return tray;
}
```

Also remove the `#include <fstream>` line only if it's no longer needed by anything else in the file.
(Check: `load_tray_yaml` uses `YAML::LoadFile` internally — the `std::ifstream` at the top of
`load_tray` was the only direct use of `<fstream>` in the entry-point section. But `<fstream>`
is used in `load_tray_yaml`'s helper functions, so look at whether the top-level includes still
serve other functions in the file before removing. **Leave `<fstream>` in place** — it is used
in `load_tray_yaml` via YAML::LoadFile indirectly and the import is harmless.)

- [ ] **Step 1.4: Update CMakeLists.txt — strip all msgpack references**

File: `pqc/libcrystals-1.2/CMakeLists.txt`

Remove these two lines (MSGPACK_INC declaration and its get_filename_component):
```cmake
set(MSGPACK_INC       "${CMAKE_SOURCE_DIR}/../../msgpack-c/include")
...
get_filename_component(MSGPACK_INC_ABS    "${MSGPACK_INC}"       ABSOLUTE)
```

Remove `src/tray_pack.cpp` from the `add_library(crystals STATIC ...)` source list (currently line 62).

Remove `"${MSGPACK_INC_ABS}"` from `target_include_directories` (currently line 85 under PUBLIC).

Remove `PUBLIC  MSGPACK_NO_BOOST` from `target_compile_definitions` (currently line 100; leave `PRIVATE HAVE_CONFIG_H` in place — if MSGPACK_NO_BOOST was the only PUBLIC entry, change `PUBLIC MSGPACK_NO_BOOST` to just remove it and keep `PRIVATE HAVE_CONFIG_H`).

After edits the relevant sections should look like:

```cmake
# ── Library paths ─────────────────────────────────────────────────────────────
set(KYBER_REF_DIR     "${CMAKE_SOURCE_DIR}/../../kyber/ref")
set(DILITHIUM_REF_DIR "${CMAKE_SOURCE_DIR}/../../dilithium/ref")
set(XKCP_DIR          "${CMAKE_SOURCE_DIR}/../../XKCP")
set(SCRYPT_DIR        "${CMAKE_SOURCE_DIR}/../../scrypt")

get_filename_component(KYBER_REF_DIR_ABS  "${KYBER_REF_DIR}"     ABSOLUTE)
get_filename_component(DIL_REF_DIR_ABS    "${DILITHIUM_REF_DIR}" ABSOLUTE)
get_filename_component(XKCP_DIR_ABS       "${XKCP_DIR}"          ABSOLUTE)
get_filename_component(SCRYPT_DIR_ABS     "${SCRYPT_DIR}"        ABSOLUTE)
```

```cmake
add_library(crystals STATIC
    src/base64.cpp
    src/ec_ops.cpp
    src/kyber_ops.cpp
    src/dilithium_ops.cpp
    src/tray.cpp
    src/yaml_io.cpp
    src/tray_reader.cpp
    # src/tray_pack.cpp  ← REMOVED
    src/ec_kem.cpp
    ...
```

```cmake
target_include_directories(crystals
    PUBLIC
        include/
        "${XKCP_INC}"
        # "${MSGPACK_INC_ABS}"  ← REMOVED
    PRIVATE
        src/
        ...
```

```cmake
target_compile_definitions(crystals
    # PUBLIC  MSGPACK_NO_BOOST  ← REMOVED
    PRIVATE HAVE_CONFIG_H
)
```

- [ ] **Step 1.5: Verify the library builds (don't install yet)**

```bash
cmake -S pqc/libcrystals-1.2 -B pqc/libcrystals-1.2/build \
    -DCMAKE_PREFIX_PATH=/mnt/c/Users/daves/OneDrive/Desktop/Crystals/local \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build pqc/libcrystals-1.2/build -j$(nproc) 2>&1 | tail -20
```

Expected: build succeeds with no errors. Any reference to `tray_pack` or `msgpack` in the error output means a missed reference.

- [ ] **Step 1.6: Commit**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals
git add pqc/libcrystals-1.2/CMakeLists.txt \
        pqc/libcrystals-1.2/src/tray_reader.hpp \
        pqc/libcrystals-1.2/src/tray_reader.cpp
git rm pqc/libcrystals-1.2/src/tray_pack.hpp \
       pqc/libcrystals-1.2/src/tray_pack.cpp
git commit -m "feat(libcrystals-1.2): remove msgpack source files and CMake integration"
```

---

## Task 2: libcrystals-1.2 — Update public header and API stability test

**Files:**
- Modify: `pqc/libcrystals-1.2/include/crystals/crystals.hpp`
- Modify: `pqc/libcrystals-1.2/test/api_stability_test-1.0.cpp`

- [ ] **Step 2.1: Remove tray_mp namespace from crystals.hpp**

In `pqc/libcrystals-1.2/include/crystals/crystals.hpp`, find and replace this block (around lines 1413–1424):

```cpp
// ── Tray reader (auto-detect YAML or msgpack) ─────────────────────────────────

Tray load_tray(const std::string& path);                    // @api-stable v1.0

// ── MessagePack tray encoding ─────────────────────────────────────────────────

namespace tray_mp {
    std::vector<uint8_t> pack(const Tray& tray);            // @api-stable v1.0
    Tray                 unpack(const std::vector<uint8_t>& data); // @api-stable v1.0
    void                 pack_to_file(const Tray& tray, const std::string& path); // @api-stable v1.0
    Tray                 unpack_from_file(const std::string& path); // @api-stable v1.0
}
```

Replace with (keep load_tray, remove tray_mp namespace entirely):

```cpp
// ── Tray reader ───────────────────────────────────────────────────────────────

Tray load_tray(const std::string& path);                    // @api-stable v1.0
```

- [ ] **Step 2.2: Remove tray_mp static-asserts from api_stability_test-1.0.cpp**

In `pqc/libcrystals-1.2/test/api_stability_test-1.0.cpp`, find and remove this block (around lines 177–186):

```cpp
// ── tray_mp functions ─────────────────────────────────────────────────────────
static_assert(std::is_same_v<
    decltype(&tray_mp::pack),
    std::vector<uint8_t>(*)(const Tray&)
>, "tray_mp::pack signature changed");

static_assert(std::is_same_v<
    decltype(&tray_mp::unpack),
    Tray(*)(const std::vector<uint8_t>&)
>, "tray_mp::unpack signature changed");
```

Leave the `load_tray` and `emit_tray_yaml` static-asserts immediately after it intact.

- [ ] **Step 2.3: Build api_stability_test-1.0 to verify**

```bash
cmake --build pqc/libcrystals-1.2/build --target api_stability_test_10 -j$(nproc) 2>&1 | tail -10
```

Expected: compiles with no errors.

- [ ] **Step 2.4: Commit**

```bash
git add pqc/libcrystals-1.2/include/crystals/crystals.hpp \
        pqc/libcrystals-1.2/test/api_stability_test-1.0.cpp
git commit -m "feat(libcrystals-1.2): remove tray_mp namespace from public API"
```

---

## Task 3: libcrystals-1.2 — Update test_crystals.cpp

**Files:**
- Modify: `pqc/libcrystals-1.2/test/test_crystals.cpp`

- [ ] **Step 3.1: Remove test_msgpack_roundtrip function**

Delete the entire `test_msgpack_roundtrip` function — the comment header and all code from
`// ── Section 3: Msgpack round-trip` through the closing `}` (currently lines ~114–147).

- [ ] **Step 3.2: Rewrite test_uuid_verification to use YAML + UUID field tampering**

The current `test_uuid_verification` (Section 4) uses `tray_mp::pack_to_file` to create a
binary tray and then flips bytes. Replace the entire function body with a YAML-based approach
that overwrites the `id:` field with a bogus UUID:

```cpp
// ── Section 3: UUID verification ─────────────────────────────────────────────

static void test_uuid_verification() {
    std::printf("=== Section 3: UUID verification ===\n");

    Tray orig = make_tray(TrayType::Level2_25519, "dave");
    std::string yaml = emit_tray_yaml(orig);

    // Tamper: replace the correct UUID with an all-zero v8 UUID
    std::string tampered = yaml;
    size_t pos = tampered.find("id: ");
    if (pos != std::string::npos) {
        size_t eol = tampered.find('\n', pos);
        tampered.replace(pos, eol - pos, "id: 00000000-0000-8000-8000-000000000000");
    }
    std::string path = tmp_path("tampered_uuid.tray");
    { std::ofstream f(path); f << tampered; }

    // load_tray must throw UUID mismatch
    bool threw = false;
    try { load_tray(path); } catch (...) { threw = true; }
    CHECK(threw);
    std::printf("  tampered YAML UUID rejected: OK\n");
}
```

Note: The replacement UUID `00000000-0000-8000-8000-000000000000` has `'8'` at position 14
so `verify_tray_uuid` will not skip it, and it will not match the derived UUID from the
real public keys — so the check throws as expected.

- [ ] **Step 3.3: Renumber sections and update main() call site**

In `main()` (around line 822), remove the call to `test_msgpack_roundtrip()` (line 829).
The call sequence should become:

```cpp
test_keygen();
test_yaml_roundtrip();
// test_msgpack_roundtrip();  ← REMOVED
test_uuid_verification();
test_kyber_kem();
...
```

Also renumber all subsequent section comments in the file to close the gap left by removing Section 3.
Old Section 4 → new Section 3 (already done in Step 3.2 replacement code).
Old Section 5 → new Section 4, old Section 6 → new Section 5, and so on for all remaining sections.
Search for `=== Section` in the file to find all occurrences.

- [ ] **Step 3.4: Build and run test_crystals to verify**

```bash
cmake --build pqc/libcrystals-1.2/build --target test_crystals -j$(nproc)
./pqc/libcrystals-1.2/build/test_crystals 2>&1 | tail -30
```

Expected: all sections pass, no msgpack output in results.

- [ ] **Step 3.5: Commit**

```bash
git add pqc/libcrystals-1.2/test/test_crystals.cpp
git commit -m "test(libcrystals-1.2): replace msgpack test with YAML-based UUID verification test"
```

---

## Task 4: libcrystals-1.2 — Update install.sh and reinstall

**Files:**
- Modify: `pqc/libcrystals-1.2/install.sh`

The `install.sh` generates two files that still contain `MSGPACK_NO_BOOST`:
1. `CrystalsConfig.cmake` — `INTERFACE_COMPILE_DEFINITIONS "MSGPACK_NO_BOOST"`
2. `crystals.pc` — `Cflags: -I${includedir} -DMSGPACK_NO_BOOST`

- [ ] **Step 4.1: Remove MSGPACK_NO_BOOST from CrystalsConfig.cmake generation**

In `pqc/libcrystals-1.2/install.sh`, find the here-doc that writes `CrystalsConfig.cmake`
(around line 190). Find and remove `MSGPACK_NO_BOOST` from the `INTERFACE_COMPILE_DEFINITIONS` line:

```cmake
# Before:
INTERFACE_COMPILE_DEFINITIONS "MSGPACK_NO_BOOST"

# After: remove the line entirely (no other PUBLIC compile defs needed)
```

The `set_target_properties` block should look like:

```cmake
set_target_properties(Crystals::crystals PROPERTIES
    IMPORTED_LOCATION             "\${_crystals_root}/lib/libcrystals-1.2.a"
    INTERFACE_INCLUDE_DIRECTORIES "\${_crystals_root}/include;${XKCP_INC}"
)
```

- [ ] **Step 4.2: Remove -DMSGPACK_NO_BOOST from pkg-config generation**

In the same file, find the here-doc that writes `crystals.pc` (around line 239).
Change the `Cflags` line:

```
# Before:
Cflags: -I${includedir} -DMSGPACK_NO_BOOST

# After:
Cflags: -I${includedir}
```

- [ ] **Step 4.3: Fix potential CRLF issues in install.sh (WSL)**

After any Write-tool edit to install.sh, strip CRLF:

```bash
tr -d '\r' < pqc/libcrystals-1.2/install.sh > /tmp/s && cp /tmp/s pqc/libcrystals-1.2/install.sh && chmod +x pqc/libcrystals-1.2/install.sh
```

- [ ] **Step 4.4: Reinstall libcrystals-1.2**

```bash
sudo bash pqc/libcrystals-1.2/install.sh
```

Expected: `Installation complete.` with no errors.

- [ ] **Step 4.5: Commit**

```bash
git add pqc/libcrystals-1.2/install.sh
git commit -m "feat(libcrystals-1.2): remove MSGPACK_NO_BOOST from generated cmake/pkgconfig"
```

---

## Task 5: zorro — Update help text

**Files:**
- Modify: `pqc/zorro/src/main.cpp`

- [ ] **Step 5.1: Update the --tray help string (line 29)**

Find in `pqc/zorro/src/main.cpp`:

```cpp
"  --tray   Tray file (YAML or msgpack, auto-detected)\n"
```

Replace with:

```cpp
"  --tray   Tray file (YAML)\n"
```

- [ ] **Step 5.2: Rebuild zorro**

```bash
cmake -S pqc/zorro -B pqc/zorro/build
cmake --build pqc/zorro/build -j$(nproc) 2>&1 | tail -10
```

Expected: clean build.

- [ ] **Step 5.3: Smoke test**

```bash
./pqc/hybrid/build/hybrid keygen --alias alice --profile level2-25519 > /tmp/alice.tray
echo "hello" > /tmp/plain.txt
./pqc/zorro/build/zorro encrypt --tray /tmp/alice.tray /tmp/plain.txt > /tmp/out.armored
./pqc/zorro/build/zorro decrypt --tray /tmp/alice.tray /tmp/out.armored | diff /tmp/plain.txt -
```

Expected: decrypt matches original.

- [ ] **Step 5.4: Commit**

```bash
git add pqc/zorro/src/main.cpp
git commit -m "feat(zorro): update help text — tray input is YAML only"
```

---

## Task 6: penelope — Remove msgpack write support

**Files:**
- Modify: `pqc/penelope/src/main.cpp`

- [ ] **Step 6.1: Delete has_yaml_ext and rewrite write_tray_file**

Find and remove the `has_yaml_ext` helper (around lines 508–513):

```cpp
static bool has_yaml_ext(const std::string& path) {
    auto dot = path.rfind('.');
    if (dot == std::string::npos) return false;
    std::string ext = path.substr(dot);
    return ext == ".yaml" || ext == ".yml";
}
```

Replace the full `write_tray_file` function (around lines 515–535) with:

```cpp
// Write tray to file in YAML format. Returns false and prints error on failure.
static bool write_tray_file(const Tray& tray, const std::string& path, const char* cmd) {
    try {
        std::ofstream f(path);
        if (!f) { std::cerr << "Error: cannot open " << path << " for writing\n"; return false; }
        f << emit_tray_yaml(tray);
    } catch (const std::exception& e) {
        std::cerr << "Error: YAML write failed: " << e.what() << "\n"; return false;
    }
    std::cout << cmd << ": tray '" << tray.alias << "' \xe2\x86\x92 " << path
              << " (" << tray.slots.size() << " slots)\n";
    return true;
}
```

- [ ] **Step 6.2: Update help text strings**

Find (around line 957):
```cpp
"  --in-tray  <file>      Input tray (YAML or msgpack)\n"
```
Replace with:
```cpp
"  --in-tray  <file>      Input tray (YAML)\n"
```

Find (around line 963):
```cpp
"  --out-tray <file>      Output tray: YAML (.yaml/.yml) or msgpack (default: YAML to stdout)\n"
```
Replace with:
```cpp
"  --out-tray <file>      Output tray (YAML format)\n"
```

- [ ] **Step 6.3: Rebuild penelope**

```bash
cmake -S pqc/penelope -B pqc/penelope/build
cmake --build pqc/penelope/build -j$(nproc) 2>&1 | tail -10
```

Expected: clean build with no references to `tray_mp` or `msgpack`.

- [ ] **Step 6.4: Smoke test**

Requires a tray and a PNG fixture. Basic build + help-text check:

```bash
./pqc/penelope/build/penelope --help 2>&1 | grep -E "in-tray|out-tray"
```

Expected: shows `(YAML)` and `(YAML format)`, no mention of msgpack.

- [ ] **Step 6.5: Commit**

```bash
git add pqc/penelope/src/main.cpp
git commit -m "feat(penelope): remove msgpack tray output — write_tray_file is YAML-only"
```

---

## Task 7: Delete pqc/msgpack/ standalone library

**Files:**
- Delete: entire `pqc/msgpack/` directory

- [ ] **Step 7.1: Remove the directory**

```bash
git rm -r pqc/msgpack/
```

- [ ] **Step 7.2: Verify gone**

```bash
ls pqc/msgpack/ 2>&1
```

Expected: `ls: cannot access ...` error.

- [ ] **Step 7.3: Commit**

```bash
git commit -m "feat: remove standalone pqc/msgpack library — no longer needed"
```

---

## Task 8: Update CLAUDE.md documentation

**Files:**
- Modify: `pqc/CLAUDE.md`

- [ ] **Step 8.1: Remove msgpack Build Command block**

Find and remove this block from the `## Build Commands` section:

```markdown
**Build msgpack** (tray binary encoding library + tests):
```bash
cmake -S pqc/msgpack -B pqc/msgpack/build
cmake --build pqc/msgpack/build -j$(nproc)
# Library: pqc/msgpack/build/libtraymsgpack.a
# Tests:   pqc/msgpack/build/test_roundtrip
\```
```

- [ ] **Step 8.2: Remove msgpack round-trip from Testing section**

Find and remove from the `## Testing` section:
```markdown
# msgpack: round-trip tests
./pqc/msgpack/build/test_roundtrip
```

- [ ] **Step 8.3: Update zorro architecture doc**

In `## Architecture / zorro Architecture`, find the library API line:
```
- `load_tray` — auto-detects YAML vs msgpack by first byte
```
Replace with:
```
- `load_tray` — loads a YAML tray file
```

Also in the same section, find and update the **Library API used** list note about msgpack.

- [ ] **Step 8.4: Remove msgpack Architecture section**

Find the `### msgpack Architecture` subsection and delete it entirely (roughly 15 lines covering
tray_pack.hpp/cpp, wire format, dependencies, and the warning about msgpack-c).

- [ ] **Step 8.5: Update penelope CMakeLists.txt description**

In the `## CMakeLists.txt Paths` section, find the msgpack entry:
```
- msgpack: `cmake -S pqc/msgpack -B pqc/msgpack/build` (no PREFIX_PATH needed; no BLAKE3/TBB)
```
Delete that line.

- [ ] **Step 8.6: Update Verified Working (zorro)**

Find and remove the line:
```
- YAML and msgpack tray formats both load correctly for encrypt+sign/verify+decrypt
```

- [ ] **Step 8.7: Update penelope section**

In the `## penelope Tool` section, update the description to remove msgpack from the tray format
description. Currently it says YAML or msgpack for `--in-tray` and `--out-tray`; update to YAML only.

- [ ] **Step 8.8: Remove msgpack-c note from repo layout**

In the repo layout tree comment, find:
```
├── msgpack-c/          — msgpack-c header-only library (vendored)
```
Remove or replace with a note that it's no longer used (or simply delete the line).

- [ ] **Step 8.9: Update API Stability Rules note**

The CLAUDE.md says: *"Never modify, rename, or remove any function marked @api-stable"*.
Add a note that the `tray_mp` namespace was intentionally removed in v1.2 per user direction —
this is a documented exception to the rule.

- [ ] **Step 8.10: Commit**

```bash
git add pqc/CLAUDE.md
git commit -m "docs: remove msgpack references from CLAUDE.md"
```

---

## Task 9: Final verification

- [ ] **Step 9.1: Clean rebuild of everything from scratch**

```bash
# Reconfigure and rebuild libcrystals (force fresh configure after install.sh changes)
cmake -S pqc/libcrystals-1.2 -B pqc/libcrystals-1.2/build \
    -DCMAKE_PREFIX_PATH=/mnt/c/Users/daves/OneDrive/Desktop/Crystals/local \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build pqc/libcrystals-1.2/build -j$(nproc)
./pqc/libcrystals-1.2/build/test_crystals

# Rebuild hybrid
cmake -S pqc/hybrid -B pqc/hybrid/build && cmake --build pqc/hybrid/build -j$(nproc)

# Rebuild zorro
cmake -S pqc/zorro -B pqc/zorro/build && cmake --build pqc/zorro/build -j$(nproc)

# Rebuild penelope
cmake -S pqc/penelope -B pqc/penelope/build && cmake --build pqc/penelope/build -j$(nproc)
```

- [ ] **Step 9.2: Verify no msgpack symbols in any binary**

```bash
nm pqc/hybrid/build/hybrid   | grep -i msgpack && echo FOUND || echo clean
nm pqc/zorro/build/zorro | grep -i msgpack && echo FOUND || echo clean
nm pqc/penelope/build/penelope     | grep -i msgpack && echo FOUND || echo clean
```

Expected: `clean` for all three.

- [ ] **Step 9.3: Full zorro smoke test**

```bash
./pqc/hybrid/build/hybrid keygen --alias alice --profile level2-25519 > /tmp/alice.tray
echo "hello world" > /tmp/plain.txt

# encrypt/decrypt (SHAKE + AES-256-GCM)
./pqc/zorro/build/zorro encrypt --tray /tmp/alice.tray /tmp/plain.txt > /tmp/out.armored
./pqc/zorro/build/zorro decrypt --tray /tmp/alice.tray /tmp/out.armored | diff /tmp/plain.txt -

# encrypt+sign / verify+decrypt
./pqc/zorro/build/zorro encrypt+sign   --tray /tmp/alice.tray /tmp/plain.txt > /tmp/alice.hyke
./pqc/zorro/build/zorro verify+decrypt --tray /tmp/alice.tray /tmp/alice.hyke | diff /tmp/plain.txt -

echo "All zorro smoke tests OK"
```

- [ ] **Step 9.4: Run libcrystals api_stability_tests**

```bash
./pqc/libcrystals-1.2/build/api_stability_test_10
./pqc/libcrystals-1.2/build/api_stability_test_11
./pqc/libcrystals-1.2/build/api_stability_test_12
```

Expected: all three exit with code 0 (build success = API contract enforced).

- [ ] **Step 9.5: Confirm no msgpack references remain in src/**

```bash
grep -r "msgpack\|tray_mp\|MSGPACK" \
    pqc/libcrystals-1.2/src/ \
    pqc/libcrystals-1.2/include/ \
    pqc/hybrid/src/ \
    pqc/zorro/src/ \
    pqc/penelope/src/ \
    pqc/libcrystals-1.2/CMakeLists.txt \
    pqc/libcrystals-1.2/install.sh \
    2>/dev/null
```

Expected: no output.

---

## Task 10: Update memory

- [ ] **Step 10.1: Update MEMORY.md and project memory**

Update `MEMORY.md` to reflect:
- msgpack support removed — trays are YAML-only
- `pqc/msgpack/` standalone library deleted
- `tray_mp` namespace removed from `crystals.hpp` (intentional API break in v1.2)
- `load_tray()` still exists but is YAML-only internally
- `MSGPACK_NO_BOOST` no longer propagated by the CMake target
- `msgpack-c/` vendored headers still present on disk but no longer referenced by any CMake target

Also update the note in MEMORY.md that says:
> `msgpack-c/` — REQUIRED, do not delete

to something like:
> `msgpack-c/` — vendored headers, no longer used; safe to delete
