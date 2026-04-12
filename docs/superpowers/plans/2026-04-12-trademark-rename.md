# Trademark Rename Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the three pqc tools (scotty→hybrid, obi-wan→zorro, padme→penelope) throughout all source, headers, tests, and docs — including all wire-format string literals — for trademark compliance.

**Architecture:** Pure renaming — no logic changes. The most sensitive work is in `libcrystals-1.2`, where wire-format magic bytes, PEM armor strings, and cryptographic domain-separation strings embed the old names. All changes break backward compatibility with existing encrypted files, signed files, tray UUIDs, and tokens; that is expected and accepted.

**Tech Stack:** C++17, CMake, BLAKE3, XKCP/KMAC256, OpenSSL. No Java changes needed (pqc-java has no product-name references).

---

## ⚠️ Backward-Compatibility Breaks

These cryptographic constants are changing. Existing files produced by the old tools will **not** be readable by the new tools:

| Old value | New value | Impact |
|-----------|-----------|--------|
| `"OBIWAN01"` (8B binary magic) | `"ZORRO001"` | Existing encrypted files unreadable |
| `"-----BEGIN/END OBIWAN ENCRYPTED FILE-----"` | `"-----BEGIN/END ZORRO ENCRYPTED FILE-----"` | Armor stripped incorrectly |
| `"-----BEGIN/END OBIWAN PW ENCRYPTED FILE-----"` | `"-----BEGIN/END ZORRO PW ENCRYPTED FILE-----"` | Same |
| `"obi-wan-hybrid-sig-v1"` (21 B, KDF domain) | `"zorro-hybrid-sig-v1"` (19 B) | HYKE signatures unverifiable; kCustomLen 21→19 |
| `"Crystals scotty tray-uuid v1"` (BLAKE3 domain) | `"Crystals hybrid tray-uuid v1"` | Existing tray files fail UUID check |
| `kTokenMagic = {'o','b','i','-','w','a','n','\0'}` | `{'z','o','r','r','o','\0','\0','\0'}` | Existing tokens invalid |

---

## Task 1: Rename Tool Directories

**Files:**
- Rename: `pqc/scotty/` → `pqc/hybrid/`
- Rename: `pqc/obi-wan/` → `pqc/zorro/`
- Rename: `pqc/padme/` → `pqc/penelope/`
- Rename: `pqc/docs/img/padme.png` → `pqc/docs/img/penelope.png`

- [ ] **Step 1: Rename directories via git mv**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc
git mv scotty hybrid
git mv obi-wan zorro
git mv padme penelope
git mv docs/img/padme.png docs/img/penelope.png
```

- [ ] **Step 2: Verify renames**

```bash
ls /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc
```

Expected: `hybrid  zorro  penelope` present; `scotty  obi-wan  padme` absent.

```bash
git status --short | grep -E "^R"
```

Expected: four `R ` (renamed) lines for the four renames.

- [ ] **Step 3: Commit**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc
git add -A
git commit -m "rename: scotty→hybrid, obi-wan→zorro, padme→penelope (directories)"
```

---

## Task 2: Update CMakeLists.txt Files

**Files:**
- Modify: `pqc/hybrid/CMakeLists.txt`
- Modify: `pqc/zorro/CMakeLists.txt`
- Modify: `pqc/penelope/CMakeLists.txt`

- [ ] **Step 1: Update hybrid/CMakeLists.txt**

Change:
```cmake
project(scotty LANGUAGES C CXX)
```
To:
```cmake
project(hybrid LANGUAGES C CXX)
```

Change:
```cmake
add_executable(scotty src/main.cpp)
target_link_libraries(scotty PRIVATE
    Crystals::crystals
    OpenSSL::Crypto
)
target_compile_options(scotty PRIVATE -O2 -Wall -Wextra)
install(TARGETS scotty DESTINATION bin)
```
To:
```cmake
add_executable(hybrid src/main.cpp)
target_link_libraries(hybrid PRIVATE
    Crystals::crystals
    OpenSSL::Crypto
)
target_compile_options(hybrid PRIVATE -O2 -Wall -Wextra)
install(TARGETS hybrid DESTINATION bin)
```

- [ ] **Step 2: Update zorro/CMakeLists.txt**

Change:
```cmake
project(obi-wan LANGUAGES C CXX)
```
To:
```cmake
project(zorro LANGUAGES C CXX)
```

Change:
```cmake
add_executable(obi-wan src/main.cpp)
target_link_libraries(obi-wan PRIVATE
    Crystals::crystals
    OpenSSL::Crypto
)
target_compile_options(obi-wan PRIVATE -O2 -Wall -Wextra)
install(TARGETS obi-wan DESTINATION bin)
```
To:
```cmake
add_executable(zorro src/main.cpp)
target_link_libraries(zorro PRIVATE
    Crystals::crystals
    OpenSSL::Crypto
)
target_compile_options(zorro PRIVATE -O2 -Wall -Wextra)
install(TARGETS zorro DESTINATION bin)
```

- [ ] **Step 3: Update penelope/CMakeLists.txt**

Change:
```cmake
project(padme LANGUAGES C CXX)
```
To:
```cmake
project(penelope LANGUAGES C CXX)
```

Change every occurrence of `padme` in target names:
```cmake
add_executable(penelope
    src/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/lodepng.cpp
)
target_include_directories(penelope PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    src/
)
target_compile_options(penelope PRIVATE -O2 -Wall -Wextra)
target_link_libraries(penelope PRIVATE
    Crystals::crystals
    OpenSSL::Crypto
)
install(TARGETS penelope DESTINATION bin)
```

- [ ] **Step 4: Commit**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc
git add hybrid/CMakeLists.txt zorro/CMakeLists.txt penelope/CMakeLists.txt
git commit -m "rename: update CMakeLists.txt project/executable names"
```

---

## Task 3: Update libcrystals-1.2 Internal Wire Format Files

**Files:**
- Modify: `pqc/libcrystals-1.2/src/armor.cpp`
- Modify: `pqc/libcrystals-1.2/src/armor.hpp`
- Modify: `pqc/libcrystals-1.2/src/kdf.hpp`
- Modify: `pqc/libcrystals-1.2/src/pw_format.hpp`
- Modify: `pqc/libcrystals-1.2/src/token_format.hpp`

- [ ] **Step 1: Update armor.cpp**

File: `pqc/libcrystals-1.2/src/armor.cpp`

Change (line ~26):
```cpp
const char* magic = "OBIWAN01";
```
To:
```cpp
const char* magic = "ZORRO001";
```

Change (line ~98):
```cpp
if (std::memcmp(p, "OBIWAN01", 8) != 0)
```
To:
```cpp
if (std::memcmp(p, "ZORRO001", 8) != 0)
```

- [ ] **Step 2: Update armor.hpp**

File: `pqc/libcrystals-1.2/src/armor.hpp`

Change the comment:
```cpp
//   Magic:          8 bytes  "OBIWAN01"
```
To:
```cpp
//   Magic:          8 bytes  "ZORRO001"
```

Change the armor constants:
```cpp
static constexpr char kArmorBegin[] = "-----BEGIN OBIWAN ENCRYPTED FILE-----";
static constexpr char kArmorEnd[]   = "-----END OBIWAN ENCRYPTED FILE-----";
```
To:
```cpp
static constexpr char kArmorBegin[] = "-----BEGIN ZORRO ENCRYPTED FILE-----";
static constexpr char kArmorEnd[]   = "-----END ZORRO ENCRYPTED FILE-----";
```

- [ ] **Step 3: Update kdf.hpp**

File: `pqc/libcrystals-1.2/src/kdf.hpp`

Change (line ~81 comment):
```cpp
// custom  = "obi-wan-hybrid-sig-v1"
```
To:
```cpp
// custom  = "zorro-hybrid-sig-v1"
```

Change (lines ~90-91):
```cpp
    static const char* kCustom = "obi-wan-hybrid-sig-v1";
    static const size_t kCustomLen = 21; // strlen("obi-wan-hybrid-sig-v1")
```
To:
```cpp
    static const char* kCustom = "zorro-hybrid-sig-v1";
    static const size_t kCustomLen = 19; // strlen("zorro-hybrid-sig-v1")
```

Change (line ~110 comment):
```cpp
// ctx = KMAC256(key=pk_classical, msg=pk_pq || "obi-wan-hybrid-sig-v1", outlen=512 bits)
```
To:
```cpp
// ctx = KMAC256(key=pk_classical, msg=pk_pq || "zorro-hybrid-sig-v1", outlen=512 bits)
```

Change (line ~116):
```cpp
    static const char* kDomain    = "obi-wan-hybrid-sig-v1";
```
To:
```cpp
    static const char* kDomain    = "zorro-hybrid-sig-v1";
```

- [ ] **Step 4: Update pw_format.hpp**

File: `pqc/libcrystals-1.2/src/pw_format.hpp`

Change:
```cpp
static constexpr char kPwArmorBegin[] = "-----BEGIN OBIWAN PW ENCRYPTED FILE-----";
static constexpr char kPwArmorEnd[]   = "-----END OBIWAN PW ENCRYPTED FILE-----";
```
To:
```cpp
static constexpr char kPwArmorBegin[] = "-----BEGIN ZORRO PW ENCRYPTED FILE-----";
static constexpr char kPwArmorEnd[]   = "-----END ZORRO PW ENCRYPTED FILE-----";
```

- [ ] **Step 5: Update token_format.hpp**

File: `pqc/libcrystals-1.2/src/token_format.hpp`

Change the comment (line ~12):
```cpp
// [MAGIC 8B "obi-wan\0"][VERSION 2B: 0x01 0x00]
```
To:
```cpp
// [MAGIC 8B "zorro\0\0\0"][VERSION 2B: 0x01 0x00]
```

Change the magic constant:
```cpp
static constexpr uint8_t kTokenMagic[8] = {'o','b','i','-','w','a','n','\0'};
```
To:
```cpp
static constexpr uint8_t kTokenMagic[8] = {'z','o','r','r','o','\0','\0','\0'};
```

- [ ] **Step 6: Commit**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc
git add libcrystals-1.2/src/armor.cpp libcrystals-1.2/src/armor.hpp \
        libcrystals-1.2/src/kdf.hpp libcrystals-1.2/src/pw_format.hpp \
        libcrystals-1.2/src/token_format.hpp
git commit -m "rename: update wire format strings in libcrystals-1.2 internal files (OBIWAN→ZORRO, obi-wan→zorro domain strings)"
```

---

## Task 4: Update libcrystals-1.2 Public Header (crystals.hpp)

**Files:**
- Modify: `pqc/libcrystals-1.2/include/crystals/crystals.hpp`

This file duplicates many of the wire format constants from the internal files for public API consumers.

- [ ] **Step 1: Update ZORRO wire format section comment**

Change (line ~256):
```cpp
// ── OBIWAN wire format ────────────────────────────────────────────────────────
```
To:
```cpp
// ── ZORRO wire format ─────────────────────────────────────────────────────────
```

- [ ] **Step 2: Update ZORRO armor constants**

Change:
```cpp
static constexpr char kArmorBegin[] = "-----BEGIN OBIWAN ENCRYPTED FILE-----";
static constexpr char kArmorEnd[]   = "-----END OBIWAN ENCRYPTED FILE-----";
```
To:
```cpp
static constexpr char kArmorBegin[] = "-----BEGIN ZORRO ENCRYPTED FILE-----";
static constexpr char kArmorEnd[]   = "-----END ZORRO ENCRYPTED FILE-----";
```

- [ ] **Step 3: Update ZORRO PW armor constants**

Change (line ~552-553):
```cpp
static constexpr char kPwArmorBegin[] = "-----BEGIN OBIWAN PW ENCRYPTED FILE-----";
static constexpr char kPwArmorEnd[]   = "-----END OBIWAN PW ENCRYPTED FILE-----";
```
To:
```cpp
static constexpr char kPwArmorBegin[] = "-----BEGIN ZORRO PW ENCRYPTED FILE-----";
static constexpr char kPwArmorEnd[]   = "-----END ZORRO PW ENCRYPTED FILE-----";
```

- [ ] **Step 4: Update derive_key_hyke domain string**

Change (line ~1176):
```cpp
    static const char* kCustom = "obi-wan-hybrid-sig-v1";
```
To:
```cpp
    static const char* kCustom = "zorro-hybrid-sig-v1";
```

- [ ] **Step 5: Update compute_hyke_ctx domain string**

Change (line ~1199):
```cpp
    static const char* kDomain    = "obi-wan-hybrid-sig-v1";
```
To:
```cpp
    static const char* kDomain    = "zorro-hybrid-sig-v1";
```

- [ ] **Step 6: Verify no remaining obi-wan/OBIWAN in crystals.hpp**

```bash
grep -n "OBIWAN\|obi.wan" /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/libcrystals-1.2/include/crystals/crystals.hpp
```

Expected: no output.

- [ ] **Step 7: Commit**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc
git add libcrystals-1.2/include/crystals/crystals.hpp
git commit -m "rename: update wire format constants in public crystals.hpp header"
```

---

## Task 5: Update libcrystals-1.2 Tray Domain String + Comments

**Files:**
- Modify: `pqc/libcrystals-1.2/src/tray.cpp`
- Modify: `pqc/libcrystals-1.2/src/tray_reader.cpp`
- Modify: `pqc/libcrystals-1.2/src/kyber_api.hpp`
- Modify: `pqc/libcrystals-1.2/src/dilithium_api.hpp`
- Modify: `pqc/libcrystals-1.2/README.md`

- [ ] **Step 1: Update tray.cpp BLAKE3 domain key**

File: `pqc/libcrystals-1.2/src/tray.cpp`

Change (line ~23):
```cpp
    blake3_hasher_init_derive_key(&h, "Crystals scotty tray-uuid v1");
```
To:
```cpp
    blake3_hasher_init_derive_key(&h, "Crystals hybrid tray-uuid v1");
```

- [ ] **Step 2: Update tray_reader.cpp BLAKE3 domain key and comment**

File: `pqc/libcrystals-1.2/src/tray_reader.cpp`

Change comment (line ~63):
```cpp
// key-derivation algorithm as scotty.  Rejects trays whose stored UUID does
```
To:
```cpp
// key-derivation algorithm as hybrid.  Rejects trays whose stored UUID does
```

Change (line ~68):
```cpp
    blake3_hasher_init_derive_key(&h, "Crystals scotty tray-uuid v1");
```
To:
```cpp
    blake3_hasher_init_derive_key(&h, "Crystals hybrid tray-uuid v1");
```

- [ ] **Step 3: Update kyber_api.hpp comment**

File: `pqc/libcrystals-1.2/src/kyber_api.hpp`

Change (line ~6):
```cpp
// Merged Kyber API: keypair (scotty) + encaps/decaps (obi-wan)
```
To:
```cpp
// Merged Kyber API: keypair (hybrid) + encaps/decaps (zorro)
```

- [ ] **Step 4: Update dilithium_api.hpp comment**

File: `pqc/libcrystals-1.2/src/dilithium_api.hpp`

Change (line ~6):
```cpp
// Merged Dilithium API: keypair (scotty) + sign/verify (obi-wan)
```
To:
```cpp
// Merged Dilithium API: keypair (hybrid) + sign/verify (zorro)
```

- [ ] **Step 5: Update libcrystals-1.2/README.md**

File: `pqc/libcrystals-1.2/README.md`

Change (line ~3):
```
Hybrid post-quantum crypto library with a frozen public API, backend for scotty, obi-wan, and padme.
```
To:
```
Hybrid post-quantum crypto library with a frozen public API, backend for hybrid, zorro, and penelope.
```

- [ ] **Step 6: Commit**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc
git add libcrystals-1.2/src/tray.cpp libcrystals-1.2/src/tray_reader.cpp \
        libcrystals-1.2/src/kyber_api.hpp libcrystals-1.2/src/dilithium_api.hpp \
        libcrystals-1.2/README.md
git commit -m "rename: update tray UUID domain key (scotty→hybrid) and API comments"
```

---

## Task 6: Update libcrystals-1.2 Tests

**Files:**
- Modify: `pqc/libcrystals-1.2/test/test_crystals.cpp`

- [ ] **Step 1: Update Section 8 armor test**

File: `pqc/libcrystals-1.2/test/test_crystals.cpp`

Change (line ~261-264):
```cpp
// ── Section 8: OBIWAN armor ───────────────────────────────────────────────────
...
    std::printf("=== Section 8: OBIWAN armor ===\n");
```
To:
```cpp
// ── Section 8: ZORRO armor ────────────────────────────────────────────────────
...
    std::printf("=== Section 8: ZORRO armor ===\n");
```

Change (lines ~275-276):
```cpp
    CHECK(armored.find("-----BEGIN OBIWAN ENCRYPTED FILE-----") != std::string::npos);
    CHECK(armored.find("-----END OBIWAN ENCRYPTED FILE-----") != std::string::npos);
```
To:
```cpp
    CHECK(armored.find("-----BEGIN ZORRO ENCRYPTED FILE-----") != std::string::npos);
    CHECK(armored.find("-----END ZORRO ENCRYPTED FILE-----") != std::string::npos);
```

Change (line ~378):
```cpp
        CHECK(armored.find("-----BEGIN OBIWAN PW ENCRYPTED FILE-----") != std::string::npos);
```
To:
```cpp
        CHECK(armored.find("-----BEGIN ZORRO PW ENCRYPTED FILE-----") != std::string::npos);
```

- [ ] **Step 2: Scan for any remaining OBIWAN/obi-wan in test file**

```bash
grep -n "OBIWAN\|obi.wan\|scotty\|padme" /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/libcrystals-1.2/test/test_crystals.cpp
```

Expected: no output.

- [ ] **Step 3: Commit**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc
git add libcrystals-1.2/test/test_crystals.cpp
git commit -m "rename: update test assertions for ZORRO armor strings"
```

---

## Task 7: Update Tool Source Files

**Files:**
- Modify: `pqc/zorro/src/main.cpp`
- Modify: `pqc/penelope/src/main.cpp`
- Modify: `pqc/penelope/src/encaps_crypto.hpp`

Note: `pqc/hybrid/src/main.cpp` has no hard-coded product name strings (uses argv[0]); no changes needed there.

- [ ] **Step 1: Update zorro/src/main.cpp**

File: `pqc/zorro/src/main.cpp`

Change (line ~35):
```cpp
        "  encrypt:   reads <target-file>, writes OBIWAN armored ciphertext to stdout\n"
```
To:
```cpp
        "  encrypt:   reads <target-file>, writes ZORRO armored ciphertext to stdout\n"
```

Then scan for any remaining references:
```bash
grep -n "OBIWAN\|obi.wan\|obi_wan\|scotty\|padme" /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/zorro/src/main.cpp
```
Expected: no output (the armor string constants come from the crystals.hpp header, which is already updated).

- [ ] **Step 2: Update penelope/src/main.cpp — rename OBIWAN_* constants**

File: `pqc/penelope/src/main.cpp`

Rename layout constants (lines ~524-526):
```cpp
static const unsigned OBIWAN_IMG_W  = 500;
static const unsigned OBIWAN_MARGIN = 12;
static const unsigned OBIWAN_DATA_W = OBIWAN_IMG_W - 2 * OBIWAN_MARGIN;  // 476
```
To:
```cpp
static const unsigned ZORRO_IMG_W  = 500;
static const unsigned ZORRO_MARGIN = 12;
static const unsigned ZORRO_DATA_W = ZORRO_IMG_W - 2 * ZORRO_MARGIN;  // 476
```

Then do a global rename of every remaining `OBIWAN_` → `ZORRO_` in this file (there are many uses: `OBIWAN_MARGIN`, `OBIWAN_DATA_W`, `OBIWAN_IMG_W`). The `replace_all` flag on Edit handles this.

- [ ] **Step 3: Update penelope/src/main.cpp — rename struct and function**

Change:
```cpp
struct OBIWANMeta { std::string format; size_t data_len = 0; };

static OBIWANMeta parse_obiwan_meta(const std::string& text) {
    OBIWANMeta m;
```
To:
```cpp
struct ZorroMeta { std::string format; size_t data_len = 0; };

static ZorroMeta parse_zorro_meta(const std::string& text) {
    ZorroMeta m;
```

Update the call site (line ~890):
```cpp
    OBIWANMeta meta;
```
To:
```cpp
    ZorroMeta meta;
```

And the function call (line ~890+):
```cpp
// wherever parse_obiwan_meta is called — change to parse_zorro_meta
```

- [ ] **Step 4: Update penelope/src/main.cpp — rename format detection strings**

Change (line ~532):
```cpp
    if (first_line.find("BEGIN OBIWAN PW ENCRYPTED") != std::string::npos) return "pwenc";
```
To:
```cpp
    if (first_line.find("BEGIN ZORRO PW ENCRYPTED") != std::string::npos) return "pwenc";
```

Change (line ~534):
```cpp
    if (first_line.find("BEGIN OBIWAN ENCRYPTED")    != std::string::npos) return "obiwan";
```
To:
```cpp
    if (first_line.find("BEGIN ZORRO ENCRYPTED")    != std::string::npos) return "zorro";
```

- [ ] **Step 5: Update penelope/src/main.cpp — rename format type return value**

Note: the `return "obiwan"` on line ~534 is also changed in step 4 above to `return "zorro"`.
Find all subsequent uses of the `"obiwan"` format string (comparisons against `fmt == "obiwan"`) and change them to `fmt == "zorro"`. Do a global search in this file:

```bash
grep -n '"obiwan"' /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/penelope/src/main.cpp
```

Change every `"obiwan"` → `"zorro"`.

- [ ] **Step 6: Update penelope/src/main.cpp — rename hardcoded armor strings**

Change (lines ~657-661):
```cpp
        begin_marker = "-----BEGIN OBIWAN PW ENCRYPTED FILE-----";
        end_marker   = "-----END OBIWAN PW ENCRYPTED FILE-----";
        ...
        begin_marker = "-----BEGIN OBIWAN ENCRYPTED FILE-----";
        end_marker   = "-----END OBIWAN ENCRYPTED FILE-----";
```
To:
```cpp
        begin_marker = "-----BEGIN ZORRO PW ENCRYPTED FILE-----";
        end_marker   = "-----END ZORRO PW ENCRYPTED FILE-----";
        ...
        begin_marker = "-----BEGIN ZORRO ENCRYPTED FILE-----";
        end_marker   = "-----END ZORRO ENCRYPTED FILE-----";
```

- [ ] **Step 7: Update penelope/src/main.cpp — rename title strings**

Change (lines ~695-697):
```cpp
    if (fmt == "hyke")    title = "OBIWAN HYKE SIGNED FILE - "    + level_str;
    else if (fmt == "pwenc") title = "OBIWAN PW ENCRYPTED FILE - " + level_str;
    else                  title = "OBIWAN ENCRYPTED FILE - "       + level_str;
```
To:
```cpp
    if (fmt == "hyke")    title = "ZORRO HYKE SIGNED FILE - "    + level_str;
    else if (fmt == "pwenc") title = "ZORRO PW ENCRYPTED FILE - " + level_str;
    else                  title = "ZORRO ENCRYPTED FILE - "       + level_str;
```

- [ ] **Step 8: Update penelope/src/main.cpp — usage text and error messages**

Change (line ~938):
```cpp
        "  pngify       Convert an obi-wan armored file (OBIWAN/HYKE/PWENC) into a PNG\n"
```
To:
```cpp
        "  pngify       Convert a zorro armored file (ZORRO/HYKE/PWENC) into a PNG\n"
```

Change (line ~952):
```cpp
        "  --in  <file>           Input armored file (OBIWAN encrypted, HYKE signed, or PWENC)\n"
```
To:
```cpp
        "  --in  <file>           Input armored file (ZORRO encrypted, HYKE signed, or PWENC)\n"
```

Change (line ~299):
```cpp
                + ") is not in the rainbow palette — not a padme PNG?");
```
To:
```cpp
                + ") is not in the rainbow palette — not a penelope PNG?");
```

Change (line ~1123):
```cpp
        std::cerr << "Error: no crystals-tray iTXt chunk — not a padme PNG\n";
```
To:
```cpp
        std::cerr << "Error: no crystals-tray iTXt chunk — not a penelope PNG\n";
```

- [ ] **Step 9: Update penelope/src/encaps_crypto.hpp**

File: `pqc/penelope/src/encaps_crypto.hpp`

Change (lines ~2-3):
```cpp
// Scrypt KDF wrapper for padme encaps/decaps.
// AES-256-GCM helpers re-use the same symmetric.hpp used by obi-wan.
```
To:
```cpp
// Scrypt KDF wrapper for penelope encaps/decaps.
// AES-256-GCM helpers re-use the same symmetric.hpp used by zorro.
```

- [ ] **Step 10: Scan for any remaining old names in tool sources**

```bash
grep -rn "OBIWAN\|obi.wan\|obi_wan\|scotty\|padme" \
  /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/zorro/src/ \
  /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/penelope/src/ \
  /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/hybrid/src/
```

Expected: no output.

- [ ] **Step 11: Commit**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc
git add zorro/src/main.cpp penelope/src/main.cpp penelope/src/encaps_crypto.hpp
git commit -m "rename: update source files in zorro and penelope"
```

---

## Task 8: Update zorro/README.md and penelope/README.md

**Files:**
- Modify: `pqc/zorro/README.md`
- Modify: `pqc/penelope/README.md`

- [ ] **Step 1: Update zorro/README.md**

Read the file first, then do a global search-and-replace:
- `obi-wan` → `zorro`
- `OBIWAN` → `ZORRO`
- `scotty` → `hybrid` (if any references to the tray generator)

- [ ] **Step 2: Update penelope/README.md**

Read the file first, then do a global search-and-replace:
- `padme` → `penelope`
- `obi-wan` → `zorro`
- `OBIWAN` → `ZORRO`
- `scotty` → `hybrid`

- [ ] **Step 3: Verify READMEs**

```bash
grep -in "obi.wan\|OBIWAN\|scotty\|padme" \
  /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/zorro/README.md \
  /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/penelope/README.md
```

Expected: no output.

- [ ] **Step 4: Commit**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc
git add zorro/README.md penelope/README.md
git commit -m "rename: update zorro and penelope README files"
```

---

## Task 9: Update Top-Level Documentation

**Files:**
- Modify: `pqc/README.md`
- Modify: `pqc/ALGORITHMS.md`
- Modify: `pqc/CLAUDE.md`
- Modify: `pqc/PASSWORD-ENC.md`
- Modify: `pqc/UUID-DERIVATION.md`
- Modify: `pqc/XKCP.md`
- Modify: `pqc/BLAKE3-BUILD.md`

- [ ] **Step 1: Update pqc/README.md**

This is the largest doc change. Read the file. Apply these replacements globally:
- `scotty` → `hybrid` (tool name and directory)
- `obi-wan` → `zorro`
- `OBIWAN` → `ZORRO`
- `padme` → `penelope`
- `docs/img/padme.png` → `docs/img/penelope.png`
- Build paths: `pqc/scotty/build/scotty` → `pqc/hybrid/build/hybrid`, etc.

After edits, verify:
```bash
grep -in "obi.wan\|scotty\|OBIWAN\|padme" /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/README.md
```
Expected: no output.

- [ ] **Step 2: Update pqc/ALGORITHMS.md**

Global replacements:
- `obi-wan` → `zorro`
- `OBIWAN` → `ZORRO`
- `scotty` → `hybrid`
- `"OBIWAN01"` → `"ZORRO001"`
- `"obi-wan-hybrid-sig-v1"` → `"zorro-hybrid-sig-v1"` (update the byte count comment too: 21 bytes → 19 bytes)
- `obi-wan-hybrid-sig-v1` → `zorro-hybrid-sig-v1` (bare occurrences in code blocks)

After edits:
```bash
grep -in "obi.wan\|scotty\|OBIWAN\|padme" /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/ALGORITHMS.md
```
Expected: no output.

- [ ] **Step 3: Update pqc/CLAUDE.md, PASSWORD-ENC.md, UUID-DERIVATION.md, XKCP.md, BLAKE3-BUILD.md**

For each file, read it and apply global replacements:
- `scotty` → `hybrid`
- `obi-wan` → `zorro`
- `OBIWAN` → `ZORRO`
- `padme` → `penelope`

Verify each:
```bash
grep -in "obi.wan\|scotty\|OBIWAN\|padme" \
  /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/CLAUDE.md \
  /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/PASSWORD-ENC.md \
  /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/UUID-DERIVATION.md \
  /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/XKCP.md \
  /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/BLAKE3-BUILD.md
```
Expected: no output.

- [ ] **Step 4: Commit**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc
git add README.md ALGORITHMS.md CLAUDE.md PASSWORD-ENC.md UUID-DERIVATION.md XKCP.md BLAKE3-BUILD.md
git commit -m "rename: update top-level documentation"
```

---

## Task 10: Update Historical Plan/Spec Docs

**Files (content updates only — do not rename the files):**
- `pqc/docs/superpowers/plans/2026-03-21-obi-wan-libcrystals-backend.md`
- `pqc/docs/superpowers/plans/2026-03-21-scotty-libcrystals-backend.md`
- `pqc/docs/superpowers/plans/2026-03-23-obi-wan-padme-libcrystals-1.2.md`
- `pqc/docs/superpowers/plans/2026-03-24-hybrid-signatures.md`
- `pqc/docs/superpowers/plans/2026-03-25-remove-msgpack.md`
- `pqc/docs/superpowers/plans/2026-03-28-blake3-digest-api.md`
- `pqc/docs/superpowers/plans/2026-04-05-mceliece-hyke-support.md`
- `pqc/docs/superpowers/specs/2026-03-21-scotty-libcrystals-backend-design.md`
- `pqc/docs/superpowers/specs/2026-03-24-hybrid-signatures-design.md`
- `pqc/docs/superpowers/specs/2026-03-28-blake3-digest-api-design.md`
- `pqc/docs/superpowers/specs/2026-04-05-mceliece-hyke-support-design.md`

- [ ] **Step 1: Update each plan/spec doc**

For each file, apply global replacements:
- `scotty` → `hybrid`
- `obi-wan` → `zorro`
- `OBIWAN` → `ZORRO`
- `padme` → `penelope`

Note: file names preserve old names intentionally (they are historical records with date-based names; the old name in the filename provides context about when/what they were written for).

- [ ] **Step 2: Verify**

```bash
grep -rln "obi.wan\|scotty\|OBIWAN\|padme" \
  /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/docs/superpowers/
```
Expected: no output.

- [ ] **Step 3: Commit**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc
git add docs/superpowers/
git commit -m "rename: update historical plan/spec docs (content only)"
```

---

## Task 11: Rebuild and Smoke Test

- [ ] **Step 1: Rebuild libcrystals-1.2**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc
rm -rf libcrystals-1.2/build
cmake -S libcrystals-1.2 -B libcrystals-1.2/build
cmake --build libcrystals-1.2/build -j$(nproc)
```
Expected: no errors.

- [ ] **Step 2: Run libcrystals tests**

```bash
./pqc/libcrystals-1.2/build/test_crystals
```
Expected: Section 8 now prints `=== Section 8: ZORRO armor ===` and all CHECKs pass.

- [ ] **Step 3: Reinstall libcrystals**

```bash
sudo bash /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/libcrystals-1.2/install.sh
```
Expected: installs updated libcrystals-1.2.a with new wire format strings to /usr/local.

- [ ] **Step 4: Rebuild hybrid**

```bash
rm -rf /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/hybrid/build
cmake -S pqc/hybrid -B pqc/hybrid/build
cmake --build pqc/hybrid/build -j$(nproc)
```
Expected: binary produced at `pqc/hybrid/build/hybrid`.

- [ ] **Step 5: Rebuild zorro**

```bash
rm -rf /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/zorro/build
cmake -S pqc/zorro -B pqc/zorro/build
cmake --build pqc/zorro/build -j$(nproc)
```
Expected: binary produced at `pqc/zorro/build/zorro`.

- [ ] **Step 6: Rebuild penelope**

```bash
rm -rf /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/penelope/build
cmake -S pqc/penelope -B pqc/penelope/build
cmake --build pqc/penelope/build -j$(nproc)
```
Expected: binary produced at `pqc/penelope/build/penelope`.

- [ ] **Step 7: Smoke test — hybrid keygen**

```bash
/mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/hybrid/build/hybrid keygen --alias alice --profile level2-25519
```
Expected: YAML tray output with `type: tray`, two KEM slots, two sig slots.

- [ ] **Step 8: Smoke test — zorro encrypt/decrypt roundtrip**

```bash
echo "hello zorro" > /tmp/plain.txt
/mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/hybrid/build/hybrid keygen --alias alice --profile level2-25519 > /tmp/alice.tray
/mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/zorro/build/zorro encrypt --tray /tmp/alice.tray /tmp/plain.txt > /tmp/out.armored
head -1 /tmp/out.armored
```
Expected: `-----BEGIN ZORRO ENCRYPTED FILE-----`

```bash
/mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/zorro/build/zorro decrypt --tray /tmp/alice.tray /tmp/out.armored
```
Expected: `hello zorro`

- [ ] **Step 9: Smoke test — HYKE sign/verify**

```bash
/mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/zorro/build/zorro sign --tray /tmp/alice.tray /tmp/plain.txt > /tmp/plain.hyke
/mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc/zorro/build/zorro verify --tray /tmp/alice.tray /tmp/plain.hyke
```
Expected: `hello zorro` (verify output matches original).

- [ ] **Step 10: Final scan — confirm no old names remain in source/headers**

```bash
grep -rn --include="*.cpp" --include="*.hpp" --include="*.h" --include="*.c" \
  --include="CMakeLists.txt" \
  -i "scotty\|obi.wan\|obi_wan\|OBIWAN\|padme" \
  /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc \
  --exclude-dir=.git --exclude-dir=build 2>/dev/null
```
Expected: no output.

- [ ] **Step 11: Commit**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pqc
git add -A
git commit -m "rebuild: verified all three tools build and pass smoke tests with new names"
```

---

## Task 12: Update Session Memory

- [ ] **Step 1: Update MEMORY.md and memory files**

Update the auto-memory at `/home/dave/.claude/projects/-mnt-c-Users-daves-OneDrive-Desktop-Crystals/memory/` to reflect the new tool names:
- `scotty` → `hybrid` everywhere
- `obi-wan` → `zorro` everywhere
- `padme` → `penelope` everywhere
- Wire format magic: `OBIWAN01` → `ZORRO001`
- Domain strings updated
- Binary paths updated: `scotty/build/scotty` → `hybrid/build/hybrid`, etc.

---

## Spec Coverage Self-Check

| Requirement | Covered by |
|-------------|------------|
| scotty → hybrid (folder, binary, CMake) | Tasks 1, 2 |
| obi-wan → zorro (folder, binary, CMake) | Tasks 1, 2 |
| padme → penelope (folder, binary, CMake) | Tasks 1, 2 |
| OBIWAN wire magic → ZORRO | Tasks 3, 4 |
| obi-wan KDF domain string → zorro | Tasks 3, 4 |
| OBIWAN armor strings → ZORRO | Tasks 3, 4 |
| OBIWAN PW armor → ZORRO | Tasks 3, 4 |
| Token magic → zorro | Task 3 |
| Tray UUID domain → hybrid | Task 5 |
| Internal comments updated | Tasks 5, 7 |
| Tests updated + passing | Task 6, 11 |
| All docs updated | Tasks 8, 9, 10 |
| pqc-java | No changes needed (confirmed: zero matches) |
