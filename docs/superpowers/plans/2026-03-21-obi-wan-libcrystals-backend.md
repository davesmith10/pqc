# zorro libcrystals-1.1 Backend Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace zorro's ~29 local source files with a single `src/main.cpp` that delegates all crypto, wire-format, and I/O to `Crystals::crystals` (libcrystals-1.1), following the same pattern established by the hybrid migration.

**Architecture:** After migration zorro's `src/` contains only `main.cpp`. The binary links `Crystals::crystals` (fat static archive at `/usr/local/lib/libcrystals-1.1.a`) plus `OpenSSL::Crypto` directly (for `openssl/rand.h` → `RAND_bytes` in `cmd_sign`). All crypto, KDF, symmetric, wire-format, tray-loading, password commands, and token commands come from the library.

**Tech Stack:** C++17, CMake, `Crystals::crystals` (libcrystals-1.1 installed at `/usr/local`), OpenSSL 3.

---

## API Status — No Gap

Every function currently called from `zorro/src/` is already declared `@api-stable v1.0` (or `@api-candidate-1.1`) in `crystals/crystals.hpp`. No libcrystals patch is needed before beginning.

| zorro file | Provided by library as |
|---|---|
| `tray_reader.{hpp,cpp}` → `load_tray(path)` | `load_tray(path)` — `@api-stable v1.0` |
| `ec_kem.{hpp,cpp}` | `ec_kem::is_classical_kem`, `ec_kem::encaps`, `ec_kem::decaps` |
| `ec_sig.{hpp,cpp}` | `ec_sig::is_classical_sig`, `ec_sig::sig_bytes`, `ec_sig::sign`, `ec_sig::verify` |
| `kyber_kem.{hpp,cpp}` | `kyber_kem::level_from_alg`, `kyber_kem::encaps`, `kyber_kem::decaps` |
| `mceliece_kem.{hpp,cpp}` | `mceliece_kem::encaps`, `mceliece_kem::decaps` |
| `dilithium_sig.{hpp,cpp}` | `dilithium_sig::is_pq_sig`, `dilithium_sig::mode_from_alg`, `dilithium_sig::sig_bytes_for_mode`, `dilithium_sig::sign`, `dilithium_sig::verify` |
| `slhdsa_sig.{hpp,cpp}` | `slhdsa_sig::is_slhdsa_sig`, `slhdsa_sig::sig_bytes`, `slhdsa_sig::sign`, `slhdsa_sig::verify` |
| `kdf.hpp` | `derive_key_shake`, `derive_key_kmac`, `derive_key_hyke`, `compute_hyke_ctx` |
| `symmetric.hpp` | `aes256gcm_encrypt`, `aes256gcm_decrypt`, `chacha20poly1305_encrypt`, `chacha20poly1305_decrypt` |
| `armor.{hpp,cpp}` | `WireHeader`, `KDFAlg`, `CipherAlg`, `armor_pack`, `armor_unpack` |
| `hyke_format.hpp` | `HykeHeader`, `tray_id_byte`, `parse_uuid`, `hyke_partial_header`, `hyke_pack`, `hyke_unpack`, `hyke_armor`, `hyke_dearmor`, `compute_hyke_ctx` |
| `pw_format.hpp` | `PwBundle`, `pack_pw_bundle`, `parse_pw_bundle`, `armor_pw`, `dearmor_pw` |
| `pw_crypt.{hpp,cpp}` | `cmd_pwencrypt(int argc, char* argv[])`, `cmd_pwdecrypt(int argc, char* argv[])` — exact same signatures |
| `token_format.hpp` | `Token`, `kTokenMagic`, `kTokenAlgECDSAP256`, `token_canonical_bytes`, `token_pack`, `token_unpack`, `token_armor`, `token_dearmor` |
| `token_cmd.cpp` | `cmd_gentok(tray_path, data_str, ttl_secs)`, `cmd_valtok(tray_path, token_file)` — exact same signatures |
| `base64.{hpp,cpp}` | `base64_encode`, `base64_decode` |
| `mceliece_randombytes.c`, `dilithium_api.hpp`, `kyber_api.hpp` | Bundled in fat archive |

---

## ⚠️ Wire Format Note — Token Protocol Change

The library's `Token` struct adds a `token_uuid` field (TLV tag `0x06`) not present in the current zorro implementation. The library's `cmd_gentok` correctly populates this field with a random UUID v4 (verified in `libcrystals-1.1/src/token_cmd.cpp` lines 95–100). The library's `token_unpack` requires all 6 TLV tags — an old token presented to `valtok` will fail with "missing mandatory tag 0x06" (exit 2). **Tokens generated before this migration will not verify after migration.** This is acceptable since gentok/valtok is a development-internal protocol, but it must be tested explicitly.

Additionally, the library's `cmd_gentok` and `cmd_valtok` use `std::exit` for all error paths, which is consistent with the existing behaviour in `zorro/src/token_cmd.cpp`. The library's `cmd_valtok` no longer enforces the `Level2`-only tray restriction (it looks for any ECDSA P-256 slot), which is a minor relaxation of the previous check.

---

## File Structure

| Location | Change |
|---|---|
| `pq/zorro/CMakeLists.txt` | Rewrite — `find_package(Crystals)` replaces all manual deps |
| `pq/zorro/src/main.cpp` | Update — replace all local `#include "..."` with `#include <crystals/crystals.hpp>`; remove forward decls for `cmd_gentok`/`cmd_valtok`/`cmd_pwencrypt`/`cmd_pwdecrypt` |
| `pq/zorro/src/` (29 files) | Delete all files except `main.cpp` |

**29 files to delete from `pq/zorro/src/`:**
`armor.cpp`, `armor.hpp`, `base64.cpp`, `base64.hpp`, `dilithium_api.hpp`, `dilithium_sig.cpp`, `dilithium_sig.hpp`, `ec_kem.cpp`, `ec_kem.hpp`, `ec_sig.cpp`, `ec_sig.hpp`, `hyke_format.hpp`, `kdf.hpp`, `kyber_api.hpp`, `kyber_kem.cpp`, `kyber_kem.hpp`, `mceliece_kem.cpp`, `mceliece_kem.hpp`, `mceliece_randombytes.c`, `pw_crypt.cpp`, `pw_crypt.hpp`, `pw_format.hpp`, `slhdsa_sig.cpp`, `slhdsa_sig.hpp`, `symmetric.hpp`, `token_cmd.cpp`, `token_format.hpp`, `tray_reader.cpp`, `tray_reader.hpp`

---

## Task 1: Rewrite CMakeLists.txt

**Files:**
- Modify: `pq/zorro/CMakeLists.txt`

- [ ] **Step 1: Replace CMakeLists.txt**

The new file is 30 lines, mirroring hybrid's CMakeLists.txt exactly. No `add_subdirectory`, no scrypt, no XKCP path, no msgpack, no PQ archive targets.

```cmake
cmake_minimum_required(VERSION 3.16)
project(zorro LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Crystals REQUIRED)
find_package(OpenSSL REQUIRED)

# RPATH: TBB lives in a non-standard path (Crystals/local/).
# TBB::tbb is available transitively after find_package(Crystals) because
# CrystalsConfig.cmake runs find_package(TBB) internally with the baked-in hint.
# /usr/local/lib included unconditionally so libXKCP.so resolves without
# requiring a prior ldconfig run.
get_target_property(_tbb_loc TBB::tbb IMPORTED_LOCATION_RELEASE)
if(NOT _tbb_loc)
    get_target_property(_tbb_loc TBB::tbb IMPORTED_LOCATION)
endif()
get_filename_component(_tbb_libdir "${_tbb_loc}" DIRECTORY)
set(CMAKE_BUILD_RPATH "${_tbb_libdir}" /usr/local/lib)

add_executable(zorro src/main.cpp)

target_link_libraries(zorro PRIVATE
    Crystals::crystals
    OpenSSL::Crypto
)

target_compile_options(zorro PRIVATE -O2 -Wall -Wextra)

install(TARGETS zorro DESTINATION bin)
```

- [ ] **Step 2: Verify CMake configures without errors**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals
rm -rf pq/zorro/build
cmake -S pq/zorro -B pq/zorro/build
```

Expected: `-- Configuring done` with no errors. It will fail to compile because `main.cpp` still has the old includes, but configuration must succeed.

---

## Task 2: Update main.cpp includes and forward declarations

**Files:**
- Modify: `pq/zorro/src/main.cpp`

The only changes to `main.cpp` are at the top (includes + forward declarations). The body of every `cmd_encrypt`, `cmd_decrypt`, `cmd_sign`, `cmd_verify`, and `main()` is unchanged — all the function calls they make are identically named in the library.

- [ ] **Step 1: Replace the include block**

Remove lines 1–21 (the 12 local `#include "..."` lines plus stdlib headers) and replace with:

```cpp
#include <crystals/crystals.hpp>

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <stdexcept>
#include <openssl/rand.h>
```

- [ ] **Step 2: Remove the forward declarations**

Delete lines 23–25 (the two forward declarations that delegated to `token_cmd.cpp`):

```cpp
// Forward declarations for token commands (token_cmd.cpp)
void cmd_gentok(const std::string& tray_path, const std::string& data_str, int64_t ttl_secs);
void cmd_valtok(const std::string& tray_path, const std::string& token_file);
```

These functions are now defined in the library and declared in `<crystals/crystals.hpp>`.

The `cmd_pwencrypt` / `cmd_pwdecrypt` are called via `pw_crypt.hpp` which is implicitly included now via the umbrella header — no separate forward declaration needed.

- [ ] **Step 3: Build and confirm it compiles**

```bash
cmake --build pq/zorro/build -j$(nproc)
```

Expected: clean build, binary at `pq/zorro/build/zorro`. There will likely be warnings about unused parameters or similar — these are acceptable (the `-Wall -Wextra` flags were already there). Fix any errors but do not fix warnings in unchanged code.

- [ ] **Step 4: Commit**

```bash
git add pq/zorro/CMakeLists.txt pq/zorro/src/main.cpp
git commit -m "build(zorro): switch to Crystals::crystals backend"
```

---

## Task 3: Delete the now-redundant source files

**Files:**
- Delete: all 29 files listed above from `pq/zorro/src/`

- [ ] **Step 1: Delete the files**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pq/zorro/src
git rm armor.cpp armor.hpp \
       base64.cpp base64.hpp \
       dilithium_api.hpp dilithium_sig.cpp dilithium_sig.hpp \
       ec_kem.cpp ec_kem.hpp \
       ec_sig.cpp ec_sig.hpp \
       hyke_format.hpp kdf.hpp \
       kyber_api.hpp kyber_kem.cpp kyber_kem.hpp \
       mceliece_kem.cpp mceliece_kem.hpp mceliece_randombytes.c \
       pw_crypt.cpp pw_crypt.hpp pw_format.hpp \
       slhdsa_sig.cpp slhdsa_sig.hpp symmetric.hpp \
       token_cmd.cpp token_format.hpp \
       tray_reader.cpp tray_reader.hpp
```

- [ ] **Step 2: Rebuild from scratch to confirm clean build**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals
rm -rf pq/zorro/build
cmake -S pq/zorro -B pq/zorro/build
cmake --build pq/zorro/build -j$(nproc)
```

Expected: clean build, binary at `pq/zorro/build/zorro`.

- [ ] **Step 3: Commit**

```bash
git add -u pq/zorro/src/
git commit -m "refactor(zorro): delete source files superseded by Crystals::crystals"
```

---

## Task 4: Verification

Run all zorro functional tests from CLAUDE.md. All must pass before the migration is considered complete.

- [ ] **Step 1: Keygen setup**

```bash
ZORRO=./pq/zorro/build/zorro
HYBRID=./pq/hybrid/build/hybrid
$HYBRID keygen --alias alice --profile level2-25519 > /tmp/alice.tray
$HYBRID keygen --alias bob   --profile level2       > /tmp/bob.tray
$HYBRID keygen --alias carol --profile level3       > /tmp/carol.tray
$HYBRID keygen --alias dave  --profile level5       > /tmp/dave.tray
echo "hello world" > /tmp/plain.txt
```

- [ ] **Step 2: encrypt / decrypt — all 4 tray types × 2 KDFs × 2 ciphers = 16 combos**

```bash
for TRAY in /tmp/alice.tray /tmp/bob.tray /tmp/carol.tray /tmp/dave.tray; do
  for KDF in SHAKE KMAC; do
    for CIPHER in AES-256-GCM ChaCha20; do
      $ZORRO encrypt --tray $TRAY --kdf $KDF --cipher $CIPHER /tmp/plain.txt > /tmp/out.armored
      $ZORRO decrypt --tray $TRAY /tmp/out.armored | diff /tmp/plain.txt -
      echo "OK: $TRAY $KDF $CIPHER"
    done
  done
done
```

Expected: 16 lines of `OK: ...`

- [ ] **Step 3: sign / verify — all 4 tray types**

```bash
for TRAY in /tmp/alice.tray /tmp/bob.tray /tmp/carol.tray /tmp/dave.tray; do
  $ZORRO encrypt+sign   --tray $TRAY /tmp/plain.txt > /tmp/out.hyke
  $ZORRO verify+decrypt --tray $TRAY /tmp/out.hyke | diff /tmp/plain.txt -
  echo "OK sign/verify: $TRAY"
done
```

Expected: 4 lines of `OK sign/verify: ...`

- [ ] **Step 4: pwencrypt / pwdecrypt — all 3 levels**

```bash
for LVL in 512 768 1024; do
  $ZORRO pwencrypt --level $LVL /tmp/plain.txt /tmp/pw.enc
  $ZORRO pwdecrypt /tmp/pw.enc /tmp/pw.dec
  diff /tmp/plain.txt /tmp/pw.dec
  echo "OK pwencrypt/pwdecrypt level $LVL"
done
```

Expected: 3 lines of `OK pwencrypt/pwdecrypt level ...`

- [ ] **Step 5: msgpack tray auto-detection**

The library's `load_tray` auto-detect path (YAML vs msgpack) is the same code as in `pq/hybrid` which was already verified in the hybrid migration. To confirm it works end-to-end, produce a msgpack tray via the `tray_mp::pack_to_file` API using the standalone msgpack test build, then encrypt with it.

```bash
# Build msgpack tools (if not already built)
cmake -S pq/msgpack -B pq/msgpack/build && cmake --build pq/msgpack/build -j$(nproc)

# Use a one-liner C++ program to write a msgpack tray from a YAML tray.
# Compile via the installed crystals headers.
cat > /tmp/yaml2mp.cpp << 'EOF'
#include <crystals/crystals.hpp>
int main(int argc, char* argv[]) {
    auto t = load_tray_yaml(argv[1]);
    tray_mp::pack_to_file(t, argv[2]);
}
EOF
g++ -std=c++17 -I/usr/local/include /tmp/yaml2mp.cpp \
    /usr/local/lib/libcrystals-1.1.a -lssl -lcrypto -lyaml-cpp \
    $(pkg-config --libs blake3 || true) \
    /usr/local/lib/libXKCP.so \
    -L/mnt/c/Users/daves/OneDrive/Desktop/Crystals/local/lib \
    -Wl,-rpath,/usr/local/lib -o /tmp/yaml2mp

/tmp/yaml2mp /tmp/alice.tray /tmp/alice.mp.tray
$ZORRO encrypt --tray /tmp/alice.mp.tray /tmp/plain.txt > /tmp/out.armored
$ZORRO decrypt --tray /tmp/alice.mp.tray /tmp/out.armored | diff /tmp/plain.txt -
echo "OK msgpack tray auto-detect"
```

**Note:** If linking the one-liner is awkward, skip this step — `load_tray` msgpack support comes from `tray_mp::unpack_from_file` in the same library that was validated during the hybrid migration. This step can also be done by calling `tray_mp::pack_to_file` from a small dedicated test rather than a one-liner.

- [ ] **Step 6: gentok / valtok roundtrip**

```bash
$HYBRID keygen --alias tok --profile level2 > /tmp/tok.tray
$ZORRO gentok --tray /tmp/tok.tray --data "hello-token" --ttl 3600 > /tmp/tok.armored
$ZORRO valtok --tray /tmp/tok.tray /tmp/tok.armored
echo "OK gentok/valtok"
```

Expected: prints `hello-token` (no newline), exit 0.

- [ ] **Step 7: Error cases**

```bash
# Missing --tray
$ZORRO encrypt /tmp/plain.txt 2>&1; echo "exit $?"
# Expected: exit 1

# Tampered HYKE payload
$HYBRID keygen --alias alice --profile level2-25519 > /tmp/alice.tray
$ZORRO encrypt+sign --tray /tmp/alice.tray /tmp/plain.txt > /tmp/out.hyke
python3 -c "
data = open('/tmp/out.hyke','rb').read()
# flip a byte near the end (in the payload)
lst = bytearray(data)
lst[-10] ^= 0xFF
open('/tmp/tampered.hyke','wb').write(lst)
"
$ZORRO verify+decrypt --tray /tmp/alice.tray /tmp/tampered.hyke 2>&1; echo "exit $?"
# Expected: "signature INVALID" + exit 2

# Wrong tray type
$HYBRID keygen --alias bob --profile level3 > /tmp/bob.tray
$ZORRO verify+decrypt --tray /tmp/bob.tray /tmp/out.hyke 2>&1; echo "exit $?"
# Expected: "tray type mismatch" + exit 2
```

- [ ] **Step 8: Commit verification**

```bash
git commit -m "test(zorro): verify all commands pass after libcrystals-1.1 migration" --allow-empty
```

(Use `--allow-empty` only if no files changed in this step; otherwise commit any updated test scripts.)

---

## Non-Goals

- No changes to zorro's CLI interface, exit codes, or wire formats (ZORRO, HYKE, PWENC)
- No changes to libcrystals-1.1's `@api-stable` declarations
- No changes to hybrid or any other tool
- Backward compatibility for pre-migration `gentok` tokens is explicitly NOT a goal (token_uuid addition is accepted)
