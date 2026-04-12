# libcrystals v1.2

Hybrid post-quantum crypto library with a frozen public API, backend for hybrid, zorro, and penelope.

## API contract

**The single public header is `crystals/crystals.hpp`.**

- Consumers must only `#include "crystals/crystals.hpp"` and must not include anything from `src/`.

Four compile-time stability tests enforce the contract:
- `api_stability_test-1.0.cpp` — frozen v1.0 API
- `api_stability_test-1.1.cpp` — v1.1 additions (TrayType McEliece variants, `mcs::`, `mceliece_kem::`, `slhdsa_sig::`)
- `api_stability_test-1.2.cpp` — v1.2 additions (TrayType MlKem/FrodoFalcon variants, `oqs_kem::`, `oqs_sig::`)

## What's in v1.1

v1.1 adds the **McEliece + SLH-DSA** namespace group on top of the frozen v1.0 API:

| Namespace | Functions | Notes |
|-----------|-----------|-------|
| `mcs` | `keygen_mceliece()`, `keygen_slhdsa()` | Key generation |
| `mceliece_kem` | `encaps()`, `decaps()` | Classic McEliece KEM (5 param sets) |
| `slhdsa_sig` | `is_slhdsa_sig()`, `sig_bytes()`, `sign()`, `verify()` | SLH-DSA signatures (5 variants) |

**McEliece param sets:** `mceliece348864f`, `mceliece460896f`, `mceliece6688128f`, `mceliece6960119f`, `mceliece8192128f`

**SLH-DSA variants:** `SLH-DSA-SHA2-128f`, `SLH-DSA-SHA2-192f`, `SLH-DSA-SHA2-256f`, `SLH-DSA-SHAKE-192f`, `SLH-DSA-SHAKE-256f`

`TrayType` gains five new enumerators: `McEliece_Level1` through `McEliece_Level5`.

HYKE wire format TrayID extended: `0x05`=McEliece_Level2 … `0x08`=McEliece_Level5
(McEliece_Level1 has no classical slots and cannot be used with HYKE).

## What's in v1.2

v1.2 adds the **ML-KEM + ML-DSA** and **FrodoKEM + Falcon** namespace groups via liboqs:

| Namespace | Functions | Notes |
|-----------|-----------|-------|
| `oqs_kem` | `keygen()`, `encaps()`, `decaps()`, `is_oqs_kem()` | liboqs KEM (ML-KEM-*, FrodoKEM-*) |
| `oqs_sig` | `keygen()`, `is_oqs_sig()`, `sig_bytes()`, `sign()`, `verify()` | liboqs signatures (ML-DSA-*, Falcon-*) |

**ML-KEM param sets:** `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024`

**FrodoKEM param sets:** `FrodoKEM-640-AES`, `FrodoKEM-976-AES`, `FrodoKEM-1344-AES`

**ML-DSA variants:** `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`

**Falcon variants:** `Falcon-512`, `Falcon-1024`

`TrayType` gains eight new enumerators: `MlKem_Level1` through `MlKem_Level4` and `FrodoFalcon_Level1` through `FrodoFalcon_Level4`.

HYKE wire format TrayID extended: `0x11`=MlKem_Level1 … `0x14`=MlKem_Level4, `0x21`=FrodoFalcon_Level1 … `0x24`=FrodoFalcon_Level4

**Breaking change:** the `tray_mp` namespace (msgpack tray encoding) was removed from the public API. msgpack support was removed entirely.

## Structure

```
pqc/libcrystals-1.2/
  include/crystals/
    crystals.hpp             ← THE public API (v1.0 frozen + v1.1 + v1.2 candidates)
  src/
    *.hpp + *.cpp            ← private implementation
    mceliece_ops.{hpp,cpp}   ← McEliece keygen (mcs namespace)
    slhdsa_ops.{hpp,cpp}     ← SLH-DSA keygen (mcs namespace)
    mceliece_kem.{hpp,cpp}   ← McEliece KEM encaps/decaps
    slhdsa_sig.{hpp,cpp}     ← SLH-DSA sign/verify
    oqs_ops.{hpp,cpp}        ← liboqs KEM + signature operations (oqs_kem::, oqs_sig::)
    token_cmd.{hpp,cpp}      ← token commands (cmd_gentok, cmd_valtok)
    mceliece_randombytes.c   ← randombytes shim for libmceliece
    hyke_format.hpp          ← HYKE wire format (TrayID 0x01–0x08)
    token_format.hpp         ← token wire format
    pw_format.hpp            ← pw wire format
  test/
    test_crystals.cpp        ← 16-section functional test (145 assertions)
    api_stability_test-1.0.cpp ← static_assert enforcement of frozen v1.0 API
    api_stability_test-1.1.cpp ← static_assert enforcement of v1.1 additions
    api_stability_test-1.2.cpp ← static_assert enforcement of v1.2 additions
  CMakeLists.txt
  install.sh
```

## Build

```bash
cmake -S pqc/libcrystals-1.2 -B pqc/libcrystals-1.2/build \
  -DCMAKE_PREFIX_PATH=/mnt/c/Users/daves/OneDrive/Desktop/Crystals/local
cmake --build pqc/libcrystals-1.2/build -j$(nproc)
```

The build type is `RelWithDebInfo` (`-O2 -g`): optimised with full debug symbols.
Swap to `-DCMAKE_BUILD_TYPE=Debug` for `-O0 -g` if you need unoptimised debugging.

## Run tests

```bash
# Functional tests (16 sections, 145 assertions)
./pqc/libcrystals-1.2/build/test_crystals

# API stability (compile + exit 0 = all static_asserts pass)
./pqc/libcrystals-1.2/build/api_stability_test_10 && echo "v1.0 OK"
./pqc/libcrystals-1.2/build/api_stability_test_11 && echo "v1.1 OK"
./pqc/libcrystals-1.2/build/api_stability_test_12 && echo "v1.2 OK"
```

## Install

```bash
./pqc/libcrystals-1.2/install.sh [--prefix <dir>] [--crystals-root <dir>]
```

Produces a fat `libcrystals-1.2.a` that bundles Kyber ref, Dilithium ref, scrypt, libmceliece,
and liboqs — consumers link one archive plus the dynamic deps below.

## Dependencies

**Static (bundled into fat archive by install.sh):**
- Kyber ref + Dilithium ref (compiled via `add_subdirectory`)
- scrypt (compiled from source)
- libmceliece (`/usr/local/lib/libmceliece.a`)
- liboqs (`/usr/local/lib64/liboqs.a` — ML-KEM, ML-DSA, FrodoKEM, Falcon)

**Dynamic (must be present at runtime):**
- OpenSSL 3.x (EVP API — McEliece keygen, SLH-DSA, EC keys)
- XKCP (`libXKCP.so` — SHAKE256/KMAC256)
- BLAKE3 (from `Crystals/local/` — UUID derivation)
- oneTBB (from `Crystals/local/` — BLAKE3 parallelism)
- yaml-cpp
