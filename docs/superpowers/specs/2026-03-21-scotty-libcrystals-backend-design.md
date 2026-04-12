# Design: Migrate hybrid to libcrystals-1.1 backend

**Date:** 2026-03-21
**Status:** Approved
**Scope:** hybrid only (zorro to follow the same pattern in a subsequent migration)

---

## Background

hybrid currently duplicates the implementation of all crypto primitives, YAML I/O, tray
construction, and protect/unprotect logic that also live inside libcrystals-1.1. The
library was extracted from the tools after the fact; going forward the discipline is
library-first — new functionality is added to libcrystals first, then called from the
application. This migration establishes that pattern by making hybrid a thin CLI shell
backed entirely by `Crystals::crystals`.

---

## Architecture

After migration hybrid's `src/` shrinks from ~20 files to **one file**: `main.cpp`.

```
hybrid (binary)
  └── main.cpp            ← arg parsing, TTY interaction, password hygiene, file I/O
        │
        └── Crystals::crystals (libcrystals-1.1.a @ /usr/local)
              ├── make_tray / make_public_tray / validate_tray_uuid
              ├── emit_tray_yaml / load_tray_yaml
              ├── emit_secure_tray_yaml / load_secure_tray_yaml
              └── protect_tray / unprotect_tray
```

**Boundary rule:** The library owns all crypto and serialisation. hybrid owns everything
that touches a human (arg parsing, TTY password prompts, entropy warnings, stdout/stderr)
and everything that touches the filesystem (reading/writing files). `cmd_protect` and
`cmd_unprotect` are pure CLI handlers that call library functions — they stay in
`main.cpp`.

---

## API Status — No Gap

All functions needed by hybrid are already declared in `crystals.hpp`:
- `make_tray`, `make_public_tray`, `validate_tray_uuid` — `@api-stable v1.0`
- `emit_tray_yaml` — `@api-stable v1.0` (line 1328 of crystals.hpp)
- `load_tray_yaml`, `load_secure_tray_yaml`, `emit_secure_tray_yaml` — `@api-stable v1.0`
- `protect_tray`, `unprotect_tray` — `@api-stable v1.0`

No libcrystals patch is required before beginning the migration.

---

## Migration Plan

### Phase 1 — Migrate hybrid (on a worktree branch)

Branch name: `hybrid-libcrystals-backend`

#### 1a. CMakeLists.txt

Replace the current ~106-line file with a streamlined version:

- Remove: both `add_subdirectory` calls (kyber/ref, dilithium/ref)
- Remove: all `SCRYPT_SOURCES` and `SCRYPT_DIR` variables and compile entries
- Remove: `RANDOMBYTES_SRC` and `KYBER_REF_DIR`
- Remove: the 8 `pqcrystals_*` link targets, `/usr/local/lib/libmceliece.a`, the 3
  scrypt archives, `BLAKE3::blake3`
- Remove: all `target_include_directories` entries for kyber/ref, scrypt, `/usr/local/include`
- Remove: `find_package(yaml-cpp)` and the `yaml-cpp` link target — both are provided
  transitively via `Crystals::crystals` (CrystalsConfig.cmake exposes yaml-cpp in
  `INTERFACE_LINK_LIBRARIES`)
- Add: `find_package(Crystals REQUIRED HINTS /usr/local/lib/cmake/crystals)`
- Add: `target_link_libraries(hybrid PRIVATE Crystals::crystals)`
- Keep: `find_package(OpenSSL REQUIRED)` — needed for `openssl/ui.h`
  (`EVP_read_pw_string`) and `openssl/crypto.h` (`OPENSSL_cleanse`) in
  `cmd_protect`/`cmd_unprotect`
- Keep: RPATH logic for TBB — `TBB::tbb` is brought in transitively via
  `Crystals::crystals` (CrystalsConfig.cmake calls `find_package(TBB)` internally),
  so `TBB::tbb` is available after `find_package(Crystals)`. Extract its library dir
  and set `CMAKE_BUILD_RPATH` as before.
- XKCP: at `/usr/local/lib/libXKCP.so` — a standard path. No explicit RPATH entry is
  needed provided `ldconfig` was run after installing libcrystals-1.1 to `/usr/local`
  (the install.sh script calls `ldconfig` automatically for `/usr/local` prefixes). If
  in doubt, add `/usr/local/lib` to `CMAKE_BUILD_RPATH` as a safety measure.

#### 1b. src/main.cpp

- Replace the three private `#include` lines with `#include <crystals/crystals.hpp>`
- Add `#include <openssl/ui.h>` and `#include <openssl/crypto.h>` (needed by the
  folded-in `cmd_protect`/`cmd_unprotect`)
- Fold `cmd_protect` and `cmd_unprotect` from `secure_tray.cpp` into `main.cpp` —
  these are pure CLI handlers calling library functions, with no crypto of their own

#### 1c. Delete from src/

21 files removed:

| File | Was providing |
|------|--------------|
| `base64.cpp` / `base64.hpp` | base64 encode/decode |
| `ec_ops.cpp` / `ec_ops.hpp` | OpenSSL EVP keygen for EC curves |
| `kyber_ops.cpp` / `kyber_ops.hpp` | Kyber keygen wrapper |
| `kyber_api.hpp` | `extern "C"` Kyber ref declarations |
| `dilithium_ops.cpp` / `dilithium_ops.hpp` | Dilithium keygen wrapper |
| `dilithium_api.hpp` | `extern "C"` Dilithium ref declarations |
| `mceliece_ops.cpp` / `mceliece_ops.hpp` | McEliece keygen |
| `slhdsa_ops.cpp` / `slhdsa_ops.hpp` | SLH-DSA keygen |
| `mceliece_randombytes.c` | getrandom shim for libmceliece |
| `tray.cpp` | `make_tray`, `make_public_tray`, UUID derivation |
| `yaml_io.cpp` / `yaml_io.hpp` | `emit_tray_yaml` |
| `secure_tray.cpp` / `secure_tray.hpp` | crypto + YAML I/O for protect/unprotect |
| `symmetric.hpp` | AES-256-GCM helpers (used only by secure_tray.cpp) |

---

## Verification

Run all hybrid test commands from CLAUDE.md after a clean build:

```bash
# All 6 crystals profiles
./pq/hybrid/build/hybrid keygen --alias alice --profile level2-25519
./pq/hybrid/build/hybrid keygen --alias alice --profile level0
./pq/hybrid/build/hybrid keygen --alias alice --profile level1
./pq/hybrid/build/hybrid keygen --alias alice --profile level2
./pq/hybrid/build/hybrid keygen --alias alice --profile level3
./pq/hybrid/build/hybrid keygen --alias alice --profile level5

# All 5 mceliece+slhdsa profiles
./pq/hybrid/build/hybrid keygen --group mceliece+slhdsa --alias alice --profile level1
./pq/hybrid/build/hybrid keygen --group mceliece+slhdsa --alias alice --profile level2
./pq/hybrid/build/hybrid keygen --group mceliece+slhdsa --alias alice --profile level3
./pq/hybrid/build/hybrid keygen --group mceliece+slhdsa --alias alice --profile level4
./pq/hybrid/build/hybrid keygen --group mceliece+slhdsa --alias alice --profile level5

# --out and --public
./pq/hybrid/build/hybrid keygen --alias alice --out /tmp/alice.tray
./pq/hybrid/build/hybrid keygen --alias alice --public --out /tmp/alice.tray

# protect / unprotect roundtrip
./pq/hybrid/build/hybrid keygen --alias alice --out /tmp/alice.tray
echo "testpass123" > /tmp/pw.txt
./pq/hybrid/build/hybrid protect --in /tmp/alice.tray --out /tmp/alice.sec.tray --password-file /tmp/pw.txt
./pq/hybrid/build/hybrid unprotect --in /tmp/alice.sec.tray --out /tmp/alice.plain.tray --password-file /tmp/pw.txt
diff /tmp/alice.tray /tmp/alice.plain.tray

# Error cases
./pq/hybrid/build/hybrid keygen                             # → exit 1 (missing --alias)
./pq/hybrid/build/hybrid keygen --alias x --group bad       # → exit 1 (unknown group)
echo "wrongpass" > /tmp/wrong.txt
./pq/hybrid/build/hybrid unprotect --in /tmp/alice.sec.tray --out /tmp/x.tray --password-file /tmp/wrong.txt
# → exit 2 (wrong password)
```

---

## Files Changed Summary

| Location | Change |
|----------|--------|
| `pq/hybrid/CMakeLists.txt` | Rewrite: find_package(Crystals) replaces all manual deps |
| `pq/hybrid/src/main.cpp` | New include + fold in cmd_protect/cmd_unprotect |
| `pq/hybrid/src/` (21 files) | Delete |

---

## Non-Goals

- No changes to hybrid's CLI interface, exit codes, or output format
- No changes to the YAML wire format
- zorro migration is a separate, subsequent task
- No changes to libcrystals-1.1's `@api-stable` declarations
