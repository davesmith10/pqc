# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Deps and pqc Repository Layout

```
Crystals/
├── kyber/ref/          — Kyber reference C source; statically compiled into libcrystals-1.2 via CMake
├── kyber/avx2/         — Kyber AVX2 source (not used by the CMake tools)
├── dilithium/ref/      — Dilithium reference C source; statically compiled into libcrystals-1.2 via CMake
├── dilithium/avx2/     — Dilithium AVX2 source (not used by the CMake tools)
├── XKCP/               — eXtended Keccak Code Package; pre-built libXKCP.so (zorro + libcrystals)
├── BLAKE3/             — BLAKE3 source; built + installed to local/ (UUID derivation)
├── oneTBB/             — oneTBB source; built + installed to local/ (BLAKE3 parallelism)
├── local/              — Shared install prefix for BLAKE3 + TBB (CMake finds them here)
└── pqc/                — Main project (git root)
    ├── include/        — Shared headers (tray.hpp domain model)
    ├── hybrid/         — Hybrid PQ+classical tray keygen tool (uses libcrystals-1.2)
    ├── zorro/          — Hybrid KEM file encryption tool
    ├── libcrystals-1.2/ — Consolidated crypto library; installed to /usr/local via install.sh
    ├── misc/           — Utilities (hashpass, etc.)
    └── static-verify/  — Standalone project verifying the static Kyber + Dilithium CMake
                          libraries; links all 8 static targets + randombytes.c, runs KEM
                          and signature round-trips for all 6 parameter sets
```

## Build Commands

**Build hybrid** (hybrid PQ+classical tray keygen):
```bash
cmake -S pqc/hybrid -B pqc/hybrid/build
cmake --build pqc/hybrid/build -j$(nproc)
# Binary: pqc/hybrid/build/hybrid
# Requires: libcrystals-1.2 installed to /usr/local (see install.sh below)
```

**Build zorro** (hybrid KEM file encryption):
```bash
cmake -S pqc/zorro -B pqc/zorro/build
cmake --build pqc/zorro/build -j$(nproc)
# Binary: pqc/zorro/build/zorro
# Requires: libcrystals-1.2 installed to /usr/local (see install.sh below)
```

**Install libcrystals-1.2** (required by hybrid and zorro; installs fat static archive + CMake config to /usr/local):
```bash
sudo bash pqc/libcrystals-1.2/install.sh
# Use --skip-build to regenerate the CMake/pkg-config files without rebuilding
```

## API Stability Rules Related to libcrystals-1.x

- Never modify, rename, or remove any function marked `@api-stable`
- Never change the signature of any function declared in the public API, "crystals/crystals.hpp"
- When migrating demo code into libcrystals, add new functions — do not modify existing ones
- If a migration seems to require changing a stable function, STOP and report the conflict
- **Exception (v1.2)**: the `tray_mp` namespace (msgpack tray encoding) was intentionally removed from the public API in libcrystals-1.2 as a documented breaking change. This is not a stability violation — msgpack support was removed entirely.


## Testing

```bash
# zorro: encrypt → decrypt (YAML tray, defaults)
./pqc/hybrid/build/hybrid keygen --alias alice --profile level2-25519 > /tmp/alice.tray
echo "hello" > /tmp/plain.txt
./pqc/zorro/build/zorro encrypt --tray /tmp/alice.tray /tmp/plain.txt > /tmp/out.armored
./pqc/zorro/build/zorro decrypt --tray /tmp/alice.tray /tmp/out.armored | diff /tmp/plain.txt -

# zorro: KMAC + ChaCha20, YAML tray written to file
./pqc/hybrid/build/hybrid keygen --alias bob --profile level3 --out /tmp/bob.tray
./pqc/zorro/build/zorro encrypt --tray /tmp/bob.tray --kdf KMAC --cipher ChaCha20 /tmp/plain.txt > /tmp/out2.armored
./pqc/zorro/build/zorro decrypt --tray /tmp/bob.tray /tmp/out2.armored | diff /tmp/plain.txt -

# zorro: encrypt+sign → verify+decrypt (HYKE, all 4 tray types)
./pqc/hybrid/build/hybrid keygen --alias alice --profile level2-25519 > /tmp/alice.tray
./pqc/zorro/build/zorro encrypt+sign   --tray /tmp/alice.tray /tmp/plain.txt > /tmp/alice.hyke
./pqc/zorro/build/zorro verify+decrypt --tray /tmp/alice.tray /tmp/alice.hyke | diff /tmp/plain.txt -

# zorro: sign → verify (pure hybrid digital signature, no encryption)
./pqc/zorro/build/zorro sign   --tray /tmp/alice.tray --in-file /tmp/plain.txt > /tmp/plain.sig.yaml
./pqc/zorro/build/zorro verify --tray /tmp/alice.tray --in-file /tmp/plain.txt --in-sig /tmp/plain.sig.yaml

# zorro: gentok / valtok (requires level2 tray — P-256 + ECDSA P-256; level2-25519 is rejected)
./pqc/hybrid/build/hybrid keygen --alias alice --profile level2 > /tmp/alice_level2.tray
./pqc/zorro/build/zorro gentok --tray /tmp/alice_level2.tray --data "hello" > /tmp/tok.bin
./pqc/zorro/build/zorro valtok --tray /tmp/alice_level2.tray /tmp/tok.bin

# hybrid: hybrid tray keygen (crystals group, default)
./hybrid keygen --profile level3 --alias alice                          # YAML to stdout (default)
./hybrid keygen --alias bob                                             # default profile: level2-25519
./hybrid keygen --profile level0 --alias alice                          # classical-only (2 slots)
./hybrid keygen --profile level1 --alias alice                          # PQ-only (2 slots)
./hybrid keygen --alias alice --out alice.tray                          # YAML to file + auto-summary to stdout
./hybrid keygen --alias carol --profile level2-25519 --public           # YAML + companion public YAML (same UUID)
./hybrid keygen --alias carol --profile level3 --public --out carol.tray  # carol.tray + carol.pub.tray

# hybrid: mceliece+slhdsa group
./hybrid keygen --group mceliece+slhdsa --alias alice --profile level1  # 2 slots (PQ-only)
./hybrid keygen --group mceliece+slhdsa --alias alice --profile level2  # 4 slots (P-256 + mc460896f + ECDSA + SLH-DSA)
./hybrid keygen --group mceliece+slhdsa --alias alice --profile level5  # 4 slots (P-256 + mc8192128f + ECDSA + SLH-DSA)

# hybrid: protect / unprotect
./hybrid protect   --in alice.tray --out alice.sec.tray --password-file /tmp/pw.txt
./hybrid unprotect --in alice.sec.tray --out alice.plain.tray --password-file /tmp/pw.txt

# Kyber upstream tests (1000 cycles each level)
cd kyber/ref && make && ./test/test_kyber768

# Dilithium upstream tests (10000 cycles each level)
cd dilithium/ref && make && ./test/test_dilithium3
```

## Architecture

### zorro Architecture
zorro has three operation modes: **ZORRO** (encrypt/decrypt using both KEM slots),
**HYKE** (encrypt+sign/verify+decrypt using all four slots — both KEMs for encryption, both sig slots for auth),
and **pure hybrid digital signature** (sign/verify using both sig slots only — no encryption).

**Source files** (single file after the libcrystals-1.2 migration):
- `zorro/src/main.cpp` — arg parsing, file I/O, and CLI handlers `cmd_encrypt`, `cmd_decrypt`,
  `cmd_encrypt_sign`, `cmd_verify_decrypt`, `cmd_pure_sign`, `cmd_pure_verify`,
  `cmd_gentok`, `cmd_valtok`, `cmd_pwencrypt`, `cmd_pwdecrypt`.
  All crypto delegated to `Crystals::crystals`.

**Library boundary**: The library (`Crystals::crystals`) owns all crypto, KDF, wire-format
pack/unpack, tray loading, and serialisation. zorro owns arg parsing, file I/O, and
stdio interaction.

**Library API used** (all `@api-stable` in `crystals/crystals.hpp`):
- `load_tray` — loads a YAML tray file
- `ec_kem::encaps/decaps`, `kyber_kem::encaps/decaps`, `mceliece_kem::encaps/decaps`
- `ec_sig::sign/verify`, `dilithium_sig::sign/verify`, `slhdsa_sig::sign/verify`
- `derive_key_shake`, `derive_key_kmac`, `derive_key_hyke`, `compute_hyke_ctx`
- `aes256gcm_encrypt/decrypt`, `chacha20poly1305_encrypt/decrypt`
- `armor_pack/unpack` (ZORRO), `hyke_pack/unpack` (HYKE)
- `cmd_pwencrypt`, `cmd_pwdecrypt`, `cmd_gentok`, `cmd_valtok`

**Link deps**: `Crystals::crystals` (fat static archive; pulls in XKCP, BLAKE3, TBB, yaml-cpp,
OpenSSL::Crypto, scrypt, Kyber, Dilithium, McEliece, SLH-DSA transitively) +
`OpenSSL::Crypto` directly (for `openssl/rand.h` RAND_bytes in main.cpp).

**ZORRO KDF input construction**:
- SHAKE256: `SHAKE256(len32(SS_cl)||SS_cl||len32(SS_pq)||SS_pq||len32(CT_cl)||CT_cl||len32(CT_pq)||CT_pq, 32B)`
- KMAC256: `KMAC256(key=SS_cl, msg=len32(SS_pq)||...|CT_pq, custom="hybrid-kem-file-encryption-v1", 256b)`

**HYKE KDF and context binding**:
- KDF: `KMAC256(key=ss_cl, msg=ss_pq||CT_cl||CT_pq||salt, custom="zorro-hybrid-sig-v1", 256b)` (no len32 prefixes)
- ctx: `KMAC256(key=pk_cl, msg=pk_pq||"zorro-hybrid-sig-v1", outlen=512b)` → 64-byte context
- Signed region: `ctx || partial_header(80+N+M bytes) || encrypted_payload`

**ECDSA signature format**: P1363 (raw r||s, fixed size) rather than DER, so signature lengths
are known from the tray type before signing. Conversion: `EVP_DigestSign` → DER → `d2i_ECDSA_SIG`
→ `BN_bn2binpad` for sign; reverse via `BN_bin2bn` → `ECDSA_SIG_set0` → `i2d_ECDSA_SIG` for verify.
Fixed sizes: P-256=64B, P-384=96B, P-521=132B.

**Slot selection**: uses `alg_name` matching — KEM classical: `{X25519,P-256,P-384,P-521}`;
KEM PQ: prefix `"Kyber"`, `"mceliece"`, or `oqs_kem::is_oqs_kem()` (ML-KEM-*, FrodoKEM-*);
Sig classical: `{Ed25519,ECDSA P-256,ECDSA P-384,ECDSA P-521}`;
Sig PQ: `{Dilithium2,Dilithium3,Dilithium5}`, prefix `"SLH-DSA"`, or `oqs_sig::is_oqs_sig()` (ML-DSA-*, Falcon-*).

### hybrid Architecture
hybrid generates **hybrid trays** — named bundles of paired PQ+classical key slots, and can
password-protect/unprotect the secret keys in place. hybrid is a thin CLI shell backed entirely
by `Crystals::crystals` (libcrystals-1.2).

**Source files** (single file after the libcrystals-1.2 migration):
- `hybrid/src/main.cpp` — arg parsing, TTY interaction, password hygiene, file I/O, and
  CLI handlers `cmd_keygen`, `cmd_protect`, `cmd_unprotect`. All crypto delegated to library.

**Library boundary**: The library (`Crystals::crystals`) owns all crypto and serialisation.
hybrid owns everything that touches a human (arg parsing, TTY password prompts, entropy
warnings, stdout/stderr) and everything that touches the filesystem.

**Library API used** (all `@api-stable` in `crystals/crystals.hpp`):
- `make_tray`, `make_public_tray`, `validate_tray_uuid`
- `emit_tray_yaml`, `load_tray_yaml`
- `emit_secure_tray_yaml`, `load_secure_tray_yaml`
- `protect_tray`, `unprotect_tray`

**Link deps**: `Crystals::crystals` (fat static archive; pulls in XKCP, BLAKE3, TBB, yaml-cpp,
OpenSSL::Crypto transitively) + `OpenSSL::Crypto` directly (for `openssl/ui.h` EVP_read_pw_string
and `openssl/crypto.h` OPENSSL_cleanse in cmd_protect/cmd_unprotect).

**Output modes**: `keygen` default = YAML stdout; `--out <file>` = YAML to file + auto-summary to stdout;
`--public` = companion public tray (no sk, alias `<name>.pub`, **same UUID** as private tray).
`protect --in <f> --out <f>` = encrypt sk fields → `type: secure-tray` YAML.
`unprotect --in <f> --out <f>` = decrypt sk fields back to plain `type: tray` YAML.

### Static Linking Strategy
**zorro** and **hybrid**: Both use `libcrystals-1.2.a` — a fat static archive (installed at
`/usr/local/lib/`) that bundles all 8 PQ ref archives + 3 scrypt archives + McEliece + the
crystals objects. No separate `add_subdirectory` or `kyber/ref` source needed. Link via the
`Crystals::crystals` CMake target.

### RPATH Setup
Both **hybrid** and **zorro** use the same RPATH strategy:
- TBB libdir (derived from `TBB::tbb` imported target location, resolved transitively via
  `CrystalsConfig.cmake`) + `/usr/local/lib` (covers `libXKCP.so` installed there by
  `libcrystals-1.2/install.sh`).

### Key Size Constants (from `*_api.hpp`)
| Level | Public Key | Secret Key | Ciphertext/Sig |
|-------|-----------|-----------|----------------|
| Kyber512 | 800 B | 1632 B | 768 B |
| Kyber768 | 1184 B | 2400 B | 1088 B |
| Kyber1024 | 1568 B | 3168 B | 1568 B |
| Dilithium2 | 1312 B | **2560 B** | 2420 B |
| Dilithium3 | 1952 B | **4032 B** | 3309 B |
| Dilithium5 | 2592 B | **4896 B** | 4627 B |

(Note: Dilithium sk sizes differ from NIST ML-DSA spec; use values from `dilithium/ref/api.h`)

## Verified Working (zorro)
- All 16 encrypt/decrypt combos: {level2-25519,level2,level3,level5} × {SHAKE,KMAC} × {AES-256-GCM,ChaCha20}: OK
- All 4 encrypt+sign/verify+decrypt (HYKE) tray types: {level2-25519,level2,level3,level5}: OK
- 1MB binary file encrypt+sign/verify+decrypt roundtrip: OK
- Tampered payload → "classical signature INVALID" + exit 2
- Wrong tray type → "tray type mismatch" + exit 2; missing --tray → exit 1
- pwencrypt/pwdecrypt: all 3 levels (512/768/1024) roundtrip OK; wrong password → exit 2; tampered binary → exit 2
- mlkem+mldsa mk-level2, mk-level3, mk-level4: encrypt/decrypt/encrypt+sign/verify+decrypt OK (2026-03-23)
- frodokem+falcon ff-level2, ff-level3: encrypt/decrypt/encrypt+sign/verify+decrypt OK (2026-03-23)
- Pure hybrid sign/verify: all crystals {level2-25519,level2,level3,level5}, mceliece+slhdsa {level2,level3,level4,level5}, mlkem+mldsa {mk-level2,mk-level3,mk-level4}, frodokem+falcon {ff-level2,ff-level3}: OK (2026-03-24)
- Pure hybrid sign/verify: tampered file → exit 2; wrong tray → tray_id mismatch + exit 2; partial tray (level0/ms-level1) → exit 1; 1MB binary roundtrip OK (2026-03-24)
- McEliece encrypt+sign/verify+decrypt: level2, level3, level4, level5 roundtrip OK (2026-04-05)
- McEliece level1 (partial tray) → exit 1 + partial-tray error message (2026-04-05)

## penelope Tool
CLI: `penelope tray-encaps --in-tray <file> --out-png <png> --pwfile /dev/stdin`
     `penelope tray-decaps --in-png <png> --out-tray <file> --pwfile /dev/stdin`
- Supports all profile groups: crystals (level0–level5), mceliece+slhdsa (level1–level5),
  mlkem+mldsa (mk-level2/3/4), frodokem+falcon (ff-level2/3)
- Migrated from direct-source-compile to `Crystals::crystals` fat archive (libcrystals-1.2)
- Build: `cmake -S pqc/penelope -B pqc/penelope/build && cmake --build pqc/penelope/build -j$(nproc)`
- Binary: `pqc/penelope/build/penelope`
- Exit codes: 0=ok, 2=crypto/wrong password, 3=I/O

## CMakeLists.txt Paths
- hybrid: `cmake -S pqc/hybrid -B pqc/hybrid/build` (no CMAKE_PREFIX_PATH needed)
  - `find_package(Crystals REQUIRED)` — finds from `/usr/local/lib/cmake/crystals`
  - `find_package(OpenSSL REQUIRED)` — for `openssl/ui.h` + `openssl/crypto.h`
  - TBB and BLAKE3 resolved transitively inside CrystalsConfig.cmake
  - RPATH: `CMAKE_BUILD_RPATH` set to TBB libdir + `/usr/local/lib`
- zorro: `cmake -S pqc/zorro -B pqc/zorro/build` (no CMAKE_PREFIX_PATH needed)
  - `find_package(Crystals REQUIRED)` — finds from `/usr/local/lib/cmake/crystals`
  - `find_package(OpenSSL REQUIRED)` — for `openssl/rand.h`
  - TBB, BLAKE3, XKCP, scrypt, PQ libs all resolved transitively via CrystalsConfig.cmake
  - RPATH: `CMAKE_BUILD_RPATH` set to TBB libdir + `/usr/local/lib`
- static-verify: `cmake -S pqc/static-verify -B pqc/static-verify/build` (no external deps)

## Exit Codes (all tools)
- `0` — success
- `1` — usage/argument error
- `2` — crypto failure (decaps mismatch, invalid signature)
- `3` — I/O error (file not found, wrong PEM header level)
