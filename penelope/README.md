# padme — Tray Encapsulator

`padme tray-encaps` renders a Crystals tray (produced by `scotty`) into a 256-pixel-wide annotated
PNG and encrypts the private key bytes with a password (scrypt + AES-256-GCM). The resulting
PNG carries the public keys as plaintext rainbow pixels, the encrypted secret keys as
ciphertext pixels, and all decryption metadata in an iTXt chunk. `padme tray-decaps` reverses the
process, recovering the original tray from the password-protected PNG.

---

## Commands

```
padme tray-encaps  --in-tray <file>     [--out-png <file.png>] [--pwfile <file>]
padme tray-decaps  --in-png <file.png>  [--out-tray <file>]    [--pwfile <file>]
```

---

### tray-encaps

Renders a tray into a 256-pixel-wide annotated PNG and password-encrypts the private key
bytes in place. Public keys are stored as plaintext rainbow pixels; secret keys are replaced
with AES-256-GCM ciphertext pixels. The PNG carries a human-readable header (alias, profile,
UUID) and a copyright footer.

| Flag | Description |
|------|-------------|
| `--in-tray <file>` | Source tray (YAML) |
| `--out-png <file.png>` | Output PNG (default: `<alias>_enc.png`) |
| `--pwfile <file>` | Read password from file (newline stripped). Prompts `password:` + `again:` if omitted. |

```bash
# Interactive (prompts twice)
padme tray-encaps --in-tray alice.tray --out-png alice_enc.png

# From a password file
echo "hunter2" > pw.txt
padme tray-encaps --in-tray alice.tray --pwfile pw.txt --out-png alice_enc.png
# Encaps: tray 'alice' → alice_enc.png (scrypt N=2^19, AES-256-GCM)
```

---

### tray-decaps

Decrypts the private keys from an encaps PNG and reconstructs the original tray.

| Flag | Description |
|------|-------------|
| `--in-png <file.png>` | encaps PNG produced by `padme tray-encaps` |
| `--out-tray <file>` | Output file (YAML format; default: YAML to stdout) |
| `--pwfile <file>` | Read password from file. Prompts `password:` once if omitted. |

```bash
# Recover to stdout (YAML)
padme tray-decaps --in-png alice_enc.png

# Recover to YAML file
padme tray-decaps --in-png alice_enc.png --out-tray alice-recovered.yaml

# Wrong password → exit 2
echo "wrong" | padme tray-decaps --in-png alice_enc.png --pwfile /dev/stdin
# Error: decryption failed — wrong password or corrupted image
```

---

## Encryption Scheme

```
Key hierarchy:
  password + random-salt (16 B) ──scrypt──► wrap_key (32 B)
  wrap_key ──AES-256-GCM──► data_key (32 B random)    [KEM block: 60 px]
  data_key ──AES-256-GCM──► all_sk (all slot secret keys concatenated)

KDF: scrypt(N=2^19, r=8, p=1) via OpenSSL EVP_PBE_scrypt
Symmetric: AES-256-GCM (nonce randomly generated per operation)
```

The KEM block (kem_nonce ∥ kem_tag ∥ encrypted_data_key = 60 bytes) is embedded as a
centered row of colored pixels between the key blocks and the footer. Decryption metadata
(salt, scrypt params, SK nonce, SK tag) is stored in a `crystals-encaps` iTXt chunk.

---

## Visual Layout (256 px wide)

```
┌─────────────────────────────────────────────────────────┐  ← 12px margin
│  PADME Tray - <profile>                                 │  ← header line 1
│  <uuid>                                                 │  ← header line 2
│                                                         │  ← 8px gap
│  [classical pk · 112px]  │  [classical sk (enc) · 112px]│  ← top section
│                                                         │  ← 8px gap
│  [PQ pk · 112px]         │  [PQ sk (enc) · 112px]      │  ← bottom section
│                                                         │  ← 8px gap
│              [KEM block — 60 pixels, centered]          │  ← 1-pixel row
│                                                         │  ← 8px gap
│              © 2026 David R. Smith                      │  ← footer line 1
│              All Rights Reserved                        │  ← footer line 2
└─────────────────────────────────────────────────────────┘  ← 12px margin
```

Public key pixels are unchanged rainbow colors. Secret key pixels are the AES-256-GCM
ciphertext of the original key bytes — visually indistinguishable but cryptographically
locked to the password.

---

## PNG Format Notes

### crystals-tray iTXt chunk

```
alias=alice
id=986f58d0-20f9-8713-ac05-604b637967e1
profile=level3
created=2026-03-12T02:35:52Z
expires=2028-03-12T02:35:52Z
```

### crystals-encaps iTXt chunk

```
salt=<base64-16-bytes>
n_log2=19
r=8
p=1
sk_nonce=<base64-12-bytes>
sk_tag=<base64-16-bytes>
```

### Palette

`byte_to_rgb` maps 256 byte values to 256 distinct RGB triples — a bijection, so the
inverse is exact. The hue range is 0°–358.6° (dividing by 256, not 255) to prevent byte 0
and byte 255 from colliding at pure red (hue 360° = hue 0°).

---

## Build

Requires: `cmake`, `g++`, `yaml-cpp`, `OpenSSL 3`, and BLAKE3 + TBB installed to `Crystals/local/`.

```bash
cmake -S pq/padme -B pq/padme/build \
  -DCMAKE_PREFIX_PATH=/mnt/c/Users/daves/OneDrive/Desktop/Crystals/local
cmake --build pq/padme/build -j$(nproc)
# Binary: pq/padme/build/padme
```

`padme` compiles lodepng directly from source (vendored in this directory) and pulls in
tray I/O code from `pq/libcrystals/src/` — no separate library install step needed.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Usage / argument error |
| 2 | Crypto / decode error (wrong password, bad palette pixel, unknown profile) |
| 3 | I/O error (file not found, PNG read/write failure) |

---

## Dependencies

| Dependency | Role |
|------------|------|
| [lodepng](https://lodev.org/lodepng/) | PNG encode/decode with iTXt chunk support (vendored) |
| OpenSSL 3 | scrypt KDF (`EVP_PBE_scrypt`) + AES-256-GCM (`encaps`/`decaps`) |
| yaml-cpp 0.6 | YAML tray parsing and emission |
| BLAKE3 | UUID self-verification when loading trays |
| TBB | Runtime dep of BLAKE3 (parallel hashing) |
