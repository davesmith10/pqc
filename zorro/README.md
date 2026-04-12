# zorro

Hybrid post-quantum + classical file encryption, signing, and token generation.
Operates on **trays** produced by [hybrid](../hybrid/), which bundle a classical key
pair (X25519/P-curve ECDH + Ed25519/ECDSA) with a post-quantum pair (Kyber KEM +
Dilithium signature, or McEliece KEM + SLH-DSA signature) at the chosen security level.

## Commands

```
zorro encrypt        --tray <file> [--kdf SHAKE|KMAC] [--cipher AES-256-GCM|ChaCha20] <target-file>
zorro decrypt        --tray <file> <target-file>
zorro encrypt+sign   --tray <file> <target-file>
zorro verify+decrypt --tray <file> <target-file>
zorro sign           --tray <file> --in-file <file>
zorro verify         --tray <file> --in-file <file> --in-sig <file>
zorro gentok         --tray <file> --data <string> [--ttl <seconds>]
zorro valtok         --tray <file> [token-file]
zorro pwencrypt      [--level 512|768|1024] [--scrypt-n 20] [--pwfile <file>] <infile> <outfile>
zorro pwdecrypt      [--pwfile <file>] <infile> <outfile>
```

### encrypt / decrypt

Encrypts a file using both the classical KEM slot and the PQ KEM slot from the tray. 
The two shared secrets are combined via a hybrid KDF; the result encrypts the payload with the 
chosen symmetric cipher.

Output is written to stdout as a PEM-armored `ZORRO ENCRYPTED FILE`.

**Options:**
- `--kdf SHAKE` (default) — SHAKE-256 over length-prefixed concatenation of both shared secrets
- `--kdf KMAC` — KMAC-256 keyed with the classical shared secret, message = PQ shared secret + ciphertexts
- `--cipher AES-256-GCM` (default)
- `--cipher ChaCha20` — ChaCha20-Poly1305

Tray files must be in YAML format.

### encrypt+sign / verify+decrypt (HYKE)

Encrypts and signs a file using all four slots in the tray: both KEM slots protect the
symmetric key (same as `encrypt`), and both signature slots (Ed25519/ECDSA + Dilithium
or SLH-DSA) sign the header and encrypted payload.

Output is written to stdout as a PEM-armored `ZORRO SIGNED FILE`.

`verify+decrypt` checks both signatures before decrypting. Any tampering causes exit code 2.

Requires a tray with all four slots present (hybrid levels only — not level0/level1).

### sign / verify (pure hybrid digital signature)

Signs an arbitrary file without encrypting it. Both the classical signature slot
(Ed25519/ECDSA) and the PQ signature slot (Dilithium/ML-DSA/Falcon/SLH-DSA) sign the
same message digest, producing a single composite signature.

```
zorro sign   --tray <file> --in-file <file>
zorro verify --tray <file> --in-file <file> --in-sig <file>
```

**Algorithm:** The signed message is `M' = tray_uuid(16 bytes) || SHA-256(file_bytes)`.
Using the tray UUID as a domain separator provides per-tray uniqueness, preventing
cross-tray signature confusion between two trays of the same profile.

`sign` writes a YAML document to stdout:

```yaml
---
version: 1
id: a1b2c3d4-...           # random UUID v4, audit identifier only
created: 2026-04-06T12:00:00Z
tray-id: 3f2a1b4c-...      # tray UUID used for domain separation
tray-alias: alice
profile-group: crystals
profile: level2-25519
input: document.pdf
composite-sig: |-           # base64: u32be(len_cl) || sig_cl || u32be(len_pq) || sig_pq
  BAAAAJQB...
```

`verify` reads the `--in-sig` YAML, recomputes `M'` from the tray and the file, and
checks both signatures. Outputs a YAML confirmation (without `composite-sig`) on success:

```yaml
---
verified: true
id: a1b2c3d4-...
tray-id: 3f2a1b4c-...
tray-alias: alice
profile-group: crystals
profile: level2-25519
input: document.pdf
```

Requires a tray with **both** a classical sig slot and a PQ sig slot. Partial-key trays
(level0 classical-only, level1 PQ-only) are rejected with exit 1.

### gentok / valtok

Issues and validates compact signed tokens bound to a tray identity.

```bash
# Generate a token (writes base64 to stdout)
zorro gentok --tray alice.tray --data "user=alice" [--ttl 3600]

# Validate a token (reads from file or stdin)
zorro valtok --tray alice.tray token.b64
echo "<base64>" | zorro valtok --tray alice.tray
```

- `--data` — 1–256 byte payload string embedded in the token
- `--ttl` — lifetime in seconds (default 86400 = 24 h)
- Tokens are signed with ECDSA P-256 (the first classical sig slot); requires a level2 or higher tray
- `valtok` exits 0 and prints the data payload if the signature is valid and the token has not expired

### pwencrypt / pwdecrypt

Password-based encryption; no tray required. Generates an ephemeral Kyber keypair,
derives a wrap key from the password via scrypt, and encrypts the file with two
nested AES-256-GCM layers.

```bash
zorro pwencrypt [--level 512|768|1024] [--scrypt-n 20] [--pwfile <file>] <infile> <outfile>
zorro pwdecrypt [--pwfile <file>] <infile> <outfile>
```

- `--level` — Kyber security level for the ephemeral KEM (default 768)
- `--scrypt-n` — log₂ of the scrypt N parameter (default 20 = 1 048 576 iterations; range 16–22)
- `--pwfile` — read password from the first line of a file (prompts on the terminal if omitted; `pwencrypt` prompts twice for confirmation)

Output is a PEM-armored `ZORRO PW ENCRYPTED FILE`.

## Tray Profiles

Trays are created by [hybrid](../hybrid/) and passed via `--tray`.

### crystals group (default)

| Profile       | Classical KEM | PQ KEM     | Classical Sig | PQ Sig      |
|---------------|---------------|------------|---------------|-------------|
| level0        | X25519        | —          | Ed25519       | —           |
| level1        | —             | Kyber512   | —             | Dilithium2  |
| level2-25519  | X25519        | Kyber512   | Ed25519       | Dilithium2  |
| level2        | P-256         | Kyber512   | ECDSA P-256   | Dilithium2  |
| level3        | P-384         | Kyber768   | ECDSA P-384   | Dilithium3  |
| level5        | P-521         | Kyber1024  | ECDSA P-521   | Dilithium5  |

### mceliece+slhdsa group (`--group mceliece+slhdsa`)

| Profile    | Classical KEM | PQ KEM              | Classical Sig | PQ Sig               |
|------------|---------------|---------------------|---------------|----------------------|
| ms-level1  | —             | mceliece348864f     | —             | SLH-DSA-SHA2-128f    |
| ms-level2  | P-256         | mceliece460896f     | ECDSA P-256   | SLH-DSA-SHA2-192f    |
| ms-level3  | P-384         | mceliece6688128f    | ECDSA P-384   | SLH-DSA-SHAKE-192f   |
| ms-level4  | P-521         | mceliece6960119f    | ECDSA P-521   | SLH-DSA-SHA2-256f    |
| ms-level5  | P-256         | mceliece8192128f    | ECDSA P-256   | SLH-DSA-SHAKE-256f   |

`encrypt`/`decrypt` require at least one classical and one PQ KEM slot (hybrid levels).
`encrypt+sign`/`verify+decrypt` and `sign`/`verify` both require at least one classical sig slot and one PQ sig slot (hybrid levels only — ms-level1 and crystals level1 are rejected).
`gentok`/`valtok` are crystals-only (level2 or higher).

## Wire Formats

### ZORRO (encrypt)

```
"ZORRO01" (8B) | kdf (1B) | cipher (1B)
| ct_classical_len (4B BE) | ct_classical
| ct_pq_len (4B BE)        | ct_pq
| nonce (12B) | tag (16B)  | ciphertext
```

Wrapped in `-----BEGIN/END ZORRO ENCRYPTED FILE-----` PEM armor (base64, 64-char lines).

### ZORRO Signed (encrypt+sign)

```
"HYKE" (4B) | version (2B) | tray_id (1B) | flags (1B)
| header_len (4B BE) | payload_len (4B BE)
| tray_uuid (16B) | salt (32B)
| ct_classical_len (4B) | ct_pq_len (4B) | sig_classical_len (4B) | sig_pq_len (4B)
| ct_classical | ct_pq | sig_classical | sig_pq
| nonce (12B) | tag (16B) | ciphertext
```

Signatures cover a 64-byte context binding (KMAC-256 over both public keys) concatenated
with the partial header and encrypted payload. Classical signatures use P1363 format
(raw r‖s). Dilithium signatures are raw bytes from the reference implementation;
SLH-DSA signatures are raw bytes via OpenSSL 3.5 (`EVP_DigestSign`). All field lengths
are stored as 32-bit big-endian values, so the wire format accommodates McEliece
ciphertexts (96–208 B) and SLH-DSA signatures (17–50 KB) without change.

Wrapped in `-----BEGIN/END ZORRO SIGNED FILE-----` PEM armor.

### Composite Sig (sign)

```
u32be(len_classical) | sig_classical | u32be(len_pq) | sig_pq
```

Base64-encoded in the `composite-sig` field of the output YAML. Both components are
always present — partial-key trays are rejected before signing. Length prefixes
accommodate variable-length PQ signatures (e.g. Falcon via `oqs_sig`).

### PWENC (pwencrypt)

```
"ZOWE" (4B) | version (1B) | level (2B BE)
| salt (32B) | scrypt_n_log2 (1B) | scrypt_r (1B) | scrypt_p (1B)
| pk | ct
| wrap_nonce (12B) | wrap_tag (16B) | sk_enc
| data_nonce (12B) | data_tag (16B) | ciphertext
```

The scrypt-derived wrap key decrypts `sk_enc` → ephemeral Kyber sk → decapsulate `ct` → data key → decrypt ciphertext.

Wrapped in `-----BEGIN/END ZORRO PW ENCRYPTED FILE-----` PEM armor.

### Token (gentok)

```
"zorro\0\0\0" (8B) | version (2B)
| TLV[0x01: data] | TLV[0x02: issued_at] | TLV[0x03: expires_at]
| TLV[0x04: tray_uuid] | TLV[0x05: algorithm] | TLV[0x06: token_uuid]
| sig_len (4B BE) | signature
```

`token_uuid` is a UUID v4 generated fresh for each `gentok` call (4 random bytes with version/variant bits set).

Tokens are output as a single base64 line (no PEM armor).

## Build

```bash
cmake -S pq/zorro -B pq/zorro/build
cmake --build pq/zorro/build -j$(nproc)
# Binary: pq/zorro/build/zorro
# Requires: libcrystals-1.1 installed to /usr/local
#   sudo bash pq/libcrystals-1.1/install.sh
```

All crypto dependencies (Kyber, Dilithium, McEliece, SLH-DSA, scrypt, BLAKE3, oneTBB,
XKCP, yaml-cpp, OpenSSL) are resolved transitively via the `Crystals::crystals` CMake
target — no `CMAKE_PREFIX_PATH` needed.

## Examples

```bash
# Generate a tray
hybrid keygen --alias alice --profile level2-25519 > alice.tray

# Encrypt / decrypt
zorro encrypt --tray alice.tray plaintext.txt > message.armored
zorro decrypt --tray alice.tray message.armored > recovered.txt

# Encrypt with KMAC + ChaCha20
zorro encrypt --tray alice.tray --kdf KMAC --cipher ChaCha20 plaintext.txt > message.armored

# Encrypt and sign / verify and decrypt (ZORRO — all-in-one encrypt+auth)
zorro encrypt+sign   --tray alice.tray document.pdf > document.zorro
zorro verify+decrypt --tray alice.tray document.zorro > document_out.pdf

# Pure hybrid digital signature (sign only — no encryption)
zorro sign   --tray alice.tray --in-file document.pdf > document.sig.yaml
zorro verify --tray alice.tray --in-file document.pdf --in-sig document.sig.yaml

# mceliece+slhdsa tray
hybrid keygen --group mceliece+slhdsa --profile level2 --alias bob --out bob.tray
zorro encrypt        --tray bob.tray plaintext.txt > message.armored
zorro decrypt        --tray bob.tray message.armored > recovered.txt
zorro encrypt+sign   --tray bob.tray document.pdf > document.zorro
zorro verify+decrypt --tray bob.tray document.zorro > document_out.pdf
zorro sign           --tray bob.tray --in-file document.pdf > document.sig.yaml
zorro verify         --tray bob.tray --in-file document.pdf --in-sig document.sig.yaml

# Password encryption (no tray needed)
zorro pwencrypt secret.txt secret.pwenc          # prompts for password
zorro pwdecrypt --pwfile pw.txt secret.pwenc secret_out.txt

# Token generation and validation
zorro gentok --tray alice.tray --data "user=alice" --ttl 3600 > token.b64
zorro valtok --tray alice.tray token.b64
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Success |
| 1    | Usage / argument error |
| 2    | Crypto failure (invalid signature, wrong password, tampered data) |
| 3    | I/O error (file not found, read/write failure) |
