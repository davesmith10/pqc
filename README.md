# pqc — Post-Quantum Crypto Tools + Libcrystals

**C++17 CLI tools and libraries for hybrid classical+PQC key management.**

## What Does This Actually Do?

### Concepts: The Tray, and the Hybrid

For the next few years, everyone (except maybe the Americans) is going to be very prudent and overkill and
implement both classical and post-quantum encryption and signature - because
we want to add additional complexity? No, because we have to plan for the situation 
in which a clever post-quantum algorithm wasn't actually so clever, and fails. 
In that scenario, we still have good old Elliptic Curve to cover our butts.

This leads to the "hybrid algorithm", which is an interesting design consideration. 
We need to use two different sets of asymmetric key materials to implement this, 
one set being classical, the other, post-quantum. 

It is convenient, since these key materials are not used separately, but the suggested
approach is to intertwine them, that they should be put together in one structure. Our
concept is the "tray" - more or less like a dish drying rack, with four "slots". Each
slot holds one key. The 0 and 2 positions (or 1 and 3, if you like) are for the
public keys, with the classical public key always at position 0. The 2 and 4 positions
in the tray are for the secret keys. 

Trays are not encoded in ASN-1 by default; that would be tedium. No, we use a YAML format
as our specification: simple, clean, easy to read, and we base64 encode the binary bits.

`hybrid` is a command-line application that does nothing but make these trays (it can
also protect the private keys with a password-based (scrypt) KDF). This level of protection
is not that different from PKCS12, but it does have the virtue of leaving the public keys
in full view. For things like signature verification.

`zorro` is a command-line application that uses the trays to do encryption and digital signature.
It has four basic operations:

- **encrypt / decrypt** — Encrypts a file using both the classical KEM slot and the PQ KEM slot
  from the tray. The two shared secrets are combined via a hybrid KDF; the result encrypts the
  payload with the chosen symmetric cipher. Output: PEM-armored `ZORRO ENCRYPTED FILE`.

- **encrypt+sign / verify+decrypt** (HYKE) — Encrypts and signs a file using all four slots in
  the tray: both KEM slots protect the symmetric key, and both signature slots (Ed25519/ECDSA +
  Dilithium or SLH-DSA) authenticate the header and encrypted payload. Output: PEM-armored
  `HYKE SIGNED FILE`.

- **sign / verify** (pure hybrid digital signature) — Signs an arbitrary file without encrypting
  it. Both the classical and PQ signature slots sign `M' = tray_uuid || SHA-256(file)`, producing
  a single composite signature. Output: YAML document containing the base64-encoded composite sig
  and metadata. Verification reads the YAML and recomputes the digest from the tray and file.

- **password encrypt / decrypt** — Password-based encryption without a tray. Generates an
  ephemeral Kyber keypair; the secret key is wrapped with scrypt, and the plaintext is encrypted
  with the Kyber shared secret. Probably the most secure password-based scheme in the world due
  to its hybrid, layered design.

See [ALGORITHMS.md](ALGORITHMS.md) for details on the ZORRO and HYKE hybrid algorithms,
and [PASSWORD-ENC.md](PASSWORD-ENC.md) for the PWENC password-based encryption scheme.

- **tokens** — zorro also provides a simple signed token with 256 bytes of space for
  assertions. Used for secure login with the [SAREK Secrets Vault](https://github.com/davesmith10/sarek).

`penelope` Showing somewhat our flair, penelope is a steganographic command-line application
that embeds the bytes of a tray into a Portable Network Graphics (png) file. This is mildly
interesting as it visualizes the key materials.

Note that the bytes are not in a *raw* condition; that would be insecure. Penelope provides an 
"encaps" (encapsulate) command that password encrypts the secret keys as it pngifies. 
It also can "pngify" any zorro encrypted file.

![](docs/img/penelope.png?raw=true)


# Tools

## hybrid — Hybrid Tray Keygen

Generates named **hybrid trays** — bundles of paired PQ+classical key slots
covering both KEM and signature roles.

```
hybrid keygen [--group crystals|mceliece+slhdsa|mlkem+mldsa|frodokem+falcon]
              [--profile <level>]
              --alias <name>
              [--out <file>]
              [--public]
hybrid protect   --in <file> --out <file> [--password-file <file>]
hybrid unprotect --in <file> --out <file> [--password-file <file>]
```

### Tray Selection

These might seem a bit capricious but there's a method to the madness. 

`crystals` profile are the public-domain kyber+dilithium lattice algorithms, fast and designed with involvement 
from Peter Schwabe. Gives us our project concept. These can be used with the X25519/Ed25519 classical EC.

`mceleice+slhdsa` The McEleice library we are using is the work of Daniel J. Bernstein and his team. 
The algorithm is intended for long-term storage - like 50 year storage. I have paired it with SLH-DSA (sphincs+)
which is a very strong pqc, NIST approved signature algorithm.

The `mlkem+mldsa` profile group is basically kyber+dilithium, but in the NIST approved
form, with slightly different key sizes. This is a good alternate if NIST standardization
is important (e.g., interoperability).

The `frodokem+falcon` pairing is a somewhat fanciful setup. FrodoKEM make large keys
but nowhere near as big as McEleice; and similar use-case for long-term storage. Falcon
was selected by NIST for the 4th round, and is known for fast and small signatures.

### Profile Groups and Profiles

We have "profile groups" which pair algorithms, and then profiles, which are marked as "level2, level3," etc.

Default group: `crystals`. Default profile: `level2-25519`.

**`--group crystals` profiles** (hybrid Kyber + Dilithium):

| Profile        | KEM-classic | KEM-PQ    | Sig-classic  | Sig-PQ     |
|----------------|-------------|-----------|--------------|------------|
| `level0`       | X25519      | —         | Ed25519      | —          |
| `level1`       | —           | Kyber512  | —            | Dilithium2 |
| `level2-25519` | X25519      | Kyber512  | Ed25519      | Dilithium2 |
| `level2`       | P-256       | Kyber512  | ECDSA P-256  | Dilithium2 |
| `level3`       | P-384       | Kyber768  | ECDSA P-384  | Dilithium3 |
| `level5`       | P-521       | Kyber1024 | ECDSA P-521  | Dilithium5 |

**`--group mceliece+slhdsa` profiles** (hybrid McEliece + SLH-DSA):

| Profile | KEM-classic | KEM-PQ            | Sig-classic  | Sig-PQ               |
|---------|-------------|-------------------|--------------|----------------------|
| `level1`| —           | mceliece348864f   | —            | SLH-DSA-SHA2-128f    |
| `level2`| P-256       | mceliece460896f   | ECDSA P-256  | SLH-DSA-SHA2-192f    |
| `level3`| P-384       | mceliece6688128f  | ECDSA P-384  | SLH-DSA-SHAKE-192f   |
| `level4`| P-521       | mceliece6960119f  | ECDSA P-521  | SLH-DSA-SHA2-256f    |
| `level5`| P-256       | mceliece8192128f  | ECDSA P-256  | SLH-DSA-SHAKE-256f   |

**`--group mlkem+mldsa` profiles** (hybrid ML-KEM + ML-DSA, NIST FIPS 203/204):

| Profile    | KEM-classic | KEM-PQ       | Sig-classic  | Sig-PQ     |
|------------|-------------|--------------|--------------|------------|
| `mk-level1`| —           | ML-KEM-512   | —            | ML-DSA-44  |
| `mk-level2`| P-256       | ML-KEM-512   | ECDSA P-256  | ML-DSA-44  |
| `mk-level3`| P-384       | ML-KEM-768   | ECDSA P-384  | ML-DSA-65  |
| `mk-level4`| P-521       | ML-KEM-1024  | ECDSA P-521  | ML-DSA-87  |

**`--group frodokem+falcon` profiles** (hybrid FrodoKEM + Falcon):

| Profile    | KEM-classic | KEM-PQ              | Sig-classic  | Sig-PQ       |
|------------|-------------|---------------------|--------------|--------------|
| `ff-level1`| —           | FrodoKEM-640-AES    | —            | Falcon-512   |
| `ff-level2`| P-256       | FrodoKEM-640-AES    | ECDSA P-256  | Falcon-512   |
| `ff-level3`| P-384       | FrodoKEM-976-AES    | ECDSA P-384  | Falcon-512   |
| `ff-level4`| P-521       | FrodoKEM-1344-AES   | ECDSA P-521  | Falcon-1024  |

**Output modes:**
- Default (no flags): YAML with literal block scalar base64 to stdout
- `--out <file>`: write YAML to `<file>`; auto-prints a human-readable summary to stdout
- `--public`: also emit a companion public tray (alias `<name>.pub`, **same UUID** as the private tray, no secret keys). 
With `--out`, written to `<name>.pub.<ext>`; without `--out`, both YAML documents go to stdout.


## zorro — Hybrid KEM Encryption and Signing

Encrypts and authenticates arbitrary files using a hybrid tray. Three operation
modes — **ZORRO** (encrypt-only), **HYKE** (encrypt-and-sign), and **pure hybrid
digital signature** (sign/verify without encryption).

#### Tray compatibility

`encrypt/decrypt` requires at least one classical KEM slot and one PQ KEM slot.
`encrypt+sign`/`verify+decrypt` and `sign`/`verify` additionally require both signature
slots. PQ-only trays (level1, mk-level1, ff-level1, mceliece+slhdsa level1) are rejected.

| Group            | Profiles                             | encrypt/decrypt | encrypt+sign / verify+decrypt | sign / verify |
|------------------|--------------------------------------|:---------------:|:-----------------------------:|:-------------:|
| crystals         | level2-25519, level2, level3, level5 | ✓ | ✓ | ✓ |
| crystals         | level0 (classical only)              | ✗ | ✗ | ✗ |
| crystals         | level1 (PQ only)                     | ✗ | ✗ | ✗ |
| mceliece+slhdsa  | level2, level3, level4, level5       | ✓ | ✓ | ✓ |
| mceliece+slhdsa  | level1 (PQ only)                     | ✗ | ✗ | ✗ |
| mlkem+mldsa      | mk-level2, mk-level3, mk-level4      | ✓ | ✓ | ✓ |
| mlkem+mldsa      | mk-level1 (PQ only)                  | ✗ | ✗ | ✗ |
| frodokem+falcon  | ff-level2, ff-level3, ff-level4      | ✓ | ✓ | ✓ |
| frodokem+falcon  | ff-level1 (PQ only)                  | ✗ | ✗ | ✗ |

`gentok`/`valtok` requires an ECDSA P-256 slot specifically: crystals `level2`,
or mceliece+slhdsa `level2`/`level5`.

#### encrypt / decrypt (ZORRO)

Uses both KEM slots from the tray (classical + PQ), combining their shared
secrets via a KDF, then encrypting with an AEAD cipher.

```
zorro encrypt --tray <file> [--kdf SHAKE|KMAC] [--cipher AES-256-GCM|ChaCha20] <target-file>
zorro decrypt --tray <file> <target-file>
```

- `--kdf`: `SHAKE` (SHAKE256, default) or `KMAC` (KMAC256)
- `--cipher`: `AES-256-GCM` (default) or `ChaCha20` (ChaCha20-Poly1305)
- KDF/cipher are stored in the wire header and auto-detected on decrypt

Output armor: `-----BEGIN/END ZORRO ENCRYPTED FILE-----`

Wire format: `"ZORRO001"` (8B) + KDF byte + cipher byte + `len32+CT_classical` +
`len32+CT_pq` + `nonce(12) || tag(16) || ciphertext`

#### pwencrypt / pwdecrypt (PWENC)

Password-based encryption without a tray. An **ephemeral** Kyber keypair is generated
fresh for each encryption; the Kyber secret key is password-wrapped via scrypt, and the
plaintext is encrypted with the Kyber shared secret. No pre-shared keys or tray files are
required.

```
zorro pwencrypt [--level 512|768|1024] [--scrypt-n 20] <infile> <outfile>
zorro pwdecrypt <infile> <outfile>
```

- `--level`: Kyber parameter set — `512`, `768` (default), or `1024`
- `--scrypt-n`: scrypt work factor as a log₂ exponent, `N = 2^n` (default 20, range 16–22)
- Password is prompted interactively; `pwencrypt` prompts twice for confirmation
- All decryption failures produce a single generic error (no oracle distinguishing
  wrong password from tampered ciphertext)

Output armor: `-----BEGIN/END ZORRO PW ENCRYPTED FILE-----`

Security is designed so that recovering the plaintext requires both a break of scrypt
(to recover the ephemeral Kyber secret key) **and** a break of Kyber's IND-CCA hardness
(to recover the shared secret without the secret key). See [PASSWORD-ENC.md](PASSWORD-ENC.md)
for full design rationale and wire format.

#### encrypt+sign / verify+decrypt (HYKE)

Encrypt-and-sign using **all four slots** from a full tray: both KEM slots for
encryption, both signature slots for authentication. Provides hybrid classical +
post-quantum confidentiality and authenticity in a single operation.

```
zorro encrypt+sign   --tray <file> <target-file>
zorro verify+decrypt --tray <file> <target-file>
```

- `encrypt+sign` requires a tray with all 4 slots including the signing secret keys
- `verify+decrypt` requires a tray with all 4 slots including the KEM secret keys
- Both classical (Ed25519 / ECDSA) and PQ (Dilithium / ML-DSA / Falcon) signatures are verified before decryption

Output armor: `-----BEGIN/END HYKE SIGNED FILE-----`

**Tray UUID self-verification**: on load, zorro recomputes the tray UUID from the
public key material in each slot (using the same BLAKE3 key-derivation algorithm as
hybrid) and rejects the tray if the stored UUID does not match. This detects accidental
corruption or substitution of key material. Trays with a non-v8 UUID are loaded without
verification (backward compat with pre-UUID-derivation trays).

Wire format: `"HYKE"` (4B) + version (2B) + tray\_id (1B) + flags (1B) +
header\_len (4B) + payload\_len (4B) + tray\_uuid (16B) + salt (32B) +
4 × length fields (16B) + `CT_classical` + `CT_pq` + `sig_classical` + `sig_pq` +
`nonce(12) || tag(16) || ciphertext`

**Context binding** prevents key-substitution attacks:
```
ctx = KMAC256(key=pk_classical, msg=pk_pq || "zorro-hybrid-sig-v1", outlen=512 bits)
```

**Signed data**: `ctx(64B) || header_fields_and_ciphertexts || encrypted_payload`

**KDF**: `KMAC256(key=ss_classical, msg=ss_pq || CT_classical || CT_pq || salt, outlen=256 bits)`

Security requires breaking **both** the classical and post-quantum KEMs (for
confidentiality) and **both** the classical and PQ signatures (for authenticity).

#### sign / verify (pure hybrid digital signature)

Signs an arbitrary document without encrypting it. Useful when confidentiality is handled
separately (e.g., the document is already at rest in encrypted storage) and only
authenticity and integrity are needed.

```
zorro sign   --tray <file> --in-file <file>
zorro verify --tray <file> --in-file <file> --in-sig <file>
```

**Algorithm**: `M' = tray_uuid(16B) || SHA-256(file_bytes)` is signed independently by
both the classical slot (Ed25519 or ECDSA) and the PQ slot (Dilithium / ML-DSA /
Falcon / SLH-DSA). The two signatures are packed as
`u32be(len_cl) || sig_cl || u32be(len_pq) || sig_pq` and base64-encoded into the
`composite_sig` field of the output YAML.

Using the tray UUID as a domain separator provides per-tray uniqueness, preventing
cross-tray signature confusion between two trays of the same profile type.

`sign` outputs:

```yaml
signature_id:  "..."  # random UUID v4, audit identifier only
tray_id:       "..."  # tray UUID (used as domain separator in M')
tray_alias:    "alice"
profile_group: "crystals"
profile:       "level2-25519"
input_file:    "document.pdf"
composite_sig: "BAAAA..."  # base64-encoded composite sig
```

`verify` reads the `--in-sig` YAML, cross-checks `tray_id` against the loaded tray,
recomputes `M'`, and verifies both signatures. Outputs `verified: true` plus the
same metadata fields on success (without `composite_sig`). Any failure exits 2.

## penelope — Tray Steganographic Encapsulator

Renders a hybrid tray into a password-protected annotated PNG image. Public key bytes
become plaintext rainbow-colored pixels; private key bytes are encrypted with AES-256-GCM
in place (scrypt-derived key). The PNG carries decryption metadata in an iTXt chunk and
can be fully recovered from the image and the original password.

```
penelope tray-encaps  --in-tray <file>    [--out-png <file.png>] [--pwfile <file>]
penelope tray-decaps  --in-png <file.png> [--out-tray <file>]    [--pwfile <file>]
```

Supports all tray profile groups: crystals, mceliece+slhdsa, mlkem+mldsa, frodokem+falcon.

See [penelope/README.md](penelope/README.md) for the full command reference, encryption scheme,
visual layout, and PNG chunk format.

## libcrystals-1.2 — Consolidated Crypto Library

Fat static archive (`libcrystals-1.2.a`) that bundles all PQ and classical cryptography
used by the tools — Kyber, Dilithium, McEliece, SLH-DSA, ML-KEM, ML-DSA, FrodoKEM,
Falcon, scrypt, XKCP, BLAKE3, and oneTBB. All three tools (hybrid, zorro, penelope)
link against it via the `Crystals::crystals` CMake target. The public API is a single
frozen header: `crystals/crystals.hpp`.

Install once before building any tool, defaults to /usr/local root:

```bash
sudo bash pqc/libcrystals-1.2/install.sh
```

See [libcrystals-1.2/README.md](libcrystals-1.2/README.md) for the API contract,
version history, dependency list, and install options.

## Building the Tools

**Prerequisites (all tools)**: CMake ≥ 3.15, GCC/Clang with C++17, OpenSSL 3.

**Additional prerequisites for hybrid**: `libcrystals-1.2` installed to `/usr/local` via
`sudo bash pqc/libcrystals-1.2/install.sh`. This installs the fat static archive, XKCP shared
library, and CMake package config. BLAKE3 and oneTBB must be in `Crystals/local/` first;
see `pqc/BLAKE3-BUILD.md` for the one-time build procedure.

**Additional prerequisites for zorro**: `libcrystals-1.2` installed to `/usr/local` via
`sudo bash pqc/libcrystals-1.2/install.sh` (same as hybrid). All crypto deps — Kyber,
Dilithium, ML-KEM, ML-DSA, FrodoKEM, Falcon, McEliece, SLH-DSA, scrypt, BLAKE3, oneTBB,
XKCP, yaml-cpp — are bundled inside the fat static archive.

**Build individual tools** (from the `Crystals/` root):

```bash
# hybrid — no CMAKE_PREFIX_PATH needed; uses libcrystals-1.2 from /usr/local
cmake -S pqc/hybrid  -B pqc/hybrid/build
cmake --build pqc/hybrid/build -j$(nproc)

# zorro — no CMAKE_PREFIX_PATH needed; uses libcrystals-1.2 from /usr/local
cmake -S pqc/zorro -B pqc/zorro/build
cmake --build pqc/zorro/build -j$(nproc)

```

**static-verify** — one-time check that the static Kyber + Dilithium libraries link and
run correctly (no external dependencies):

```bash
cmake -S pqc/static-verify -B pqc/static-verify/build
cmake --build pqc/static-verify/build -j$(nproc)
./pqc/static-verify/build/test_static_pq   # all 6 levels should print OK
```

## Exit Codes

All tools use the same exit code convention:

| Code | Meaning |
|------|---------|
| `0`  | Success |
| `1`  | Usage / argument error |
| `2`  | Crypto failure (decaps mismatch, invalid signature) |
| `3`  | I/O error (file not found, wrong PEM header level) |

## Repository Layout

Quite a bit of third-party crypto is going into libcrystals. While this is somewhat fetishistic, I guess I just like crypto.
We need to gather these source project from github. 

```
Crystals/
├── kyber/ref/                — Kyber reference C source; statically compiled and linked
├── kyber/avx2/               — Kyber AVX2 source (not currently used)
├── dilithium/ref/            — Dilithium reference C source; statically compiled and linked
├── dilithium/avx2/           — Dilithium AVX2 source (not currently used)
├── liboqs/                   — Open Quantum Safe library (ML-KEM, ML-DSA, FrodoKEM, Falcon, etc.)
├── libmceliece/              — Classic McEliece KEM source
├── scrypt/                   — scrypt KDF source
├── XKCP/                     — eXtended Keccak Code Package; pre-built libXKCP.so (SHAKE/KMAC)
├── BLAKE3/                   — BLAKE3 source; built + installed to local/ (UUID derivation)
├── oneTBB/                   — oneTBB source; built + installed to local/ (BLAKE3 parallelism)
├── lodepng/                  — LodePNG source (vendored; PNG encode/decode used by penelope)
├── librandombytes-20240318/  — RNG API shim (DJB; used during PQ keygen)
├── libcpucycles-20260105/    — CPU cycle counter (DJB; benchmarking only)
├── local/                    — Shared install prefix for BLAKE3 + TBB (CMake finds them here)
└── pqc/                      — Main project (git root)
    ├── include/              — Shared headers (tray.hpp domain model)
    ├── hybrid/               — Hybrid PQ+classical tray keygen tool (uses libcrystals-1.2)
    ├── zorro/                — Hybrid KEM file encryption tool
    ├── penelope/             — Tray steganographic encapsulator (tray → password-protected PNG)
    ├── libcrystals-1.2/      — Consolidated crypto library; installed to /usr/local via install.sh
    ├── misc/                 — Utilities (hashpass, etc.)
    └── static-verify/        — Standalone project verifying the static Kyber + Dilithium CMake
                                libraries; links all 8 static targets + randombytes.c, runs KEM
                                and signature round-trips for all 6 parameter sets
                            
    pqc-java/                 — Java Binding (coming soon)
    ├── shim/                 — thin shim in extern C for a reliable ABI to use with FFM API.
    ├── java/                 — Java binding
                            
```

## Licensing

The pqc repo contents is available under an MIT license:

```
© 2026 David R. Smith, All Rights Reserved

By obtaining, using, and/or copying this software and/or its associated documentation, you agree that you have read, understood, 
and will comply with the following terms and conditions:

Permission to use, copy, modify, and distribute this software and its associated documentation for any purpose and without fee is 
hereby granted, provided that the above copyright notice appears in all copies, and that both that copyright notice and this permission 
notice appear in supporting documentation, and that the name of the copyright holder not be used in advertising or publicity pertaining 
to distribution of the software without specific, written prior permission.

THE COPYRIGHT HOLDER DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. 
IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING 
FROM THE LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

```

See [LICENSE-THIRD-PARTY](LICENSE-THIRD-PARTY) for a comprehensive list of third-party software that has been linked to.






