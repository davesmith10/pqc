# PWENC — Password-Based Post-Quantum Encryption

This document describes the **PWENC** scheme implemented by `zorro pwencrypt` and
`zorro pwdecrypt`. An implementer should be able to reproduce the wire format and
encryption/decryption procedures from this document alone.

---

## 1. Motivation and Design Goals

Most password-based encryption tools (GnuPG `--symmetric`, age, OpenSSL enc) derive the
data encryption key directly from the password via a KDF. This design has a well-known
limitation: the password **is** the key. A sufficiently determined adversary who records
the ciphertext today and later obtains a faster machine (classical or quantum) can mount
an offline dictionary attack with no additional cryptographic barriers.

PWENC adds a second, independent barrier: a **post-quantum KEM** (Kyber). The data is
encrypted under a fresh Kyber shared secret, not under the password-derived key directly.
The password-derived key is used only to wrap the Kyber secret key, keeping it confidential.

This achieves two complementary properties:

1. **Password-gated access**: decryption requires presenting the correct password
   (or brute-forcing the scrypt function). A quantum adversary gets no meaningful
   speedup on a correctly-tuned scrypt invocation beyond Grover's ≈√ reduction.

2. **Post-quantum data confidentiality**: the data encryption key (`ss`) is a fresh Kyber
   shared secret, believed to be hard for quantum computers to recover from the public key
   and ciphertext alone. An adversary recording ciphertext today cannot later recover `ss`
   by quantum-attacking the symmetric or KDF layer; they would need to break Kyber's
   IND-CCA hardness.

---

## 2. The Two-Layer Construction

The scheme uses two independent AES-256-GCM ciphertexts, each with its own key and nonce:

```
                    ┌─────────────────────────────────────────┐
                    │          bundle (on disk)               │
                    │                                         │
password ──scrypt──►  wrap_key ──AES-GCM──► [sk_enc]         │
                    │                           │             │
Kyber.KeyGen ──────►  (pk, sk) ◄───────────────┘             │
                    │                                         │
Kyber.Enc(pk) ─────►  (ct, ss)                               │
                    │      │                                  │
plaintext ─────────────────┘ ──AES-GCM(aad)──► [data_enc]   │
                    │                                         │
                    │  pk, ct, salt, params, sk_enc, data_enc │
                    └─────────────────────────────────────────┘
```

### Layer 1 — Key wrapping (scrypt + AES-256-GCM)

```
salt      ← CSPRNG(32 bytes)
wrap_key  ← scrypt(password, salt, N=2^n_log2, r=8, p=1, outlen=32)
sk_enc    ← AES-256-GCM.Encrypt(key=wrap_key, plaintext=sk, aad=∅)
```

`sk_enc` is a 28 + sk_size byte blob: `nonce(12) || tag(16) || ciphertext(sk_size)`.

`sk` is the secret key of the ephemeral Kyber keypair — typically 1632, 2400, or 3168
bytes depending on the selected level. No AAD is used for the wrap layer (the wrap blob
is fully authenticated by the GCM tag; the outer bundle header provides context binding
for the data layer instead).

### Layer 2 — Data encryption (Kyber KEM + AES-256-GCM with AAD)

```
(pk, sk)  ← Kyber{N}.KeyGen()           # ephemeral, fresh per encryption
(ct, ss)  ← Kyber{N}.Enc(pk)            # ss = 32-byte shared secret
aad       ← "OBWE" || 0x01 || BE16(level)   # 7 bytes; binds ciphertext to its metadata
data_enc  ← AES-256-GCM.Encrypt(key=ss, plaintext=plaintext, aad=aad)
```

`data_enc` is a 28 + plaintext_size byte blob: `nonce(12) || tag(16) || ciphertext(M)`.

The 7-byte AAD commits the data ciphertext to the bundle header's magic, version, and
Kyber level. This prevents an attacker from modifying the level field to confuse a
decryptor into using the wrong key sizes, and prevents transplanting a data ciphertext
from one bundle into another.

---

## 3. Security Model

### What an attacker needs

An attacker who records a PWENC bundle has access to:
- `pk` (Kyber public key, in the clear)
- `ct` (Kyber ciphertext, in the clear)
- `sk_enc` (sk wrapped with scrypt output)
- `data_enc` (plaintext encrypted with `ss`)
- `salt`, scrypt parameters (in the clear)

To recover the plaintext the attacker must recover `ss`. There are exactly two routes:

**Route A — Via the KEM**: break Kyber's IND-CCA security and recover `ss` directly
from `(pk, ct)` without knowing `sk`. This is believed to be computationally infeasible
for both classical and quantum computers (Kyber's security is based on the hardness of
module Learning with Errors, MLWE).

**Route B — Via the password**: break the scrypt layer to recover `wrap_key`, unwrap
`sk`, then run the classical Kyber decapsulation algorithm (a fast, deterministic
computation) to get `ss`. Breaking scrypt requires either guessing the password or
exhausting the scrypt parameter space — the memory-hard construction limits the speed
at which candidates can be tested.

Blocking Route A and Route B independently means:

| Adversary | Route A feasible? | Route B feasible? | Can decrypt? |
|-----------|------------------|------------------|-------------|
| Classical, no password | No (classical MLWE) | No (scrypt hard) | **No** |
| Classical, knows password | No | **Yes** | Yes |
| Quantum, no password | No (MLWE quantum-hard by design) | Limited (Grover ~√ speedup on scrypt) | **Not without strong password** |
| Quantum, breaks Kyber | **Yes** | Irrelevant | Yes |
| Quantum, knows password | No | **Yes** | Yes |

The design is **not** a generic "must break both simultaneously" construction in all
adversary models — knowing the password is sufficient to decrypt. The contribution
of the Kyber layer is specifically against **offline quantum attacks on the data layer**:
the data key `ss` is a Kyber shared secret, not a password-derived key, so quantum
computers get no shortcut to `ss` from `(pk, ct)` that they would not need for any
other Kyber ciphertext.

### What changes compared to a simple PBKDF + AES scheme

In a classical `scrypt → AES-256-GCM` scheme, every bit of data confidentiality rests
on the password. Here, the data confidentiality also rests on Kyber's hardness. The
password determines **access to the decryption key**, but the data key `ss` has its own
hardness independent of the password.

Concretely: an adversary who records the bundle today and later learns the password can
decrypt. An adversary who records the bundle today and later acquires a quantum computer
capable of breaking all classical crypto cannot decrypt unless Kyber is also broken (which
would be a separate, significant cryptographic event). This is the classical hybrid-security
motivation applied to the password setting.

### scrypt parameters

The default parameters are `N=2^20, r=8, p=1` (the Colin Percival 2017 recommendation
for interactive use, consuming ~1 GiB of memory per attempt). The `--scrypt-n` flag
accepts 16–22 (64 MiB to 4 GiB). Higher `n` raises the cost for both the legitimate
user and an attacker proportionally.

---

## 4. Wire Format

All multi-byte integer fields are **big-endian**.

```
Offset      Size    Field
------      ----    -----
   0           4    Magic: ASCII "OBWE"
   4           1    Version: 0x01
   5           2    Level: uint16  (512, 768, or 1024)
   7          32    salt   (32 random bytes)
  39           1    scrypt_n_log2  (uint8; N = 2^scrypt_n_log2)
  40           1    scrypt_r       (uint8; fixed 8 in current implementation)
  41           1    scrypt_p       (uint8; fixed 1 in current implementation)
  42         pk_sz  pk  (Kyber public key; see §4.1 for sizes)
42+pk        ct_sz  ct  (Kyber ciphertext)
42+pk+ct      12    wrap_nonce
  +12          16    wrap_tag
  +28        sk_sz  sk_enc  (scrypt-wrapped Kyber secret key)
  +sk_sz      12    data_nonce
  +12          16    data_tag
  +28           M    ciphertext  (AES-256-GCM-encrypted plaintext)
```

The full wire blob is base64-encoded (standard alphabet, 64-character line wrap) and
wrapped in PEM-style armor.

### 4.1 Algorithm sizes by level

| Level       | pk_sz  | sk_sz  | ct_sz  | ss_sz | wrap blob  | scrypt_n default |
|-------------|--------|--------|--------|-------|------------|-----------------|
| Kyber512    | 800 B  | 1632 B | 768 B  | 32 B  | 1676 B     | 20 (N=2^20)     |
| Kyber768    | 1184 B | 2400 B | 1088 B | 32 B  | 2444 B     | 20              |
| Kyber1024   | 1568 B | 3168 B | 1568 B | 32 B  | 3212 B     | 20              |

`wrap_blob` = 12 (nonce) + 16 (tag) + sk_sz.

### 4.2 AAD

The 7-byte additional authenticated data for the data layer is:

```
aad = magic(4) || version(1) || level_be16(2)
    = "OBWE" || 0x01 || BE16(level)
```

For Kyber768 (level 768 = 0x0300): `aad = 4F 42 57 45 01 03 00`.

The wrap layer uses **no AAD** (aad = ∅, aad_len = 0).

### 4.3 Armor

```
-----BEGIN ZORRO PW ENCRYPTED FILE-----
<base64 lines, 64 characters each>
-----END ZORRO PW ENCRYPTED FILE-----
```

---

## 5. Encrypt Procedure

1. Parse arguments; validate `level` ∈ {512, 768, 1024} and `scrypt_n_log2` ∈ [16, 22].
2. Read plaintext from `<infile>`.
3. Prompt for password twice; confirm match.
4. Generate ephemeral Kyber keypair: `(pk, sk) ← Kyber{level}.KeyGen()`.
5. Encapsulate: `(ct, ss) ← Kyber{level}.Enc(pk)`.
6. Generate `salt ← CSPRNG(32)`.
7. Derive wrap key: `wrap_key ← scrypt(password, salt, N=2^n, r=8, p=1, outlen=32)`.
8. Wrap secret key: `wrap_blob ← AES-256-GCM.Encrypt(key=wrap_key, pt=sk, aad=∅)`.
   Format: `nonce(12) || tag(16) || sk_enc(sk_sz)`.
9. Construct 7-byte `aad` from magic, version, and level (§4.2).
10. Encrypt plaintext: `data_blob ← AES-256-GCM.Encrypt(key=ss, pt=plaintext, aad=aad)`.
    Format: `nonce(12) || tag(16) || ciphertext(M)`.
11. Assemble wire bundle per §4 layout.
12. Base64-encode; wrap in armor; write to `<outfile>`.
13. Securely zero `sk`, `ss`, `wrap_key` from memory.

---

## 6. Decrypt Procedure

1. Parse arguments.
2. Read armored bundle from `<infile>`; strip armor; base64-decode.
3. Parse wire bundle per §4 layout to extract: `level`, `salt`, scrypt params,
   `pk`, `ct`, `wrap_blob`, `data_blob`.
4. Prompt for password once.
5. Derive: `wrap_key ← scrypt(password, salt, N=2^scrypt_n_log2, r=scrypt_r, p=scrypt_p, outlen=32)`.
6. Unwrap: `sk ← AES-256-GCM.Decrypt(key=wrap_key, ct=wrap_blob, aad=∅)`.
   Authentication failure → generic error, exit 2.
7. Validate `sk` length matches expected size for `level`.
8. Decapsulate: `ss ← Kyber{level}.Dec(sk, ct)`.
9. Construct 7-byte `aad` (§4.2).
10. Decrypt: `plaintext ← AES-256-GCM.Decrypt(key=ss, ct=data_blob, aad=aad)`.
    Authentication failure → generic error, exit 2.
11. Write plaintext to `<outfile>`.
12. Securely zero `sk`, `ss`, `wrap_key` from memory.

**Error handling**: all decryption failures (wrong password, tampered ciphertext,
corrupted bundle) produce the same error message:

```
decryption failed: incorrect password or corrupted file
```

This prevents distinguishing a wrong password from a corrupted file without providing
an oracle to an attacker.

---

## 7. Implementation Notes

- **Nonce generation**: all nonces (both wrap and data layers) are generated via
  `RAND_bytes()` (OpenSSL's CSPRNG). They are chosen independently and stored in the
  bundle; no nonce counter or derived-nonce scheme is used.

- **Key separation**: `wrap_key` and `ss` are completely independent keys derived via
  independent mechanisms (scrypt and Kyber respectively). There is no risk of key reuse
  between the two AES-256-GCM invocations even if their nonces collide — the keys are
  different.

- **Kyber KEM is ephemeral**: the public key `pk` and ciphertext `ct` stored in the
  bundle are unique to this encryption. The corresponding `sk` exists only in the bundle
  (wrapped by the password) and in memory during encryption/decryption. There are no
  long-term Kyber keys and no tray files involved.

- **Memory zeroing**: after use, `sk`, `ss`, and `wrap_key` are overwritten via
  `OPENSSL_cleanse()` to reduce the window during which sensitive material is in memory.

- **scrypt library**: uses Colin Percival's reference scrypt implementation
  (`crypto_scrypt` from `libscrypt-kdf`). The `crypto_scrypt` function signature is:
  ```c
  int crypto_scrypt(const uint8_t *passwd, size_t passwdlen,
                    const uint8_t *salt,   size_t saltlen,
                    uint64_t N, uint32_t r, uint32_t p,
                    uint8_t *buf, size_t buflen);
  ```
  Returns 0 on success, -1 on failure (e.g. insufficient memory for the requested N).

- **Password prompting**: `EVP_read_pw_string()` (OpenSSL) handles interactive password
  input, including echo suppression. `pwencrypt` calls it twice and compares; `pwdecrypt`
  calls it once.

- **Kyber reference**: uses `pqcrystals_kyber{512,768,1024}_ref_{keypair,enc,dec}` from
  the CRYSTALS-Kyber reference implementation, linked statically. The shared secret is
  always 32 bytes regardless of level.

---

## 8. Comparison with ZORRO/HYKE

| Property | ZORRO/HYKE | PWENC |
|---|---|---|
| Key management | Pre-generated hybrid tray (hybrid) | Password only; no tray |
| Kyber key | Long-term (in tray) | Ephemeral (new per encryption) |
| Classical KEM | Yes (X25519 / P-curves) | No |
| Authentication | HYKE only: classical + PQ sig | None (AES-GCM provides integrity) |
| Decryption requires | Tray file + secret keys | Password |
| Post-quantum data key | From tray Kyber slot | From ephemeral Kyber |
| Suitable for | Secure file exchange, signing | Password-protected archives |

PWENC intentionally omits the classical KEM layer present in ZORRO/HYKE. The hybrid
rationale for ZORRO/HYKE is that if Kyber is broken, the classical KEM still provides
security. PWENC instead relies on Kyber alone for data key confidentiality, accepting
that a Kyber break would compromise the data key regardless of what classical layer was
added — because the classical KEM approach requires long-term key infrastructure (a tray)
which PWENC explicitly avoids.
