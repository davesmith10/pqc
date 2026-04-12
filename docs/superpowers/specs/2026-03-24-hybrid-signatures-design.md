# Hybrid Digital Signatures — Design Spec

**Date:** 2026-03-24
**Status:** Approved
**Scope:** `@pqc/zorro` CLI only. No changes to `libcrystals-1.2` — all required primitives already present in the installed library.

---

## Overview

Add a pure hybrid digital signature capability to `zorro`: a `sign` command that signs an
arbitrary document using both the classical and PQ signature keys in a tray, and a `verify`
command that checks the resulting composite signature. The existing HYKE sign+encrypt and
verify+decrypt operations are renamed to `encrypt+sign` and `verify+decrypt` respectively to
free up the `sign` and `verify` names.

---

## Command Renames

| Old command | New command | Behaviour |
|---|---|---|
| `sign` | `encrypt+sign` | HYKE (encrypt-and-sign) — unchanged internally |
| `verify` | `verify+decrypt` | HYKE (verify-and-decrypt) — unchanged internally |
| *(new)* | `sign` | Pure hybrid digital signature (no encryption) |
| *(new)* | `verify` | Pure hybrid signature verification (no decryption) |

Internal C++ function renames in `zorro/src/main.cpp`:
- `cmd_sign` → `cmd_encrypt_sign`
- `cmd_verify` → `cmd_verify_decrypt`
- New: `cmd_pure_sign`, `cmd_pure_verify`

No changes to the library — all required primitives already exist.

---

## Tray Requirements

Both `sign` and `verify` require a tray with **both** a classical signature slot and a PQ
signature slot. Partial-key trays (level0 classical-only, level1 PQ-only, mceliece+slhdsa
level1 PQ-only) are rejected with exit 1 and a clear error message. This is consistent with
the existing `encrypt+sign` / `verify+decrypt` behaviour.

Supported profile groups and their eligible profiles (those with both sig slots):
- `crystals`: level2-25519, level2, level3, level5
- `mceliece+slhdsa`: level2, level3, level4, level5
- `mlkem+mldsa`: mk-level2, mk-level3, mk-level4 (PQ sig via `oqs_sig::sign/verify`)
- `frodokem+falcon`: ff-level2, ff-level3 (PQ sig via `oqs_sig::sign/verify`)

---

## Algorithm

### Domain Construction

```
M' = uuid_bytes(16) || SHA-256(file_bytes)
```

- `uuid_bytes`: the tray UUID parsed to raw 16 bytes via the existing `parse_uuid()` function.
  Using the UUID as domain provides per-tray uniqueness (not just per-profile-type), preventing
  cross-tray signature confusion attacks between two trays of the same profile.
- `SHA-256`: computed via `EVP_digest` (OpenSSL, already linked).
- `M'` is 48 bytes total.

### Composite Signature Wire Format

```
u32be(len_cl) || sig_cl || u32be(len_pq) || sig_pq
```

Both components are always present (no partial-key trays supported). Length prefixes handle
variable-length PQ signatures (e.g. Falcon via `oqs_sig`). The composite is treated as a
single opaque blob — it represents one hybrid signing operation, not two independent
signatures.

The composite is base64-encoded for embedding in the YAML output.

---

## `sign` Command

### CLI

```
zorro sign --tray <path> --in-file <path>
```

### Steps

1. Load tray; find classical sig slot and PQ sig slot — reject if either missing (exit 1).
2. Require both sig secret keys present — reject public-only tray (exit 1).
3. Read file bytes from `--in-file`.
4. Generate a fresh random UUID v4 for `signature_id` via `RAND_bytes`.
5. Parse tray UUID string → 16 raw bytes via `parse_uuid()`.
6. Compute `SHA-256(file_bytes)` → 32-byte hash via `EVP_digest`.
7. Build `M' = uuid_bytes(16) || hash(32)`.
8. Sign with classical: `ec_sig::sign(cl_sig->alg_name, cl_sig->sk, M', sig_cl)`.
9. Sign with PQ: same three-way dispatch used by the existing `cmd_encrypt_sign`:
   `dilithium_sig::is_pq_sig()` → `dilithium_sig::sign`; `oqs_sig::is_oqs_sig()` → `oqs_sig::sign`;
   else → `slhdsa_sig::sign`. The dispatch logic is duplicated inline in `cmd_pure_sign`
   (consistent with the existing single-file pattern; no shared helper extracted).
10. Pack composite: `u32be(len_cl) || sig_cl || u32be(len_pq) || sig_pq`.
11. Base64-encode composite.
12. Emit YAML to stdout.

### Output YAML

```yaml
signature_id: "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
tray_id: "3f2a1b4c-8e1d-4a2b-9c3d-7f6e5d4c3b2a"
tray_alias: "alice"
profile_group: "crystals"
profile: "level3"
input_file: "document.pdf"
composite_sig: "BAAAAJQB3f2a1..."
```

`profile` is derived from `tray.tray_type` via a local `tray_type_to_profile(TrayType)`
helper in `main.cpp` (switch statement mapping enum values to canonical level name strings,
e.g. `Level3` → `"level3"`, `Level2_25519` → `"level2-25519"`, `McEliece_Level2` → `"level2"`,
`MlKem_Level2` → `"mk-level2"`, `FrodoFalcon_Level2` → `"ff-level2"`).
`profile_group` is read directly from `tray.profile_group` (already a string field on `Tray`).

`signature_id` is an audit field only. It is not incorporated into `M'` and plays no role
in the cryptographic verification. Its purpose is to give each signature bundle a unique,
trackable identity.

---

## `verify` Command

### CLI

```
zorro verify --tray <path> --in-file <path> --in-sig <path>
```

### Steps

1. Load tray; find classical sig slot and PQ sig slot — reject if either missing (exit 1).
2. Parse signature YAML from `--in-sig`; extract `tray_id`, `composite_sig`, `signature_id`,
   and `input_file`. Missing `tray_id` or `composite_sig` → stderr + exit 2.
3. Cross-check `tray_id` in YAML against `tray.id` — mismatch → stderr + exit 2.
4. Read file bytes from `--in-file`.
5. Parse tray UUID → 16 raw bytes via `parse_uuid()` on `tray.id`.
6. Compute `SHA-256(file_bytes)` → 32-byte hash.
7. Build `M' = uuid_bytes(16) || hash(32)`.
8. Base64-decode `composite_sig` — failure (invalid characters) → stderr + exit 2.
   Parse `u32be(len_cl) || sig_cl || u32be(len_pq) || sig_pq`; if `len_cl` or `len_pq`
   exceeds the remaining buffer, treat as malformed → stderr + exit 2.
9. Verify classical: `ec_sig::verify(cl_sig->alg_name, cl_sig->pk, M', sig_cl)` — `alg_name`
   and `pk` come from the loaded tray's classical sig slot, not from the YAML. Fail → exit 2.
10. Verify PQ: same three-way dispatch as `cmd_encrypt_sign` / `cmd_pure_sign`:
    `dilithium_sig::is_pq_sig()` → `dilithium_sig::verify`; `oqs_sig::is_oqs_sig()` → `oqs_sig::verify`;
    else → `slhdsa_sig::verify`. All use `pq_sig->alg_name` and `pq_sig->pk` from the tray. Fail → exit 2.
11. Both pass → emit YAML to stdout (echoing `signature_id` and `input_file` from parsed sig YAML,
    remaining fields from loaded tray) + exit 0.

### Output YAML (on success)

```yaml
verified: true
signature_id: "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
tray_id: "3f2a1b4c-8e1d-4a2b-9c3d-7f6e5d4c3b2a"
tray_alias: "alice"
profile_group: "crystals"
profile: "level3"
input_file: "document.pdf"
```

`composite_sig` is intentionally omitted from the verify output — the caller retains the
original sig file.

---

## Error Handling

| Condition | Exit |
|---|---|
| Missing/unknown flag or command | 1 |
| Missing `--tray` or `--in-file` (either command); missing `--in-sig` (`verify` only) | 1 |
| Unknown flag passed (e.g. `--in-sig` passed to `sign`) | 1 |
| Protected (secure-tray) YAML passed as `--tray` — `load_tray` rejects it | 3 |
| Tray missing classical or PQ sig slot | 1 |
| Public-only tray passed to `sign` | 1 |
| `tray_id` mismatch | 2 |
| Classical signature invalid | 2 |
| PQ signature invalid | 2 |
| Malformed composite sig bytes (including out-of-bounds length fields) | 2 |
| Sig YAML present but missing a required field (`tray_id`, `composite_sig`) | 2 |
| Any crypto operation throws | 2 |
| File or YAML unreadable | 3 |

All errors print a descriptive message to stderr before exiting.

---

## YAML Parsing

The signature YAML (`--in-sig`) is a simple flat document. Rather than pulling in yaml-cpp
(which is already in libcrystals but not directly in zorro's main.cpp), parse with
lightweight line-by-line `key: value` parsing — consistent with the fact that zorro
currently emits YAML by hand (no yaml-cpp in main.cpp).

The verifier requires exactly two fields for cryptographic correctness:
- `tray_id` — for cross-checking against the loaded tray
- `composite_sig` — the signature blob

The remaining fields (`signature_id`, `tray_alias`, `profile_group`, `profile`, `input_file`)
are informational. The verifier reads `signature_id` and `input_file` to echo them in its
output YAML; `tray_alias`, `profile_group`, and `profile` may be ignored during parsing.
`profile_group` is read directly from `tray.profile_group` (a field on the `Tray` struct)
for the output YAML — no additional helper is needed for it.

A missing `tray_id` or `composite_sig` field is treated as a malformed sig file → exit 2.

---

## Testing Plan

```bash
# Basic sign/verify roundtrip — crystals level2-25519
hybrid keygen --alias alice --profile level2-25519 > /tmp/alice.tray
echo "hello world" > /tmp/doc.txt
zorro sign   --tray /tmp/alice.tray --in-file /tmp/doc.txt > /tmp/doc.sig.yaml
zorro verify --tray /tmp/alice.tray --in-file /tmp/doc.txt --in-sig /tmp/doc.sig.yaml

# All 4 crystals hybrid profiles: level2-25519, level2, level3, level5
# mceliece+slhdsa with 4 slots: level2, level3, level4, level5
# mlkem+mldsa and frodokem+falcon profiles where both sig slots present

# Tampered file → exit 2
echo "tampered" > /tmp/doc2.txt
zorro verify --tray /tmp/alice.tray --in-file /tmp/doc2.txt --in-sig /tmp/doc.sig.yaml

# Wrong tray → exit 2 (tray_id mismatch)
hybrid keygen --alias bob --profile level2-25519 > /tmp/bob.tray
zorro verify --tray /tmp/bob.tray --in-file /tmp/doc.txt --in-sig /tmp/doc.sig.yaml

# Renamed HYKE commands still work
zorro encrypt+sign   --tray /tmp/alice.tray /tmp/doc.txt > /tmp/doc.hyke
zorro verify+decrypt --tray /tmp/alice.tray /tmp/doc.hyke | diff /tmp/doc.txt -

# Partial tray → exit 1 with clear error
hybrid keygen --alias cl-only --profile level0 > /tmp/cl.tray
zorro sign --tray /tmp/cl.tray --in-file /tmp/doc.txt   # expect exit 1

# Tampered composite_sig blob → exit 2 (both sig checks fail)
cp /tmp/doc.sig.yaml /tmp/doc.sig.corrupt.yaml
# manually corrupt one base64 character in composite_sig field
zorro verify --tray /tmp/alice.tray --in-file /tmp/doc.txt --in-sig /tmp/doc.sig.corrupt.yaml

# 1MB binary file roundtrip
dd if=/dev/urandom of=/tmp/big.bin bs=1M count=1
zorro sign   --tray /tmp/alice.tray --in-file /tmp/big.bin > /tmp/big.sig.yaml
zorro verify --tray /tmp/alice.tray --in-file /tmp/big.bin --in-sig /tmp/big.sig.yaml
```

---

## Out of Scope

- Existing HYKE (`encrypt+sign` / `verify+decrypt`) code is left unchanged.
- No changes to `libcrystals-1.2` public API.
- No streaming / chunked file hashing (entire file read into memory, consistent with existing zorro behaviour).
