# McEliece HYKE Support — Design Spec

**Date:** 2026-04-05  
**Status:** Approved for implementation  
**Scope:** Unblock `@api-stable-1.2` — allow McEliece Level2–5 trays to be used with `obi-wan encrypt+sign` / `verify+decrypt` (HYKE wire format)

---

## Background

`tray_id_byte()` and `tray_type_from_id()` in `crystals.hpp` encode tray type into the HYKE wire header. McEliece tray types (`McEliece_Level1`–`Level5`) were absent from both functions, causing them to throw `std::invalid_argument("Unknown TrayType")` when any McEliece tray was used for HYKE. All other crypto dispatch for McEliece (KEM encaps/decaps, SLH-DSA sign/verify) was already correct in `obi-wan`.

McEliece Level1 is a PQ-only tray (no classical KEM or sig slots) and structurally cannot participate in HYKE, which requires all four slots. It receives a tray ID byte for API completeness but is rejected early with a clear diagnostic.

---

## Wire Format

No changes. HYKE wire `version = 0x0001` is unchanged. The existing `uint32_t` ciphertext length fields accommodate McEliece ciphertext sizes (up to ~240 KB for mc8192128f).

ID byte assignment follows the existing block scheme:

| Block | Group |
|-------|-------|
| `0x0x` | crystals (Kyber + Dilithium) |
| `0x1x` | mlkem + mldsa |
| `0x2x` | frodokem + falcon |
| `0x3x` | mceliece + slhdsa |

McEliece assignments:

| TrayType | ID byte |
|----------|---------|
| `McEliece_Level1` | `0x31` |
| `McEliece_Level2` | `0x32` |
| `McEliece_Level3` | `0x33` |
| `McEliece_Level4` | `0x34` |
| `McEliece_Level5` | `0x35` |

---

## Library Changes (`crystals.hpp`)

### 1. `tray_id_byte()` — additive

Add five cases returning `0x31`–`0x35` for `McEliece_Level1`–`Level5`. Existing inputs and behavior unchanged. Function remains `@api-stable v1.0`.

### 2. `tray_type_from_id()` — additive

Add inverse mappings for `0x31`–`0x35`. Function remains `@api-stable v1.0`.

### 3. New helper: `is_tray_complete(TrayType t)` — `@api-stable v1.2`

```cpp
inline bool is_tray_complete(TrayType t);
```

Returns `false` for structurally partial trays (missing classical or PQ slots):
- `TrayType::Level0` — crystals, classical-only
- `TrayType::Level1` — crystals, PQ-only
- `TrayType::McEliece_Level1` — mceliece+slhdsa, PQ-only

Returns `true` for all other tray types (all have four slots and are valid HYKE candidates).

Consumers call this before any HYKE operation to obtain a meaningful diagnostic rather than a generic slot-missing failure.

---

## `obi-wan` Changes (`src/main.cpp`)

Two surgical insertions immediately after the tray is loaded in:

- `cmd_encrypt_sign` (before the slot scan, ~line 437)
- `cmd_verify_decrypt` (before the slot scan, ~line 605)

```cpp
if (!is_tray_complete(tray.tray_type)) {
    std::cerr << "Error: '" << tray.type_str
              << "' is a partial tray and cannot be used for HYKE"
              << " — a full 4-slot tray (classical + PQ KEM and sig) is required\n";
    return 1;
}
```

No other changes to `obi-wan`. KEM dispatch (`mceliece_kem::encaps/decaps`) and sig dispatch (`slhdsa_sig::sign/verify`) are already correct for McEliece trays.

---

## Testing

### `api_stability_test-1.2.cpp`

Add to the `@api-stable v1.2` block:

- `tray_id_byte` / `tray_type_from_id` round-trip assertions for `McEliece_Level1`–`Level5` (`0x31`–`0x35`)
- `is_tray_complete` returns `false` for `Level0`, `Level1`, `McEliece_Level1`
- `is_tray_complete` returns `true` for a representative set of full trays (e.g. `Level2_25519`, `McEliece_Level2`, `MlKem_Level2`, `FrodoFalcon_Level2`)

### Integration (manual, via `CLAUDE.md` test commands)

New entries to add to verified-working:

```bash
# McEliece HYKE encrypt+sign / verify+decrypt (Level2–5)
./scotty keygen --group mceliece+slhdsa --alias mc --profile level2 --out /tmp/mc.tray
echo "hello" > /tmp/plain.txt
./obi-wan encrypt+sign   --tray /tmp/mc.tray /tmp/plain.txt > /tmp/mc.hyke
./obi-wan verify+decrypt --tray /tmp/mc.tray /tmp/mc.hyke | diff /tmp/plain.txt -

# McEliece Level1 → partial tray error
./scotty keygen --group mceliece+slhdsa --alias mc1 --profile level1 --out /tmp/mc1.tray
./obi-wan encrypt+sign --tray /tmp/mc1.tray /tmp/plain.txt  # expect exit 1 + partial-tray message
```

---

## Files Changed

| File | Change |
|------|--------|
| `pqc/libcrystals-1.2/include/crystals/crystals.hpp` | Add cases to `tray_id_byte()`, `tray_type_from_id()`; add `is_tray_complete()` |
| `pqc/obi-wan/src/main.cpp` | Add `is_tray_complete()` guard in `cmd_encrypt_sign` and `cmd_verify_decrypt` |
| `pqc/libcrystals-1.2/test/api_stability_test-1.2.cpp` | New assertions for McEliece IDs and `is_tray_complete()` |
| `pqc/CLAUDE.md` | Update verified-working section |
