# zorro + penelope libcrystals-1.2 Update Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add mlkem+mldsa and frodokem+falcon profile group support to zorro (encrypt/decrypt/sign/verify) and penelope (tray-encaps/tray-decaps), and fix penelope's broken CMakeLists.txt to use installed libcrystals-1.2.

**Architecture:** Two-phase: (1) add `oqs_kem::is_oqs_kem()` helper + new tray_id bytes to the library and reinstall; (2) update dispatch logic in zorro and penelope to branch on the new helper. penelope also needs its broken direct-source-include CMake replaced with `find_package(Crystals REQUIRED)`.

**Tech Stack:** C++17, libcrystals-1.2 (fat static archive at `/usr/local/lib/libcrystals-1.2.a`), CMake, OpenSSL, liboqs (ML-KEM/ML-DSA/FrodoKEM/Falcon via `oqs_kem::` and `oqs_sig::` namespaces), lodepng (penelope only).

**Branch:** `zorro-penelope-1.2` in `worktrees/pq/`

**Spec:** `additional-profile-groups-part2.txt`

---

## File Structure

**Files to modify:**

| File | Changes |
|------|---------|
| `pq/libcrystals-1.2/include/crystals/crystals.hpp` | Add `oqs_kem::is_oqs_kem()` declaration; add 8 cases to `tray_id_byte()` and `tray_type_from_id()` |
| `pq/libcrystals-1.2/src/oqs_ops.cpp` | Add `oqs_kem::is_oqs_kem()` implementation |
| `pq/libcrystals-1.2/install.sh` | No change needed — same install process |
| `pq/zorro/src/main.cpp` | 6 dispatch points updated (find_pq_slot, find_pq_sig_slot, 4× KEM/sig dispatch) |
| `pq/penelope/CMakeLists.txt` | Replace broken direct-source-include with `find_package(Crystals REQUIRED)` |
| `pq/penelope/src/main.cpp` | `is_pq_slot()`, `PROFILES`, TrayType mapping in decaps, `hyke_level_str()` |
| `CLAUDE.md` | Update references from libcrystals-1.1 to 1.2; add new profile groups |

---

## Background: What Already Exists in libcrystals-1.2

- `oqs_kem::encaps(alg_name, pk, ct, ss)` ✅
- `oqs_kem::decaps(alg_name, sk, ct, ss)` ✅
- `oqs_sig::is_oqs_sig(alg_name)` — checks `"ML-DSA-*"` and `"Falcon-512"`/`"Falcon-1024"` ✅
- `oqs_sig::sign/verify/sig_bytes` ✅
- **Missing:** `oqs_kem::is_oqs_kem(alg_name)` — needed to identify ML-KEM and FrodoKEM slots

**Algorithm names stored in tray slots** (set by `make_tray` in `tray.cpp`):
- ML-KEM-512, ML-KEM-768, ML-KEM-1024
- ML-DSA-44, ML-DSA-65, ML-DSA-87
- FrodoKEM-640-AES, FrodoKEM-976-AES, FrodoKEM-1344-AES
- Falcon-512, Falcon-1024

**tray_id_byte** is `@api-stable` but the `default:` branch throws for all new TrayTypes. Safe to add new cases without changing existing behavior.

---

## Task 1: Add `oqs_kem::is_oqs_kem()` to Library Header

**Files:**
- Modify: `pq/libcrystals-1.2/include/crystals/crystals.hpp:138-161`

- [ ] **Step 1: Add declaration after existing oqs_kem functions**

In `crystals.hpp` (in the `oqs_kem` namespace block, lines 138–161), add the `is_oqs_kem` declaration. Replace the decaps declaration + closing brace:

```cpp
// Decapsulate ct with sk; fills ss_out.
void decaps(const std::string& alg_name,
            const std::vector<uint8_t>& sk,
            const std::vector<uint8_t>& ct,
            std::vector<uint8_t>& ss_out);  // @api-candidate-1.2

} // namespace oqs_kem
```

With:

```cpp
// Decapsulate ct with sk; fills ss_out.
void decaps(const std::string& alg_name,
            const std::vector<uint8_t>& sk,
            const std::vector<uint8_t>& ct,
            std::vector<uint8_t>& ss_out);  // @api-candidate-1.2

// Returns true if alg_name is handled by this namespace (ML-KEM-* or FrodoKEM-*).
bool is_oqs_kem(const std::string& alg_name);  // @api-candidate-1.2

} // namespace oqs_kem
```

- [ ] **Step 2: Verify the change looks correct**

Run: `grep -n "is_oqs_kem\|is_oqs_sig\|namespace oqs" pq/libcrystals-1.2/include/crystals/crystals.hpp`

Expected: `is_oqs_kem` appears inside the `oqs_kem` namespace (before line ~163), `is_oqs_sig` appears inside `oqs_sig` namespace. Both declared exactly once.

---

## Task 2: Add `oqs_kem::is_oqs_kem()` Implementation

**Files:**
- Modify: `pq/libcrystals-1.2/src/oqs_ops.cpp:99` (after `is_oqs_sig` implementation)

- [ ] **Step 1: Add implementation in oqs_ops.cpp**

In the `oqs_kem` namespace section (after `decaps`, before `} // namespace oqs_kem`), add:

```cpp
bool is_oqs_kem(const std::string& alg_name) {
    if (alg_name.rfind("ML-KEM-", 0) == 0) return true;
    if (alg_name.rfind("FrodoKEM-", 0) == 0) return true;
    return false;
}
```

- [ ] **Step 2: Verify placement**

Run: `grep -n "namespace oqs_kem\|is_oqs_kem\|namespace oqs_sig" pq/libcrystals-1.2/src/oqs_ops.cpp`

Expected: `is_oqs_kem` appears inside the `oqs_kem` namespace block.

---

## Task 3: Add New TrayType Cases to `tray_id_byte()` and `tray_type_from_id()`

**Files:**
- Modify: `pq/libcrystals-1.2/include/crystals/crystals.hpp:277-295`

The new TrayType enumerators from `pq/libcrystals-1.2/src/tray.hpp` (added in the previous plan):
- `MlKem_Level1`, `MlKem_Level2`, `MlKem_Level3`, `MlKem_Level4`
- `FrodoFalcon_Level1`, `FrodoFalcon_Level2`, `FrodoFalcon_Level3`, `FrodoFalcon_Level4`

ID byte allocation:
- 0x01–0x04: crystals group (Level2_25519, Level2, Level3, Level5) — RESERVED
- 0x11–0x14: mlkem+mldsa levels 1–4
- 0x21–0x24: frodokem+falcon levels 1–4

- [ ] **Step 1: Update tray_id_byte()**

Replace the existing `tray_id_byte` function with:

```cpp
inline uint8_t tray_id_byte(TrayType t) {                    // @api-stable v1.0
    switch (t) {
        case TrayType::Level2_25519:      return 0x01;
        case TrayType::Level2:            return 0x02;
        case TrayType::Level3:            return 0x03;
        case TrayType::Level5:            return 0x04;
        case TrayType::MlKem_Level1:      return 0x11;
        case TrayType::MlKem_Level2:      return 0x12;
        case TrayType::MlKem_Level3:      return 0x13;
        case TrayType::MlKem_Level4:      return 0x14;
        case TrayType::FrodoFalcon_Level1: return 0x21;
        case TrayType::FrodoFalcon_Level2: return 0x22;
        case TrayType::FrodoFalcon_Level3: return 0x23;
        case TrayType::FrodoFalcon_Level4: return 0x24;
        default: throw std::invalid_argument("Unknown TrayType");
    }
}
```

- [ ] **Step 2: Update tray_type_from_id()**

Replace the existing `tray_type_from_id` function with:

```cpp
inline TrayType tray_type_from_id(uint8_t id) {             // @api-stable v1.0
    switch (id) {
        case 0x01: return TrayType::Level2_25519;
        case 0x02: return TrayType::Level2;
        case 0x03: return TrayType::Level3;
        case 0x04: return TrayType::Level5;
        case 0x11: return TrayType::MlKem_Level1;
        case 0x12: return TrayType::MlKem_Level2;
        case 0x13: return TrayType::MlKem_Level3;
        case 0x14: return TrayType::MlKem_Level4;
        case 0x21: return TrayType::FrodoFalcon_Level1;
        case 0x22: return TrayType::FrodoFalcon_Level2;
        case 0x23: return TrayType::FrodoFalcon_Level3;
        case 0x24: return TrayType::FrodoFalcon_Level4;
        default: throw std::runtime_error("Unknown HYKE TrayID: " + std::to_string((int)id));
    }
}
```

---

## Task 4: Rebuild and Reinstall libcrystals-1.2

**Files:** None (build output only)

- [ ] **Step 1: Rebuild from source directory**

Run: `cmake --build pq/libcrystals-1.2/build -j$(nproc)`

Expected: Clean compile, no errors. (The build directory was set up in the previous session.)

If build directory doesn't exist: `cmake -S pq/libcrystals-1.2 -B pq/libcrystals-1.2/build -DCMAKE_INSTALL_PREFIX=/usr/local`

- [ ] **Step 2: Reinstall**

Run: `sudo bash pq/libcrystals-1.2/install.sh`

Expected: "Crystals root: /mnt/c/Users/daves/OneDrive/Desktop/Crystals" (not `worktrees/`) + "DONE" at the end.

If the root is wrong, run from the Crystals directory: `sudo bash pq/libcrystals-1.2/install.sh` from `/mnt/c/Users/daves/OneDrive/Desktop/Crystals`.

- [ ] **Step 3: Verify is_oqs_kem is exported**

Run: `nm -D /usr/local/lib/libcrystals-1.2.a 2>/dev/null | grep is_oqs_kem || ar t /usr/local/lib/libcrystals-1.2.a | head -5`

Expected: symbol present.

- [ ] **Step 4: Commit library changes**

```bash
git -C pq add libcrystals-1.2/include/crystals/crystals.hpp libcrystals-1.2/src/oqs_ops.cpp
git -C pq commit -m "feat(libcrystals-1.2): add oqs_kem::is_oqs_kem(), extend tray_id_byte for mk/ff profiles"
```

---

## Task 5: Update zorro Slot Detection

**Files:**
- Modify: `pq/zorro/src/main.cpp:73-98`

The two slot-finder functions need to recognize OQS algorithms.

- [ ] **Step 1: Update find_pq_slot to include OQS KEMs**

Replace lines 73–80 with:

```cpp
// Find the first PQ KEM slot (Kyber*, mceliece*, ML-KEM-*, FrodoKEM-*)
static const Slot* find_pq_slot(const Tray& tray) {
    for (const auto& s : tray.slots) {
        if (s.alg_name.substr(0, 5) == "Kyber" ||
            s.alg_name.substr(0, 8) == "mceliece" ||
            oqs_kem::is_oqs_kem(s.alg_name))
            return &s;
    }
    return nullptr;
}
```

- [ ] **Step 2: Update find_pq_sig_slot to include OQS signatures**

Replace lines 91–98 with:

```cpp
// Find the first PQ signature slot (Dilithium*, SLH-DSA-*, ML-DSA-*, Falcon-*)
static const Slot* find_pq_sig_slot(const Tray& tray) {
    for (const auto& s : tray.slots) {
        if (dilithium_sig::is_pq_sig(s.alg_name) ||
            slhdsa_sig::is_slhdsa_sig(s.alg_name) ||
            oqs_sig::is_oqs_sig(s.alg_name))
            return &s;
    }
    return nullptr;
}
```

---

## Task 6: Update zorro PQ KEM Dispatch (encrypt + decrypt + sign + verify)

**Files:**
- Modify: `pq/zorro/src/main.cpp` — 4 dispatch sites

The pattern to find and update (appears at lines ~145, ~247, ~335, ~565):
```cpp
if (pq_slot->alg_name.substr(0, 5) == "Kyber") {
    kyber_kem::encaps(...);
} else {
    mceliece_kem::encaps(...);
}
```

- [ ] **Step 1: Update encrypt cmd_encrypt PQ encaps (line ~145)**

Replace:
```cpp
        if (pq_slot->alg_name.substr(0, 5) == "Kyber") {
            kyber_kem::encaps(kyber_kem::level_from_alg(pq_slot->alg_name), pq_slot->pk, ct_pq, ss_pq);
        } else {
            mceliece_kem::encaps(pq_slot->alg_name, pq_slot->pk, ct_pq, ss_pq);
        }
```

With:
```cpp
        if (pq_slot->alg_name.substr(0, 5) == "Kyber") {
            kyber_kem::encaps(kyber_kem::level_from_alg(pq_slot->alg_name), pq_slot->pk, ct_pq, ss_pq);
        } else if (oqs_kem::is_oqs_kem(pq_slot->alg_name)) {
            oqs_kem::encaps(pq_slot->alg_name, pq_slot->pk, ct_pq, ss_pq);
        } else {
            mceliece_kem::encaps(pq_slot->alg_name, pq_slot->pk, ct_pq, ss_pq);
        }
```

- [ ] **Step 2: Update cmd_decrypt PQ decaps (line ~247)**

Replace:
```cpp
        if (pq_slot->alg_name.substr(0, 5) == "Kyber") {
            kyber_kem::decaps(kyber_kem::level_from_alg(pq_slot->alg_name), pq_slot->sk, hdr.ct_pq, ss_pq);
        } else {
            mceliece_kem::decaps(pq_slot->alg_name, pq_slot->sk, hdr.ct_pq, ss_pq);
        }
```

With:
```cpp
        if (pq_slot->alg_name.substr(0, 5) == "Kyber") {
            kyber_kem::decaps(kyber_kem::level_from_alg(pq_slot->alg_name), pq_slot->sk, hdr.ct_pq, ss_pq);
        } else if (oqs_kem::is_oqs_kem(pq_slot->alg_name)) {
            oqs_kem::decaps(pq_slot->alg_name, pq_slot->sk, hdr.ct_pq, ss_pq);
        } else {
            mceliece_kem::decaps(pq_slot->alg_name, pq_slot->sk, hdr.ct_pq, ss_pq);
        }
```

- [ ] **Step 3: Update cmd_sign PQ KEM encaps (line ~335)**

Replace (in cmd_sign, near "PQ KEM encaps"):
```cpp
        if (pq_kem->alg_name.substr(0, 5) == "Kyber") {
            kyber_kem::encaps(kyber_kem::level_from_alg(pq_kem->alg_name), pq_kem->pk, ct_pq, ss_pq);
        } else {
            mceliece_kem::encaps(pq_kem->alg_name, pq_kem->pk, ct_pq, ss_pq);
        }
```

With:
```cpp
        if (pq_kem->alg_name.substr(0, 5) == "Kyber") {
            kyber_kem::encaps(kyber_kem::level_from_alg(pq_kem->alg_name), pq_kem->pk, ct_pq, ss_pq);
        } else if (oqs_kem::is_oqs_kem(pq_kem->alg_name)) {
            oqs_kem::encaps(pq_kem->alg_name, pq_kem->pk, ct_pq, ss_pq);
        } else {
            mceliece_kem::encaps(pq_kem->alg_name, pq_kem->pk, ct_pq, ss_pq);
        }
```

- [ ] **Step 4: Update cmd_verify PQ KEM decaps (line ~565)**

Replace (in cmd_verify, near "PQ KEM decaps"):
```cpp
        if (pq_kem->alg_name.substr(0, 5) == "Kyber") {
            kyber_kem::decaps(kyber_kem::level_from_alg(pq_kem->alg_name), pq_kem->sk, hdr.ct_pq, ss_pq);
        } else {
            mceliece_kem::decaps(pq_kem->alg_name, pq_kem->sk, hdr.ct_pq, ss_pq);
        }
```

With:
```cpp
        if (pq_kem->alg_name.substr(0, 5) == "Kyber") {
            kyber_kem::decaps(kyber_kem::level_from_alg(pq_kem->alg_name), pq_kem->sk, hdr.ct_pq, ss_pq);
        } else if (oqs_kem::is_oqs_kem(pq_kem->alg_name)) {
            oqs_kem::decaps(pq_kem->alg_name, pq_kem->sk, hdr.ct_pq, ss_pq);
        } else {
            mceliece_kem::decaps(pq_kem->alg_name, pq_kem->sk, hdr.ct_pq, ss_pq);
        }
```

---

## Task 7: Update zorro PQ Signature Dispatch (sign + verify)

**Files:**
- Modify: `pq/zorro/src/main.cpp` — 3 dispatch sites in cmd_sign and cmd_verify

- [ ] **Step 1: Update sig_pq_size lookup in cmd_sign (line ~388)**

Replace:
```cpp
        if (dilithium_sig::is_pq_sig(pq_sig->alg_name)) {
            int mode = dilithium_sig::mode_from_alg(pq_sig->alg_name);
            sig_pq_size = (uint32_t)dilithium_sig::sig_bytes_for_mode(mode);
        } else {
            sig_pq_size = (uint32_t)slhdsa_sig::sig_bytes(pq_sig->alg_name);
        }
```

With:
```cpp
        if (dilithium_sig::is_pq_sig(pq_sig->alg_name)) {
            int mode = dilithium_sig::mode_from_alg(pq_sig->alg_name);
            sig_pq_size = (uint32_t)dilithium_sig::sig_bytes_for_mode(mode);
        } else if (oqs_sig::is_oqs_sig(pq_sig->alg_name)) {
            sig_pq_size = (uint32_t)oqs_sig::sig_bytes(pq_sig->alg_name);
        } else {
            sig_pq_size = (uint32_t)slhdsa_sig::sig_bytes(pq_sig->alg_name);
        }
```

- [ ] **Step 2: Update PQ sign dispatch in cmd_sign (line ~431)**

Replace:
```cpp
        if (dilithium_sig::is_pq_sig(pq_sig->alg_name)) {
            dilithium_sig::sign(dilithium_sig::mode_from_alg(pq_sig->alg_name),
                                pq_sig->sk, m_to_sign, hdr.sig_pq);
        } else {
            slhdsa_sig::sign(pq_sig->alg_name, pq_sig->sk, m_to_sign, hdr.sig_pq);
        }
```

With:
```cpp
        if (dilithium_sig::is_pq_sig(pq_sig->alg_name)) {
            dilithium_sig::sign(dilithium_sig::mode_from_alg(pq_sig->alg_name),
                                pq_sig->sk, m_to_sign, hdr.sig_pq);
        } else if (oqs_sig::is_oqs_sig(pq_sig->alg_name)) {
            oqs_sig::sign(pq_sig->alg_name, pq_sig->sk, m_to_sign, hdr.sig_pq);
        } else {
            slhdsa_sig::sign(pq_sig->alg_name, pq_sig->sk, m_to_sign, hdr.sig_pq);
        }
```

- [ ] **Step 3: Update PQ verify dispatch in cmd_verify (line ~538)**

Replace:
```cpp
        bool pq_ok = false;
        if (dilithium_sig::is_pq_sig(pq_sig->alg_name)) {
            pq_ok = dilithium_sig::verify(dilithium_sig::mode_from_alg(pq_sig->alg_name),
                                          pq_sig->pk, m_to_sign, hdr.sig_pq);
        } else {
            pq_ok = slhdsa_sig::verify(pq_sig->alg_name, pq_sig->pk, m_to_sign, hdr.sig_pq);
        }
```

With:
```cpp
        bool pq_ok = false;
        if (dilithium_sig::is_pq_sig(pq_sig->alg_name)) {
            pq_ok = dilithium_sig::verify(dilithium_sig::mode_from_alg(pq_sig->alg_name),
                                          pq_sig->pk, m_to_sign, hdr.sig_pq);
        } else if (oqs_sig::is_oqs_sig(pq_sig->alg_name)) {
            pq_ok = oqs_sig::verify(pq_sig->alg_name, pq_sig->pk, m_to_sign, hdr.sig_pq);
        } else {
            pq_ok = slhdsa_sig::verify(pq_sig->alg_name, pq_sig->pk, m_to_sign, hdr.sig_pq);
        }
```

---

## Task 8: Build and Test zorro

**Files:** None (build + test only)

- [ ] **Step 1: Reconfigure and build**

```bash
cmake -S pq/zorro -B pq/zorro/build
cmake --build pq/zorro/build -j$(nproc)
```

Expected: Clean compile, no errors.

- [ ] **Step 2: Test encrypt/decrypt with mlkem+mldsa trays**

```bash
echo "hello zorro ml-kem" > /tmp/plain.txt

# mk-level2 (P-256 + ML-KEM-512 + ECDSA P-256 + ML-DSA-44)
./pq/hybrid/build/hybrid keygen --group mlkem+mldsa --alias mktest2 --profile level2 --out /tmp/mktest2.tray
./pq/zorro/build/zorro encrypt --tray /tmp/mktest2.tray /tmp/plain.txt > /tmp/mk2.armored
./pq/zorro/build/zorro decrypt --tray /tmp/mktest2.tray /tmp/mk2.armored | diff /tmp/plain.txt -

# mk-level3
./pq/hybrid/build/hybrid keygen --group mlkem+mldsa --alias mktest3 --profile level3 --out /tmp/mktest3.tray
./pq/zorro/build/zorro encrypt --tray /tmp/mktest3.tray /tmp/plain.txt > /tmp/mk3.armored
./pq/zorro/build/zorro decrypt --tray /tmp/mktest3.tray /tmp/mk3.armored | diff /tmp/plain.txt -

# mk-level4
./pq/hybrid/build/hybrid keygen --group mlkem+mldsa --alias mktest4 --profile level4 --out /tmp/mktest4.tray
./pq/zorro/build/zorro encrypt --tray /tmp/mktest4.tray /tmp/plain.txt > /tmp/mk4.armored
./pq/zorro/build/zorro decrypt --tray /tmp/mktest4.tray /tmp/mk4.armored | diff /tmp/plain.txt -
```

Expected: All `diff` commands produce no output (roundtrip OK).

- [ ] **Step 3: Test sign/verify with mlkem+mldsa trays**

```bash
./pq/zorro/build/zorro sign   --tray /tmp/mktest2.tray /tmp/plain.txt > /tmp/mk2.hyke
./pq/zorro/build/zorro verify --tray /tmp/mktest2.tray /tmp/mk2.hyke | diff /tmp/plain.txt -

./pq/zorro/build/zorro sign   --tray /tmp/mktest3.tray /tmp/plain.txt > /tmp/mk3.hyke
./pq/zorro/build/zorro verify --tray /tmp/mktest3.tray /tmp/mk3.hyke | diff /tmp/plain.txt -
```

Expected: Roundtrip OK.

- [ ] **Step 4: Test encrypt/decrypt with frodokem+falcon trays**

```bash
# ff-level2 (P-256 + FrodoKEM-640-AES + ECDSA P-256 + Falcon-512)
./pq/hybrid/build/hybrid keygen --group frodokem+falcon --alias fftest2 --profile level2 --out /tmp/fftest2.tray
./pq/zorro/build/zorro encrypt --tray /tmp/fftest2.tray /tmp/plain.txt > /tmp/ff2.armored
./pq/zorro/build/zorro decrypt --tray /tmp/fftest2.tray /tmp/ff2.armored | diff /tmp/plain.txt -

# ff-level3
./pq/hybrid/build/hybrid keygen --group frodokem+falcon --alias fftest3 --profile level3 --out /tmp/fftest3.tray
./pq/zorro/build/zorro encrypt --tray /tmp/fftest3.tray /tmp/plain.txt > /tmp/ff3.armored
./pq/zorro/build/zorro decrypt --tray /tmp/fftest3.tray /tmp/ff3.armored | diff /tmp/plain.txt -
```

Expected: Roundtrip OK. (Note: FrodoKEM keys are large ~10-43KB, so generation takes a moment.)

- [ ] **Step 5: Test sign/verify with frodokem+falcon trays**

```bash
./pq/zorro/build/zorro sign   --tray /tmp/fftest2.tray /tmp/plain.txt > /tmp/ff2.hyke
./pq/zorro/build/zorro verify --tray /tmp/fftest2.tray /tmp/ff2.hyke | diff /tmp/plain.txt -
```

Expected: Roundtrip OK.

- [ ] **Step 6: Verify tamper detection still works**

```bash
# Tamper the mk2 HYKE file and verify it fails
python3 -c "
import sys
data = open('/tmp/mk2.hyke').read()
lines = data.split('\n')
# Corrupt a body line (not header/footer)
for i, l in enumerate(lines):
    if l and not l.startswith('---'):
        lines[i] = l[:-4] + 'XXXX'
        break
open('/tmp/mk2.hyke.bad', 'w').write('\n'.join(lines))
"
./pq/zorro/build/zorro verify --tray /tmp/mktest2.tray /tmp/mk2.hyke.bad
echo "exit code: $?"
```

Expected: exit code 2, error message about signature INVALID.

- [ ] **Step 7: Verify existing crystals group trays still work (regression)**

```bash
./pq/hybrid/build/hybrid keygen --alias regtest --profile level2-25519 > /tmp/regtest.tray
./pq/zorro/build/zorro encrypt --tray /tmp/regtest.tray /tmp/plain.txt > /tmp/reg.armored
./pq/zorro/build/zorro decrypt --tray /tmp/regtest.tray /tmp/reg.armored | diff /tmp/plain.txt -
./pq/zorro/build/zorro sign   --tray /tmp/regtest.tray /tmp/plain.txt > /tmp/reg.hyke
./pq/zorro/build/zorro verify --tray /tmp/regtest.tray /tmp/reg.hyke | diff /tmp/plain.txt -
```

Expected: All OK — no regression.

- [ ] **Step 8: Commit zorro changes**

```bash
git -C pq add zorro/src/main.cpp
git -C pq commit -m "feat(zorro): add ML-KEM, ML-DSA, FrodoKEM, Falcon dispatch for encrypt/decrypt/sign/verify"
```

---

## Task 9: Fix penelope CMakeLists.txt

**Files:**
- Modify: `pq/penelope/CMakeLists.txt`

The current file directly includes source files from `../libcrystals/src` which no longer exists. Replace the entire file content.

- [ ] **Step 1: Rewrite CMakeLists.txt**

Replace the full content of `pq/penelope/CMakeLists.txt` with:

```cmake
cmake_minimum_required(VERSION 3.16)
project(penelope LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Crystals REQUIRED)
find_package(OpenSSL  REQUIRED)

# ── RPATH for TBB and XKCP shared libraries ───────────────────────────────────
get_target_property(_tbb_loc TBB::tbb IMPORTED_LOCATION_RELEASE)
if(NOT _tbb_loc)
    get_target_property(_tbb_loc TBB::tbb IMPORTED_LOCATION)
endif()
get_filename_component(_tbb_libdir "${_tbb_loc}" DIRECTORY)
set(CMAKE_BUILD_RPATH "${_tbb_libdir}" "/usr/local/lib")

# ── Executable ────────────────────────────────────────────────────────────────
add_executable(penelope
    src/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/lodepng.cpp
)

target_include_directories(penelope PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}   # lodepng.h (at penelope root)
    src/                          # encaps_crypto.hpp, bitmap_font.hpp
)

target_compile_options(penelope PRIVATE -O2 -Wall -Wextra)

target_link_libraries(penelope PRIVATE
    Crystals::crystals
    OpenSSL::Crypto
)

# ── Install ───────────────────────────────────────────────────────────────────
install(TARGETS penelope DESTINATION bin)
```

- [ ] **Step 2: Verify CrystalsConfig provides the right include path and compile definitions**

The `Crystals::crystals` target exposes:
- `crystals/crystals.hpp` via `INTERFACE_INCLUDE_DIRECTORIES`
- `MSGPACK_NO_BOOST` via `INTERFACE_COMPILE_DEFINITIONS` (declared `PUBLIC` in libcrystals CMakeLists.txt) — no need to repeat it in penelope's CMakeLists.txt

Check that `encaps_crypto.hpp` includes `<crystals/symmetric.hpp>` (it does — already verified). That header is part of the installed crystals package.

Run: `ls /usr/local/include/crystals/ | grep -E "symmetric|tray|base64"`

Expected: `symmetric.hpp`, `tray.hpp`, `tray_reader.hpp`, etc. are present.

---

## Task 10: Update penelope `is_pq_slot()` and `PROFILES` Table

**Files:**
- Modify: `pq/penelope/src/main.cpp:77-210`

**Key sizes** (standard OQS values, same source as hybrid's keygen):

| Algorithm | pk bytes | sk bytes |
|-----------|----------|----------|
| ML-KEM-512 | 800 | 1632 |
| ML-KEM-768 | 1184 | 2400 |
| ML-KEM-1024 | 1568 | 3168 |
| ML-DSA-44 | 1312 | 2560 |
| ML-DSA-65 | 1952 | 4032 |
| ML-DSA-87 | 2592 | 4896 |
| FrodoKEM-640-AES | 9616 | 19888 |
| FrodoKEM-976-AES | 15632 | 31296 |
| FrodoKEM-1344-AES | 21520 | 43088 |
| Falcon-512 | 897 | 1281 |
| Falcon-1024 | 1793 | 2305 |

> **IMPORTANT:** Verify these sizes before committing. Run `./pq/hybrid/build/hybrid keygen --group mlkem+mldsa --alias x --profile level2` and check the pk/sk field lengths in the YAML output. FrodoKEM sizes in particular should be confirmed.

- [ ] **Step 1: Update is_pq_slot()**

Replace lines 76–80 with:

```cpp
static bool is_pq_slot(const std::string& alg_name) {
    return alg_name.rfind("Kyber",      0) == 0 ||
           alg_name.rfind("Dilithium",  0) == 0 ||
           alg_name.rfind("ML-KEM-",    0) == 0 ||
           alg_name.rfind("ML-DSA-",    0) == 0 ||
           alg_name.rfind("FrodoKEM-",  0) == 0 ||
           alg_name.rfind("Falcon-",    0) == 0;
}
```

- [ ] **Step 2: Extend PROFILES map (add mlkem+mldsa profiles)**

After the `"level5"` entry (line ~209), add new entries:

```cpp
    {"mk-level1", {
        {"ML-KEM-512",   800,  1632},
        {"ML-DSA-44",    1312, 2560},
    }},
    {"mk-level2", {
        {"P-256",        65,   32},
        {"ML-KEM-512",   800,  1632},
        {"ECDSA P-256",  65,   32},
        {"ML-DSA-44",    1312, 2560},
    }},
    {"mk-level3", {
        {"P-384",        97,   48},
        {"ML-KEM-768",   1184, 2400},
        {"ECDSA P-384",  97,   48},
        {"ML-DSA-65",    1952, 4032},
    }},
    {"mk-level4", {
        {"P-521",        133,  66},
        {"ML-KEM-1024",  1568, 3168},
        {"ECDSA P-521",  133,  66},
        {"ML-DSA-87",    2592, 4896},
    }},
    {"ff-level1", {
        {"FrodoKEM-640-AES",  9616,  19888},
        {"Falcon-512",        897,   1281},
    }},
    {"ff-level2", {
        {"P-256",             65,    32},
        {"FrodoKEM-640-AES",  9616,  19888},
        {"ECDSA P-256",       65,    32},
        {"Falcon-512",        897,   1281},
    }},
    {"ff-level3", {
        {"P-384",             97,    48},
        {"FrodoKEM-976-AES",  15632, 31296},
        {"ECDSA P-384",       97,    48},
        {"Falcon-512",        897,   1281},  // intentional per spec
    }},
    {"ff-level4", {
        {"P-521",             133,   66},
        {"FrodoKEM-1344-AES", 21520, 43088},
        {"ECDSA P-521",       133,   66},
        {"Falcon-1024",       1793,  2305},
    }},
```

- [ ] **Step 3: Update TrayType mapping AND profile_group in cmd_tray_decaps (line ~1250)**

The current code at lines ~1248–1259 sets `profile_group` unconditionally to `"crystals"` and then maps `type_str` to `TrayType`. Replace both:

Old:
```cpp
    tray.profile_group = "crystals";
    tray.created       = meta.created;
    tray.expires       = meta.expires;

    if      (meta.profile == "level0")       tray.tray_type = TrayType::Level0;
    else if (meta.profile == "level1")       tray.tray_type = TrayType::Level1;
    else if (meta.profile == "level2-25519") tray.tray_type = TrayType::Level2_25519;
    else if (meta.profile == "level2")       tray.tray_type = TrayType::Level2;
    else if (meta.profile == "level3")       tray.tray_type = TrayType::Level3;
    else if (meta.profile == "level5")       tray.tray_type = TrayType::Level5;
```

New:
```cpp
    if      (meta.profile.rfind("mk-", 0) == 0) tray.profile_group = "mlkem+mldsa";
    else if (meta.profile.rfind("ff-", 0) == 0) tray.profile_group = "frodokem+falcon";
    else                                         tray.profile_group = "crystals";
    tray.created       = meta.created;
    tray.expires       = meta.expires;

    if      (meta.profile == "level0")       tray.tray_type = TrayType::Level0;
    else if (meta.profile == "level1")       tray.tray_type = TrayType::Level1;
    else if (meta.profile == "level2-25519") tray.tray_type = TrayType::Level2_25519;
    else if (meta.profile == "level2")       tray.tray_type = TrayType::Level2;
    else if (meta.profile == "level3")       tray.tray_type = TrayType::Level3;
    else if (meta.profile == "level5")       tray.tray_type = TrayType::Level5;
    else if (meta.profile == "mk-level1")    tray.tray_type = TrayType::MlKem_Level1;
    else if (meta.profile == "mk-level2")    tray.tray_type = TrayType::MlKem_Level2;
    else if (meta.profile == "mk-level3")    tray.tray_type = TrayType::MlKem_Level3;
    else if (meta.profile == "mk-level4")    tray.tray_type = TrayType::MlKem_Level4;
    else if (meta.profile == "ff-level1")    tray.tray_type = TrayType::FrodoFalcon_Level1;
    else if (meta.profile == "ff-level2")    tray.tray_type = TrayType::FrodoFalcon_Level2;
    else if (meta.profile == "ff-level3")    tray.tray_type = TrayType::FrodoFalcon_Level3;
    else if (meta.profile == "ff-level4")    tray.tray_type = TrayType::FrodoFalcon_Level4;
```

- [ ] **Step 4: Update hyke_level_str() to show new tray types**

Replace lines 545–554 (the `hyke_level_str` function):

```cpp
static std::string hyke_level_str(const std::vector<uint8_t>& wire) {
    if (wire.size() < 7) return "unknown";
    switch (wire[6]) {
        case 0x01: return "level2-25519";
        case 0x02: return "level2";
        case 0x03: return "level3";
        case 0x04: return "level5";
        case 0x11: return "mk-level1";
        case 0x12: return "mk-level2";
        case 0x13: return "mk-level3";
        case 0x14: return "mk-level4";
        case 0x21: return "ff-level1";
        case 0x22: return "ff-level2";
        case 0x23: return "ff-level3";
        case 0x24: return "ff-level4";
        default:   return "unknown";
    }
}
```

---

## Task 11: Build and Test penelope

**Files:** None (build + test only)

- [ ] **Step 1: Reconfigure and build penelope**

```bash
cmake -S pq/penelope -B pq/penelope/build
cmake --build pq/penelope/build -j$(nproc)
```

Expected: Clean compile. If missing headers are reported, check `/usr/local/include/crystals/` for the missing file.

- [ ] **Step 2: Test tray-encaps/tray-decaps with mlkem+mldsa tray**

```bash
# Generate mk-level2 tray (if not already done from Task 8)
./pq/hybrid/build/hybrid keygen --group mlkem+mldsa --alias mktest2 --profile level2 --out /tmp/mktest2.tray

# Encaps to PNG
./pq/penelope/build/penelope tray-encaps --in-tray /tmp/mktest2.tray --out-png /tmp/mktest2_enc.png --pwfile /dev/stdin <<< "testpassword123"

# Decaps back to tray
./pq/penelope/build/penelope tray-decaps --in-png /tmp/mktest2_enc.png --out-tray /tmp/mktest2_recovered.yaml --pwfile /dev/stdin <<< "testpassword123"

# Verify key material matches
diff <(grep "pk:" /tmp/mktest2.tray | head -4) <(grep "pk:" /tmp/mktest2_recovered.yaml | head -4)
```

Expected: Encaps succeeds producing PNG; decaps recovers tray; pk fields match.

- [ ] **Step 3: Test tray-encaps/tray-decaps with frodokem+falcon tray**

```bash
./pq/hybrid/build/hybrid keygen --group frodokem+falcon --alias fftest2 --profile level2 --out /tmp/fftest2.tray
./pq/penelope/build/penelope tray-encaps --in-tray /tmp/fftest2.tray --out-png /tmp/fftest2_enc.png --pwfile /dev/stdin <<< "testpassword123"
./pq/penelope/build/penelope tray-decaps --in-png /tmp/fftest2_enc.png --out-tray /tmp/fftest2_recovered.yaml --pwfile /dev/stdin <<< "testpassword123"
diff <(grep "pk:" /tmp/fftest2.tray | head -4) <(grep "pk:" /tmp/fftest2_recovered.yaml | head -4)
```

Expected: Roundtrip OK. Note: FrodoKEM keys are large (pk ≈ 9–21KB); the PNG will be significantly bigger than for crystals trays.

- [ ] **Step 4: Wrong password test**

```bash
./pq/penelope/build/penelope tray-decaps --in-png /tmp/mktest2_enc.png --pwfile /dev/stdin <<< "wrongpassword"
echo "exit code: $?"
```

Expected: exit code 2, "decryption failed — wrong password" message.

- [ ] **Step 5: Regression test existing crystals trays**

```bash
./pq/hybrid/build/hybrid keygen --alias padreg --profile level2-25519 --out /tmp/padreg.tray
./pq/penelope/build/penelope tray-encaps --in-tray /tmp/padreg.tray --out-png /tmp/padreg_enc.png --pwfile /dev/stdin <<< "testpassword123"
./pq/penelope/build/penelope tray-decaps --in-png /tmp/padreg_enc.png --out-tray /tmp/padreg_recovered.yaml --pwfile /dev/stdin <<< "testpassword123"
diff <(grep "pk:" /tmp/padreg.tray | head -4) <(grep "pk:" /tmp/padreg_recovered.yaml | head -4)
```

Expected: Roundtrip OK — no regression.

- [ ] **Step 6: Commit penelope changes**

```bash
git -C pq add penelope/CMakeLists.txt penelope/src/main.cpp
git -C pq commit -m "feat(penelope): add mlkem+mldsa and frodokem+falcon profile support; migrate to Crystals::crystals"
```

---

## Task 12: Update CLAUDE.md

**Files:**
- Modify: `pq/CLAUDE.md`

- [ ] **Step 1: Update libcrystals version references**

Search for `libcrystals-1.1` and replace with `libcrystals-1.2` throughout. Key sections:
- "hybrid Build Notes" section: "Migrated to libcrystals-1.2 backend"
- "zorro Build Notes" section: "Migrated to libcrystals-1.2 backend"
- "Static Linking Strategy" section: references to `libcrystals-1.1.a`
- Install command: `sudo bash pq/libcrystals-1.1/install.sh` → `sudo bash pq/libcrystals-1.2/install.sh`
- Archive path: `/usr/local/lib/libcrystals-1.1.a` → `/usr/local/lib/libcrystals-1.2.a`

- [ ] **Step 2: Update zorro Slot selection docs**

In "Architecture → zorro Architecture", update the "Slot selection" line:

Old:
```
**Slot selection**: uses `alg_name` matching — KEM classical: `{X25519,P-256,P-384,P-521}`;
KEM PQ: prefix `"Kyber"` or prefix `"mceliece"`; Sig classical: `{Ed25519,ECDSA P-256,ECDSA P-384,ECDSA P-521}`;
Sig PQ: `{Dilithium2,Dilithium3,Dilithium5}` or prefix `"SLH-DSA"`.
```

New:
```
**Slot selection**: uses `alg_name` matching — KEM classical: `{X25519,P-256,P-384,P-521}`;
KEM PQ: prefix `"Kyber"`, `"mceliece"`, or `oqs_kem::is_oqs_kem()` (ML-KEM-*, FrodoKEM-*);
Sig classical: `{Ed25519,ECDSA P-256,ECDSA P-384,ECDSA P-521}`;
Sig PQ: `{Dilithium2,Dilithium3,Dilithium5}`, prefix `"SLH-DSA"`, or `oqs_sig::is_oqs_sig()` (ML-DSA-*, Falcon-*).
```

- [ ] **Step 3: Add zorro Verified Working entries for new profiles**

Add to the "Verified Working (zorro)" section:
```
- mlkem+mldsa mk-level2, mk-level3, mk-level4: encrypt/decrypt/sign/verify OK (2026-03-23)
- frodokem+falcon ff-level2, ff-level3: encrypt/decrypt/sign/verify OK (2026-03-23)
```

- [ ] **Step 4: Update penelope documentation**

Add a "penelope Tool" section or update the existing one (if any) to note:
- Supports all mlkem+mldsa and frodokem+falcon profiles
- Migrated from direct-source-compile to `Crystals::crystals` fat archive
- Build: `cmake -S pq/penelope -B pq/penelope/build && cmake --build pq/penelope/build -j$(nproc)`

- [ ] **Step 5: Commit CLAUDE.md update**

```bash
git -C pq add CLAUDE.md
git -C pq commit -m "docs: update CLAUDE.md for libcrystals-1.2 and new profile groups in zorro/penelope"
```

---

## Final: Push and Summary

- [ ] **Step 1: Push branch**

```bash
git -C pq push origin zorro-penelope-1.2
```

- [ ] **Step 2: Confirm all tasks complete**

Checklist:
- [ ] `oqs_kem::is_oqs_kem()` added to library header + impl
- [ ] `tray_id_byte()` extended for MlKem_Level1-4 and FrodoFalcon_Level1-4
- [ ] Library rebuilt and reinstalled
- [ ] zorro: 9 dispatch sites updated (4× KEM, 2× sig size/sign/verify, 2× slot finders)
- [ ] zorro: all 4 encrypt/decrypt roundtrips with new profiles pass
- [ ] zorro: sign/verify with mk-level2, ff-level2 pass
- [ ] penelope: CMakeLists.txt migrated to `Crystals::crystals`
- [ ] penelope: `is_pq_slot()` updated; 8 new `PROFILES` entries; TrayType mapping extended
- [ ] penelope: tray-encaps/tray-decaps roundtrip with mk-level2 and ff-level2 pass
- [ ] CLAUDE.md updated

---

## Notes for Implementer

1. **Key size verification**: Before committing the penelope `PROFILES` table, verify FrodoKEM/Falcon key sizes by inspecting actual hybrid output:
   ```bash
   ./pq/hybrid/build/hybrid keygen --group frodokem+falcon --alias x --profile level2 | \
     python3 -c "import sys,base64; d=sys.stdin.read(); \
     [print(len(base64.b64decode(l.split(':')[1].strip())), l[:30]) for l in d.split('\n') if 'pk:' in l or 'sk:' in l]"
   ```

2. **FrodoKEM PNG size**: FrodoKEM keys are large (pk: 9–21KB, sk: 19–43KB). The resulting penelope PNG for ff-level4 could be very large. This is expected behavior — no fix needed.

3. **level1 PQ-only trays (mk-level1, ff-level1)**: zorro `encrypt` and `sign` require both a classical KEM slot AND a PQ KEM slot (the guard at line ~119 returns exit 1 if either is missing). Since level1 trays have no classical slot, they will fail `encrypt` and `sign` with a usage error. This is **intentional and out of scope** — the spec's primary use case is hybrid operation (levels 2–4). level1 trays are useful for key archival (penelope tray-encaps/decaps) and could be used with a future PQ-only encrypt mode. No code change needed; behavior is consistent with how crystals level1 trays have always worked.

4. **mceliece+slhdsa trays**: NOT added to penelope's PROFILES in this plan. McEliece public keys are 260KB+ which would produce impractically large PNGs. This is out of scope.

4. **obiwan_level_str() in penelope**: The ZORRO wire format doesn't carry enough information to distinguish mk-level2 from crystals level2 (same CT sizes for ML-KEM-512 vs Kyber512). The pngify display will show "level2" for mk-level2 ZORRO files. This is a cosmetic limitation — pngify is a visualization tool and correctness of the label is not critical.

5. **level1 trays**: mk-level1 and ff-level1 (PQ-only, no classical) are not tested for sign/verify since zorro requires all 4 slots for HYKE. They will work for encrypt/decrypt if they have a PQ KEM slot (but zorro's encrypt requires both classical AND PQ KEM, so level1 PQ-only won't encrypt either). These trays are useful for key backup/archival but not for zorro encrypt/sign.
