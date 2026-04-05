# McEliece HYKE Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add McEliece Level1–5 tray ID bytes to the HYKE wire format and a general `is_tray_complete()` helper, unblocking `encrypt+sign` / `verify+decrypt` for McEliece Level2–5 trays.

**Architecture:** Two additive cases added to `tray_id_byte()` / `tray_type_from_id()` in `crystals.hpp` (IDs `0x31`–`0x35`); a new `is_tray_complete()` inline guards against PQ-only trays before HYKE operations in `obi-wan`. All crypto dispatch for McEliece KEM and SLH-DSA is already correct.

**Tech Stack:** C++17, `crystals/crystals.hpp` (public API), `libcrystals-1.2` static library, CMake, OpenSSL.

---

## Files

| File | Change |
|------|--------|
| `pqc/libcrystals-1.2/include/crystals/crystals.hpp` | Add 5 cases to `tray_id_byte()`, 5 cases to `tray_type_from_id()`, add `is_tray_complete()` inline |
| `pqc/libcrystals-1.2/test/api_stability_test-1.2.cpp` | Add static_assert for `is_tray_complete` signature + runtime assertions in `main()` |
| `pqc/obi-wan/src/main.cpp` | Add `is_tray_complete()` guard in `cmd_encrypt_sign` (~line 437) and `cmd_verify_decrypt` (~line 605) |
| `pqc/CLAUDE.md` | Add McEliece HYKE entries to verified-working section |

All commands run from: `/mnt/c/Users/daves/OneDrive/Desktop/Crystals/`

---

## Task 1: Test and implement McEliece tray ID bytes

**Files:**
- Modify: `pqc/libcrystals-1.2/test/api_stability_test-1.2.cpp`
- Modify: `pqc/libcrystals-1.2/include/crystals/crystals.hpp:280-314`

- [ ] **Step 1: Add runtime assertions to api_stability_test-1.2.cpp**

Add `#include <cassert>` at the top of the file (alongside the existing includes). Then replace the final `int main() { return 0; }` with:

```cpp
int main() {
    // McEliece tray ID byte round-trips
    assert(tray_id_byte(TrayType::McEliece_Level1) == 0x31);
    assert(tray_id_byte(TrayType::McEliece_Level2) == 0x32);
    assert(tray_id_byte(TrayType::McEliece_Level3) == 0x33);
    assert(tray_id_byte(TrayType::McEliece_Level4) == 0x34);
    assert(tray_id_byte(TrayType::McEliece_Level5) == 0x35);
    assert(tray_type_from_id(0x31) == TrayType::McEliece_Level1);
    assert(tray_type_from_id(0x32) == TrayType::McEliece_Level2);
    assert(tray_type_from_id(0x33) == TrayType::McEliece_Level3);
    assert(tray_type_from_id(0x34) == TrayType::McEliece_Level4);
    assert(tray_type_from_id(0x35) == TrayType::McEliece_Level5);
    return 0;
}
```

- [ ] **Step 2: Build and verify test fails**

```bash
cmake -S pqc/libcrystals-1.2 -B pqc/libcrystals-1.2/build \
  -DCMAKE_PREFIX_PATH=/mnt/c/Users/daves/OneDrive/Desktop/Crystals/local \
  2>/dev/null
cmake --build pqc/libcrystals-1.2/build -j$(nproc) --target api_stability_test_12 2>&1 | tail -5
./pqc/libcrystals-1.2/build/api_stability_test_12; echo "exit: $?"
```

Expected: build succeeds; binary terminates abnormally (unhandled `std::invalid_argument` from the `default: throw` branch — McEliece types not yet handled).

- [ ] **Step 3: Add McEliece cases to `tray_id_byte()` in `crystals.hpp`**

In `pqc/libcrystals-1.2/include/crystals/crystals.hpp`, inside `tray_id_byte()`, insert before `default: throw std::invalid_argument("Unknown TrayType");` (currently line 294):

```cpp
        case TrayType::McEliece_Level1:    return 0x31;
        case TrayType::McEliece_Level2:    return 0x32;
        case TrayType::McEliece_Level3:    return 0x33;
        case TrayType::McEliece_Level4:    return 0x34;
        case TrayType::McEliece_Level5:    return 0x35;
```

- [ ] **Step 4: Add McEliece cases to `tray_type_from_id()` in `crystals.hpp`**

Inside `tray_type_from_id()`, insert before `default: throw std::runtime_error(...)` (currently line 312):

```cpp
        case 0x31: return TrayType::McEliece_Level1;
        case 0x32: return TrayType::McEliece_Level2;
        case 0x33: return TrayType::McEliece_Level3;
        case 0x34: return TrayType::McEliece_Level4;
        case 0x35: return TrayType::McEliece_Level5;
```

- [ ] **Step 5: Rebuild and verify test passes**

```bash
cmake --build pqc/libcrystals-1.2/build -j$(nproc) --target api_stability_test_12 2>&1 | tail -5
./pqc/libcrystals-1.2/build/api_stability_test_12; echo "exit: $?"
```

Expected: `exit: 0`

- [ ] **Step 6: Commit**

```bash
git -C pqc add libcrystals-1.2/include/crystals/crystals.hpp \
               libcrystals-1.2/test/api_stability_test-1.2.cpp
git -C pqc commit -m "feat: add McEliece Level1-5 HYKE tray ID bytes (0x31-0x35)"
```

---

## Task 2: Test and implement `is_tray_complete()`

**Files:**
- Modify: `pqc/libcrystals-1.2/test/api_stability_test-1.2.cpp`
- Modify: `pqc/libcrystals-1.2/include/crystals/crystals.hpp` (after `tray_type_from_id()`)

- [ ] **Step 1: Add signature assertion and runtime assertions to api_stability_test-1.2.cpp**

Add a static_assert for the function signature (at file scope, after the existing static_asserts) and extend `main()` with completeness checks. The full updated bottom of the file:

```cpp
// ── is_tray_complete (@api-stable v1.2) ──────────────────────────────────────
static_assert(std::is_same_v<
    decltype(&is_tray_complete),
    bool (*)(TrayType)>);

int main() {
    // McEliece tray ID byte round-trips (from Task 1)
    assert(tray_id_byte(TrayType::McEliece_Level1) == 0x31);
    assert(tray_id_byte(TrayType::McEliece_Level2) == 0x32);
    assert(tray_id_byte(TrayType::McEliece_Level3) == 0x33);
    assert(tray_id_byte(TrayType::McEliece_Level4) == 0x34);
    assert(tray_id_byte(TrayType::McEliece_Level5) == 0x35);
    assert(tray_type_from_id(0x31) == TrayType::McEliece_Level1);
    assert(tray_type_from_id(0x32) == TrayType::McEliece_Level2);
    assert(tray_type_from_id(0x33) == TrayType::McEliece_Level3);
    assert(tray_type_from_id(0x34) == TrayType::McEliece_Level4);
    assert(tray_type_from_id(0x35) == TrayType::McEliece_Level5);

    // is_tray_complete: partial trays return false
    assert(!is_tray_complete(TrayType::Level0));
    assert(!is_tray_complete(TrayType::Level1));
    assert(!is_tray_complete(TrayType::McEliece_Level1));

    // is_tray_complete: full trays return true
    assert(is_tray_complete(TrayType::Level2_25519));
    assert(is_tray_complete(TrayType::Level2));
    assert(is_tray_complete(TrayType::Level3));
    assert(is_tray_complete(TrayType::Level5));
    assert(is_tray_complete(TrayType::McEliece_Level2));
    assert(is_tray_complete(TrayType::McEliece_Level3));
    assert(is_tray_complete(TrayType::McEliece_Level4));
    assert(is_tray_complete(TrayType::McEliece_Level5));
    assert(is_tray_complete(TrayType::MlKem_Level2));
    assert(is_tray_complete(TrayType::FrodoFalcon_Level2));
    return 0;
}
```

- [ ] **Step 2: Build and verify test fails**

```bash
cmake --build pqc/libcrystals-1.2/build -j$(nproc) --target api_stability_test_12 2>&1 | grep -i error | head -5
```

Expected: compile error — `is_tray_complete` not declared.

- [ ] **Step 3: Add `is_tray_complete()` to `crystals.hpp`**

In `pqc/libcrystals-1.2/include/crystals/crystals.hpp`, insert after the closing `}` of `tray_type_from_id()` (currently around line 314):

```cpp
inline bool is_tray_complete(TrayType t) {              // @api-stable v1.2
    switch (t) {
        case TrayType::Level0:          return false;   // crystals, classical-only
        case TrayType::Level1:          return false;   // crystals, PQ-only
        case TrayType::McEliece_Level1: return false;   // mceliece+slhdsa, PQ-only
        default:                        return true;
    }
}
```

- [ ] **Step 4: Rebuild and verify test passes**

```bash
cmake --build pqc/libcrystals-1.2/build -j$(nproc) --target api_stability_test_12 2>&1 | tail -5
./pqc/libcrystals-1.2/build/api_stability_test_12; echo "exit: $?"
```

Expected: `exit: 0`

- [ ] **Step 5: Install libcrystals so obi-wan picks up the changes**

```bash
sudo bash pqc/libcrystals-1.2/install.sh
```

Expected: ends with `libcrystals installed` (or similar success message).

- [ ] **Step 6: Commit**

```bash
git -C pqc add libcrystals-1.2/include/crystals/crystals.hpp \
               libcrystals-1.2/test/api_stability_test-1.2.cpp
git -C pqc commit -m "feat: add is_tray_complete() helper (@api-stable v1.2)"
```

---

## Task 3: Add `is_tray_complete()` guard in obi-wan

**Files:**
- Modify: `pqc/obi-wan/src/main.cpp:420-444` (cmd_encrypt_sign)
- Modify: `pqc/obi-wan/src/main.cpp:588-612` (cmd_verify_decrypt)

- [ ] **Step 1: Add guard to `cmd_encrypt_sign`**

In `pqc/obi-wan/src/main.cpp`, after the tray-loading try/catch block in `cmd_encrypt_sign` (after `return 3;` at ~line 429, before `const Slot* cl_kem` at ~line 432), insert:

```cpp
    if (!is_tray_complete(tray.tray_type)) {
        std::cerr << "Error: " << tray.profile_group << " "
                  << tray_type_to_profile(tray.tray_type)
                  << " is a partial tray and cannot be used for HYKE"
                  << " — a full 4-slot tray (classical + PQ KEM and sig) is required\n";
        return 1;
    }
```

- [ ] **Step 2: Add guard to `cmd_verify_decrypt`**

Same insertion in `cmd_verify_decrypt` after the tray-loading try/catch block (after `return 3;` at ~line 597, before `const Slot* cl_kem` at ~line 600):

```cpp
    if (!is_tray_complete(tray.tray_type)) {
        std::cerr << "Error: " << tray.profile_group << " "
                  << tray_type_to_profile(tray.tray_type)
                  << " is a partial tray and cannot be used for HYKE"
                  << " — a full 4-slot tray (classical + PQ KEM and sig) is required\n";
        return 1;
    }
```

- [ ] **Step 3: Rebuild obi-wan**

```bash
cmake -S pqc/obi-wan -B pqc/obi-wan/build 2>/dev/null
cmake --build pqc/obi-wan/build -j$(nproc) 2>&1 | tail -5
```

Expected: build succeeds with no errors.

- [ ] **Step 4: Test McEliece Level1 partial-tray rejection**

```bash
./pqc/scotty/build/scotty keygen --group mceliece+slhdsa --alias ms1 \
  --profile level1 --out /tmp/ms1.tray
echo "hello" > /tmp/plain.txt
./pqc/obi-wan/build/obi-wan encrypt+sign --tray /tmp/ms1.tray /tmp/plain.txt
echo "exit: $?"
```

Expected: stderr contains `mceliece+slhdsa level1 is a partial tray and cannot be used for HYKE`, exit code `1`.

- [ ] **Step 5: Test McEliece Level2 encrypt+sign / verify+decrypt roundtrip**

```bash
./pqc/scotty/build/scotty keygen --group mceliece+slhdsa --alias ms2 \
  --profile level2 --out /tmp/ms2.tray
./pqc/obi-wan/build/obi-wan encrypt+sign --tray /tmp/ms2.tray /tmp/plain.txt \
  > /tmp/ms2.hyke
./pqc/obi-wan/build/obi-wan verify+decrypt --tray /tmp/ms2.tray /tmp/ms2.hyke \
  | diff /tmp/plain.txt -
echo "exit: $?"
```

Expected: no diff output, exit code `0`.

- [ ] **Step 6: Test McEliece Level5 roundtrip (largest key — confirms large CT handling)**

```bash
./pqc/scotty/build/scotty keygen --group mceliece+slhdsa --alias ms5 \
  --profile level5 --out /tmp/ms5.tray
./pqc/obi-wan/build/obi-wan encrypt+sign --tray /tmp/ms5.tray /tmp/plain.txt \
  > /tmp/ms5.hyke
./pqc/obi-wan/build/obi-wan verify+decrypt --tray /tmp/ms5.tray /tmp/ms5.hyke \
  | diff /tmp/plain.txt -
echo "exit: $?"
```

Expected: no diff output, exit code `0`.

- [ ] **Step 7: Commit**

```bash
git -C pqc add obi-wan/src/main.cpp
git -C pqc commit -m "feat: guard HYKE commands against partial trays; unblock McEliece HYKE"
```

---

## Task 4: Update CLAUDE.md verified-working section

**Files:**
- Modify: `pqc/CLAUDE.md`

- [ ] **Step 1: Add McEliece HYKE entries to verified-working**

In `pqc/CLAUDE.md`, find the `## Verified Working (obi-wan)` section and append:

```
- McEliece encrypt+sign/verify+decrypt: level2, level3, level4, level5 roundtrip OK (2026-04-05)
- McEliece level1 (partial tray) → exit 1 + partial-tray error message (2026-04-05)
```

- [ ] **Step 2: Commit**

```bash
git -C pqc add CLAUDE.md
git -C pqc commit -m "docs: update verified-working for McEliece HYKE support"
```
