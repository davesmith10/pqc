# Hybrid Digital Signatures Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add pure hybrid digital `sign` / `verify` commands to zorro, and rename the existing HYKE sign/verify to `encrypt+sign` / `verify+decrypt`.

**Architecture:** All changes are in `pqc/zorro/src/main.cpp` (single-file pattern already established). New helper functions are inserted before the command functions. New commands are dispatched early in `main()` via their own arg-parsing blocks, consistent with how `gentok` / `valtok` are handled.

**Tech Stack:** C++17, OpenSSL (EVP_Digest for SHA-256, RAND_bytes for UUID generation), libcrystals-1.2 (ec_sig, dilithium_sig, slhdsa_sig, oqs_sig, base64_encode/decode, parse_uuid, load_tray).

**Spec:** `docs/superpowers/specs/2026-03-24-hybrid-signatures-design.md`

---

## File Map

| File | Action | What changes |
|---|---|---|
| `pqc/zorro/src/main.cpp` | Modify | All changes — renames, helpers, new commands, dispatch |

No other files change. No library changes.

### Insertion points in main.cpp (~780 lines)

- **After line 10** (`#include <openssl/rand.h>`): add `#include <cstdio>`
- **After line 102** (end of slot-selection helpers): add new helper functions
- **After `cmd_verify_decrypt`** (renamed from `cmd_verify`, ~line 640): add `cmd_pure_sign`, `cmd_pure_verify`
- **In `main()`, before `pwencrypt`/`pwdecrypt` early dispatch**: add `sign`/`verify` dispatch blocks
- **In the existing positional-arg dispatch block**: update command names from `sign`/`verify` to `encrypt+sign`/`verify+decrypt`

---

## Task 1: Rename sign→encrypt+sign, verify→verify+decrypt

**Files:**
- Modify: `pqc/zorro/src/main.cpp`

- [ ] **Step 1: Write the failing test — confirm new command names don't exist yet**

```bash
cmake -S pqc/zorro -B pqc/zorro/build -DCMAKE_BUILD_TYPE=Release 2>/dev/null
cmake --build pqc/zorro/build -j$(nproc) 2>/dev/null
./pqc/zorro/build/zorro encrypt+sign 2>&1 | head -2
```
Expected: `Error: unknown command 'encrypt+sign'`

- [ ] **Step 2: Rename `cmd_sign` → `cmd_encrypt_sign`**

In `main.cpp`, rename the function at the `// ── sign command` section:
```cpp
// ── encrypt+sign command ─────────────────────────────────────────────────────

static int cmd_encrypt_sign(const std::string& tray_path,
                              const std::string& target_path)
```

- [ ] **Step 3: Rename `cmd_verify` → `cmd_verify_decrypt`**

```cpp
// ── verify+decrypt command ────────────────────────────────────────────────────

static int cmd_verify_decrypt(const std::string& tray_path,
                               const std::string& target_path)
```

- [ ] **Step 4: Update the command-validation guard in `main()`**

Find (around line 699):
```cpp
if (cmd != "encrypt" && cmd != "decrypt" && cmd != "sign" && cmd != "verify") {
```
Replace with:
```cpp
if (cmd != "encrypt" && cmd != "decrypt" && cmd != "encrypt+sign" && cmd != "verify+decrypt") {
```

> **Why `sign`/`verify` are NOT added back here:** The new `sign` and `verify` commands are dispatched earlier in `main()` via their own early-return blocks (added in Tasks 3 and 4), before execution reaches this guard. The guard only sees commands that reach the positional-arg parsing block, which the new `sign`/`verify` never do.

- [ ] **Step 5: Update the command dispatch at the bottom of the positional-arg block**

Find:
```cpp
    if (cmd == "encrypt") {
        return cmd_encrypt(tray_path, target_path, kdf_alg, cipher_alg);
    } else if (cmd == "decrypt") {
        return cmd_decrypt(tray_path, target_path);
    } else if (cmd == "sign") {
        return cmd_sign(tray_path, target_path);
    } else {
        return cmd_verify(tray_path, target_path);
    }
```
Replace with:
```cpp
    if (cmd == "encrypt") {
        return cmd_encrypt(tray_path, target_path, kdf_alg, cipher_alg);
    } else if (cmd == "decrypt") {
        return cmd_decrypt(tray_path, target_path);
    } else if (cmd == "encrypt+sign") {
        return cmd_encrypt_sign(tray_path, target_path);
    } else {
        return cmd_verify_decrypt(tray_path, target_path);
    }
```

- [ ] **Step 6: Update `print_usage`**

Find the two lines referencing `sign` and `verify` in the HYKE section:
```cpp
        "  " << prog << " sign    --tray <file> <target-file>\n"
        "  " << prog << " verify  --tray <file> <target-file>\n"
```
Replace with:
```cpp
        "  " << prog << " encrypt+sign --tray <file> <target-file>\n"
        "  " << prog << " verify+decrypt --tray <file> <target-file>\n"
        "  " << prog << " sign    --tray <file> --in-file <file>\n"
        "  " << prog << " verify  --tray <file> --in-file <file> --in-sig <file>\n"
```
Also update the description lines for sign/verify below the flags section:
```cpp
        "  encrypt+sign: encrypt-and-sign using all 4 tray slots; writes HYKE armor to stdout\n"
        "  verify+decrypt: verify both signatures and decrypt HYKE file; writes plaintext to stdout\n"
        "  sign:      hybrid digital signature (no encryption); writes sig YAML to stdout\n"
        "  verify:    verify hybrid composite signature; writes verification YAML to stdout\n"
```

- [ ] **Step 7: Build and verify renamed commands work**

```bash
cmake --build pqc/zorro/build -j$(nproc)
./pqc/hybrid/build/hybrid keygen --alias alice --profile level2-25519 > /tmp/alice.tray
echo "hello" > /tmp/plain.txt
./pqc/zorro/build/zorro encrypt+sign --tray /tmp/alice.tray /tmp/plain.txt > /tmp/alice.hyke
./pqc/zorro/build/zorro verify+decrypt --tray /tmp/alice.tray /tmp/alice.hyke | diff /tmp/plain.txt -
echo "exit: $?"
```
Expected: `exit: 0`

- [ ] **Step 8: Confirm old `sign` name is rejected (valid only before Task 3 adds the new `sign` dispatch)**

```bash
./pqc/zorro/build/zorro sign --tray /tmp/alice.tray /tmp/plain.txt 2>&1 | head -1
```
Expected: `Error: unknown command 'sign'`

> **Note:** After Task 3 adds the new `sign` command, the binary will accept `sign` again (with `--in-file` flags). This step is only valid between Task 1 and Task 3.

- [ ] **Step 9: Commit**

```bash
git add pqc/zorro/src/main.cpp
git commit -m "rename zorro sign/verify to encrypt+sign/verify+decrypt"
```

---

## Task 2: Add helper functions

**Files:**
- Modify: `pqc/zorro/src/main.cpp`

Insert all helpers after the slot-selection block (after the `find_pq_sig_slot` function, before `// ── encrypt command`).

- [ ] **Step 1: Add `#include <cstdio>` for `snprintf`**

After `#include <openssl/rand.h>`:
```cpp
#include <cstdio>
```

- [ ] **Step 2: Add `sha256_bytes` helper**

```cpp
// ── Pure-sig helpers ──────────────────────────────────────────────────────────

static std::array<uint8_t, 32> sha256_bytes(const std::vector<uint8_t>& data) {
    std::array<uint8_t, 32> digest{};
    unsigned int len = 32;
    if (!EVP_Digest(data.data(), data.size(), digest.data(), &len, EVP_sha256(), nullptr))
        throw std::runtime_error("SHA-256 failed");
    return digest;
}
```

- [ ] **Step 3: Add `generate_uuid_v4` helper**

```cpp
static std::string generate_uuid_v4() {
    uint8_t b[16];
    if (RAND_bytes(b, 16) != 1)
        throw std::runtime_error("RAND_bytes failed");
    b[6] = (b[6] & 0x0F) | 0x40; // version 4
    b[8] = (b[8] & 0x3F) | 0x80; // variant bits
    char buf[37];
    std::snprintf(buf, sizeof(buf),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        b[0],b[1],b[2],b[3], b[4],b[5], b[6],b[7],
        b[8],b[9], b[10],b[11],b[12],b[13],b[14],b[15]);
    return std::string(buf);
}
```

- [ ] **Step 4: Add `tray_type_to_profile` helper**

```cpp
static std::string tray_type_to_profile(TrayType t) {
    switch (t) {
        case TrayType::Level0:             return "level0";
        case TrayType::Level1:             return "level1";
        case TrayType::Level2_25519:       return "level2-25519";
        case TrayType::Level2:             return "level2";
        case TrayType::Level3:             return "level3";
        case TrayType::Level5:             return "level5";
        case TrayType::McEliece_Level1:    return "level1";
        case TrayType::McEliece_Level2:    return "level2";
        case TrayType::McEliece_Level3:    return "level3";
        case TrayType::McEliece_Level4:    return "level4";
        case TrayType::McEliece_Level5:    return "level5";
        case TrayType::MlKem_Level1:       return "mk-level1";
        case TrayType::MlKem_Level2:       return "mk-level2";
        case TrayType::MlKem_Level3:       return "mk-level3";
        case TrayType::MlKem_Level4:       return "mk-level4";
        case TrayType::FrodoFalcon_Level1: return "ff-level1";
        case TrayType::FrodoFalcon_Level2: return "ff-level2";
        case TrayType::FrodoFalcon_Level3: return "ff-level3";
        case TrayType::FrodoFalcon_Level4: return "ff-level4";
        default:                           return "unknown";
    }
}
```

- [ ] **Step 5: Add `pack_composite_sig` and `unpack_composite_sig`**

```cpp
static std::vector<uint8_t> pack_composite_sig(const std::vector<uint8_t>& sig_cl,
                                                const std::vector<uint8_t>& sig_pq)
{
    std::vector<uint8_t> out;
    out.reserve(8 + sig_cl.size() + sig_pq.size());
    auto push_u32be = [&](uint32_t v) {
        out.push_back((v >> 24) & 0xFF); out.push_back((v >> 16) & 0xFF);
        out.push_back((v >>  8) & 0xFF); out.push_back((v >>  0) & 0xFF);
    };
    push_u32be((uint32_t)sig_cl.size());
    out.insert(out.end(), sig_cl.begin(), sig_cl.end());
    push_u32be((uint32_t)sig_pq.size());
    out.insert(out.end(), sig_pq.begin(), sig_pq.end());
    return out;
}

struct CompositeSig {
    std::vector<uint8_t> sig_cl;
    std::vector<uint8_t> sig_pq;
};

static CompositeSig unpack_composite_sig(const std::vector<uint8_t>& data) {
    auto read_u32be = [](const uint8_t* p) -> uint32_t {
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] <<  8) | (uint32_t)p[3];
    };
    const uint8_t* p   = data.data();
    const uint8_t* end = p + data.size();
    if (p + 4 > end) throw std::runtime_error("composite sig too short");
    uint32_t len_cl = read_u32be(p); p += 4;
    if (p + len_cl > end) throw std::runtime_error("composite sig: len_cl overflows buffer");
    CompositeSig cs;
    cs.sig_cl.assign(p, p + len_cl); p += len_cl;
    if (p + 4 > end) throw std::runtime_error("composite sig: truncated len_pq");
    uint32_t len_pq = read_u32be(p); p += 4;
    if (p + len_pq > end) throw std::runtime_error("composite sig: len_pq overflows buffer");
    cs.sig_pq.assign(p, p + len_pq);
    return cs;
}
```

- [ ] **Step 6: Add `SigYaml` struct and `parse_sig_yaml`**

```cpp
struct SigYaml {
    std::string signature_id;
    std::string tray_id;
    std::string input_file;
    std::string composite_sig;
};

static SigYaml parse_sig_yaml(const std::string& text) {
    SigYaml r;
    std::istringstream ss(text);
    std::string line;
    while (std::getline(ss, line)) {
        auto pos = line.find(": ");
        if (pos == std::string::npos) continue;
        std::string key = line.substr(0, pos);
        std::string val = line.substr(pos + 2);
        if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
            val = val.substr(1, val.size() - 2);
        if      (key == "signature_id")  r.signature_id  = val;
        else if (key == "tray_id")       r.tray_id       = val;
        else if (key == "input_file")    r.input_file    = val;
        else if (key == "composite_sig") r.composite_sig = val;
    }
    if (r.tray_id.empty())
        throw std::runtime_error("sig YAML missing required field: tray_id");
    if (r.composite_sig.empty())
        throw std::runtime_error("sig YAML missing required field: composite_sig");
    return r;
}
```

- [ ] **Step 7: Build to confirm helpers compile**

```bash
cmake --build pqc/zorro/build -j$(nproc) 2>&1 | tail -5
```
Expected: `[100%] Linking CXX executable zorro` or similar with no errors.

- [ ] **Step 8: Commit**

```bash
git add pqc/zorro/src/main.cpp
git commit -m "add pure-sig helpers to zorro (sha256, uuid, tray_type_to_profile, composite sig pack/unpack, sig yaml)"
```

---

## Task 3: Add `cmd_pure_sign` and dispatch

**Files:**
- Modify: `pqc/zorro/src/main.cpp`

- [ ] **Step 1: Write the failing test**

```bash
./pqc/hybrid/build/hybrid keygen --alias alice --profile level2-25519 > /tmp/alice.tray
echo "hello world" > /tmp/doc.txt
./pqc/zorro/build/zorro sign --tray /tmp/alice.tray --in-file /tmp/doc.txt 2>&1 | head -1
```
Expected: `Error: unknown command 'sign'`

- [ ] **Step 2: Add `cmd_pure_sign` after `cmd_verify_decrypt`**

Insert the following function (after the `cmd_verify_decrypt` function, before `main()`):

```cpp
// ── sign command (pure hybrid digital signature) ──────────────────────────────

static int cmd_pure_sign(const std::string& tray_path,
                          const std::string& in_file_path)
{
    Tray tray;
    try {
        tray = load_tray(tray_path);
    } catch (const std::exception& e) {
        std::cerr << "Error: cannot load tray: " << e.what() << "\n";
        return 3;
    }

    const Slot* cl_sig = find_classical_sig_slot(tray);
    const Slot* pq_sig = find_pq_sig_slot(tray);

    if (!cl_sig || !pq_sig) {
        std::cerr << "Error: tray must contain both a classical sig slot and a PQ sig slot for sign\n";
        return 1;
    }
    if (cl_sig->sk.empty() || pq_sig->sk.empty()) {
        std::cerr << "Error: tray signing secret keys required for sign\n";
        return 1;
    }

    std::vector<uint8_t> file_bytes;
    try {
        file_bytes = read_file(in_file_path);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 3;
    }

    std::string sig_id;
    try { sig_id = generate_uuid_v4(); }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n"; return 2;
    }

    uint8_t uuid_bytes[16];
    try { parse_uuid(tray.id, uuid_bytes); }
    catch (const std::exception& e) {
        std::cerr << "Error: failed to parse tray UUID: " << e.what() << "\n"; return 2;
    }

    std::array<uint8_t, 32> hash;
    try { hash = sha256_bytes(file_bytes); }
    catch (const std::exception& e) {
        std::cerr << "Error: SHA-256 failed: " << e.what() << "\n"; return 2;
    }

    std::vector<uint8_t> m_prime;
    m_prime.reserve(48);
    m_prime.insert(m_prime.end(), uuid_bytes, uuid_bytes + 16);
    m_prime.insert(m_prime.end(), hash.begin(), hash.end());

    std::vector<uint8_t> sig_cl;
    try { ec_sig::sign(cl_sig->alg_name, cl_sig->sk, m_prime, sig_cl); }
    catch (const std::exception& e) {
        std::cerr << "Error: classical signing failed: " << e.what() << "\n"; return 2;
    }

    std::vector<uint8_t> sig_pq;
    try {
        if (dilithium_sig::is_pq_sig(pq_sig->alg_name))
            dilithium_sig::sign(dilithium_sig::mode_from_alg(pq_sig->alg_name),
                                pq_sig->sk, m_prime, sig_pq);
        else if (oqs_sig::is_oqs_sig(pq_sig->alg_name))
            oqs_sig::sign(pq_sig->alg_name, pq_sig->sk, m_prime, sig_pq);
        else
            slhdsa_sig::sign(pq_sig->alg_name, pq_sig->sk, m_prime, sig_pq);
    } catch (const std::exception& e) {
        std::cerr << "Error: PQ signing failed: " << e.what() << "\n"; return 2;
    }

    auto composite     = pack_composite_sig(sig_cl, sig_pq);
    auto composite_b64 = base64_encode(composite.data(), composite.size());

    std::cout << "signature_id: \"" << sig_id          << "\"\n"
              << "tray_id: \""      << tray.id          << "\"\n"
              << "tray_alias: \""   << tray.alias       << "\"\n"
              << "profile_group: \"" << tray.profile_group << "\"\n"
              << "profile: \""      << tray_type_to_profile(tray.tray_type) << "\"\n"
              << "input_file: \""   << in_file_path     << "\"\n"
              << "composite_sig: \"" << composite_b64   << "\"\n";
    return 0;
}
```

- [ ] **Step 3: Wire up `sign` dispatch in `main()`**

In `main()`, find the block that handles `pwencrypt` / `pwdecrypt`:
```cpp
    if (cmd == "pwencrypt") return cmd_pwencrypt(argc - 1, argv + 1);
    if (cmd == "pwdecrypt") return cmd_pwdecrypt(argc - 1, argv + 1);
```
Insert **before** those lines:
```cpp
    if (cmd == "sign") {
        std::string tray_path, in_file;
        for (int i = 2; i < argc; ++i) {
            if (std::strcmp(argv[i], "--tray") == 0) {
                if (++i >= argc) { std::cerr << "Error: --tray requires a filename\n"; return 1; }
                tray_path = argv[i];
            } else if (std::strcmp(argv[i], "--in-file") == 0) {
                if (++i >= argc) { std::cerr << "Error: --in-file requires a filename\n"; return 1; }
                in_file = argv[i];
            } else {
                std::cerr << "Error: unknown option '" << argv[i] << "'\n"; return 1;
            }
        }
        if (tray_path.empty()) { std::cerr << "Error: --tray is required\n"; return 1; }
        if (in_file.empty())   { std::cerr << "Error: --in-file is required\n"; return 1; }
        return cmd_pure_sign(tray_path, in_file);
    }
```

- [ ] **Step 4: Build**

```bash
cmake --build pqc/zorro/build -j$(nproc) 2>&1 | tail -3
```
Expected: build succeeds with no errors.

- [ ] **Step 5: Run sign test**

```bash
./pqc/zorro/build/zorro sign --tray /tmp/alice.tray --in-file /tmp/doc.txt > /tmp/doc.sig.yaml
echo "exit: $?"
cat /tmp/doc.sig.yaml
```
Expected: exit 0. YAML contains `signature_id`, `tray_id`, `tray_alias: "alice"`, `profile_group: "crystals"`, `profile: "level2-25519"`, `input_file`, `composite_sig`.

- [ ] **Step 6: Test partial tray rejected**

```bash
./pqc/hybrid/build/hybrid keygen --alias cl-only --profile level0 > /tmp/cl.tray
./pqc/zorro/build/zorro sign --tray /tmp/cl.tray --in-file /tmp/doc.txt 2>&1
echo "exit: $?"
```
Expected: error message about missing sig slots; exit 1.

- [ ] **Step 7: Commit**

```bash
git add pqc/zorro/src/main.cpp
git commit -m "add zorro sign command (pure hybrid digital signature)"
```

---

## Task 4: Add `cmd_pure_verify` and dispatch

**Files:**
- Modify: `pqc/zorro/src/main.cpp`

- [ ] **Step 1: Write the failing test**

```bash
./pqc/zorro/build/zorro verify --tray /tmp/alice.tray --in-file /tmp/doc.txt --in-sig /tmp/doc.sig.yaml 2>&1 | head -1
```
Expected: `Error: unknown command 'verify'`

- [ ] **Step 2: Add `cmd_pure_verify` after `cmd_pure_sign`**

```cpp
// ── verify command (pure hybrid signature verification) ───────────────────────

static int cmd_pure_verify(const std::string& tray_path,
                            const std::string& in_file_path,
                            const std::string& in_sig_path)
{
    Tray tray;
    try {
        tray = load_tray(tray_path);
    } catch (const std::exception& e) {
        std::cerr << "Error: cannot load tray: " << e.what() << "\n";
        return 3;
    }

    const Slot* cl_sig = find_classical_sig_slot(tray);
    const Slot* pq_sig = find_pq_sig_slot(tray);

    if (!cl_sig || !pq_sig) {
        std::cerr << "Error: tray must contain both a classical sig slot and a PQ sig slot for verify\n";
        return 1;
    }

    SigYaml syaml;
    try {
        syaml = parse_sig_yaml(read_file_text(in_sig_path));
    } catch (const std::exception& e) {
        std::cerr << "Error: failed to parse sig file: " << e.what() << "\n";
        return 2;
    }

    if (syaml.tray_id != tray.id) {
        std::cerr << "Error: tray_id mismatch (sig was made with a different tray)\n";
        return 2;
    }

    std::vector<uint8_t> file_bytes;
    try {
        file_bytes = read_file(in_file_path);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 3;
    }

    uint8_t uuid_bytes[16];
    try { parse_uuid(tray.id, uuid_bytes); }
    catch (const std::exception& e) {
        std::cerr << "Error: failed to parse tray UUID: " << e.what() << "\n"; return 2;
    }

    std::array<uint8_t, 32> hash;
    try { hash = sha256_bytes(file_bytes); }
    catch (const std::exception& e) {
        std::cerr << "Error: SHA-256 failed: " << e.what() << "\n"; return 2;
    }

    std::vector<uint8_t> m_prime;
    m_prime.reserve(48);
    m_prime.insert(m_prime.end(), uuid_bytes, uuid_bytes + 16);
    m_prime.insert(m_prime.end(), hash.begin(), hash.end());

    CompositeSig cs;
    try {
        cs = unpack_composite_sig(base64_decode(syaml.composite_sig));
    } catch (const std::exception& e) {
        std::cerr << "Error: malformed composite sig: " << e.what() << "\n";
        return 2;
    }

    try {
        if (!ec_sig::verify(cl_sig->alg_name, cl_sig->pk, m_prime, cs.sig_cl)) {
            std::cerr << "Error: classical signature INVALID\n"; return 2;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: classical signature verification failed: " << e.what() << "\n";
        return 2;
    }

    try {
        bool pq_ok = false;
        if (dilithium_sig::is_pq_sig(pq_sig->alg_name))
            pq_ok = dilithium_sig::verify(dilithium_sig::mode_from_alg(pq_sig->alg_name),
                                          pq_sig->pk, m_prime, cs.sig_pq);
        else if (oqs_sig::is_oqs_sig(pq_sig->alg_name))
            pq_ok = oqs_sig::verify(pq_sig->alg_name, pq_sig->pk, m_prime, cs.sig_pq);
        else
            pq_ok = slhdsa_sig::verify(pq_sig->alg_name, pq_sig->pk, m_prime, cs.sig_pq);
        if (!pq_ok) { std::cerr << "Error: PQ signature INVALID\n"; return 2; }
    } catch (const std::exception& e) {
        std::cerr << "Error: PQ signature verification failed: " << e.what() << "\n";
        return 2;
    }

    std::cout << "verified: true\n"
              << "signature_id: \"" << syaml.signature_id << "\"\n"
              << "tray_id: \""      << tray.id             << "\"\n"
              << "tray_alias: \""   << tray.alias          << "\"\n"
              << "profile_group: \"" << tray.profile_group << "\"\n"
              << "profile: \""      << tray_type_to_profile(tray.tray_type) << "\"\n"
              << "input_file: \""   << syaml.input_file    << "\"\n";
    return 0;
}
```

- [ ] **Step 3: Wire up `verify` dispatch in `main()`**

In `main()`, immediately after the `sign` dispatch block added in Task 3, insert:
```cpp
    if (cmd == "verify") {
        std::string tray_path, in_file, in_sig;
        for (int i = 2; i < argc; ++i) {
            if (std::strcmp(argv[i], "--tray") == 0) {
                if (++i >= argc) { std::cerr << "Error: --tray requires a filename\n"; return 1; }
                tray_path = argv[i];
            } else if (std::strcmp(argv[i], "--in-file") == 0) {
                if (++i >= argc) { std::cerr << "Error: --in-file requires a filename\n"; return 1; }
                in_file = argv[i];
            } else if (std::strcmp(argv[i], "--in-sig") == 0) {
                if (++i >= argc) { std::cerr << "Error: --in-sig requires a filename\n"; return 1; }
                in_sig = argv[i];
            } else {
                std::cerr << "Error: unknown option '" << argv[i] << "'\n"; return 1;
            }
        }
        if (tray_path.empty()) { std::cerr << "Error: --tray is required\n"; return 1; }
        if (in_file.empty())   { std::cerr << "Error: --in-file is required\n"; return 1; }
        if (in_sig.empty())    { std::cerr << "Error: --in-sig is required\n"; return 1; }
        return cmd_pure_verify(tray_path, in_file, in_sig);
    }
```

- [ ] **Step 4: Build**

```bash
cmake --build pqc/zorro/build -j$(nproc) 2>&1 | tail -3
```
Expected: build succeeds.

- [ ] **Step 5: Basic roundtrip test**

```bash
./pqc/zorro/build/zorro verify \
    --tray /tmp/alice.tray \
    --in-file /tmp/doc.txt \
    --in-sig /tmp/doc.sig.yaml
echo "exit: $?"
```
Expected: exit 0. YAML output contains `verified: true` plus matching `tray_id`, `profile: "level2-25519"`.

- [ ] **Step 6: Tampered file test**

```bash
echo "tampered" > /tmp/doc_tampered.txt
./pqc/zorro/build/zorro verify \
    --tray /tmp/alice.tray \
    --in-file /tmp/doc_tampered.txt \
    --in-sig /tmp/doc.sig.yaml 2>&1
echo "exit: $?"
```
Expected: `Error: classical signature INVALID`; exit 2.

- [ ] **Step 7: Wrong tray test**

```bash
./pqc/hybrid/build/hybrid keygen --alias bob --profile level2-25519 > /tmp/bob.tray
./pqc/zorro/build/zorro verify \
    --tray /tmp/bob.tray \
    --in-file /tmp/doc.txt \
    --in-sig /tmp/doc.sig.yaml 2>&1
echo "exit: $?"
```
Expected: `Error: tray_id mismatch`; exit 2.

- [ ] **Step 8: Commit**

```bash
git add pqc/zorro/src/main.cpp
git commit -m "add zorro verify command (pure hybrid signature verification)"
```

---

## Task 5: Extended integration tests

**Files:**
- No code changes — testing only.

Run the full test matrix from the spec. All should produce exit 0 unless noted.

- [ ] **Step 1: All crystals hybrid profiles**

```bash
for profile in level2-25519 level2 level3 level5; do
    ./pqc/hybrid/build/hybrid keygen --alias test --profile $profile > /tmp/t.tray
    ./pqc/zorro/build/zorro sign   --tray /tmp/t.tray --in-file /tmp/doc.txt > /tmp/t.sig.yaml
    ./pqc/zorro/build/zorro verify --tray /tmp/t.tray --in-file /tmp/doc.txt --in-sig /tmp/t.sig.yaml
    echo "$profile: $?"
done
```
Expected: all exit 0.

- [ ] **Step 2: mceliece+slhdsa profiles (4-slot ones)**

```bash
for profile in level2 level3 level4 level5; do
    ./pqc/hybrid/build/hybrid keygen --group mceliece+slhdsa --alias test --profile $profile > /tmp/t.tray
    ./pqc/zorro/build/zorro sign   --tray /tmp/t.tray --in-file /tmp/doc.txt > /tmp/t.sig.yaml
    ./pqc/zorro/build/zorro verify --tray /tmp/t.tray --in-file /tmp/doc.txt --in-sig /tmp/t.sig.yaml
    echo "mceliece $profile: $?"
done
```
Expected: all exit 0.

- [ ] **Step 3: mlkem+mldsa and frodokem+falcon**

```bash
for profile in mk-level2 mk-level3 mk-level4; do
    ./pqc/hybrid/build/hybrid keygen --group mlkem+mldsa --alias test --profile $profile > /tmp/t.tray
    ./pqc/zorro/build/zorro sign   --tray /tmp/t.tray --in-file /tmp/doc.txt > /tmp/t.sig.yaml
    ./pqc/zorro/build/zorro verify --tray /tmp/t.tray --in-file /tmp/doc.txt --in-sig /tmp/t.sig.yaml
    echo "$profile: $?"
done
for profile in ff-level2 ff-level3; do
    ./pqc/hybrid/build/hybrid keygen --group frodokem+falcon --alias test --profile $profile > /tmp/t.tray
    ./pqc/zorro/build/zorro sign   --tray /tmp/t.tray --in-file /tmp/doc.txt > /tmp/t.sig.yaml
    ./pqc/zorro/build/zorro verify --tray /tmp/t.tray --in-file /tmp/doc.txt --in-sig /tmp/t.sig.yaml
    echo "$profile: $?"
done
```
Expected: all exit 0.

- [ ] **Step 4: 1MB binary file roundtrip**

```bash
dd if=/dev/urandom of=/tmp/big.bin bs=1M count=1 2>/dev/null
./pqc/hybrid/build/hybrid keygen --alias alice --profile level2-25519 > /tmp/alice.tray
./pqc/zorro/build/zorro sign   --tray /tmp/alice.tray --in-file /tmp/big.bin > /tmp/big.sig.yaml
./pqc/zorro/build/zorro verify --tray /tmp/alice.tray --in-file /tmp/big.bin --in-sig /tmp/big.sig.yaml
echo "exit: $?"
```
Expected: exit 0.

- [ ] **Step 5: Tampered composite_sig blob**

```bash
# Replace the composite_sig value with a short valid-base64 string that decodes to only
# 3 bytes — far too short for any real composite sig — triggering "composite sig too short".
# Using "XXXX" (4 base64 chars = 3 decoded bytes) is reliable regardless of algorithm.
sed 's/\(composite_sig: "\)[^"]*/\1XXXX/' /tmp/doc.sig.yaml > /tmp/doc.sig.corrupt.yaml
./pqc/zorro/build/zorro verify \
    --tray /tmp/alice.tray \
    --in-file /tmp/doc.txt \
    --in-sig /tmp/doc.sig.corrupt.yaml 2>&1
echo "exit: $?"
```
Expected: `Error: malformed composite sig: composite sig too short`; exit 2.

- [ ] **Step 6: Confirm existing HYKE commands still work**

```bash
./pqc/zorro/build/zorro encrypt+sign   --tray /tmp/alice.tray /tmp/doc.txt > /tmp/doc.hyke
./pqc/zorro/build/zorro verify+decrypt --tray /tmp/alice.tray /tmp/doc.hyke | diff /tmp/doc.txt -
echo "HYKE exit: $?"
```
Expected: exit 0, no diff output.

- [ ] **Step 7: Confirm missing `--in-sig` on verify → exit 1**

```bash
./pqc/zorro/build/zorro verify \
    --tray /tmp/alice.tray \
    --in-file /tmp/doc.txt 2>&1
echo "exit: $?"
```
Expected: `Error: --in-sig is required`; exit 1.

- [ ] **Confirm `--in-sig` passed to `sign` is rejected → exit 1**

```bash
./pqc/zorro/build/zorro sign \
    --tray /tmp/alice.tray \
    --in-file /tmp/doc.txt \
    --in-sig /tmp/doc.sig.yaml 2>&1
echo "exit: $?"
```
Expected: `Error: unknown option '--in-sig'`; exit 1.

- [ ] **Step 9: Confirm mceliece+slhdsa level1 (PQ-only) rejected**

```bash
./pqc/hybrid/build/hybrid keygen --group mceliece+slhdsa --alias test --profile level1 > /tmp/mc1.tray
./pqc/zorro/build/zorro sign --tray /tmp/mc1.tray --in-file /tmp/doc.txt 2>&1
echo "exit: $?"
```
Expected: error about missing classical sig slot; exit 1.

- [ ] **Step 8: Commit**

```bash
git add pqc/zorro/src/main.cpp
git commit -m "verify hybrid sign/verify across all profile groups"
```
