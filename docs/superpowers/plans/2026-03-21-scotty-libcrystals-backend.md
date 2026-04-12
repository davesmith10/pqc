# hybrid → libcrystals-1.1 Backend Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace hybrid's ~20 private source files with a single `main.cpp` that calls `Crystals::crystals` (libcrystals-1.1), making hybrid a thin CLI shell with no duplicated crypto or YAML logic.

**Architecture:** `find_package(Crystals REQUIRED HINTS /usr/local/lib/cmake/crystals)` replaces all `add_subdirectory`, scrypt, and individual PQ link targets in CMakeLists.txt. `main.cpp` changes its three private `#include` lines to `#include <crystals/crystals.hpp>` and folds in `cmd_protect`/`cmd_unprotect` (pure CLI handlers) from the deleted `secure_tray.cpp`. All crypto and YAML logic lives entirely in the library.

**Tech Stack:** C++17, CMake 3.15+, libcrystals-1.1 (`Crystals::crystals` at `/usr/local`), OpenSSL 3 (for `EVP_read_pw_string` / `OPENSSL_cleanse` in the CLI password layer)

---

## File Map

| File | Action | Responsibility after change |
|------|--------|-----------------------------|
| `pq/hybrid/CMakeLists.txt` | **Rewrite** | find_package(Crystals) + thin executable |
| `pq/hybrid/src/main.cpp` | **Rewrite** | All hybrid CLI: keygen, protect, unprotect, helpers |
| `pq/hybrid/src/base64.cpp` + `.hpp` | **Delete** | (in libcrystals) |
| `pq/hybrid/src/ec_ops.cpp` + `.hpp` | **Delete** | (in libcrystals) |
| `pq/hybrid/src/kyber_ops.cpp` + `.hpp` | **Delete** | (in libcrystals) |
| `pq/hybrid/src/kyber_api.hpp` | **Delete** | (in libcrystals) |
| `pq/hybrid/src/dilithium_ops.cpp` + `.hpp` | **Delete** | (in libcrystals) |
| `pq/hybrid/src/dilithium_api.hpp` | **Delete** | (in libcrystals) |
| `pq/hybrid/src/mceliece_ops.cpp` + `.hpp` | **Delete** | (in libcrystals) |
| `pq/hybrid/src/slhdsa_ops.cpp` + `.hpp` | **Delete** | (in libcrystals) |
| `pq/hybrid/src/mceliece_randombytes.c` | **Delete** | (in libcrystals) |
| `pq/hybrid/src/tray.cpp` | **Delete** | (in libcrystals) |
| `pq/hybrid/src/yaml_io.cpp` + `.hpp` | **Delete** | (in libcrystals) |
| `pq/hybrid/src/secure_tray.cpp` + `.hpp` | **Delete** | CLI parts fold into main.cpp; crypto in libcrystals |
| `pq/hybrid/src/symmetric.hpp` | **Delete** | (in libcrystals) |

---

## Task 1: Create the worktree branch

**Files:**
- No source files changed — git setup only

- [ ] **Step 1: Confirm you are in the pq/ git root**

```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/pq
git status
```

Expected: on branch `main`, working tree clean (or only untracked files).

- [ ] **Step 2: Create the worktree**

```bash
git worktree add ../hybrid-libcrystals-wt -b hybrid-libcrystals-backend
```

Expected: `Preparing worktree (new branch 'hybrid-libcrystals-backend')` — no errors.

- [ ] **Step 3: Confirm worktree is ready**

```bash
ls ../hybrid-libcrystals-wt/hybrid/src/
```

Expected: the full list of ~20 source files is visible.

---

## Task 2: Rewrite CMakeLists.txt

**Files:**
- Modify: `hybrid/CMakeLists.txt` (in the worktree: `../hybrid-libcrystals-wt/hybrid/CMakeLists.txt`)

All path references below assume you are working **inside the worktree**:
```bash
cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals/hybrid-libcrystals-wt
```

- [ ] **Step 1: Replace CMakeLists.txt entirely**

Write this exact content to `hybrid/CMakeLists.txt`:

```cmake
cmake_minimum_required(VERSION 3.15)
project(hybrid LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Crystals REQUIRED HINTS /usr/local/lib/cmake/crystals)
find_package(OpenSSL REQUIRED)

# RPATH: TBB lives in a non-standard path (Crystals/local/).
# TBB::tbb is available transitively after find_package(Crystals) because
# CrystalsConfig.cmake runs find_package(TBB) internally with the baked-in hint.
get_target_property(_tbb_loc TBB::tbb IMPORTED_LOCATION_RELEASE)
if(NOT _tbb_loc)
    get_target_property(_tbb_loc TBB::tbb IMPORTED_LOCATION)
endif()
get_filename_component(_tbb_libdir "${_tbb_loc}" DIRECTORY)
# /usr/local/lib is included unconditionally so libXKCP.so resolves without
# requiring a prior ldconfig run (e.g. on a fresh session after install).
set(CMAKE_BUILD_RPATH "${_tbb_libdir}" /usr/local/lib)

add_executable(hybrid src/main.cpp)

target_link_libraries(hybrid PRIVATE
    Crystals::crystals
    OpenSSL::Crypto
)

target_compile_options(hybrid PRIVATE -O2 -Wall -Wextra)

install(TARGETS hybrid DESTINATION bin)
```

Key things removed vs. the old file:
- Both `add_subdirectory` calls (kyber/ref, dilithium/ref)
- `SCRYPT_SOURCES`, `SCRYPT_DIR`, `RANDOMBYTES_SRC`, `KYBER_REF_DIR` variables
- `find_package(yaml-cpp)` — provided transitively via `Crystals::crystals`
- `find_package(BLAKE3)` / `find_package(TBB)` — handled inside CrystalsConfig.cmake
- All 8 `pqcrystals_*` link targets
- `/usr/local/lib/libmceliece.a`, the 3 scrypt archives, `BLAKE3::blake3`
- All `target_include_directories` for kyber/ref, scrypt, `/usr/local/include`

- [ ] **Step 2: Verify the file looks right**

```bash
cat hybrid/CMakeLists.txt
```

Expected: ~30 lines total, no references to `add_subdirectory`, `SCRYPT`, `kyber`, `dilithium`, `mceliece.a`, `yaml-cpp`, or `BLAKE3` as top-level dependencies.

---

## Task 3: Rewrite main.cpp

**Files:**
- Modify: `hybrid/src/main.cpp`

The new `main.cpp` folds in the CLI-layer helper functions and `cmd_protect`/`cmd_unprotect` from the soon-to-be-deleted `secure_tray.cpp`. All crypto calls go through the library.

- [ ] **Step 1: Replace main.cpp entirely**

Write this exact content to `hybrid/src/main.cpp`:

```cpp
#include <crystals/crystals.hpp>
#include <openssl/ui.h>
#include <openssl/crypto.h>

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cmath>

// ── Usage ─────────────────────────────────────────────────────────────────────

static void print_usage(const char* prog) {
    std::cerr <<
        "Usage: " << prog << " keygen\n"
        "              --alias <name>\n"
        "              [--group crystals|mceliece+slhdsa]\n"
        "              [--profile <level>]\n"
        "              [--out <file>]\n"
        "              [--public]\n"
        "\n"
        "       " << prog << " protect   --in <file> --out <file> [--password-file <file>]\n"
        "       " << prog << " unprotect --in <file> --out <file> [--password-file <file>]\n"
        "\n"
        "  --alias       Name for this tray (required for keygen)\n"
        "  --group       Profile group (default: crystals)\n"
        "  --profile     Tray profile within group (see below)\n"
        "  --out <file>  Write YAML to file; auto-prints a human-readable summary to stdout\n"
        "  --public      Also emit a companion public tray (no secret keys)\n"
        "\n"
        "  protect:    Encrypt secret keys in a tray with a password → secure-tray YAML\n"
        "  unprotect:  Decrypt secret keys from a secure-tray back to a plain tray\n"
        "  --password-file: read password from first line of file (default: TTY prompt)\n"
        "\n"
        "Crystals group profiles (--group crystals, default):\n"
        "  level0       X25519 + Ed25519                           (classical-only)\n"
        "  level1       Kyber512 + Dilithium2                      (PQ-only)\n"
        "  level2-25519 X25519 + Kyber512 + Ed25519 + Dilithium2  (default)\n"
        "  level2       P-256  + Kyber512 + ECDSA P-256 + Dilithium2\n"
        "  level3       P-384  + Kyber768 + ECDSA P-384 + Dilithium3\n"
        "  level5       P-521  + Kyber1024 + ECDSA P-521 + Dilithium5\n"
        "\n"
        "McEliece+SLH-DSA group profiles (--group mceliece+slhdsa):\n"
        "  level1       mceliece348864f + SLH-DSA-SHA2-128f        (PQ-only)\n"
        "  level2       P-256 + mceliece460896f + ECDSA P-256 + SLH-DSA-SHA2-192f  (default)\n"
        "  level3       P-384 + mceliece6688128f + ECDSA P-384 + SLH-DSA-SHAKE-192f\n"
        "  level4       P-521 + mceliece6960119f + ECDSA P-521 + SLH-DSA-SHA2-256f\n"
        "  level5       P-256 + mceliece8192128f + ECDSA P-256 + SLH-DSA-SHAKE-256f\n"
        "\n"
        "Output (no --out): YAML to stdout. With --out: YAML to file + summary to stdout.\n"
        "With --public: companion public tray (alias <name>.pub) also emitted.\n";
}

// ── Helpers ───────────────────────────────────────────────────────────────────

static void print_summary(const Tray& tray) {
    std::cout << "Tray generated:\n"
              << "  alias:   " << tray.alias         << "\n"
              << "  profile: " << tray.type_str       << "\n"
              << "  id:      " << tray.id             << "\n"
              << "  created: " << tray.created      << "\n"
              << "  expires: " << tray.expires      << "\n"
              << "  slots:   " << tray.slots.size() << "\n";
    for (const auto& s : tray.slots) {
        std::cout << "    - " << s.alg_name
                  << "  pk=" << s.pk.size() << "B"
                  << "  sk=" << s.sk.size() << "B\n";
    }
}

// Insert ".pub" before the last extension, e.g. "alice.tray" → "alice.pub.tray".
// Falls back to path + ".pub" if no extension found.
static std::string derive_pub_filename(const std::string& path) {
    auto dot = path.rfind('.');
    if (dot == std::string::npos)
        return path + ".pub";
    return path.substr(0, dot) + ".pub" + path.substr(dot);
}

static int write_yaml_file(const Tray& tray, const std::string& path) {
    std::string yaml;
    try { yaml = emit_tray_yaml(tray); }
    catch (const std::exception& e) {
        std::cerr << "Error: YAML output failed: " << e.what() << "\n";
        return 3;
    }
    std::ofstream f(path);
    if (!f) { std::cerr << "Error: cannot open " << path << " for writing\n"; return 3; }
    f << yaml;
    return 0;
}

// ── Password helpers ───────────────────────────────────────────────────────────

static float shannon_entropy(const std::string& s) {
    if (s.empty()) return 0.0f;
    int freq[256] = {};
    for (unsigned char c : s) freq[(int)c]++;
    float H = 0.0f;
    float n = (float)s.size();
    for (int i = 0; i < 256; ++i) {
        if (freq[i] > 0) {
            float p = (float)freq[i] / n;
            H -= p * std::log2(p);
        }
    }
    return H;
}

static bool read_pwfile(const std::string& path, char* buf, int buflen) {
    std::ifstream f(path);
    if (!f) {
        std::cerr << "Error: cannot open password file: " << path << "\n";
        return false;
    }
    std::string line;
    std::getline(f, line);

    size_t start = 0;
    while (start < line.size() && (line[start] == ' ' || line[start] == '\t' ||
                                    line[start] == '\r' || line[start] == '\n'))
        ++start;

    size_t end = line.size();
    while (end > start && (line[end-1] == ' ' || line[end-1] == '\t' ||
                            line[end-1] == '\r' || line[end-1] == '\n'))
        --end;

    bool trimmed = (start > 0 || end < line.size());
    std::string pw = line.substr(start, end - start);

    if (trimmed)
        std::cerr << "Warning: leading/trailing whitespace stripped from password file\n";

    if ((int)pw.size() >= buflen) {
        std::cerr << "Error: password in file is too long\n";
        return false;
    }
    std::memcpy(buf, pw.data(), pw.size());
    buf[pw.size()] = '\0';
    return true;
}

static bool prompt_password_confirm(char* buf, int buflen) {
    char verify[256] = {};
    if (buflen > (int)sizeof(verify))
        buflen = (int)sizeof(verify);

    if (EVP_read_pw_string(buf, buflen, "Enter password: ", 0) != 0)
        return false;
    if (EVP_read_pw_string(verify, (int)sizeof(verify), "Confirm password: ", 0) != 0) {
        OPENSSL_cleanse(verify, sizeof(verify));
        return false;
    }
    bool match = (std::strcmp(buf, verify) == 0);
    OPENSSL_cleanse(verify, sizeof(verify));
    if (!match)
        std::cerr << "Error: passwords do not match\n";
    return match;
}

static bool prompt_password_once(char* buf, int buflen) {
    return EVP_read_pw_string(buf, buflen, "Enter password: ", 0) == 0;
}

static int check_password(const char* buf) {
    size_t len = std::strlen(buf);
    if (len < 3) {
        std::cerr << "Error: password must be at least 3 characters\n";
        return 1;
    }
    std::string s(buf, len);
    float total_bits = shannon_entropy(s) * (float)len;
    if (total_bits < 80.0f)
        std::cerr << "Warning: password has low entropy (" << total_bits
                  << " bits); consider using a stronger password\n";
    return 0;
}

// ── keygen command ────────────────────────────────────────────────────────────

static int cmd_keygen(int argc, char* argv[]) {
    std::string alias;
    std::string group_str = "crystals";
    std::string tray_str;
    std::string out_file;
    bool pub_flag = false;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--alias") == 0) {
            if (++i >= argc) { std::cerr << "Error: --alias requires a value\n"; return 1; }
            alias = argv[i];
        } else if (std::strcmp(argv[i], "--group") == 0) {
            if (++i >= argc) { std::cerr << "Error: --group requires a value\n"; return 1; }
            group_str = argv[i];
        } else if (std::strcmp(argv[i], "--profile") == 0) {
            if (++i >= argc) { std::cerr << "Error: --profile requires a value\n"; return 1; }
            tray_str = argv[i];
        } else if (std::strcmp(argv[i], "--out") == 0) {
            if (++i >= argc) { std::cerr << "Error: --out requires a filename\n"; return 1; }
            out_file = argv[i];
        } else if (std::strcmp(argv[i], "--public") == 0) {
            pub_flag = true;
        } else {
            std::cerr << "Error: unknown option: " << argv[i] << "\n";
            return 1;
        }
    }

    if (alias.empty()) {
        std::cerr << "Error: --alias is required\n";
        return 1;
    }

    if (group_str != "crystals" && group_str != "mceliece+slhdsa") {
        std::cerr << "Error: unknown group '" << group_str
                  << "' (must be crystals or mceliece+slhdsa)\n";
        return 1;
    }

    if (tray_str.empty()) {
        tray_str = (group_str == "mceliece+slhdsa") ? "level2" : "level2-25519";
    }

    TrayType ttype;
    if (group_str == "crystals") {
        if      (tray_str == "level0")       ttype = TrayType::Level0;
        else if (tray_str == "level1")       ttype = TrayType::Level1;
        else if (tray_str == "level2-25519") ttype = TrayType::Level2_25519;
        else if (tray_str == "level2")       ttype = TrayType::Level2;
        else if (tray_str == "level3")       ttype = TrayType::Level3;
        else if (tray_str == "level5")       ttype = TrayType::Level5;
        else {
            std::cerr << "Error: unknown profile '" << tray_str
                      << "' for group crystals"
                         " (must be level0, level1, level2-25519, level2, level3, or level5)\n";
            return 1;
        }
    } else {
        if      (tray_str == "level1") ttype = TrayType::McEliece_Level1;
        else if (tray_str == "level2") ttype = TrayType::McEliece_Level2;
        else if (tray_str == "level3") ttype = TrayType::McEliece_Level3;
        else if (tray_str == "level4") ttype = TrayType::McEliece_Level4;
        else if (tray_str == "level5") ttype = TrayType::McEliece_Level5;
        else {
            std::cerr << "Error: unknown profile '" << tray_str
                      << "' for group mceliece+slhdsa"
                         " (must be level1, level2, level3, level4, or level5)\n";
            return 1;
        }
    }

    Tray tray;
    try {
        tray = make_tray(ttype, alias);
    } catch (const std::exception& e) {
        std::cerr << "Error: crypto failure: " << e.what() << "\n";
        return 2;
    }

    Tray pub_tray;
    if (pub_flag) {
        try {
            pub_tray = make_public_tray(tray);
        } catch (const std::exception& e) {
            std::cerr << "Error: public tray generation failed: " << e.what() << "\n";
            return 2;
        }
    }

    if (!out_file.empty()) {
        if (int rc = write_yaml_file(tray, out_file)) return rc;
        if (pub_flag) {
            if (int rc = write_yaml_file(pub_tray, derive_pub_filename(out_file))) return rc;
        }
        print_summary(tray);
        if (pub_flag) print_summary(pub_tray);
    } else {
        try {
            std::cout << emit_tray_yaml(tray);
        } catch (const std::exception& e) {
            std::cerr << "Error: YAML output failed: " << e.what() << "\n";
            return 3;
        }
        if (pub_flag) {
            try {
                std::cout << emit_tray_yaml(pub_tray);
            } catch (const std::exception& e) {
                std::cerr << "Error: YAML output failed: " << e.what() << "\n";
                return 3;
            }
        }
    }

    return 0;
}

// ── protect command ────────────────────────────────────────────────────────────

int cmd_protect(int argc, char* argv[]) {
    std::string in_path, out_path, pw_file;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--in") == 0) {
            if (++i >= argc) { std::cerr << "Error: --in requires a value\n"; return 1; }
            in_path = argv[i];
        } else if (std::strcmp(argv[i], "--out") == 0) {
            if (++i >= argc) { std::cerr << "Error: --out requires a value\n"; return 1; }
            out_path = argv[i];
        } else if (std::strcmp(argv[i], "--password-file") == 0) {
            if (++i >= argc) { std::cerr << "Error: --password-file requires a value\n"; return 1; }
            pw_file = argv[i];
        } else {
            std::cerr << "Error: unknown option: " << argv[i] << "\n";
            return 1;
        }
    }

    if (in_path.empty())  { std::cerr << "Error: --in is required\n";  return 1; }
    if (out_path.empty()) { std::cerr << "Error: --out is required\n"; return 1; }

    char pw_buf[256] = {};

    if (!pw_file.empty()) {
        if (!read_pwfile(pw_file, pw_buf, sizeof(pw_buf))) return 1;
    } else {
        if (!prompt_password_confirm(pw_buf, sizeof(pw_buf))) {
            std::cerr << "Error: password prompt failed\n";
            OPENSSL_cleanse(pw_buf, sizeof(pw_buf));
            return 1;
        }
    }

    int pw_rc = check_password(pw_buf);
    if (pw_rc != 0) {
        OPENSSL_cleanse(pw_buf, sizeof(pw_buf));
        return pw_rc;
    }

    Tray tray;
    try {
        tray = load_tray_yaml(in_path);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        OPENSSL_cleanse(pw_buf, sizeof(pw_buf));
        return 1;
    }

    bool has_sk = false;
    for (const auto& s : tray.slots)
        if (!s.sk.empty()) { has_sk = true; break; }
    if (!has_sk) {
        std::cerr << "Error: tray has no secret keys — cannot protect a public tray\n";
        OPENSSL_cleanse(pw_buf, sizeof(pw_buf));
        return 1;
    }

    SecureTray st;
    try {
        st = protect_tray(tray, pw_buf, std::strlen(pw_buf));
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        OPENSSL_cleanse(pw_buf, sizeof(pw_buf));
        return 2;
    }

    OPENSSL_cleanse(pw_buf, sizeof(pw_buf));

    std::string yaml;
    try {
        yaml = emit_secure_tray_yaml(st);
    } catch (const std::exception& e) {
        std::cerr << "Error: YAML output failed: " << e.what() << "\n";
        return 3;
    }

    std::ofstream f(out_path);
    if (!f) {
        std::cerr << "Error: cannot open " << out_path << " for writing\n";
        return 3;
    }
    f << yaml;
    return 0;
}

// ── unprotect command ──────────────────────────────────────────────────────────

int cmd_unprotect(int argc, char* argv[]) {
    std::string in_path, out_path, pw_file;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--in") == 0) {
            if (++i >= argc) { std::cerr << "Error: --in requires a value\n"; return 1; }
            in_path = argv[i];
        } else if (std::strcmp(argv[i], "--out") == 0) {
            if (++i >= argc) { std::cerr << "Error: --out requires a value\n"; return 1; }
            out_path = argv[i];
        } else if (std::strcmp(argv[i], "--password-file") == 0) {
            if (++i >= argc) { std::cerr << "Error: --password-file requires a value\n"; return 1; }
            pw_file = argv[i];
        } else {
            std::cerr << "Error: unknown option: " << argv[i] << "\n";
            return 1;
        }
    }

    if (in_path.empty())  { std::cerr << "Error: --in is required\n";  return 1; }
    if (out_path.empty()) { std::cerr << "Error: --out is required\n"; return 1; }

    char pw_buf[256] = {};

    if (!pw_file.empty()) {
        if (!read_pwfile(pw_file, pw_buf, sizeof(pw_buf))) return 1;
    } else {
        if (!prompt_password_once(pw_buf, sizeof(pw_buf))) {
            std::cerr << "Error: password prompt failed\n";
            OPENSSL_cleanse(pw_buf, sizeof(pw_buf));
            return 1;
        }
    }

    int pw_rc = check_password(pw_buf);
    if (pw_rc != 0) {
        OPENSSL_cleanse(pw_buf, sizeof(pw_buf));
        return pw_rc;
    }

    SecureTray st;
    try {
        st = load_secure_tray_yaml(in_path);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        OPENSSL_cleanse(pw_buf, sizeof(pw_buf));
        return 1;
    }

    Tray tray;
    try {
        tray = unprotect_tray(st, pw_buf, std::strlen(pw_buf));
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        OPENSSL_cleanse(pw_buf, sizeof(pw_buf));
        return 2;
    }

    OPENSSL_cleanse(pw_buf, sizeof(pw_buf));

    std::string yaml;
    try {
        yaml = emit_tray_yaml(tray);
    } catch (const std::exception& e) {
        std::cerr << "Error: YAML output failed: " << e.what() << "\n";
        return 3;
    }

    std::ofstream f(out_path);
    if (!f) {
        std::cerr << "Error: cannot open " << out_path << " for writing\n";
        return 3;
    }
    f << yaml;
    return 0;
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "keygen") {
        return cmd_keygen(argc - 1, argv + 1);
    }

    if (cmd == "protect") {
        return cmd_protect(argc - 1, argv + 1);
    }

    if (cmd == "unprotect") {
        return cmd_unprotect(argc - 1, argv + 1);
    }

    if (cmd == "--help" || cmd == "-h") {
        print_usage(argv[0]);
        return 0;
    }

    std::cerr << "Error: unknown command '" << cmd << "'\n";
    print_usage(argv[0]);
    return 1;
}
```

- [ ] **Step 2: Count the lines to sanity-check**

```bash
wc -l hybrid/src/main.cpp
```

Expected: ~640 lines. If dramatically different, recheck the write.

---

## Task 4: First build (compilation test)

**Files:**
- No file changes — build only

Do this from inside the worktree directory.

- [ ] **Step 1: Wipe any stale build dir and configure fresh**

```bash
rm -rf hybrid/build
cmake -S hybrid -B hybrid/build
```

Expected: CMake configure output ends with `-- Build files have been written to: .../hybrid/build`. You should see `found Crystals` or similar. You should NOT see errors about missing TBB, BLAKE3, kyber, or dilithium.

If configure fails with "Could not find Crystals":
- Verify libcrystals is installed: `ls /usr/local/lib/cmake/crystals/CrystalsConfig.cmake`
- If the file is missing, libcrystals-1.1 needs to be installed first:
  ```bash
  cd /mnt/c/Users/daves/OneDrive/Desktop/Crystals
  sudo pq/libcrystals-1.1/install.sh --prefix /usr/local
  ```

- [ ] **Step 2: Build**

```bash
cmake --build hybrid/build -j$(nproc)
```

Expected: Compiles only `main.cpp`. Should produce the binary at `hybrid/build/hybrid`.
No warnings about undefined references. No "implicit declaration" warnings.

If you get `error: 'EVP_read_pw_string' undeclared`: add `#include <openssl/evp.h>` to main.cpp — some OpenSSL configurations put this function's declaration there rather than in `ui.h`.

- [ ] **Step 3: Confirm binary exists**

```bash
ls -lh hybrid/build/hybrid
```

Expected: binary present, size in the MB range (libcrystals is statically linked).

---

## Task 5: Smoke test (quick sanity check before cleanup)

**Files:**
- No changes — testing only

- [ ] **Step 1: Basic keygen smoke test**

```bash
hybrid/build/hybrid keygen --alias smoketest --profile level2-25519
```

Expected: Valid YAML to stdout with `alias: smoketest`, 4 slots (X25519, Kyber512, Ed25519, Dilithium2).

- [ ] **Step 2: Protect / unprotect roundtrip smoke test**

```bash
hybrid/build/hybrid keygen --alias smoketest --out /tmp/smoke.tray
echo "smokepass99" > /tmp/smoke_pw.txt
hybrid/build/hybrid protect --in /tmp/smoke.tray --out /tmp/smoke.sec.tray --password-file /tmp/smoke_pw.txt
hybrid/build/hybrid unprotect --in /tmp/smoke.sec.tray --out /tmp/smoke.plain.tray --password-file /tmp/smoke_pw.txt
diff /tmp/smoke.tray /tmp/smoke.plain.tray
```

Expected: `diff` exits 0 (files identical).

---

## Task 6: Delete the 21 superseded source files

**Files:**
- Delete all 21 files listed below from `hybrid/src/`

- [ ] **Step 1: Delete all superseded files**

```bash
rm hybrid/src/base64.cpp hybrid/src/base64.hpp \
   hybrid/src/ec_ops.cpp hybrid/src/ec_ops.hpp \
   hybrid/src/kyber_ops.cpp hybrid/src/kyber_ops.hpp \
   hybrid/src/kyber_api.hpp \
   hybrid/src/dilithium_ops.cpp hybrid/src/dilithium_ops.hpp \
   hybrid/src/dilithium_api.hpp \
   hybrid/src/mceliece_ops.cpp hybrid/src/mceliece_ops.hpp \
   hybrid/src/slhdsa_ops.cpp hybrid/src/slhdsa_ops.hpp \
   hybrid/src/mceliece_randombytes.c \
   hybrid/src/tray.cpp \
   hybrid/src/yaml_io.cpp hybrid/src/yaml_io.hpp \
   hybrid/src/secure_tray.cpp hybrid/src/secure_tray.hpp \
   hybrid/src/symmetric.hpp
```

- [ ] **Step 2: Confirm only main.cpp remains**

```bash
ls hybrid/src/
```

Expected: only `main.cpp`.

- [ ] **Step 3: Rebuild to confirm nothing was accidentally depended on**

```bash
cmake --build hybrid/build -j$(nproc)
```

Expected: clean build, same binary. (CMake will just relink since no .cpp changed.)

---

## Task 7: Full verification

**Files:**
- No changes — final verification only

- [ ] **Step 1: All 6 crystals profiles**

```bash
SCOTTY=hybrid/build/hybrid
$SCOTTY keygen --alias alice --profile level2-25519
$SCOTTY keygen --alias alice --profile level0
$SCOTTY keygen --alias alice --profile level1
$SCOTTY keygen --alias alice --profile level2
$SCOTTY keygen --alias alice --profile level3
$SCOTTY keygen --alias alice --profile level5
```

Expected: each produces valid YAML to stdout. level0 and level1 have 2 slots; level2-25519, level2 have 4 slots; level3 has 4 slots; level5 has 4 slots.

- [ ] **Step 2: All 5 mceliece+slhdsa profiles**

```bash
$SCOTTY keygen --group mceliece+slhdsa --alias alice --profile level1
$SCOTTY keygen --group mceliece+slhdsa --alias alice --profile level2
$SCOTTY keygen --group mceliece+slhdsa --alias alice --profile level3
$SCOTTY keygen --group mceliece+slhdsa --alias alice --profile level4
$SCOTTY keygen --group mceliece+slhdsa --alias alice --profile level5
```

Expected: valid YAML. level1 has 2 slots; level2–5 have 4 slots.

- [ ] **Step 3: --out and --public**

```bash
$SCOTTY keygen --alias alice --out /tmp/alice.tray
cat /tmp/alice.tray   # confirm YAML on disk
$SCOTTY keygen --alias alice --public --out /tmp/alice2.tray
ls /tmp/alice2.tray /tmp/alice2.pub.tray   # both files must exist
```

- [ ] **Step 4: protect / unprotect full roundtrip**

```bash
$SCOTTY keygen --alias alice --out /tmp/alice.tray
echo "testpass123" > /tmp/pw.txt
$SCOTTY protect   --in /tmp/alice.tray     --out /tmp/alice.sec.tray  --password-file /tmp/pw.txt
$SCOTTY unprotect --in /tmp/alice.sec.tray --out /tmp/alice.plain.tray --password-file /tmp/pw.txt
diff /tmp/alice.tray /tmp/alice.plain.tray
```

Expected: `diff` exits 0.

- [ ] **Step 5: Error cases**

```bash
$SCOTTY keygen; echo "exit: $?"                                         # → exit 1
$SCOTTY keygen --alias x --group bad; echo "exit: $?"                   # → exit 1
echo "wrong" > /tmp/wrong.txt
$SCOTTY unprotect --in /tmp/alice.sec.tray --out /tmp/x.tray \
        --password-file /tmp/wrong.txt; echo "exit: $?"                 # → exit 2
```

- [ ] **Step 6: Verify binary has correct RPATH (no LD_LIBRARY_PATH needed)**

```bash
ldd hybrid/build/hybrid | grep -E "tbb|XKCP|not found"
```

Expected: `libtbb.so` resolves to a path (not "not found"). `libXKCP.so` resolves (likely via `/usr/local/lib`). No "not found" entries.

---

## Task 8: Commit

**Files:**
- All changes committed on `hybrid-libcrystals-backend` branch

- [ ] **Step 1: Stage all changes**

```bash
git add hybrid/CMakeLists.txt hybrid/src/main.cpp
git rm hybrid/src/base64.cpp hybrid/src/base64.hpp \
       hybrid/src/ec_ops.cpp hybrid/src/ec_ops.hpp \
       hybrid/src/kyber_ops.cpp hybrid/src/kyber_ops.hpp \
       hybrid/src/kyber_api.hpp \
       hybrid/src/dilithium_ops.cpp hybrid/src/dilithium_ops.hpp \
       hybrid/src/dilithium_api.hpp \
       hybrid/src/mceliece_ops.cpp hybrid/src/mceliece_ops.hpp \
       hybrid/src/slhdsa_ops.cpp hybrid/src/slhdsa_ops.hpp \
       hybrid/src/mceliece_randombytes.c \
       hybrid/src/tray.cpp \
       hybrid/src/yaml_io.cpp hybrid/src/yaml_io.hpp \
       hybrid/src/secure_tray.cpp hybrid/src/secure_tray.hpp \
       hybrid/src/symmetric.hpp
```

- [ ] **Step 2: Verify staged changes look right**

```bash
git status
git diff --staged --stat
```

Expected: 2 files modified (`CMakeLists.txt`, `main.cpp`), 21 files deleted.

- [ ] **Step 3: Commit**

```bash
git commit -m "$(cat <<'EOF'
refactor(hybrid): migrate to libcrystals-1.1 backend

Replace all private crypto, YAML I/O, and tray logic with calls to
Crystals::crystals. hybrid/src/ now contains only main.cpp. CMakeLists.txt
is replaced by find_package(Crystals) + a single target_link_libraries call.

21 source files deleted; cmd_protect/cmd_unprotect (pure CLI handlers) folded
into main.cpp. No changes to CLI interface, exit codes, or YAML wire format.
EOF
)"
```

---

## Notes for the Implementer

**libcrystals must be installed before Task 4.** Verify with:
```bash
ls /usr/local/lib/cmake/crystals/CrystalsConfig.cmake
ls /usr/local/lib/libcrystals-1.1.a
```

**All paths in Tasks 2–8 assume you are in the worktree root** (`hybrid-libcrystals-wt/`), not the main `pq/` checkout.

**If the build fails with TBB not found:** This means `CrystalsConfig.cmake` couldn't locate TBB at its baked-in path. Run `cat /usr/local/lib/cmake/crystals/CrystalsConfig.cmake` and look for the TBB hint path — it should point to `Crystals/local/lib/cmake/TBB`. If that directory is missing, TBB needs to be rebuilt from source (see `Crystals/oneTBB`).

**zorro will follow the same pattern** in a subsequent migration. The discipline going forward: all new crypto functionality goes into libcrystals-1.1 first, then is called from the application.
