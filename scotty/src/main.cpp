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
        "              [--group crystals|mceliece+slhdsa|mlkem+mldsa|frodokem+falcon]\n"
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
        "ML-KEM+ML-DSA group profiles (--group mlkem+mldsa):\n"
        "  level1       ML-KEM-512 + ML-DSA-44                            (PQ-only)\n"
        "  level2       P-256 + ML-KEM-512 + ECDSA P-256 + ML-DSA-44     (default)\n"
        "  level3       P-384 + ML-KEM-768 + ECDSA P-384 + ML-DSA-65\n"
        "  level4       P-521 + ML-KEM-1024 + ECDSA P-521 + ML-DSA-87\n"
        "\n"
        "FrodoKEM+Falcon group profiles (--group frodokem+falcon):\n"
        "  level1       FrodoKEM-640-AES + Falcon-512                        (PQ-only)\n"
        "  level2       P-256 + FrodoKEM-640-AES + ECDSA P-256 + Falcon-512  (default)\n"
        "  level3       P-384 + FrodoKEM-976-AES + ECDSA P-384 + Falcon-512\n"
        "  level4       P-521 + FrodoKEM-1344-AES + ECDSA P-521 + Falcon-1024\n"
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

    if (group_str != "crystals" && group_str != "mceliece+slhdsa" &&
        group_str != "mlkem+mldsa" && group_str != "frodokem+falcon") {
        std::cerr << "Error: unknown group '" << group_str
                  << "' (must be crystals, mceliece+slhdsa, mlkem+mldsa, or frodokem+falcon)\n";
        return 1;
    }

    if (tray_str.empty()) {
        if (group_str == "crystals")
            tray_str = "level2-25519";
        else
            tray_str = "level2";  // default for mceliece+slhdsa, mlkem+mldsa, frodokem+falcon
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
    } else if (group_str == "mceliece+slhdsa") {
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
    } else if (group_str == "mlkem+mldsa") {
        if      (tray_str == "level1") ttype = TrayType::MlKem_Level1;
        else if (tray_str == "level2") ttype = TrayType::MlKem_Level2;
        else if (tray_str == "level3") ttype = TrayType::MlKem_Level3;
        else if (tray_str == "level4") ttype = TrayType::MlKem_Level4;
        else {
            std::cerr << "Error: unknown profile '" << tray_str
                      << "' for group mlkem+mldsa"
                         " (must be level1, level2, level3, or level4)\n";
            return 1;
        }
    } else if (group_str == "frodokem+falcon") {
        if      (tray_str == "level1") ttype = TrayType::FrodoFalcon_Level1;
        else if (tray_str == "level2") ttype = TrayType::FrodoFalcon_Level2;
        else if (tray_str == "level3") ttype = TrayType::FrodoFalcon_Level3;
        else if (tray_str == "level4") ttype = TrayType::FrodoFalcon_Level4;
        else {
            std::cerr << "Error: unknown profile '" << tray_str
                      << "' for group frodokem+falcon"
                         " (must be level1, level2, level3, or level4)\n";
            return 1;
        }
    } else {
		 std::cerr << "Error: unknown profile group '" << group_str << "'\n";
            return 1;
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

static int cmd_protect(int argc, char* argv[]) {
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
        return 3;
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

static int cmd_unprotect(int argc, char* argv[]) {
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
        return 3;
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
