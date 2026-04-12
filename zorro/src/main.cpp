#include <crystals/crystals.hpp>

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <stdexcept>
#include <openssl/rand.h>
#include <cstdio>

// ── Usage ─────────────────────────────────────────────────────────────────────

static void print_usage(const char* prog) {
    std::cerr <<
        "Usage:\n"
        "  " << prog << " encrypt --tray <file> [--kdf SHAKE|KMAC] [--cipher AES-256-GCM|ChaCha20] <target-file>\n"
        "  " << prog << " decrypt --tray <file> <target-file>\n"
        "  " << prog << " encrypt+sign --tray <file> <target-file>\n"
        "  " << prog << " verify+decrypt --tray <file> <target-file>\n"
        "  " << prog << " sign    --tray <file> --in-file <file>\n"
        "  " << prog << " verify  --tray <file> --in-file <file> --in-sig <file>\n"
        "  " << prog << " gentok  --tray <file> --data <string> [--ttl <seconds>]\n"
        "  " << prog << " valtok  --tray <file> [token-file]\n"
        "  " << prog << " pwencrypt [--level 512|768|1024] [--scrypt-n 20] [--pwfile <file>] <infile> <outfile>\n"
        "  " << prog << " pwdecrypt [--pwfile <file>] <infile> <outfile>\n"
        "\n"
        "  --tray   Tray file (YAML)\n"
        "  --kdf    Key derivation function (encrypt only): SHAKE (default) or KMAC\n"
        "  --cipher Symmetric cipher (encrypt only): AES-256-GCM (default) or ChaCha20\n"
        "  --data   Token payload string (gentok only, 1–256 bytes)\n"
        "  --ttl    Token lifetime in seconds (gentok only, default 86400)\n"
        "\n"
        "  encrypt:   reads <target-file>, writes OBIWAN armored ciphertext to stdout\n"
        "  decrypt:   reads armored <target-file>, writes plaintext to stdout\n"
        "  encrypt+sign: encrypt-and-sign using all 4 tray slots; writes HYKE armor to stdout\n"
        "  verify+decrypt: verify both signatures and decrypt HYKE file; writes plaintext to stdout\n"
        "  sign:      hybrid digital signature (no encryption); writes sig YAML to stdout\n"
        "  verify:    verify hybrid composite signature; writes verification YAML to stdout\n"
        "  gentok:    generate a signed token; requires level2 tray; writes armor to stdout\n"
        "  valtok:    validate a token; writes data to stdout; reads stdin if no file given\n"
        "  pwencrypt: password-based encryption (ephemeral Kyber + scrypt); no tray required\n"
        "  pwdecrypt: decrypt a pwencrypt file\n"
        "\n"
        "Exit codes: 0=ok, 1=usage, 2=crypto, 3=I/O\n";
}

// ── File reading ──────────────────────────────────────────────────────────────

static std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        throw std::runtime_error("Cannot open file: " + path);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
}

static std::string read_file_text(const std::string& path) {
    std::ifstream f(path);
    if (!f)
        throw std::runtime_error("Cannot open file: " + path);
    return std::string((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
}

// ── Slot selection ────────────────────────────────────────────────────────────

// Find the first classical KEM slot (X25519 or P-xxx)
static const Slot* find_classical_slot(const Tray& tray) {
    for (const auto& s : tray.slots) {
        if (ec_kem::is_classical_kem(s.alg_name))
            return &s;
    }
    return nullptr;
}

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

// Find the first classical signature slot (Ed25519 or ECDSA P-*)
static const Slot* find_classical_sig_slot(const Tray& tray) {
    for (const auto& s : tray.slots) {
        if (ec_sig::is_classical_sig(s.alg_name))
            return &s;
    }
    return nullptr;
}

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

// ── Pure-sig helpers ──────────────────────────────────────────────────────────

static std::array<uint8_t, 32> sha256_bytes(const std::vector<uint8_t>& data) {
    std::array<uint8_t, 32> digest{};
    unsigned int len = 32;
    if (!EVP_Digest(data.data(), data.size(), digest.data(), &len, EVP_sha256(), nullptr))
        throw std::runtime_error("SHA-256 failed");
    return digest;
}

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


// ── encrypt command ───────────────────────────────────────────────────────────

static int cmd_encrypt(const std::string& tray_path,
                        const std::string& target_path,
                        KDFAlg kdf_alg,
                        CipherAlg cipher_alg)
{
    // Load tray
    Tray tray;
    try {
        tray = load_tray(tray_path);
    } catch (const std::exception& e) {
        std::cerr << "Error: cannot load tray: " << e.what() << "\n";
        return 3;
    }

    const Slot* cl_slot = find_classical_slot(tray);
    const Slot* pq_slot = find_pq_slot(tray);

    if (!cl_slot || !pq_slot) {
        std::cerr << "Error: tray must contain both a classical KEM slot and a PQ KEM slot\n";
        return 1;
    }

    // Read plaintext
    std::vector<uint8_t> plaintext;
    try {
        plaintext = read_file(target_path);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 3;
    }

    // Classical KEM encaps
    std::vector<uint8_t> ct_classical, ss_classical;
    try {
        ec_kem::encaps(cl_slot->alg_name, cl_slot->pk, ct_classical, ss_classical);
    } catch (const std::exception& e) {
        std::cerr << "Error: classical KEM encaps failed: " << e.what() << "\n";
        return 2;
    }

    // PQ KEM encaps
    std::vector<uint8_t> ct_pq, ss_pq;
    try {
        if (pq_slot->alg_name.substr(0, 5) == "Kyber") {
            kyber_kem::encaps(kyber_kem::level_from_alg(pq_slot->alg_name), pq_slot->pk, ct_pq, ss_pq);
        } else if (oqs_kem::is_oqs_kem(pq_slot->alg_name)) {
            oqs_kem::encaps(pq_slot->alg_name, pq_slot->pk, ct_pq, ss_pq);
        } else {
            mceliece_kem::encaps(pq_slot->alg_name, pq_slot->pk, ct_pq, ss_pq);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: PQ KEM encaps failed: " << e.what() << "\n";
        return 2;
    }

    // KDF
    std::array<uint8_t, 32> key;
    try {
        if (kdf_alg == KDFAlg::SHAKE256)
            key = derive_key_shake(ss_classical, ss_pq, ct_classical, ct_pq);
        else
            key = derive_key_kmac(ss_classical, ss_pq, ct_classical, ct_pq);
    } catch (const std::exception& e) {
        std::cerr << "Error: KDF failed: " << e.what() << "\n";
        return 2;
    }

    // Symmetric encrypt
    std::vector<uint8_t> payload;
    try {
        if (cipher_alg == CipherAlg::AES256GCM)
            payload = aes256gcm_encrypt(key.data(), plaintext);
        else
            payload = chacha20poly1305_encrypt(key.data(), plaintext);
    } catch (const std::exception& e) {
        std::cerr << "Error: encryption failed: " << e.what() << "\n";
        return 2;
    }

    // Armor and output
    WireHeader hdr;
    hdr.kdf          = kdf_alg;
    hdr.cipher       = cipher_alg;
    hdr.ct_classical = std::move(ct_classical);
    hdr.ct_pq        = std::move(ct_pq);

    std::cout << armor_pack(hdr, payload);
    return 0;
}

// ── decrypt command ───────────────────────────────────────────────────────────

static int cmd_decrypt(const std::string& tray_path,
                        const std::string& target_path)
{
    // Load tray
    Tray tray;
    try {
        tray = load_tray(tray_path);
    } catch (const std::exception& e) {
        std::cerr << "Error: cannot load tray: " << e.what() << "\n";
        return 3;
    }

    const Slot* cl_slot = find_classical_slot(tray);
    const Slot* pq_slot = find_pq_slot(tray);

    if (!cl_slot || !pq_slot) {
        std::cerr << "Error: tray must contain both a classical KEM slot and a PQ KEM slot\n";
        return 1;
    }
    if (cl_slot->sk.empty() || pq_slot->sk.empty()) {
        std::cerr << "Error: tray secret keys required for decryption\n";
        return 1;
    }

    // Read armored ciphertext
    std::string armored;
    try {
        armored = read_file_text(target_path);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 3;
    }

    // Unpack
    std::vector<uint8_t> payload;
    WireHeader hdr;
    try {
        hdr = armor_unpack(armored, payload);
    } catch (const std::exception& e) {
        std::cerr << "Error: failed to parse ciphertext: " << e.what() << "\n";
        return 3;
    }

    // Classical KEM decaps
    std::vector<uint8_t> ss_classical;
    try {
        ec_kem::decaps(cl_slot->alg_name, cl_slot->sk, hdr.ct_classical, ss_classical);
    } catch (const std::exception& e) {
        std::cerr << "Error: classical KEM decaps failed: " << e.what() << "\n";
        return 2;
    }

    // PQ KEM decaps
    std::vector<uint8_t> ss_pq;
    try {
        if (pq_slot->alg_name.substr(0, 5) == "Kyber") {
            kyber_kem::decaps(kyber_kem::level_from_alg(pq_slot->alg_name), pq_slot->sk, hdr.ct_pq, ss_pq);
        } else if (oqs_kem::is_oqs_kem(pq_slot->alg_name)) {
            oqs_kem::decaps(pq_slot->alg_name, pq_slot->sk, hdr.ct_pq, ss_pq);
        } else {
            mceliece_kem::decaps(pq_slot->alg_name, pq_slot->sk, hdr.ct_pq, ss_pq);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: PQ KEM decaps failed: " << e.what() << "\n";
        return 2;
    }

    // KDF
    std::array<uint8_t, 32> key;
    try {
        if (hdr.kdf == KDFAlg::SHAKE256)
            key = derive_key_shake(ss_classical, ss_pq, hdr.ct_classical, hdr.ct_pq);
        else
            key = derive_key_kmac(ss_classical, ss_pq, hdr.ct_classical, hdr.ct_pq);
    } catch (const std::exception& e) {
        std::cerr << "Error: KDF failed: " << e.what() << "\n";
        return 2;
    }

    // Symmetric decrypt
    std::vector<uint8_t> plaintext;
    try {
        if (hdr.cipher == CipherAlg::AES256GCM)
            plaintext = aes256gcm_decrypt(key.data(), payload);
        else
            plaintext = chacha20poly1305_decrypt(key.data(), payload);
    } catch (const std::exception& e) {
        std::cerr << "Error: decryption/authentication failed: " << e.what() << "\n";
        return 2;
    }

    // Output plaintext
    std::cout.write((const char*)plaintext.data(), (std::streamsize)plaintext.size());
    return 0;
}

// ── encrypt+sign command ─────────────────────────────────────────────────────

static int cmd_encrypt_sign(const std::string& tray_path,
                              const std::string& target_path)
{
    // Load tray
    Tray tray;
    try {
        tray = load_tray(tray_path);
    } catch (const std::exception& e) {
        std::cerr << "Error: cannot load tray: " << e.what() << "\n";
        return 3;
    }

    if (!is_tray_complete(tray.tray_type)) {
        std::cerr << "Error: " << tray.profile_group << " "
                  << tray_type_to_profile(tray.tray_type)
                  << " is a partial tray and cannot be used for HYKE"
                  << " — a full 4-slot tray (classical + PQ KEM and sig) is required\n";
        return 1;
    }

    const Slot* cl_kem = find_classical_slot(tray);
    const Slot* pq_kem = find_pq_slot(tray);
    const Slot* cl_sig = find_classical_sig_slot(tray);
    const Slot* pq_sig = find_pq_sig_slot(tray);

    if (!cl_kem || !pq_kem || !cl_sig || !pq_sig) {
        std::cerr << "Error: tray must contain all 4 slots (KEM-classical, KEM-PQ, Sig-classical, Sig-PQ) for sign\n";
        return 1;
    }
    if (cl_sig->sk.empty() || pq_sig->sk.empty()) {
        std::cerr << "Error: tray signing secret keys (Sig-classical and Sig-PQ) are required for sign\n";
        return 1;
    }

    // Read plaintext
    std::vector<uint8_t> plaintext;
    try {
        plaintext = read_file(target_path);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 3;
    }

    // Classical KEM encaps
    std::vector<uint8_t> ct_classical, ss_classical;
    try {
        ec_kem::encaps(cl_kem->alg_name, cl_kem->pk, ct_classical, ss_classical);
    } catch (const std::exception& e) {
        std::cerr << "Error: classical KEM encaps failed: " << e.what() << "\n";
        return 2;
    }

    // PQ KEM encaps
    std::vector<uint8_t> ct_pq, ss_pq;
    try {
        if (pq_kem->alg_name.substr(0, 5) == "Kyber") {
            kyber_kem::encaps(kyber_kem::level_from_alg(pq_kem->alg_name), pq_kem->pk, ct_pq, ss_pq);
        } else if (oqs_kem::is_oqs_kem(pq_kem->alg_name)) {
            oqs_kem::encaps(pq_kem->alg_name, pq_kem->pk, ct_pq, ss_pq);
        } else {
            mceliece_kem::encaps(pq_kem->alg_name, pq_kem->pk, ct_pq, ss_pq);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: PQ KEM encaps failed: " << e.what() << "\n";
        return 2;
    }

    // Generate 32-byte random salt
    uint8_t salt[32];
    if (RAND_bytes(salt, 32) != 1) {
        std::cerr << "Error: RAND_bytes failed\n";
        return 2;
    }

    // HYKE KMAC KDF → symmetric key
    std::array<uint8_t, 32> sym_key;
    try {
        sym_key = derive_key_hyke(ss_classical, ss_pq, ct_classical, ct_pq, salt);
    } catch (const std::exception& e) {
        std::cerr << "Error: HYKE KDF failed: " << e.what() << "\n";
        return 2;
    }

    // AES-256-GCM encrypt
    std::vector<uint8_t> encrypted_payload;
    try {
        encrypted_payload = aes256gcm_encrypt(sym_key.data(), plaintext);
    } catch (const std::exception& e) {
        std::cerr << "Error: encryption failed: " << e.what() << "\n";
        return 2;
    }

    // Build HykeHeader (CTs populated; sigs filled in later)
    HykeHeader hdr;
    hdr.tray_id = tray_id_byte(tray.tray_type);
    try {
        parse_uuid(tray.id, hdr.tray_uuid);
    } catch (const std::exception& e) {
        std::cerr << "Error: failed to parse tray UUID: " << e.what() << "\n";
        return 2;
    }
    std::memcpy(hdr.salt, salt, 32);
    hdr.ct_classical = std::move(ct_classical);
    hdr.ct_pq        = std::move(ct_pq);

    // Pre-compute expected signature sizes (fixed by tray type / algorithm)
    uint32_t sig_cl_size = 0;
    uint32_t sig_pq_size = 0;
    try {
        sig_cl_size = (uint32_t)ec_sig::sig_bytes(cl_sig->alg_name);
        if (dilithium_sig::is_pq_sig(pq_sig->alg_name)) {
            int mode = dilithium_sig::mode_from_alg(pq_sig->alg_name);
            sig_pq_size = (uint32_t)dilithium_sig::sig_bytes_for_mode(mode);
        } else if (oqs_sig::is_oqs_sig(pq_sig->alg_name)) {
            sig_pq_size = (uint32_t)oqs_sig::sig_bytes(pq_sig->alg_name);
        } else {
            sig_pq_size = (uint32_t)slhdsa_sig::sig_bytes(pq_sig->alg_name);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: signature size lookup failed: " << e.what() << "\n";
        return 2;
    }

    // Build partial header (includes sig length fields but not the sig bytes themselves)
    auto partial_hdr = hyke_partial_header(hdr,
                                           (uint32_t)encrypted_payload.size(),
                                           sig_cl_size,
                                           sig_pq_size);

    // Compute context binding: ctx = KMAC256(key=pk_cl, msg=pk_pq || domain, outlen=512 bits)
    std::vector<uint8_t> ctx_bytes;
    try {
        ctx_bytes = compute_hyke_ctx(cl_kem->pk, pq_kem->pk);
    } catch (const std::exception& e) {
        std::cerr << "Error: context binding failed: " << e.what() << "\n";
        return 2;
    }

    // Build m_to_sign = ctx || partial_header || encrypted_payload
    std::vector<uint8_t> m_to_sign;
    m_to_sign.reserve(ctx_bytes.size() + partial_hdr.size() + encrypted_payload.size());
    m_to_sign.insert(m_to_sign.end(), ctx_bytes.begin(),     ctx_bytes.end());
    m_to_sign.insert(m_to_sign.end(), partial_hdr.begin(),   partial_hdr.end());
    m_to_sign.insert(m_to_sign.end(), encrypted_payload.begin(), encrypted_payload.end());

    // Classical signature
    try {
        ec_sig::sign(cl_sig->alg_name, cl_sig->sk, m_to_sign, hdr.sig_classical);
    } catch (const std::exception& e) {
        std::cerr << "Error: classical signing failed: " << e.what() << "\n";
        return 2;
    }

    // PQ signature
    try {
        if (dilithium_sig::is_pq_sig(pq_sig->alg_name)) {
            dilithium_sig::sign(dilithium_sig::mode_from_alg(pq_sig->alg_name),
                                pq_sig->sk, m_to_sign, hdr.sig_pq);
        } else if (oqs_sig::is_oqs_sig(pq_sig->alg_name)) {
            oqs_sig::sign(pq_sig->alg_name, pq_sig->sk, m_to_sign, hdr.sig_pq);
        } else {
            slhdsa_sig::sign(pq_sig->alg_name, pq_sig->sk, m_to_sign, hdr.sig_pq);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: PQ signing failed: " << e.what() << "\n";
        return 2;
    }

    // Pack and armor
    auto wire = hyke_pack(hdr, encrypted_payload);
    std::cout << hyke_armor(wire);
    return 0;
}

// ── verify+decrypt command ────────────────────────────────────────────────────

static int cmd_verify_decrypt(const std::string& tray_path,
                               const std::string& target_path)
{
    // Load tray
    Tray tray;
    try {
        tray = load_tray(tray_path);
    } catch (const std::exception& e) {
        std::cerr << "Error: cannot load tray: " << e.what() << "\n";
        return 3;
    }

    if (!is_tray_complete(tray.tray_type)) {
        std::cerr << "Error: " << tray.profile_group << " "
                  << tray_type_to_profile(tray.tray_type)
                  << " is a partial tray and cannot be used for HYKE"
                  << " — a full 4-slot tray (classical + PQ KEM and sig) is required\n";
        return 1;
    }

    const Slot* cl_kem = find_classical_slot(tray);
    const Slot* pq_kem = find_pq_slot(tray);
    const Slot* cl_sig = find_classical_sig_slot(tray);
    const Slot* pq_sig = find_pq_sig_slot(tray);

    if (!cl_kem || !pq_kem || !cl_sig || !pq_sig) {
        std::cerr << "Error: tray must contain all 4 slots for verify\n";
        return 1;
    }
    if (cl_kem->sk.empty() || pq_kem->sk.empty()) {
        std::cerr << "Error: tray KEM secret keys (KEM-classical and KEM-PQ) are required for verify\n";
        return 1;
    }

    // Read armored file
    std::string armored;
    try {
        armored = read_file_text(target_path);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 3;
    }

    // Dearmor and unpack
    std::vector<uint8_t> payload;
    HykeHeader hdr;
    try {
        auto wire = hyke_dearmor(armored);
        hdr = hyke_unpack(wire, payload);
    } catch (const std::exception& e) {
        std::cerr << "Error: failed to parse HYKE file: " << e.what() << "\n";
        return 3;
    }

    // Check tray_id matches
    if (hdr.tray_id != tray_id_byte(tray.tray_type)) {
        std::cerr << "Error: tray type mismatch (file was signed with a different tray type)\n";
        return 2;
    }

    // Reconstruct partial header (the bytes that were signed).
    // sig_pq_size must match what was used during sign: oqs_sig::sig_bytes()
    // returns the *maximum* signature length (e.g. Falcon is variable-length),
    // so we must use that value here rather than hdr.sig_pq.size() (actual from
    // wire) to ensure both sides hash the same partial header bytes.
    uint32_t verify_sig_cl_size = (uint32_t)hdr.sig_classical.size();
    uint32_t verify_sig_pq_size;
    try {
        if (dilithium_sig::is_pq_sig(pq_sig->alg_name)) {
            int mode = dilithium_sig::mode_from_alg(pq_sig->alg_name);
            verify_sig_pq_size = (uint32_t)dilithium_sig::sig_bytes_for_mode(mode);
        } else if (oqs_sig::is_oqs_sig(pq_sig->alg_name)) {
            verify_sig_pq_size = (uint32_t)oqs_sig::sig_bytes(pq_sig->alg_name);
        } else {
            verify_sig_pq_size = (uint32_t)slhdsa_sig::sig_bytes(pq_sig->alg_name);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: signature size lookup failed: " << e.what() << "\n";
        return 2;
    }
    auto partial_hdr = hyke_partial_header(hdr,
                                           (uint32_t)payload.size(),
                                           verify_sig_cl_size,
                                           verify_sig_pq_size);

    // Compute context binding
    std::vector<uint8_t> ctx_bytes;
    try {
        ctx_bytes = compute_hyke_ctx(cl_kem->pk, pq_kem->pk);
    } catch (const std::exception& e) {
        std::cerr << "Error: context binding failed: " << e.what() << "\n";
        return 2;
    }

    // Build m_to_sign = ctx || partial_header || payload
    std::vector<uint8_t> m_to_sign;
    m_to_sign.reserve(ctx_bytes.size() + partial_hdr.size() + payload.size());
    m_to_sign.insert(m_to_sign.end(), ctx_bytes.begin(),   ctx_bytes.end());
    m_to_sign.insert(m_to_sign.end(), partial_hdr.begin(), partial_hdr.end());
    m_to_sign.insert(m_to_sign.end(), payload.begin(),     payload.end());

    // Verify classical signature
    try {
        if (!ec_sig::verify(cl_sig->alg_name, cl_sig->pk, m_to_sign, hdr.sig_classical)) {
            std::cerr << "Error: classical signature INVALID\n";
            return 2;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: classical signature verification failed: " << e.what() << "\n";
        return 2;
    }

    // Verify PQ signature
    try {
        bool pq_ok = false;
        if (dilithium_sig::is_pq_sig(pq_sig->alg_name)) {
            pq_ok = dilithium_sig::verify(dilithium_sig::mode_from_alg(pq_sig->alg_name),
                                          pq_sig->pk, m_to_sign, hdr.sig_pq);
        } else if (oqs_sig::is_oqs_sig(pq_sig->alg_name)) {
            pq_ok = oqs_sig::verify(pq_sig->alg_name, pq_sig->pk, m_to_sign, hdr.sig_pq);
        } else {
            pq_ok = slhdsa_sig::verify(pq_sig->alg_name, pq_sig->pk, m_to_sign, hdr.sig_pq);
        }
        if (!pq_ok) {
            std::cerr << "Error: PQ signature INVALID\n";
            return 2;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: PQ signature verification failed: " << e.what() << "\n";
        return 2;
    }

    // Classical KEM decaps
    std::vector<uint8_t> ss_classical;
    try {
        ec_kem::decaps(cl_kem->alg_name, cl_kem->sk, hdr.ct_classical, ss_classical);
    } catch (const std::exception& e) {
        std::cerr << "Error: classical KEM decaps failed: " << e.what() << "\n";
        return 2;
    }

    // PQ KEM decaps
    std::vector<uint8_t> ss_pq;
    try {
        if (pq_kem->alg_name.substr(0, 5) == "Kyber") {
            kyber_kem::decaps(kyber_kem::level_from_alg(pq_kem->alg_name), pq_kem->sk, hdr.ct_pq, ss_pq);
        } else if (oqs_kem::is_oqs_kem(pq_kem->alg_name)) {
            oqs_kem::decaps(pq_kem->alg_name, pq_kem->sk, hdr.ct_pq, ss_pq);
        } else {
            mceliece_kem::decaps(pq_kem->alg_name, pq_kem->sk, hdr.ct_pq, ss_pq);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: PQ KEM decaps failed: " << e.what() << "\n";
        return 2;
    }

    // HYKE KMAC KDF
    std::array<uint8_t, 32> sym_key;
    try {
        sym_key = derive_key_hyke(ss_classical, ss_pq, hdr.ct_classical, hdr.ct_pq, hdr.salt);
    } catch (const std::exception& e) {
        std::cerr << "Error: HYKE KDF failed: " << e.what() << "\n";
        return 2;
    }

    // AES-256-GCM decrypt
    std::vector<uint8_t> plaintext;
    try {
        plaintext = aes256gcm_decrypt(sym_key.data(), payload);
    } catch (const std::exception& e) {
        std::cerr << "Error: decryption/authentication failed: " << e.what() << "\n";
        return 2;
    }

    // Output plaintext
    std::cout.write((const char*)plaintext.data(), (std::streamsize)plaintext.size());
    return 0;
}

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

    Signature sig;
    sig.id            = sig_id;
    sig.created       = iso8601_now();
    sig.tray_id       = tray.id;
    sig.tray_alias    = tray.alias;
    sig.profile_group = tray.profile_group;
    sig.profile       = tray.type_str;
    sig.input         = in_file_path;
    sig.composite     = pack_composite_sig(sig_cl, sig_pq);

    std::cout << emit_signature_yaml(sig);
    return 0;
}

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

    Signature syaml;
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
        cs = unpack_composite_sig(syaml.composite);
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

    syaml.tray_alias    = tray.alias;
    syaml.profile_group = tray.profile_group;
    syaml.profile       = tray.type_str;

    std::cout << emit_verify_yaml(syaml);
    return 0;
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "--help" || cmd == "-h") {
        print_usage(argv[0]);
        return 0;
    }

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

    if (cmd == "pwencrypt") return cmd_pwencrypt(argc - 1, argv + 1);
    if (cmd == "pwdecrypt") return cmd_pwdecrypt(argc - 1, argv + 1);

    // ── gentok / valtok ───────────────────────────────────────────────────────
    if (cmd == "gentok") {
        std::string tray_path, data_str;
        int64_t ttl_secs = 86400;
        for (int i = 2; i < argc; ++i) {
            if (std::strcmp(argv[i], "--tray") == 0) {
                if (++i >= argc) { std::cerr << "Error: --tray requires a filename\n"; return 1; }
                tray_path = argv[i];
            } else if (std::strcmp(argv[i], "--data") == 0) {
                if (++i >= argc) { std::cerr << "Error: --data requires a value\n"; return 1; }
                data_str = argv[i];
            } else if (std::strcmp(argv[i], "--ttl") == 0) {
                if (++i >= argc) { std::cerr << "Error: --ttl requires a value\n"; return 1; }
                try { ttl_secs = (int64_t)std::stoll(argv[i]); }
                catch (...) { std::cerr << "Error: --ttl value is not a valid integer\n"; return 1; }
                if (ttl_secs <= 0) { std::cerr << "Error: --ttl must be positive\n"; return 1; }
            } else {
                std::cerr << "Error: unknown option '" << argv[i] << "'\n"; return 1;
            }
        }
        if (tray_path.empty()) { std::cerr << "Error: --tray is required\n"; return 1; }
        if (data_str.empty())  { std::cerr << "Error: --data is required\n"; return 1; }
        cmd_gentok(tray_path, data_str, ttl_secs);
        return 0;
    }

    if (cmd == "valtok") {
        std::string tray_path, token_file;
        for (int i = 2; i < argc; ++i) {
            if (std::strcmp(argv[i], "--tray") == 0) {
                if (++i >= argc) { std::cerr << "Error: --tray requires a filename\n"; return 1; }
                tray_path = argv[i];
            } else if (argv[i][0] == '-') {
                std::cerr << "Error: unknown option '" << argv[i] << "'\n"; return 1;
            } else {
                if (!token_file.empty()) {
                    std::cerr << "Error: unexpected argument '" << argv[i] << "'\n"; return 1;
                }
                token_file = argv[i];
            }
        }
        if (tray_path.empty()) { std::cerr << "Error: --tray is required\n"; return 1; }
        cmd_valtok(tray_path, token_file);
        return 0;
    }

    if (cmd != "encrypt" && cmd != "decrypt" && cmd != "encrypt+sign" && cmd != "verify+decrypt") {
        std::cerr << "Error: unknown command '" << cmd << "'\n";
        print_usage(argv[0]);
        return 1;
    }

    // Parse shared and command-specific options
    std::string tray_path;
    std::string target_path;
    KDFAlg    kdf_alg    = KDFAlg::SHAKE256;
    CipherAlg cipher_alg = CipherAlg::AES256GCM;

    for (int i = 2; i < argc; ++i) {
        if (std::strcmp(argv[i], "--tray") == 0) {
            if (++i >= argc) {
                std::cerr << "Error: --tray requires a filename\n";
                return 1;
            }
            tray_path = argv[i];
        } else if (std::strcmp(argv[i], "--kdf") == 0) {
            if (++i >= argc) {
                std::cerr << "Error: --kdf requires a value\n";
                return 1;
            }
            std::string v = argv[i];
            if (v == "SHAKE" || v == "SHAKE256") {
                kdf_alg = KDFAlg::SHAKE256;
            } else if (v == "KMAC" || v == "KMAC256") {
                kdf_alg = KDFAlg::KMAC256;
            } else {
                std::cerr << "Error: unknown --kdf value '" << v << "' (must be SHAKE or KMAC)\n";
                return 1;
            }
        } else if (std::strcmp(argv[i], "--cipher") == 0) {
            if (++i >= argc) {
                std::cerr << "Error: --cipher requires a value\n";
                return 1;
            }
            std::string v = argv[i];
            if (v == "AES-256-GCM" || v == "AES") {
                cipher_alg = CipherAlg::AES256GCM;
            } else if (v == "ChaCha20" || v == "ChaCha20-Poly1305") {
                cipher_alg = CipherAlg::ChaCha20Poly1305;
            } else {
                std::cerr << "Error: unknown --cipher value '" << v
                          << "' (must be AES-256-GCM or ChaCha20)\n";
                return 1;
            }
        } else if (argv[i][0] == '-') {
            std::cerr << "Error: unknown option '" << argv[i] << "'\n";
            return 1;
        } else {
            if (!target_path.empty()) {
                std::cerr << "Error: unexpected argument '" << argv[i] << "'\n";
                return 1;
            }
            target_path = argv[i];
        }
    }

    if (tray_path.empty()) {
        std::cerr << "Error: --tray is required\n";
        return 1;
    }
    if (target_path.empty()) {
        std::cerr << "Error: <target-file> is required\n";
        return 1;
    }

    if (cmd == "encrypt") {
        return cmd_encrypt(tray_path, target_path, kdf_alg, cipher_alg);
    } else if (cmd == "decrypt") {
        return cmd_decrypt(tray_path, target_path);
    } else if (cmd == "encrypt+sign") {
        return cmd_encrypt_sign(tray_path, target_path);
    } else {
        return cmd_verify_decrypt(tray_path, target_path);
    }
}
