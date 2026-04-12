#include <crystals/crystals.hpp>

#include <cassert>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

// ── Test helpers ──────────────────────────────────────────────────────────────

static int g_pass = 0, g_fail = 0;

#define CHECK(expr) \
    do { \
        if (!(expr)) { \
            std::fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, #expr); \
            ++g_fail; \
        } else { \
            ++g_pass; \
        } \
    } while(0)

#define CHECK_THROWS(expr) \
    do { \
        bool caught = false; \
        try { (void)(expr); } catch (...) { caught = true; } \
        if (!caught) { \
            std::fprintf(stderr, "FAIL [%s:%d]: expected exception: %s\n", __FILE__, __LINE__, #expr); \
            ++g_fail; \
        } else { \
            ++g_pass; \
        } \
    } while(0)

static bool uuid_is_v8(const std::string& id) {
    // Format: xxxxxxxx-xxxx-8xxx-xxxx-xxxxxxxxxxxx (position 14 must be '8')
    return id.size() == 36 && id[14] == '8' && id[8] == '-' && id[13] == '-';
}

static std::string tmp_path(const char* name) {
    return std::string("/tmp/crystals_test_") + name;
}

// ── Section 1: Keygen ─────────────────────────────────────────────────────────

static void test_keygen() {
    std::printf("=== Section 1: Keygen ===\n");

    struct Case { TrayType t; const char* name; size_t slots; };
    Case cases[] = {
        { TrayType::Level0,       "level0",       2 },
        { TrayType::Level1,       "level1",       2 },
        { TrayType::Level2_25519, "level2-25519", 4 },
        { TrayType::Level2,       "level2",       4 },
        { TrayType::Level3,       "level3",       4 },
        { TrayType::Level5,       "level5",       4 },
    };

    for (auto& c : cases) {
        Tray tray = make_tray(c.t, "alice");
        CHECK(tray.slots.size() == c.slots);
        CHECK(!tray.id.empty());
        CHECK(uuid_is_v8(tray.id));
        CHECK(tray.alias == "alice");
        CHECK(tray.profile_group == "crystals");

        for (const auto& slot : tray.slots) {
            CHECK(!slot.pk.empty());
            CHECK(!slot.sk.empty());
        }

        // make_public_tray: same UUID, sk cleared
        Tray pub = make_public_tray(tray);
        CHECK(pub.id == tray.id);
        CHECK(pub.alias == "alice.pub");
        for (const auto& slot : pub.slots)
            CHECK(slot.sk.empty());

        std::printf("  %s: OK\n", c.name);
    }
}

// ── Section 2: YAML round-trip ────────────────────────────────────────────────

static void test_yaml_roundtrip() {
    std::printf("=== Section 2: YAML round-trip ===\n");

    Tray orig = make_tray(TrayType::Level2_25519, "bob");
    std::string yaml = emit_tray_yaml(orig);
    CHECK(!yaml.empty());

    // Write to temp file, then load_tray
    std::string path = tmp_path("yaml.tray");
    {
        std::ofstream f(path);
        f << yaml;
    }

    Tray loaded = load_tray(path);
    CHECK(loaded.id == orig.id);
    CHECK(loaded.alias == orig.alias);
    CHECK(loaded.slots.size() == orig.slots.size());
    for (size_t i = 0; i < orig.slots.size(); ++i) {
        CHECK(loaded.slots[i].alg_name == orig.slots[i].alg_name);
        CHECK(loaded.slots[i].pk == orig.slots[i].pk);
        CHECK(loaded.slots[i].sk == orig.slots[i].sk);
    }
    std::printf("  level2-25519 YAML round-trip: OK\n");
}

// ── Section 3: UUID verification ─────────────────────────────────────────────

static void test_uuid_verification() {
    std::printf("=== Section 3: UUID verification ===\n");

    Tray orig = make_tray(TrayType::Level2_25519, "dave");
    std::string yaml = emit_tray_yaml(orig);

    // Tamper: replace the correct UUID with an all-zero v8 UUID
    std::string tampered = yaml;
    size_t pos = tampered.find("id: ");
    if (pos != std::string::npos) {
        size_t eol = tampered.find('\n', pos);
        tampered.replace(pos, eol - pos, "id: 00000000-0000-8000-8000-000000000000");
    }
    std::string path = tmp_path("tampered_uuid.tray");
    { std::ofstream f(path); f << tampered; }

    // load_tray must throw UUID mismatch
    bool threw = false;
    try { load_tray(path); } catch (...) { threw = true; }
    CHECK(threw);
    std::printf("  tampered YAML UUID rejected: OK\n");
}

// ── Section 4: Kyber KEM ──────────────────────────────────────────────────────

static void test_kyber_kem() {
    std::printf("=== Section 4: Kyber KEM ===\n");

    for (int level : {512, 768, 1024}) {
        std::vector<uint8_t> pk, sk;
        kyber::keygen(level, pk, sk);

        auto sz = kyber_kem_sizes(level);
        CHECK(pk.size() == sz.pk_bytes);
        CHECK(sk.size() == sz.sk_bytes);

        std::vector<uint8_t> ct, ss_enc, ss_dec;
        kyber_kem::encaps(level, pk, ct, ss_enc);
        CHECK(ct.size() == sz.ct_bytes);
        CHECK(ss_enc.size() == sz.ss_bytes);

        kyber_kem::decaps(level, sk, ct, ss_dec);
        CHECK(ss_enc == ss_dec);

        std::printf("  Kyber%d KEM: OK\n", level);
    }
}

// ── Section 5: EC KEM ─────────────────────────────────────────────────────────

static void test_ec_kem() {
    std::printf("=== Section 5: EC KEM ===\n");

    struct Case { const char* alg; ec::Algorithm alg_enum; };
    Case cases[] = {
        { "X25519", ec::Algorithm::X25519 },
        { "P-256",  ec::Algorithm::P256   },
        { "P-384",  ec::Algorithm::P384   },
        { "P-521",  ec::Algorithm::P521   },
    };

    for (auto& c : cases) {
        auto kp = ec::keygen(c.alg_enum);
        CHECK(!kp.pk.empty());
        CHECK(!kp.sk.empty());

        std::vector<uint8_t> ct, ss_enc, ss_dec;
        ec_kem::encaps(c.alg, kp.pk, ct, ss_enc);
        CHECK(!ct.empty());
        CHECK(!ss_enc.empty());

        ec_kem::decaps(c.alg, kp.sk, ct, ss_dec);
        CHECK(ss_enc == ss_dec);

        std::printf("  %s EC KEM: OK\n", c.alg);
    }
}

// ── Section 6: Dilithium sign/verify ─────────────────────────────────────────

static void test_dilithium_sig() {
    std::printf("=== Section 6: Dilithium sign/verify ===\n");

    std::vector<uint8_t> msg = {0x01, 0x02, 0x03, 0x04, 0x05};

    for (int mode : {2, 3, 5}) {
        std::vector<uint8_t> pk, sk;
        dilithium::keygen(mode, pk, sk);

        auto sz = dilithium_sizes(mode);
        CHECK(pk.size() == sz.pk_bytes);
        CHECK(sk.size() == sz.sk_bytes);

        std::vector<uint8_t> sig;
        dilithium_sig::sign(mode, sk, msg, sig);
        CHECK(!sig.empty());

        bool ok = dilithium_sig::verify(mode, pk, msg, sig);
        CHECK(ok);

        // Tampered message should fail
        std::vector<uint8_t> bad_msg = msg;
        bad_msg[0] ^= 0xFF;
        bool bad_ok = dilithium_sig::verify(mode, pk, bad_msg, sig);
        CHECK(!bad_ok);

        std::printf("  Dilithium%d sign/verify: OK\n", mode);
    }
}

// ── Section 7: EC sign/verify ─────────────────────────────────────────────────

static void test_ec_sig() {
    std::printf("=== Section 7: EC sign/verify ===\n");

    std::vector<uint8_t> msg = {0xDE, 0xAD, 0xBE, 0xEF};

    struct Case { const char* alg; ec::Algorithm alg_enum; size_t expected_sig; };
    Case cases[] = {
        { "Ed25519",    ec::Algorithm::Ed25519, 64  },
        { "ECDSA P-256", ec::Algorithm::P256,   64  },
        { "ECDSA P-384", ec::Algorithm::P384,   96  },
        { "ECDSA P-521", ec::Algorithm::P521,   132 },
    };

    for (auto& c : cases) {
        auto kp = ec::keygen(c.alg_enum);

        std::vector<uint8_t> sig;
        ec_sig::sign(c.alg, kp.sk, msg, sig);
        CHECK(sig.size() == c.expected_sig);

        bool ok = ec_sig::verify(c.alg, kp.pk, msg, sig);
        CHECK(ok);

        // Tampered sig should fail
        std::vector<uint8_t> bad_sig = sig;
        bad_sig[0] ^= 0xFF;
        bool bad_ok = ec_sig::verify(c.alg, kp.pk, msg, bad_sig);
        CHECK(!bad_ok);

        std::printf("  %s sign/verify: OK\n", c.alg);
    }
}

// ── Section 8: ZORRO armor ────────────────────────────────────────────────────

static void test_zorro_armor() {
    std::printf("=== Section 8: ZORRO armor ===\n");

    WireHeader hdr;
    hdr.kdf    = KDFAlg::SHAKE256;
    hdr.cipher = CipherAlg::AES256GCM;
    hdr.ct_classical = {0x01, 0x02, 0x03, 0x04};
    hdr.ct_pq        = {0xAA, 0xBB, 0xCC};

    std::vector<uint8_t> payload = {0x11, 0x22, 0x33, 0x44, 0x55};

    std::string armored = armor_pack(hdr, payload);
    CHECK(armored.find("-----BEGIN ZORRO ENCRYPTED FILE-----") != std::string::npos);
    CHECK(armored.find("-----END ZORRO ENCRYPTED FILE-----") != std::string::npos);

    std::vector<uint8_t> payload_out;
    WireHeader hdr2 = armor_unpack(armored, payload_out);
    CHECK((uint8_t)hdr2.kdf    == (uint8_t)hdr.kdf);
    CHECK((uint8_t)hdr2.cipher == (uint8_t)hdr.cipher);
    CHECK(hdr2.ct_classical == hdr.ct_classical);
    CHECK(hdr2.ct_pq == hdr.ct_pq);
    CHECK(payload_out == payload);

    std::printf("  armor_pack/unpack round-trip: OK\n");
}

// ── Section 9: AES-256-GCM + ChaCha20 ────────────────────────────────────────

static void test_symmetric() {
    std::printf("=== Section 9: AES-256-GCM + ChaCha20 ===\n");

    uint8_t key[32];
    std::memset(key, 0x42, 32);

    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"

    // AES-256-GCM no AAD
    {
        auto blob = aes256gcm_encrypt(key, plaintext);
        CHECK(blob.size() >= 12 + 16 + plaintext.size());
        auto pt = aes256gcm_decrypt(key, blob);
        CHECK(pt == plaintext);

        // Tampered blob should throw
        auto bad = blob;
        bad[bad.size() / 2] ^= 0xFF;
        CHECK_THROWS(aes256gcm_decrypt(key, bad));
        std::printf("  AES-256-GCM: OK\n");
    }

    // AES-256-GCM with AAD
    {
        std::vector<uint8_t> aad = {0x01, 0x02};
        auto blob = aes256gcm_encrypt_aad(key, plaintext, aad.data(), aad.size());
        auto pt = aes256gcm_decrypt_aad(key, blob, aad.data(), aad.size());
        CHECK(pt == plaintext);

        // Wrong AAD should throw
        std::vector<uint8_t> bad_aad = {0xFF, 0xFF};
        CHECK_THROWS(aes256gcm_decrypt_aad(key, blob, bad_aad.data(), bad_aad.size()));
        std::printf("  AES-256-GCM with AAD: OK\n");
    }

    // ChaCha20-Poly1305
    {
        auto blob = chacha20poly1305_encrypt(key, plaintext);
        CHECK(blob.size() >= 12 + 16 + plaintext.size());
        auto pt = chacha20poly1305_decrypt(key, blob);
        CHECK(pt == plaintext);

        auto bad = blob;
        bad[bad.size() / 2] ^= 0xFF;
        CHECK_THROWS(chacha20poly1305_decrypt(key, bad));
        std::printf("  ChaCha20-Poly1305: OK\n");
    }
}

// ── Section 10: pw wire format ────────────────────────────────────────────────

static void test_pw_wire_format() {
    std::printf("=== Section 10: pw wire format ===\n");

    for (int level : {512, 768, 1024}) {
        auto sz = kyber_kem_sizes(level);

        PwBundle b;
        b.level = level;
        std::memset(b.salt, 0xAB, 32);
        b.scrypt_n_log2 = 16;
        b.scrypt_r = 8;
        b.scrypt_p = 1;
        b.pk.assign(sz.pk_bytes, 0x11);
        b.ct.assign(sz.ct_bytes, 0x22);
        b.wrap_nonce_tag_sk_enc.assign(12 + 16 + sz.sk_bytes, 0x33);
        b.data_nonce_tag_ct.assign(12 + 16 + 100, 0x44);

        auto wire = pack_pw_bundle(b);

        // Check AAD prefix
        auto aad = pw_bundle_aad(level);
        CHECK(aad.size() == 7);
        CHECK(aad[0] == 'O' && aad[1] == 'B' && aad[2] == 'W' && aad[3] == 'E');

        // Round-trip
        PwBundle b2 = parse_pw_bundle(wire);
        CHECK(b2.level == b.level);
        CHECK(std::memcmp(b2.salt, b.salt, 32) == 0);
        CHECK(b2.scrypt_n_log2 == b.scrypt_n_log2);
        CHECK(b2.pk == b.pk);
        CHECK(b2.ct == b.ct);
        CHECK(b2.wrap_nonce_tag_sk_enc == b.wrap_nonce_tag_sk_enc);
        CHECK(b2.data_nonce_tag_ct == b.data_nonce_tag_ct);

        // Armor/dearmor
        auto armored = armor_pw(wire);
        CHECK(armored.find("-----BEGIN ZORRO PW ENCRYPTED FILE-----") != std::string::npos);
        auto wire2 = dearmor_pw(armored);
        CHECK(wire2 == wire);

        std::printf("  pw wire Kyber%d round-trip: OK\n", level);
    }
}

// ── Section 11: token wire format ─────────────────────────────────────────────

static void test_token_format() {
    std::printf("=== Section 11: token wire format ===\n");

    // Pack/unpack round-trip
    {
        Token tok;
        tok.data = {0x68, 0x65, 0x6C, 0x6C, 0x6F};  // "hello"
        tok.issued_at  = 1700000000;
        tok.expires_at = 1700003600;
        tok.algorithm  = kTokenAlgECDSAP256;
        std::memset(tok.tray_uuid, 0xAB, 16);
        std::memset(tok.token_uuid, 0xCD, 16);
        tok.signature.assign(64, 0x55);  // fake 64-byte sig

        auto wire = token_pack(tok);
        Token rt = token_unpack(wire);

        CHECK(rt.data == tok.data);
        CHECK(rt.issued_at  == tok.issued_at);
        CHECK(rt.expires_at == tok.expires_at);
        CHECK(rt.algorithm  == tok.algorithm);
        CHECK(std::memcmp(rt.tray_uuid, tok.tray_uuid, 16) == 0);
        CHECK(std::memcmp(rt.token_uuid, tok.token_uuid, 16) == 0);
        CHECK(rt.signature  == tok.signature);

        std::printf("  pack/unpack round-trip: OK\n");
    }

    // Armor/dearmor round-trip
    {
        Token tok;
        tok.data = {0x74, 0x65, 0x73, 0x74};  // "test"
        tok.issued_at  = 1000000000;
        tok.expires_at = 1000001000;
        tok.algorithm  = kTokenAlgECDSAP256;
        std::memset(tok.tray_uuid, 0x12, 16);
        std::memset(tok.token_uuid, 0x34, 16);
        tok.signature.assign(64, 0x77);

        auto wire = token_pack(tok);
        std::string armored = token_armor(wire);

        // Must end with '\n'
        CHECK(!armored.empty() && armored.back() == '\n');

        auto wire2 = token_dearmor(armored);
        CHECK(wire2 == wire);

        std::printf("  armor/dearmor round-trip: OK\n");
    }

    // token_unpack rejects bad magic
    {
        Token tok;
        tok.data = {0x41};
        tok.issued_at  = 1000;
        tok.expires_at = 2000;
        tok.algorithm  = kTokenAlgECDSAP256;
        std::memset(tok.tray_uuid, 0x00, 16);
        std::memset(tok.token_uuid, 0x00, 16);
        tok.signature.assign(64, 0x00);

        auto wire = token_pack(tok);
        wire[0] ^= 0xFF;  // corrupt magic
        CHECK_THROWS(token_unpack(wire));

        std::printf("  bad magic rejected: OK\n");
    }

    // token_unpack rejects issued_at > expires_at
    {
        Token tok;
        tok.data = {0x41};
        tok.issued_at  = 2000;
        tok.expires_at = 1000;  // expires before issued
        tok.algorithm  = kTokenAlgECDSAP256;
        std::memset(tok.tray_uuid, 0x00, 16);
        std::memset(tok.token_uuid, 0x00, 16);
        tok.signature.assign(64, 0x00);

        // Build wire manually (skip token_pack which doesn't validate)
        auto canonical = token_canonical_bytes(tok);
        std::vector<uint8_t> wire;
        wire.insert(wire.end(), canonical.begin(), canonical.end());
        // SIG_LEN
        wire.push_back(0x00); wire.push_back(0x00);
        wire.push_back(0x00); wire.push_back(0x40);
        wire.insert(wire.end(), 64, 0x00);
        CHECK_THROWS(token_unpack(wire));

        std::printf("  issued_at > expires_at rejected: OK\n");
    }

    // token_unpack rejects wrong SIG_LEN
    {
        Token tok;
        tok.data = {0x41};
        tok.issued_at  = 1000;
        tok.expires_at = 2000;
        tok.algorithm  = kTokenAlgECDSAP256;
        std::memset(tok.tray_uuid, 0x00, 16);
        std::memset(tok.token_uuid, 0x00, 16);
        tok.signature.assign(64, 0x00);

        auto wire = token_pack(tok);
        // Corrupt the SIG_LEN field (last 68 bytes: 4 len + 64 sig)
        // SIG_LEN starts at wire.size()-68
        size_t sig_len_offset = wire.size() - 68;
        wire[sig_len_offset + 3] = 0x20;  // change 64 → 32
        CHECK_THROWS(token_unpack(wire));

        std::printf("  wrong SIG_LEN rejected: OK\n");
    }
}

// ── Section 12: protect / unprotect ───────────────────────────────────────────

static void test_protect_unprotect() {
    std::printf("=== Section 12: protect / unprotect ===\n");

    // Round-trip: make_tray → protect_tray → unprotect_tray
    {
        Tray orig = make_tray(TrayType::Level2_25519, "protect_test");
        const char* pw = "correct-horse-battery-staple";
        SecureTray st = protect_tray(orig, pw, std::strlen(pw));
        Tray rt = unprotect_tray(st, pw, std::strlen(pw));

        CHECK(rt.id == orig.id);
        CHECK(rt.alias == orig.alias);
        CHECK(rt.slots.size() == orig.slots.size());
        for (size_t i = 0; i < orig.slots.size(); ++i) {
            CHECK(rt.slots[i].alg_name == orig.slots[i].alg_name);
            CHECK(rt.slots[i].pk == orig.slots[i].pk);
            CHECK(rt.slots[i].sk == orig.slots[i].sk);
        }
        std::printf("  protect/unprotect round-trip: OK\n");
    }

    // Wrong password → unprotect_tray throws
    {
        Tray orig = make_tray(TrayType::Level2, "wrong_pw_test");
        const char* pw  = "right-password";
        const char* bad = "wrong-password";
        SecureTray st = protect_tray(orig, pw, std::strlen(pw));
        CHECK_THROWS(unprotect_tray(st, bad, std::strlen(bad)));
        std::printf("  wrong password rejected: OK\n");
    }

    // UUID validation: protect_tray on a tray with tampered UUID throws
    {
        Tray orig = make_tray(TrayType::Level1, "tampered_uuid_test");
        orig.id = "00000000-0000-8000-8000-000000000000";  // valid format, wrong value
        const char* pw = "any-password";
        CHECK_THROWS(protect_tray(orig, pw, std::strlen(pw)));
        std::printf("  tampered UUID rejected by protect_tray: OK\n");
    }
}

// ── Section 13: mceliece+slhdsa keygen ────────────────────────────────────────

static void test_mceliece_slhdsa_keygen() {
    std::printf("=== Section 13: mceliece+slhdsa keygen ===\n");

    struct Case {
        TrayType t;
        const char* name;
        size_t expected_slots;
        const char* expected_group;
        const char* expected_type_str;
    };
    Case cases[] = {
        { TrayType::McEliece_Level1, "ms-level1", 2, "mceliece+slhdsa", "ms-level1" },
        { TrayType::McEliece_Level2, "ms-level2", 4, "mceliece+slhdsa", "ms-level2" },
        { TrayType::McEliece_Level3, "ms-level3", 4, "mceliece+slhdsa", "ms-level3" },
        { TrayType::McEliece_Level4, "ms-level4", 4, "mceliece+slhdsa", "ms-level4" },
        { TrayType::McEliece_Level5, "ms-level5", 4, "mceliece+slhdsa", "ms-level5" },
    };

    for (auto& c : cases) {
        Tray tray = make_tray(c.t, "alice");
        CHECK(tray.slots.size() == c.expected_slots);
        CHECK(!tray.id.empty());
        CHECK(uuid_is_v8(tray.id));
        CHECK(tray.alias == "alice");
        CHECK(tray.profile_group == c.expected_group);
        CHECK(tray.type_str == c.expected_type_str);

        for (const auto& slot : tray.slots) {
            CHECK(!slot.pk.empty());
            CHECK(!slot.sk.empty());
            CHECK(!slot.alg_name.empty());
        }

        // public tray: same UUID, sk cleared
        Tray pub = make_public_tray(tray);
        CHECK(pub.id == tray.id);
        CHECK(pub.alias == "alice.pub");
        for (const auto& slot : pub.slots)
            CHECK(slot.sk.empty());

        // UUID validation
        CHECK(validate_tray_uuid(tray));

        std::printf("  %s: OK\n", c.name);
    }
}

// ── Section 14: McEliece KEM ──────────────────────────────────────────────────

static void test_mceliece_kem() {
    std::printf("=== Section 14: McEliece KEM ===\n");

    // Test encaps/decaps round-trip for each of the 5 param sets
    const char* param_sets[] = {
        "mceliece348864f", "mceliece460896f", "mceliece6688128f",
        "mceliece6960119f", "mceliece8192128f"
    };
    for (const char* ps : param_sets) {
        auto kp = mcs::keygen_mceliece(ps);
        CHECK(!kp.pk.empty());
        CHECK(!kp.sk.empty());

        std::vector<uint8_t> ct, ss_enc, ss_dec;
        mceliece_kem::encaps(ps, kp.pk, ct, ss_enc);
        CHECK(!ct.empty());
        CHECK(ss_enc.size() == 32);

        mceliece_kem::decaps(ps, kp.sk, ct, ss_dec);
        CHECK(ss_enc == ss_dec);

        std::printf("  %s: OK\n", ps);
    }
}

// ── Section 15: SLH-DSA sign/verify ──────────────────────────────────────────

static void test_slhdsa_sig() {
    std::printf("=== Section 15: SLH-DSA sign/verify ===\n");

    const char* algs[] = {
        "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256f",
        "SLH-DSA-SHAKE-192f",
        "SLH-DSA-SHAKE-256f"
    };

    std::vector<uint8_t> msg = {0x01, 0x02, 0x03, 0x04, 0x05};

    for (const char* alg : algs) {
        CHECK(slhdsa_sig::is_slhdsa_sig(alg));
        CHECK(slhdsa_sig::sig_bytes(alg) > 0);

        auto kp = mcs::keygen_slhdsa(alg);
        CHECK(!kp.pk.empty());
        CHECK(!kp.sk.empty());

        std::vector<uint8_t> sig;
        slhdsa_sig::sign(alg, kp.sk, msg, sig);
        CHECK(sig.size() == slhdsa_sig::sig_bytes(alg));

        CHECK(slhdsa_sig::verify(alg, kp.pk, msg, sig));

        // tamper check: flip a byte in the message
        std::vector<uint8_t> bad_msg = msg;
        bad_msg[0] ^= 0xFF;
        CHECK(!slhdsa_sig::verify(alg, kp.pk, bad_msg, sig));

        std::printf("  %s: OK\n", alg);
    }
}

// ── Section 16: OQS Groups (mlkem+mldsa and frodokem+falcon) ─────────────────

static void test_oqs_groups() {
    std::printf("=== Section 16: OQS Groups ===\n");

    // ── mlkem+mldsa ──────────────────────────────────────────────────────────
    {
        struct Case { TrayType t; const char* name; size_t slots; };
        Case cases[] = {
            { TrayType::MlKem_Level1, "mk-level1", 2 },
            { TrayType::MlKem_Level2, "mk-level2", 4 },
            { TrayType::MlKem_Level3, "mk-level3", 4 },
            { TrayType::MlKem_Level4, "mk-level4", 4 },
        };

        for (auto& c : cases) {
            Tray tray = make_tray(c.t, "alice");
            CHECK(tray.slots.size() == c.slots);
            CHECK(!tray.id.empty());
            CHECK(uuid_is_v8(tray.id));
            CHECK(tray.alias == "alice");
            CHECK(tray.profile_group == "mlkem+mldsa");
            CHECK(validate_tray_uuid(tray));

            for (const auto& slot : tray.slots) {
                CHECK(!slot.pk.empty());
                CHECK(!slot.sk.empty());
            }

            // make_public_tray: same UUID, sk cleared
            Tray pub = make_public_tray(tray);
            CHECK(pub.id == tray.id);
            CHECK(pub.alias == "alice.pub");
            for (const auto& slot : pub.slots)
                CHECK(slot.sk.empty());

            std::printf("  mlkem+mldsa %s: OK\n", c.name);
        }
    }

    // ── frodokem+falcon ──────────────────────────────────────────────────────
    {
        struct Case { TrayType t; const char* name; size_t slots; };
        Case cases[] = {
            { TrayType::FrodoFalcon_Level1, "ff-level1", 2 },
            { TrayType::FrodoFalcon_Level2, "ff-level2", 4 },
            { TrayType::FrodoFalcon_Level3, "ff-level3", 4 },
            { TrayType::FrodoFalcon_Level4, "ff-level4", 4 },
        };

        for (auto& c : cases) {
            Tray tray = make_tray(c.t, "bob");
            CHECK(tray.slots.size() == c.slots);
            CHECK(!tray.id.empty());
            CHECK(uuid_is_v8(tray.id));
            CHECK(tray.alias == "bob");
            CHECK(tray.profile_group == "frodokem+falcon");
            CHECK(validate_tray_uuid(tray));

            for (const auto& slot : tray.slots) {
                CHECK(!slot.pk.empty());
                CHECK(!slot.sk.empty());
            }

            // make_public_tray: same UUID, sk cleared
            Tray pub = make_public_tray(tray);
            CHECK(pub.id == tray.id);
            CHECK(pub.alias == "bob.pub");
            for (const auto& slot : pub.slots)
                CHECK(slot.sk.empty());

            std::printf("  frodokem+falcon %s: OK\n", c.name);
        }
    }

    // ── YAML round-trip for a new group ──────────────────────────────────────
    {
        Tray orig = make_tray(TrayType::MlKem_Level2, "carol");
        std::string yaml = emit_tray_yaml(orig);
        CHECK(!yaml.empty());
        std::string path = tmp_path("mlkem_yaml.tray");
        { std::ofstream f(path); f << yaml; }
        Tray loaded = load_tray(path);
        CHECK(loaded.id == orig.id);
        CHECK(loaded.alias == orig.alias);
        CHECK(loaded.profile_group == "mlkem+mldsa");
        CHECK(loaded.slots.size() == 4);
        for (size_t i = 0; i < 4; ++i) {
            CHECK(loaded.slots[i].alg_name == orig.slots[i].alg_name);
            CHECK(loaded.slots[i].pk == orig.slots[i].pk);
            CHECK(loaded.slots[i].sk == orig.slots[i].sk);
        }
        std::printf("  mlkem+mldsa YAML round-trip: OK\n");
    }

    // ── protect/unprotect for a new group ────────────────────────────────────
    {
        Tray tray = make_tray(TrayType::FrodoFalcon_Level2, "dave");
        const char* pw = "hunter2hunter2hunter2";
        SecureTray st = protect_tray(tray, pw, std::strlen(pw));
        CHECK(st.type_str == "ff-level2");

        Tray recovered = unprotect_tray(st, pw, std::strlen(pw));
        CHECK(recovered.id == tray.id);
        CHECK(recovered.slots.size() == tray.slots.size());
        for (size_t i = 0; i < tray.slots.size(); ++i) {
            CHECK(recovered.slots[i].alg_name == tray.slots[i].alg_name);
            CHECK(recovered.slots[i].pk == tray.slots[i].pk);
            CHECK(recovered.slots[i].sk == tray.slots[i].sk);
        }
        std::printf("  frodokem+falcon protect/unprotect: OK\n");
    }
}

// ── Section 17: BLAKE3 digest ─────────────────────────────────────────────────

static void test_blake3() {
    std::printf("=== Section 17: BLAKE3 digest ===\n");

    const std::vector<uint8_t> data  = {0x01, 0x02, 0x03, 0x04, 0x05};
    const std::vector<uint8_t> data2 = {0x01, 0x02, 0x03, 0x04, 0x06}; // one byte differs

    std::array<uint8_t, 32> key1{};
    std::array<uint8_t, 32> key2{};
    key1.fill(0xAA);
    key2.fill(0xBB);

    // digest known-answer test: {0x01..0x05} → value computed by blake3_hasher
    // using the BLAKE3 C reference implementation (BLAKE3-team/BLAKE3)
    {
        std::array<uint8_t, 32> expected = {
            0x02, 0x4f, 0x67, 0xc0, 0x42, 0x5a, 0x3d, 0xc0,
            0x2f, 0xba, 0xf5, 0x8c, 0xb9, 0x3d, 0xe5, 0x13,
            0x2e, 0x3d, 0x75, 0xc5, 0x19, 0xfa, 0xa0, 0xba,
            0xda, 0x21, 0x49, 0x1d, 0x88, 0xc9, 0x70, 0x57
        };
        CHECK(blake3::digest(data) == expected);
        std::printf("  digest known-answer test: OK\n");
    }

    // digest known-answer test: empty input → BLAKE3 spec reference value
    {
        const std::vector<uint8_t> empty;
        std::array<uint8_t, 32> expected_empty = {
            0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6,
            0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
            0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7,
            0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62
        };
        CHECK(blake3::digest(empty) == expected_empty);
        std::printf("  digest known-answer (empty): OK\n");
    }

    // digest is sensitive to input
    CHECK(blake3::digest(data) != blake3::digest(data2));
    std::printf("  digest input sensitivity: OK\n");

    // verify returns true on matching digest
    CHECK(blake3::verify(data, blake3::digest(data)) == true);
    std::printf("  verify match: OK\n");

    // verify returns false on tampered data
    CHECK(blake3::verify(data2, blake3::digest(data)) == false);
    std::printf("  verify tamper detection: OK\n");

    // keyed_digest differs from plain digest on same input
    CHECK(blake3::keyed_digest(key1, data) != blake3::digest(data));
    std::printf("  keyed_digest differs from plain digest: OK\n");

    // keyed_digest is sensitive to key
    CHECK(blake3::keyed_digest(key1, data) != blake3::keyed_digest(key2, data));
    std::printf("  keyed_digest key sensitivity: OK\n");

    // keyed_verify returns true on matching digest
    CHECK(blake3::keyed_verify(key1, data, blake3::keyed_digest(key1, data)) == true);
    std::printf("  keyed_verify match: OK\n");

    // keyed_verify returns false on tampered data
    CHECK(blake3::keyed_verify(key1, data2, blake3::keyed_digest(key1, data)) == false);
    std::printf("  keyed_verify tamper detection: OK\n");

    // keyed_verify returns false on wrong key
    CHECK(blake3::keyed_verify(key2, data, blake3::keyed_digest(key1, data)) == false);
    std::printf("  keyed_verify wrong key detection: OK\n");
}

// ── Section 18: load_tray_yaml tray_type preservation (DEF-001) ──────────────
// load_tray_yaml() must populate tray_type from the YAML "profile" field
// for all profile groups, not just when going through load_tray().

static void test_load_tray_yaml_tray_type() {
    std::printf("=== Section 18: load_tray_yaml tray_type preservation (DEF-001) ===\n");

    // Full round-trip (emit → file → load) for crystals-group profiles.
    struct Case { TrayType t; const char* type_str; const char* group; size_t slots; };
    const Case cases[] = {
        { TrayType::Level0,       "level0",       "crystals", 2 },
        { TrayType::Level1,       "level1",       "crystals", 2 },
        { TrayType::Level2,       "level2",       "crystals", 4 },
        { TrayType::Level2_25519, "level2-25519", "crystals", 4 },
        { TrayType::Level3,       "level3",       "crystals", 4 },
        { TrayType::Level5,       "level5",       "crystals", 4 },
    };

    for (const auto& c : cases) {
        Tray orig = make_tray(c.t, "test");
        std::string yaml = emit_tray_yaml(orig);

        std::string path = tmp_path((std::string("lty_") + c.type_str + ".tray").c_str());
        { std::ofstream f(path); f << yaml; }

        Tray loaded = load_tray_yaml(path);

        CHECK(loaded.tray_type     == c.t);
        CHECK(loaded.type_str      == c.type_str);
        CHECK(loaded.profile_group == c.group);
        CHECK(loaded.id            == orig.id);
        CHECK(loaded.alias         == orig.alias);
        CHECK(loaded.slots.size()  == c.slots);
        std::printf("  %s tray_type preserved: OK\n", c.type_str);
    }

    // Stub-YAML coverage for non-crystals profile groups: verifies the
    // tray_type_from_str mapping for each group prefix without expensive
    // key generation.  One representative per group is sufficient.
    struct StubCase { const char* profile; const char* group; TrayType expected; };
    const StubCase stubs[] = {
        { "ms-level2", "mceliece+slhdsa", TrayType::McEliece_Level2   },
        { "mk-level2", "mlkem+mldsa",     TrayType::MlKem_Level2      },
        { "ff-level2", "frodokem+falcon", TrayType::FrodoFalcon_Level2 },
    };

    for (const auto& s : stubs) {
        std::string yaml =
            std::string("profile-group: ") + s.group  + "\n"
                        "profile: "        + s.profile + "\n"
                        "slots: []\n";
        std::string path = tmp_path((std::string("lty_stub_") + s.profile + ".tray").c_str());
        { std::ofstream f(path); f << yaml; }

        Tray loaded = load_tray_yaml(path);
        CHECK(loaded.tray_type == s.expected);
        std::printf("  %s tray_type preserved: OK\n", s.profile);
    }
}

// ── main ──────────────────────────────────────────────────────────────────────

int main() {
    std::printf("crystals library test\n");
    std::printf("=====================\n\n");

    try {
        test_keygen();
        test_yaml_roundtrip();
        test_uuid_verification();
        test_kyber_kem();
        test_ec_kem();
        test_dilithium_sig();
        test_ec_sig();
        test_zorro_armor();
        test_symmetric();
        test_pw_wire_format();
        test_token_format();
        test_protect_unprotect();
        test_mceliece_slhdsa_keygen();
        test_mceliece_kem();
        test_slhdsa_sig();
        test_oqs_groups();
        test_blake3();
        test_load_tray_yaml_tray_type();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "UNCAUGHT EXCEPTION: %s\n", e.what());
        return 1;
    }

    std::printf("\n=====================\n");
    std::printf("Results: %d passed, %d failed\n", g_pass, g_fail);

    return (g_fail == 0) ? 0 : 1;
}
