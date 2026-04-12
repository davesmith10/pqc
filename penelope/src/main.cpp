#include <crystals/crystals.hpp>
#include "lodepng.h"
#include "bitmap_font.hpp"
#include "encaps_crypto.hpp"

#include <array>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <termios.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

// ── Rainbow palette ───────────────────────────────────────────────────────────

static std::array<uint8_t, 3> byte_to_rgb(uint8_t v) {
    double h  = (v / 256.0) * 360.0;
    double h6 = h / 60.0;
    int    i  = static_cast<int>(h6) % 6;
    double f  = h6 - std::floor(h6);

    double r, g, b;
    switch (i) {
        case 0: r = 1.0; g = f;       b = 0.0;   break;
        case 1: r = 1-f; g = 1.0;     b = 0.0;   break;
        case 2: r = 0.0; g = 1.0;     b = f;     break;
        case 3: r = 0.0; g = 1.0-f;   b = 1.0;   break;
        case 4: r = f;   g = 0.0;     b = 1.0;   break;
        default:r = 1.0; g = 0.0;     b = 1.0-f; break;
    }

    return {
        static_cast<uint8_t>(r * 255.0 + 0.5),
        static_cast<uint8_t>(g * 255.0 + 0.5),
        static_cast<uint8_t>(b * 255.0 + 0.5)
    };
}

// Reverse lookup: RGB triple (packed as r<<16|g<<8|b) → original byte value.
static std::unordered_map<uint32_t, uint8_t> build_reverse_lut() {
    std::unordered_map<uint32_t, uint8_t> lut;
    lut.reserve(256);
    for (int v = 0; v < 256; ++v) {
        auto c = byte_to_rgb(static_cast<uint8_t>(v));
        uint32_t key = (uint32_t(c[0]) << 16) | (uint32_t(c[1]) << 8) | c[2];
        lut[key] = static_cast<uint8_t>(v);
    }
    return lut;
}

// ── Image geometry constants (encaps / decaps) ────────────────────────────────

static const unsigned ENCAPS_IMG_W  = 256;
static const unsigned ENCAPS_MARGIN = 12;
static const unsigned ENCAPS_GAP    = 8;
static const unsigned ENCAPS_COL_W  = (ENCAPS_IMG_W - ENCAPS_MARGIN - ENCAPS_MARGIN - ENCAPS_GAP) / 2;  // 112
static const unsigned LINE_SPACING  = 10;
static const unsigned KEM_BLOB_BYTES = 60;  // kem_nonce(12) + kem_tag(16) + data_key_enc(32)

struct ImageResult {
    std::vector<uint8_t> pixels;
    unsigned w, h;
};

static bool is_pq_slot(const std::string& alg_name) {
    return alg_name.rfind("Kyber",     0) == 0 ||
           alg_name.rfind("Dilithium", 0) == 0 ||
           alg_name.rfind("ML-KEM-",   0) == 0 ||
           alg_name.rfind("ML-DSA-",   0) == 0 ||
           alg_name.rfind("FrodoKEM-", 0) == 0 ||
           alg_name.rfind("Falcon-",   0) == 0;
}

// row_count for arbitrary column width
static unsigned row_count_cw(size_t nbytes, unsigned col_w) {
    if (nbytes == 0 || col_w == 0) return 0;
    return static_cast<unsigned>((nbytes + col_w - 1) / col_w);
}

// ── iTXt metadata ─────────────────────────────────────────────────────────────

static std::string make_meta_text(const Tray& tray, int scale = 1) {
    std::ostringstream ss;
    ss << "alias="   << tray.alias    << "\n"
       << "id="      << tray.id       << "\n"
       << "profile=" << tray.type_str << "\n"
       << "created=" << tray.created  << "\n"
       << "expires=" << tray.expires  << "\n"
       << "scale="   << scale         << "\n";
    return ss.str();
}

struct TrayMeta {
    std::string alias, id, profile, created, expires;
    int scale = 1;
};

static TrayMeta parse_meta(const std::string& text) {
    TrayMeta m;
    std::istringstream ss(text);
    std::string line;
    while (std::getline(ss, line)) {
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        if      (key == "alias")   m.alias   = val;
        else if (key == "id")      m.id      = val;
        else if (key == "profile") m.profile = val;
        else if (key == "created") m.created = val;
        else if (key == "expires") m.expires = val;
        else if (key == "scale")   m.scale   = std::stoi(val);
    }
    if (m.alias.empty() || m.id.empty() || m.profile.empty())
        throw std::runtime_error("crystals-tray iTXt chunk is missing required fields");
    return m;
}

// ── crystals-encaps iTXt metadata ────────────────────────────────────────────

struct EncapsMeta {
    std::vector<uint8_t> salt;          // 16 bytes
    int n_log2 = 0;
    int r = 0, p = 0;
    std::vector<uint8_t> sk_nonce;      // 12 bytes
    std::vector<uint8_t> sk_tag;        // 16 bytes
};

static std::string make_encaps_text(const EncapsMeta& em) {
    std::ostringstream ss;
    ss << "salt="     << base64_encode(em.salt.data(), em.salt.size())         << "\n"
       << "n_log2="   << em.n_log2                                             << "\n"
       << "r="        << em.r                                                  << "\n"
       << "p="        << em.p                                                  << "\n"
       << "sk_nonce=" << base64_encode(em.sk_nonce.data(), em.sk_nonce.size()) << "\n"
       << "sk_tag="   << base64_encode(em.sk_tag.data(), em.sk_tag.size())     << "\n";
    return ss.str();
}

static EncapsMeta parse_encaps_meta(const std::string& text) {
    EncapsMeta em;
    std::istringstream ss(text);
    std::string line;
    while (std::getline(ss, line)) {
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        if      (key == "salt")     em.salt     = base64_decode(val);
        else if (key == "n_log2")   em.n_log2   = std::stoi(val);
        else if (key == "r")        em.r        = std::stoi(val);
        else if (key == "p")        em.p        = std::stoi(val);
        else if (key == "sk_nonce") em.sk_nonce = base64_decode(val);
        else if (key == "sk_tag")   em.sk_tag   = base64_decode(val);
    }
    if (em.salt.empty() || em.n_log2 == 0 || em.sk_nonce.empty() || em.sk_tag.empty())
        throw std::runtime_error("crystals-encaps iTXt chunk is missing required fields");
    return em;
}

// ── Profile slot-size table ───────────────────────────────────────────────────

struct SlotDef {
    std::string alg_name;
    size_t pk_size;
    size_t sk_size;
};

static const std::map<std::string, std::vector<SlotDef>> PROFILES = {
    {"level0", {
        {"X25519",     32,   32},
        {"Ed25519",    32,   32},
    }},
    {"level1", {
        {"Kyber512",   800,  1632},
        {"Dilithium2", 1312, 2560},
    }},
    {"level2-25519", {
        {"X25519",     32,   32},
        {"Kyber512",   800,  1632},
        {"Ed25519",    32,   32},
        {"Dilithium2", 1312, 2560},
    }},
    {"level2", {
        {"P-256",      65,   32},
        {"Kyber512",   800,  1632},
        {"ECDSA P-256", 65,  32},
        {"Dilithium2", 1312, 2560},
    }},
    {"level3", {
        {"P-384",      97,   48},
        {"Kyber768",   1184, 2400},
        {"ECDSA P-384", 97,  48},
        {"Dilithium3", 1952, 4032},
    }},
    {"level5", {
        {"P-521",      133,  66},
        {"Kyber1024",  1568, 3168},
        {"ECDSA P-521", 133, 66},
        {"Dilithium5", 2592, 4896},
    }},
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
        {"Falcon-512",        897,   1281},
    }},
    {"ff-level4", {
        {"P-521",             133,   66},
        {"FrodoKEM-1344-AES", 21520, 43088},
        {"ECDSA P-521",       133,   66},
        {"Falcon-1024",       1793,  2305},
    }},
};

// ── Pixel buffer helpers ──────────────────────────────────────────────────────

// fill_block: writes data bytes as rainbow pixels.
// col_width: number of pixels per row (ROW_WIDTH for render, ENCAPS_COL_W for encaps).
static void fill_block(std::vector<uint8_t>& pixels, unsigned img_w,
                        const std::vector<uint8_t>& data, unsigned nrows,
                        unsigned x_off, unsigned y_off,
                        unsigned col_width) {
    for (unsigned row = 0; row < nrows; ++row) {
        for (unsigned col = 0; col < col_width; ++col) {
            size_t byte_idx = static_cast<size_t>(row) * col_width + col;
            if (byte_idx >= data.size()) continue;   // leave background (white)
            auto [r, g, b] = byte_to_rgb(data[byte_idx]);
            size_t px = ((y_off + row) * img_w + (x_off + col)) * 4;
            pixels[px + 0] = r;
            pixels[px + 1] = g;
            pixels[px + 2] = b;
            pixels[px + 3] = 255;
        }
    }
}

// read_block: extracts nbytes from the image using the reverse palette LUT.
// col_width: number of pixels per row (ROW_WIDTH for render, ENCAPS_COL_W for encaps).
static std::vector<uint8_t> read_block(const unsigned char* pixels, unsigned img_w,
                                        const std::unordered_map<uint32_t, uint8_t>& rlut,
                                        unsigned x_off, unsigned y_off,
                                        size_t nbytes,
                                        unsigned col_width) {
    std::vector<uint8_t> out;
    out.reserve(nbytes);
    for (size_t i = 0; i < nbytes; ++i) {
        unsigned row = static_cast<unsigned>(i / col_width);
        unsigned col = static_cast<unsigned>(i % col_width);
        size_t px = ((y_off + row) * img_w + (x_off + col)) * 4;
        uint32_t key = (uint32_t(pixels[px])     << 16)
                     | (uint32_t(pixels[px + 1]) <<  8)
                     |  uint32_t(pixels[px + 2]);
        auto it = rlut.find(key);
        if (it == rlut.end())
            throw std::runtime_error("pixel at ("
                + std::to_string(x_off + col) + ","
                + std::to_string(y_off + row)
                + ") is not in the rainbow palette — not a padme PNG?");
        out.push_back(it->second);
    }
    return out;
}

// ── Nearest-neighbor scale helpers ───────────────────────────────────────────

// Upscale by 4× (w→4w, h→4h); each source pixel becomes a 4×4 block.
static std::vector<uint8_t> upscale4x(
    const std::vector<uint8_t>& src, unsigned w, unsigned h)
{
    unsigned ow = w * 4, oh = h * 4;
    std::vector<uint8_t> dst(ow * oh * 4);
    for (unsigned oy = 0; oy < oh; ++oy)
        for (unsigned ox = 0; ox < ow; ++ox)
            for (int c = 0; c < 4; ++c)
                dst[(oy * ow + ox) * 4 + c] = src[(oy / 4 * w + ox / 4) * 4 + c];
    return dst;
}

// Downscale by 4× — takes top-left pixel of each 4×4 block.
static std::vector<uint8_t> downscale4x(
    const std::vector<uint8_t>& src, unsigned sw, unsigned sh)
{
    unsigned ow = sw / 4, oh = sh / 4;
    std::vector<uint8_t> dst(ow * oh * 4);
    for (unsigned oy = 0; oy < oh; ++oy)
        for (unsigned ox = 0; ox < ow; ++ox)
            for (int c = 0; c < 4; ++c)
                dst[(oy * ow + ox) * 4 + c] = src[(oy * 4 * sw + ox * 4) * 4 + c];
    return dst;
}

// ── Write PNG with one or two iTXt chunks ─────────────────────────────────────

static void write_png(const ImageResult& img, const std::string& out_file,
                       const std::string& meta_text,
                       const std::string& encaps_text = "") {
    LodePNGState state;
    lodepng_state_init(&state);
    state.info_raw.colortype = LCT_RGBA;
    state.info_raw.bitdepth  = 8;
    state.info_png.color.colortype = LCT_RGBA;
    state.info_png.color.bitdepth  = 8;
    state.encoder.auto_convert = 0;

    unsigned err = lodepng_add_itext(&state.info_png,
                                      "crystals-tray", "", "crystals-tray",
                                      meta_text.c_str());
    if (err) {
        lodepng_state_cleanup(&state);
        throw std::runtime_error(std::string("iTXt error: ") + lodepng_error_text(err));
    }

    if (!encaps_text.empty()) {
        err = lodepng_add_itext(&state.info_png,
                                 "crystals-encaps", "", "crystals-encaps",
                                 encaps_text.c_str());
        if (err) {
            lodepng_state_cleanup(&state);
            throw std::runtime_error(std::string("iTXt encaps error: ") + lodepng_error_text(err));
        }
    }

    unsigned char* png_buf = nullptr;
    size_t png_size = 0;
    err = lodepng_encode(&png_buf, &png_size, img.pixels.data(), img.w, img.h, &state);
    lodepng_state_cleanup(&state);
    if (err) {
        free(png_buf);
        throw std::runtime_error(std::string("PNG encode error: ") + lodepng_error_text(err));
    }

    err = lodepng_save_file(png_buf, png_size, out_file.c_str());
    free(png_buf);
    if (err)
        throw std::runtime_error(std::string("PNG write error: ") + lodepng_error_text(err));
}

// ── Encaps image builder ───────────────────────────────────────────────────────

// Build the encaps-format image (256px wide, text header+footer, 112px columns).
// cl_sk_enc and pq_sk_enc are the encrypted SK bytes for their respective sections.
// kem_blob is 60 bytes: kem_nonce(12) || kem_tag(16) || data_key_enc(32).
static ImageResult build_encaps_image(
    const Tray& tray,
    const std::vector<uint8_t>& cl_pk,
    const std::vector<uint8_t>& cl_sk_enc,
    const std::vector<uint8_t>& pq_pk,
    const std::vector<uint8_t>& pq_sk_enc,
    const std::vector<uint8_t>& kem_blob)
{
    const unsigned img_w = ENCAPS_IMG_W;

    // ── Key section heights ─────────────────────────────────────────────────
    unsigned cl_rows = std::max(row_count_cw(cl_pk.size(),     ENCAPS_COL_W),
                                 row_count_cw(cl_sk_enc.size(), ENCAPS_COL_W));
    unsigned pq_rows = std::max(row_count_cw(pq_pk.size(),     ENCAPS_COL_W),
                                 row_count_cw(pq_sk_enc.size(), ENCAPS_COL_W));

    // ── Y positions ─────────────────────────────────────────────────────────
    // Header: 2 lines of text, each LINE_SPACING apart
    unsigned y_hdr1    = ENCAPS_MARGIN;                          // line 1
    unsigned y_hdr2    = y_hdr1 + LINE_SPACING;                  // line 2
    unsigned y_keys    = y_hdr2 + FONT_H + ENCAPS_GAP;           // start of key blocks

    unsigned y_cl      = y_keys;
    unsigned y_pq      = y_cl + cl_rows + (cl_rows > 0 && pq_rows > 0 ? ENCAPS_GAP : 0);

    unsigned total_key_h = cl_rows + (cl_rows > 0 && pq_rows > 0 ? ENCAPS_GAP : 0) + pq_rows;
    if (total_key_h == 0) total_key_h = 1;

    unsigned y_kem     = y_keys + total_key_h + ENCAPS_GAP;      // KEM row
    unsigned y_cpy1    = y_kem + 1 + ENCAPS_GAP;                 // copyright line 1
    unsigned y_cpy2    = y_cpy1 + LINE_SPACING;                  // copyright line 2

    unsigned img_h     = y_cpy2 + FONT_H + ENCAPS_MARGIN;

    std::vector<uint8_t> pixels(img_w * img_h * 4, 0xFF);

    // ── Text colors ──────────────────────────────────────────────────────────
    std::array<uint8_t, 3> fg_dark  = {20,  20,  20};
    std::array<uint8_t, 3> bg_white = {255, 255, 255};

    // ── Header line 1: "PADME Tray - <level>" ───────────────────────────────
    std::string hdr1 = "PADME Tray - " + tray.type_str;
    draw_text(pixels, img_w, ENCAPS_MARGIN, y_hdr1, hdr1, fg_dark, bg_white);

    // ── Header line 2: <uuid> ────────────────────────────────────────────────
    draw_text(pixels, img_w, ENCAPS_MARGIN, y_hdr2, tray.id, fg_dark, bg_white);

    // ── Classical key block (top section) ────────────────────────────────────
    const unsigned x_pk = ENCAPS_MARGIN;
    const unsigned x_sk = ENCAPS_MARGIN + ENCAPS_COL_W + ENCAPS_GAP;

    if (cl_rows > 0) {
        fill_block(pixels, img_w, cl_pk,     cl_rows, x_pk, y_cl, ENCAPS_COL_W);
        fill_block(pixels, img_w, cl_sk_enc, cl_rows, x_sk, y_cl, ENCAPS_COL_W);
    }

    // ── PQ key block (bottom section) ────────────────────────────────────────
    if (pq_rows > 0) {
        fill_block(pixels, img_w, pq_pk,     pq_rows, x_pk, y_pq, ENCAPS_COL_W);
        fill_block(pixels, img_w, pq_sk_enc, pq_rows, x_sk, y_pq, ENCAPS_COL_W);
    }

    // ── KEM block: 60 pixels centered ────────────────────────────────────────
    // Content area: ENCAPS_MARGIN to img_w-ENCAPS_MARGIN = 232px wide
    unsigned content_w = img_w - 2 * ENCAPS_MARGIN;
    unsigned x_kem = ENCAPS_MARGIN + (content_w - KEM_BLOB_BYTES) / 2;
    fill_block(pixels, img_w, kem_blob, 1, x_kem, y_kem, KEM_BLOB_BYTES);

    // ── Copyright footer ─────────────────────────────────────────────────────
    const std::string cpy1 = "\xC2\xA9 2026 David R. Smith";  // © 2026 David R. Smith
    const std::string cpy2 = "All Rights Reserved";
    unsigned cpy1_w = text_pixel_width(cpy1);
    unsigned cpy2_w = text_pixel_width(cpy2);
    unsigned x_cpy1 = ENCAPS_MARGIN + (content_w - cpy1_w) / 2;
    unsigned x_cpy2 = ENCAPS_MARGIN + (content_w - cpy2_w) / 2;
    draw_text(pixels, img_w, x_cpy1, y_cpy1, cpy1, fg_dark, bg_white);
    draw_text(pixels, img_w, x_cpy2, y_cpy2, cpy2, fg_dark, bg_white);

    return {std::move(pixels), img_w, img_h};
}

// ── Password prompt helpers ───────────────────────────────────────────────────

static std::string read_noecho(const char* prompt) {
    std::cerr << prompt;
    struct termios old_t, new_t;
    tcgetattr(STDIN_FILENO, &old_t);
    new_t = old_t;
    new_t.c_lflag &= ~(tcflag_t)ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_t);
    std::string pw;
    std::getline(std::cin, pw);
    tcsetattr(STDIN_FILENO, TCSANOW, &old_t);
    std::cerr << "\n";
    return pw;
}

static std::string get_password_encaps(const std::string& pwfile) {
    if (!pwfile.empty()) {
        std::ifstream f(pwfile);
        if (!f) throw std::runtime_error("Cannot open pwfile: " + pwfile);
        std::string pw;
        std::getline(f, pw);
        return pw;
    }
    std::string p1 = read_noecho("password: ");
    std::string p2 = read_noecho("again: ");
    if (p1 != p2) throw std::runtime_error("Passwords do not match");
    return p1;
}

static std::string get_password_decaps(const std::string& pwfile) {
    if (!pwfile.empty()) {
        std::ifstream f(pwfile);
        if (!f) throw std::runtime_error("Cannot open pwfile: " + pwfile);
        std::string pw;
        std::getline(f, pw);
        return pw;
    }
    return read_noecho("password: ");
}

// ── Output helpers ────────────────────────────────────────────────────────────

// Write tray to file in YAML format. Returns false and prints error on failure.
static bool write_tray_file(const Tray& tray, const std::string& path, const char* cmd) {
    try {
        std::ofstream f(path);
        if (!f) { std::cerr << "Error: cannot open " << path << " for writing\n"; return false; }
        f << emit_tray_yaml(tray);
    } catch (const std::exception& e) {
        std::cerr << "Error: YAML write failed: " << e.what() << "\n"; return false;
    }
    std::cout << cmd << ": tray '" << tray.alias << "' \xe2\x86\x92 " << path
              << " (" << tray.slots.size() << " slots)\n";
    return true;
}

// ── pngify / pngout image constants ──────────────────────────────────────────

static const unsigned OBIWAN_IMG_W  = 500;
static const unsigned OBIWAN_MARGIN = 12;
static const unsigned OBIWAN_DATA_W = OBIWAN_IMG_W - 2 * OBIWAN_MARGIN;  // 476

// ── pngify / pngout helpers ───────────────────────────────────────────────────

// Returns "obiwan", "hyke", or "pwenc" from the BEGIN armor line.
static std::string detect_armor_format(const std::string& first_line) {
    if (first_line.find("BEGIN OBIWAN PW ENCRYPTED") != std::string::npos) return "pwenc";
    if (first_line.find("BEGIN HYKE")                != std::string::npos) return "hyke";
    if (first_line.find("BEGIN OBIWAN ENCRYPTED")    != std::string::npos) return "obiwan";
    return "";
}

// Strip armor header/footer, concatenate base64 lines, base64_decode.
static std::vector<uint8_t> dearmor_bytes(const std::string& text, const std::string& fmt) {
    std::string b64;
    std::istringstream ss(text);
    std::string line;
    bool in_body = false;
    while (std::getline(ss, line)) {
        // trim \r
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.find("-----BEGIN ") == 0) { in_body = true; continue; }
        if (line.find("-----END ")   == 0) break;
        if (in_body) b64 += line;
    }
    (void)fmt;
    return base64_decode(b64);
}

// OBIWAN wire: "OBIWAN01"(8) + kdf(1) + cipher(1) + ct_cl_len u32be(4) + ct_cl + ct_pq_len u32be(4) + ...
static std::string obiwan_level_str(const std::vector<uint8_t>& wire) {
    if (wire.size() < 14) return "unknown";
    uint32_t ct_cl_len = (uint32_t(wire[10]) << 24) | (uint32_t(wire[11]) << 16)
                       | (uint32_t(wire[12]) << 8)  |  uint32_t(wire[13]);
    size_t off2 = 14 + ct_cl_len;
    if (off2 + 4 > wire.size()) return "unknown";
    uint32_t ct_pq_len = (uint32_t(wire[off2])   << 24) | (uint32_t(wire[off2+1]) << 16)
                       | (uint32_t(wire[off2+2])  <<  8) |  uint32_t(wire[off2+3]);
    if (ct_cl_len == 0  && ct_pq_len == 768)  return "level1";
    if (ct_cl_len == 32 && ct_pq_len == 768)  return "level2-25519";
    if (ct_cl_len == 65 && ct_pq_len == 768)  return "level2";
    if (ct_cl_len == 97 && ct_pq_len == 1088) return "level3";
    if (ct_cl_len == 133&& ct_pq_len == 1568) return "level5";
    if (ct_cl_len > 0  && ct_pq_len == 0)     return "level0";
    return "unknown";
}

// HYKE wire: offset 6 = tray_id byte
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

// PWENC wire: uint16 big-endian at offset 5
static std::string pwenc_level_str(const std::vector<uint8_t>& wire) {
    if (wire.size() < 7) return "unknown";
    uint16_t lvl = (uint16_t(wire[5]) << 8) | wire[6];
    if (lvl == 512)  return "512";
    if (lvl == 768)  return "768";
    if (lvl == 1024) return "1024";
    return "unknown";
}

// Format 16 UUID bytes as "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
static std::string format_uuid_bytes(const uint8_t* uuid) {
    char buf[37];
    std::snprintf(buf, sizeof(buf),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        uuid[0],  uuid[1],  uuid[2],  uuid[3],
        uuid[4],  uuid[5],
        uuid[6],  uuid[7],
        uuid[8],  uuid[9],
        uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
    return buf;
}

// Compute y_data from format: 1 header line (obiwan/pwenc) → 28; 2 header lines (hyke) → 38
static unsigned pngify_y_data(const std::string& fmt) {
    if (fmt == "hyke")
        return OBIWAN_MARGIN + LINE_SPACING + FONT_H + ENCAPS_GAP;  // 12+10+8+8 = 38
    return OBIWAN_MARGIN + FONT_H + ENCAPS_GAP;                     // 12+8+8    = 28
}

// Make crystals-obiwan iTXt text
static std::string make_obiwan_text(const std::string& fmt, size_t data_len) {
    std::ostringstream ss;
    ss << "format="   << fmt      << "\n"
       << "data_len=" << data_len << "\n";
    return ss.str();
}

struct OBIWANMeta { std::string format; size_t data_len = 0; };

static OBIWANMeta parse_obiwan_meta(const std::string& text) {
    OBIWANMeta m;
    std::istringstream ss(text);
    std::string line;
    while (std::getline(ss, line)) {
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        if      (key == "format")   m.format   = val;
        else if (key == "data_len") m.data_len = std::stoull(val);
    }
    if (m.format.empty() || m.data_len == 0)
        throw std::runtime_error("crystals-obiwan iTXt chunk is missing required fields");
    return m;
}

// Armor bytes with 64-char line breaks and armor header/footer
static std::string rearmor_bytes(const std::vector<uint8_t>& data, const std::string& fmt) {
    std::string begin_marker, end_marker;
    if (fmt == "hyke") {
        begin_marker = "-----BEGIN HYKE SIGNED FILE-----";
        end_marker   = "-----END HYKE SIGNED FILE-----";
    } else if (fmt == "pwenc") {
        begin_marker = "-----BEGIN OBIWAN PW ENCRYPTED FILE-----";
        end_marker   = "-----END OBIWAN PW ENCRYPTED FILE-----";
    } else {
        begin_marker = "-----BEGIN OBIWAN ENCRYPTED FILE-----";
        end_marker   = "-----END OBIWAN ENCRYPTED FILE-----";
    }

    std::string b64 = base64_encode(data.data(), data.size());
    std::string out = begin_marker + "\n";
    for (size_t i = 0; i < b64.size(); i += 64) {
        out += b64.substr(i, 64);
        out += "\n";
    }
    out += end_marker + "\n";
    return out;
}

// Build the 500px-wide pngify image
static ImageResult build_pngify_image(const std::string& fmt,
                                       const std::string& level_str,
                                       const std::string& uuid_str,
                                       const std::vector<uint8_t>& data) {
    const unsigned img_w  = OBIWAN_IMG_W;
    const unsigned y_data = pngify_y_data(fmt);
    unsigned data_rows = (unsigned)((data.size() + OBIWAN_DATA_W - 1) / OBIWAN_DATA_W);
    if (data_rows == 0) data_rows = 1;

    unsigned y_cpy1 = y_data + data_rows + ENCAPS_GAP;
    unsigned y_cpy2 = y_cpy1 + LINE_SPACING;
    unsigned img_h  = y_cpy2 + FONT_H + OBIWAN_MARGIN;

    std::vector<uint8_t> pixels(img_w * img_h * 4, 0xFF);

    std::array<uint8_t, 3> fg_dark  = {20,  20,  20};
    std::array<uint8_t, 3> bg_white = {255, 255, 255};

    // Header text
    std::string title;
    if (fmt == "hyke")    title = "OBIWAN HYKE SIGNED FILE - "    + level_str;
    else if (fmt == "pwenc") title = "OBIWAN PW ENCRYPTED FILE - " + level_str;
    else                  title = "OBIWAN ENCRYPTED FILE - "       + level_str;

    draw_text(pixels, img_w, OBIWAN_MARGIN, OBIWAN_MARGIN, title, fg_dark, bg_white);

    if (fmt == "hyke" && !uuid_str.empty()) {
        unsigned y_uuid = OBIWAN_MARGIN + LINE_SPACING;
        draw_text(pixels, img_w, OBIWAN_MARGIN, y_uuid, uuid_str, fg_dark, bg_white);
    }

    // Data region
    fill_block(pixels, img_w, data, data_rows, OBIWAN_MARGIN, y_data, OBIWAN_DATA_W);

    // Copyright footer (centered over the 476px data region)
    const std::string cpy1 = "\xC2\xA9 2026 David R. Smith";
    const std::string cpy2 = "All Rights Reserved";
    unsigned content_w = OBIWAN_DATA_W;
    unsigned cpy1_w = text_pixel_width(cpy1);
    unsigned cpy2_w = text_pixel_width(cpy2);
    unsigned x_cpy1 = OBIWAN_MARGIN + (content_w - cpy1_w) / 2;
    unsigned x_cpy2 = OBIWAN_MARGIN + (content_w - cpy2_w) / 2;
    draw_text(pixels, img_w, x_cpy1, y_cpy1, cpy1, fg_dark, bg_white);
    draw_text(pixels, img_w, x_cpy2, y_cpy2, cpy2, fg_dark, bg_white);

    return {std::move(pixels), img_w, img_h};
}

// Write PNG with only a crystals-obiwan iTXt chunk (no crystals-tray chunk)
static void write_obiwan_png(const ImageResult& img, const std::string& out_file,
                              const std::string& obiwan_text) {
    LodePNGState state;
    lodepng_state_init(&state);
    state.info_raw.colortype = LCT_RGBA;
    state.info_raw.bitdepth  = 8;
    state.info_png.color.colortype = LCT_RGBA;
    state.info_png.color.bitdepth  = 8;
    state.encoder.auto_convert = 0;

    unsigned err = lodepng_add_itext(&state.info_png,
                                      "crystals-obiwan", "", "crystals-obiwan",
                                      obiwan_text.c_str());
    if (err) {
        lodepng_state_cleanup(&state);
        throw std::runtime_error(std::string("iTXt error: ") + lodepng_error_text(err));
    }

    unsigned char* png_buf = nullptr;
    size_t png_size = 0;
    err = lodepng_encode(&png_buf, &png_size, img.pixels.data(), img.w, img.h, &state);
    lodepng_state_cleanup(&state);
    if (err) {
        free(png_buf);
        throw std::runtime_error(std::string("PNG encode error: ") + lodepng_error_text(err));
    }

    err = lodepng_save_file(png_buf, png_size, out_file.c_str());
    free(png_buf);
    if (err)
        throw std::runtime_error(std::string("PNG write error: ") + lodepng_error_text(err));
}

// ── pngify command ────────────────────────────────────────────────────────────

static int cmd_pngify(int argc, char* argv[]) {
    std::string in_file, out_file;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--in") == 0) {
            if (++i >= argc) { std::cerr << "Error: --in requires a filename\n"; return 1; }
            in_file = argv[i];
        } else if (std::strcmp(argv[i], "--out") == 0) {
            if (++i >= argc) { std::cerr << "Error: --out requires a filename\n"; return 1; }
            out_file = argv[i];
        } else {
            std::cerr << "Error: unknown option: " << argv[i] << "\n"; return 1;
        }
    }
    if (in_file.empty())  { std::cerr << "Error: --in is required\n";  return 1; }
    if (out_file.empty()) { std::cerr << "Error: --out is required\n"; return 1; }

    // 1. Read input file
    std::string text;
    {
        std::ifstream f(in_file);
        if (!f) { std::cerr << "Error: cannot open: " << in_file << "\n"; return 3; }
        std::ostringstream ss;
        ss << f.rdbuf();
        text = ss.str();
    }

    // 2. Detect format from first non-empty line
    std::string fmt;
    {
        std::istringstream ss(text);
        std::string line;
        while (std::getline(ss, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (!line.empty()) { fmt = detect_armor_format(line); break; }
        }
    }
    if (fmt.empty()) {
        std::cerr << "Error: unrecognized armor format in: " << in_file << "\n"; return 2;
    }

    // 3. Dearmor
    std::vector<uint8_t> data;
    try { data = dearmor_bytes(text, fmt); }
    catch (const std::exception& e) {
        std::cerr << "Error: dearmor failed: " << e.what() << "\n"; return 2;
    }
    if (data.empty()) {
        std::cerr << "Error: empty payload after dearmoring\n"; return 2;
    }

    // 4. Extract level and UUID
    std::string level_str, uuid_str;
    if      (fmt == "obiwan") level_str = obiwan_level_str(data);
    else if (fmt == "hyke")   { level_str = hyke_level_str(data); }
    else                      level_str = pwenc_level_str(data);

    if (fmt == "hyke" && data.size() >= 32) {
        // UUID at offset 16 (after "HYKE" + 2 ver + tray_id(1) + flags(1) + header_len(4) + payload_len(4) + uuid(16))
        // Actually per hyke_format.hpp: "HYKE"(4) + ver(2) + tray_id(1) + flags(1) + header_len(4) + payload_len(4) = 16 bytes, then uuid(16)
        if (data.size() >= 32)
            uuid_str = format_uuid_bytes(data.data() + 16);
    }

    // 5. Build image
    ImageResult img = build_pngify_image(fmt, level_str, uuid_str, data);

    // 6. Write PNG
    try { write_obiwan_png(img, out_file, make_obiwan_text(fmt, data.size())); }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n"; return 3;
    }

    std::cout << "pngify: " << fmt << " [" << level_str << "] -> " << out_file
              << " (" << data.size() << " bytes)\n";
    return 0;
}

// ── pngout command ────────────────────────────────────────────────────────────

static int cmd_pngout(int argc, char* argv[]) {
    std::string in_file, out_file;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--in") == 0) {
            if (++i >= argc) { std::cerr << "Error: --in requires a filename\n"; return 1; }
            in_file = argv[i];
        } else if (std::strcmp(argv[i], "--out") == 0) {
            if (++i >= argc) { std::cerr << "Error: --out requires a filename\n"; return 1; }
            out_file = argv[i];
        } else {
            std::cerr << "Error: unknown option: " << argv[i] << "\n"; return 1;
        }
    }
    if (in_file.empty()) { std::cerr << "Error: --in is required\n"; return 1; }

    // 1. Load PNG
    unsigned char* png_bytes = nullptr;
    size_t png_size = 0;
    if (lodepng_load_file(&png_bytes, &png_size, in_file.c_str())) {
        std::cerr << "Error: cannot read PNG file: " << in_file << "\n"; return 3;
    }

    LodePNGState state;
    lodepng_state_init(&state);
    state.info_raw.colortype = LCT_RGBA;
    state.info_raw.bitdepth  = 8;

    unsigned char* pixels_raw = nullptr;
    unsigned img_w = 0, img_h = 0;
    unsigned err = lodepng_decode(&pixels_raw, &img_w, &img_h, &state, png_bytes, png_size);
    free(png_bytes);
    if (err) {
        free(pixels_raw);
        lodepng_state_cleanup(&state);
        std::cerr << "Error: PNG decode failed: " << lodepng_error_text(err) << "\n"; return 3;
    }
    std::vector<uint8_t> pixels(pixels_raw, pixels_raw + img_w * img_h * 4);
    free(pixels_raw);

    // 2. Find crystals-obiwan iTXt chunk
    std::string obiwan_text;
    for (size_t i = 0; i < state.info_png.itext_num; ++i) {
        if (std::strcmp(state.info_png.itext_keys[i], "crystals-obiwan") == 0)
            obiwan_text = state.info_png.itext_strings[i];
    }
    lodepng_state_cleanup(&state);

    if (obiwan_text.empty()) {
        std::cerr << "Error: no crystals-obiwan iTXt chunk — not a pngify PNG\n"; return 2;
    }

    // 3. Parse metadata
    OBIWANMeta meta;
    try { meta = parse_obiwan_meta(obiwan_text); }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n"; return 2;
    }

    // 4. Determine y_data
    unsigned y_data = pngify_y_data(meta.format);

    // 5. Read rainbow pixels
    auto rlut = build_reverse_lut();
    std::vector<uint8_t> data;
    try {
        data = read_block(pixels.data(), img_w, rlut,
                          OBIWAN_MARGIN, y_data, meta.data_len, OBIWAN_DATA_W);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n"; return 2;
    }

    // 6. Rearmor
    std::string armored = rearmor_bytes(data, meta.format);

    // 7. Write output
    if (!out_file.empty()) {
        std::ofstream f(out_file);
        if (!f) { std::cerr << "Error: cannot write: " << out_file << "\n"; return 3; }
        f << armored;
    } else {
        std::cout << armored;
    }

    if (!out_file.empty())
        std::cout << "pngout: " << meta.format << " -> " << out_file
                  << " (" << data.size() << " bytes)\n";
    return 0;
}

// ── encaps command ────────────────────────────────────────────────────────────

static void print_usage(const char* prog) {
    std::cerr <<
        "Usage: " << prog << " tray-encaps  --in-tray <file>     [--out-png <file.png>] [--pwfile <file>]\n"
        "       " << prog << " tray-decaps  --in-png <file.png>  [--out-tray <file>]    [--pwfile <file>]\n"
        "       " << prog << " pngify       --in <file.armored>  --out <file.png>\n"
        "       " << prog << " pngout       --in <file.png>      [--out <file.armored>]\n"
        "\n"
        "  tray-encaps  Render + password-encrypt private keys into a PNG\n"
        "  tray-decaps  Decrypt and recover a tray from an encaps PNG\n"
        "  pngify       Convert an obi-wan armored file (OBIWAN/HYKE/PWENC) into a PNG\n"
        "  pngout       Recover an armored file from a pngify PNG\n"
        "\n"
        "tray-encaps options:\n"
        "  --in-tray  <file>      Input tray (YAML)\n"
        "  --out-png  <file.png>  Output PNG (default: <alias>_enc.png)\n"
        "  --pwfile   <file>      Read password from file (prompts if omitted)\n"
        "\n"
        "tray-decaps options:\n"
        "  --in-png   <file.png>  Input encaps PNG\n"
        "  --out-tray <file>      Output tray (YAML format)\n"
        "  --pwfile   <file>      Read password from file (prompts if omitted)\n"
        "\n"
        "pngify options:\n"
        "  --in  <file>           Input armored file (OBIWAN encrypted, HYKE signed, or PWENC)\n"
        "  --out <file.png>       Output PNG\n"
        "\n"
        "pngout options:\n"
        "  --in  <file.png>       Input pngify PNG\n"
        "  --out <file>           Output armored file (default: stdout)\n";
}

static int cmd_tray_encaps(int argc, char* argv[]) {
    std::string tray_file, out_file, pwfile;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--in-tray") == 0) {
            if (++i >= argc) { std::cerr << "Error: --in-tray requires a filename\n"; return 1; }
            tray_file = argv[i];
        } else if (std::strcmp(argv[i], "--out-png") == 0) {
            if (++i >= argc) { std::cerr << "Error: --out-png requires a filename\n"; return 1; }
            out_file = argv[i];
        } else if (std::strcmp(argv[i], "--pwfile") == 0) {
            if (++i >= argc) { std::cerr << "Error: --pwfile requires a filename\n"; return 1; }
            pwfile = argv[i];
        } else {
            std::cerr << "Error: unknown option: " << argv[i] << "\n"; return 1;
        }
    }
    if (tray_file.empty()) { std::cerr << "Error: --in-tray is required\n"; return 1; }

    // ── 1. Load tray ──────────────────────────────────────────────────────────
    Tray tray;
    try { tray = load_tray(tray_file); }
    catch (const std::exception& e) {
        std::cerr << "Error: failed to load tray: " << e.what() << "\n"; return 2;
    }
    if (out_file.empty()) out_file = tray.alias + "_enc.png";

    // ── 2. Get password ───────────────────────────────────────────────────────
    std::string password;
    try { password = get_password_encaps(pwfile); }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n"; return 1;
    }

    try {
        // ── 3. Key derivation ─────────────────────────────────────────────────
        auto salt     = encaps_rand(ENCAPS_SALT_LEN);           // 16 bytes
        auto wrap_key = encaps_derive_key(password, salt);       // 32 bytes (scrypt)
        auto data_key = encaps_rand(ENCAPS_KEY_LEN);             // 32 bytes

        // ── 4. Encrypt data_key → KEM blob ───────────────────────────────────
        // aes_enc returns nonce(12)||tag(16)||ct(32) = 60 bytes
        auto kem_blob = encaps_aes_enc(wrap_key, data_key);
        if (kem_blob.size() != KEM_BLOB_BYTES) {
            std::cerr << "Error: unexpected KEM blob size\n"; return 2;
        }

        // ── 5. Concatenate all sk in slot order ───────────────────────────────
        std::vector<uint8_t> all_sk;
        for (const auto& s : tray.slots)
            all_sk.insert(all_sk.end(), s.sk.begin(), s.sk.end());

        // ── 6. Encrypt all_sk → sk_blob ──────────────────────────────────────
        // aes_enc returns nonce(12)||tag(16)||ct(N)
        auto sk_blob = encaps_aes_enc(data_key, all_sk);
        // nonce=sk_blob[0..11], tag=sk_blob[12..27], ct=sk_blob[28..]
        std::vector<uint8_t> sk_nonce(sk_blob.begin(),      sk_blob.begin() + 12);
        std::vector<uint8_t> sk_tag  (sk_blob.begin() + 12, sk_blob.begin() + 28);
        // sk_enc_raw: ciphertext only, same length as all_sk
        std::vector<uint8_t> sk_enc_raw(sk_blob.begin() + 28, sk_blob.end());

        // ── 7. Split sk_enc_raw into cl and pq portions ───────────────────────
        // Walk slots in order, dispatch to cl or pq by alg type
        std::vector<uint8_t> cl_pk, cl_sk_enc, pq_pk, pq_sk_enc;
        size_t sk_off = 0;
        for (const auto& s : tray.slots) {
            if (is_pq_slot(s.alg_name)) {
                pq_pk.insert(pq_pk.end(), s.pk.begin(), s.pk.end());
                pq_sk_enc.insert(pq_sk_enc.end(),
                                  sk_enc_raw.begin() + (std::ptrdiff_t)sk_off,
                                  sk_enc_raw.begin() + (std::ptrdiff_t)(sk_off + s.sk.size()));
            } else {
                cl_pk.insert(cl_pk.end(), s.pk.begin(), s.pk.end());
                cl_sk_enc.insert(cl_sk_enc.end(),
                                  sk_enc_raw.begin() + (std::ptrdiff_t)sk_off,
                                  sk_enc_raw.begin() + (std::ptrdiff_t)(sk_off + s.sk.size()));
            }
            sk_off += s.sk.size();
        }

        // ── 8. Build encaps image ─────────────────────────────────────────────
        ImageResult img = build_encaps_image(tray, cl_pk, cl_sk_enc, pq_pk, pq_sk_enc, kem_blob);

        // 4× nearest-neighbor upscale
        img.pixels = upscale4x(img.pixels, img.w, img.h);
        img.w *= 4; img.h *= 4;

        // ── 9. Build iTXt chunks ──────────────────────────────────────────────
        EncapsMeta em;
        em.salt     = salt;
        em.n_log2   = ENCAPS_N_LOG2;
        em.r        = ENCAPS_R;
        em.p        = ENCAPS_P;
        em.sk_nonce = sk_nonce;
        em.sk_tag   = sk_tag;

        write_png(img, out_file, make_meta_text(tray, 4), make_encaps_text(em));

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n"; return 2;
    }

    std::cout << "Encaps: tray '" << tray.alias << "' \xe2\x86\x92 " << out_file
              << " (scrypt N=2^" << ENCAPS_N_LOG2 << ", AES-256-GCM)\n";
    return 0;
}

// ── decaps command ────────────────────────────────────────────────────────────

static int cmd_tray_decaps(int argc, char* argv[]) {
    std::string png_file, out_file, pwfile;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--in-png") == 0) {
            if (++i >= argc) { std::cerr << "Error: --in-png requires a filename\n"; return 1; }
            png_file = argv[i];
        } else if (std::strcmp(argv[i], "--out-tray") == 0) {
            if (++i >= argc) { std::cerr << "Error: --out-tray requires a filename\n"; return 1; }
            out_file = argv[i];
        } else if (std::strcmp(argv[i], "--pwfile") == 0) {
            if (++i >= argc) { std::cerr << "Error: --pwfile requires a filename\n"; return 1; }
            pwfile = argv[i];
        } else {
            std::cerr << "Error: unknown option: " << argv[i] << "\n"; return 1;
        }
    }
    if (png_file.empty()) { std::cerr << "Error: --in-png is required\n"; return 1; }

    // ── 1. Load PNG ───────────────────────────────────────────────────────────
    unsigned char* png_bytes = nullptr;
    size_t png_size = 0;
    if (lodepng_load_file(&png_bytes, &png_size, png_file.c_str()))
        { std::cerr << "Error: cannot read PNG file: " << png_file << "\n"; return 3; }

    LodePNGState state;
    lodepng_state_init(&state);
    state.info_raw.colortype = LCT_RGBA;
    state.info_raw.bitdepth  = 8;

    unsigned char* pixels_raw2 = nullptr;
    unsigned img_w = 0, img_h = 0;
    unsigned err = lodepng_decode(&pixels_raw2, &img_w, &img_h, &state, png_bytes, png_size);
    free(png_bytes);
    if (err) {
        free(pixels_raw2);
        lodepng_state_cleanup(&state);
        std::cerr << "Error: PNG decode failed: " << lodepng_error_text(err) << "\n";
        return 3;
    }

    // Take ownership into a vector so all error paths are clean.
    std::vector<uint8_t> pixel_vec2(pixels_raw2, pixels_raw2 + img_w * img_h * 4);
    free(pixels_raw2);

    // ── 2. Extract both iTXt chunks ───────────────────────────────────────────
    std::string meta_text, encaps_text;
    for (size_t i = 0; i < state.info_png.itext_num; ++i) {
        if (std::strcmp(state.info_png.itext_keys[i], "crystals-tray") == 0)
            meta_text   = state.info_png.itext_strings[i];
        if (std::strcmp(state.info_png.itext_keys[i], "crystals-encaps") == 0)
            encaps_text = state.info_png.itext_strings[i];
    }
    lodepng_state_cleanup(&state);

    if (meta_text.empty()) {
        std::cerr << "Error: no crystals-tray iTXt chunk — not a padme PNG\n";
        return 2;
    }
    if (encaps_text.empty()) {
        std::cerr << "Error: no crystals-encaps chunk — not an encaps PNG; use 'decode'\n";
        return 2;
    }

    TrayMeta meta;
    EncapsMeta em;
    try {
        meta = parse_meta(meta_text);
        em   = parse_encaps_meta(encaps_text);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n"; return 2;
    }

    // ── 2a. Downscale if the PNG was upscaled ─────────────────────────────────
    if (meta.scale == 4) {
        pixel_vec2 = downscale4x(pixel_vec2, img_w, img_h);
        img_w /= 4; img_h /= 4;
    }

    // ── 3. Look up profile ────────────────────────────────────────────────────
    auto pit = PROFILES.find(meta.profile);
    if (pit == PROFILES.end()) {
        std::cerr << "Error: unknown profile '" << meta.profile << "'\n";
        return 2;
    }
    const auto& slot_defs = pit->second;

    // ── 4. Compute byte counts ────────────────────────────────────────────────
    size_t cl_pk_bytes = 0, cl_sk_bytes = 0, pq_pk_bytes = 0, pq_sk_bytes = 0;
    for (const auto& sd : slot_defs) {
        if (is_pq_slot(sd.alg_name)) {
            pq_pk_bytes += sd.pk_size;
            pq_sk_bytes += sd.sk_size;
        } else {
            cl_pk_bytes += sd.pk_size;
            cl_sk_bytes += sd.sk_size;
        }
    }

    // ── 5. Reconstruct encaps image geometry ──────────────────────────────────
    unsigned cl_rows = std::max(row_count_cw(cl_pk_bytes, ENCAPS_COL_W),
                                 row_count_cw(cl_sk_bytes, ENCAPS_COL_W));
    unsigned pq_rows = std::max(row_count_cw(pq_pk_bytes, ENCAPS_COL_W),
                                 row_count_cw(pq_sk_bytes, ENCAPS_COL_W));

    unsigned y_keys = ENCAPS_MARGIN + LINE_SPACING + FONT_H + ENCAPS_GAP;  // = 38
    unsigned y_cl   = y_keys;
    unsigned y_pq   = y_cl + cl_rows + (cl_rows > 0 && pq_rows > 0 ? ENCAPS_GAP : 0);

    unsigned total_key_h = cl_rows + (cl_rows > 0 && pq_rows > 0 ? ENCAPS_GAP : 0) + pq_rows;
    if (total_key_h == 0) total_key_h = 1;
    unsigned y_kem = y_keys + total_key_h + ENCAPS_GAP;

    unsigned content_w = ENCAPS_IMG_W - 2 * ENCAPS_MARGIN;
    unsigned x_pk  = ENCAPS_MARGIN;
    unsigned x_sk  = ENCAPS_MARGIN + ENCAPS_COL_W + ENCAPS_GAP;
    unsigned x_kem = ENCAPS_MARGIN + (content_w - KEM_BLOB_BYTES) / 2;

    // ── 6. Read pixel blocks ──────────────────────────────────────────────────
    auto rlut = build_reverse_lut();
    const uint8_t* pixels2 = pixel_vec2.data();
    std::vector<uint8_t> cl_pk_data, cl_sk_enc, pq_pk_data, pq_sk_enc, kem_raw;
    try {
        if (cl_rows > 0) {
            cl_pk_data = read_block(pixels2, img_w, rlut, x_pk, y_cl, cl_pk_bytes, ENCAPS_COL_W);
            cl_sk_enc  = read_block(pixels2, img_w, rlut, x_sk, y_cl, cl_sk_bytes, ENCAPS_COL_W);
        }
        if (pq_rows > 0) {
            pq_pk_data = read_block(pixels2, img_w, rlut, x_pk, y_pq, pq_pk_bytes, ENCAPS_COL_W);
            pq_sk_enc  = read_block(pixels2, img_w, rlut, x_sk, y_pq, pq_sk_bytes, ENCAPS_COL_W);
        }
        kem_raw = read_block(pixels2, img_w, rlut, x_kem, y_kem, KEM_BLOB_BYTES, KEM_BLOB_BYTES);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n"; return 2;
    }

    // ── 7. Get password and derive wrap_key ───────────────────────────────────
    std::string password;
    try { password = get_password_decaps(pwfile); }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n"; return 1;
    }

    std::vector<uint8_t> wrap_key;
    try { wrap_key = encaps_derive_key(password, em.salt, em.n_log2); }
    catch (const std::exception& e) {
        std::cerr << "Error: key derivation failed: " << e.what() << "\n"; return 2;
    }
    OPENSSL_cleanse((void*)password.data(), password.size());

    // ── 8. Decrypt data_key from KEM block ────────────────────────────────────
    // kem_raw = nonce(12)||tag(16)||ct(32) — same format as aes_enc output
    std::vector<uint8_t> data_key;
    try {
        data_key = encaps_aes_dec(wrap_key, kem_raw);
    } catch (const std::exception&) {
        OPENSSL_cleanse(wrap_key.data(), wrap_key.size());
        std::cerr << "Error: decryption failed — wrong password or corrupted image\n";
        return 2;
    }
    OPENSSL_cleanse(wrap_key.data(), wrap_key.size());

    // ── 9. Reconstruct all_sk_enc in slot order ───────────────────────────────
    std::vector<uint8_t> all_sk_enc;
    size_t cl_sk_off = 0, pq_sk_off = 0;
    for (const auto& sd : slot_defs) {
        if (is_pq_slot(sd.alg_name)) {
            all_sk_enc.insert(all_sk_enc.end(),
                               pq_sk_enc.begin() + (std::ptrdiff_t)pq_sk_off,
                               pq_sk_enc.begin() + (std::ptrdiff_t)(pq_sk_off + sd.sk_size));
            pq_sk_off += sd.sk_size;
        } else {
            all_sk_enc.insert(all_sk_enc.end(),
                               cl_sk_enc.begin() + (std::ptrdiff_t)cl_sk_off,
                               cl_sk_enc.begin() + (std::ptrdiff_t)(cl_sk_off + sd.sk_size));
            cl_sk_off += sd.sk_size;
        }
    }

    // ── 10. Decrypt all_sk ────────────────────────────────────────────────────
    // Reassemble nonce(12)||tag(16)||ct for AES-GCM
    std::vector<uint8_t> sk_blob;
    sk_blob.insert(sk_blob.end(), em.sk_nonce.begin(), em.sk_nonce.end());
    sk_blob.insert(sk_blob.end(), em.sk_tag.begin(),   em.sk_tag.end());
    sk_blob.insert(sk_blob.end(), all_sk_enc.begin(),  all_sk_enc.end());

    std::vector<uint8_t> all_sk;
    try {
        all_sk = encaps_aes_dec(data_key, sk_blob);
    } catch (const std::exception&) {
        OPENSSL_cleanse(data_key.data(), data_key.size());
        std::cerr << "Error: SK decryption failed — corrupted image or metadata\n";
        return 2;
    }
    OPENSSL_cleanse(data_key.data(), data_key.size());

    // ── 11. Split all_sk into per-slot sk ─────────────────────────────────────
    std::vector<uint8_t> cl_pk_data_dec, cl_sk_data, pq_pk_data_dec, pq_sk_data;
    // pk data for reconstruction (same as from image)
    cl_pk_data_dec = cl_pk_data;
    pq_pk_data_dec = pq_pk_data;

    size_t all_sk_off = 0;
    for (const auto& sd : slot_defs) {
        auto sk = std::vector<uint8_t>(all_sk.begin() + (std::ptrdiff_t)all_sk_off,
                                        all_sk.begin() + (std::ptrdiff_t)(all_sk_off + sd.sk_size));
        all_sk_off += sd.sk_size;
        if (is_pq_slot(sd.alg_name))
            pq_sk_data.insert(pq_sk_data.end(), sk.begin(), sk.end());
        else
            cl_sk_data.insert(cl_sk_data.end(), sk.begin(), sk.end());
    }
    OPENSSL_cleanse(all_sk.data(), all_sk.size());

    // ── 12. Reconstruct Tray ──────────────────────────────────────────────────
    Tray tray;
    tray.version       = 1;
    tray.alias         = meta.alias;
    tray.id            = meta.id;
    tray.type_str      = meta.profile;
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

    size_t cl_pk_off = 0, cl_sk_off2 = 0, pq_pk_off = 0, pq_sk_off2 = 0;
    for (const auto& sd : slot_defs) {
        Slot s;
        s.alg_name = sd.alg_name;
        if (is_pq_slot(sd.alg_name)) {
            s.pk = std::vector<uint8_t>(pq_pk_data_dec.begin() + (std::ptrdiff_t)pq_pk_off,
                                         pq_pk_data_dec.begin() + (std::ptrdiff_t)(pq_pk_off + sd.pk_size));
            pq_pk_off += sd.pk_size;
            s.sk = std::vector<uint8_t>(pq_sk_data.begin() + (std::ptrdiff_t)pq_sk_off2,
                                         pq_sk_data.begin() + (std::ptrdiff_t)(pq_sk_off2 + sd.sk_size));
            pq_sk_off2 += sd.sk_size;
        } else {
            s.pk = std::vector<uint8_t>(cl_pk_data_dec.begin() + (std::ptrdiff_t)cl_pk_off,
                                         cl_pk_data_dec.begin() + (std::ptrdiff_t)(cl_pk_off + sd.pk_size));
            cl_pk_off += sd.pk_size;
            s.sk = std::vector<uint8_t>(cl_sk_data.begin() + (std::ptrdiff_t)cl_sk_off2,
                                         cl_sk_data.begin() + (std::ptrdiff_t)(cl_sk_off2 + sd.sk_size));
            cl_sk_off2 += sd.sk_size;
        }
        tray.slots.push_back(std::move(s));
    }

    // ── 13. Output ────────────────────────────────────────────────────────────
    if (!out_file.empty()) {
        if (!write_tray_file(tray, out_file, "Decaps")) return 3;
    } else {
        try { std::cout << emit_tray_yaml(tray); }
        catch (const std::exception& e) {
            std::cerr << "Error: YAML output failed: " << e.what() << "\n"; return 3;
        }
    }
    return 0;
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) { print_usage(argv[0]); return 1; }

    const std::string cmd = argv[1];
    if (cmd == "tray-encaps") return cmd_tray_encaps(argc - 1, argv + 1);
    if (cmd == "tray-decaps") return cmd_tray_decaps(argc - 1, argv + 1);
    if (cmd == "pngify")      return cmd_pngify(argc - 1, argv + 1);
    if (cmd == "pngout")      return cmd_pngout(argc - 1, argv + 1);
    if (cmd == "--help" || cmd == "-h") { print_usage(argv[0]); return 0; }

    std::cerr << "Error: unknown command '" << cmd << "'\n";
    print_usage(argv[0]);
    return 1;
}
