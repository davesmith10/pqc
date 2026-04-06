// oqs_ops.cpp — liboqs-backed KEM and signature operations for the
// oqs_kem and oqs_sig namespaces.  These implement the @api-stable v1.2
// declarations in crystals/crystals.hpp.
//
// Supported KEM algorithms:   ML-KEM-512, ML-KEM-768, ML-KEM-1024,
//                             FrodoKEM-640-AES, FrodoKEM-976-AES, FrodoKEM-1344-AES
// Supported signature algos:  ML-DSA-44, ML-DSA-65, ML-DSA-87,
//                             Falcon-512, Falcon-1024

#include "oqs_ops.hpp"
#include <stdexcept>
#include <string>

extern "C" {
#include <oqs/oqs.h>
}

namespace oqs_kem {

Keys keygen(const std::string& alg_name) {
    OQS_KEM* kem = OQS_KEM_new(alg_name.c_str());
    if (!kem)
        throw std::runtime_error("OQS_KEM_new failed: unknown or disabled algorithm: " + alg_name);

    Keys keys;
    keys.pk.resize(kem->length_public_key);
    keys.sk.resize(kem->length_secret_key);

    if (kem->keypair(keys.pk.data(), keys.sk.data()) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        throw std::runtime_error("OQS KEM keypair failed for: " + alg_name);
    }

    OQS_KEM_free(kem);
    return keys;
}

void encaps(const std::string& alg_name,
            const std::vector<uint8_t>& pk,
            std::vector<uint8_t>& ct_out,
            std::vector<uint8_t>& ss_out)
{
    OQS_KEM* kem = OQS_KEM_new(alg_name.c_str());
    if (!kem)
        throw std::runtime_error("OQS_KEM_new failed: " + alg_name);

    ct_out.resize(kem->length_ciphertext);
    ss_out.resize(kem->length_shared_secret);

    if (kem->encaps(ct_out.data(), ss_out.data(), pk.data()) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        throw std::runtime_error("OQS KEM encaps failed for: " + alg_name);
    }

    OQS_KEM_free(kem);
}

void decaps(const std::string& alg_name,
            const std::vector<uint8_t>& sk,
            const std::vector<uint8_t>& ct,
            std::vector<uint8_t>& ss_out)
{
    OQS_KEM* kem = OQS_KEM_new(alg_name.c_str());
    if (!kem)
        throw std::runtime_error("OQS_KEM_new failed: " + alg_name);

    ss_out.resize(kem->length_shared_secret);

    if (kem->decaps(ss_out.data(), ct.data(), sk.data()) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        throw std::runtime_error("OQS KEM decaps failed for: " + alg_name);
    }

    OQS_KEM_free(kem);
}

bool is_oqs_kem(const std::string& alg_name) {
    if (alg_name.rfind("ML-KEM-", 0) == 0) return true;
    if (alg_name.rfind("FrodoKEM-", 0) == 0) return true;
    return false;
}

} // namespace oqs_kem

namespace oqs_sig {

Keys keygen(const std::string& alg_name) {
    OQS_SIG* sig = OQS_SIG_new(alg_name.c_str());
    if (!sig)
        throw std::runtime_error("OQS_SIG_new failed: unknown or disabled algorithm: " + alg_name);

    Keys keys;
    keys.pk.resize(sig->length_public_key);
    keys.sk.resize(sig->length_secret_key);

    if (sig->keypair(keys.pk.data(), keys.sk.data()) != OQS_SUCCESS) {
        OQS_SIG_free(sig);
        throw std::runtime_error("OQS SIG keypair failed for: " + alg_name);
    }

    OQS_SIG_free(sig);
    return keys;
}

bool is_oqs_sig(const std::string& alg_name) {
    if (alg_name.rfind("ML-DSA-", 0) == 0) return true;
    if (alg_name == "Falcon-512" || alg_name == "Falcon-1024") return true;
    return false;
}

size_t sig_bytes(const std::string& alg_name) {
    OQS_SIG* sig = OQS_SIG_new(alg_name.c_str());
    if (!sig)
        throw std::runtime_error("OQS_SIG_new failed: " + alg_name);
    size_t n = sig->length_signature;
    OQS_SIG_free(sig);
    return n;
}

void sign(const std::string& alg_name,
          const std::vector<uint8_t>& sk,
          const std::vector<uint8_t>& msg,
          std::vector<uint8_t>& sig_out)
{
    OQS_SIG* sig_obj = OQS_SIG_new(alg_name.c_str());
    if (!sig_obj)
        throw std::runtime_error("OQS_SIG_new failed: " + alg_name);

    sig_out.resize(sig_obj->length_signature);
    size_t actual_len = 0;

    if (sig_obj->sign(sig_out.data(), &actual_len,
                      msg.data(), msg.size(),
                      sk.data()) != OQS_SUCCESS) {
        OQS_SIG_free(sig_obj);
        throw std::runtime_error("OQS SIG sign failed for: " + alg_name);
    }

    OQS_SIG_free(sig_obj);
    sig_out.resize(actual_len);
}

bool verify(const std::string& alg_name,
            const std::vector<uint8_t>& pk,
            const std::vector<uint8_t>& msg,
            const std::vector<uint8_t>& sig)
{
    OQS_SIG* sig_obj = OQS_SIG_new(alg_name.c_str());
    if (!sig_obj)
        throw std::runtime_error("OQS_SIG_new failed: " + alg_name);

    OQS_STATUS status = sig_obj->verify(msg.data(), msg.size(),
                                        sig.data(), sig.size(),
                                        pk.data());
    OQS_SIG_free(sig_obj);
    return (status == OQS_SUCCESS);
}

} // namespace oqs_sig
