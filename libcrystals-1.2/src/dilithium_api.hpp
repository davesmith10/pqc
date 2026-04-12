#pragma once
#include <cstdint>
#include <cstddef>
#include <stdexcept>

// Merged Dilithium API: keypair (hybrid) + sign/verify (zorro)

extern "C" {

int pqcrystals_dilithium2_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_dilithium3_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_dilithium5_ref_keypair(uint8_t *pk, uint8_t *sk);

int pqcrystals_dilithium2_ref_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *ctx, size_t ctxlen,
                                        const uint8_t *sk);
int pqcrystals_dilithium2_ref_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk);

int pqcrystals_dilithium3_ref_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *ctx, size_t ctxlen,
                                        const uint8_t *sk);
int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk);

int pqcrystals_dilithium5_ref_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *ctx, size_t ctxlen,
                                        const uint8_t *sk);
int pqcrystals_dilithium5_ref_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk);

} // extern "C"

struct DilithiumSizes {
    size_t pk_bytes;
    size_t sk_bytes;
};

inline DilithiumSizes dilithium_sizes(int mode) {
    switch (mode) {
        case 2: return {1312, 2560};
        case 3: return {1952, 4032};
        case 5: return {2592, 4896};
        default: throw std::invalid_argument("Invalid Dilithium mode: must be 2, 3, or 5");
    }
}

// Signature size constants (from dilithium/ref/api.h)
static constexpr size_t DILITHIUM2_SIG_BYTES = 2420;
static constexpr size_t DILITHIUM3_SIG_BYTES = 3309;
static constexpr size_t DILITHIUM5_SIG_BYTES = 4627;
