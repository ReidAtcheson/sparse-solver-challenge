#include "drand.h"

/* Trust parameters published by drand at
 * https://docs.drand.love/blog/2023/10/16/quicknet-is-live/ */
const uint8_t drand_quicknet_chain_hash[32] = {
    0x52, 0xdb, 0x9b, 0xa7, 0x0e, 0x0c, 0xc0, 0xf6,
    0xea, 0xf7, 0x80, 0x3d, 0xd0, 0x74, 0x47, 0xa1,
    0xf5, 0x47, 0x77, 0x35, 0xfd, 0x3f, 0x66, 0x17,
    0x92, 0xba, 0x94, 0x60, 0x0c, 0x84, 0xe9, 0x71
};

int drand_quicknet_time(uint64_t round, uint64_t *scheduled_ns)
{
    const uint64_t genesis = 1692803367, period = 3, ns_per_sec = 1000000000;
    const uint64_t last_delta = (UINT64_MAX / ns_per_sec - genesis) / period;
    if (!scheduled_ns || !round || round - 1 > last_delta) return 0;
    *scheduled_ns = (genesis + period * (round - 1)) * ns_per_sec;
    return 1;
}

#if defined(STENCIL_HAVE_BLST) && STENCIL_HAVE_BLST
#include <stdbool.h>
#include <blst.h>
#include <openssl/sha.h>
#include <string.h>

static const uint8_t public_key[96] = {
    0x83, 0xcf, 0x0f, 0x28, 0x96, 0xad, 0xee, 0x7e,
    0xb8, 0xb5, 0xf0, 0x1f, 0xca, 0xd3, 0x91, 0x22,
    0x12, 0xc4, 0x37, 0xe0, 0x07, 0x3e, 0x91, 0x1f,
    0xb9, 0x00, 0x22, 0xd3, 0xe7, 0x60, 0x18, 0x3c,
    0x8c, 0x4b, 0x45, 0x0b, 0x6a, 0x0a, 0x6c, 0x3a,
    0xc6, 0xa5, 0x77, 0x6a, 0x2d, 0x10, 0x64, 0x51,
    0x0d, 0x1f, 0xec, 0x75, 0x8c, 0x92, 0x1c, 0xc2,
    0x2b, 0x0e, 0x17, 0xe6, 0x3a, 0xaf, 0x4b, 0xcb,
    0x5e, 0xd6, 0x63, 0x04, 0xde, 0x9c, 0xf8, 0x09,
    0xbd, 0x27, 0x4c, 0xa7, 0x3b, 0xab, 0x4a, 0xf5,
    0xa6, 0xe9, 0xc7, 0x6a, 0x4b, 0xc0, 0x9e, 0x76,
    0xea, 0xe8, 0x99, 0x1e, 0xf5, 0xec, 0xe4, 0x5a
};

int drand_quicknet_available(void) { return 1; }

int drand_quicknet_verify(uint64_t expected_round, const uint8_t signature[48],
                         uint8_t randomness[32], uint64_t *scheduled_ns)
{
    static const uint8_t dst[] = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
    blst_p1_affine sig;
    blst_p2_affine pk;
    uint8_t round_be[8], message[32], canonical[48], seed[32];
    uint64_t time_ns;
    if (!signature || !randomness || !scheduled_ns ||
        !drand_quicknet_time(expected_round, &time_ns)) return 0;
    if (blst_p1_uncompress(&sig, signature) != BLST_SUCCESS ||
        blst_p1_affine_is_inf(&sig) || !blst_p1_affine_in_g1(&sig)) return 0;
    blst_p1_affine_compress(canonical, &sig);
    if (memcmp(canonical, signature, sizeof canonical) ||
        blst_p2_uncompress(&pk, public_key) != BLST_SUCCESS ||
        blst_p2_affine_is_inf(&pk) || !blst_p2_affine_in_g2(&pk)) return 0;

    /* Quicknet signs SHA256(uint64_be(round)). The random bytes returned by
     * drand are a separate SHA256 of the verified serialized signature. */
    for (unsigned i = 0; i < sizeof round_be; ++i)
        round_be[sizeof round_be - 1 - i] = (uint8_t)(expected_round >> (8 * i));
    if (!SHA256(round_be, sizeof round_be, message) ||
        blst_core_verify_pk_in_g2(&pk, &sig, true, message, sizeof message,
                                  dst, sizeof dst - 1, NULL, 0) != BLST_SUCCESS ||
        !SHA256(signature, sizeof canonical, seed)) return 0;
    memcpy(randomness, seed, sizeof seed);
    *scheduled_ns = time_ns;
    return 1;
}

#else
int drand_quicknet_available(void) { return 0; }

int drand_quicknet_verify(uint64_t expected_round, const uint8_t signature[48],
                         uint8_t randomness[32], uint64_t *scheduled_ns)
{
    (void)expected_round;
    (void)signature;
    (void)randomness;
    (void)scheduled_ns;
    return 0;
}
#endif
