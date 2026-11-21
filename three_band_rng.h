#ifndef STENCIL_THREE_BAND_RNG_H
#define STENCIL_THREE_BAND_RNG_H

#include <stdint.h>

/* State for the NumPy 2.3.5 default_rng(SeedSequence) stream. A 32-bit
 * draw can leave half a word buffered through subsequent binary64 draws. */
typedef struct {
    __uint128_t state;
    __uint128_t increment;
    uint32_t buffered;
    int have_buffered;
} tb_rng;

void tb_rng_seed(tb_rng *rng, uint64_t seed);
void tb_rng_seed_signs(tb_rng *rng, uint64_t n, uint64_t pattern_seed,
                       uint64_t sign_draw);
double tb_rng_uniform(tb_rng *rng);
double tb_rng_gumbel(tb_rng *rng);
void tb_rng_discard_gumbels(tb_rng *rng, uint64_t count);
void tb_rng_permutation3(tb_rng *rng, unsigned bands[3]);
int tb_rng_sign(tb_rng *rng);

#endif
