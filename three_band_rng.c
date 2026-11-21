#include "three_band_rng.h"

#include <math.h>
#include <stddef.h>

/* Wire-compatible sampling for this profile. The matching NumPy v2.3.5
 * algorithms are in numpy/random/bit_generator.pyx, _generator.pyx,
 * src/pcg64/pcg64.h and src/distributions/distributions.c.
 * See LICENSE.numpy-three-band for upstream notices. */
static uint32_t seed_hash(uint32_t input, uint32_t *salt, uint32_t multiplier)
{
    uint32_t word = input ^ *salt;
    *salt *= multiplier;
    word *= *salt;
    return word ^ (word >> 16);
}

static uint32_t seed_mix(uint32_t previous, uint32_t incoming)
{
    uint32_t word = UINT32_C(0xca01f9dd) * previous - UINT32_C(0x4973f715) * incoming;
    return word ^ (word >> 16);
}

static __uint128_t join_u64(uint64_t high, uint64_t low)
{
    return ((__uint128_t)high << 64) | low;
}

static void advance(tb_rng *rng)
{
    const __uint128_t multiplier = join_u64(UINT64_C(2549297995355413924),
                                            UINT64_C(4865540595714422341));
    rng->state = rng->state * multiplier + rng->increment;
}

/* Each Python integer contributes its shortest nonempty LE32 sequence. */
static void initialize(tb_rng *rng, const uint64_t *seeds, size_t count)
{
    uint32_t words[8], pool[4];
    const uint32_t entropy_multiplier = UINT32_C(0x931e8875);
    uint32_t salt = UINT32_C(0x43b0d7e5);
    size_t length = 0;
    for (size_t i = 0; i < count; ++i) {
        words[length++] = (uint32_t)seeds[i];
        uint32_t high = (uint32_t)(seeds[i] >> 32);
        if (high) words[length++] = high;
    }
    for (size_t i = 0; i < 4; ++i)
        pool[i] = seed_hash(i < length ? words[i] : 0, &salt, entropy_multiplier);
    for (size_t src = 0; src < 4; ++src)
        for (size_t dst = 0; dst < 4; ++dst)
            if (src != dst)
                pool[dst] = seed_mix(pool[dst], seed_hash(pool[src], &salt, entropy_multiplier));
    for (size_t i = 4; i < length; ++i)
        for (size_t dst = 0; dst < 4; ++dst)
            pool[dst] = seed_mix(pool[dst], seed_hash(words[i], &salt, entropy_multiplier));

    /* SeedSequence.generate_state(4, uint64) joins adjacent LE32 words. */
    salt = UINT32_C(0x8b51f9dd);
    uint64_t state_words[4] = {0};
    for (size_t i = 0; i < 8; ++i) {
        uint32_t word = seed_hash(pool[i % 4], &salt, UINT32_C(0x58f38ded));
        state_words[i / 2] |= (uint64_t)word << (32 * (i % 2));
    }

    __uint128_t initial = join_u64(state_words[0], state_words[1]);
    __uint128_t stream = join_u64(state_words[2], state_words[3]);
    rng->increment = (stream << 1) | 1;
    rng->state = initial + rng->increment;
    advance(rng);
    rng->buffered = 0;
    rng->have_buffered = 0;
}

void tb_rng_seed(tb_rng *rng, uint64_t seed)
{
    initialize(rng, &seed, 1);
}

void tb_rng_seed_signs(tb_rng *rng, uint64_t n, uint64_t pattern_seed, uint64_t sign_draw)
{
    const uint64_t seeds[] = {n, pattern_seed, sign_draw, 7531};
    initialize(rng, seeds, 4);
}

static uint64_t next_u64(tb_rng *rng)
{
    advance(rng);
    uint64_t word = (uint64_t)(rng->state >> 64) ^ (uint64_t)rng->state;
    unsigned rotation = (unsigned)(rng->state >> 122);
    return (word >> rotation) | (word << ((0u - rotation) & 63));
}

static uint32_t next_u32(tb_rng *rng)
{
    if (rng->have_buffered) {
        rng->have_buffered = 0;
        return rng->buffered;
    }
    uint64_t word = next_u64(rng);
    rng->buffered = (uint32_t)(word >> 32);
    rng->have_buffered = 1;
    return (uint32_t)word;
}

double tb_rng_uniform(tb_rng *rng)
{
    return (double)(next_u64(rng) >> 11) * 0x1p-53;
}

static double gumbel_uniform(tb_rng *rng)
{
    double u;
    do {
        u = 1.0 - tb_rng_uniform(rng);
    } while (u == 1.0);
    return u;
}

double tb_rng_gumbel(tb_rng *rng)
{
    return -log(-log(gumbel_uniform(rng)));
}

void tb_rng_discard_gumbels(tb_rng *rng, uint64_t count)
{
    for (uint64_t i = 0; i < count; ++i) (void)gumbel_uniform(rng);
}

void tb_rng_permutation3(tb_rng *rng, unsigned bands[3])
{
    bands[0] = 0;
    bands[1] = 1;
    bands[2] = 2;
    /* NumPy shuffle uses masked rejection, first for [0,2], then [0,1]. */
    unsigned j;
    do {
        j = next_u32(rng) & 3u;
    } while (j > 2);
    bands[2] = bands[j];
    bands[j] = 2;
    j = next_u32(rng) & 1u;
    unsigned tmp = bands[1];
    bands[1] = bands[j];
    bands[j] = tmp;
}

int tb_rng_sign(tb_rng *rng)
{
    /* choice([-1.,1.]) calls integers(0,2,dtype=int64). For this bound
     * NumPy's uint32 multiply-high sampler returns the most significant bit. */
    return (next_u32(rng) >> 31) ? 1 : -1;
}
