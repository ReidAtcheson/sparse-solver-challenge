#include "../three_band_rng.h"

#include <assert.h>
#include <float.h>
#include <math.h>
#include <stdio.h>

/* Known answers from numpy==2.3.5: random(), permutation(3) twice,
 * gumbel(size=3), gumbel(size=107), permutation(3), random(). */
struct vector {
    uint64_t seed;
    double first, last;
    unsigned permutation[3][3];
    double gumbels[3];
};

static void check_permutation(tb_rng *rng, const unsigned expected[3])
{
    unsigned actual[3];
    tb_rng_permutation3(rng, actual);
    for (unsigned i = 0; i < 3; ++i) assert(actual[i] == expected[i]);
}

static void check_mixed_calls(const struct vector *v)
{
    tb_rng rng;
    tb_rng_seed(&rng, v->seed);
    assert(tb_rng_uniform(&rng) == v->first);
    check_permutation(&rng, v->permutation[0]);
    check_permutation(&rng, v->permutation[1]);
    for (unsigned i = 0; i < 3; ++i) {
        double draw = tb_rng_gumbel(&rng);
        /* The sequence of underlying uniform draws is exact. Different
         * libm implementations can round either of Gumbel's logarithms differently. */
        assert(fabs(draw - v->gumbels[i]) < 4 * DBL_EPSILON * fmax(1.0, fabs(draw)));
    }
    tb_rng_discard_gumbels(&rng, 107);
    check_permutation(&rng, v->permutation[2]);
    assert(tb_rng_uniform(&rng) == v->last);
}

static void check_signs(uint64_t n, uint64_t pattern, uint64_t draw, const char *expected)
{
    tb_rng rng;
    tb_rng_seed_signs(&rng, n, pattern, draw);
    /* The oracle first called choice([-1.,1.], size=7), then size=9. */
    for (; *expected; ++expected)
        assert(tb_rng_sign(&rng) == (*expected == '1' ? 1 : -1));
}

static void check_zero_rejection(void)
{
    /* The first PCG output of this state is 1, so the 53-bit uniform is zero. */
    tb_rng with_rejection = {.state = 0, .increment = 1};
    tb_rng already_skipped = with_rejection;
    tb_rng discarded = with_rejection;
    assert(tb_rng_uniform(&already_skipped) == 0);
    assert(tb_rng_gumbel(&with_rejection) == tb_rng_gumbel(&already_skipped));
    tb_rng_discard_gumbels(&discarded, 1);
    assert(tb_rng_uniform(&discarded) == tb_rng_uniform(&already_skipped));
}

int main(void)
{
    const struct vector vectors[] = {
        {0, 0x1.461fd79fb3850p-1, 0x1.06884fb64c764p-1, {{2,0,1}, {2,1,0}, {0,2,1}},
         {0x1.060aa6ce1f01bp+2, -0x1.090a75e3e4cefp-1, -0x1.c88079d07016bp-1}},
        {UINT64_MAX, 0x1.5c2c74f5188eap-1, 0x1.f8be5489a29e0p-6, {{0,2,1}, {0,1,2}, {2,0,1}},
         {-0x1.9f2033a47cdddp-1, 0x1.fadf4f43e9489p+0, 0x1.ea19beb5f15ffp-1}}
    };
    for (unsigned i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i)
        check_mixed_calls(&vectors[i]);
    check_signs(511, 21, 1, "1000010001010111");
    check_signs(UINT64_C(4294967297), UINT64_MAX, UINT64_C(9223372036854775817),
                "1010111100101111");
    check_zero_rejection();
    puts("PASS three-band NumPy 2.3.5 RNG vectors");
    return 0;
}
