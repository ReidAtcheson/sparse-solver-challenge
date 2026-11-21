/* Compare every output row with individual, canonical libsodium operations.
   Powers of two on each side of the window thresholds exercise every MSM width. */
#include "../commit.h"
#include "../witness.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <fenv.h>
#include <float.h>
#include <math.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>

extern int sodium_init(void);
extern int crypto_core_ristretto255_from_hash(unsigned char *, const unsigned char *);
extern int crypto_core_ristretto255_add(unsigned char *, const unsigned char *, const unsigned char *);
extern int crypto_scalarmult_ristretto255(unsigned char *, const unsigned char *, const unsigned char *);
extern void crypto_core_ristretto255_scalar_negate(unsigned char *, const unsigned char *);
extern void crypto_core_ristretto255_scalar_add(unsigned char *, const unsigned char *, const unsigned char *);
extern void crypto_core_ristretto255_scalar_mul(unsigned char *, const unsigned char *, const unsigned char *);
extern void crypto_core_ristretto255_scalar_reduce(unsigned char *, const unsigned char *);

typedef unsigned char Element[32];
static uint64_t rng = UINT64_C(0x98379188b56c01bb);

static uint64_t next_word(void)
{
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}

/* Use integers exactly representable in binary64, including high-bit signed
   values and windows that need a carry into an additional most-significant digit. */
static int64_t sample(uint32_t side, uint32_t i, uint32_t j)
{
    static const int64_t edges[] = {
        INT64_MIN, INT64_MAX - 1023, -(INT64_MAX - 1023), -1, 1,
        7, -8, 15, -31, 32, 63, -127, 128, 255, -256,
        INT64_C(0xffffffffffffff) & ~INT64_C(0xfff),
        -INT64_C(0x7ffffffffffff800)
    };
    if (!i) return 0;
    if (i == 1) return edges[j % (sizeof(edges)/sizeof(*edges))];
    if (i == 2 || i == side/2 || (i + 1 == side)) {
        uint64_t word = next_word();
        unsigned shift = next_word() % 12;
        int64_t value = (int64_t)(((word >> 12) << shift) & INT64_MAX);
        return (word & 1) ? -value : value;
    }
    return 0;
}

static void signed_scalar(Element s, __int128 x)
{
    __uint128_t mag = x < 0 ? (__uint128_t)-x : (__uint128_t)x;
    memset(s, 0, 32);
    for (unsigned k = 0; k < 16; k++) s[k] = (unsigned char)(mag >> (8*k));
    if (x < 0) {
        Element neg;
        crypto_core_ristretto255_scalar_negate(neg, s);
        memcpy(s, neg, 32);
    }
}

static void check_digest(uint32_t width, uint32_t height, const unsigned char *rows,
                         const Element digest, const int *exponent)
{
    const char *domain = width == height ? "stencil-ristretto255-row-commitments-v1"
                                        : "stencil-ristretto255-rect-commitments-v1";
    if (exponent) domain = "stencil-ristretto255-wide80-row-commitments-v1";
    size_t prefix = strlen(domain);
    size_t shape = exponent ? 12 : width == height ? 4 : 8;
    size_t total = prefix + shape + 32*(size_t)height;
    unsigned char *message = malloc(total);
    Element reference;
    assert(message);
    memcpy(message, domain, prefix);
    uint32_t parts[3] = {width, height, exponent ? (uint32_t)*exponent : 0};
    for (size_t k = 0; k < shape; k++)
        message[prefix+k] = (unsigned char)(parts[k/4] >> (8*(k%4)));
    memcpy(message+prefix+shape, rows, 32*(size_t)height);
    assert(SHA256(message, total, reference));
    assert(memcmp(reference, digest, sizeof(reference)) == 0);
    free(message);
}

static void test_shape(uint32_t width, uint32_t height, const int *exponent)
{
    size_t bytes = (size_t)height * 32;
    Element *gens = calloc(width, sizeof(*gens)), *weights = calloc(height, sizeof(*weights));
    Element *fold = calloc(width, sizeof(*fold)), *expected = calloc(height, sizeof(*expected));
    unsigned char *actual = malloc(bytes);
    double *row = calloc(width, sizeof(*row));
    FILE *file = tmpfile();
    assert(gens && weights && fold && expected && actual && row && file);

    for (uint32_t j = 0; j < width; j++) {
        static const char domain[] = "stencil-ristretto255-generator-v1";
        unsigned char input[sizeof(domain)-1+4], hash[64];
        memcpy(input, domain, sizeof(domain)-1);
        for (unsigned k = 0; k < 4; k++) input[sizeof(domain)-1+k] = (unsigned char)(j >> (8*k));
        assert(SHA512(input, sizeof(input), hash));
        assert(crypto_core_ristretto255_from_hash(gens[j], hash) == 0);
    }
    for (uint32_t j = 0; j < height; j++) {
        unsigned char wide[64];
        for (size_t k = 0; k < sizeof(wide); k++) wide[k] = (unsigned char)next_word();
        crypto_core_ristretto255_scalar_reduce(weights[j], wide);
    }

    for (uint32_t i = 0; i < height; i++) {
        for (uint32_t j = 0; j < width; j++) {
            __int128 x = sample(height, i, j);
            if (exponent) x *= (__int128)1 << (15 - j % 16);
            row[j] = ldexp((double)x, exponent ? *exponent - 78 : -58);
            if (!x) continue;
            Element s, term, addend;
            signed_scalar(s, x);
            assert(crypto_scalarmult_ristretto255(term, s, gens[j]) == 0);
            assert(crypto_core_ristretto255_add(expected[i], expected[i], term) == 0);
            crypto_core_ristretto255_scalar_mul(addend, weights[i], s);
            crypto_core_ristretto255_scalar_add(fold[j], fold[j], addend);
        }
        assert(fwrite(row, sizeof(*row), width, file) == width);
    }

    rewind(file);
    Element digest;
    if (exponent) {
        int inferred;
        assert(witness_exponent(file, (uint64_t)width * height, &inferred));
        assert(inferred == *exponent);
        assert(vc_commit_wide(file, width, height, inferred, actual, digest));
        Element altered;
        assert(vc_digest_wide(width, height, inferred+1, actual, altered));
        assert(memcmp(altered, digest, 32));
    } else {
        assert(vc_commit(file, width, height, actual, digest));
    }
    assert(memcmp(actual, expected, bytes) == 0);
    check_digest(width, height, actual, digest, exponent);
    assert(vc_verify(width, height, actual, weights[0], fold[0]));
    const Element one = {1};
    crypto_core_ristretto255_scalar_add(fold[0], fold[0], one);
    assert(!vc_verify(width, height, actual, weights[0], fold[0]));

    assert(fclose(file) == 0);
    free(gens); free(weights); free(fold); free(expected); free(actual); free(row);
}

static void test_wide_reader(void)
{
    FILE *f = tmpfile();
    assert(f);
    const double values[] = {-0., 0.5, 1.5, -2.5, 3.5, 0x1p78, -0x1p78};
    const __int128 high = (__int128)1 << 78;
    const __int128 expected[] = {0, 0, 2, -2, 4, high, -high};
    size_t n = sizeof(values) / sizeof(*values);
    __int128 codes[sizeof(values) / sizeof(*values)];
    int exponent;
    assert(fwrite(values, sizeof(*values), n, f) == n);
    assert(!witness_exponent(f, n - 1, &exponent));
    assert(!witness_exponent(f, n + 1, &exponent));
    assert(witness_exponent(f, n, &exponent) && exponent == 78);
    assert(witness_pread_wide(fileno(f), codes, 3, 2, exponent));
    assert(!memcmp(codes, expected+2, 3*sizeof(*codes)) && ftell(f) == 0);
    assert(witness_read_wide(f, codes, n, exponent));
    assert(!memcmp(codes, expected, sizeof(expected)));
    rewind(f);
    assert(!witness_read_wide(f, codes, n, 77));
    fclose(f);
    const double edges[] = {0, -0x1p-1074, 0x1.8p-32, DBL_MAX, INFINITY, NAN};
    const int exponents[] = {0, -1074, -31, 1024};
    for (size_t i = 0; i < sizeof(edges)/sizeof(*edges); i++) {
        f = tmpfile();
        assert(f && fwrite(edges+i, sizeof(*edges), 1, f) == 1);
        if (isfinite(edges[i])) {
            assert(witness_exponent(f, 1, &exponent) && exponent == exponents[i]);
            assert(witness_read_wide(f, codes, 1, exponent));
            assert(scalbn((double)codes[0], exponent - 78) == edges[i]);
        } else {
            assert(!witness_exponent(f, 1, &exponent));
            rewind(f);
            assert(!witness_read_wide(f, codes, 1, 0));
        }
        fclose(f);
    }
}

int main(void)
{
    assert(sodium_init() >= 0 && fesetround(FE_TONEAREST) == 0);
    const uint32_t sides[] = {1, 8, 32, 64, 128, 256, 512, 1024};
    for (size_t i = 0; i < sizeof(sides)/sizeof(*sides); i++) test_shape(sides[i], sides[i], NULL);
    test_shape(32, 64, NULL);
    test_shape(64, 32, NULL);
    const int e = -31;
    test_wide_reader();
    test_shape(32, 64, &e);
    test_shape(64, 4, &e);
    test_shape(256, 4, &e);
    test_shape(1024, 4, &e);
    puts("PASS legacy and shared-exponent commitments, quantization, random folds and altered openings");
    return 0;
}
