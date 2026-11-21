#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64
#include "commit.h"
#include "beacon.h"
#include "library_internal.h"
#include "field.h"
#include "fold.h"
#include "witness.h"
#include "mask.h"
#include "matrix.h"
#include "operator.h"
#include "scratch.h"
#include "receipt.h"

#include <errno.h>
#include <fenv.h>
#include <float.h>
#include <inttypes.h>
#include <math.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum { MAX_BITS = 30 };
static const unsigned char magic[8] = {'S', 'T', 'N', 'P', 'R', 'F', '0', '1'};
static const unsigned char wide_magic[8] = {'S', 'T', 'N', 'P', 'R', 'F', '0', '2'};
static const unsigned char beacon_magic[8] = "STNPRF03";
static const int64_t scale = INT64_C(1) << 58;
_Static_assert(sizeof(double) == 8 && DBL_MANT_DIG == 53 && DBL_MAX_EXP == 1024,
               "binary64 required");

static void die(const char *message)
{
    fprintf(stderr, "stencil: %s\n", message);
    exit(1);
}

static void *alloc_items(size_t count, size_t bytes)
{
    void *p = calloc(count, bytes);
    if (!p)
        die("allocation failed");
    return p;
}

static void read_all(FILE *f, void *p, size_t size)
{
    if (fread(p, 1, size, f) != size)
        die("truncated file or read error");
}

static void write_all(FILE *f, const void *p, size_t size)
{
    if (fwrite(p, 1, size, f) != size)
        die("write failed");
}

static void end_input(FILE *f)
{
    if (fgetc(f) != EOF || ferror(f))
        die("trailing bytes or read error");
}

static void close_file(FILE *f)
{
    if (fclose(f))
        die("file close failed");
}

static void to_start(FILE *f)
{
    if (fseeko(f, 0, SEEK_SET))
        die("file seek failed");
}

static FILE *open_file(const char *path, const char *mode)
{
    FILE *f = fopen(path, mode);
    if (!f) {
        perror(path);
        exit(1);
    }
    return f;
}

/* A commit writes a reconstructible row cache then its digest. If interrupted
 * between those publications, retrying can reuse the identical first file. */
static int same_output(FILE *source, const char *path)
{
    FILE *existing = fopen(path, "rb");
    if (!existing)
        return 0;
    to_start(source);
    unsigned char a[4096], b[4096];
    size_t n;
    int equal = 1;
    while ((n = fread(a, 1, sizeof(a), source)) > 0) {
        if (fread(b, 1, n, existing) != n || memcmp(a, b, n)) {
            equal = 0;
            break;
        }
    }
    if (ferror(source) || fgetc(existing) != EOF || ferror(existing))
        equal = 0;
    if (fclose(existing))
        equal = 0;
    return equal;
}

/* link() publishes a complete file without replacing conflicting content. */
static void publish(FILE *source, const char *path)
{
    size_t len = strlen(path) + 8;
    char *tmp = alloc_items(len, 1);
    snprintf(tmp, len, "%s.XXXXXX", path);
    int fd = mkstemp(tmp);
    if (fd < 0)
        die("cannot create output beside destination");
    FILE *out = fdopen(fd, "wb");
    if (!out) {
        close(fd);
        unlink(tmp);
        die("fdopen failed");
    }
    to_start(source);
    unsigned char buf[16384];
    size_t n;
    int ok = 1;
    while ((n = fread(buf, 1, sizeof(buf), source)) > 0)
        if (fwrite(buf, 1, n, out) != n) {
            ok = 0;
            break;
        }
    if (ferror(source) || fflush(out) || fsync(fd))
        ok = 0;
    if (fclose(out))
        ok = 0;
    if (ok && link(tmp, path))
        ok = errno == EEXIST && same_output(source, path);
    unlink(tmp);
    free(tmp);
    if (!ok)
        die("cannot publish file (conflicting destination or I/O error)");
}

static void publish_bytes(const char *path, const void *p, size_t n)
{
    FILE *f = private_scratch();
    write_all(f, p, n);
    publish(f, path);
    close_file(f);
}

/* An odd number of Boolean variables gives a rectangular commitment table. */
typedef struct {
    uint64_t n;
    unsigned bits;
    uint32_t width, height;
} Layout;

static Layout grid_layout(const struct rc_info *info)
{
    uint64_t n = matrix_size(info->side, info->dimensions);
    if (!n || n > (UINT64_C(1) << MAX_BITS) || (n & (n - 1)))
        die("unsupported grid");
    unsigned bits = 0;
    for (uint64_t remaining = n; remaining > 1; remaining >>= 1)
        ++bits;
    return (Layout){n, bits, 1U << (bits / 2), 1U << (bits - bits / 2)};
}

/* All fields have fixed width and order. Fiat-Shamir samples are read-only
 * views of the running SHA-512 transcript, with a role byte and LE32 index. */
typedef struct {
    SHA512_CTX hash;
    FILE *file;
    int writing;
} Transcript;
static void trans_init(Transcript *t, FILE *file, int writing, int beacon)
{
    const char *label = beacon ? "stencil-proof-transcript-quicknet-v1" : "stencil-proof-transcript-v1";
    t->file = file;
    t->writing = writing;
    SHA512_Init(&t->hash);
    SHA512_Update(&t->hash, label, strlen(label));
}

static void exchange(Transcript *t, void *p, size_t n)
{
    if (t->writing)
        write_all(t->file, p, n);
    else
        read_all(t->file, p, n);
    SHA512_Update(&t->hash, p, n);
}

static void field_io(Transcript *t, F *v)
{
    exchange(t, v, sizeof(*v));
    if (fcmp(*v, scalar_order) >= 0)
        die("noncanonical scalar");
}

static void challenge_bytes(const Transcript *t, unsigned char role, uint32_t idx,
                            unsigned char out[64])
{
    SHA512_CTX copy = t->hash;
    SHA512_Update(&copy, &role, 1);
    SHA512_Update(&copy, &idx, sizeof(idx));
    SHA512_Final(out, &copy);
}

static F challenge(const Transcript *t, unsigned char role, uint32_t idx)
{
    unsigned char bytes[64];
    challenge_bytes(t, role, idx, bytes);
    F result;
    crypto_core_ristretto255_scalar_reduce((unsigned char *)&result, bytes);
    return result;
}

typedef struct {
    F g0, quadratic, r;
} Round;
typedef struct {
    Round round[MAX_BITS];
} Check;

/* g(1) = claim - g(0). The two transmitted coefficients determine g. */
static F advance(const Round *s, F claim)
{
    F linear = fsub(fsub(claim, fadd(s->g0, s->g0)), s->quadratic);
    return fadd(s->g0, fmul(s->r, fadd(linear, fmul(s->r, s->quadratic))));
}

static void round_io(Transcript *t, Round *s, char role, unsigned k)
{
    field_io(t, &s->g0);
    field_io(t, &s->quadratic);
    s->r = challenge(t, (unsigned char)role, k);
}

/* Fold into the front of a single private file. In the first product
 * round two public weights occupy precisely the space of one folded pair. */
static FoldPair prove_check(Transcript *t, Check *check, FILE *table, unsigned bits, FILE *witness,
                            Moment m, F claim, const int *exponent)
{
    int product = witness != NULL;
    FoldPair endpoint = {0};
    for (unsigned k = 0; k < bits; ++k) {
        uint64_t count = UINT64_C(1) << (bits - k);
        Round *s = &check->round[k];
        s->g0 = m.g0;
        s->quadratic = m.quadratic;
        round_io(t, s, product ? 'V' : 'U', k);
        claim = advance(s, claim);
        if (product && k == 0 && exponent)
            endpoint = fold_product_first_wide(table, witness, count, s->r, &m, *exponent);
        else if (product && k == 0)
            endpoint = fold_product_first(table, witness, count, s->r, &m);
        else
            endpoint = fold_step(table, count, product, s->r, &m);
    }
    close_file(table);
    if (fcmp(claim, fmul(endpoint.x, endpoint.weight)))
        die("inconsistent sumcheck witness");
    return endpoint;
}

static F replay(const Check *c, unsigned bits, F claim)
{
    for (unsigned k = 0; k < bits; ++k)
        claim = advance(&c->round[k], claim);
    return claim;
}

/* Boolean equality weights in little-endian bit order. Split them into two
 * near-square factors so neither process stores an n-entry weight table. */
typedef struct {
    F *lo, *hi;
} Weights;
static F *weights(const Round *rounds, unsigned bits)
{
    unsigned n = 1U << bits;
    F *w = alloc_items(n, sizeof(F));
    w[0] = fone();
    for (unsigned k = 0; k < bits; ++k) {
        unsigned half = 1U << k;
        for (unsigned i = 0; i < half; ++i) {
            w[i + half] = fmul(w[i], rounds[k].r);
            w[i] = fsub(w[i], w[i + half]);
        }
    }
    return w;
}

static Weights split_weights(const Check *c, unsigned bits)
{
    unsigned half = bits / 2;
    return (Weights){weights(c->round, half), weights(c->round + half, bits - half)};
}

static void release_weights(Weights w)
{
    free(w.lo);
    free(w.hi);
}

static F mask_endpoint(Layout layout, Weights v, const unsigned char seed[32], const F coef[128])
{
    Mask *mask = mask_begin(seed, coef);
    F total = fzero();
    for (unsigned i = 0; i < layout.height; ++i) {
        F row = fzero();
        for (unsigned j = 0; j < layout.width; ++j)
            row = fadd(row, fmul(v.lo[j], mask_next(mask)));
        total = fadd(total, fmul(row, v.hi[i]));
    }
    mask_end(mask);
    return total;
}

static void fold_rows(FILE *xi, Layout layout, const F *hi, F *z, const int *exponent)
{
    to_start(xi);
    __int128 *x = alloc_items(layout.width, sizeof(*x));
    for (uint32_t i = 0; i < layout.height; ++i) {
        if (!witness_read_encoded(xi, x, layout.width, exponent))
            die("invalid binary64 witness during opening");
        for (uint32_t j = 0; j < layout.width; ++j)
            z[j] = fadd(z[j], fmul(hi[i], fwide(x[j])));
    }
    free(x);
}

/* These profiles share the two-energy proof and choose residual units
 * from their registered matrix and RHS generators. */
static int wide_profile(const struct rc_info *info)
{
    return info->signed_unit || info->dimensions == 1;
}

static int rhs_shift(int exponent, unsigned bits, const struct rc_info *info)
{
    int shift;
    if (!witness_profile_shift(info->dimensions, info->signed_unit, bits, exponent, &shift))
        die("shared exponent outside registered profile");
    return shift;
}

static void read_start(const char *pk, const char *path, unsigned char start[RC_START_BYTES],
                       struct rc_info *info)
{
    if (!rc_read_exact(path, start, RC_START_BYTES) || !rc_verify_start(pk, start, info))
        die("invalid signed start or authority key");
}

static int commit_main(char **argv)
{
    struct rc_info info;
    unsigned char start[RC_START_BYTES], digest[32];
    read_start(argv[1], argv[2], start, &info);
    Layout layout = grid_layout(&info);
    size_t bytes = (size_t)layout.height * 32;
    size_t prefix = wide_profile(&info) ? sizeof(int32_t) : 0;
    unsigned char *cache = alloc_items(bytes + prefix, 1);
    FILE *q = open_file(argv[3], "rb");
    if (!stencil_commit_stream(q, layout.n, info.dimensions, info.signed_unit,
                               cache, bytes + prefix, digest))
        die("invalid binary64 input, size, or vector commitment");
    close_file(q);
    publish_bytes(argv[4], cache, bytes + prefix);
    publish_bytes(argv[5], digest, sizeof(digest));
    free(cache);
    return 0;
}

static int report(const struct rc_info *info, F energy, __uint128_t rhs_squared)
{
    BIGNUM *bn = BN_lebin2bn((const unsigned char *)&energy, sizeof(energy), NULL);
    if (!bn)
        die("cannot format score");
    char *decimal = BN_bn2dec(bn);
    if (!decimal)
        die("cannot format score");
    uint64_t n = matrix_size(info->side, info->dimensions);
    F threshold = fwide((__int128)(rhs_squared << 16));
    int pass = fcmp(energy, threshold) <= 0;
    long double relative = rhs_squared
                               ? sqrtl(strtold(decimal, NULL) / (long double)rhs_squared) / scale
                               : (fcmp(energy, fzero()) ? INFINITY : 0);
    printf("certified rows=%" PRIu64 " rho=%s relative_rhs=%.12Lg target=%s elapsed_ns=%" PRIu64
           " attempt=",
           n, decimal, relative, pass ? "pass" : "miss", info->finish_ns - info->start_ns);
    for (size_t i = 0; i < sizeof(info->attempt); ++i)
        printf("%02x", info->attempt[i]);
    puts("");
    OPENSSL_free(decimal);
    BN_free(bn);
    return pass ? 0 : 3;
}

/* In integer residual units the denominator is L*k*sqrt(Q)+h*||B||,
 * where L <= ||A||_2 and L^2 is rational in every registered profile. */
static int report_wide(const struct rc_info *info, F energy, F x_squared,
                       uint64_t n, __uint128_t rhs_squared, int exponent, int shift)
{
    int blog = info->dimensions == 1 && !info->signed_unit;
    int three_band = info->dimensions == 1 && info->signed_unit;
    uint64_t numerator = 7, denominator = 1;
    if (blog) {
        /* L is the Rayleigh quotient of the tridiagonal at all ones. */
        numerator = 10*n - 2;
        denominator = n;
    } else if (three_band) {
        /* L^2 = ||A||_F^2 / n: 7*n-12 stored entries of magnitude one. */
        numerator = 7*n - 12;
        denominator = n;
    }
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx)
        die("cannot allocate score context");
    BN_CTX_start(ctx);
    BIGNUM *r = BN_CTX_get(ctx), *x = BN_CTX_get(ctx), *lhs = BN_CTX_get(ctx);
    BIGNUM *a = BN_CTX_get(ctx), *b = BN_CTX_get(ctx), *diff = BN_CTX_get(ctx);
    BIGNUM *bound = BN_CTX_get(ctx), *num_sq = BN_CTX_get(ctx), *den_sq = BN_CTX_get(ctx);
    int k_bits = shift < 0 ? -shift : 0, h_bits = shift > 0 ? shift : 0;
    if (!den_sq || !BN_lebin2bn((const unsigned char *)&numerator, sizeof(numerator), num_sq) ||
        !BN_lebin2bn((const unsigned char *)&denominator, sizeof(denominator), den_sq) ||
        (!three_band && (!BN_sqr(num_sq, num_sq, ctx) || !BN_sqr(den_sq, den_sq, ctx))) ||
        !BN_lebin2bn((const unsigned char *)&energy, sizeof(energy), r) ||
        !BN_lebin2bn((const unsigned char *)&x_squared, sizeof(x_squared), x) ||
        !BN_lshift(lhs, r, 106) || !BN_mul(lhs, lhs, den_sq, ctx) ||
        !BN_lshift(a, x, 2*k_bits) || !BN_mul(a, a, num_sq, ctx) ||
        !BN_lebin2bn((const unsigned char *)&rhs_squared, sizeof(rhs_squared), b) ||
        !BN_lshift(b, b, 2*h_bits) || !BN_mul(b, b, den_sq, ctx) ||
        !BN_sub(diff, lhs, a) || !BN_sub(diff, diff, b))
        die("integer score computation failed");
    int pass = BN_is_negative(diff) || BN_is_zero(diff);
    if (!pass) {
        if (!BN_sqr(lhs, diff, ctx) || !BN_mul(bound, a, b, ctx) || !BN_lshift(bound, bound, 2))
            die("integer score comparison failed");
        pass = BN_cmp(lhs, bound) <= 0;
    }
    char *rho = BN_bn2dec(r), *x2 = BN_bn2dec(x);
    if (!rho || !x2)
        die("cannot format scores");
    long double residual = sqrtl(strtold(rho, NULL));
    long double rhs = ldexpl(sqrtl((long double)rhs_squared), h_bits);
    long double sol = ldexpl(sqrtl(strtold(x2, NULL)), k_bits);
    long double norm = (long double)numerator / denominator;
    if (three_band) norm = sqrtl(norm);
    printf("certified rows=%" PRIu64 " exponent=%d rho=%s x_squared=%s relative_rhs=%.17Lg "
           "%s=%.17Lg target=%s elapsed_ns=%" PRIu64 " attempt=",
           n, exponent, rho, x2, residual/rhs, blog || three_band ? "backward_2_upper" : "backward_2",
           residual/(norm*sol+rhs),
           pass ? "pass" : "miss", info->finish_ns - info->start_ns);
    for (size_t i = 0; i < sizeof(info->attempt); ++i)
        printf("%02x", info->attempt[i]);
    if (info->profile == matrix_profile_id(MATRIX_THREE_BAND_ID))
        printf(" profile=%s", info->profile->id);
    puts("");
    OPENSSL_free(rho);
    OPENSSL_free(x2);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return pass ? 0 : 3;
}

typedef struct {
    const char *trust, *start, *finish, *expected_start;
    const char *solution, *cache, *proof;
    const char *ca, *policy, *digest, *tsr;
    int creating;
} ProofJob;

static void local_prefix(Transcript *t, const ProofJob *job, struct rc_info *info)
{
    unsigned char header[8], start[RC_START_BYTES], finish[RC_FINISH_BYTES];
    if (job->creating) {
        if (!rc_read_exact(job->start, start, sizeof(start)) ||
            !rc_read_exact(job->finish, finish, sizeof(finish)) ||
            !rc_verify_pair(job->trust, start, finish, info))
            die("invalid signed receipt chain");
        memcpy(header, wide_profile(info) ? wide_magic : magic, sizeof(header));
    }
    exchange(t, header, sizeof(header));
    if (memcmp(header, magic, sizeof(header)) && memcmp(header, wide_magic, sizeof(header)))
        die("unsupported local proof format");
    exchange(t, start, sizeof(start));
    exchange(t, finish, sizeof(finish));
    if (!job->creating && !rc_verify_pair(job->trust, start, finish, info))
        die("invalid signed receipt chain");
    if (memcmp(header, wide_profile(info) ? wide_magic : magic, sizeof(header)))
        die("proof format does not match signed profile");
    if (job->expected_start) {
        unsigned char expected[RC_START_BYTES];
        if (!rc_read_exact(job->expected_start, expected, sizeof(expected)) ||
            memcmp(expected, start, sizeof(start)))
            die("unexpected challenge");
    }
}

/* DER is a separately authenticated time witness. Only canonical, immutable
 * values enter Fiat-Shamir. Multiple valid certificates, wrapper encodings or
 * TSA serial numbers for one submission must yield exactly the same challenges. */
static void beacon_prefix(Transcript *t, const ProofJob *job, struct rc_info *info,
                          uint64_t *clock_error)
{
    unsigned char header[8], start[RC_START_BYTES], digest[32], pinned[32], sig[BC_SIG_BYTES];
    uint32_t size = 0;
    uint8_t *der = NULL;
    if (!rc_read_exact(job->digest, pinned, sizeof(pinned)))
        die("expected a 32-byte commitment digest");
    if (job->creating) {
        size_t n;
        if (!rc_read_exact(job->start, start, sizeof(start)) ||
            !rc_read_exact(job->finish, sig, sizeof(sig)) ||
            !(der = rc_tsa_read_response(job->tsr, &n)))
            die("invalid beacon evidence files");
        size = (uint32_t)n;
        memcpy(header, beacon_magic, 8);
        memcpy(digest, pinned, 32);
    }
    exchange(t, header, 8);
    if (memcmp(header, beacon_magic, 8)) die("expected STNPRF03 beacon proof");
    exchange(t, start, sizeof(start));
    exchange(t, digest, 32);
    if (memcmp(digest, pinned, 32)) die("unexpected registered commitment");
    exchange(t, sig, sizeof(sig));
    if (job->creating) {
        write_all(t->file, &size, sizeof(size));
        write_all(t->file, der, size);
    } else {
        read_all(t->file, &size, sizeof(size));
        if (!size || size > RC_TSA_MAX_RESPONSE) die("invalid timestamp response length");
        der = alloc_items(size, 1);
        read_all(t->file, der, size);
    }
    if (!bc_check_evidence(job->trust, job->ca, job->policy, start, digest, sig,
                           der, size, info, clock_error))
        die("invalid registration, beacon signatures, TSA trust, imprint or time window");
    free(der);
}

static int run_proof(const ProofJob *job)
{
    int creating = job->creating;
    struct rc_info info;
    FILE *file = creating ? private_scratch() : open_file(job->proof, "rb");
    Transcript t;
    uint64_t clock_error = 0;
    trans_init(&t, file, creating, job->ca != NULL);
    if (job->ca)
        beacon_prefix(&t, job, &info, &clock_error);
    else
        local_prefix(&t, job, &info);
    int wide = wide_profile(&info);
    Layout layout = grid_layout(&info);
    unsigned bits = layout.bits;
    uint64_t n = layout.n;
    Matrix matrix = info.profile->initialize(info.side, info.seed);
    /* At this prefix the digest is fixed and fresh entropy has been authenticated. */
    unsigned char mask_seed[64];
    challenge_bytes(&t, 'M', 0, mask_seed);
    unsigned char *rows = alloc_items(layout.height, 32), digest[32];
    int32_t stored_exponent = 0;
    if (creating) {
        FILE *cache = open_file(job->cache, "rb");
        if (wide)
            read_all(cache, &stored_exponent, sizeof(stored_exponent));
        read_all(cache, rows, (size_t)layout.height * 32);
        end_input(cache);
        close_file(cache);
    }
    if (wide)
        exchange(&t, &stored_exponent, sizeof(stored_exponent));
    int exponent = stored_exponent;
    int shift = wide ? rhs_shift(exponent, bits, &info) : 58;
    F rhs_factor = fwide((__int128)1 << (shift > 0 ? shift : 0));
    int matrix_factor = 1 << (shift < 0 ? -shift : 0);
    exchange(&t, rows, (size_t)layout.height * 32);
    int hashed = wide ? vc_digest_wide(layout.width, layout.height, exponent, rows, digest)
                      : vc_digest(layout.width, layout.height, rows, digest);
    if (!hashed || memcmp(info.digest, digest, 32))
        die("commitment digest mismatch");

    F energy = fzero(), x_squared = fzero();
    __int128 projections[MASK_COUNT];
    FILE *xi = NULL, *residual = NULL;
    if (creating) {
        xi = open_file(job->solution, "rb");
        int error = matrix_prepare(&matrix);
        if (error) die(strerror(error));
        if (wide) {
            mask_sums_wide(xi, n, mask_seed, projections, exponent);
            residual = op_residual_wide(xi, &matrix, n, exponent, shift, &energy, &x_squared);
        } else {
            mask_sums(xi, n, mask_seed, projections);
            residual = op_residual(xi, &matrix, n, &energy);
        }
    }
    field_io(&t, &energy);
    if (wide) {
        field_io(&t, &x_squared);
        F max_x_squared = fmul(fwide((__int128)1 << 78), fwide((__int128)n << 78));
        if (fcmp(x_squared, max_x_squared) > 0)
            die("solution squared norm outside wide encoding bound");
    }
    exchange(&t, projections, sizeof(projections));
    __int128 limit = (__int128)n << (wide ? 78 : 63);
    for (unsigned j = 0; j < MASK_COUNT; ++j)
        if (projections[j] < -limit || projections[j] > limit)
            die("range projection too large");

    Check norm, matvec;
    FoldPair endpoint = {0};
    F ru = fzero();
    if (creating) {
        Moment m = fold_moment(residual, n, 0);
        endpoint = prove_check(&t, &norm, residual, bits, NULL, m, energy, NULL);
        ru = endpoint.x;
    } else
        for (unsigned k = 0; k < bits; ++k)
            round_io(&t, &norm.round[k], 'U', k);
    field_io(&t, &ru);
    if (fcmp(replay(&norm, bits, energy), fmul(ru, ru)))
        die("norm sumcheck failed");

    F coef[MASK_COUNT], projected = fzero(), bval = fzero();
    for (unsigned j = 0; j < MASK_COUNT; ++j) {
        coef[j] = challenge(&t, 'B', j);
        projected = fadd(projected, fmul(coef[j], fwide(projections[j])));
    }
    Weights u = split_weights(&norm, bits);
    /* The same opening authenticates the solution energy. A fresh coefficient
     * combines its quadratic claim with the public matrix and projection terms. */
    F lambda = wide ? challenge(&t, 'X', 0) : fzero();
    F partial = fadd(fadd(ru, projected), fmul(lambda, x_squared));
    if (creating) {
        FILE *transpose = op_transpose(&matrix, n, layout.width, u.hi, u.lo, &bval);
        matrix_release(&matrix);
        Moment m = wide ? fold_product_prepare_wide(transpose, xi, n, mask_seed, coef,
                                                    exponent, lambda, matrix_factor)
                        : fold_product_prepare(transpose, xi, n, mask_seed, coef);
        endpoint = prove_check(&t, &matvec, transpose, bits, xi, m,
                               fadd(partial, fmul(bval, rhs_factor)), wide ? &exponent : NULL);
    } else
        for (unsigned k = 0; k < bits; ++k)
            round_io(&t, &matvec.round[k], 'V', k);
    Weights v = split_weights(&matvec, bits);
    F *z = alloc_items(layout.width, sizeof(F));
    if (creating) {
        fold_rows(xi, layout, v.hi, z, wide ? &exponent : NULL);
        close_file(xi);
    }
    for (uint32_t j = 0; j < layout.width; ++j)
        field_io(&t, &z[j]);
    if (!creating)
        end_input(file);
    if (!vc_verify(layout.width, layout.height, rows, (const unsigned char *)v.hi, (const unsigned char *)z))
        die("opening does not match stamped solution");
    F xv = fzero();
    for (uint32_t j = 0; j < layout.width; ++j)
        xv = fadd(xv, fmul(v.lo[j], z[j]));
    __uint128_t rhs_squared = 0;
    if (creating) {
        if (fcmp(endpoint.x, xv))
            die("opening differs from matvec endpoint");
        publish(file, job->proof);
    } else {
        F a = op_endpoint(&matrix, n, layout.width, u.hi, u.lo, v.hi, v.lo, &bval, &rhs_squared);
        F weight = fadd(fscale(a, matrix_factor), mask_endpoint(layout, v, mask_seed, coef));
        if (wide)
            weight = fadd(weight, fmul(lambda, xv));
        F claim = fadd(partial, fmul(bval, rhs_factor));
        if (fcmp(replay(&matvec, bits, claim), fmul(xv, weight)))
            die("matvec or projection sumcheck failed");
    }
    close_file(file);
    free(z);
    free(rows);
    release_weights(u);
    release_weights(v);
    if (creating)
        return 0;
    if (info.profile != matrix_profile_id(MATRIX_THREE_BAND_ID))
        fprintf(stderr, "replay of archived/test profile %s\n", info.profile->id);
    if (job->ca)
        printf("start_scheduled_ns=%" PRIu64 " commitment_utc_ns=%" PRIu64
               " clock_uncertainty_ns=%" PRIu64 "\n", info.start_ns, info.finish_ns, clock_error);
    return wide ? report_wide(&info, energy, x_squared, n, rhs_squared, exponent, shift)
                : report(&info, energy, rhs_squared);
}

int three_band_main(int argc, char **argv);

int main(int argc, char **argv)
{
    if (fesetround(FE_TONEAREST))
        die("round-to-nearest unavailable");
    if (argc >= 2) {
        --argc;
        ++argv;
        /* Isolate historical issuance for the regression harnesses. Replays
         * of existing signatures still select their authenticated generator. */
        if (!strcmp(argv[0], "fixture") && argc >= 2) {
            if (argc == 10 && !strcmp(argv[1], "beacon-register"))
                return bc_register_fixture(argv + 2);
            if (matrix_profile_command(argv[1], 1) && strcmp(argv[1], "start"))
                return receipt_main(argc - 1, argv + 1);
            return 2;
        }
        if (!strcmp(argv[0], "keygen") || !strcmp(argv[0], "start") ||
            !strcmp(argv[0], "stamp") || !strcmp(argv[0], "stamp-stdio"))
            return receipt_main(argc, argv);
        if (!strncmp(argv[0], "beacon-", 7))
            return bc_main(argc, argv);
        if (!strcmp(argv[0], "tsa-query") || !strcmp(argv[0], "tsa-verify"))
            return rc_tsa_main(argc, argv);
        if (!strcmp(argv[0], "three-band")) return three_band_main(argc, argv);
        if (!strcmp(argv[0], "solve"))
            return solve_main(argc, argv);
        if (!strcmp(argv[0], "commit") && argc == 6)
            return commit_main(argv);
        if (!strcmp(argv[0], "prove") && argc == 7)
            return run_proof(&(ProofJob){.creating=1, .trust=argv[1], .start=argv[2],
                .finish=argv[3], .solution=argv[4], .cache=argv[5], .proof=argv[6]});
        if (!strcmp(argv[0], "verify") && (argc == 3 || argc == 4))
            return run_proof(&(ProofJob){.trust=argv[1], .proof=argv[2],
                .expected_start=argc == 4 ? argv[3] : NULL});
        if (!strcmp(argv[0], "prove-beacon") && argc == 11)
            return run_proof(&(ProofJob){.creating=1, .trust=argv[1], .ca=argv[2], .policy=argv[3],
                .start=argv[4], .digest=argv[5], .tsr=argv[6], .finish=argv[7],
                .solution=argv[8], .cache=argv[9], .proof=argv[10]});
        if (!strcmp(argv[0], "verify-beacon") && argc == 6)
            return run_proof(&(ProofJob){.trust=argv[1], .ca=argv[2], .policy=argv[3],
                .digest=argv[4], .proof=argv[5]});
    }
    fputs("usage: stencil COMMAND ARGS\n"
          "  keygen SECRET PUBLIC\n  start SECRET ROWS ENTRY START  (three-band challenge)\n"
          "  solve PUBLIC START SOLUTION.f64\n  commit PUBLIC START SOLUTION.f64 ROWS DIGEST\n"
          "  stamp SECRET START DIGEST FINISH\n"
          "  stamp-stdio SECRET AUTHENTICATED_ENTRY < start-and-digest > finish\n"
          "  prove PUBLIC START FINISH SOLUTION.f64 ROWS PROOF\n"
          "  verify PUBLIC PROOF [EXPECTED_START]\n"
          "  three-band N PATTERN_SEED [--sign-draw ID | --sign-seed SEED] [--perm FILE] > matrix.mtx\n"
          "  beacon-register | beacon-start | beacon-query | beacon-verify-stamp | beacon-record  (see BEACON.md)\n"
          "  tsa-query DIGEST REQUEST.tsq [POLICY_OID] | tsa-verify CA.pem DIGEST RESPONSE.tsr [POLICY_OID]\n"
          "  prove-beacon REG CA.pem POLICY_OID START DIGEST RESPONSE.tsr ROUND_SIG SOLUTION.f64 ROWS PROOF\n"
          "  verify-beacon REG CA.pem POLICY_OID REGISTERED_DIGEST PROOF\n",
          stderr);
    return 2;
}
