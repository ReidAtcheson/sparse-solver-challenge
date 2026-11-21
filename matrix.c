#include "matrix.h"
#include "three_band.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(MATRIX_PROFILE_ID) <= MATRIX_ID_BYTES &&
               sizeof(MATRIX_PROFILE_3D_ID) <= MATRIX_ID_BYTES &&
               sizeof(MATRIX_SIGNED3D_ID) <= MATRIX_ID_BYTES &&
               sizeof(MATRIX_THREE_BAND_ID) <= MATRIX_ID_BYTES &&
               sizeof(MATRIX_THREE_BAND_V1_ID) <= MATRIX_ID_BYTES &&
               sizeof(MATRIX_BLOG_ID) <= MATRIX_ID_BYTES, "profile must fit the signed receipt");
static Matrix three_band(uint32_t n, const uint8_t seed[32]);

static Matrix three_band_v1(uint32_t n, const uint8_t seed[32])
{
    Matrix matrix = three_band(n, seed);
    matrix.legacy_three_band = 1;
    return matrix;
}

static Matrix diffusion3d(uint32_t side, const uint8_t seed[32])
{
    return matrix_init_profile(side, 3, seed);
}

static Matrix july_fixture(uint32_t side, const uint8_t seed[32])
{
    (void)seed;
    return matrix_init_blog(side);
}

static const MatrixProfile profiles[] = {
    /* The bounded graph has at most 1,203 predecessors, three choices and one diagonal. */
    {MATRIX_THREE_BAND_ID, "three-band", "start", 1, 1, 1207,
     1024, MATRIX_THREE_BAND_MAX_ROWS, 1, three_band},
    /* Preserve historical generators only for authenticated replay and tests. */
    {MATRIX_THREE_BAND_V1_ID, "three-band-v1", "startbandv1", 1, 1, MATRIX_ABS_ROW_LIMIT,
     1024, MATRIX_ABS_ROW_LIMIT, 1, three_band_v1},
    {MATRIX_PROFILE_ID, "2d", "start2d", 2, 0, 5, 512, 32768, 1, matrix_init},
    {MATRIX_PROFILE_3D_ID, "3d", "start3d", 3, 0, 7, 32, 1024, 1, diffusion3d},
    {MATRIX_SIGNED3D_ID, "signed3d", "startsigned3d", 3, 1, 7, 32, 1024, 1, matrix_init_signed3d},
    {MATRIX_BLOG_ID, "blog", "startblog", 1, 0, 3, 1024, UINT32_C(1) << 30, 0, july_fixture},
};
enum { PROFILE_COUNT = sizeof(profiles) / sizeof(profiles[0]) };

const MatrixProfile *matrix_profile_wire(const uint8_t id[MATRIX_ID_BYTES])
{
    for (unsigned i = 0; i < PROFILE_COUNT; i++)
        if (memcmp(id, profiles[i].id, MATRIX_ID_BYTES) == 0) return &profiles[i];
    return NULL;
}

const MatrixProfile *matrix_profile_id(const char *id)
{
    for (unsigned i = 0; i < PROFILE_COUNT; i++)
        if (strcmp(id, profiles[i].id) == 0) return &profiles[i];
    return NULL;
}

const MatrixProfile *matrix_profile_command(const char *name, int local_start)
{
    for (unsigned i = 0; i < PROFILE_COUNT; i++) {
        const char *candidate = local_start ? profiles[i].start_command : profiles[i].short_name;
        if (strcmp(name, candidate) == 0) return &profiles[i];
    }
    return NULL;
}

const MatrixProfile *matrix_profile_kind(unsigned dimensions, int signed_unit)
{
    /* Old receipt provider plugins could describe the v1 three-band profile
     * using only these two fields. New providers must return v2 explicitly. */
    if (dimensions == 1 && signed_unit) return matrix_profile_id(MATRIX_THREE_BAND_V1_ID);
    const MatrixProfile *found = NULL;
    for (unsigned i = 0; i < PROFILE_COUNT; i++) {
        if (profiles[i].dimensions == dimensions && profiles[i].signed_unit == signed_unit) {
            if (found) return NULL;
            found = &profiles[i];
        }
    }
    return found;
}

int matrix_profile_side(const MatrixProfile *profile, uint64_t side)
{
    return profile && side >= profile->min_side && side <= profile->max_side &&
           (side & (side - 1)) == 0;
}

/* SplitMix64 finalizer. This is a numerical test family, not a cryptographic
 * generator. The receipt authenticates the full seed. */
static uint64_t mix64(uint64_t x)
{
    x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
    return x ^ (x >> 31);
}

static uint64_t le64(const unsigned char *p)
{
    uint64_t x = 0;
    for (unsigned k = 0; k < 8; ++k)
        x |= (uint64_t)p[k] << (8 * k);
    return x;
}

static Matrix three_band(uint32_t n, const uint8_t seed[32])
{
    /* Separate seed words for NumPy-compatible pattern and sign streams;
     * the remaining two words key a row-addressable RHS sign generator. */
    Matrix a = {
        .side = n, .dimensions = 1, .signed_unit = 1,
        .pattern_seed = le64(seed), .sign_seed = le64(seed + 8),
        .rhs_key = mix64(le64(seed + 16) ^ mix64(le64(seed + 24))),
    };
    for (uint32_t t = n; t > 1; t >>= 1) ++a.side_log2;
    return a;
}

int32_t matrix_three_band_rhs(const Matrix *a, uint64_t row)
{
    return (mix64(a->rhs_key + row) >> 63) ? 1 : -1;
}

int matrix_three_band_scan(const Matrix *a,
                           int (*emit)(void *, size_t, size_t, int), void *context)
{
    if (!a || a->dimensions != 1 || !a->signed_unit || !emit) return EINVAL;
    if (a->legacy_three_band)
        return tb_signed_scan_v1(a->side, a->pattern_seed, TB_SIGN_SEED, a->sign_seed,
                                 NULL, emit, context);
    return tb_signed_scan(a->side, a->pattern_seed, TB_SIGN_SEED, a->sign_seed,
                          NULL, emit, context);
}

typedef struct {
    uint32_t *upper;
    uint64_t *counts;
    int8_t *diagonal;
    size_t used;
} EdgeBuffer;

static int collect_edge(void *context, size_t i, size_t j, int sign)
{
    EdgeBuffer *buffer = context;
    if (i == j) {
        buffer->diagonal[i] = (int8_t)sign;
    } else {
        buffer->upper[buffer->used++] = ((uint32_t)j << 1) | (sign < 0);
        ++buffer->counts[j];
    }
    ++buffer->counts[i];
    return 0;
}

void matrix_release(Matrix *a)
{
    free(a->offsets);
    free(a->entries);
    a->offsets = NULL;
    a->entries = NULL;
    a->max_row_terms = 0;
}

int matrix_prepare(Matrix *a)
{
    if (!a) return EINVAL;
    if (a->dimensions != 1 || !a->signed_unit || a->offsets) return 0;
    size_t n = a->side;
    uint32_t max_rows = a->legacy_three_band ? MATRIX_ABS_ROW_LIMIT : MATRIX_THREE_BAND_MAX_ROWS;
    if (n < 3 || n > max_rows) return EINVAL;
    uint64_t expected_nnz = matrix_three_band_nnz(a->side);
    if (expected_nnz > SIZE_MAX / sizeof(*a->entries) ||
        n + 1 > SIZE_MAX / sizeof(*a->offsets)) return EOVERFLOW;
    size_t upper_count = 3*n - 6;
    uint64_t *offsets = calloc(n + 1, sizeof(*offsets));
    EdgeBuffer b = {.upper = malloc(upper_count * sizeof(*b.upper)),
                    .counts = offsets, .diagonal = malloc(n * sizeof(*b.diagonal))};
    uint32_t *entries = NULL;
    int error = ENOMEM;
    if (!offsets || !b.upper || !b.diagonal) goto done;
    error = matrix_three_band_scan(a, collect_edge, &b);
    if (error) goto done;
    assert(b.used == upper_count);

    /* Turn degree counts into exclusive ends. Fill each row backwards from
     * its end, leaving the offsets in their final CSR start positions. */
    uint64_t nnz = 0;
    unsigned max_terms = 0;
    for (size_t i = 0; i < n; ++i) {
        if (offsets[i] > max_terms) max_terms = (unsigned)offsets[i];
        nnz += offsets[i];
        offsets[i] = nnz;
    }
    assert(nnz == expected_nnz);
    offsets[n] = nnz;
    entries = malloc((size_t)nnz * sizeof(*entries));
    if (!entries) { error = ENOMEM; goto done; }
    size_t end = upper_count;
    for (size_t i = n; i-- > 0;) {
        size_t count = n-1-i < 3 ? n-1-i : 3;
        size_t start = end - count;
        /* Sort the at most three upper entries. Visiting source rows in
         * descending order already orders the corresponding lower entries. */
        for (size_t j = start + 1; j < end; ++j) {
            uint32_t entry = b.upper[j];
            size_t k = j;
            while (k > start && entry < b.upper[k-1]) {
                b.upper[k] = b.upper[k-1];
                --k;
            }
            b.upper[k] = entry;
        }
        while (end > start) {
            uint32_t entry = b.upper[--end];
            entries[--offsets[i]] = entry;
            entries[--offsets[entry >> 1]] = ((uint32_t)i << 1) | (entry & 1);
        }
        entries[--offsets[i]] = ((uint32_t)i << 1) | (b.diagonal[i] < 0);
    }
    a->offsets = offsets;
    a->entries = entries;
    a->max_row_terms = max_terms;
done:
    free(b.upper);
    free(b.diagonal);
    if (error) free(offsets);
    return error;
}

Matrix matrix_init_profile(uint32_t side, unsigned dimensions, const unsigned char seed[32])
{
    const uint64_t tag = dimensions == 3 ? UINT64_C(0x7374656e63696c33)
                                         : UINT64_C(0x7374656e63696c31);
    const uint64_t salt = mix64(le64(seed + 24) ^ tag);
    const uint64_t third_key = mix64(le64(seed + 16) ^ salt ^ 3);
    Matrix a = {
        .side = side,
        .dimensions = dimensions,
        .horizontal_key = mix64(le64(seed) ^ salt ^ 1),
        .vertical_key = mix64(le64(seed + 8) ^ salt ^ 2),
        .depth_key = dimensions == 3 ? third_key : 0,
        .rhs_key = dimensions == 3 ? mix64(le64(seed + 24) ^ salt ^ 4) : third_key,
    };
    for (uint32_t t = side; t > 1; t >>= 1) ++a.side_log2;
    return a;
}

Matrix matrix_init(uint32_t side, const unsigned char seed[32])
{
    return matrix_init_profile(side, 2, seed);
}

Matrix matrix_init_signed3d(uint32_t side, const unsigned char seed[32])
{
    Matrix a = matrix_init_profile(side, 3, seed);
    a.signed_unit = 1;
    return a;
}

Matrix matrix_init_blog(uint32_t n)
{
    Matrix a = {.side = n, .dimensions = 1};
    for (uint32_t t = n; t > 1; t >>= 1) ++a.side_log2;
    return a;
}


/* Verbatim public nonce from random-tridiagonal-whir-field192-l2-v4.json.
 * The July size sweep changed only dimension. This fixture uses exactly
 * the upstream seeded-dyadic-v1 mixer on the low ten row-index bits. */
static int blog_rhs_code(uint64_t i)
{
    static const unsigned char seed[32] = {
        0x9f,0x36,0xa2,0xc4,0xd7,0x81,0x5b,0xe0,0x08,0x4d,0x63,0xa9,0x12,0xf7,0xc5,0xb3,
        0x4e,0x18,0x60,0xda,0xfb,0x29,0x5c,0x73,0xa6,0x41,0x8e,0xd0,0x2b,0xc9,0x57,0x4f
    };
    unsigned code = 0;
    for (unsigned bit = 0; bit < 7; ++bit) {
        const unsigned char *idx = seed + 4 * bit;
        unsigned a = (i >> (idx[0] % 10)) & 1, b = (i >> (idx[1] % 10)) & 1;
        unsigned c = (i >> (idx[2] % 10)) & 1, d = (i >> (idx[3] % 10)) & 1;
        code |= (a ^ b ^ (c & d) ^ ((seed[28] >> bit) & 1)) << bit;
    }
    int magnitude = 144 + (int)(code & 63);
    return code & 64 ? -magnitude : magnitude;
}

int matrix_vertex_sign(const Matrix *a, uint64_t i)
{
    return (mix64(a->horizontal_key + i) >> 63) ? 1 : -1;
}

static void signed_torus_row(const Matrix *a, uint64_t i, MatrixRow *r)
{
    int sign = matrix_vertex_sign(a, i);
    r->count = 1;
    r->col[0] = i;
    r->val[0] = 1;
    r->rhs = (mix64(a->rhs_key + i) >> 63) ? 1 : -1;
    for (unsigned axis = 0; axis < 3; ++axis) {
        unsigned shift = axis * a->side_log2;
        uint64_t stride = UINT64_C(1) << shift;
        uint64_t mask = (uint64_t)(a->side - 1) << shift;
        uint64_t lo = (i & ~mask) | ((i - stride) & mask);
        uint64_t hi = (i & ~mask) | ((i + stride) & mask);
        r->col[r->count] = lo;
        r->val[r->count++] = sign * matrix_vertex_sign(a, lo);
        r->col[r->count] = hi;
        r->val[r->count++] = sign * matrix_vertex_sign(a, hi);
    }
}

static int conductance(uint64_t key, uint64_t face)
{
    return 1 + (int)(mix64(key + face) >> 62);
}

static void neighbor(MatrixRow *r, uint64_t col, int weight)
{
    r->col[r->count] = col;
    r->val[r->count++] = -weight;
}

void matrix_row(const Matrix *a, uint64_t i, MatrixRow *r)
{
    assert(a->dimensions != 1 || !a->signed_unit);
    if (a->dimensions == 1) {
        r->count = 0;
        if (i > 0) {
            r->col[r->count] = i - 1;
            r->val[r->count++] = 1;
        }
        r->col[r->count] = i;
        r->val[r->count++] = 8;
        if (i + 1 < a->side) {
            r->col[r->count] = i + 1;
            r->val[r->count++] = 1;
        }
        r->rhs = blog_rhs_code(i);
        return;
    }
    if (a->signed_unit) {
        signed_torus_row(a, i, r);
        return;
    }
    uint64_t side = a->side;
    uint64_t x = i & (side - 1);
    uint64_t y = (i >> a->side_log2) & (side - 1);
    uint64_t plane = side * side;
    uint64_t z = i >> (2 * a->side_log2);
    /* Separate face lattices contain an extra layer perpendicular to each
     * axis. Adjacent cells use the same key and ID for their common face. */
    uint64_t left_face = i + (i >> a->side_log2);
    uint64_t up_face = i + z * side;
    int left  = conductance(a->horizontal_key, left_face);
    int right = conductance(a->horizontal_key, left_face + 1);
    int up    = conductance(a->vertical_key, up_face);
    int down  = conductance(a->vertical_key, up_face + side);
    r->count = 1;
    r->col[0] = i;
    r->val[0] = 4 + left + right + up + down;
    r->rhs = (mix64(a->rhs_key + i) >> 63) ? 1 : -1;
    if (x != 0) neighbor(r, i - 1, left);
    if (x + 1 < side) neighbor(r, i + 1, right);
    if (y != 0) neighbor(r, i - side, up);
    if (y + 1 < side) neighbor(r, i + side, down);
    if (a->dimensions == 3) {
        int back = conductance(a->depth_key, i);
        int front = conductance(a->depth_key, i + plane);
        r->val[0] += back + front;
        if (z != 0) neighbor(r, i - plane, back);
        if (z + 1 < side) neighbor(r, i + plane, front);
    }
}

int32_t matrix_visit(const Matrix *a, uint64_t i, MatrixTerm emit, void *context)
{
    if (a->dimensions == 1 && a->signed_unit) {
        assert(a->offsets && a->entries && i < a->side);
        for (uint64_t k = a->offsets[i]; k < a->offsets[i + 1]; ++k) {
            uint32_t entry = a->entries[k];
            emit(context, entry >> 1, entry & 1 ? -1 : 1);
        }
        return matrix_three_band_rhs(a, i);
    }
    MatrixRow r;
    matrix_row(a, i, &r);
    for (int k = 0; k < r.count; ++k) emit(context, r.col[k], r.val[k]);
    return r.rhs;
}
