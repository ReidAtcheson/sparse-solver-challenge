#define _POSIX_C_SOURCE 200809L
#include "stencil.h"
#include "library_internal.h"
#include "commit.h"
#include "matrix.h"
#include "receipt.h"
#include "witness.h"

#include <errno.h>
#include <fenv.h>
#include <stdlib.h>
#include <string.h>

struct stencil_instance {
    Matrix matrix;
    const MatrixProfile *profile;
    uint64_t n;
};

static int create(const MatrixProfile *profile, uint32_t side,
                  const uint8_t seed[32], stencil_instance **out)
{
    if (!matrix_profile_side(profile, side)) return EINVAL;
    stencil_instance *instance = malloc(sizeof(*instance));
    if (!instance) return ENOMEM;
    instance->profile = profile;
    instance->matrix = profile->initialize(side, seed);
    instance->n = matrix_size(side, profile->dimensions);
    int error = matrix_prepare(&instance->matrix);
    if (error) { free(instance); return error; }
    *out = instance;
    return 0;
}

int stencil_instance_open(const char *trust_path, const char *start_path,
                          stencil_instance **out)
{
    if (!out) return EINVAL;
    *out = NULL;
    if (!trust_path || !start_path) return EINVAL;
    uint8_t start[RC_START_BYTES];
    struct rc_info info;
    if (!rc_read_exact(start_path, start, sizeof(start)) ||
        !rc_verify_start(trust_path, start, &info)) return EINVAL;
    return create(info.profile, info.side, info.seed, out);
}

int stencil_instance_from_seed(const char *profile_id, uint32_t side,
                               const uint8_t seed[32], stencil_instance **out)
{
    if (!out) return EINVAL;
    *out = NULL;
    if (!profile_id || !seed) return EINVAL;
    return create(matrix_profile_id(profile_id), side, seed, out);
}

void stencil_close(stencil_instance *instance)
{
    if (instance) matrix_release(&instance->matrix);
    free(instance);
}

uint64_t stencil_row_count(const stencil_instance *instance)
{
    return instance ? instance->n : 0;
}

unsigned stencil_max_row_terms(const stencil_instance *instance)
{
    if (!instance) return 0;
    return instance->matrix.offsets ? instance->matrix.max_row_terms : instance->profile->max_terms;
}

typedef struct {
    uint32_t *columns;
    double *values;
    size_t used, capacity;
    uint64_t n;
    double scale;
    int error;
} RowOutput;

static void append_term(void *context, uint64_t column, int32_t coefficient)
{
    RowOutput *out = context;
    if (column >= out->n) { out->error = EDOM; return; }
    if (out->used == out->capacity) { out->error = ENOBUFS; return; }
    out->columns[out->used] = (uint32_t)column;
    out->values[out->used++] = coefficient * out->scale;
}

int stencil_rows(const stencil_instance *instance, uint64_t first, size_t count,
                 uint64_t *offsets, uint32_t *columns, double *values,
                 size_t capacity, double *rhs)
{
    if (!instance || first > instance->n || count > instance->n - first ||
        !offsets || (count && !rhs) || (capacity && (!columns || !values))) return EINVAL;
    const Matrix *matrix = &instance->matrix;
    int july = matrix->dimensions == 1 && !matrix->signed_unit;
    const double matrix_scale = july ? 0x1p-4 : 1.0;
    const double rhs_scale = july ? 0x1p-8 :
                             (matrix->signed_unit ? 1.0 / (double)instance->n : 1.0);
    RowOutput out = {.columns = columns, .values = values, .capacity = capacity,
                     .n = instance->n, .scale = matrix_scale};
    offsets[0] = 0;
    for (size_t i = 0; i < count; i++) {
        int32_t numerator = matrix_visit(matrix, first + i, append_term, &out);
        if (out.error) return out.error;
        offsets[i + 1] = out.used;
        rhs[i] = numerator * rhs_scale;
    }
    return 0;
}

static unsigned size_bits(uint64_t n)
{
    unsigned bits = 0;
    while (n > 1) { n >>= 1; bits++; }
    return bits;
}

static size_t cache_size(unsigned bits, int wide)
{
    return ((size_t)32 << (bits - bits / 2)) + (wide ? sizeof(int32_t) : 0);
}

size_t stencil_commit_size(const stencil_instance *instance)
{
    if (!instance) return 0;
    const Matrix *matrix = &instance->matrix;
    return cache_size(size_bits(instance->n), matrix->signed_unit || matrix->dimensions == 1);
}

int stencil_commit_stream(FILE *input, uint64_t n, unsigned dimensions, int signed_unit,
                          uint8_t *cache, size_t cache_bytes, uint8_t digest[32])
{
    if (!n || n > (UINT64_C(1) << 30) || (n & (n - 1)) || !input || !cache || !digest) {
        errno = EINVAL;
        return 0;
    }
    unsigned bits = size_bits(n);
    int wide = signed_unit || dimensions == 1;
    if (cache_bytes != cache_size(bits, wide)) { errno = EINVAL; return 0; }
    uint32_t width = UINT32_C(1) << (bits / 2);
    uint32_t height = (uint32_t)(n / width);
    if (!wide) return vc_commit(input, width, height, cache, digest);
    int exponent, shift;
    if (!witness_exponent(input, n, &exponent)) return 0;
    if (!witness_profile_shift(dimensions, signed_unit, bits, exponent, &shift)) {
        errno = ERANGE;
        return 0;
    }
    int32_t prefix = exponent;
    memcpy(cache, &prefix, sizeof(prefix));
    return vc_commit_wide(input, width, height, exponent, cache + sizeof(prefix), digest);
}

int stencil_commit(const stencil_instance *instance, const double *solution,
                   size_t count, uint8_t *cache, size_t cache_bytes, uint8_t digest[32])
{
    if (!instance || count != instance->n || count > SIZE_MAX / sizeof(double) ||
        !solution || !cache || !digest || cache_bytes != stencil_commit_size(instance))
        return EINVAL;
    FILE *input = fmemopen((void *)solution, count * sizeof(double), "rb");
    if (!input) return errno;
    fenv_t saved;
    int status = EIO;
    if (feholdexcept(&saved) == 0) {
        if (fesetround(FE_TONEAREST) == 0) {
            errno = 0;
            int ok = stencil_commit_stream(input, instance->n, instance->matrix.dimensions,
                                           instance->matrix.signed_unit, cache, cache_bytes, digest);
            status = ok ? 0 : (errno ? errno : EIO);
        }
        if (fesetenv(&saved) != 0) status = EIO;
    }
    if (fclose(input) != 0 && status == 0) status = errno;
    return status;
}
