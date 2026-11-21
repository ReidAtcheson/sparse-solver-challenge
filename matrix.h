#ifndef STENCIL_MATRIX_H
#define STENCIL_MATRIX_H
#include <stdint.h>

/* Public callers may request any row in any order. */
typedef struct {
    uint32_t side;
    unsigned side_log2;
    unsigned dimensions;
    int signed_unit;
    uint64_t horizontal_key, vertical_key, depth_key, rhs_key;
} Matrix;

/* The protocol consumes this streaming interface only. Emit each (column,
 * signed coefficient) synchronously and return the row's signed RHS. Terms
 * may repeat or arrive in any order. There is no row buffer or degree
 * parameter. A generator must use bounded local state. For this integer
 * interface the emitted absolute coefficients must sum to at most 65536 per
 * row and the RHS numerator is a signed 32-bit integer. The signed-unit
 * profile divides that numerator by the number of rows, with integer RHS
 * values in the two legacy profiles. The July comparison emits 16*A and
 * 256*b. Columns lie in [0, side^dimensions). Give a changed
 * generator a new signed profile identifier, even with unchanged bounds. */
#define MATRIX_PROFILE_ID "seeded-stencil-exact-residual-v1"
#define MATRIX_PROFILE_3D_ID "seeded-stencil-3d-exact-residual-v1"
#define MATRIX_SIGNED3D_ID "signed-unit-torus-3d-backward80-v2"
#define MATRIX_BLOG_ID "july-tridiagonal-fixed-nonce-80-v1"
enum { MATRIX_ID_BYTES = 40 };
typedef struct matrix_profile {
    char id[MATRIX_ID_BYTES];  /* canonical zero-padded wire bytes */
    const char *short_name, *start_command;
    unsigned dimensions;
    int signed_unit;
    unsigned max_terms;
    uint32_t min_side, max_side;
    int allow_beacon;
    Matrix (*initialize)(uint32_t side, const uint8_t seed[32]);
} MatrixProfile;

/* Each successful lookup returns immutable, process-lifetime metadata. */
const MatrixProfile *matrix_profile_wire(const uint8_t id[MATRIX_ID_BYTES]);
const MatrixProfile *matrix_profile_id(const char *id);
const MatrixProfile *matrix_profile_command(const char *name, int local_start);
const MatrixProfile *matrix_profile_kind(unsigned dimensions, int signed_unit);
int matrix_profile_side(const MatrixProfile *profile, uint64_t side);
enum { MATRIX_ABS_ROW_LIMIT = 65536 };
typedef void (*MatrixTerm)(void *context, uint64_t column, int32_t coefficient);
int32_t matrix_visit(const Matrix *a, uint64_t row, MatrixTerm emit, void *context);

/* Fixture-only fixed stencil representation used by the numerical solver. */
typedef struct {
    uint64_t col[7];
    int val[7];
    int count, rhs;
} MatrixRow;

/* side must be a power of two. */
Matrix matrix_init(uint32_t side, const unsigned char seed[32]);
/* dimensions is 2 or 3. Registered profiles satisfy side^dimensions <= 2^30. */
Matrix matrix_init_profile(uint32_t side, unsigned dimensions, const unsigned char seed[32]);
/* Signed periodic seven-point matrix. matrix_visit returns the numerator
 * of b_i = +/-1 / side^3. Every eigenvalue is seed independent. */
Matrix matrix_init_signed3d(uint32_t side, const unsigned char seed[32]);
/* Fixed public replay of the July v4 benchmark, with n tridiagonal rows. */
Matrix matrix_init_blog(uint32_t n);
int matrix_vertex_sign(const Matrix *a, uint64_t i);
static inline uint64_t matrix_size(uint32_t side, unsigned dimensions)
{
    if (dimensions == 1) return side;
    uint64_t plane = (uint64_t)side * side;
    return dimensions == 3 ? plane * side : plane;
}
/* Precondition: i < matrix_size(a->side, a->dimensions). */
void matrix_row(const Matrix *a, uint64_t i, MatrixRow *r);

int solve_main(int argc, char **argv);
#endif
