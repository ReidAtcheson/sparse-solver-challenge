#define _POSIX_C_SOURCE 200809L
#include "matrix.h"
#include "receipt.h"
#include <mkl.h>

#include <errno.h>
#include <float.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(double) == 8 && DBL_MANT_DIG == 53 && DBL_MAX_EXP == 1024,
               "binary64 required");
#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "the private solution file requires little-endian binary64"
#endif

typedef long long Index; /* pardiso_64 also uses 64-bit indices for fill. */
typedef struct {
    void *handle[64];
    Index iparm[64], n, type;
    Index *offset, *column;
    double *value;
} Solver;

static double seconds(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) { perror("clock_gettime"); exit(1); }
    return (double)ts.tv_sec + 1e-9 * (double)ts.tv_nsec;
}

typedef struct {
    Index index, column[7];
    double value[7];
    unsigned count;
} UpperRow;

static void upper_term(void *context, uint64_t column, int32_t coefficient)
{
    UpperRow *row = context;
    if (column < (uint64_t)row->index) return;
    if (row->count == 7) {
        fputs("invalid 3D stencil degree\n", stderr);
        exit(1);
    }
    /* PARDISO expects the upper triangle of the symmetric matrix, with sorted
     * column numbers. Keep generation order independent of the solver. */
    unsigned pos = row->count++;
    while (pos && (uint64_t)row->column[pos-1] > column) {
        row->column[pos] = row->column[pos-1];
        row->value[pos] = row->value[pos-1];
        --pos;
    }
    row->column[pos] = (Index)column;
    row->value[pos] = coefficient;
}

static int assemble(Solver *s, const Matrix *a, Index nnz, double *rhs)
{
    /* The unit diagonal gives static LDL^T orderings many exactly zero
     * pivots. Factor A + shift I, then refine against the original A.
     * tests/signed_spectrum.py verifies shift < min |lambda(A)|/64. */
    static const double shifts[] = {0x1p-16, 0x1p-19, 0x1p-19,
                                    0x1p-24, 0x1p-27, 0x1p-32};
    double shift = a->signed_unit ? shifts[a->side_log2 - 5] : 0;
    Index used = 0;
    for (Index i = 0; i < s->n; ++i) {
        UpperRow row = {.index = i};
        rhs[i] = matrix_visit(a, (uint64_t)i, upper_term, &row);
        if (a->signed_unit) rhs[i] /= (double)s->n;
        if (!row.count || row.column[0] != i || used + row.count > nnz) return 0;
        s->offset[i] = used;
        for (unsigned j = 0; j < row.count; ++j, ++used) {
            s->column[used] = row.column[j];
            s->value[used] = row.value[j] + (row.column[j] == i ? shift : 0);
        }
    }
    s->offset[s->n] = used;
    return used == nnz;
}

typedef struct {
    const double *x;
    long double sum;
} DotRow;

static void dot_term(void *context, uint64_t column, int32_t coefficient)
{
    DotRow *row = context;
    row->sum += (long double)coefficient * row->x[column];
}

/* Generate the true residual from the signed problem; refinement uses the
 * existing numerical factor. Only the solve process ever sees these vectors. */
static double residual(const Matrix *a, Index n, const double *x, double *rhs)
{
    long double norm = 0;
    for (Index i = 0; i < n; ++i) {
        DotRow dot = {.x = x};
        int32_t b = matrix_visit(a, (uint64_t)i, dot_term, &dot);
        long double r = (a->signed_unit ? b / (long double)n : b) - dot.sum;
        rhs[i] = (double)r;
        norm += r * r;
    }
    return (double)(sqrtl(norm/n) * (a->signed_unit ? n : 1));
}

static double signed_backward_error(Index n, const double *x, double relative_rhs)
{
    long double x_squared = 0;
    for (Index i = 0; i < n; ++i)
        x_squared += (long double)x[i] * x[i];
    /* ||A||_2 = 7, ||b||_2 = 1/sqrt(n). */
    return (double)(relative_rhs / (7 * sqrtl(n * x_squared) + 1));
}

static int phase(Solver *s, Index step, double *rhs, double *x)
{
    const Index max_factors = 1, factor = 1, nrhs = 1, verbosity = 0;
    Index error = 0, ignored_permutation = 0;
    pardiso_64(s->handle, &max_factors, &factor, &s->type, &step, &s->n, s->value,
               s->offset, s->column, &ignored_permutation, &nrhs, s->iparm, &verbosity,
               rhs, x, &error);
    if (error) fprintf(stderr, "PARDISO phase %lld failed with error %lld\n", step, error);
    return !error;
}

/* Keep a private partial file invisible until every byte has reached stdio's
 * backing file. A failed solve or I/O error cannot publish a prefix. */
static int write_solution(const char *path, const double *x, size_t n)
{
    size_t len = strlen(path) + sizeof(".XXXXXX");
    char *tmp = malloc(len);
    if (!tmp) return 0;
    snprintf(tmp, len, "%s.XXXXXX", path);
    int fd = mkstemp(tmp);
    if (fd < 0) { perror("create solution"); free(tmp); return 0; }
    FILE *f = fdopen(fd, "wb");
    int ok = 0;
    if (f) {
        ok = fwrite(x, sizeof(*x), n, f) == n;
        if (fclose(f)) ok = 0;
    } else {
        close(fd);
    }
    if (ok) ok = !link(tmp, path);
    if (!ok) perror("write new binary64 solution");
    unlink(tmp);
    free(tmp);
    return ok;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fputs("usage: stencil-direct3d AUTHORITY.pub START.receipt NEW-SOLUTION.f64\n", stderr);
        return 2;
    }
    struct rc_info info;
    uint8_t start[RC_START_BYTES];
    if (!rc_read_exact(argv[2], start, sizeof(start)) ||
        !rc_verify_start(argv[1], start, &info) ||
        (info.profile != matrix_profile_id(MATRIX_PROFILE_3D_ID) &&
         info.profile != matrix_profile_id(MATRIX_SIGNED3D_ID))) {
        fputs("invalid 3D signed start\n", stderr);
        return 1;
    }

    uint64_t n = matrix_size(info.side, info.dimensions);
    if (!n || n > (uint64_t)LLONG_MAX/4 || n > SIZE_MAX/(4 * sizeof(Index))) {
        fputs("grid too large\n", stderr);
        return 1;
    }
    Index nnz = info.signed_unit ? (Index)(4*n) :
                (Index)(n + 3 * (uint64_t)info.side * info.side * (info.side-1));
    Solver s = {.n = (Index)n, .type = info.signed_unit ? -2 : 2};
    Matrix a = info.profile->initialize(info.side, info.seed);
    s.offset = malloc((n+1) * sizeof(*s.offset));
    s.column = malloc(nnz * sizeof(*s.column));
    s.value = malloc(nnz * sizeof(*s.value));
    double *rhs = malloc(n * sizeof(*rhs));
    double *x = malloc(n * sizeof(*x));
    double *correction = malloc(n * sizeof(*correction));
    int success = 0, initialized = 0;
    if (!s.offset || !s.column || !s.value || !rhs || !x || !correction) {
        fputs("direct solver allocation failed\n", stderr);
        goto done;
    }
    if (!assemble(&s, &a, nnz, rhs)) {
        fputs("invalid symmetric 3D stencil structure\n", stderr);
        goto done;
    }
    s.iparm[0] = 1;  /* C iparm options below, rather than PARDISO defaults. */
    s.iparm[1] = 2;  /* METIS nested dissection */
    s.iparm[7] = 0;  /* external correction is explicit and measurable */
    s.iparm[17] = -1; /* report number of nonzeros in the factor */
    s.iparm[34] = 1; /* zero-based CSR */
    if (info.signed_unit) {
        s.iparm[9] = 8;
        s.iparm[10] = 1; /* allow scaling and weighted matching for pivot selection */
        s.iparm[12] = 1;
        s.iparm[20] = 1; /* symmetric indefinite 1x1/2x2 diagonal pivoting */
    }
    /* Ubuntu's MKL ships a GNU/OpenMP threading backend. Select it before
     * any computational call so ordering and factorization share a runtime. */
    if (mkl_set_threading_layer(MKL_THREADING_GNU) != MKL_THREADING_GNU) {
        fputs("cannot select the GNU MKL threading backend\n", stderr);
        goto done;
    }
    char version[256];
    mkl_get_version_string(version, sizeof(version));
    fprintf(stderr,"solver=%s algorithm=PARDISO_64-%s threading=GNU threads=%d side=%u"
            " n=%llu upper_nnz=%lld\n",version,info.signed_unit ? "indefinite" : "SPD",
            (int)mkl_get_max_threads(),info.side,
            (unsigned long long)n,nnz);
    double t0 = seconds();
    initialized = 1;
    if (!phase(&s, 11, rhs, x)) goto done;
    double analyzed = seconds();
    fprintf(stderr, "ordering_s=%.6f factor_nnz=%lld\n", analyzed-t0, s.iparm[17]);
    if (!phase(&s, 22, rhs, x)) goto done;
    double factored = seconds();
    if (!phase(&s, 33, rhs, x)) goto done;
    double solved = seconds();
    double before = residual(&a, s.n, x, rhs), after = before;
    if (!isfinite(before)) goto done;
    unsigned corrections = 0;
    unsigned limit = info.signed_unit ? 16 : 1;
    do {
        if (!phase(&s, 33, rhs, correction)) goto done;
        for (size_t i = 0; i < n; ++i) x[i] += correction[i];
        after = residual(&a, s.n, x, rhs);
        if (!isfinite(after)) goto done;
        ++corrections;
    } while (corrections < limit && signed_backward_error(s.n, x, after) > 0x1p-54);
    if (info.signed_unit) {
        double error = signed_backward_error(s.n, x, after);
        fprintf(stderr, "shifted_LDL_refinements=%u original_backward_2=%.12e\n",
                corrections, error);
        if (!(error <= 0x1p-53)) {
            fputs("shifted factor did not attain binary64 backward accuracy\n", stderr);
            goto done;
        }
    }
    fprintf(stderr, "factor_s=%.6f triangular_s=%.6f refinement_and_checks_s=%.6f"
            " relative_rhs_before=%.12e relative_rhs_after=%.12e\n",
            factored-analyzed, solved-factored, seconds()-solved, before, after);
    success = 1;
done:
    if (initialized && !phase(&s, -1, rhs, x)) success = 0;
    if (success) success = write_solution(argv[3], x, (size_t)n);
    free(correction); free(x); free(rhs);
    free(s.value); free(s.column); free(s.offset);
    return success ? 0 : 1;
}
