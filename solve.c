#include "matrix.h"
#include "receipt.h"
#include "three_band_lu.h"

#include <dlfcn.h>
#include <time.h>

#include <float.h>
#include <complex.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(double) == 8 && DBL_MANT_DIG == 53 && DBL_MAX_EXP == 1024,
               "this solver needs IEEE 754 binary64");

/* Initial residual is in r, initial iterate is zero. The screened operator's
 * spectrum lies in [4,36] in 2D and [4,52] in 3D. */
static int cg(const Matrix *a, size_t n, double *iterate,
              double *r, double *p, double *ap, double tol)
{
    double rr = 0;
    for (size_t i = 0; i < n; ++i) {
        p[i] = r[i];
        rr += r[i] * r[i];
    }
    double target = rr * tol * tol;
    for (int iteration = 0; iteration < 160; ++iteration) {
        if (rr <= target) return iteration;
        double pap = 0;
        for (size_t i = 0; i < n; ++i) {
            MatrixRow row;
            matrix_row(a, i, &row);
            double sum = 0;
            for (int j = 0; j < row.count; ++j)
                sum += row.val[j] * p[row.col[j]];
            ap[i] = sum;
            pap += p[i] * sum;
        }
        if (!(pap > 0) || !isfinite(pap)) return -1;
        double alpha = rr / pap;
        double next_rr = 0;
        for (size_t i = 0; i < n; ++i) {
            iterate[i] += alpha * p[i];
            r[i] -= alpha * ap[i];
            next_rr += r[i] * r[i];
        }
        double beta = next_rr / rr;
        for (size_t i = 0; i < n; ++i)
            p[i] = r[i] + beta * p[i];
        rr = next_rr;
    }
    return -1;
}

static double true_residual(const Matrix *a, size_t n, const double *x,
                            double *r)
{
    double squared = 0;
    double rhs_unit = a->signed_unit ? 1.0 / (double)n : 1.0;
    for (size_t i = 0; i < n; ++i) {
        MatrixRow row;
        matrix_row(a, i, &row);
        long double residual = rhs_unit * row.rhs;
        for (int j = 0; j < row.count; ++j)
            residual -= (long double)row.val[j] * x[row.col[j]];
        r[i] = (double)residual;
        squared += r[i] * r[i];
    }
    return sqrt(squared / (double)n) / rhs_unit;
}

static int write_vector(const char *path, const double *x, size_t n)
{
    const uint16_t one = 1;
    FILE *out = fopen(path, "wbx");
    if (!out) {
        perror(path);
        return 0;
    }
    int success = 1;
    if (*(const unsigned char *)&one) {
        success = fwrite(x, sizeof(*x), n, out) == n;
    } else {
        for (size_t i = 0; success && i < n; ++i) {
            uint64_t bits;
            unsigned char le[8];
            memcpy(&bits, x + i, sizeof(bits));
            for (unsigned j = 0; j < 8; ++j) le[j] = (unsigned char)(bits >> (8 * j));
            success = fwrite(le, 1, sizeof(le), out) == sizeof(le);
        }
    }
    if (fclose(out)) success = 0;
    if (!success) {
        perror(path);
        remove(path);
    }
    return success;
}

/* A = D H D, where H is the periodic constant-coefficient stencil and D is
 * the seed-derived diagonal of signs. The private solver exploits the Fourier
 * basis of H. Neither the prover nor the verifier uses this solver. */
static void fft_line(double complex *v, size_t stride, unsigned side,
                     const double complex *roots, int inverse)
{
    for (unsigned i = 1, j = 0; i < side; ++i) {
        unsigned bit = side >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) {
            double complex save = v[i * stride];
            v[i * stride] = v[j * stride];
            v[j * stride] = save;
        }
    }
    for (unsigned len = 2; len <= side; len *= 2) {
        unsigned half = len / 2;
        for (unsigned j = 0; j < half; ++j) {
            double complex root = roots[j * (side / len)];
            if (inverse) root = conj(root);
            for (unsigned k = j; k < side; k += len) {
                double complex first = v[k * stride];
                double complex second = root * v[(k + half) * stride];
                v[k * stride] = first + second;
                v[(k + half) * stride] = first - second;
            }
        }
    }
}

static void fft_cube(double complex *work, size_t n, uint32_t side,
                     const double complex *roots, int inverse)
{
    for (size_t stride = 1; stride < n; stride *= side)
        for (size_t slab = 0; slab < n; slab += stride * side)
            for (size_t offset = 0; offset < stride; ++offset)
                fft_line(work + slab + offset, stride, side, roots, inverse);
}

static int solve_signed_torus(const Matrix *a, size_t n, const char *path)
{
    uint32_t side = a->side;
    if (n > SIZE_MAX / sizeof(double complex)) return 0;
    double complex *work = malloc(n * sizeof(*work)), *roots = malloc(side * sizeof(*roots));
    long double *modes = malloc(side * sizeof(*modes));
    double *x = calloc(n, sizeof(*x)), *r = malloc(n * sizeof(*r));
    int ok = 0;
    if (!work || !roots || !modes || !x || !r) {
        fprintf(stderr, "FFT allocation failed for %zu rows\n", n);
        goto done;
    }
    long double angle_step = -2 * acosl(-1.0L) / side;
    for (uint32_t j = 0; j < side; ++j) {
        long double cosine = cosl(j * angle_step);
        roots[j] = (double)cosine + I * (double)sinl(j * angle_step);
        modes[j] = 2 * cosine;
    }
    for (size_t i = 0; i < n; ++i) {
        MatrixRow row;
        matrix_row(a, i, &row);
        r[i] = row.rhs / (double)n;
    }
    double relative[2];
    for (unsigned pass = 0; pass < 2; ++pass) {
        for (size_t i = 0; i < n; ++i)
            work[i] = r[i] * matrix_vertex_sign(a, i);
        fft_cube(work, n, side, roots, 0);
        size_t i = 0;
        for (uint32_t z = 0; z < side; ++z)
            for (uint32_t y = 0; y < side; ++y)
                for (uint32_t j = 0; j < side; ++j, ++i) {
                    long double eigenvalue = 1 + modes[j] + modes[y] + modes[z];
                    work[i] /= (double)(eigenvalue * n);
                }
        fft_cube(work, n, side, roots, 1);
        for (size_t j = 0; j < n; ++j)
            x[j] += matrix_vertex_sign(a, j) * creal(work[j]);
        relative[pass] = true_residual(a, n, x, r);
        if (!isfinite(relative[pass])) goto done;
    }
    fprintf(stderr, "periodic 3D FFT + refinement, relative RHS residual %.12e -> %.12e\n",
            relative[0], relative[1]);
    ok = write_vector(path, x, n);
done:
    free(r); free(x); free(modes); free(roots); free(work);
    return ok;
}

/* The July solver uses the binary64 Thomas recurrence, then rounds each
 * output to Q63.64. Here its modified-RHS array also holds the final vector.
 * All coefficients and RHS values are dyadic. Preserve the two operations
 * in the back substitution even in a build targeting hardware with FMA. */
static int solve_blog(const Matrix *a, size_t n, const char *path)
{
    const double diagonal = 0.5, off = 0.0625;
    double *upper = malloc(n * sizeof(*upper));
    double *x = malloc(n * sizeof(*x));
    int ok = 0;
    if (!upper || !x) {
        fputs("Thomas solver allocation failed\n", stderr);
        goto done;
    }
    MatrixRow row;
    matrix_row(a, 0, &row);
    upper[0] = off / diagonal;
    x[0] = (row.rhs / 256.0) / diagonal;
    for (size_t i = 1; i < n; ++i) {
        matrix_row(a, i, &row);
        double pivot = diagonal - off * upper[i-1];
        upper[i] = i+1 < n ? off / pivot : 0.0;
        x[i] = (row.rhs / 256.0 - off * x[i-1]) / pivot;
    }
    for (size_t i = n-1; i > 0; --i) {
        volatile double product = upper[i-1] * x[i];
        x[i-1] -= product;
    }
    for (size_t i = 0; i < n; ++i) x[i] = scalbn(round(scalbn(x[i],64)), -64);
    ok = write_vector(path, x, n);
done:
    free(x);
    free(upper);
    return ok;
}

static double elapsed_seconds(struct timespec a, struct timespec b)
{
    return (double)(b.tv_sec - a.tv_sec) + (double)(b.tv_nsec - a.tv_nsec) * 1e-9;
}

static int solve_three_band(Matrix *a, size_t n, const char *path)
{
    /* Only the private solver loads SuperLU and its BLAS runtime. */
    void *library = dlopen("$ORIGIN/libstencil_superlu.so", RTLD_NOW | RTLD_LOCAL);
    if (!library) {
        fprintf(stderr, "three-band solver unavailable: %s\n"
                "Install libsuperlu-dev and rebuild with make, or supply your own x.f64.\n",
                dlerror());
        return 0;
    }
    three_band_lu_fn *solve = (three_band_lu_fn *)dlsym(library, "stencil_three_band_lu");
    struct timespec start, prepared, finished;
    int ok = 0;
    double *rhs = malloc(n * sizeof(*rhs)), *x = malloc(n * sizeof(*x));
    if (!solve || !rhs || !x) {
        fputs("failed to initialize three-band solver\n", stderr);
        goto done;
    }
    clock_gettime(CLOCK_MONOTONIC, &start);
    int error = matrix_prepare(a);
    if (error) {
        fprintf(stderr, "three-band generation failed: %s\n", strerror(error));
        goto done;
    }
    for (size_t i = 0; i < n; ++i) rhs[i] = matrix_three_band_rhs(a, i) / (double)n;
    clock_gettime(CLOCK_MONOTONIC, &prepared);
    ok = solve((int)n, a->offsets, a->entries, rhs, x);
    clock_gettime(CLOCK_MONOTONIC, &finished);
    fprintf(stderr, "generation_seconds=%.9f solve_seconds=%.9f\n",
            elapsed_seconds(start, prepared), elapsed_seconds(prepared, finished));
    if (ok) ok = write_vector(path, x, n);
done:
    matrix_release(a);
    free(rhs); free(x);
    dlclose(library);
    return ok;
}

int solve_main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: solve AUTHORITY.pub START.receipt NEW-SOLUTION.f64\n");
        return 2;
    }
    unsigned char start[RC_START_BYTES];
    struct rc_info info;
    if (!rc_read_exact(argv[2], start, sizeof(start)) ||
        !rc_verify_start(argv[1], start, &info)) {
        fprintf(stderr, "invalid start receipt or authority public key\n");
        return 1;
    }
    uint64_t rows = matrix_size(info.side, info.dimensions);
    if (!info.side || (info.side & (info.side - 1)) || rows > SIZE_MAX / sizeof(double)) {
        fprintf(stderr, "unsupported dimensions\n");
        return 1;
    }
    size_t n = (size_t)rows;
    Matrix a = info.profile->initialize(info.side, info.seed);
    if (info.dimensions == 1 && info.signed_unit)
        return solve_three_band(&a, n, argv[3]) ? 0 : 1;
    if (info.profile == matrix_profile_id(MATRIX_BLOG_ID))
        return solve_blog(&a, n, argv[3]) ? 0 : 1;
    if (info.profile == matrix_profile_id(MATRIX_SIGNED3D_ID))
        return solve_signed_torus(&a, n, argv[3]) ? 0 : 1;
    double *x = calloc(n, sizeof(*x)), *delta = NULL;
    double *r = malloc(n * sizeof(*r)), *p = malloc(n * sizeof(*p));
    double *ap = malloc(n * sizeof(*ap));
    int success = 0;
    if (!x || !r || !p || !ap) goto out_of_memory;
    for (size_t i = 0; i < n; ++i) {
        MatrixRow row;
        matrix_row(&a, i, &row);
        r[i] = row.rhs;
    }
    int first = cg(&a, n, x, r, p, ap, 1e-14);
    if (first < 0) goto convergence_error;
    double before = true_residual(&a, n, x, r);
    delta = calloc(n, sizeof(*delta));
    if (!delta) goto out_of_memory;
    int refine = cg(&a, n, delta, r, p, ap, 1e-5);
    if (refine < 0) goto convergence_error;
    for (size_t i = 0; i < n; ++i) x[i] += delta[i];
    double after = true_residual(&a, n, x, r);
    if (!isfinite(after)) goto convergence_error;
    success = write_vector(argv[3], x, n);
    if (success)
        fprintf(stderr, "CG iterations %d + %d refinement, relative RHS residual %.4e -> %.4e\n",
                first, refine, before, after);
    goto done;
out_of_memory:
    fprintf(stderr, "solver allocation failed for %zu rows\n", n);
    goto done;
convergence_error:
    fprintf(stderr, "screened CG failed to converge\n");
done:
    free(x); free(r); free(p); free(ap); free(delta);
    return success ? 0 : 1;
}
