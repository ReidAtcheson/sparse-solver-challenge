/* Links operator.c to an alternate public generator, without matrix.c. */
#include "operator.h"
#include "witness.h"

#include <math.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

/* The 8^3 physical cube uses a 32-by-16 polynomial commitment layout. */
enum { SIDE = 8, N = SIDE * SIDE * SIDE, WIDTH = 16, HEIGHT = N / WIDTH };
static const int displacement[] = {5, 803, 17, 396, 552, 66, 511, 5, 17};
static const int coefficient[] = {-3, 2, 4, -1, 3, -2, 1, 6, -2};

static unsigned column(unsigned row, unsigned k)
{
    return (37 * row + displacement[k]) % N;
}

/* Seven to nine streamed terms, distant columns, repeated output columns and
 * no symmetry. Each test row's absolute coefficient sum is at most 24. */
int32_t matrix_visit(const Matrix *a, uint64_t row, MatrixTerm emit, void *context)
{
    if (a->dimensions == 1 && a->signed_unit) {
        if (row) emit(context, row - 1, (row - 1) % 2 ? 1 : -1);
        emit(context, row, -1);
        if (row + 1 < a->side) emit(context, row + 1, row % 2 ? 1 : -1);
        return matrix_three_band_rhs(a, row);
    }
    for (unsigned k = 0; k < 7 + row % 3; ++k)
        emit(context, column((unsigned)row, k), coefficient[k]);
    /* This fixture uses horizontal_key solely to select malformed variants. */
    if (row == 1) {
        switch (a->horizontal_key) {
        case 1: emit(context, N, 1); break;
        case 2: emit(context, 0, INT_MIN); break;
        case 3: emit(context, 13, MATRIX_ABS_ROW_LIMIT); break;
        case 4: return INT32_MIN;
        }
    }
    return row % 17 == 0 ? 2 : row % 3 == 0 ? -1 : 1;
}

/* A second, symmetric fixture exercises a verifier that sees each upper
 * edge just once and obtains the two public interpolation weights separately. */
int matrix_three_band_scan(const Matrix *a, int (*emit)(void *, size_t, size_t, int), void *context)
{
    for (size_t i = 0; i + 1 < a->side; ++i) {
        int error = emit(context, i, i + 1, i % 2 ? 1 : -1);
        if (error) return error;
    }
    for (size_t i = 0; i < a->side; ++i) {
        int error = emit(context, i, i, -1);
        if (error) return error;
    }
    return 0;
}

int32_t matrix_three_band_rhs(const Matrix *a, uint64_t i)
{
    (void)a;
    return i % 3 ? -1 : 1;
}

static void require(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "generator test: %s\n", message);
        exit(1);
    }
}

static void equal_element(FILE *f, F expected)
{
    F got;
    require(fread(&got, sizeof(got), 1, f) == 1 && fcmp(got, expected) == 0,
            "wrong streamed element");
}

static F power_of_two(unsigned exponent)
{
    F value = fzero();
    value.l[exponent / 64] = UINT64_C(1) << (exponent % 64);
    return value;
}

/* Exercise the exact scaling selected at the maximum registered dimension,
 * using a small tridiagonal operator so the regression needs no large files.
 * For X = 2^78 e_0, AX has just two nonzeros, both -2^78, on opposite RHS
 * signs. Their mixed terms cancel in rho = N h² + 2 (k 2^78)². */
static void check_wide_residual(int exponent, int expected_shift)
{
    int shift;
    require(witness_profile_shift(1, 1, 30, exponent, &shift) && shift == expected_shift,
            "wrong endpoint exponent scaling");
    unsigned k_bits = shift < 0 ? (unsigned)-shift : 0;
    unsigned h_bits = shift > 0 ? (unsigned)shift : 0;
    Matrix a = {.side = N, .dimensions = 1, .signed_unit = 1};
    double y[N] = {0};
    y[0] = ldexp(1.0, exponent);
    FILE *xi = tmpfile();
    require(xi && fwrite(y, sizeof(*y), N, xi) == N, "write wide witness");
    F rho, q;
    FILE *r = op_residual_wide(xi, &a, N, exponent, shift, &rho, &q);
    __int128 kx = (__int128)1 << (78 + k_bits), h = (__int128)1 << h_bits;
    for (unsigned i = 0; i < N; ++i) {
        __int128 defect = (i < 2 ? -kx : 0) - h * matrix_three_band_rhs(&a, i);
        equal_element(r, fwide(defect));
    }
    F expected = fadd(fmul(fsmall(N), power_of_two(2*h_bits)), power_of_two(157 + 2*k_bits));
    require(!fcmp(rho, expected) && !fcmp(q, power_of_two(156)), "wrong wide energies");
    require(!fclose(xi) && !fclose(r), "close");
}

int main(void)
{
    Matrix a = {.side = SIDE, .side_log2 = 3, .dimensions = 3};
    int64_t witness[N], transposed[N] = {0}, expected_rhs = 0, expected_endpoint = 0;
    F rowhi[HEIGHT], rowlo[WIDTH], colhi[HEIGHT], collo[WIDTH], energy, b;
    FILE *input = tmpfile();
    require(input != NULL, "tmpfile");
    for (int i = 0; i < N; ++i) {
        witness[i] = (73 * i % 101) - 50;
        double v = (double)witness[i] * 0x1p-58;
        require(fwrite(&v, sizeof(v), 1, input) == 1, "write witness");
    }
    for (int i = 0; i < HEIGHT; ++i) {
        rowhi[i] = fsmall(i - 5);
        colhi[i] = fsmall(3 * i - 8);
    }
    for (int i = 0; i < WIDTH; ++i) {
        rowlo[i] = fsmall(2 * i - 11);
        collo[i] = fsmall(i - 19);
    }
    FILE *residual = op_residual(input, &a, N, &energy);
    __int128 exact_energy = 0;
    __uint128_t expected_rhs_energy = 0, rhs_energy;
    for (int i = 0; i < N; ++i) {
        int rhs = i % 17 == 0 ? 2 : i % 3 == 0 ? -1 : 1;
        int rw = (i / WIDTH - 5) * (2 * (i % WIDTH) - 11);
        int64_t ri = -((int64_t)1 << 58) * rhs;
        expected_rhs += (int64_t)rw * rhs;
        expected_rhs_energy += (unsigned)(rhs * rhs);
        for (int k = 0; k < 7 + i % 3; ++k) {
            int j = (int)column((unsigned)i, (unsigned)k);
            ri += coefficient[k] * witness[j];
            transposed[j] += (int64_t)rw * coefficient[k];
            int cw = (3 * (j / WIDTH) - 8) * (j % WIDTH - 19);
            expected_endpoint += (int64_t)rw * coefficient[k] * cw;
        }
        equal_element(residual, fsmall(ri));
        exact_energy += (__int128)ri * ri;
    }
    require(fcmp(energy, fwide(exact_energy)) == 0, "wrong integer energy");
    FILE *transpose = op_transpose(&a, N, WIDTH, rowhi, rowlo, &b);
    require(fcmp(b, fsmall(expected_rhs)) == 0, "wrong transpose RHS");
    for (int i = 0; i < N; ++i) equal_element(transpose, fsmall(transposed[i]));
    F endpoint = op_endpoint(&a, N, WIDTH, rowhi, rowlo, colhi, collo, &b, &rhs_energy);
    require(fcmp(b, fsmall(expected_rhs)) == 0, "wrong endpoint RHS");
    require(fcmp(endpoint, fsmall(expected_endpoint)) == 0, "wrong matrix endpoint");
    require(rhs_energy == expected_rhs_energy, "wrong exact RHS norm");
    require(!fclose(input) && !fclose(residual) && !fclose(transpose), "close");

    Matrix symmetric = {.dimensions = 1, .signed_unit = 1, .side = N};
    F ref = fzero(), ref_rhs = fzero();
    for (unsigned i = 0; i < N; ++i) {
        F wi = fmul(rowhi[i/WIDTH], rowlo[i%WIDTH]);
        F row = fzero();
        for (unsigned j = i ? i-1 : 0; j <= i+1 && j < N; ++j) {
            int sign = j == i ? -1 : (i < j ? i : j) % 2 ? 1 : -1;
            row = fadd(row, fscale(fmul(colhi[j/WIDTH], collo[j%WIDTH]), sign));
        }
        ref = fadd(ref, fmul(wi, row));
        ref_rhs = fadd(ref_rhs, fscale(wi, i % 3 ? -1 : 1));
    }
    endpoint = op_endpoint(&symmetric, N, WIDTH, rowhi, rowlo, colhi, collo, &b, &rhs_energy);
    require(!fcmp(endpoint, ref) && !fcmp(b, ref_rhs) && rhs_energy == N,
            "symmetric scan differs from explicit rows");

    check_wide_residual(-60, 108);
    check_wide_residual(48, 0);
    check_wide_residual(54, -6);

    a.horizontal_key = 4;
    (void)op_endpoint(&a, N, WIDTH, rowhi, rowlo, colhi, collo, &b, &rhs_energy);
    require(rhs_energy == expected_rhs_energy - 1 + ((__uint128_t)1 << 62), "INT32_MIN RHS square");
    for (unsigned bad = 1; bad <= 3; ++bad) {
        pid_t pid = fork();
        require(pid >= 0, "fork");
        if (!pid) {
            if (!freopen("/dev/null", "w", stderr)) _exit(2);
            a.horizontal_key = bad;
            (void)op_endpoint(&a, N, WIDTH, rowhi, rowlo, colhi, collo, &b, &rhs_energy);
            _exit(0);
        }
        int status;
        require(waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
                WEXITSTATUS(status) == EXIT_FAILURE, "validator accepted malformed generator");
    }
    puts("PASS rectangular streamed directed generator, exact residual and endpoints, signed RHS, three profile violations");
    return 0;
}
