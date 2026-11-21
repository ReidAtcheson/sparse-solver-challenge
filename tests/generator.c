/* Links operator.c to an alternate public generator, without matrix.c. */
#include "operator.h"

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
