#define _GNU_SOURCE
#include "matrix.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>

typedef struct {
    uint32_t column;
    int count;
} Expected;

static void check_entry(void *context, uint64_t column, int32_t value)
{
    Expected *want = context;
    assert(column == want->column && value == -1 && !want->count);
    ++want->count;
}

/* Exercise the row walker at a real >32-bit CSR position. Reserve virtual
 * addresses but commit a single page, even for the last entry of a billion-row
 * graph. Containers with small address-space limits still check the counts. */
int main(void)
{
    const uint32_t n = MATRIX_THREE_BAND_MAX_ROWS;
    const uint64_t nnz = matrix_three_band_nnz(n);
    assert(nnz == UINT64_C(7516192756));
    _Static_assert(sizeof(*((Matrix *)0)->offsets) == 8, "need 64-bit CSR offsets");
    assert(matrix_profile_side(matrix_profile_id(MATRIX_THREE_BAND_ID), n));
    assert(!matrix_profile_side(matrix_profile_id(MATRIX_THREE_BAND_V1_ID), n));
    if (nnz > SIZE_MAX / sizeof(uint32_t)) {
        puts("PASS billion-row counts; host address width limits the row-walker test");
        return 0;
    }
    size_t bytes = (size_t)nnz * sizeof(uint32_t);
    uint32_t *entries = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (entries == MAP_FAILED && errno == ENOMEM) {
        puts("PASS billion-row counts; virtual address limit precludes the row-walker test");
        return 0;
    }
    assert(entries != MAP_FAILED);
    Expected want = {.column = n - 1};
    uint64_t offsets[2] = {nnz - 1, nnz};
    Matrix a = {.side = n, .dimensions = 1, .signed_unit = 1,
                .entries = entries, .offsets = offsets};
    entries[nnz-1] = (want.column << 1) | 1;
    matrix_visit(&a, 0, check_entry, &want);
    assert(want.count == 1);
    assert(munmap(entries, bytes) == 0);
    puts("PASS billion-row counts, 64-bit CSR traversal and last packed column");
}
