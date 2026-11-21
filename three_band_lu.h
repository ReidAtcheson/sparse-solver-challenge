#ifndef STENCIL_THREE_BAND_LU_H
#define STENCIL_THREE_BAND_LU_H
#include <stdint.h>

/* Private interface to the optional solver built alongside stencil. The matrix
 * is symmetric and sorted. Entries are (column << 1) | (coefficient < 0). */
typedef int three_band_lu_fn(int n, const uint64_t *offsets, const uint32_t *entries,
                             const double *rhs, double *solution);
struct three_band_lu_backend {
    int (*can_factor)(uint64_t nnz); /* Check input and estimated initial factor capacity. */
    three_band_lu_fn *solve;
};
extern const struct three_band_lu_backend stencil_three_band_lu_v2;
#endif
