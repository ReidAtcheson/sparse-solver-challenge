#ifndef STENCIL_THREE_BAND_LU_H
#define STENCIL_THREE_BAND_LU_H
#include <stdint.h>

/* Private interface to the optional solver built alongside stencil. The matrix
 * is symmetric and sorted. Entries are (column << 1) | (coefficient < 0). */
typedef int three_band_lu_fn(int n, const uint32_t *offsets, const uint32_t *entries,
                             const double *rhs, double *solution);
three_band_lu_fn stencil_three_band_lu;
#endif
