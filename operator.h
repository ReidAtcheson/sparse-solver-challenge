#ifndef STENCIL_OPERATOR_H
#define STENCIL_OPERATOR_H

#include "field.h"
#include "matrix.h"
#include <stdio.h>

/* xi is the private, seekable little-endian binary64 input. Its entries are
 * quantized only when fetched. Returned tmpfiles hold n native F values
 * and are positioned at zero.
 * The caller owns them. A disk I/O failure terminates the CLI.
 * width is the power-of-two low-bit dimension of the commitment table;
 * hi arrays have n/width entries and lo arrays have width entries. */
FILE *op_residual(FILE *xi, const Matrix *a, uint64_t n, F *energy);
/* Signed-unit profile. R = 2^max(-rhs_shift,0) A X -
 * 2^max(rhs_shift,0) sign(b), where rhs_shift=78-exponent-log2(n).
 * Return the initial R table and the squared norms of R and X. */
FILE *op_residual_wide(FILE *xi, const Matrix *a, uint64_t n, int exponent,
                       int rhs_shift, F *residual_energy, F *solution_energy);
FILE *op_transpose(const Matrix *a, uint64_t n, uint32_t width, const F *rowhi,
                   const F *rowlo, F *bval);
F op_endpoint(const Matrix *a, uint64_t n, uint32_t width, const F *rowhi, const F *rowlo,
              const F *colhi, const F *collo, F *bval, __uint128_t *rhs_squared);

#endif
