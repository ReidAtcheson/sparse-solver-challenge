#ifndef STENCIL_FOLD_H
#define STENCIL_FOLD_H

#include "field.h"
#include <stdio.h>

typedef struct { F x, weight; } FoldPair;
typedef struct { F g0, quadratic; } Moment;

/* All counts are powers of two, at least 2. A scalar table represents x*x;
 * a pair table represents x*weight. Each fold replaces its table in place
 * and returns the last folded entry (the endpoint at count==2). 'next' is
 * the following round's moment, or zero at the endpoint. */
Moment fold_moment(FILE *table, uint64_t count, int product);
FoldPair fold_step(FILE *table, uint64_t count, int product, F r, Moment *next);

/* The first product round keeps the private witness in its original binary64
 * file. prepare adds masks to the scalar transpose table and computes the first
 * moment. first changes that same table into n/2 folded pairs, byte-for-byte
 * within its original extent. Both operations reread xi starting at zero. */
Moment fold_product_prepare(FILE *table, FILE *xi, uint64_t n,
                            const unsigned char seed[32], const F coeff[128]);
FoldPair fold_product_first(FILE *table, FILE *xi, uint64_t n, F r, Moment *next);

/* Wide profiles batch the solution norm into the same product sumcheck.
 * Each initial weight is matvec_multiplier*A(u,j) + mask(j) + lambda*X_j. */
Moment fold_product_prepare_wide(FILE *table, FILE *xi, uint64_t n,
                            const unsigned char seed[32], const F coeff[128],
                            int exponent, F lambda, int matvec_multiplier);
FoldPair fold_product_first_wide(FILE *table, FILE *xi, uint64_t n, F r,
                                Moment *next, int exponent);

#endif
