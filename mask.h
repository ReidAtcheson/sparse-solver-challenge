#ifndef STENCIL_MASK_H
#define STENCIL_MASK_H

#include "field.h"
#include <stdint.h>
#include <stdio.h>

#define MASK_COUNT 128

typedef struct Mask Mask;

/* xi is a seekable, private file of exactly n little-endian binary64 values.
 * Each chunk is quantized to signed fixed-point integers before accumulation.
 * These routines terminate with a diagnostic on I/O or cryptographic errors. */
void mask_sums(FILE *xi, uint64_t n, const unsigned char seed[32], __int128 out[MASK_COUNT]);
void mask_sums_wide(FILE *xi, uint64_t n, const unsigned char seed[32],
                    __int128 out[MASK_COUNT], int exponent);
Mask *mask_begin(const unsigned char seed[32], const F coeff[MASK_COUNT]);
F mask_next(Mask *mask);
void mask_end(Mask *mask);

#endif
