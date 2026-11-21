#ifndef STENCIL_WITNESS_H
#define STENCIL_WITNESS_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Read exactly n little-endian binary64 values, quantized to signed integers
   with scale 2^58. The caller sets FE_TONEAREST. Returns 1 on success. */
int witness_read(FILE *f, int64_t *out, size_t n);
/* Same conversion, starting at coordinate first. Leaves the file offset alone. */
int witness_pread(int fd, int64_t *out, size_t n, uint64_t first);

/* For signed 80-bit witnesses, x = X * 2^(exponent-78).
   Scan exactly n doubles from the beginning and rewind on success. The
   exponent is ceil(log2(max |x|)), or zero for an all-zero witness. */
int witness_exponent(FILE *f, uint64_t n, int *exponent);
/* Return 1 and the signed shift used by this wide profile on success. */
int witness_profile_shift(unsigned dimensions, unsigned bits, int exponent, int *shift);
int witness_read_wide(FILE *f, __int128 *out, size_t n, int exponent);
int witness_pread_wide(int fd, __int128 *out, size_t n, uint64_t first, int exponent);
/* NULL selects the legacy signed-64 fixed scale and widens the result. */
int witness_read_encoded(FILE *f, __int128 *out, size_t n, const int *exponent);

#endif
