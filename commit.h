#ifndef STENCIL_COMMIT_H
#define STENCIL_COMMIT_H

#include <stdint.h>
#include <stdio.h>

/* The rows and weights hold height 32-byte elements. z holds width scalars.
   input has exactly height rows of width little-endian binary64 values.
   The caller sets FE_TONEAREST. */
int vc_commit(FILE *input, uint32_t width, uint32_t height, unsigned char *rows, unsigned char digest[32]);
int vc_digest(uint32_t width, uint32_t height, const unsigned char *rows, unsigned char digest[32]);
/* Wide profiles bind both dimensions and the shared binary exponent. */
int vc_commit_wide(FILE *input, uint32_t width, uint32_t height, int exponent,
                   unsigned char *rows, unsigned char digest[32]);
int vc_digest_wide(uint32_t width, uint32_t height, int exponent,
                   const unsigned char *rows, unsigned char digest[32]);
int vc_verify(uint32_t width, uint32_t height, const unsigned char *rows, const unsigned char *weights,
              const unsigned char *z);
#endif
