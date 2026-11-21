#ifndef STENCIL_LIBRARY_INTERNAL_H
#define STENCIL_LIBRARY_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Shared with the CLI. input points to the beginning of exactly n binary64
 * coordinates, and the calling thread uses FE_TONEAREST. Return 1 on success. */
int stencil_commit_stream(FILE *input, uint64_t n, unsigned dimensions, int signed_unit,
                          uint8_t *cache, size_t cache_bytes, uint8_t digest[32]);

#endif
