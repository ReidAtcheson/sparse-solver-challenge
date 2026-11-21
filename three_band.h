#ifndef STENCIL_THREE_BAND_H
#define STENCIL_THREE_BAND_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Signed bounded three-band challenge family, in original zero-based vertex
 * order. Functions return 0 on success and an errno value on failure. */
typedef struct tb_pattern tb_pattern;
typedef int (*tb_edge_fn)(void *context, size_t row, size_t column);

/* Replay a seed from row zero, emitting each strict-upper edge once, in draw
 * order. A callback error stops the scan and is returned to the caller.
 * Pattern storage is a rolling ring of 16-bit incoming counts with size
 * O(min(n, n^(2/3) + 201)). The generator
 * establishes round-to-nearest and restores the calling thread's floating
 * point environment on return. Callbacks must preserve its rounding mode. */
int tb_pattern_scan(size_t n, uint64_t pattern_seed, tb_edge_fn visit, void *context);

/* Cache the upper endpoints so multiple signs can reuse the same pattern.
 * On success the caller owns *out. The cached array is borrowed, immutable,
 * and lives until tb_pattern_free. Row i owns the next min(3,n-1-i)
 * endpoints. A failed creation leaves *out NULL. */
int tb_pattern_create(size_t n, uint64_t pattern_seed, tb_pattern **out);
void tb_pattern_free(tb_pattern *pattern);
size_t tb_pattern_dimension(const tb_pattern *pattern);
size_t tb_pattern_edge_count(const tb_pattern *pattern);
const size_t *tb_pattern_columns(const tb_pattern *pattern);

typedef enum { TB_SIGN_DRAW, TB_SIGN_SEED } tb_sign_mode;
typedef int (*tb_entry_fn)(void *context, size_t row, size_t column, int sign);

/* Stream signed upper edges in their pattern draw order, then the diagonal
 * in sign draw order. Each undirected edge carries both symmetric entries.
 * A supplied perm[n] maps each diagonal draw to its original vertex. It is
 * checked before any callbacks using a temporary n-bit visited set. A NULL
 * perm uses original index order. The solution, edge list and sparse matrix
 * are unnecessary. Any callback error stops the operation after the prefix
 * already delivered. Both edge and diagonal callbacks use round-to-nearest
 * and must preserve it. Restore the caller's floating point environment on
 * return, including when a callback stops the stream. */
int tb_signed_scan(size_t n, uint64_t pattern_seed, tb_sign_mode mode,
                   uint64_t sign_seed_or_draw, const size_t *perm,
                   tb_entry_fn emit, void *context);

/* Compatibility entry point for archived unbounded v1 transcripts. */
int tb_signed_scan_v1(size_t n, uint64_t pattern_seed, tb_sign_mode mode,
                      uint64_t sign_seed_or_draw, const size_t *perm,
                      tb_entry_fn emit, void *context);

typedef enum { TB_CSR, TB_CSC } tb_format;
typedef struct {
    size_t n, nnz;
    size_t *offsets, *indices;
    double *values;
} tb_sparse;

/* TB_SIGN_DRAW uses NumPy SeedSequence([n, pattern_seed, draw, 7531]),
 * draw >= 1. TB_SIGN_SEED uses a separate scalar seed, including zero.
 * Optional perm[n] maps METIS positions to original vertices and affects
 * only assignment of the diagonal signs. The sparse output is sorted,
 * with physical binary64 entries, including all n diagonal entries.
 * On error *out is zeroed. Release prior output before reusing it. */
int tb_signed_matrix(const tb_pattern *pattern, tb_sign_mode mode, uint64_t sign_seed_or_draw,
                     const size_t *perm, tb_format format, tb_sparse *out);
void tb_sparse_free(tb_sparse *matrix);

#ifdef __cplusplus
}
#endif
#endif
