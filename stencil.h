#ifndef STENCIL_H
#define STENCIL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* libstencil. Nonzero status codes are errno values, usable with strerror().
 * The library borrows input buffers only for the duration of the call. The
 * caller owns all output buffers and releases instances with stencil_close(). */
typedef struct stencil_instance stencil_instance;

/* Authenticate a start receipt using the configured provider and trust file.
 * Opening a three-band instance generates and caches its sparse rows once. */
int stencil_instance_open(const char *trust_path, const char *start_path,
                          stencil_instance **out);

/* Construct an instance from an already authenticated 32-byte seed, registered
 * profile ID and side (row count for the three-band challenge or July fixture).
 * The caller is responsible
 * for authenticating these inputs. Profile IDs are the exact protocol strings. */
int stencil_instance_from_seed(const char *profile_id, uint32_t side,
                               const uint8_t seed[32], stencil_instance **out);
void stencil_close(stencil_instance *instance);
uint64_t stencil_row_count(const stencil_instance *instance);
unsigned stencil_max_row_terms(const stencil_instance *instance);

/* Generate [first, first + count) in compressed sparse row format. All column
 * indices are global and zero-based. offsets[0] = 0; offsets[count] is the
 * number of terms. Both values and RHS use the physical units of A*x = b.
 * Provide count+1 offsets, count RHS doubles, and capacity entries for each
 * of columns and values. capacity >= count * max_row_terms always suffices.
 * Request rows in any order. Ignore all outputs if a call reports an error.
 * The three-band instance stores 64-bit row offsets and 32-bit packed entries. Calls to stencil_rows
 * on an open instance use constant additional working space. */
int stencil_rows(const stencil_instance *instance, uint64_t first, size_t count,
                 uint64_t *offsets, uint32_t *columns, double *values,
                 size_t capacity, double *rhs);

/* Returns the byte length of the CLI-compatible private commit cache. */
size_t stencil_commit_size(const stencil_instance *instance);

/* Commit directly to count contiguous, native little-endian binary64 values.
 * Supply an independent output cache of exactly stencil_commit_size() bytes.
 * The 32-byte digest is ready for timestamping. Keep the private solution
 * and cache for the prove worker. Do not change the solution during commit
 * or between commit and proving. Ignore both outputs on error. */
int stencil_commit(const stencil_instance *instance, const double *solution,
                   size_t count, uint8_t *cache, size_t cache_bytes, uint8_t digest[32]);

#ifdef __cplusplus
}
#endif
#endif
