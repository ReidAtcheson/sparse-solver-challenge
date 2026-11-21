/* Symbolic fill on fixed three-band fixtures. Build from the source root:
 * cc -std=c11 -O3 -ffp-contract=off -I/usr/include/suitesparse \
 *    benchmarks/three_band_ordering.c three_band.c three_band_rng.c \
 *    -lcholmod -lm -o /tmp/three-band-ordering
 * /tmp/three-band-ordering
 */
#include "../three_band.h"
#include <cholmod.h>

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

enum { N = 4096, TRAINING_SEED = 42 };

static int append_entry(void *context, size_t row, size_t column)
{
    cholmod_triplet *triplet = context;
    if (triplet->nnz >= triplet->nzmax) return EOVERFLOW;
    int32_t *rows = triplet->i;
    int32_t *columns = triplet->j;
    rows[triplet->nnz] = (int32_t)row;
    columns[triplet->nnz++] = (int32_t)column;
    return 0;
}

static cholmod_sparse *make_pattern(unsigned seed, cholmod_common *common)
{
    /* Upper triangle including its diagonal. Numeric signs cannot affect
     * this symbolic Cholesky count for an explicitly fixed permutation. */
    cholmod_triplet *triplet = cholmod_allocate_triplet(N, N, 4*N - 6, 1,
                                                        CHOLMOD_PATTERN, common);
    if (!triplet) return NULL;
    int status = tb_pattern_scan(N, seed, append_entry, triplet);
    for (size_t i = 0; !status && i < N; ++i) status = append_entry(triplet, i, i);
    cholmod_sparse *matrix = NULL;
    if (!status && triplet->nnz == (size_t)(4*N - 6))
        matrix = cholmod_triplet_to_sparse(triplet, 0, common);
    cholmod_free_triplet(&triplet, common);
    return matrix;
}

static int fill(cholmod_sparse *matrix, int32_t *permutation, cholmod_common *common,
                uint64_t *nonzeros)
{
    cholmod_factor *factor = cholmod_analyze_p(matrix, permutation, NULL, 0, common);
    if (!factor) return 0;
    int ok = factor->itype == CHOLMOD_INT && factor->n == N &&
             memcmp(factor->Perm, permutation, N * sizeof(*permutation)) == 0;
    if (ok) {
        const int32_t *counts = factor->ColCount;
        *nonzeros = 0;
        for (size_t i = 0; i < N; ++i) *nonzeros += (uint64_t)counts[i];
    }
    cholmod_free_factor(&factor, common);
    return ok;
}

int main(void)
{
    cholmod_common common;
    if (!cholmod_start(&common)) return 1;
    common.nmethods = 1;
    common.method[0].ordering = CHOLMOD_GIVEN;
    common.postorder = 0;
    common.supernodal = CHOLMOD_SIMPLICIAL;

    int32_t natural[N], training[N], fresh[N];
    for (int i = 0; i < N; ++i) natural[i] = i;
    puts("n pattern_seed natural_nnz_L reused_metis42_nnz_L fresh_metis_nnz_L reused_over_fresh");
    int ok = 1;
    for (unsigned seed = TRAINING_SEED; seed <= 45 && ok; ++seed) {
        cholmod_sparse *matrix = make_pattern(seed, &common);
        ok = matrix && cholmod_metis(matrix, NULL, 0, 0, fresh, &common);
        if (ok) {
            if (seed == TRAINING_SEED) memcpy(training, fresh, sizeof(training));
            uint64_t a, b, c;
            ok = fill(matrix, natural, &common, &a) && fill(matrix, training, &common, &b)
                 && fill(matrix, fresh, &common, &c);
            if (ok) printf("%d %u %" PRIu64 " %" PRIu64 " %" PRIu64 " %.4f\n",
                           N, seed, a, b, c, (double)b / (double)c);
        }
        cholmod_free_sparse(&matrix, &common);
    }
    cholmod_finish(&common);
    if (!ok) fputs("Pattern generation, METIS or symbolic analysis failed\n", stderr);
    return ok ? 0 : 1;
}
