#include "three_band_lu.h"

#include <slu_ddefs.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int stencil_three_band_lu(int n, const uint32_t *offsets, const uint32_t *entries,
                          const double *rhs, double *solution)
{
    int_t nnz = offsets[n], info = 0;
    int_t *column_starts = malloc(((size_t)n + 1) * sizeof(*column_starts));
    int_t *rows = malloc((size_t)nnz * sizeof(*rows));
    double *values = malloc((size_t)nnz * sizeof(*values));
    int *perm_c = malloc((size_t)n * sizeof(*perm_c));
    int *perm_r = malloc((size_t)n * sizeof(*perm_r));
    double *delta = malloc((size_t)n * sizeof(*delta));
    int success = 0;
    if (!column_starts || !rows || !values || !perm_c || !perm_r || !delta) {
        fputs("SuperLU input allocation failed\n", stderr);
        goto cleanup;
    }
    /* CSR(A) is CSC(A) for this real symmetric input. */
    for (int i = 0; i <= n; ++i) column_starts[i] = offsets[i];
    for (int_t k = 0; k < nnz; ++k) {
        rows[k] = entries[k] >> 1;
        values[k] = (entries[k] & 1) ? -1.0 : 1.0;
    }
    SuperMatrix a, b, l = {0}, u = {0};
    dCreate_CompCol_Matrix(&a, n, n, nnz, values, rows, column_starts, SLU_NC, SLU_D, SLU_GE);
    dCreate_Dense_Matrix(&b, n, 1, delta, n, SLU_DN, SLU_D, SLU_GE);
    superlu_options_t options;
    set_default_options(&options);
    options.Equil = NO;
    options.ColPerm = MMD_AT_PLUS_A;
    SuperLUStat_t stats;
    StatInit(&stats);
    memcpy(delta, rhs, (size_t)n * sizeof(*rhs));
    dgssv(&options, &a, perm_c, perm_r, &l, &u, &b, &stats, &info);
    if (!info) memcpy(solution, delta, (size_t)n * sizeof(*delta));
    for (int pass = 0; !info && pass < 2; ++pass) {
        for (int i = 0; i < n; ++i) {
            long double residual = rhs[i];
            for (int_t k = column_starts[i]; k < column_starts[i+1]; ++k)
                residual -= (long double)values[k] * solution[rows[k]];
            delta[i] = (double)residual;
        }
        dgstrs(NOTRANS, &l, &u, perm_c, perm_r, &b, &stats, &info);
        if (!info)
            for (int i = 0; i < n; ++i) solution[i] += delta[i];
    }
    success = !info;
    if (info)
        fprintf(stderr, "SuperLU failed (info=%lld); keeping the original draw\n", (long long)info);
    for (int i = 0; success && i < n; ++i) success = isfinite(solution[i]);
    if (l.Store) Destroy_SuperNode_Matrix(&l);
    if (u.Store) Destroy_CompCol_Matrix(&u);
    Destroy_SuperMatrix_Store(&a);
    Destroy_SuperMatrix_Store(&b);
    StatFree(&stats);
cleanup:
    free(column_starts); free(rows); free(values); free(perm_c); free(perm_r); free(delta);
    return success;
}
