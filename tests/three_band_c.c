/* C API behavior independent of NumPy; cross-language vectors test the RNG. */
#include "../three_band.h"
#include <assert.h>
#include <errno.h>
#include <fenv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const tb_pattern *pattern;
    const tb_sparse *matrix;
    const size_t *perm;
    size_t events;
} replay;

static double entry(const tb_sparse *a, size_t i, size_t j)
{
    for (size_t k = a->offsets[i]; k < a->offsets[i+1]; ++k)
        if (a->indices[k] == j) return a->values[k];
    return 0;
}

static int check_event(void *context, size_t i, size_t j, int sign)
{
    replay *r = context;
    size_t n = r->matrix->n, e = r->events++, edges = tb_pattern_edge_count(r->pattern);
    assert(fegetround() == FE_TONEAREST);
    if (e < edges) {
        /* All rows before the last three own three edges. */
        size_t row = e < 3*(n-3)+2 ? e/3 : n-2;
        assert(i == row && j > i && tb_pattern_columns(r->pattern)[e] == j);
    } else {
        size_t k = e - edges;
        assert(k < n && i == j && i == (r->perm ? r->perm[k] : k));
    }
    assert(sign == 1 || sign == -1);
    assert(entry(r->matrix, i, j) == sign && entry(r->matrix, j, i) == sign);
    return 0;
}

static int stop(void *context, size_t i, size_t j, int sign)
{
    (void)i; (void)j; (void)sign;
    size_t *count = context;
    return ++*count == 3 ? ECANCELED : 0;
}

static void verify(size_t n, uint64_t seed)
{
    tb_pattern *p;
    assert(tb_pattern_create(n, seed, &p) == 0 && p);
    assert(tb_pattern_dimension(p) == n && tb_pattern_edge_count(p) == 3*n-6);
    size_t *perm = malloc(n * sizeof(*perm));
    assert(perm);
    for (size_t i = 0; i < n; ++i) perm[i] = n-1-i;
    for (int variant = 0; variant < 2; ++variant) {
        tb_sparse a;
        tb_sign_mode mode = variant ? TB_SIGN_DRAW : TB_SIGN_SEED;
        const size_t *order = variant ? perm : NULL;
        uint64_t id = variant ? 3 : 0;
        assert(tb_signed_matrix(p, mode, id, order, variant ? TB_CSC : TB_CSR, &a) == 0);
        assert(a.n == n && a.nnz == 7*n-12 && a.offsets[0] == 0 && a.offsets[n] == a.nnz);
        for (size_t i = 0; i < n; ++i)
            for (size_t j = a.offsets[i]+1; j < a.offsets[i+1]; ++j)
                assert(a.indices[j-1] < a.indices[j]);
        replay r = {.pattern = p, .matrix = &a, .perm = order};
        assert(fesetround(FE_UPWARD) == 0);
        assert(feclearexcept(FE_ALL_EXCEPT) == 0);
        assert(feraiseexcept(FE_INEXACT) == 0);
        int flags = fetestexcept(FE_ALL_EXCEPT);
        assert(tb_signed_scan(n, seed, mode, id, order, check_event, &r) == 0);
        assert(fegetround() == FE_UPWARD && fetestexcept(FE_ALL_EXCEPT) == flags);
        assert(fesetround(FE_TONEAREST) == 0 && feclearexcept(FE_ALL_EXCEPT) == 0);
        assert(r.events == 4*n-6);
        tb_sparse_free(&a);
        assert(!a.offsets && !a.values && !a.indices);
    }
    size_t count = 0;
    assert(tb_signed_scan(n, seed, TB_SIGN_DRAW, 0, NULL, stop, &count) == EINVAL);
    perm[0] = perm[1];
    tb_sparse bad;
    assert(tb_signed_matrix(p, TB_SIGN_DRAW, 1, perm, TB_CSR, &bad) == EINVAL && !bad.offsets);
    assert(tb_signed_scan(n, seed, TB_SIGN_DRAW, 1, perm, stop, &count) == EINVAL && !count);
    perm[0] = n;
    assert(tb_signed_scan(n, seed, TB_SIGN_DRAW, 1, perm, stop, &count) == EINVAL && !count);
    assert(tb_signed_scan(n, seed, TB_SIGN_DRAW, 1, NULL, stop, &count) == ECANCELED && count == 3);
    free(perm);
    tb_pattern_free(p);
}

int main(void)
{
    tb_pattern *invalid;
    assert(tb_pattern_create(2, 1, &invalid) == EINVAL && !invalid);
    assert(tb_pattern_create(SIZE_MAX, 1, &invalid) == EOVERFLOW && !invalid);
    verify(3, 0);
    verify(101, UINT64_C(0x12345678abcdef));
    verify(343, 87);
    puts("PASS three-band signed edge scan, sorted CSR/CSC, permutations and rounding");
    return 0;
}
