#include "three_band.h"
#include "three_band_rng.h"

#include <errno.h>
#include <fenv.h>
#include <float.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

/* A seed identifies the same categorical draws across implementations.
 * The Makefile also disables multiply-add contraction for this file. */
_Static_assert(FLT_RADIX == 2 && DBL_MANT_DIG == 53 && DBL_MAX_EXP == 1024 &&
               FLT_EVAL_METHOD == 0, "three-band seed replay requires binary64 evaluation");
#ifdef __FAST_MATH__
#error "three-band seed replay requires ordinary binary64 arithmetic"
#endif

struct tb_pattern {
    uint64_t seed;
    size_t n, edges;
    size_t columns[];
};

/* sigma = 100 / statistics.NormalDist().inv_cdf(0.995), as binary64. */
static const double sigma = 0x1.36945fc7f60afp+5;
static const double ln2 = 0x1.62e42fefa39efp-1;

typedef struct {
    double center;
    size_t first, past; /* inlier positive distances in [first, past) */
} band;

typedef struct {
    size_t n;
    uint8_t *small;
    size_t *wide;
} counters;

static int increment(counters *incoming, size_t j)
{
    if (!incoming->wide && incoming->small[j] == UINT8_MAX) {
        if (incoming->n > SIZE_MAX / sizeof(*incoming->wide)) return EOVERFLOW;
        incoming->wide = malloc(incoming->n * sizeof(*incoming->wide));
        if (!incoming->wide) return ENOMEM;
        for (size_t k = 0; k < incoming->n; ++k)
            incoming->wide[k] = incoming->small[k];
        free(incoming->small);
        incoming->small = NULL;
    }
    if (incoming->wide) ++incoming->wide[j];
    else ++incoming->small[j];
    return 0;
}

static size_t row_edge_count(size_t n, size_t i)
{
    size_t future = n - i - 1;
    return future < 3 ? future : 3;
}

/* Evaluate the same floating-point subtraction as the actual candidate
 * test. Rounding center +/- 100 to integer endpoints can change which
 * side of the strict threshold contains an exactly representable offset. */
static size_t band_boundary(size_t n, double center, int upper)
{
    size_t lo = 1, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        double deviation = (double)mid - center;
        if (upper ? deviation >= 100.0 : deviation > -100.0) hi = mid;
        else lo = mid + 1;
    }
    return lo;
}

static size_t available(size_t first, size_t past, size_t row_past,
                        const size_t used[3], size_t draws)
{
    size_t end = past < row_past ? past : row_past;
    if (end <= first) return 0;
    size_t count = end - first;
    for (size_t k = 0; k < draws; ++k)
        if (used[k] >= first && used[k] < end) --count;
    return count;
}

typedef struct {
    tb_rng *rng;
    const counters *incoming;
    size_t row;
    const size_t *used;
    size_t draws;
    double center, best_score;
    size_t best_offset;
} selection;

/* Scan eligible offsets in increasing order; strict comparison implements
 * the first-maximum tie rule. Consume a Gumbel even for a previous choice. */
static void score_range(selection *s, size_t first, size_t past)
{
    for (size_t offset = first; offset < past; ++offset) {
        double g = tb_rng_gumbel(s->rng);
        if ((s->draws >= 1 && s->used[0] == offset) ||
            (s->draws >= 2 && s->used[1] == offset)) continue;
        size_t j = s->row + offset;
        size_t count = s->incoming->wide ? s->incoming->wide[j] : s->incoming->small[j];
        double d = ((double)offset - s->center) / sigma;
        double score = (-0.5 * (d*d) - (double)count * ln2) + g;
        if (score > s->best_score) {
            s->best_score = score;
            s->best_offset = offset;
        }
    }
}

static int scan_pattern_v1(size_t n, uint64_t pattern_seed, tb_edge_fn visit, void *context)
{
    counters incoming = {.n = n, .small = calloc(n, sizeof(uint8_t))};
    if (!incoming.small) return ENOMEM;
    double extent = cbrt((double)n);
    /* NumPy scalar extent**2 calls libm pow; it can differ by one ulp
     * from multiplication. A runtime exponent prevents constant folding. */
    volatile double exponent = 2.0;
    band bands[] = {{.center = 1.0}, {.center = extent}, {.center = pow(extent, exponent)}};
    for (unsigned k = 0; k < 3; ++k) {
        bands[k].first = band_boundary(n, bands[k].center, 0);
        bands[k].past = band_boundary(n, bands[k].center, 1);
    }
    tb_rng rng;
    tb_rng_seed(&rng, pattern_seed);
    int error = 0;
    for (size_t i = 0; i < n-1; ++i) {
        unsigned order[3];
        tb_rng_permutation3(&rng, order);
        size_t used[3], past = n-i;
        for (size_t k = 0; k < row_edge_count(n, i); ++k) {
            band b = bands[order[k]];
            size_t inliers = available(b.first, b.past, past, used, k);
            if (!inliers) {
                b = bands[0];
                inliers = available(b.first, b.past, past, used, k);
            }
            int tail = past-1-k > inliers && tb_rng_uniform(&rng) < 0.01;
            selection s = {.rng = &rng, .incoming = &incoming, .row = i,
                           .used = used, .draws = k, .center = b.center,
                           .best_score = -INFINITY};
            size_t end = b.past < past ? b.past : past;
            /* The selected band has at least one available inlier, including
             * after fallback. Masked spans still consume the reference stream. */
            if (tail) {
                score_range(&s, 1, b.first);
                tb_rng_discard_gumbels(&rng, end - b.first);
                score_range(&s, end, past);
            } else {
                tb_rng_discard_gumbels(&rng, b.first-1);
                score_range(&s, b.first, end);
                tb_rng_discard_gumbels(&rng, past-end);
            }
            size_t j = i + s.best_offset;
            used[k] = s.best_offset;
            error = increment(&incoming, j);
            if (!error) error = visit(context, i, j);
            if (error) goto done;
        }
    }
done:
    free(incoming.small);
    free(incoming.wide);
    return error;
}

/* Each band has at most 401 integer offsets at distance <= 200. A column
 * can receive at most one edge from each distinct predecessor, so 1203 is
 * a conservative bound on incoming counts even when bands overlap. */
enum { BAND_RADIUS = 200, BAND_WIDTH = 2 * BAND_RADIUS + 1, MAX_INCOMING = 3 * BAND_WIDTH };

typedef struct {
    size_t first, past, in_first, in_past;
    double gaussian[BAND_WIDTH]; /* indexed relative to first */
} bounded_band;

/* These operations, including their order, are part of the bounded seed
 * replay. Avoid platform-specific last bits of cbrt/pow/exp: a boundary
 * offset or categorical draw can distinguish adjacent binary64 values. */
static double bounded_extent(size_t n)
{
    double target = (double)n, lo = 1.0, hi = target;
    for (;;) {
        double mid = lo + (hi - lo) * 0.5;
        if (mid == lo || mid == hi) return hi;
        double cube = (mid * mid) * mid;
        if (cube == target) return mid;
        if (cube < target) lo = mid;
        else hi = mid;
    }
}

static double gaussian_weight(double deviation)
{
    double x = deviation / sigma;
    double z = (-0.5 * (x * x)) * (1.0 / 16.0);
    /* |z| < 0.83. Evaluate exp(z) through degree 17, then exp(z)^16. */
    double sum = 1.0, term = 1.0;
    for (unsigned k = 1; k <= 17; ++k) {
        term = (term * z) / k;
        sum += term;
    }
    for (unsigned k = 0; k < 4; ++k) sum *= sum;
    return sum;
}

static void init_bounded_band(bounded_band *b, size_t n, double center)
{
    size_t middle = (size_t)center;
    size_t first = middle > BAND_RADIUS ? middle - BAND_RADIUS : 1;
    if ((double)first - center < -BAND_RADIUS) ++first;
    b->first = first;
    size_t past = middle + BAND_RADIUS + 1;
    b->past = past < n ? past : n;
    b->in_first = band_boundary(n, center, 0);
    b->in_past = band_boundary(n, center, 1);
    for (size_t off = b->first; off < b->past; ++off)
        b->gaussian[off - b->first] = gaussian_weight((double)off - center);
}

typedef struct { size_t first, past; } interval;

static size_t bounded_pick(const bounded_band *b, int tail, size_t row, size_t row_past,
                           const size_t used[3], size_t draws, const uint16_t *incoming,
                           size_t ring_mask, const double penalty[], tb_rng *rng)
{
    interval spans[2];
    size_t nspan = 1;
    if (tail) {
        spans[0] = (interval){b->first, b->in_first};
        spans[1] = (interval){b->in_past, b->past};
        nspan = 2;
    } else {
        spans[0] = (interval){b->in_first, b->in_past};
    }

    uint16_t offsets[BAND_WIDTH], counts[BAND_WIDTH];
    size_t count = 0;
    unsigned min_incoming = MAX_INCOMING;
    for (size_t range = 0; range < nspan; ++range) {
        size_t end = spans[range].past < row_past ? spans[range].past : row_past;
        for (size_t off = spans[range].first; off < end; ++off) {
            if ((draws >= 1 && used[0] == off) || (draws >= 2 && used[1] == off)) continue;
            unsigned load = incoming[(row + off) & ring_mask];
            if (load < min_incoming) min_incoming = load;
            counts[count] = (uint16_t)load;
            offsets[count++] = (uint16_t)(off - b->first);
        }
    }
    /* Subtract the minimum to keep at least one positive normal weight,
     * including in tail intervals whose candidates all have high load. */
    double cdf[BAND_WIDTH], total = 0;
    size_t last_positive = 0;
    for (size_t k = 0; k < count; ++k) {
        double w = b->gaussian[offsets[k]] * penalty[counts[k] - min_incoming];
        if (w > 0) last_positive = k;
        total += w;
        cdf[k] = total;
    }
    double target = tb_rng_uniform(rng) * total;
    size_t lo = 0, hi = last_positive;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (cdf[mid] > target) hi = mid;
        else lo = mid + 1;
    }
    return b->first + offsets[lo];
}

static int scan_pattern(size_t n, uint64_t pattern_seed, tb_edge_fn visit, void *context)
{
    double extent = bounded_extent(n);
    bounded_band bands[3];
    init_bounded_band(&bands[0], n, 1.0);
    init_bounded_band(&bands[1], n, extent);
    init_bounded_band(&bands[2], n, extent * extent);
    size_t ring_size = 1;
    while (ring_size < bands[2].past) ring_size *= 2;
    uint16_t *incoming = calloc(ring_size, sizeof(*incoming));
    if (!incoming) return ENOMEM;
    size_t ring_mask = ring_size - 1;
    double penalty[MAX_INCOMING + 1];
    for (int k = 0; k <= MAX_INCOMING; ++k) penalty[k] = ldexp(1.0, -k);
    tb_rng rng;
    tb_rng_seed(&rng, pattern_seed);
    int error = 0;
    for (size_t row = 0; row < n-1; ++row) {
        unsigned order[3];
        tb_rng_permutation3(&rng, order);
        /* No future selection can touch row itself. Every candidate lies
         * less than ring_size ahead, so aliases are clear on first use. */
        incoming[row & ring_mask] = 0;
        size_t used[3], past = n - row;
        for (size_t k = 0; k < row_edge_count(n, row); ++k) {
            const bounded_band *b = &bands[order[k]];
            size_t in = available(b->in_first, b->in_past, past, used, k);
            if (!in) {
                b = &bands[0];
                in = available(b->in_first, b->in_past, past, used, k);
            }
            size_t all = available(b->first, b->past, past, used, k);
            int tail = all > in && tb_rng_uniform(&rng) < 0.01;
            size_t off = bounded_pick(b, tail, row, past, used, k,
                                      incoming, ring_mask, penalty, &rng);
            used[k] = off;
            ++incoming[(row + off) & ring_mask];
            error = visit(context, row, row + off);
            if (error) goto done;
        }
    }
done:
    free(incoming);
    return error;
}

static int enter_round_to_nearest(fenv_t *saved)
{
    if (feholdexcept(saved)) return EDOM;
    if (!fesetround(FE_TONEAREST)) return 0;
    fesetenv(saved);
    return EDOM;
}

int tb_pattern_scan(size_t n, uint64_t pattern_seed, tb_edge_fn visit, void *context)
{
    if (n < 3 || !visit) return EINVAL;
    fenv_t saved;
    if (enter_round_to_nearest(&saved)) return EDOM;
    int err = scan_pattern(n, pattern_seed, visit, context);
    if (fesetenv(&saved)) return EDOM;
    return err;
}

static int init_signs(tb_rng *signs, size_t n, uint64_t pattern_seed,
                      tb_sign_mode mode, uint64_t id)
{
    if (mode == TB_SIGN_SEED) tb_rng_seed(signs, id);
    else if (mode == TB_SIGN_DRAW && id) tb_rng_seed_signs(signs, n, pattern_seed, id);
    else return EINVAL;
    return 0;
}

static int check_permutation(const size_t *perm, size_t n)
{
    uint8_t *seen = calloc(n/8 + (n%8 != 0), 1);
    if (!seen) return ENOMEM;
    int err = 0;
    for (size_t k = 0; k < n; ++k) {
        size_t j = perm[k];
        uint8_t bit = (uint8_t)(1u << (j%8));
        if (j >= n || (seen[j/8] & bit)) {
            err = EINVAL;
            break;
        }
        seen[j/8] |= bit;
    }
    free(seen);
    return err;
}

typedef struct {
    tb_rng signs;
    tb_entry_fn emit;
    void *context;
} signed_stream;

static int sign_edge(void *context, size_t i, size_t j)
{
    signed_stream *s = context;
    return s->emit(s->context, i, j, tb_rng_sign(&s->signs));
}

typedef int (*pattern_scan_fn)(size_t, uint64_t, tb_edge_fn, void *);

static int signed_scan(pattern_scan_fn scan, size_t n, uint64_t pattern_seed,
                       tb_sign_mode mode, uint64_t id, const size_t *perm,
                       tb_entry_fn emit, void *context)
{
    if (n < 3 || !emit) return EINVAL;
    signed_stream s = {.emit = emit, .context = context};
    int err = init_signs(&s.signs, n, pattern_seed, mode, id);
    if (!err && perm) err = check_permutation(perm, n);
    if (err) return err;
    fenv_t saved;
    if (enter_round_to_nearest(&saved)) return EDOM;
    err = scan(n, pattern_seed, sign_edge, &s);
    for (size_t k = 0; !err && k < n; ++k) {
        size_t row = perm ? perm[k] : k;
        err = emit(context, row, row, tb_rng_sign(&s.signs));
    }
    if (fesetenv(&saved)) return EDOM;
    return err;
}

int tb_signed_scan(size_t n, uint64_t pattern_seed, tb_sign_mode mode, uint64_t id,
                   const size_t *perm, tb_entry_fn emit, void *context)
{
    return signed_scan(scan_pattern, n, pattern_seed, mode, id, perm, emit, context);
}

int tb_signed_scan_v1(size_t n, uint64_t pattern_seed, tb_sign_mode mode, uint64_t id,
                      const size_t *perm, tb_entry_fn emit, void *context)
{
    return signed_scan(scan_pattern_v1, n, pattern_seed, mode, id, perm, emit, context);
}

static int cache_edge(void *context, size_t i, size_t j)
{
    (void)i;
    size_t **next = context;
    **next = j;
    ++*next;
    return 0;
}

int tb_pattern_create(size_t n, uint64_t seed, tb_pattern **out)
{
    if (!out) return EINVAL;
    *out = NULL;
    if (n < 3) return EINVAL;
    if (n-2 > SIZE_MAX / 3) return EOVERFLOW;
    size_t edges = 3 * (n-2);
    if (edges > (SIZE_MAX - sizeof(tb_pattern)) / sizeof(size_t)) return EOVERFLOW;
    tb_pattern *p = malloc(sizeof(*p) + edges * sizeof(*p->columns));
    if (!p) return ENOMEM;
    p->seed = seed;
    p->n = n;
    p->edges = edges;
    size_t *next = p->columns;
    int err = tb_pattern_scan(n, seed, cache_edge, &next);
    if (err) free(p);
    else *out = p;
    return err;
}

void tb_pattern_free(tb_pattern *p) { free(p); }
size_t tb_pattern_dimension(const tb_pattern *p) { return p ? p->n : 0; }
size_t tb_pattern_edge_count(const tb_pattern *p) { return p ? p->edges : 0; }
const size_t *tb_pattern_columns(const tb_pattern *p) { return p ? p->columns : NULL; }

void tb_sparse_free(tb_sparse *a)
{
    if (!a) return;
    free(a->offsets);
    free(a->indices);
    free(a->values);
    *a = (tb_sparse){0};
}

int tb_signed_matrix(const tb_pattern *p, tb_sign_mode mode, uint64_t id,
                     const size_t *perm, tb_format format, tb_sparse *out)
{
    if (!out) return EINVAL;
    *out = (tb_sparse){0};
    if (!p || (format != TB_CSR && format != TB_CSC)) return EINVAL;
    size_t n = p->n;
    tb_rng signs;
    int err = init_signs(&signs, n, p->seed, mode, id);
    if (err) return err;
    if (p->edges > (SIZE_MAX - n) / 2) return EOVERFLOW;
    size_t nnz = 2 * p->edges + n;
    if (nnz > SIZE_MAX / sizeof(double) || nnz > SIZE_MAX / sizeof(size_t)) return EOVERFLOW;
    tb_sparse a = {.n = n, .nnz = nnz};
    a.offsets = calloc(n+1, sizeof(*a.offsets));
    a.indices = malloc(nnz * sizeof(*a.indices));
    a.values = malloc(nnz * sizeof(*a.values));
    if (!a.offsets || !a.indices || !a.values) {
        tb_sparse_free(&a);
        return ENOMEM;
    }
    for (size_t e = 0; e < p->edges; ++e) ++a.offsets[p->columns[e]+1];
    for (size_t i = 0; i < n; ++i)
        a.offsets[i+1] += a.offsets[i] + 1 + row_edge_count(n, i);

    /* Direct sorted CSR assembly uses offsets as advancing cursors. Each
     * lower neighbor arrives in sorted order. Sort the at-most-three upper
     * neighbors after assigning signs in their original draw order. By
     * symmetry, the resulting three arrays also represent sorted CSC. */
    size_t edge = 0;
    for (size_t i = 0; i < n; ++i) {
        size_t diag = a.offsets[i]++;
        a.indices[diag] = i;
        a.values[diag] = 0;
        size_t upper = row_edge_count(n, i);
        for (size_t k = 0; k < upper; ++k) {
            size_t j = p->columns[edge++];
            double sign = tb_rng_sign(&signs);
            size_t lower_slot = a.offsets[j]++;
            a.indices[lower_slot] = i;
            a.values[lower_slot] = sign;
            size_t pos = a.offsets[i]++;
            while (pos > diag+1 && a.indices[pos-1] > j) {
                a.indices[pos] = a.indices[pos-1];
                a.values[pos] = a.values[pos-1];
                --pos;
            }
            a.indices[pos] = j;
            a.values[pos] = sign;
        }
    }
    for (size_t k = 0; k < n; ++k) {
        size_t row = perm ? perm[k] : k;
        if (row >= n) { tb_sparse_free(&a); return EINVAL; }
        size_t diag = a.offsets[row] - row_edge_count(n, row) - 1;
        if (a.values[diag] != 0) { tb_sparse_free(&a); return EINVAL; }
        a.values[diag] = tb_rng_sign(&signs);
    }
    memmove(a.offsets+1, a.offsets, n * sizeof(*a.offsets));
    a.offsets[0] = 0;
    *out = a;
    return 0;
}
