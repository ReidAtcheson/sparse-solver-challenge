#define _FILE_OFFSET_BITS 64
#define _POSIX_C_SOURCE 200809L
#include "operator.h"
#include "scratch.h"
#include "witness.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

/* All scratch vectors use private, unlinked files. Keeping a handful of
 * pages avoids retaining n entries for a generator with arbitrary columns. */
enum { PAGE_BYTES = 4096, SLOTS = 8, F_PER_PAGE = PAGE_BYTES / sizeof(F) };
_Static_assert(sizeof(F) == 32 && sizeof(off_t) >= 8, "64-bit offsets and 32-byte F required");

typedef struct {
    uint64_t page[SLOTS], use[SLOTS], tick;
} PageDirectory;

static unsigned find_page(PageDirectory *d, uint64_t page, int *hit)
{
    unsigned oldest = 0;
    for (unsigned i = 0; i < SLOTS; ++i) {
        if (d->use[i] && d->page[i] == page) {
            d->use[i] = ++d->tick;
            *hit = 1;
            return i;
        }
        if (d->use[i] < d->use[oldest]) oldest = i;
    }
    *hit = 0;
    return oldest;
}

typedef union {
    F f[F_PER_PAGE];
    int64_t x[PAGE_BYTES / sizeof(int64_t)];
    __int128 wide[PAGE_BYTES / sizeof(__int128)];
} Page;

typedef struct {
    PageDirectory dir;
    int fd;
    uint64_t bytes;
    int is_witness;
    const int *exponent;
    unsigned char dirty[SLOTS];
    Page data[SLOTS];
} DiskCache;

static void io_error(const char *what)
{
    perror(what);
    exit(EXIT_FAILURE);
}

static void bad_size(void)
{
    fputs("unsupported vector size or invalid matrix column\n", stderr);
    exit(EXIT_FAILURE);
}

static void check_size(const Matrix *a, uint64_t n)
{
    if (!n || (n & (n - 1)) || n > (UINT64_C(1) << 30) ||
        (a->dimensions < 1 || a->dimensions > 3) ||
        n != matrix_size(a->side, a->dimensions)) bad_size();
}

static unsigned layout_shift(const Matrix *a, uint64_t n, uint32_t width)
{
    check_size(a, n);
    if (!width || width > n || (width & (width - 1))) bad_size();
    return (unsigned)__builtin_ctz(width);
}

static void transfer_page(DiskCache *c, unsigned slot, int writing)
{
    uint64_t pos = c->dir.page[slot] * PAGE_BYTES;
    if (pos >= c->bytes) bad_size();
    size_t count = (c->bytes - pos >= PAGE_BYTES) ? PAGE_BYTES : (size_t)(c->bytes - pos);
    if (c->is_witness) {
        int ok = c->exponent
            ? witness_pread_wide(c->fd, c->data[slot].wide, count / sizeof(__int128),
                                 pos / sizeof(__int128), *c->exponent)
            : witness_pread(c->fd, c->data[slot].x, count / sizeof(int64_t),
                            pos / sizeof(int64_t));
        if (!ok) {
            fputs("invalid or unreadable binary64 witness page\n", stderr);
            exit(EXIT_FAILURE);
        }
        return;
    }
    char *buf = (char *)&c->data[slot];
    for (size_t done = 0; done < count;) {
        ssize_t amount = writing ? pwrite(c->fd, buf + done, count - done, (off_t)(pos + done))
                                 : pread(c->fd, buf + done, count - done, (off_t)(pos + done));
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) {
            if (!amount) errno = EIO;
            io_error(writing ? "write scratch page" : "read vector page");
        }
        done += (size_t)amount;
    }
}

static unsigned disk_page(DiskCache *c, uint64_t index)
{
    int hit;
    unsigned slot = find_page(&c->dir, index, &hit);
    if (!hit) {
        if (c->dirty[slot]) transfer_page(c, slot, 1);
        c->dir.page[slot] = index;
        c->dir.use[slot] = ++c->dir.tick;
        transfer_page(c, slot, 0);
        c->dirty[slot] = 0;
    }
    return slot;
}


static void reset_stream(FILE *f)
{
    if (fflush(f) != 0 || fseeko(f, 0, SEEK_SET) != 0) io_error("rewind scratch file");
}

typedef struct {
    uint64_t n;
    int remaining;
} RowLimit;

static void check_term(RowLimit *limit, uint64_t j, int coefficient)
{
    if (j >= limit->n) bad_size();
    if (coefficient > limit->remaining || coefficient < -limit->remaining) {
        fputs("matrix generator exceeded the signed profile's absolute row-sum bound\n", stderr);
        exit(EXIT_FAILURE);
    }
    limit->remaining -= coefficient < 0 ? -coefficient : coefficient;
}

typedef struct {
    RowLimit limit;
    DiskCache *cache;
    __int128 sum;
} ResidualRow;

static __int128 witness_entry(DiskCache *cache, uint64_t j)
{
    if (cache->exponent) {
        const unsigned per_page = PAGE_BYTES / sizeof(__int128);
        unsigned slot = disk_page(cache, j / per_page);
        return cache->data[slot].wide[j % per_page];
    }
    const unsigned per_page = PAGE_BYTES / sizeof(int64_t);
    unsigned slot = disk_page(cache, j / per_page);
    return cache->data[slot].x[j % per_page];
}

static void residual_term(void *context, uint64_t j, int coefficient)
{
    ResidualRow *r = context;
    check_term(&r->limit, j, coefficient);
    r->sum += coefficient * witness_entry(r->cache, j);
}

static FILE *make_residual(FILE *xi, const Matrix *a, uint64_t n, const int *exponent,
                           int ax_multiplier, __int128 rhs_multiplier, F *energy,
                           F *solution_energy)
{
    check_size(a, n);
    DiskCache c = { .fd = fileno(xi), .bytes = n * (exponent ? sizeof(__int128) : sizeof(int64_t)),
                    .is_witness = 1, .exponent = exponent };
    struct stat st;
    reset_stream(xi);
    if (fstat(c.fd, &st) != 0) io_error("stat witness file");
    if (st.st_size != (off_t)(n * sizeof(double))) bad_size();
    FILE *out = private_scratch();
    F total = fzero();
    F x_squared = fzero();
    __int128 small_energy = 0;
    for (uint64_t i = 0; i < n; ++i) {
        ResidualRow r = { .limit = {n, MATRIX_ABS_ROW_LIMIT}, .cache = &c };
        int32_t rhs = matrix_visit(a, i, residual_term, &r);
        if (exponent && a->dimensions == 1 && !a->signed_unit) {
            if (rhs < -207 || rhs > 207) bad_size();
        } else if (exponent && rhs != 1 && rhs != -1) bad_size();
        __int128 residual = ax_multiplier * r.sum - rhs_multiplier * rhs;
        F fr = fwide(residual);
        if (solution_energy) {
            F x = fwide(witness_entry(&c, i));
            x_squared = fadd(x_squared, fmul(x, x));
        }
        if (fwrite(&fr, sizeof(fr), 1, out) != 1) io_error("write residual");
        /* For accurate witnesses this sum fits in one accumulator. Each
         * addition stays below 2^125: each retained term is below 2^120. */
        if (residual > -((__int128)1 << 60) && residual < ((__int128)1 << 60)) {
            small_energy += residual * residual;
            if (small_energy >= ((__int128)1 << 124)) {
                total = fadd(total, fwide(small_energy));
                small_energy = 0;
            }
        } else {
            total = fadd(total, fmul(fr, fr));
        }
    }
    *energy = fadd(total, fwide(small_energy));
    if (solution_energy) *solution_energy = x_squared;
    reset_stream(out);
    return out;
}

FILE *op_residual(FILE *xi, const Matrix *a, uint64_t n, F *energy)
{
    return make_residual(xi, a, n, NULL, 1, (__int128)1 << 58, energy, NULL);
}

FILE *op_residual_wide(FILE *xi, const Matrix *a, uint64_t n, int exponent,
                       int rhs_shift, F *residual_energy, F *solution_energy)
{
    if (rhs_shift < -6 || rhs_shift > 108) bad_size();
    int ax_multiplier = rhs_shift < 0 ? 1 << -rhs_shift : 1;
    __int128 rhs_multiplier = rhs_shift > 0 ? (__int128)1 << rhs_shift : 1;
    return make_residual(xi, a, n, &exponent, ax_multiplier, rhs_multiplier,
                         residual_energy, solution_energy);
}

typedef struct {
    RowLimit limit;
    DiskCache *cache;
    F weight;
} TransposeRow;

static void transpose_term(void *context, uint64_t j, int coefficient)
{
    TransposeRow *r = context;
    check_term(&r->limit, j, coefficient);
    unsigned slot = disk_page(r->cache, j / F_PER_PAGE);
    F *v = &r->cache->data[slot].f[j % F_PER_PAGE];
    *v = fadd(*v, fscale(r->weight, coefficient));
    r->cache->dirty[slot] = 1;
}

FILE *op_transpose(const Matrix *a, uint64_t n, uint32_t width, const F *rowhi,
                   const F *rowlo, F *bval)
{
    unsigned shift = layout_shift(a, n, width);
    FILE *out = private_scratch();
    DiskCache c = { .fd = fileno(out), .bytes = n * sizeof(F) };
    if (ftruncate(c.fd, (off_t)c.bytes) != 0) io_error("size transpose scratch file");
    F b = fzero();
    for (uint64_t i = 0; i < n; ++i) {
        F rowweight = fmul(rowhi[i >> shift], rowlo[i & (width - 1)]);
        TransposeRow r = { .limit = {n, MATRIX_ABS_ROW_LIMIT}, .cache = &c, .weight = rowweight };
        int32_t rhs = matrix_visit(a, i, transpose_term, &r);
        b = fadd(b, fscale(rowweight, rhs));
    }
    for (unsigned slot = 0; slot < SLOTS; ++slot)
        if (c.dirty[slot]) transfer_page(&c, slot, 1);
    *bval = b;
    reset_stream(out);
    return out;
}

typedef struct {
    RowLimit limit;
    PageDirectory dir;
    F weights[SLOTS][F_PER_PAGE];
    uint64_t known[SLOTS][2];
    uint32_t mask;
    unsigned shift;
    const F *hi, *lo;
    F dot;
} EndpointRow;

static void endpoint_term(void *context, uint64_t j, int coefficient)
{
    EndpointRow *r = context;
    check_term(&r->limit, j, coefficient);
    uint64_t page = j / F_PER_PAGE;
    int hit;
    unsigned slot = find_page(&r->dir, page, &hit);
    if (!hit) {
        r->dir.page[slot] = page;
        r->dir.use[slot] = ++r->dir.tick;
        r->known[slot][0] = r->known[slot][1] = 0;
    }
    unsigned index = (unsigned)(j % F_PER_PAGE);
    uint64_t bit = UINT64_C(1) << (index % 64);
    if (!(r->known[slot][index / 64] & bit)) {
        r->weights[slot][index] = fmul(r->hi[j >> r->shift], r->lo[j & r->mask]);
        r->known[slot][index / 64] |= bit;
    }
    r->dot = fadd(r->dot, fscale(r->weights[slot][index], coefficient));
}

typedef struct {
    uint32_t mask;
    unsigned shift;
    const F *rowhi, *rowlo, *colhi, *collo;
    F result;
} SymmetricEndpoint;

/* Accumulate the bilinear form directly from the signed upper triangle.
 * Both terms of an off-diagonal pair use the same sign. */
static int symmetric_entry(void *context, size_t i, size_t j, int sign)
{
    SymmetricEndpoint *e = context;
    F ri = fmul(e->rowhi[i >> e->shift], e->rowlo[i & e->mask]);
    F cj = fmul(e->colhi[j >> e->shift], e->collo[j & e->mask]);
    F term = fmul(ri, cj);
    if (i != j) {
        F rj = fmul(e->rowhi[j >> e->shift], e->rowlo[j & e->mask]);
        F ci = fmul(e->colhi[i >> e->shift], e->collo[i & e->mask]);
        term = fadd(term, fmul(rj, ci));
    }
    e->result = sign == 1 ? fadd(e->result, term) : fsub(e->result, term);
    return 0;
}

F op_endpoint(const Matrix *a, uint64_t n, uint32_t width, const F *rowhi, const F *rowlo,
              const F *colhi, const F *collo, F *bval, __uint128_t *rhs_squared)
{
    unsigned shift = layout_shift(a, n, width);
    if (a->dimensions == 1 && a->signed_unit) {
        SymmetricEndpoint e = {.mask = width - 1, .shift = shift, .rowhi = rowhi, .rowlo = rowlo,
                               .colhi = colhi, .collo = collo, .result = fzero()};
        int error = matrix_three_band_scan(a, symmetric_entry, &e);
        if (error) {
            errno = error;
            io_error("regenerate three-band matrix");
        }
        F b = fzero();
        for (uint64_t i = 0; i < n; ++i) {
            F wi = fmul(rowhi[i >> shift], rowlo[i & (width - 1)]);
            b = fadd(b, fscale(wi, matrix_three_band_rhs(a, i)));
        }
        *bval = b;
        *rhs_squared = n;  /* every unscaled RHS code is +1 or -1 */
        return e.result;
    }
    EndpointRow r = {.limit = {n, 0}, .mask = width - 1, .shift = shift,
                     .hi = colhi, .lo = collo};
    _Static_assert(F_PER_PAGE == 128, "endpoint page bitmap width");
    F b = fzero(), result = fzero();
    __uint128_t energy = 0;
    for (uint64_t i = 0; i < n; ++i) {
        F rowweight = fmul(rowhi[i >> shift], rowlo[i & (width - 1)]);
        r.dot = fzero();
        r.limit.remaining = MATRIX_ABS_ROW_LIMIT;
        int32_t rhs = matrix_visit(a, i, endpoint_term, &r);
        energy += (uint64_t)((int64_t)rhs * rhs);
        b = fadd(b, fscale(rowweight, rhs));
        result = fadd(result, fmul(rowweight, r.dot));
    }
    *bval = b;
    *rhs_squared = energy;
    return result;
}
