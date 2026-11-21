#define _FILE_OFFSET_BITS 64
#define _POSIX_C_SOURCE 200809L
#include "fold.h"
#include "mask.h"
#include "witness.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

enum { CHUNK = 512 };
_Static_assert(sizeof(FoldPair) == 2 * sizeof(F), "folded pairs share the scalar table extent");
_Static_assert(sizeof(off_t) >= 8, "64-bit table offsets required");

static void fail(const char *message)
{
    fprintf(stderr, "sumcheck table: %s\n", message);
    exit(EXIT_FAILURE);
}

/* Flush stdio before switching to explicit offsets. All tables are private
 * regular scratch files, so their exact size can be checked before a pass. */
static int table_fd(FILE *table, uint64_t count, size_t width)
{
    struct stat st;
    if (count < 2 || (count & (count-1)) || count > INT64_MAX/width)
        fail("unsupported table size");
    if (fflush(table) != 0) fail("could not flush table");
    int fd = fileno(table);
    if (fd < 0 || fstat(fd, &st) < 0 || st.st_size != (off_t)(count*width))
        fail("incorrect table length");
    return fd;
}

static void read_at(int fd, void *buf, size_t len, off_t offset)
{
    unsigned char *p = buf;
    while (len) {
        ssize_t got = pread(fd, p, len, offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) fail("could not read complete table block");
        p += got;
        offset += got;
        len -= (size_t)got;
    }
}

static void write_at(int fd, const void *buf, size_t len, off_t offset)
{
    const unsigned char *p = buf;
    while (len) {
        ssize_t sent = pwrite(fd, p, len, offset);
        if (sent < 0 && errno == EINTR) continue;
        if (sent <= 0) fail("could not write complete table block");
        p += sent;
        offset += sent;
        len -= (size_t)sent;
    }
}

static size_t chunk_size(uint64_t remaining)
{
    return remaining < CHUNK ? (size_t)remaining : CHUNK;
}

static void rewind_checked(FILE *file)
{
    if (fseeko(file, 0, SEEK_SET)) fail("could not rewind file");
}

static void witness_end(FILE *xi)
{
    if (fgetc(xi) != EOF || ferror(xi)) fail("private witness has incorrect length");
}

/* If the two factors interpolate from (a.x,a.weight) to (b.x,b.weight),
 * the constant coefficient is their product at zero and the quadratic
 * coefficient is the product of their slopes. */
static inline void moment_pair(Moment *m, FoldPair a, FoldPair b)
{
    m->g0 = fadd(m->g0, fmul(a.x, a.weight));
    m->quadratic = fadd(m->quadratic, fmul(fsub(b.x,a.x), fsub(b.weight,a.weight)));
}

static inline void moment_square(Moment *m, F a, F b)
{
    F delta = fsub(b,a);
    m->g0 = fadd(m->g0, fmul(a,a));
    m->quadratic = fadd(m->quadratic, fmul(delta,delta));
}

static inline FoldPair interp_pair(FoldPair a, FoldPair b, F r)
{
    return (FoldPair){flerp(a.x,b.x,r), flerp(a.weight,b.weight,r)};
}

typedef union { F scalar[CHUNK]; FoldPair pair[CHUNK]; } Block;

Moment fold_moment(FILE *table, uint64_t count, int product)
{
    Moment m = {0};
    Block block;
    size_t width = product ? sizeof(FoldPair) : sizeof(F);
    int fd = table_fd(table, count, width);
    for (uint64_t pos = 0; pos < count; pos += CHUNK) {
        size_t n = chunk_size(count-pos);
        read_at(fd, &block, n*width, (off_t)(pos*width));
        if (product) {
            for (size_t j = 0; j < n; j += 2) moment_pair(&m,block.pair[j],block.pair[j+1]);
        } else {
            for (size_t j = 0; j < n; j += 2) moment_square(&m,block.scalar[j],block.scalar[j+1]);
        }
    }
    return m;
}

FoldPair fold_step(FILE *table, uint64_t count, int product, F r, Moment *next)
{
    *next = (Moment){0};
    FoldPair last = {0};
    Block block;
    size_t width = product ? sizeof(FoldPair) : sizeof(F);
    int fd = table_fd(table, count, width);
    for (uint64_t pos = 0; pos < count; pos += CHUNK) {
        size_t n = chunk_size(count-pos);
        read_at(fd, &block, n*width, (off_t)(pos*width));
        /* Compress into the already-consumed half of this block. Since CHUNK
         * and count are powers of two, the next moment never straddles blocks. */
        if (product) {
            for (size_t j = 0; j < n/2; j++)
                block.pair[j] = interp_pair(block.pair[2*j],block.pair[2*j+1],r);
            for (size_t j = 0; j+1 < n/2; j += 2)
                moment_pair(next,block.pair[j],block.pair[j+1]);
            last = block.pair[n/2-1];
        } else {
            for (size_t j = 0; j < n/2; j++)
                block.scalar[j] = flerp(block.scalar[2*j],block.scalar[2*j+1],r);
            for (size_t j = 0; j+1 < n/2; j += 2)
                moment_square(next,block.scalar[j],block.scalar[j+1]);
            last.x = last.weight = block.scalar[n/2-1];
        }
        write_at(fd, &block, (n/2)*width, (off_t)((pos/2)*width));
    }
    if (ftruncate(fd, (off_t)((count/2)*width)) < 0) fail("could not shrink folded table");
    rewind_checked(table);
    return last;
}

static Moment prepare_product(FILE *table, FILE *xi, uint64_t n,
                              const unsigned char seed[32], const F coeff[MASK_COUNT],
                              const int *exponent, F lambda, int matvec_multiplier)
{
    Moment m = {0};
    __int128 xs[CHUNK];
    F w[CHUNK];
    int fd = table_fd(table, n, sizeof(F));
    rewind_checked(xi);
    Mask *mask = mask_begin(seed, coeff);
    for (uint64_t pos = 0; pos < n; pos += CHUNK) {
        size_t count = chunk_size(n-pos);
        off_t offset = (off_t)(pos*sizeof(F));
        read_at(fd, w, count*sizeof(F), offset);
        if (!witness_read_encoded(xi, xs, count, exponent)) fail("invalid or incomplete binary64 witness");
        for (size_t j = 0; j < count; j += 2) {
            FoldPair pair[2];
            for (unsigned k = 0; k < 2; ++k) {
                size_t i = j + k;
                F x = fwide(xs[i]);
                F weight = w[i];
                if (exponent) {
                    if (matvec_multiplier != 1) weight = fscale(weight, matvec_multiplier);
                    weight = fadd(weight, fmul(lambda, x));
                }
                w[i] = fadd(weight, mask_next(mask));
                pair[k] = (FoldPair){x, w[i]};
            }
            moment_pair(&m, pair[0], pair[1]);
        }
        write_at(fd, w, count*sizeof(F), offset);
    }
    mask_end(mask);
    witness_end(xi);
    rewind_checked(table);
    return m;
}

Moment fold_product_prepare(FILE *table, FILE *xi, uint64_t n,
                            const unsigned char seed[32], const F coeff[MASK_COUNT])
{
    return prepare_product(table, xi, n, seed, coeff, NULL, fzero(), 1);
}

Moment fold_product_prepare_wide(FILE *table, FILE *xi, uint64_t n,
                                 const unsigned char seed[32], const F coeff[MASK_COUNT],
                                 int exponent, F lambda, int matvec_multiplier)
{
    return prepare_product(table, xi, n, seed, coeff, &exponent, lambda, matvec_multiplier);
}

static FoldPair first_product(FILE *table, FILE *xi, uint64_t n, F r, Moment *next,
                              const int *exponent)
{
    *next = (Moment){0};
    __int128 xs[CHUNK];
    F w[CHUNK];
    FoldPair out[CHUNK/2], last = {0};
    int fd = table_fd(table, n, sizeof(F));
    rewind_checked(xi);
    for (uint64_t pos = 0; pos < n; pos += CHUNK) {
        size_t count = chunk_size(n-pos);
        off_t offset = (off_t)(pos*sizeof(F));
        read_at(fd, w, count*sizeof(F), offset);
        if (!witness_read_encoded(xi, xs, count, exponent)) fail("invalid or incomplete binary64 witness");
        for (size_t j = 0; j < count/2; j++) {
            size_t k = 2*j;
            out[j] = interp_pair((FoldPair){fwide(xs[k]),w[k]},
                                 (FoldPair){fwide(xs[k+1]),w[k+1]},r);
        }
        for (size_t j = 0; j+1 < count/2; j += 2) moment_pair(next,out[j],out[j+1]);
        last = out[count/2-1];
        write_at(fd, out, (count/2)*sizeof(FoldPair), offset);
    }
    witness_end(xi);
    rewind_checked(table);
    return last;
}

FoldPair fold_product_first(FILE *table, FILE *xi, uint64_t n, F r, Moment *next)
{
    return first_product(table, xi, n, r, next, NULL);
}

FoldPair fold_product_first_wide(FILE *table, FILE *xi, uint64_t n, F r,
                                Moment *next, int exponent)
{
    return first_product(table, xi, n, r, next, &exponent);
}
