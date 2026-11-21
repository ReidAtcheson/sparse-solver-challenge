#include "three_band.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_number(const char *s, uint64_t *out)
{
    if (!*s || strspn(s, "0123456789") != strlen(s)) return 0;
    errno = 0;
    uintmax_t number = strtoumax(s, NULL, 10);
    if (errno || number > UINT64_MAX) return 0;
    *out = (uint64_t)number;
    return 1;
}

/* Whitespace-delimited, decimal, zero-based original indices in METIS order. */
static int read_permutation(const char *path, size_t n, size_t **out)
{
    if (n > SIZE_MAX / sizeof(size_t)) return EOVERFLOW;
    FILE *f = strcmp(path, "-") == 0 ? stdin : fopen(path, "r");
    if (!f) return errno;
    size_t *perm = malloc(n * sizeof(*perm));
    int err = perm ? 0 : ENOMEM;
    int c = fgetc(f);
    for (size_t k = 0; k < n && !err; ++k) {
        while (isspace(c)) c = fgetc(f);
        if (c < '0' || c > '9') { err = EINVAL; break; }
        size_t v = 0;
        do {
            unsigned digit = (unsigned)(c - '0');
            if (v > (SIZE_MAX - digit) / 10) { err = EOVERFLOW; break; }
            v = v * 10 + digit;
            c = fgetc(f);
        } while (c >= '0' && c <= '9');
        if ((c != EOF && !isspace(c)) || v >= n) err = EINVAL;
        perm[k] = v;
    }
    while (isspace(c)) c = fgetc(f);
    if (c != EOF && !err) err = EINVAL;
    if (ferror(f)) err = EIO;
    if (f != stdin && fclose(f) != 0 && !err) err = EIO;
    if (err) free(perm);
    else *out = perm;
    return err;
}

typedef struct {
    size_t n, entries;
    int header_written;
} market_writer;

/* Matrix Market accepts coordinate entries in any order. Delay the header
 * until the iterator has validated the permutation and started successfully. */
static int write_entry(void *context, size_t i, size_t j, int sign)
{
    market_writer *w = context;
    if (!w->header_written) {
        if (printf("%%%%MatrixMarket matrix coordinate real symmetric\n%zu %zu %zu\n",
                   w->n, w->n, w->entries) < 0) return EIO;
        w->header_written = 1;
    }
    return printf("%zu %zu %d\n", j+1, i+1, sign) < 0 ? EIO : 0;
}

int three_band_main(int argc, char **argv)
{
    uint64_t size, pattern_seed, sign = 1;
    tb_sign_mode mode = TB_SIGN_DRAW;
    const char *permutation_path = NULL;
    int have_sign = 0;
    if (argc < 3 || !parse_number(argv[1], &size) || size < 3 || size > SIZE_MAX ||
        !parse_number(argv[2], &pattern_seed)) goto usage;
    for (int k = 3; k < argc; k += 2) {
        if (k + 1 >= argc) goto usage;
        if (strcmp(argv[k], "--perm") == 0 && !permutation_path) {
            permutation_path = argv[k+1];
        } else if (!have_sign && (!strcmp(argv[k], "--sign-draw") || !strcmp(argv[k], "--sign-seed"))) {
            mode = !strcmp(argv[k], "--sign-draw") ? TB_SIGN_DRAW : TB_SIGN_SEED;
            if (!parse_number(argv[k+1], &sign) || (mode == TB_SIGN_DRAW && !sign)) goto usage;
            have_sign = 1;
        } else goto usage;
    }

    size_t n = (size_t)size;
    if (n-2 > (SIZE_MAX-2)/4) goto usage;
    market_writer writer = {.n = n, .entries = 4*(n-2)+2};
    size_t *perm = NULL;
    int err = permutation_path ? read_permutation(permutation_path, n, &perm) : 0;
    if (!err) err = tb_signed_scan(n, pattern_seed, mode, sign, perm, write_entry, &writer);
    if (!err && fflush(stdout)) err = EIO;
    free(perm);
    if (err) fprintf(stderr, "stencil three-band: %s\n", strerror(err));
    return err ? 1 : 0;

usage:
    fputs("usage: stencil three-band N PATTERN_SEED [--sign-draw ID | --sign-seed SEED]"
          " [--perm FILE] > matrix.mtx\n", stderr);
    return 2;
}
