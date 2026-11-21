#define _POSIX_C_SOURCE 200809L
#include "mask.h"
#include "witness.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

enum { GROUPS = MASK_COUNT / 8, BLOCK_BYTES = 32768, CHUNK_ROWS = 2048 };

typedef struct {
    EVP_CIPHER_CTX *ctx;
    unsigned char block[BLOCK_BYTES];
    size_t pos;
} Stream;

struct Mask {
    Stream stream;
    F weights[GROUPS][256];
};

static void fail(const char *message)
{
    fprintf(stderr, "range mask: %s\n", message);
    exit(EXIT_FAILURE);
}

/* The fixed ASCII label is followed immediately by the 32-byte caller seed;
 * the trailing C NUL is excluded. ChaCha20 uses an all-zero 16-byte IV.
 * Each coordinate consumes 16 consecutive bytes. Bit b of byte g (LSB first)
 * selects subset number 8*g+b. */
static void stream_begin(Stream *s, const unsigned char seed[32])
{
    static const char domain[] = "seeded-stencil/exact-v1/range-mask";
    unsigned char input[sizeof(domain) - 1 + 32];
    unsigned char key[32];
    static const unsigned char iv[16] = {0};
    memcpy(input, domain, sizeof(domain) - 1);
    memcpy(input + sizeof(domain) - 1, seed, 32);
    unsigned int key_len = 0;
    s->ctx = EVP_CIPHER_CTX_new();
    if (!s->ctx || EVP_Digest(input, sizeof(input), key, &key_len, EVP_sha256(), NULL) != 1 ||
        key_len != 32 || EVP_EncryptInit_ex(s->ctx, EVP_chacha20(), NULL, key, iv) != 1)
        fail("cannot initialize ChaCha20");
    s->pos = BLOCK_BYTES;
}

static const unsigned char *next_row(Stream *s)
{
    static const unsigned char zero[BLOCK_BYTES] = {0};
    if (s->pos == BLOCK_BYTES) {
        int n = 0;
        if (EVP_EncryptUpdate(s->ctx, s->block, &n, zero, BLOCK_BYTES) != 1 || n != BLOCK_BYTES)
            fail("cannot expand ChaCha20 stream");
        s->pos = 0;
    }
    const unsigned char *row = s->block + s->pos;
    s->pos += GROUPS;
    return row;
}

static void accumulate_masks(FILE *xi, uint64_t n, const unsigned char seed[32],
                             __int128 out[MASK_COUNT], const int *exponent)
{
    __int128 totals[GROUPS][256] = {{0}};
    __int128 input[CHUNK_ROWS];
    Stream s;
    if (fseeko(xi, 0, SEEK_SET) != 0) fail("cannot seek private witness");
    stream_begin(&s, seed);
    for (uint64_t remaining = n; remaining;) {
        size_t count = remaining < CHUNK_ROWS ? (size_t)remaining : CHUNK_ROWS;
        if (!witness_read_encoded(xi, input, count, exponent)) fail("invalid or unreadable binary64 witness");
        for (size_t i = 0; i < count; i++) {
            const unsigned char *row = next_row(&s);
            for (size_t g = 0; g < GROUPS; g++) totals[g][row[g]] += input[i];
        }
        remaining -= count;
    }
    if (fgetc(xi) != EOF || ferror(xi)) fail("invalid private witness length or read failure");
    EVP_CIPHER_CTX_free(s.ctx);
    for (unsigned g = 0; g < GROUPS; g++) {
        for (unsigned b = 0; b < 8; b++) {
            __int128 sum = 0;
            for (unsigned j = 0; j < 256; j++)
                if (j & (1u << b)) sum += totals[g][j];
            out[8*g+b] = sum;
        }
    }
}

void mask_sums(FILE *xi, uint64_t n, const unsigned char seed[32], __int128 out[MASK_COUNT])
{
    accumulate_masks(xi, n, seed, out, NULL);
}

void mask_sums_wide(FILE *xi, uint64_t n, const unsigned char seed[32],
                    __int128 out[MASK_COUNT], int exponent)
{
    accumulate_masks(xi, n, seed, out, &exponent);
}

Mask *mask_begin(const unsigned char seed[32], const F coeff[MASK_COUNT])
{
    Mask *mask = malloc(sizeof(*mask));
    if (!mask) fail("out of memory");
    stream_begin(&mask->stream, seed);
    for (unsigned g = 0; g < GROUPS; g++) {
        mask->weights[g][0] = fzero();
        for (unsigned b = 0; b < 8; b++) {
            unsigned bit = 1u << b;
            for (unsigned v = 0; v < bit; v++)
                mask->weights[g][bit + v] = fadd(mask->weights[g][v], coeff[8*g+b]);
        }
    }
    return mask;
}

F mask_next(Mask *mask)
{
    const unsigned char *row = next_row(&mask->stream);
    F sum = mask->weights[0][row[0]];
    for (unsigned g = 1; g < GROUPS; g++) sum = fadd(sum, mask->weights[g][row[g]]);
    return sum;
}

void mask_end(Mask *mask)
{
    EVP_CIPHER_CTX_free(mask->stream.ctx);
    free(mask);
}
