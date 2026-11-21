#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64
#include "witness.h"

#include <errno.h>
#include <float.h>
#include <limits.h>
#include <math.h>
#include <string.h>
#include <unistd.h>

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "The witness input format requires a little-endian target."
#endif
_Static_assert(sizeof(double) == 8 && DBL_MANT_DIG == 53 && DBL_MAX_EXP == 1024 &&
               CHAR_BIT == 8 && sizeof(off_t) >= 8, "binary64 and 64-bit offsets required");

/* Raw bytes first land in the caller's buffer. memcpy reads the double bit
   pattern without an aliasing cast. Each resulting integer replaces its input. */
static int quantize(int64_t *out, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        double value;
        memcpy(&value, out + i, sizeof(value));
        double rounded = nearbyint(value * 0x1p58);
        if (!(rounded >= -0x1p63 && rounded < 0x1p63)) {
            errno = ERANGE;
            return 0;
        }
        out[i] = (int64_t)rounded;
    }
    return 1;
}

static int read_bytes(FILE *f, unsigned char *buf, size_t bytes)
{
    for (size_t done = 0; done < bytes;) {
        size_t got = fread(buf + done, 1, bytes - done, f);
        done += got;
        if (ferror(f)) {
            if (errno != EINTR) return 0;
            clearerr(f);
        } else if (got == 0) {
            errno = EIO;
            return 0;
        }
    }
    return 1;
}

static int read_at(int fd, unsigned char *buf, size_t n, uint64_t first)
{
    if (n > SIZE_MAX / sizeof(double) || first > INT64_MAX / sizeof(double) ||
        n > INT64_MAX / sizeof(double) - first) {
        errno = EOVERFLOW;
        return 0;
    }
    size_t bytes = n * sizeof(double);
    off_t pos = (off_t)(first * sizeof(double));
    for (size_t done = 0; done < bytes;) {
        size_t pending = bytes - done;
        if (pending > (size_t)SSIZE_MAX) pending = (size_t)SSIZE_MAX;
        ssize_t got = pread(fd, buf + done, pending, pos + (off_t)done);
        if (got < 0) {
            if (errno == EINTR) continue;
            return 0;
        }
        if (got == 0) {
            errno = EIO;
            return 0;
        }
        done += (size_t)got;
    }
    return 1;
}

int witness_read(FILE *f, int64_t *out, size_t n)
{
    if (n > SIZE_MAX / sizeof(*out)) {
        errno = EOVERFLOW;
        return 0;
    }
    return read_bytes(f, (unsigned char *)out, n * sizeof(double)) && quantize(out, n);
}

int witness_pread(int fd, int64_t *out, size_t n, uint64_t first)
{
    return read_at(fd, (unsigned char *)out, n, first) && quantize(out, n);
}

int witness_exponent(FILE *f, uint64_t n, int *exponent)
{
    double block[1024], maximum = 0;
    if (fseeko(f, 0, SEEK_SET) != 0) return 0;
    while (n) {
        size_t count = n < 1024 ? (size_t)n : 1024;
        if (!read_bytes(f, (unsigned char *)block, count * sizeof(double))) return 0;
        for (size_t i = 0; i < count; i++) {
            if (!isfinite(block[i])) { errno = ERANGE; return 0; }
            if (fabs(block[i]) > maximum) maximum = fabs(block[i]);
        }
        n -= count;
    }
    if (fgetc(f) != EOF) { errno = EINVAL; return 0; }
    if (ferror(f) || fseeko(f, 0, SEEK_SET) != 0) return 0;
    int e = 0;
    if (maximum > 0 && frexp(maximum, &e) == 0.5) e--;
    *exponent = e;
    return 1;
}

static int wide_size(size_t n, int exponent)
{
    if (n > SIZE_MAX / sizeof(__int128)) { errno = EOVERFLOW; return 0; }
    if (exponent < -1074 || exponent > 1024) { errno = ERANGE; return 0; }
    return 1;
}

int witness_profile_shift(unsigned dimensions, unsigned bits, int exponent, int *shift)
{
    if (dimensions == 1) {
        if (exponent < -26 || exponent > 54) return 0;
        *shift = 74 - exponent;
    } else {
        if (dimensions != 3 || bits > 30 || exponent < -(int)bits - 30 || exponent > 54)
            return 0;
        *shift = 78 - exponent - (int)bits;
    }
    return 1;
}

/* Expand in reverse so the 16-byte integers can share their input buffer
   with the 8-byte binary64 file data. Power-of-two scaling is exact near
   every half-integer rounding boundary, including for subnormal inputs. */
static int quantize_wide(__int128 *out, size_t n, int exponent)
{
    const unsigned char *raw = (const unsigned char *)out;
    while (n > 0) {
        double value;
        n--;
        memcpy(&value, raw + n * sizeof(double), sizeof(value));
        double rounded = nearbyint(scalbn(value, 78 - exponent));
        if (!(fabs(rounded) <= 0x1p78)) { errno = ERANGE; return 0; }
        out[n] = (__int128)rounded;
    }
    return 1;
}

int witness_read_wide(FILE *f, __int128 *out, size_t n, int exponent)
{
    return wide_size(n, exponent) && read_bytes(f, (unsigned char *)out, n * sizeof(double)) &&
           quantize_wide(out, n, exponent);
}

int witness_pread_wide(int fd, __int128 *out, size_t n, uint64_t first, int exponent)
{
    return wide_size(n, exponent) && read_at(fd, (unsigned char *)out, n, first) &&
           quantize_wide(out, n, exponent);
}

int witness_read_encoded(FILE *f, __int128 *out, size_t n, const int *exponent)
{
    if (exponent) return witness_read_wide(f, out, n, *exponent);
    int64_t block[256];
    while (n) {
        size_t count = n < 256 ? n : 256;
        if (!witness_read(f, block, count)) return 0;
        for (size_t j = 0; j < count; j++) out[j] = block[j];
        out += count;
        n -= count;
    }
    return 1;
}
