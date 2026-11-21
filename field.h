#ifndef STENCIL_FIELD_H
#define STENCIL_FIELD_H
#include <stdint.h>
#include <string.h>
#include <limits.h>

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "This reference implementation requires a little-endian target."
#endif
typedef struct {
    uint64_t l[4];
} F;
_Static_assert(sizeof(F) == 32 && CHAR_BIT == 8, "scalar format");
static const F scalar_order = {
    {UINT64_C(0x5812631a5cf5d3ed), UINT64_C(0x14def9dea2f79cd6), 0, UINT64_C(0x1000000000000000)}};
/* These two public libsodium entry points accept little-endian byte strings. */
void crypto_core_ristretto255_scalar_mul(unsigned char *, const unsigned char *,
                                         const unsigned char *);
void crypto_core_ristretto255_scalar_reduce(unsigned char *, const unsigned char *);
static inline F fzero(void) { return (F){{0, 0, 0, 0}}; }
static inline F fone(void) { return (F){{1, 0, 0, 0}}; }
static inline int fcmp(F a, F b)
{
    for (int i = 3; i >= 0; --i)
        if (a.l[i] != b.l[i])
            return a.l[i] > b.l[i] ? 1 : -1;
    return 0;
}
static inline F raw_sub(F a, F b, uint64_t *underflow)
{
    uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        __uint128_t d = (__uint128_t)a.l[i] - b.l[i] - borrow;
        a.l[i] = (uint64_t)d;
        borrow = (uint64_t)(d >> 127);
    }
    *underflow = borrow;
    return a;
}
static inline F raw_add(F a, F b)
{
    uint64_t carry = 0;
    for (int i = 0; i < 4; ++i) {
        __uint128_t s = (__uint128_t)a.l[i] + b.l[i] + carry;
        a.l[i] = (uint64_t)s;
        carry = (uint64_t)(s >> 64);
    }
    return a;
}
static inline F fadd(F a, F b)
{
    a = raw_add(a, b);
    uint64_t ignored;
    if (fcmp(a, scalar_order) >= 0)
        a = raw_sub(a, scalar_order, &ignored);
    return a;
}
static inline F fsub(F a, F b)
{
    uint64_t underflow;
    a = raw_sub(a, b, &underflow);
    return underflow ? raw_add(a, scalar_order) : a;
}
static inline F fmul(F a, F b)
{
    F c;
    crypto_core_ristretto255_scalar_mul((unsigned char *)&c, (const unsigned char *)&a,
                                        (const unsigned char *)&b);
    return c;
}
static inline F fwide(__int128 v)
{
    __uint128_t u = (__uint128_t)v;
    if (v < 0)
        u = 0 - u;
    F out = {{(uint64_t)u, (uint64_t)(u >> 64), 0, 0}};
    return v < 0 ? fsub(fzero(), out) : out;
}
static inline F fsmall(int64_t v) { return fwide(v); }
static inline F fscale(F a, int k)
{
    unsigned m = k < 0 ? 0U - (unsigned)k : (unsigned)k;
    F s = fzero();
    while (m) {
        if (m & 1)
            s = fadd(s, a);
        m >>= 1;
        if (m)
            a = fadd(a, a);
    }
    return k < 0 ? fsub(fzero(), s) : s;
}
static inline F flerp(F a, F b, F point) { return fadd(a, fmul(point, fsub(b, a))); }
#endif
