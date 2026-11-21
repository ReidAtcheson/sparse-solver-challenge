#include "commit.h"
#include "witness.h"

#include <openssl/evp.h>
#ifdef STENCIL_CHECK_LIMBS
#undef NDEBUG
#include <assert.h>
#endif
#include <stdlib.h>
#include <string.h>

/* Stable libsodium ABI. Some UNIX distributions package the shared object
   separately from the development headers. */
extern int sodium_init(void);
extern int crypto_core_ristretto255_from_hash(unsigned char *, const unsigned char *);
extern int crypto_core_ristretto255_is_valid_point(const unsigned char *);
extern int crypto_core_ristretto255_add(unsigned char *, const unsigned char *, const unsigned char *);
extern int crypto_scalarmult_ristretto255(unsigned char *, const unsigned char *, const unsigned char *);

static void put32(unsigned char out[4], uint32_t value)
{
    for (unsigned i = 0; i < 4; i++) out[i] = (unsigned char)(value >> (8*i));
}

static int generator(uint32_t col, unsigned char out[32])
{
    static const char domain[] = "stencil-ristretto255-generator-v1";
    unsigned char message[sizeof(domain)-1+4], hash[64];
    memcpy(message, domain, sizeof(domain)-1);
    put32(message + sizeof(domain)-1, col);
    return EVP_Digest(message, sizeof(message), hash, NULL, EVP_sha512(), NULL)
        && crypto_core_ristretto255_from_hash(out, hash) == 0;
}

static int digest_rows(uint32_t height, const char *domain, const unsigned char *shape,
                       size_t shape_len, const unsigned char *rows, unsigned char digest[32])
{
    if (!height || SIZE_MAX / height < 32) return 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)
        && EVP_DigestUpdate(ctx, domain, strlen(domain))
        && EVP_DigestUpdate(ctx, shape, shape_len)
        && EVP_DigestUpdate(ctx, rows, (size_t)height * 32)
        && EVP_DigestFinal_ex(ctx, digest, NULL);
    EVP_MD_CTX_free(ctx);
    return ok;
}

int vc_digest(uint32_t width, uint32_t height, const unsigned char *rows, unsigned char digest[32])
{
    if (!width) return 0;
    /* Old square commitments signed the width once. Rectangles bind both sides. */
    const char *domain = width == height ? "stencil-ristretto255-row-commitments-v1"
                                        : "stencil-ristretto255-rect-commitments-v1";
    unsigned char shape[8];
    put32(shape, width);
    put32(shape + 4, height);
    return digest_rows(height, domain, shape, width == height ? 4 : 8, rows, digest);
}

int vc_digest_wide(uint32_t width, uint32_t height, int exponent,
                   const unsigned char *rows, unsigned char digest[32])
{
    if (!width || exponent < -1074 || exponent > 1024) return 0;
    unsigned char shape[12];
    put32(shape, width);
    put32(shape + 4, height);
    put32(shape + 8, (uint32_t)exponent);
    return digest_rows(height, "stencil-ristretto255-wide80-row-commitments-v1",
                       shape, sizeof(shape), rows, digest);
}

/* The timing-critical row writer accumulates points before compressing. The
   independent verifier below uses only libsodium's canonical group operations.
   Formula references: RFC 9496 §§4.2–4.3, and the extended Edwards addition
   law for a=-1 (Hisil et al., 2008). Variable-time MSM is intentional. */
typedef struct { uint64_t v[5]; } Fe;
typedef struct { Fe x, y, z, t; } Point;
typedef struct { Fe plus, minus, dt; } Cached;
typedef struct { Point point; Cached pos, neg; } Base;
typedef __uint128_t Wide;
#define MASK51 ((UINT64_C(1) << 51) - 1)
static const Fe zero = {{0}}, one = {{1}};
static const Fe d = {{929955233495203,466365720129213,1662059464998953,2033849074728123,1442794654840575}};
static const Fe d2 = {{1859910466990425,932731440258426,1072319116312658,1815898335770999,633789495995903}};
static const Fe sqrt_m1 = {{1718705420411056,234908883556509,2233514472574048,2117202627021982,765476049583133}};
static const Fe invsqrt_a_minus_d = {{278908739862762,821645201101625,8113234426968,1777959178193151,2118520810568447}};

static inline Fe add(Fe a, Fe b)
{
    for (int i = 0; i < 5; i++) a.v[i] += b.v[i];
    return a;
}

/* A product's limbs are < B+2^16, B=2^51. The only loose subtrahends
   are negated point coordinates, formed as 4p minus a carried coordinate.
   Each such limb is at most its own bias. complete() and double_point()
   use only products as subtrahends. */
static inline Fe sub(Fe a, Fe b)
{
    for (int i = 0; i < 5; i++) {
        uint64_t bias = 4 * (MASK51 - (i == 0 ? 18 : 0));
#ifdef STENCIL_CHECK_LIMBS
        assert(b.v[i] <= bias);
#endif
        a.v[i] = (a.v[i] + bias) - b.v[i];
    }
    return a;
}

static inline Fe mul(Fe a, Fe b)
{
    const uint64_t *x = a.v, *y = b.v;
    /* The largest loose inputs arise from the double subtraction in Decode
       (<8B) and from g+2c in doubling (<8B). Even at 12B the largest
       convolution coefficient is <2^116; h4 after the carries is <721B².
       Thus the final wrap adds <2^16 to the second output limb. */
#ifdef STENCIL_CHECK_LIMBS
    for (int i = 0; i < 5; i++) {
        assert(x[i] < 12*(MASK51+1));
        assert(y[i] < 12*(MASK51+1));
    }
#endif
    const uint64_t w1=19*y[1], w2=19*y[2], w3=19*y[3], w4=19*y[4];
#define PROD(i,v) ((Wide)x[i] * (v))
    Wide h0=PROD(0,y[0])+PROD(1,w4)+PROD(2,w3)+PROD(3,w2)+PROD(4,w1);
    Wide h1=PROD(0,y[1])+PROD(1,y[0])+PROD(2,w4)+PROD(3,w3)+PROD(4,w2);
    Wide h2=PROD(0,y[2])+PROD(1,y[1])+PROD(2,y[0])+PROD(3,w4)+PROD(4,w3);
    Wide h3=PROD(0,y[3])+PROD(1,y[2])+PROD(2,y[1])+PROD(3,y[0])+PROD(4,w4);
    Wide h4=PROD(0,y[4])+PROD(1,y[3])+PROD(2,y[2])+PROD(3,y[1])+PROD(4,y[0]);
#undef PROD
    h1 += h0 >> 51; h2 += h1 >> 51; h3 += h2 >> 51; h4 += h3 >> 51;
    h0 = ((uint64_t)h0 & MASK51) + 19 * (h4 >> 51);
    return (Fe){{(uint64_t)h0 & MASK51, ((uint64_t)h1 & MASK51)+(uint64_t)(h0>>51),
                 (uint64_t)h2 & MASK51, (uint64_t)h3 & MASK51, (uint64_t)h4 & MASK51}};
}

static Fe canonical(Fe a)
{
    /* Multiplying by one carries the loose input; a second round propagates
       across any run of all-ones limbs. Finally subtract p if necessary. */
    a = mul(a,one);
    for (int pass = 0; pass < 2; pass++) {
        for (int i = 0; i < 4; i++) {
            a.v[i+1] += a.v[i] >> 51;
            a.v[i] &= MASK51;
        }
        a.v[0] += 19 * (a.v[4] >> 51);
        a.v[4] &= MASK51;
    }
    if (a.v[4] == MASK51 && a.v[3] == MASK51 && a.v[2] == MASK51 &&
        a.v[1] == MASK51 && a.v[0] >= MASK51-18)
        return (Fe){{a.v[0]-(MASK51-18),0,0,0,0}};
    return a;
}

static int negative(Fe a) { return canonical(a).v[0] & 1; }
static Fe absolute(Fe a) { return negative(a) ? sub(zero,a) : a; }
static int equal(Fe a, Fe b)
{
    a = canonical(a); b = canonical(b);
    return memcmp(a.v,b.v,sizeof(a.v)) == 0;
}

static Fe unpack(const unsigned char bytes[32])
{
    Fe x = zero;
    for (int bit = 0; bit < 255; bit++)
        x.v[bit/51] |= (uint64_t)((bytes[bit/8] >> (bit%8)) & 1) << (bit%51);
    return x;
}

static void pack(unsigned char bytes[32], Fe x)
{
    x = canonical(x);
    memset(bytes,0,32);
    for (int bit = 0; bit < 255; bit++)
        bytes[bit/8] |= ((x.v[bit/51] >> (bit%51)) & 1) << (bit%8);
}

/* All calls use an input known to be a square, or zero when encoding the
   identity. x^((p-5)/8) = x^(2^252-3). */
static Fe invsqrt(Fe v)
{
    Fe v2 = mul(v,v), v3 = mul(v2,v), v7 = mul(mul(v3,v3),v);
    Fe power = one;
    for (int i=251; i>=0; i--) {
        power = mul(power,power);
        if (i != 1) power = mul(power,v7);
    }
    Fe r = mul(v3,power);
    if (!equal(mul(v,mul(r,r)),one)) r = mul(r,sqrt_m1);
    return absolute(r);
}

/* The only inputs to this function are canonical points produced by libsodium. */
static Point decode_generator(const unsigned char bytes[32])
{
    Fe s=unpack(bytes), ss=mul(s,s);
    Fe u1=sub(one,ss), u2=add(one,ss), u22=mul(u2,u2);
    Fe v=sub(sub(zero,mul(d,mul(u1,u1))),u22);
    Fe r=invsqrt(mul(v,u22)), dx=mul(r,u2);
    Fe x=absolute(mul(add(s,s),dx)), y=mul(u1,mul(mul(r,dx),v));
    return (Point){x,y,one,mul(x,y)};
}

static void encode(unsigned char bytes[32], Point p)
{
    Fe u1=mul(add(p.z,p.y),sub(p.z,p.y)), u2=mul(p.x,p.y);
    Fe r=invsqrt(mul(u1,mul(u2,u2)));
    Fe den1=mul(r,u1), den2=mul(r,u2), zinv=mul(mul(den1,den2),p.t);
    Fe x=p.x, y=p.y, den=den2;
    if (negative(mul(p.t,zinv))) {
        x=mul(p.y,sqrt_m1);
        y=mul(p.x,sqrt_m1);
        den=mul(den1,invsqrt_a_minus_d);
    }
    if (negative(mul(x,zinv))) y=sub(zero,y);
    pack(bytes,absolute(mul(den,sub(p.z,y))));
}

static Point identity(void) { return (Point){zero,one,one,zero}; }

static inline Point complete(Fe a, Fe b, Fe c, Fe z2)
{
    Fe e=sub(b,a), f=sub(z2,c), g=add(z2,c), h=add(b,a);
    return (Point){mul(e,f),mul(g,h),mul(f,g),mul(e,h)};
}

static inline Point add_base(Point p, const Cached *q)
{
    return complete(mul(sub(p.y,p.x),q->minus),mul(add(p.y,p.x),q->plus),
                    mul(p.t,q->dt),add(p.z,p.z));
}

static inline Point add_point(Point p, Point q)
{
    Fe zz=mul(p.z,q.z);
    return complete(mul(sub(p.y,p.x),sub(q.y,q.x)),mul(add(p.y,p.x),add(q.y,q.x)),
                    mul(mul(p.t,q.t),d2),add(zz,zz));
}

static inline Point double_point(Point p)
{
    Fe a=mul(p.x,p.x), b=mul(p.y,p.y), c=mul(p.z,p.z), sum=add(p.x,p.y);
    Fe h=add(a,b), g=sub(a,b);
    Fe e=sub(h,mul(sum,sum)), f=add(g,add(c,c));
    return (Point){mul(e,f),mul(g,h),mul(f,g),mul(e,h)};
}

/* Signed-window Pippenger. Recode each magnitude in balanced radix 2^width.
   Both formats fit in 80 bits, including after negation. */
static void row_msm(unsigned char out[32], const Base *base, __int128 *mag,
                    unsigned char *neg, uint32_t side)
{
    unsigned width = side >= 1024 ? 8 : side >= 256 ? 6 : side >= 64 ? 5 : 3;
    unsigned radix=1u<<width, half=radix/2, bits=0;
    Wide all=0;
    for (uint32_t j=0;j<side;j++) {
        neg[j]=mag[j]<0;
        if (neg[j]) mag[j]=-mag[j];
        all |= mag[j];
    }
    while (all) { bits++; all >>= 1; }
    Point acc=identity(), bucket[129];
    for (int shift=(int)(bits/width*width); shift>=0; shift-=(int)width) {
        unsigned char used[129]={0};
        for (unsigned b=0;b<width;b++) acc=double_point(acc);
        for (uint32_t j=0;j<side;j++) {
            unsigned digit=(mag[j]>>shift) & (radix-1);
            unsigned carry=shift ? (mag[j]>>(shift-1)) & 1u : 0;
            int val=(int)digit+(int)carry-(digit>=half ? (int)radix : 0);
            if (!val) continue;
            int flip=neg[j] ^ (val<0);
            unsigned k=(unsigned)(val<0 ? -val : val);
            if (used[k]) bucket[k]=add_base(bucket[k],flip ? &base[j].neg : &base[j].pos);
            else {
                bucket[k]=base[j].point;
                if (flip) {
                    bucket[k].x=sub(zero,bucket[k].x);
                    bucket[k].t=sub(zero,bucket[k].t);
                }
                used[k]=1;
            }
        }
        Point running=identity();
        int started=0;
        for (unsigned k=half;k;k--) {
            if (used[k]) {
                running=started ? add_point(running,bucket[k]) : bucket[k];
                started=1;
            }
            if (started) acc=add_point(acc,running);
        }
    }
    encode(out,acc);
}

static int commit_rows(FILE *input, uint32_t width, uint32_t height, const int *exponent,
                       unsigned char *rows, unsigned char digest[32])
{
    if (!width || !height || SIZE_MAX/width < sizeof(Base) || SIZE_MAX/height < 32 || sodium_init()<0) return 0;
    Base *base=calloc(width,sizeof(*base));
    __int128 *values=calloc(width,sizeof(*values));
    unsigned char *neg=calloc(width,1);
    int ok=0;
    if (!base || !values || !neg) goto done;
    for (uint32_t j=0;j<width;j++) {
        unsigned char bytes[32];
        if (!generator(j,bytes)) goto done;
        Point p=decode_generator(bytes);
        /* Keep stored coordinates carried so later loose sums fit their bounds. */
        p.x=canonical(p.x); p.y=canonical(p.y);
        base[j].point=p;
        Cached c={add(p.y,p.x),sub(p.y,p.x),mul(p.t,d2)};
        base[j].pos=c;
        base[j].neg=(Cached){c.minus,c.plus,sub(zero,c.dt)};
    }
    for (uint32_t i=0;i<height;i++) {
        if (!witness_read_encoded(input,values,width,exponent)) goto done;
        row_msm(rows+32*(size_t)i,base,values,neg,width);
    }
    ok=fgetc(input)==EOF && !ferror(input) &&
       (exponent ? vc_digest_wide(width,height,*exponent,rows,digest)
                 : vc_digest(width,height,rows,digest));
done:
    free(neg); free(values); free(base);
    return ok;
}

int vc_commit(FILE *input, uint32_t width, uint32_t height, unsigned char *rows, unsigned char digest[32])
{
    return commit_rows(input, width, height, NULL, rows, digest);
}

int vc_commit_wide(FILE *input, uint32_t width, uint32_t height, int exponent,
                   unsigned char *rows, unsigned char digest[32])
{
    return commit_rows(input, width, height, &exponent, rows, digest);
}

static int scalar_canonical(const unsigned char *s)
{
    static const unsigned char order[32]={
        0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10};
    for (int j=31;j>=0;j--) if (s[j]!=order[j]) return s[j]<order[j];
    return 0;
}

static int accumulate(unsigned char *sum,const unsigned char *s,const unsigned char *p)
{
    static const unsigned char id[32]={0};
    if (!scalar_canonical(s)) return 0;
    if (memcmp(s,id,32)==0 || memcmp(p,id,32)==0) return 1;
    unsigned char term[32];
    return crypto_scalarmult_ristretto255(term,s,p)==0 &&
           crypto_core_ristretto255_add(sum,sum,term)==0;
}

int vc_verify(uint32_t width, uint32_t height, const unsigned char *rows,
              const unsigned char *weights, const unsigned char *z)
{
    if (!width || !height || SIZE_MAX/width < 32 || SIZE_MAX/height < 32 || sodium_init()<0)
        return 0;
    unsigned char left[32]={0},right[32]={0};
    for (uint32_t i=0;i<height;i++) {
        size_t off=32*(size_t)i;
        const unsigned char *p=rows+off;
        if ((p[31]&0x80) || !crypto_core_ristretto255_is_valid_point(p) ||
            !accumulate(left,weights+off,p)) return 0;
    }
    for (uint32_t j=0;j<width;j++) {
        unsigned char g[32];
        if (!generator(j,g) || !accumulate(right,z+32*(size_t)j,g)) return 0;
    }
    return memcmp(left,right,32)==0;
}
