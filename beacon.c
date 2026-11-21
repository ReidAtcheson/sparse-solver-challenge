#define _POSIX_C_SOURCE 200809L
#include "beacon.h"
#include "drand.h"
#include "matrix.h"

#include <errno.h>
#include <inttypes.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum { PROFILE = 8, SIDE = 48, START_ROUND = 56, PROOF_ROUND = 64,
       CLOCK_ERROR = 72, ENTRY = 80, NONCE = 112 };
static const uint8_t reg_tag[8] = "STNREG01";
_Static_assert(BC_REG_BYTES + BC_SIG_BYTES == RC_START_BYTES, "start wire size");

static uint64_t le(const uint8_t *p, size_t n)
{
    uint64_t v = 0;
    while (n) v = (v << 8) | p[--n];
    return v;
}

static void put(uint8_t *p, size_t n, uint64_t v)
{
    for (size_t i = 0; i < n; ++i, v >>= 8) p[i] = (uint8_t)v;
}

static int number(const char *s, uint64_t *v)
{
    if (!*s || strspn(s, "0123456789") != strlen(s)) return 0;
    errno = 0;
    uintmax_t n = strtoumax(s, NULL, 10);
    if (errno || n > UINT64_MAX) return 0;
    *v = (uint64_t)n;
    return 1;
}

static void hash_label(SHA256_CTX *ctx, const char *tag)
{
    SHA256_Init(ctx);
    SHA256_Update(ctx, tag, strlen(tag));
}

static void hash_one(const char *tag, const void *p, size_t n, uint8_t out[32])
{
    SHA256_CTX ctx;
    hash_label(&ctx, tag);
    SHA256_Update(&ctx, p, n);
    SHA256_Final(out, &ctx);
}

int bc_is_start(const uint8_t start[RC_START_BYTES])
{
    return !memcmp(start, reg_tag, sizeof(reg_tag));
}

static const MatrixProfile *reg_profile(const uint8_t *reg)
{
    uint64_t release, cutoff;
    uint64_t error = le(reg + CLOCK_ERROR, 8);
    if (memcmp(reg, reg_tag, 8) || le(reg + 52, 4) ||
        !drand_quicknet_time(le(reg + START_ROUND, 8), &release) ||
        !drand_quicknet_time(le(reg + PROOF_ROUND, 8), &cutoff) || release >= cutoff ||
        !error || error > (cutoff - release - 1) / 2)
        return NULL;
    const MatrixProfile *p = matrix_profile_wire(reg + PROFILE);
    return p && p->allow_beacon && matrix_profile_side(p, le(reg + SIDE, 4)) ? p : NULL;
}

int bc_check_start(const char *registration, const uint8_t start[RC_START_BYTES],
                   struct rc_info *info)
{
    uint8_t trusted[BC_REG_BYTES], randomness[32];
    uint64_t release;
    const MatrixProfile *p = reg_profile(start);
    if (!p || !rc_read_exact(registration, trusted, sizeof(trusted)) ||
        memcmp(trusted, start, sizeof(trusted)) ||
        !drand_quicknet_verify(le(start + START_ROUND, 8), start + BC_REG_BYTES,
                               randomness, &release)) return 0;
    memset(info, 0, sizeof(*info));
    info->side = (uint32_t)le(start + SIDE, 4);
    info->profile = p;
    info->dimensions = p->dimensions;
    info->signed_unit = p->signed_unit;
    info->start_ns = release;
    memcpy(info->entry, start + ENTRY, 32);
    hash_one("stencil-quicknet-attempt-v1", start, RC_START_BYTES, info->attempt);
    /* Entrants in the same profile/side/start round receive the same instance. */
    SHA256_CTX ctx;
    hash_label(&ctx, "stencil-quicknet-instance-v1");
    SHA256_Update(&ctx, drand_quicknet_chain_hash, 32);
    SHA256_Update(&ctx, start + PROFILE, 44);
    SHA256_Update(&ctx, start + START_ROUND, 8);
    SHA256_Update(&ctx, randomness, 32);
    SHA256_Final(info->seed, &ctx);
    return 1;
}

static void imprint(const uint8_t *start, const uint8_t digest[32], uint8_t out[32])
{
    SHA256_CTX ctx;
    hash_label(&ctx, "stencil-quicknet-commit-time-v1");
    SHA256_Update(&ctx, start, RC_START_BYTES);
    SHA256_Update(&ctx, digest, 32);
    SHA256_Final(out, &ctx);
}

/* Call only after authenticating start. Allow for the greater of the trusted
 * TSA policy's error bound and the token's signed accuracy. */
static int check_stamp(const char *ca, const char *policy, const uint8_t *start,
                       const uint8_t digest[32], const uint8_t *der, size_t n,
                       struct rc_info *info, uint64_t *error)
{
    struct rc_tsa_time stamp;
    uint8_t expected[32];
    uint64_t cutoff, floor = le(start + CLOCK_ERROR, 8);
    imprint(start, digest, expected);
    if (!rc_tsa_verify_policy(ca, policy, expected, der, n, &stamp) ||
        !drand_quicknet_time(le(start + PROOF_ROUND, 8), &cutoff)) return 0;
    uint64_t err = stamp.has_accuracy && stamp.accuracy_ns > floor ? stamp.accuracy_ns : floor;
    if (stamp.unix_ns < info->start_ns || stamp.unix_ns - info->start_ns < err ||
        stamp.unix_ns >= cutoff || cutoff - stamp.unix_ns <= err) return 0;
    info->finish_ns = stamp.unix_ns;
    memcpy(info->digest, digest, 32);
    *error = err;
    return 1;
}

int bc_check_evidence(const char *registration, const char *ca, const char *policy,
                      const uint8_t start[RC_START_BYTES], const uint8_t digest[32],
                      const uint8_t finish_sig[BC_SIG_BYTES], const uint8_t *der,
                      size_t der_len, struct rc_info *info, uint64_t *uncertainty_ns)
{
    uint8_t randomness[32];
    uint64_t release;
    return bc_check_start(registration, start, info) &&
           drand_quicknet_verify(le(start + PROOF_ROUND, 8), finish_sig, randomness, &release) &&
           check_stamp(ca, policy, start, digest, der, der_len, info, uncertainty_ns);
}

static int registration(char **a)
{
    uint8_t reg[BC_REG_BYTES] = {0};
    uint64_t side, first, last, err;
    const MatrixProfile *p = matrix_profile_command(a[1], 0);
    if (!p || !p->allow_beacon || !*a[3] || !number(a[2], &side) || side > UINT32_MAX ||
        !number(a[5], &first) || !number(a[6], &last) || !number(a[7], &err) ||
        !rc_read_exact(a[4], reg + NONCE, 32)) return 0;
    memcpy(reg, reg_tag, 8);
    memcpy(reg + PROFILE, p->id, sizeof(p->id));
    put(reg + SIDE, 4, side);
    put(reg + START_ROUND, 8, first);
    put(reg + PROOF_ROUND, 8, last);
    put(reg + CLOCK_ERROR, 8, err);
    hash_one("stencil-entry-v1", a[3], strlen(a[3]), reg + ENTRY);
    return reg_profile(reg) && rc_deliver(a[8], reg, sizeof(reg));
}

static int start_receipt(char **a)
{
    uint8_t start[RC_START_BYTES];
    struct rc_info info;
    return rc_read_exact(a[1], start, BC_REG_BYTES) &&
           rc_read_exact(a[2], start + BC_REG_BYTES, BC_SIG_BYTES) &&
           bc_check_start(a[1], start, &info) && rc_deliver(a[3], start, sizeof(start));
}

static int make_query(char **a, const char *policy)
{
    struct rc_info info;
    uint8_t start[RC_START_BYTES], digest[32], expected[32], req[192];
    size_t size;
    if (!rc_read_exact(a[2], start, sizeof(start)) || !bc_check_start(a[1], start, &info) ||
        !rc_read_exact(a[3], digest, sizeof(digest))) return 0;
    imprint(start, digest, expected);
    int ok = policy ? rc_tsa_query_policy(expected, policy, req, sizeof(req), &size)
                    : rc_tsa_query(expected, req, sizeof(req), &size);
    return ok && rc_deliver(a[4], req, size);
}

static int before_cutoff(uint64_t cutoff, uint64_t clock_error)
{
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) || now.tv_sec < 0) return 0;
    uint64_t seconds = (uint64_t)now.tv_sec, ns = (uint64_t)now.tv_nsec;
    if (seconds > (UINT64_MAX - ns) / UINT64_C(1000000000)) return 0;
    uint64_t observed = seconds * UINT64_C(1000000000) + ns;
    return observed < cutoff && cutoff - observed > clock_error;
}

/* The candidate is durable and immutable before the decisive clock check.
 * A stall during fsync or a race at the deadline cannot make a late choice
 * eligible. Only the final non-dotfile is a public record. */
static int record_digest(const char *directory, const uint8_t attempt[32],
                         const uint8_t digest[32], uint64_t cutoff, uint64_t clock_error)
{
    char id[65];
    for (int i = 0; i < 32; ++i) snprintf(id + 2*i, 3, "%02x", attempt[i]);
    size_t size = strlen(directory) + sizeof("/.claim-") + sizeof(id);
    char *path = malloc(size);
    if (!path) return 0;
    snprintf(path, size, "%s/%s", directory, id);
    uint8_t prior[32];
    int ok;
    if (rc_read_exact(path, prior, sizeof(prior))) {
        ok = !memcmp(prior, digest, sizeof(prior)) && rc_deliver(path, digest, 32);
    } else {
        snprintf(path, size, "%s/.claim-%s", directory, id);
        ok = before_cutoff(cutoff, clock_error) && rc_deliver(path, digest, 32) &&
             before_cutoff(cutoff, clock_error);
        snprintf(path, size, "%s/%s", directory, id);
        if (ok) ok = rc_deliver(path, digest, 32);
    }
    if (ok) puts(path);
    free(path);
    return ok;
}

/* The offline check and the registrar authenticate exactly the same evidence.
 * The registrar additionally selects one winner in its own ledger directory. */
static int verify_submission(char **a, const char *ledger)
{
    uint8_t start[RC_START_BYTES], digest[32];
    struct rc_info info;
    uint64_t error, cutoff;
    size_t len;
    if (!rc_read_exact(a[4], start, sizeof(start)) || !bc_check_start(a[1], start, &info) ||
        !rc_read_exact(a[5], digest, sizeof(digest))) return 0;
    uint8_t *der = rc_tsa_read_response(a[6], &len);
    if (!der) return 0;
    int ok = check_stamp(a[2], a[3], start, digest, der, len, &info, &error);
    free(der);
    if (!ok) return 0;
    if (ledger)
        return drand_quicknet_time(le(start + PROOF_ROUND, 8), &cutoff) &&
               record_digest(ledger, info.attempt, digest, cutoff, le(start + CLOCK_ERROR, 8));
    return printf("start_scheduled_ns=%" PRIu64 " commitment_utc_ns=%" PRIu64
                  " clock_uncertainty_ns=%" PRIu64 "\n",
                  info.start_ns, info.finish_ns, error) >= 0;
}

int bc_main(int argc, char **argv)
{
    int ok;
    if (!strcmp(argv[0], "beacon-register") && argc == 9)
        ok = registration(argv);
    else if (!strcmp(argv[0], "beacon-start") && argc == 4)
        ok = start_receipt(argv);
    else if (!strcmp(argv[0], "beacon-query") && (argc == 5 || argc == 6))
        ok = make_query(argv, argc == 6 ? argv[5] : NULL);
    else if (!strcmp(argv[0], "beacon-verify-stamp") && argc == 7)
        ok = verify_submission(argv, NULL);
    else if (!strcmp(argv[0], "beacon-record") && argc == 8)
        ok = verify_submission(argv, argv[7]);
    else {
        fputs("  beacon-register {2d|3d|signed3d} SIDE ENTRY NONCE32 START_ROUND PROOF_ROUND CLOCK_ERROR_NS REG\n"
              "  beacon-start REG ROUND_SIG START\n"
              "  beacon-query REG START DIGEST REQUEST.tsq [POLICY_OID]\n"
              "  beacon-verify-stamp REG CA.pem POLICY_OID START DIGEST RESPONSE.tsr\n"
              "  beacon-record REG CA.pem POLICY_OID START DIGEST RESPONSE.tsr LEDGER_DIR\n", stderr);
        return 2;
    }
    if (!ok) fprintf(stderr, "stencil: %s failed%s\n", argv[0],
                     drand_quicknet_available() ? "" : " (Quicknet verification requires blst)");
    return ok ? 0 : 1;
}
