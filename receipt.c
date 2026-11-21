#define _POSIX_C_SOURCE 200809L
#include "receipt.h"
#include "beacon.h"
#include "matrix.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Start body: magic[8], side LE32, reserved[4], time LE64, entry[32],
 * nonce[32], profile[40]. Finish body: magic[8], time LE64, attempt[32],
 * digest[32], entropy[16]. Each body is followed by its Ed25519 signature. */
static const uint8_t start_tag[8] = {'S','T','N','S','T','A','0','1'};
static const uint8_t finish_tag[8] = {'S','T','N','F','I','N','0','1'};
static uint64_t get_le(const uint8_t *s, size_t n)
{
    uint64_t v = 0;
    while (n > 0) v = (v << 8) | s[--n];
    return v;
}

static void put_le(uint8_t *s, size_t n, uint64_t v)
{
    for (size_t i = 0; i < n; ++i) {
        s[i] = (uint8_t)v;
        v >>= 8;
    }
}

static int read_exact(FILE *f, void *buf, size_t len)
{
    return fread(buf, 1, len, f) == len && fgetc(f) == EOF && !ferror(f);
}

int rc_read_exact(const char *path, void *buf, size_t len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    int ok = read_exact(f, buf, len);
    return fclose(f) == 0 && ok;
}

static int write_all(int fd, const uint8_t *s, size_t n)
{
    while (n) {
        ssize_t written = write(fd, s, n);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return 0;
        n -= (size_t)written;
        s += written;
    }
    return 1;
}

/* Sync a containing directory before releasing a record to another process. */
static int sync_parent(const char *path)
{
    char *buf = strdup(path);
    if (!buf) return 0;
    char *slash = strrchr(buf, '/');
    const char *dir = ".";
    if (slash) {
        *slash = '\0';
        dir = *buf ? buf : "/";
    }
    int fd = open(dir, O_RDONLY | O_DIRECTORY);
    int ok = fd >= 0 && fsync(fd) == 0;
    if (fd >= 0) close(fd);
    free(buf);
    return ok;
}

/* Prepare the whole file next to its destination. A hard link atomically
 * publishes it only if the destination is still absent. Return -1 on EEXIST. */
static int publish(const char *path, const uint8_t *s, size_t n, mode_t mode)
{
    const char suffix[] = ".XXXXXX";
    size_t plen = strlen(path);
    char *tmp = malloc(plen + sizeof(suffix));
    if (!tmp) return 0;
    memcpy(tmp, path, plen);
    memcpy(tmp + plen, suffix, sizeof(suffix));
    int fd = mkstemp(tmp);
    int ok = 0;
    if (fd >= 0) {
        ok = write_all(fd, s, n) && fchmod(fd, mode) == 0 && fsync(fd) == 0;
        if (close(fd) < 0) ok = 0;
        if (ok && link(tmp, path) != 0) ok = errno == EEXIST ? -1 : 0;
        unlink(tmp);
        /* A competing writer may have linked the winner and crashed just
         * before syncing this directory. EEXIST also needs the durability
         * barrier before a separate receipt file can become visible. */
        if (ok != 0 && !sync_parent(path)) ok = 0;
    }
    free(tmp);
    return ok;
}

static int hash_parts(const char *label, const uint8_t *data, size_t n, uint8_t out[32])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int len = 0;
    int ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, label, strlen(label)) == 1 &&
             EVP_DigestUpdate(ctx, data, n) == 1 &&
             EVP_DigestFinal_ex(ctx, out, &len) == 1 && len == 32;
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int signed_body(EVP_PKEY *key, uint8_t *buf, size_t n)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t len = 64;
    int ok = ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1 &&
             EVP_DigestSign(ctx, buf + n, &len, buf, n) == 1 && len == 64;
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int checked_body(EVP_PKEY *key, const uint8_t *buf, size_t n)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
             EVP_DigestVerify(ctx, buf + n, 64, buf, n) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

static EVP_PKEY *load_key(const char *path, int secret)
{
    uint8_t raw[32];
    EVP_PKEY *key = NULL;
    if (rc_read_exact(path, raw, sizeof(raw))) {
        key = secret ? EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, raw, sizeof(raw))
                     : EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, raw, sizeof(raw));
    }
    OPENSSL_cleanse(raw, sizeof(raw));
    return key;
}

static int start_info(EVP_PKEY *key, const uint8_t *start, struct rc_info *out)
{
    uint32_t side = (uint32_t)get_le(start + 8, 4);
    uint64_t ns = get_le(start + 16, 8);
    const MatrixProfile *profile = matrix_profile_wire(start + 88);
    if (!key || memcmp(start, start_tag, 8) || !matrix_profile_side(profile, side) ||
        get_le(start + 12, 4) || !ns ||
        !checked_body(key, start, RC_START_BYTES - 64)) return 0;
    memset(out, 0, sizeof(*out));
    out->side = side;
    out->profile = profile;
    out->dimensions = profile->dimensions;
    out->signed_unit = profile->signed_unit;
    out->start_ns = ns;
    memcpy(out->entry, start + 24, 32);
    return hash_parts("stencil-attempt-v1", start, RC_START_BYTES, out->attempt) &&
           hash_parts("stencil-instance-seed-v1", start, RC_START_BYTES, out->seed);
}

static int finish_info(EVP_PKEY *key, const uint8_t *finish, struct rc_info *out)
{
    uint64_t ns = get_le(finish + 8, 8);
    if (memcmp(finish, finish_tag, 8) || memcmp(finish + 16, out->attempt, 32) ||
        ns < out->start_ns || !checked_body(key, finish, RC_FINISH_BYTES - 64)) return 0;
    out->finish_ns = ns;
    memcpy(out->digest, finish + 48, 32);
    return 1;
}

int rc_check_start(const char *pub_path, const uint8_t start[RC_START_BYTES], struct rc_info *out)
{
    EVP_PKEY *key = load_key(pub_path, 0);
    int ok = start_info(key, start, out);
    EVP_PKEY_free(key);
    return ok;
}

static int checked_profile(struct rc_info *out)
{
    if (!out->profile)
        out->profile = matrix_profile_kind(out->dimensions, out->signed_unit);
    return matrix_profile_side(out->profile, out->side) &&
           out->profile->dimensions == out->dimensions && out->profile->signed_unit == out->signed_unit;
}

int rc_verify_start(const char *trust, const uint8_t *start, struct rc_info *out)
{
    memset(out, 0, sizeof(*out));
    if (bc_is_start(start)) return bc_check_start(trust, start, out);
    return RC_PROVIDER.check_start(trust, start, out) && checked_profile(out);
}

int rc_verify_pair(const char *trust, const uint8_t *start, const uint8_t *finish,
                   struct rc_info *out)
{
    memset(out, 0, sizeof(*out));
    return RC_PROVIDER.check_pair(trust, start, finish, out) && checked_profile(out);
}

int rc_check_pair(const char *pub_path, const uint8_t start[RC_START_BYTES],
                  const uint8_t finish[RC_FINISH_BYTES], struct rc_info *out)
{
    EVP_PKEY *key = load_key(pub_path, 0);
    int ok = start_info(key, start, out) && finish_info(key, finish, out);
    EVP_PKEY_free(key);
    return ok;
}

const struct rc_provider rc_local_provider = {
    .check_start = rc_check_start,
    .check_pair = rc_check_pair,
};

static int clock_ns(uint64_t *v)
{
    const uint64_t billion = UINT64_C(1000000000);
    struct timespec t;
    if (clock_gettime(CLOCK_REALTIME, &t) < 0 || t.tv_sec < 0 ||
        (uint64_t)t.tv_sec > (UINT64_MAX - (uint64_t)t.tv_nsec) / billion) return 0;
    *v = (uint64_t)t.tv_sec * billion + (uint64_t)t.tv_nsec;
    return *v != 0;
}

static int keygen(const char *sk, const char *pk)
{
    /* A retry can finish publishing the public file after a process interruption. */
    uint8_t priv[32], pub[32], existing[32];
    int ok = RAND_priv_bytes(priv, sizeof(priv)) == 1;
    int fresh = ok ? publish(sk, priv, sizeof(priv), 0600) : 0;
    OPENSSL_cleanse(priv, sizeof(priv));
    if (fresh == 0) return 0;
    EVP_PKEY *key = load_key(sk, 1);
    size_t n = sizeof(pub);
    ok = key && EVP_PKEY_get_raw_public_key(key, pub, &n) == 1 && n == sizeof(pub);
    EVP_PKEY_free(key);
    if (ok) {
        int result = publish(pk, pub, sizeof(pub), 0644);
        ok = result == 1 || (result == -1 && rc_read_exact(pk, existing, sizeof(existing)) &&
                             !memcmp(existing, pub, sizeof(pub)));
    }
    if (!ok) fprintf(stderr, "could not publish matching public key\n");
    return ok;
}

static int entry_hash(const char *entry, uint8_t out[32])
{
    return *entry && hash_parts("stencil-entry-v1", (const uint8_t *)entry, strlen(entry), out);
}

static char *record_path(const char *sk, const char *kind, const uint8_t id[32])
{
    static const char hex[] = "0123456789abcdef";
    size_t len = strlen(sk), kind_len = strlen(kind);
    char *path = malloc(len + kind_len + 65);
    if (!path) return NULL;
    memcpy(path, sk, len);
    memcpy(path + len, kind, kind_len);
    len += kind_len;
    for (size_t i = 0; i < 32; i++) {
        path[len++] = hex[id[i] >> 4];
        path[len++] = hex[id[i] & 15];
    }
    path[len] = '\0';
    return path;
}

static char *start_record_path(const char *sk, const MatrixProfile *profile,
                               uint32_t side, const uint8_t entry[32])
{
    uint8_t spec[MATRIX_ID_BYTES+4+32], id[32];
    memcpy(spec, profile->id, MATRIX_ID_BYTES);
    put_le(spec + MATRIX_ID_BYTES, 4, side);
    memcpy(spec + MATRIX_ID_BYTES + 4, entry, 32);
    if (!hash_parts("stencil-registration-v1", spec, sizeof(spec), id)) return NULL;
    return record_path(sk, ".start.", id);
}

/* Repeated delivery to an existing output is allowed only for the exact bytes
 * already published there. This also recovers a lost delivery to a new path. */
int rc_deliver(const char *path, const uint8_t *data, size_t n)
{
    uint8_t existing[RC_START_BYTES];
    if (n > sizeof(existing)) return 0;
    int result = publish(path, data, n, 0644);
    return result == 1 || (result == -1 && rc_read_exact(path, existing, n) &&
                           !memcmp(existing, data, n));
}

static int issue_start(EVP_PKEY *key, const char *sk, const MatrixProfile *profile,
                       const char *side_s, const char *entry, const char *output)
{
    char *end;
    errno = 0;
    uintmax_t side = strtoumax(side_s, &end, 10);
    uint8_t entry_id[32], start[RC_START_BYTES] = {0};
    struct rc_info info;
    struct stat st;
    if (*side_s < '0' || *side_s > '9' || *end || errno || !matrix_profile_side(profile, side) ||
        !entry_hash(entry, entry_id)) return 0;
    char *record = start_record_path(sk, profile, (uint32_t)side, entry_id);
    if (!record) return 0;
    int ok = 0;
    if (lstat(record, &st) < 0) {
        if (errno != ENOENT) goto done;
        uint64_t ns;
        memcpy(start, start_tag, sizeof(start_tag));
        put_le(start + 8, 4, side);
        memcpy(start + 24, entry_id, 32);
        memcpy(start + 88, profile->id, MATRIX_ID_BYTES);
        if (RAND_bytes(start + 56, 32) != 1 || !clock_ns(&ns)) goto done;
        put_le(start + 16, 8, ns);
        if (!signed_body(key, start, RC_START_BYTES - 64)) goto done;
        /* On EEXIST the racing winner determines the only eligible seed. */
        if (publish(record, start, sizeof(start), 0600) == 0) goto done;
    } else if (!S_ISREG(st.st_mode)) {
        goto done;
    }
    /* The winner may be a prior invocation or a concurrent writer which
     * linked the record but has not yet persisted its directory entry. */
    ok = rc_read_exact(record, start, sizeof(start)) && start_info(key, start, &info) &&
         info.side == side && info.profile == profile &&
         !memcmp(info.entry, entry_id, 32) &&
         sync_parent(record) &&
         rc_deliver(output, start, sizeof(start));
done:
    free(record);
    return ok;
}

static int record_stamp(EVP_PKEY *key, const char *sk, const uint8_t start[RC_START_BYTES],
                        const uint8_t digest[32], const char *entry, uint8_t finish[RC_FINISH_BYTES])
{
    uint8_t expected_entry[32];
    struct rc_info info;
    uint64_t ns;
    if (!start_info(key, start, &info)) return 0;
    if (entry && (!entry_hash(entry, expected_entry) || memcmp(info.entry, expected_entry, 32))) return 0;
    uint8_t enrolled[RC_START_BYTES];
    const MatrixProfile *profile = matrix_profile_wire(start + 88);
    char *registration = start_record_path(sk, profile, info.side, info.entry);
    if (!registration) return 0;
    int registered = rc_read_exact(registration, enrolled, sizeof(enrolled)) &&
                     !memcmp(enrolled, start, sizeof(enrolled));
    free(registration);
    if (!registered || !clock_ns(&ns) || ns < info.start_ns) return 0;
    memcpy(finish, finish_tag, sizeof(finish_tag));
    put_le(finish + 8, 8, ns);
    memcpy(finish + 16, info.attempt, 32);
    memcpy(finish + 48, digest, 32);
    if (RAND_bytes(finish + 80, 16) != 1 || !signed_body(key, finish, RC_FINISH_BYTES - 64)) return 0;
    char *record = record_path(sk, ".stamp.", info.attempt);
    if (!record) return 0;
    int result = publish(record, finish, RC_FINISH_BYTES, 0600);
    int ok = result == 1;
    if (result == -1) {
        ok = rc_read_exact(record, finish, RC_FINISH_BYTES) && finish_info(key, finish, &info) &&
             !memcmp(digest, info.digest, 32);
        if (!ok) fprintf(stderr, "conflicting or invalid first commitment for this attempt\n");
    }
    free(record);
    return ok;
}

static int stamp_file(EVP_PKEY *key, char **argv)
{
    uint8_t start[RC_START_BYTES], digest[32], finish[RC_FINISH_BYTES];
    if (!rc_read_exact(argv[2], start, sizeof(start)) || !rc_read_exact(argv[3], digest, sizeof(digest)) ||
        !record_stamp(key, argv[1], start, digest, NULL, finish)) return 0;
    return rc_deliver(argv[4], finish, sizeof(finish));
}

static int stamp_stdio(EVP_PKEY *key, const char *sk, const char *entry)
{
    uint8_t request[RC_START_BYTES + RC_DIGEST_BYTES], finish[RC_FINISH_BYTES];
    return read_exact(stdin, request, sizeof(request)) &&
           record_stamp(key, sk, request, request + RC_START_BYTES, entry, finish) &&
           write_all(STDOUT_FILENO, finish, sizeof(finish));
}

int receipt_main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[0], "keygen")) return keygen(argv[1], argv[2]) ? 0 : 1;
    const MatrixProfile *profile = matrix_profile_command(argv[0], 1);
    if ((argc == 3 && !strcmp(argv[0], "stamp-stdio")) ||
        (argc == 5 && (profile || !strcmp(argv[0], "stamp")))) {
        EVP_PKEY *key = load_key(argv[1], 1);
        int ok = 0;
        if (key) {
            if (profile) ok = issue_start(key, argv[1], profile, argv[2], argv[3], argv[4]);
            else if (!strcmp(argv[0], "stamp")) ok = stamp_file(key, argv);
            else ok = stamp_stdio(key, argv[1], argv[2]);
        }
        EVP_PKEY_free(key);
        if (!ok) fprintf(stderr, "%s failed\n", argv[0]);
        return ok ? 0 : 1;
    }
    fprintf(stderr, "commands:\n  keygen SECRET PUBLIC\n  start SECRET N ENTRY START\n"
                    "  stamp SECRET START DIGEST_FILE FINISH\n"
                    "  stamp-stdio SECRET AUTHENTICATED_ENTRY < request > finish\n");
    return 2;
}
