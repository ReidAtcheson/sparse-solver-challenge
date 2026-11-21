#ifndef STENCIL_RECEIPT_H
#define STENCIL_RECEIPT_H

#include <stddef.h>
#include <stdint.h>

#define RC_START_BYTES 192
#define RC_FINISH_BYTES 160
#define RC_DIGEST_BYTES 32

struct rc_info {
    uint32_t side;
    unsigned dimensions;
    int signed_unit;
    uint64_t start_ns;
    uint64_t finish_ns;
    uint8_t seed[32];
    uint8_t attempt[32];
    uint8_t entry[32];
    uint8_t digest[RC_DIGEST_BYTES];
    /* Exact authenticated generator. Pre-v3 custom providers may omit it
     * to replay their historical dimension/encoding mapping. Bounded three-band
     * providers must set this pointer to the authenticated v2 profile. */
    const struct matrix_profile *profile;
};

/* Fixed-size receipt providers for STNPRF01/02 authenticate the profile,
 * entrant, attempt, seed and committed digest. The finish carries fresh
 * entropy sampled after the digest is fixed. The default uses a pinned
 * Ed25519 key. STNPRF03 uses the independent evidence checks in beacon.h. */
struct rc_provider {
    int (*check_start)(const char *trust, const uint8_t *start, struct rc_info *out);
    int (*check_pair)(const char *trust, const uint8_t *start, const uint8_t *finish,
                      struct rc_info *out);
};

extern const struct rc_provider rc_local_provider;
/* The provider may be replaced at build time by defining RC_PROVIDER to the
 * name of a linked provider object. The fixed receipt sizes still apply. */
#ifndef RC_PROVIDER
#define RC_PROVIDER rc_local_provider
#endif
extern const struct rc_provider RC_PROVIDER;

/* The local authority uses a pinned 32-byte raw Ed25519 key. */
int rc_read_exact(const char *path, void *buf, size_t len);
/* Atomic no-replace publication of up to RC_START_BYTES. Identical retries succeed. */
int rc_deliver(const char *path, const uint8_t *data, size_t n);
int rc_check_start(const char *pub_path, const uint8_t start[RC_START_BYTES],
                   struct rc_info *out);
int rc_check_pair(const char *pub_path, const uint8_t start[RC_START_BYTES],
                  const uint8_t finish[RC_FINISH_BYTES], struct rc_info *out);

/* The start tag chooses the expected trust-file type: either a pinned local
 * authority key or a byte-for-byte pinned Quicknet registration. */
int rc_verify_start(const char *trust, const uint8_t *start, struct rc_info *out);

int rc_verify_pair(const char *trust, const uint8_t *start, const uint8_t *finish,
                   struct rc_info *out);

/* start registers the bounded three-band challenge. Legacy issuance is a
 * fixture-only command dispatched by the CLI. The stdio endpoint reads
 * exactly START || digest, checks the authority-supplied authenticated entrant
 * label, and writes the recorded FINISH receipt. Returns a process exit code. */
int receipt_main(int argc, char **argv);

#endif
