#ifndef STENCIL_RFC3161_H
#define STENCIL_RFC3161_H

#include <stddef.h>
#include <stdint.h>

struct rc_tsa_time {
    uint64_t unix_ns;       /* UTC genTime on the Unix time scale */
    uint64_t accuracy_ns;   /* signed +/- uncertainty, if present */
    int has_accuracy;
};

/* Encode a DER TimeStampReq for an already-computed SHA-256 imprint.
 * Set der to NULL for a sizing call. On a short buffer, return 0 and
 * report the required size. The request asks for the signing certificate.
 * Its imprint should already bind the attempt. RFC 3161 nonces are
 * optional. This API authenticates existence of the imprint by genTime. */
int rc_tsa_query(const uint8_t digest[32], uint8_t *der, size_t capacity,
                 size_t *der_size);
/* Also request a specific numeric TSA policy OID. */
int rc_tsa_query_policy(const uint8_t digest[32], const char *policy_oid,
                        uint8_t *der, size_t capacity, size_t *der_size);

/* Check a complete DER TimeStampResp against the supplied PEM trust bundle
 * (chain verification at genTime and the current time). Return 1 and fill out only on
 * success. Accept any policy of a TSA chaining to those trust anchors.
 * The token should carry the certificates needed to build that chain.
 * CRL, OCSP and long-term archival validation are outside this verifier.
 * A missing accuracy means unknown uncertainty.
 * Wire references: RFC 3161 sections 2.4.1 and 2.4.2, RFC 5816. */
#define RC_TSA_MAX_RESPONSE (1024u * 1024u)
int rc_tsa_verify(const char *ca_pem, const uint8_t digest[32],
                  const uint8_t *der, size_t der_size, struct rc_tsa_time *out);

/* Also require the exact signed TSTInfo policy OID. policy_oid is a numeric
 * dotted OID selected by the relying party (e.g. "1.2.3.4.5"). */
int rc_tsa_verify_policy(const char *ca_pem, const char *policy_oid,
                         const uint8_t digest[32], const uint8_t *der,
                         size_t der_size, struct rc_tsa_time *out);

/* Load one bounded evidence file. The caller owns the result and frees it
 * with free(). On failure return NULL and leave size unchanged. */
uint8_t *rc_tsa_read_response(const char *path, size_t *size);

/* argv[0] is tsa-query or tsa-verify. Digest files contain 32 raw bytes. */
int rc_tsa_main(int argc, char **argv);

#endif
