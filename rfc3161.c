#include "rfc3161.h"
#include "receipt.h"

#include <inttypes.h>
#include <openssl/ts.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static TS_REQ *sha256_request(const uint8_t digest[32], const ASN1_OBJECT *policy)
{
    TS_REQ *req = TS_REQ_new();
    if (!req) return NULL;
    TS_MSG_IMPRINT *imprint = TS_REQ_get_msg_imprint(req);
    if (imprint && TS_REQ_set_version(req, 1) &&
        X509_ALGOR_set0(TS_MSG_IMPRINT_get_algo(imprint), OBJ_nid2obj(NID_sha256),
                        V_ASN1_NULL, NULL) &&
        ASN1_OCTET_STRING_set(TS_MSG_IMPRINT_get_msg(imprint), digest, 32) &&
        TS_REQ_set_cert_req(req, 1) && (!policy || TS_REQ_set_policy_id(req, policy)))
        return req;
    TS_REQ_free(req);
    return NULL;
}

static int encode_query(const uint8_t digest[32], const ASN1_OBJECT *policy,
                        uint8_t *der, size_t capacity, size_t *der_size)
{
    if (!digest || !der_size) return 0;
    TS_REQ *req = sha256_request(digest, policy);
    if (!req) return 0;
    int len = i2d_TS_REQ(req, NULL);
    int ok = len > 0;
    if (ok) {
        *der_size = (size_t)len;
        if (der) ok = capacity >= *der_size && i2d_TS_REQ(req, &der) == len;
    }
    TS_REQ_free(req);
    return ok;
}

int rc_tsa_query(const uint8_t digest[32], uint8_t *der, size_t capacity,
                 size_t *der_size)
{
    return encode_query(digest, NULL, der, capacity, der_size);
}

int rc_tsa_query_policy(const uint8_t digest[32], const char *policy_oid,
                        uint8_t *der, size_t capacity, size_t *der_size)
{
    ASN1_OBJECT *policy = policy_oid ? OBJ_txt2obj(policy_oid, 1) : NULL;
    int ok = policy && encode_query(digest, policy, der, capacity, der_size);
    ASN1_OBJECT_free(policy);
    return ok;
}

/* GeneralizedTime in RFC 3161 is UTC, with mandatory seconds and an
 * optional decimal fraction. Reject times outside the API's exact range. */
static int timestamp_ns(const ASN1_GENERALIZEDTIME *value, uint64_t *out)
{
    if (!value) return 0;
    int len = ASN1_STRING_length(value);
    const unsigned char *s = ASN1_STRING_get0_data(value);
    if (len < 15 || len > 25 || s[len - 1] != 'Z') return 0;
    for (int i = 0; i < 14; ++i)
        if (s[i] < '0' || s[i] > '9') return 0;
    uint64_t fraction = 0;
    if (len != 15) {
        if (len < 17 || s[14] != '.' || s[len - 2] == '0') return 0;
        uint64_t place = 100000000;
        for (int i = 15; i < len - 1; ++i, place /= 10) {
            if (s[i] < '0' || s[i] > '9') return 0;
            fraction += (s[i] - '0') * place;
        }
    }
    ASN1_TIME *epoch = ASN1_TIME_set(NULL, 0);
    int days = 0, seconds = 0;
    int ok = epoch && ASN1_TIME_diff(&days, &seconds, epoch, value);
    ASN1_TIME_free(epoch);
    if (!ok || days < 0 || seconds < 0) return 0;
    uint64_t total = (uint64_t)days * 86400 + (unsigned)seconds;
    if (total > (UINT64_MAX - fraction) / 1000000000) return 0;
    *out = total * 1000000000 + fraction;
    return 1;
}

static int subsecond_part(const ASN1_INTEGER *part, uint64_t *v)
{
    *v = 0;
    return !part || (ASN1_INTEGER_get_uint64(v, part) && *v >= 1 && *v <= 999);
}

static int accuracy_ns(const TS_ACCURACY *accuracy, uint64_t *out)
{
    const ASN1_INTEGER *seconds = TS_ACCURACY_get_seconds(accuracy);
    uint64_t secs = 0, millis, micros;
    if ((seconds && !ASN1_INTEGER_get_uint64(&secs, seconds)) ||
        !subsecond_part(TS_ACCURACY_get_millis(accuracy), &millis) ||
        !subsecond_part(TS_ACCURACY_get_micros(accuracy), &micros)) return 0;
    uint64_t fraction = 1000000 * millis + 1000 * micros;
    if (secs > (UINT64_MAX - fraction) / 1000000000) return 0;
    *out = secs * 1000000000 + fraction;
    return 1;
}

static int verify_response(const char *ca_pem, const ASN1_OBJECT *policy,
                           const uint8_t digest[32], const uint8_t *der,
                           size_t der_size, struct rc_tsa_time *out)
{
    if (!ca_pem || !digest || !der || !out || !der_size ||
        der_size > RC_TSA_MAX_RESPONSE) return 0;
    const unsigned char *next = der;
    TS_RESP *resp = d2i_TS_RESP(NULL, &next, (long)der_size);
    TS_REQ *req = NULL;
    TS_VERIFY_CTX *ctx = NULL;
    X509_STORE *store = NULL;
    int ok = 0;
    if (!resp || next != der + der_size) goto done;
    req = sha256_request(digest, policy);
    if (!req || !(ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL))) goto done;
    store = X509_STORE_new();
    if (!store || X509_STORE_load_locations(store, ca_pem, NULL) != 1) goto done;
    X509_VERIFY_PARAM *chain_params = X509_STORE_get0_param(store);
    if (!chain_params) goto done;
    TS_VERIFY_CTX_set_store(ctx, store); /* ctx takes ownership */
    store = NULL;
    /* OpenSSL explicitly omits the signature flag when deriving the verify
     * context from a request. The added check verifies the TSA signing EKU,
     * chain and CMS signature. OpenSSL also checks status, version, algorithm,
     * imprint bytes, and any included TSA name. */
    TS_VERIFY_CTX_add_flags(ctx, TS_VFY_SIGNATURE);
    if (TS_RESP_verify_response(ctx, resp) != 1) goto done;
    TS_TST_INFO *info = TS_RESP_get_tst_info(resp);
    struct rc_tsa_time result = {0};
    if (!info || TS_TST_INFO_get_ext_by_critical(info, 1, -1) >= 0 ||
        !timestamp_ns(TS_TST_INFO_get_time(info), &result.unix_ns)) goto done;
    /* The chain must also have been valid when the TSA claims it signed. */
    uint64_t whole_seconds = result.unix_ns / 1000000000;
    time_t signing_time = (time_t)whole_seconds;
    if (signing_time < 0 || (uint64_t)signing_time != whole_seconds) goto done;
    X509_VERIFY_PARAM_set_time(chain_params, signing_time);
    if (TS_RESP_verify_response(ctx, resp) != 1) goto done;
    TS_ACCURACY *accuracy = TS_TST_INFO_get_accuracy(info);
    if (accuracy) {
        if (!accuracy_ns(accuracy, &result.accuracy_ns)) goto done;
        result.has_accuracy = 1;
    }
    *out = result;
    ok = 1;
done:
    X509_STORE_free(store);
    TS_VERIFY_CTX_free(ctx);
    TS_REQ_free(req);
    TS_RESP_free(resp);
    return ok;
}

int rc_tsa_verify(const char *ca_pem, const uint8_t digest[32],
                  const uint8_t *der, size_t der_size, struct rc_tsa_time *out)
{
    return verify_response(ca_pem, NULL, digest, der, der_size, out);
}

int rc_tsa_verify_policy(const char *ca_pem, const char *policy_oid,
                         const uint8_t digest[32], const uint8_t *der,
                         size_t der_size, struct rc_tsa_time *out)
{
    ASN1_OBJECT *policy = policy_oid ? OBJ_txt2obj(policy_oid, 1) : NULL;
    int ok = policy && verify_response(ca_pem, policy, digest, der, der_size, out);
    ASN1_OBJECT_free(policy);
    return ok;
}

uint8_t *rc_tsa_read_response(const char *path, size_t *size)
{
    if (!path || !size) return NULL;
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    long length = fseek(f, 0, SEEK_END) == 0 ? ftell(f) : -1;
    uint8_t *data = NULL;
    if (length > 0 && length <= RC_TSA_MAX_RESPONSE && fseek(f, 0, SEEK_SET) == 0) {
        size_t n = (size_t)length;
        data = malloc(n);
        if (data && (fread(data, 1, n, f) != n || fgetc(f) != EOF || ferror(f))) {
            free(data);
            data = NULL;
        }
        if (data) *size = n;
    }
    fclose(f);
    return data;
}

int rc_tsa_main(int argc, char **argv)
{
    uint8_t digest[32];
    if ((argc == 3 || argc == 4) && strcmp(argv[0], "tsa-query") == 0) {
        uint8_t req[RC_START_BYTES];
        size_t n;
        int ok = rc_read_exact(argv[1], digest, sizeof(digest));
        if (ok && argc == 4) ok = rc_tsa_query_policy(digest, argv[3], req, sizeof(req), &n);
        else if (ok) ok = rc_tsa_query(digest, req, sizeof(req), &n);
        if (!ok) {
            fputs("failed to encode SHA-256 timestamp query\n", stderr);
            return 1;
        }
        ok = rc_deliver(argv[2], req, n);
        if (!ok) fputs("failed to publish timestamp query\n", stderr);
        return ok ? 0 : 1;
    }
    if ((argc == 4 || argc == 5) && strcmp(argv[0], "tsa-verify") == 0) {
        struct rc_tsa_time result;
        size_t n;
        uint8_t *der = rc_tsa_read_response(argv[3], &n);
        int ok = der && rc_read_exact(argv[2], digest, sizeof(digest));
        if (ok && argc == 5) ok = rc_tsa_verify_policy(argv[1], argv[4], digest, der, n, &result);
        else if (ok) ok = rc_tsa_verify(argv[1], digest, der, n, &result);
        free(der);
        if (!ok) {
            fputs("invalid RFC 3161 response, digest, or TSA trust\n", stderr);
            return 1;
        }
        printf("unix_ns=%" PRIu64, result.unix_ns);
        if (result.has_accuracy) printf(" accuracy_ns=%" PRIu64 "\n", result.accuracy_ns);
        else puts(" accuracy_ns=unknown");
        return 0;
    }
    fputs("  tsa-query DIGEST_FILE REQUEST.tsq [POLICY_OID]\n"
          "  tsa-verify CA.pem DIGEST_FILE RESPONSE.tsr [POLICY_OID]\n", stderr);
    return 2;
}
