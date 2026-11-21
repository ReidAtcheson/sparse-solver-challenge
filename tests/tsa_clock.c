/* Test-only RFC 3161 signer with a fixture clock. This lets an offline test
 * stamp a newly generated commitment between two archived drand rounds. */
#include <errno.h>
#include <openssl/err.h>
#include <openssl/ts.h>
#include <stdlib.h>

static int test_time(TS_RESP_CTX *ctx, void *data, long *sec, long *usec)
{
    (void)ctx;
    *sec = *(long *)data;
    *usec = 0;
    return 1;
}

int main(int argc, char **argv)
{
    if (argc != 4) return 2; /* QUERY.tsq UNIX_SECONDS RESPONSE.tsr */
    char *end;
    errno = 0;
    long seconds = strtol(argv[2], &end, 10);
    if (errno || *end || seconds <= 0) return 2;
    CONF *conf = NCONF_new(NULL);
    TS_RESP_CTX *ctx = TS_RESP_CTX_new();
    TS_RESP *response = NULL;
    BIO *in = BIO_new_file(argv[1], "rb"), *out = NULL;
    int ok = 0;
    if (!ctx || !in || !conf || !NCONF_load(conf, "tsa.cnf", NULL) ||
        !TS_CONF_set_signer_cert(conf, "local", NULL, ctx) ||
        !TS_CONF_set_signer_key(conf, "local", NULL, NULL, ctx) ||
        !TS_CONF_set_signer_digest(conf, "local", NULL, ctx) ||
        !TS_CONF_set_def_policy(conf, "local", NULL, ctx) ||
        !TS_CONF_set_digests(conf, "local", ctx) ||
        !TS_CONF_set_accuracy(conf, "local", ctx) ||
        !TS_CONF_set_ess_cert_id_digest(conf, "local", ctx)) goto done;
    TS_RESP_CTX_set_time_cb(ctx, test_time, &seconds);
    response = TS_RESP_create_response(ctx, in);
    if (!response || !TS_RESP_get_token(response)) goto done;
    out = BIO_new_file(argv[3], "wb");
    ok = out && i2d_TS_RESP_bio(out, response) && BIO_flush(out) == 1;
done:
    if (!ok) ERR_print_errors_fp(stderr);
    BIO_free(in);
    BIO_free(out);
    TS_RESP_free(response);
    TS_RESP_CTX_free(ctx);
    NCONF_free(conf);
    return ok ? 0 : 1;
}
