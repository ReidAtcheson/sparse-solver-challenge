#include "../drand.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Published JSON fixtures from https://api.drand.sh/<quicknet-chain-hash>/public/<round>.
 * These tests are offline. Round 34000000 exercises multi-byte round encoding. */
static const struct {
    uint64_t round, scheduled_ns;
    const char *signature, *randomness;
} vectors[] = {
    {1, UINT64_C(1692803367000000000),
     "b55e7cb2d5c613ee0b2e28d6750aabbb78c39dcc96bd9d38"
     "c2c2e12198df95571de8e8e402a0cc48871c7089a2b3af4b",
     "1466a6cd24e327188770752f6134001c64d6efcc590ccc26b721611ad96f165a"},
    {34000000, UINT64_C(1794803364000000000),
     "b4fec76939fa077a38b30d35cc5cc2426f9bfef2e9363b89"
     "787d2466a29ab01be346b95e771c727676e54368ef662dbb",
     "25286e095fc8f1d411bc86f8515babdb571f85629592dff9a38160e77358d8b0"}
};

static void decode(uint8_t *out, size_t len, const char *hex)
{
    assert(strlen(hex) == 2 * len);
    for (size_t i = 0; i < len; ++i) {
        unsigned x;
        assert(sscanf(hex + 2 * i, "%2x", &x) == 1);
        out[i] = (uint8_t)x;
    }
}

int main(void)
{
    uint8_t sig[48], expected[32], randomness[32];
    uint64_t ns;
#if defined(STENCIL_HAVE_BLST) && STENCIL_HAVE_BLST
    assert(drand_quicknet_available());
#else
    assert(!drand_quicknet_available());
#endif
    assert(!drand_quicknet_time(0, &ns));
    assert(!drand_quicknet_time(UINT64_MAX, &ns));
    assert(!drand_quicknet_time(1, NULL));
    for (size_t i = 0; i < sizeof vectors / sizeof vectors[0]; ++i) {
        uint64_t round = vectors[i].round;
        decode(sig, sizeof sig, vectors[i].signature);
        decode(expected, sizeof expected, vectors[i].randomness);
        assert(drand_quicknet_time(round, &ns) && ns == vectors[i].scheduled_ns);
        if (drand_quicknet_available()) {
            assert(drand_quicknet_verify(round, sig, randomness, &ns));
            assert(ns == vectors[i].scheduled_ns);
            assert(!memcmp(expected, randomness, sizeof randomness));
        } else {
            assert(!drand_quicknet_verify(round, sig, randomness, &ns));
        }
        memset(randomness, 0xa5, sizeof randomness);
        memset(expected, 0xa5, sizeof expected);
        ns = 37;
        assert(!drand_quicknet_verify(round + 1, sig, randomness, &ns));
        sig[4] ^= 1;
        assert(!drand_quicknet_verify(round, sig, randomness, &ns));
        memset(sig, 0, sizeof sig);
        assert(!drand_quicknet_verify(round, sig, randomness, &ns));
        sig[0] = 0xc0; /* canonical point at infinity */
        assert(!drand_quicknet_verify(round, sig, randomness, &ns));
        assert(ns == 37 && !memcmp(randomness, expected, sizeof expected));
    }
    puts(drand_quicknet_available() ? "drand quicknet vectors passed" :
                                     "drand disabled-backend checks passed");
    return 0;
}
