#ifndef STENCIL_DRAND_H
#define STENCIL_DRAND_H

#include <stdint.h>

/* League of Entropy mainnet "quicknet", bls-unchained-g1-rfc9380. */
#define DRAND_QUICKNET_SIGNATURE_BYTES 48
extern const uint8_t drand_quicknet_chain_hash[32];

/* Return 1 on success. scheduled_ns is the nominal round release time in
 * Unix nanoseconds. Round zero is reserved. */
int drand_quicknet_time(uint64_t round, uint64_t *scheduled_ns);
int drand_quicknet_available(void);

/* Verify the canonical compressed BLS signature under the pinned public key.
 * The caller supplies the independently expected round. Both outputs are
 * written on success only. No remote endpoint or relay metadata is trusted. */
int drand_quicknet_verify(uint64_t expected_round,
                         const uint8_t signature[DRAND_QUICKNET_SIGNATURE_BYTES],
                         uint8_t randomness[32], uint64_t *scheduled_ns);

#endif
