#ifndef STENCIL_BEACON_H
#define STENCIL_BEACON_H

#include "receipt.h"
#include "rfc3161.h"

/* The start is the preregistered 144-byte manifest and a 48-byte Quicknet signature. */
enum { BC_REG_BYTES = 144, BC_SIG_BYTES = 48 };
int bc_is_start(const uint8_t start[RC_START_BYTES]);
int bc_check_start(const char *registration, const uint8_t start[RC_START_BYTES],
                   struct rc_info *info);
int bc_check_evidence(const char *registration, const char *ca, const char *policy,
                      const uint8_t start[RC_START_BYTES], const uint8_t digest[32],
                      const uint8_t finish_sig[BC_SIG_BYTES], const uint8_t *der,
                      size_t der_len, struct rc_info *info, uint64_t *uncertainty_ns);
int bc_main(int argc, char **argv);
#endif
