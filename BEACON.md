# A timed attempt with drand quicknet and RFC 3161

A judge publishes a registration for each entrant before a common start round. When that round arrives, everyone in the same profile and grid size gets the same seeded system. Each entrant solves the system, computes its row commitments, obtains an RFC 3161 timestamp and registers its digest. A second fixed drand round supplies unpredictable bits for the proof. The entrant can do the expensive proving work after that round. The score uses the timestamp on the commitment.

## Build and run

The optional Quicknet backend uses blst. The reference was tested with v0.3.16, commit `e7f90de551e8df682f3cc99067d204d8b90d27ad`. Build blst in its own directory using its provided `./build.sh`, then pass its absolute directory to make. The ordinary build supports the local Ed25519 provider and standalone RFC 3161 requests and verification. It rejects Quicknet signatures when the BLS backend is unavailable. [blst release](https://github.com/supranational/blst/releases/tag/v0.3.16)

```sh
make BLST_DIR=/absolute/path/to/blst
make BLST_DIR=/absolute/path/to/blst check
```

Before the start, the judge fixes the profile, size, entrant label, a 32-byte registration nonce, two future round numbers, an allowed TSA trust bundle and numerical policy OID. It also sets a nonzero clock error allowance in nanoseconds based on that TSA's accuracy policy and the registrar's clock. The proof round acts as the deadline for recording a commitment. Choose it far enough after the start to allow the solve, commitment, timestamp and delivery to the registrar.

```sh
# Judge. Publish the exact registration and trust settings before START_ROUND.
openssl rand -out nonce32 32
./stencil beacon-register 3d 32 team-a nonce32 "$START_ROUND" "$PROOF_ROUND" "$ERROR_NS" reg
```

Fetch a signature when its round is available. The relay supplies transport. The C verifier checks the signature against the compiled Quicknet public key and the independently registered round. Quicknet round times are scheduled UTC release times. Actual network delivery may be later. [Quicknet parameters](https://docs.drand.love/blog/2023/10/16/quicknet-is-live/) · [drand specification](https://docs.drand.love/docs/specification/)

```sh
chain=52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971
round_signature() {
    curl -fsS "https://api.drand.sh/$chain/public/$1" |
        python3 -c 'import sys,json; sys.stdout.buffer.write(bytes.fromhex(json.load(sys.stdin)["signature"]))'
}

round_signature "$START_ROUND" > start.sig
./stencil beacon-start reg start.sig start
./stencil solve reg start x.f64
./stencil commit reg start x.f64 rows digest

# Entrant. Use the TSA URL and numeric policy selected by the judge.
./stencil beacon-query reg start digest request.tsq "$POLICY_OID"
curl -fsS -H 'Content-Type: application/timestamp-query' \
     -H 'Accept: application/timestamp-reply' --data-binary @request.tsq "$TSA_URL" -o stamp.tsr
```

The registrar receives the digest and response through an authenticated entrant channel. It selects the matching registration and the ledger directory from its own configuration. Run the following on the registrar while the submission window is open. The command prints the path to the winning 32-byte digest, keyed by attempt. The registrar durably fixes a single candidate in an internal `.claim-*` file, checks the cutoff again, then publishes the accepted record. Only the final filename printed by the command is eligible. An identical retry can recover an accepted record after the deadline. Competing digests fail, including during concurrent submissions. Publish the accepted record over the judge's authenticated channel for validators. Protect the ledger from entrant writes.

```sh
mkdir -p ledger
./stencil beacon-record reg tsa-ca.pem "$POLICY_OID" start digest stamp.tsr ledger
```

Once the proof round is public, the entrant produces the transcript. The validator receives that transcript from the entrant. Its registration, TSA trust settings and winning digest come independently from the judge. It can verify offline.

```sh
round_signature "$PROOF_ROUND" > proof-round.sig
./stencil prove-beacon reg tsa-ca.pem "$POLICY_OID" start digest stamp.tsr proof-round.sig x.f64 rows proof
./stencil verify-beacon reg tsa-ca.pem "$POLICY_OID" "$WINNING_DIGEST_FILE" proof
```

The verifier reports the scheduled start, TSA `genTime`, clock uncertainty, elapsed nanoseconds and numerical result. A score certifies existence of the commitment by the TSA time within its uncertainty. It includes time to solve, commit and reach the TSA. Proof assembly, waiting for the second round and submission of the final transcript can occur afterward. [RFC 3161, section 2.4.2](https://www.rfc-editor.org/rfc/rfc3161.html#section-2.4.2)

## Wire format and trust inputs

All integers below are little-endian. Hash labels are ASCII without a trailing NUL. The 144-byte registration is laid out as follows. Verifiers require an exact match to the independently published registration.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 8 | ASCII `STNREG01`, specifying the pinned Quicknet chain and version |
| 8 | 40 | Registered matrix profile ID, padded with zeros |
| 48 | 4 | Grid side |
| 52 | 4 | Zero |
| 56 | 8 | Start round |
| 64 | 8 | Proof round |
| 72 | 8 | Clock error allowance in nanoseconds |
| 80 | 32 | SHA256("stencil-entry-v1" ∥ exact entrant label bytes) |
| 112 | 32 | Registration nonce |

The start is `registration || start_round_signature[48]`. Verify both round signatures as specified by Quicknet. Its BLS message is SHA-256 of the eight-byte **big-endian** round number. The chain uses the unchained G1 RFC 9380 scheme. Hashing its unique compressed signature with SHA-256 yields the round randomness. [Pinned parameters and verifier](drand.c)

```text
attempt = SHA256("stencil-quicknet-attempt-v1" || start)
seed = SHA256("stencil-quicknet-instance-v1" || chain_hash[32]
              || registration[8:52] || registration[56:64] || start_randomness[32])
tsa_imprint = SHA256("stencil-quicknet-commit-time-v1" || start || row_commitment_digest[32])
```

A TSA response must carry a signed SHA-256 imprint for those exact bytes and the selected policy OID. Trust a dedicated CA bundle independently. The verifier checks the certificate chain at verification time and at the signed generation time, the timestamping purpose and the token signature. Its offline policy does not retrieve revocation evidence. Replaying after certificate expiry and long-term archival validation require a different certificate validation policy and preserved validation evidence. [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html) · [OpenSSL timestamp verification](https://docs.openssl.org/3.0/man1/openssl-ts/)

Let `u` be the greater of the registered clock allowance and the token's signed accuracy when supplied. The entire interval must satisfy `start_time <= genTime - u` and `genTime + u < proof_round_time`. The registrar also checks its own reception against the proof-round cutoff with the configured clock allowance. A registration file identifies a challenge. Evidence that it was frozen before release, the entrant's identity, and the first-wins digest record depend on the judge and its publication channel. A verifier accepting arbitrary entrant-supplied registration and digest files would lose those guarantees.

The external proof has this prefix, followed immediately by the existing algebraic proof body for the registered generator.

```text
"STNPRF03" || start[192] || row_commitment_digest[32] || proof_round_signature[48]
           || LE32(response_bytes) || complete_DER_TimeStampResp[response_bytes]
```

The response length must be in `[1,1048576]`. Initialize the Fiat–Shamir SHA-512 state with `"stencil-proof-transcript-quicknet-v1"` and absorb the first 280 bytes through the second signature. Derive the mask challenge at this point. Resume absorption with the first byte of the algebraic body, using the existing round roles and indexes. The verifier authenticates the timestamp response separately. The same registered digest has the same masks and subsequent challenges under alternate valid TSA serial numbers, certificates or response wrappers. Compared with the same algebra under local receipts, the wire size changes by exactly `response_bytes - 76` bytes. [Algebra and reference vector](INTEROP.md)

The security argument assumes the signatures are unpredictable before their scheduled release, the TSA clock and registrar enforce the time window, and the registrar admits one digest per attempt. All entrants on a round share its beacon output. The existing local-issuer extraction analysis uses simulated fresh receipts on rewind. A concrete security reduction for the shared external beacon and a deployment review remain open. [Existing soundness analysis](SOUNDNESS.md)

## Offline reference check

`make BLST_DIR=/absolute/path/to/blst check-beacon` exercises both the diffusion and signed-unit 3D profiles with archived, genuine Quicknet signatures and a locally issued RFC 3161 test response. In one signed 32³ run the transcript occupied 17,552 bytes, including a 912-byte response, and certified a joint backward error of `1.7897962026112965e-17`. The 262,144-byte solution stayed with the prover. DER length varies with the test certificates and signatures. These historical fixtures test verification and interoperability. Live service latency is a separate measurement. [End-to-end tests](tests/check_beacon.py)
