# Public timestamp authorities

The repository includes presets for **FreeTSA** and **Sigstore Public Good**. Both accept a DER RFC 3161 request over HTTPS and return a signed response. Only the SHA-256 message imprint and the request parameters go to the service. Verification uses the chosen authority's pinned public root and timestamp policy and can run offline. The helper requires Bash, OpenSSL and GNU coreutils on Linux. Issuance also uses curl. [Helper](examples/public-tsa)

## Verify a real stamp in a fresh checkout

Both authorities stamped the three public bytes `abc` (no newline) on November 21, 2026. These commands check the two original, unmodified responses. They make no network requests.

```sh
make
work=$(mktemp -d)
printf abc | openssl dgst -sha256 -binary > "$work/abc.sha256"
./examples/public-tsa freetsa verify "$work/abc.sha256" examples/tsa/freetsa-abc.tsr
./examples/public-tsa sigstore verify "$work/abc.sha256" examples/tsa/sigstore-abc.tsr
```

| Provider | Signed UTC | Output from the C validator |
|---|---|---|
| FreeTSA | 2026-11-21 17:58:40 | `unix_ns=1795283920000000000 accuracy_ns=unknown` |
| Sigstore | 2026-11-21 17:58:41 | `unix_ns=1795283921000000000 accuracy_ns=1000000000` |

A successful check exits 0. A changed digest, damaged signature, untrusted signer or unexpected policy fails. The reported accuracy is specific to each signed response. FreeTSA omitted accuracy on this example. Sigstore signed an accuracy of ±1 second. [FreeTSA sample](examples/tsa/freetsa-abc.tsr) · [Sigstore sample](examples/tsa/sigstore-abc.tsr)

## Timestamp and verify a benchmark commitment

Agree on the authority, exact trust root, policy OID and clock allowance **before the start round**. The external match workflow produces `reg`, `start` and a 32-byte row commitment `digest`. For that workflow build with blst. [Challenge setup and build](BEACON.md#build-and-run)

```sh
# From the repo root, with the challenge files in the current directory.
provider=sigstore                     # or freetsa
ca=$(./examples/public-tsa "$provider" root)
policy=$(./examples/public-tsa "$provider" policy)

# Entrant. One HTTP request. The helper verifies the received stamp before saving it.
./examples/public-tsa "$provider" stamp-commit reg start digest stamp.tsr

# Another machine can check this file before the proof round, entirely offline.
./examples/public-tsa "$provider" verify-commit reg start digest stamp.tsr
# The equivalent C validator command:
./stencil beacon-verify-stamp reg "$ca" "$policy" start digest stamp.tsr
```

`verify-commit` authenticates the registered start, reconstructs the imprint from **that start and that commitment digest**, verifies the TSA signature, chain and policy, and checks the timestamp and uncertainty against both registered round times. It prints the scheduled start, signed commitment time and effective clock uncertainty. It does not need the solution or the future round signature.

For a match with a first-submission rule, the organizer must also run `beacon-record` before the deadline. That operation durably records the first eligible digest. Use the same CA and policy with `prove-beacon` and `verify-beacon`. A stamp on a bare digest can establish when that digest existed; the benchmark requires its attempt-bound imprint. [Registrar, proving and replay](BEACON.md)

### Replay a full Quicknet and Sigstore attempt

The repository includes a signed 32³ practice run with a real Sigstore timestamp and Quicknet rounds **34,160,276** and **34,160,289**. The registrar for this demonstration ran locally. The checked-in registration and digest supply the public inputs for replay. Build with blst, then check the standalone stamp and the proof separately.

```sh
demo=examples/tsa/quicknet-sigstore
ca=$(./examples/public-tsa sigstore root)
policy=$(./examples/public-tsa sigstore policy)
./examples/public-tsa sigstore verify-commit "$demo/registration" "$demo/start" \
    "$demo/winner.digest" "$demo/stamp.tsr"
./stencil verify-beacon "$demo/registration" "$ca" "$policy" \
    "$demo/winner.digest" "$demo/proof.bin"
```

The stamp reports `commitment_utc_ns=1795284194000000000` and `clock_uncertainty_ns=1000000000`. The 17,891-byte proof reports `target=pass` and `backward_2=1.7756332617809703e-17`. Replay uses only the public files. [Example transcript and receipts](examples/tsa/quicknet-sigstore/)

## Timestamp an ordinary file

Use a standalone stamp for a file, a public result, or a published proof artifact. This mode works with the ordinary build. Both machines recompute the digest from the exact bytes they want to verify.

```sh
openssl dgst -sha256 -binary proof.bin > proof.sha256
./examples/public-tsa freetsa stamp proof.sha256 proof.tsr
./examples/public-tsa freetsa verify proof.sha256 proof.tsr
```

`stamp` and `stamp-commit` each send one request to the named provider and require a new output file. The helper requests the default policy and independently enforces the expected numeric OID on the response. Save the response and the verification inputs for replay.

## Check independently with OpenSSL

For the bundled examples, run the following after creating `$work/abc.sha256` above. It expresses the independently expected SHA-256 imprint **and policy** as an RFC 3161 query, then verifies each response against its corresponding trusted CA. The C helper's queries use no nonce. If another client used a nonce, keep and use its original query to verify the nonce as well.

```sh
for provider in freetsa sigstore; do
    ca=$(./examples/public-tsa "$provider" root)
    policy=$(./examples/public-tsa "$provider" policy)
    ./stencil tsa-query "$work/abc.sha256" "$work/$provider.tsq" "$policy"
    openssl ts -verify -queryfile "$work/$provider.tsq" \
        -in "examples/tsa/$provider-abc.tsr" -CAfile "$ca"
done
```

For a benchmark stamp, regenerate the expected query with `./stencil beacon-query reg start digest expected.tsq "$policy"` and use it in the same OpenSSL command. OpenSSL checks that query and the signed token. The C `beacon-verify-stamp` command also enforces the registered benchmark time window. For inspecting the signed fields after verification, use `openssl ts -reply -in stamp.tsr -text`. [OpenSSL timestamp verification](https://docs.openssl.org/3.0/man1/openssl-ts/) · [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html)

## Authority settings and trust

| Preset | Issuance endpoint | Required timestamp policy OID | Root SHA-256 over DER |
|---|---|---|---|
| `freetsa` | `https://freetsa.org/tsr` | `1.2.3.4.1` | `a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc` |
| `sigstore` | `https://timestamp.sigstore.dev/api/v1/timestamp` | `1.3.6.1.4.1.57264.2` | `2aca8fea5d3ce48b01cc77076293c280e6c23ffe44034757ee7833ca9f45d633` |

The roots in `examples/tsa/` are public PEM-encoded certificates. Pin them from a repository revision or independently agreed match configuration. The helper checks the SHA-256 fingerprint of the decoded certificate. A service rotation requires reviewing its new trust material and pinning it for subsequent matches.

- **FreeTSA.** The root was obtained from the operator's certificate download. FreeTSA publishes its rate limit of one request per IP per second. [Operator instructions](https://freetsa.org/index_en.php) · [Public root](https://freetsa.org/files/cacert.pem) · [Service policy](https://www.freetsa.org/freetsa.html)
- **Sigstore.** The root is the last certificate in the `timestampAuthorities` chain for the named URI in Sigstore's published trust metadata. Sigstore documents the policy OID and the public timestamp endpoint. [Pinned trust metadata](https://github.com/sigstore/root-signing/blob/6f637ea189df60b5ea9ed5f454b4623bd3a7b3aa/targets/trusted_root.json) · [Timestamp policy](https://github.com/sigstore/timestamp-authority/blob/main/docs/tsa-policy.md) · [Public service](https://docs.sigstore.dev/cosign/verifying/timestamps/)

The C validator checks the chain at both verification time and signed generation time. Its offline validation uses the pinned roots and certificates carried with the response. It does not fetch revocation evidence or implement long-term archival renewal. For a timed match the organizer must also choose a defensible clock allowance under the selected service's policy, especially when a response omits signed accuracy.
