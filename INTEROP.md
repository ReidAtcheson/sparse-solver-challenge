# Interoperability for independent provers

The default three-band challenge uses the wide `STNPRF02` wire layout for local receipts. Its signed profile ID selects the generator and numerical decision. A complete public example is archived with the cloud measurements. [Three-band specification](THREE_BAND_PROOF.md) · [Public replay](benchmarks/three-band-cloud/public)

An entrant can implement the solver, commitment and prover in any language. The interface to the judge is the proof byte stream and the judge's preregistered public inputs. A prover can regenerate rows directly from the instance seed and keep its solution in memory. The row ordering, numerical encoding, commitment, transcript and acceptance equations determine interoperability. The signed 3D test profile has a complete worked transcript below. [Prover equations](PROVER.md) · [Validator equations](VALIDATOR.md) · [Public matrix and RHS generators](matrix.c)

## Signed 3D proof with local receipts

The profile ID is `signed-unit-torus-3d-backward80-v2`. Write ASCII strings as their literal bytes without a trailing NUL, except for the explicitly zero-padded profile slot in the start receipt. All integers in the following layout are little-endian. A scalar is a canonical 32-byte encoding of an integer in `[0, q)`, where `q = 2^252 + 27742317777372353535851937790883648493`. A point is a canonical 32-byte Ristretto255 encoding.

Set `n = side³`, `L = log2(n)`, `w = 2^floor(L/2)`, and `H = n/w`. The committed row with index `a` contains solution coordinates `a*w+c` in increasing column order. Its commitment is `C[a] = sum_c X[a*w+c] G[c]`. Derive `G[c]` by applying the Ristretto255 64-byte map to `SHA512("stencil-ristretto255-generator-v1" || LE32(c))`. This commitment has no blinding term. [Reference commitment](commit.c)

The table gives byte offsets for the archived `side=32` proof. For other registered sides use the lengths in the third column.

| Offset | Item | Length in bytes |
|---:|---|---:|
| 0 | ASCII `STNPRF02` | 8 |
| 8 | Local start receipt | 192 |
| 200 | Local finish receipt | 160 |
| 360 | Shared exponent `E`, signed two's complement | 4 |
| 364 | Points `C[0]` through `C[H-1]` | `32H` |
| 8556 | Residual energy `rho`, then solution energy `Q`, both scalars | 64 |
| 8620 | 128 signed, two's-complement subset sums, 16 bytes each | 2048 |
| 10668 | Norm sumcheck, `L` pairs of scalars `(g(0), quadratic coefficient)` | `64L` |
| 11628 | Scalar `R(u)` | 32 |
| 11660 | Batched sumcheck, `L` pairs in the same format | `64L` |
| 12620 | Folded solution row, `w` scalars | `32w` |
| 16716 | End of file | 0 |

The local start body contains the tag `STNSTA01`, side (4 bytes), zero (4), Unix nanoseconds (8), entrant ID (32), nonce (32) and profile ID (40, zero-padded). The local finish body contains `STNFIN01`, Unix nanoseconds (8), attempt hash (32), commitment digest (32) and fresh entropy (16). Append the authority's 64-byte Ed25519 signature over the exact body in each case. The enrolled public key and expected start come from the judge. Both hashes below include the 64-byte start signature.

```text
instance_seed = SHA256("stencil-instance-seed-v1" || start)
attempt       = SHA256("stencil-attempt-v1" || start)
commit_digest = SHA256("stencil-ristretto255-wide80-row-commitments-v1"
                       || LE32(w) || LE32(H) || signed_LE32(E)
                       || C[0] || ... || C[H-1])
```

For the signed 3D profile, encode coordinate `y[j]` as `X[j] = round_ties_to_even(y[j] * 2^(78-E))`. The reference chooses `E = ceil(log2(max(abs(y))))`, using zero when all coordinates are zero. Obtain the finish receipt on the commitment digest as soon as the row commitments are ready. The prover can retain `X` and the row commitments privately until it builds the rest of the proof. [Encoding and exponent limits](PROVER.md)

## Fiat–Shamir schedule

For a prefix ending just before byte `end`, the 64-byte challenge is

```text
SHA512("stencil-proof-transcript-v1" || proof[0:end] || ASCII(role) || LE32(index))
```

The role occupies one byte. Sampling leaves the prefix untouched. Use the first 32 digest bytes directly as the `M` seed. For scalar challenges, decode the full 64 bytes as a little-endian unsigned integer and reduce modulo `q`.

| Role | Index | End of absorbed prefix |
|---|---|---|
| `M` | 0 | Finish receipt, before `E` |
| `U` | Round `k`, starting at 0 | Both scalars of norm round `k` |
| `B` | Subset index 0 through 127 | Scalar `R(u)` |
| `X` | 0 | Same prefix as every `B` |
| `V` | Round `k`, starting at 0 | Both scalars of batched round `k` |

For either sumcheck round, let `s` be its incoming claim, `a` the transmitted value at zero, `c` its quadratic coefficient, and `r` its scalar challenge. The outgoing claim is `a + r*(s - 2*a - c + r*c)` modulo `q`. Each round eliminates the lowest remaining index bit. The last `V` round fixes the weights of the folded row. The validator checks the group opening, both endpoints, the receipts and the integer bounds before scoring the result. A valid proof can report a certified miss when its backward error exceeds the benchmark target. [Validator checks](VALIDATOR.md)

## Archived known answers

The archived proof has 32,768 unknowns, 256 committed rows, 128 columns, 15 rounds per sumcheck and shared exponent `E = -8`. The two energy integers are `rho = 689899610386202624` and `Q = 45285274284675669591449445514204914440525729234944`. For the scalar challenges below, hex lists the 32 little-endian bytes in wire order. [Public fixture](benchmarks/signed3d-public/grid-32-trial-01)

| Value | Hex |
|---|---|
| Instance seed | `1a02ba82c38bd9658dde7fb174486ed1ef2f993103575801c4c8564c6f7c578d` |
| Commitment digest | `41812e0f36bf9409edc47a903c6c97f046eb8004f8b9728a1b9d0cc5d4bf8136` |
| `M[0]` seed | `ec972ae897b2168fd68d11d87ccca5799089cb56f464d7b71607801ba828ad09` |
| `U[0]` scalar | `2512ce5f33b1126abf8a82a315c49bec26f2d58a39fb622f4bfc4785652a2102` |
| `B[0]` scalar | `9a4d985d73f0ccff6ad55a476b65bb54b45dbc92e65e60081809e2ed3ab5a503` |
| `X[0]` scalar | `6e0f66b9ac7553fb0629af0fa11e3b87418169d8e2fdd5c5f3a97acca53b8c03` |
| `V[0]` scalar | `0ff428ad7503b507ad8657e592804d24cdab0b153abc8d3b9baa70859d870e0f` |
| SHA-256 of the 16,716-byte proof | `1a2e776e3c555ea48e03e369f3a7e9a1acf1a1355a51f4ae4d1f05ec8707495c` |

From the project root, run the independent Python parser and the C validator against the same public inputs.

```sh
make
python3 tests/check_interop.py
```

The Python test checks the commitment digest, challenges, norm sumcheck, canonical scalar encodings, offsets and proof hash. It invokes the C validator for full verification, including receipt signatures, the batched endpoint and the Ristretto opening. For a fresh local-receipt proof from an independently implemented prover, run `./stencil verify authority.pub your-proof.bin expected-start.receipt`. The archived hashes apply to this one signed attempt. For external attempts, use the registration, clock evidence and validator command specified for the drand and RFC 3161 format. [Independent test](tests/check_interop.py) · [External receipts](BEACON.md)
