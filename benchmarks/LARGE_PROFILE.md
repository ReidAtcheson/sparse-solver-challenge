# Three-band size-limit validation

A solved **131,072-row** bounded three-band challenge passed with `backward_2_upper=4.6476053728964346e-17`. Its proof occupies **29,260 bytes**. The private solver copied the signed entries directly into band storage, used unshifted LAPACK general-band LU with partial pivoting, and refined against the same matrix. The proof and an independent public replay used the reference tool. This was a self-timed correctness run. From the repository root, replay it with the following command.

```sh
p=benchmarks/large-profile/public
./stencil verify "$p/authority.pub" "$p/proof.bin" "$p/start.receipt"
```

The size regression exercises both the local signed-start issuer and the offline Quicknet registration command. Each accepted 1,073,741,824 rows and rejected 1,073,741,825 and 2,147,483,648 rows. Registration writes a small public record and does not allocate a matrix or proof. Archived v1 issuance retains its original size range.

The separate million-row test exercised commitment, proving and public verification on a fresh bounded v2 draw with 1,048,576 rows. Its dense candidate was $x_i=(-1)^i/n$. The numerical verdict was a **certified miss**, as expected for this test vector. An independent streaming integer matvec computed both exact reference energies from the raw seeded Matrix Market stream and RHS signs. Verification ran in a separate process after deletion of the private working directory. Its only inputs were the signed start, public key and proof.

| Stage | Wall time | Peak RSS |
|---|---:|---:|
| Commit | 0.207 s | 6.38 MiB |
| Prove | 3.130 s | 54.75 MiB |
| Verify | 3.809 s | 6.34 MiB |

The full transcript occupied **70,604 bytes**, or **0.842%** of the 8,388,608-byte private binary64 vector. These are single local observations on an Intel Core i7-1360P with GCC 13.3.0 and Linux. The per-process measurement uses monotonic wall time and Linux `wait4` peak RSS. This test measures proof processing of a known candidate and has no solver stage. The largest full transcript exercised here has $2^{20}$ rows.

From the repository root, reproduce the boundary registrations and the million-row proof with a fresh seed.

```sh
make
cc -std=c11 -O2 benchmarks/measure.c -o /tmp/stencil-large-profile-measure
python3 tests/check_large_profile.py --million --measure /tmp/stencil-large-profile-measure
```

Running the same script without `--million` uses a 131,072-row candidate while retaining the billion-row registration checks. [Size regression](../tests/check_large_profile.py) · [Proof units and integer lifting](../THREE_BAND_PROOF.md)

## Comparing the numerical instance with the published bounded release

We built the original bounded generator at commit `6610045` and the expanded-size implementation in separate clean directories with GCC 13.3.0. Separate processes loaded each build's library. For all seven original row counts ($2^{10}$ through $2^{16}$) and eight 32-byte seeds per size, we exported every physical row through `stencil_rows`. We compared the original-order row offsets (uint64), columns (uint32), signed binary64 coefficients, and binary64 RHS byte for byte. We separately extracted and compared all diagonal entries in row order, checking that each row contained exactly one. The 56 matrices contained 1,040,384 rows and 7,282,016 nonzeros in total. All bytes matched. The diagonal contained 521,097 positive and 519,287 negative entries across the test set.

The seeds were 32 zero bytes, 32 bytes of `ff`, the bytes `00` through `1f`, the authenticated seed of the archived 16,384-row bounded proof, and SHA-256 of each ASCII string `row-equality/0` through `row-equality/3`. The library regression freezes hashes of the published 4,096-row CSR, diagonal and RHS for the `00` through `1f` seed. [Known-answer test](../tests/library.py)

We also called the matrix and RHS generators directly in both builds at the newly admitted sizes of 131,072 and 1,048,576 rows, using the `00` through `1f` seed. The original release already supported these sizes in its raw generator. Its full ordered stream of signed upper-triangle edges, signed diagonal and binary64 RHS matched the updated build byte for byte at both sizes.

For a fresh 1,024-row challenge, we supplied both tools with the same signed start, the same SuperLU solution to the unmodified system and the same signed finish. Their 1,028-byte row caches, 32-byte commitment digests and 5,836-byte proofs matched byte for byte. Both validators accepted the other's proof with the same certified score. The published 16,384-row passing proof also replayed with byte-identical output in both builds. [Archived solved proof](bounded-three-band/public)
