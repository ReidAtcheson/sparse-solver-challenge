# Random 2D diffusion measurements

Three fresh signed challenges per grid. Each stage ran in a separate single-threaded C process. The machine was an Intel Core i7-1360P running Linux 7.2.6-76070206-generic on x86-64. The optimized build used GCC 13.3.0, OpenSSL 3.0.13 and libsodium 1.0.18. Private scratch used ext4 on NVMe. The kernel could cache files between stages. Each grid used the same fixed numerical profile and independent seeds.

## Wall time

Times are medians in seconds. Solve includes one iterative refinement and writing the private binary64 file. Commit includes quantization, all row commitments and publishing the digest. The signed interval ends at the issuer’s timestamp in the finish receipt. Prove starts with that receipt already in hand. Each command time includes process startup. The signed interval and the separately measured command times have different boundaries.

| Unknowns | Solve | Commit | Stamp command | Signed start to digest | Prove after stamp | Validate | Transcript bytes |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 262,144 | 0.145 | 0.269 | 0.029 | 0.447 | 0.388 | 0.270 | 37,544 |
| 1,048,576 | 0.595 | 0.873 | 0.033 | 1.505 | 1.392 | 0.936 | 70,568 |
| 4,194,304 | 2.376 | 2.871 | 0.026 | 5.278 | 5.378 | 3.588 | 136,360 |

## Peak resident memory

Figures in MiB are medians of individual child-process peak RSS from wait4. The scratch column gives the maximum size of the single large field table used by the prover. The small proof-output staging file is additional. The private input file, kernel filesystem cache and temporary disk space are outside the RSS figures. Validation reads the public inputs and uses no scratch table.

| Unknowns | Solve RSS | Commit RSS | Prove RSS | Validate RSS | Private binary64 input | Prover scratch table |
|---:|---:|---:|---:|---:|---:|---:|
| 262,144 | 15.62 | 6.19 | 6.44 | 6.44 | 2 | 8 |
| 1,048,576 | 45.56 | 6.16 | 6.53 | 6.43 | 8 | 32 |
| 4,194,304 | 165.55 | 6.46 | 6.61 | 6.68 | 32 | 128 |

At 1,048,576 rows the additional capped trial set RLIMIT_AS to 32 MiB. Proving completed in 1.391 s and produced byte-identical output. Validation completed in 0.936 s with the same score. The solver failed its vector allocation at that limit. The working-set comparison is with the supplied matrix-free CG solver. The cap applies to process address space, and disk-backed scratch is essential to this result.

## Public replay

The saved 4,194,304-row transcript occupies 136,360 bytes, or 0.0325 bytes per row and 0.406% of the private binary64 file size. It certifies an exact integer squared residual of 1,732,769,977, relative RHS error of 7.05181250117e-17, and a signed elapsed time of 5.278464286 s.

```sh
./stencil verify benchmarks/public/authority.pub benchmarks/public/proof.bin benchmarks/public/start.receipt
```

The independent end-to-end test recomputed the score of a separate 512² challenge using Python integers and accepted a valid all-zero witness as a certified accuracy miss. The negative tests cover changed receipts, a changed solution, invalid scalar encodings, altered sumcheck and opening messages, and truncated or extended proofs. A second generator test covers directed nonlocal terms and arbitrary signed RHS values. The sanitizer build also passed the end-to-end suite.

The timestamps in this run use a local test authority. The validation times are host CPU measurements. All per-attempt seeds, scores, stage timings, RSS figures, proof hashes and the hard-cap trial are in [results.json](results.json).
