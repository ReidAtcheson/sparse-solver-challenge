# Bounded three-band challenge measurements

Four fresh local practice rounds on an Intel Core i7-1360P used the bounded v2 generator, SuperLU 6.0.1, and single-threaded OpenBLAS. Each stage ran in a separate process. After proving, the benchmark removed the private directory, then validated from the public key, signed start and proof. Each row of the table is one draw. [Measurements with exact scores and seeds](results.json) · [Benchmark harness](../three_band_challenge.py)

| Rows | Solve, s | Commit, s | Prove, s | Validate, s | Solve / prove / validate peak RSS, MiB | Proof bytes | Binary64 solution bytes |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1,024 | 0.0327 | 0.0248 | 0.0307 | 0.0219 | 12.36 / 6.54 / 6.54 | 5,836 | 8,192 |
| 4,096 | 0.7632 | 0.0269 | 0.0367 | 0.0295 | 78.70 / 6.77 / 6.62 | 8,140 | 32,768 |
| 8,192 | 5.8733 | 0.0426 | 0.0456 | 0.0472 | 248.43 / 6.79 / 6.49 | 10,316 | 65,536 |
| 16,384 | 62.2948 | 0.0389 | 0.0696 | 0.0650 | 880.43 / 6.91 / 6.60 | 12,492 | 131,072 |

Solve includes generating the sparse system, fresh ordering, factorization, two refinement steps, and writing the solution. Proving starts after the commitment receipt. The process peak RSS excludes temporary disk storage and kernel file cache. All four proofs passed the conservative $2^{-53}$ backward-error target. [Generator-only and symbolic ordering measurements](../BOUNDED_PATTERN.md)

To verify the 16,384-row round from the repository root, run this command.

```sh
p=benchmarks/bounded-three-band/public
./stencil verify "$p/authority.pub" "$p/proof.bin" "$p/start.receipt"
```
