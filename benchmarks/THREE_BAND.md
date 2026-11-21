# Signed three-band cloud benchmark

One fresh challenge at each size on a Google Compute Engine n2-standard-8 VM in us-central1-a. The host reported Intel(R) Xeon(R) CPU @ 2.80GHz and 8 vCPUs. The numerical solver used one thread with SuperLU 6.0.1, OpenBLAS 0.3.26, and the symmetric minimum-degree ordering on the pattern of A + Aᵀ. The compiler was GCC 13.3.0 on Ubuntu 24.04. Every draw was accepted as issued and every transcript passed the $2^{-53}$ threshold. The clock used local Ed25519 practice receipts. These are single observations per size and include process startup. [Raw measurements, seeds and receipt metadata](three-band-cloud/results.json)

## Wall time in seconds

**Solve process** includes matrix and RHS generation, conversion for SuperLU, ordering, pivoted LU factorization, triangular solves, two refinement steps and writing the private binary64 vector. **Generate CSR** and **Numerical solve** are measured inside that process. Commit produces the digest that is timestamped. Proving runs after the timestamp. A fresh verification process receives only the signed start, public key and transcript. The harness deletes the private working directory before verification.

| Rows | Generate CSR | Numerical solve | Solve process | Commit | Timestamp | Prove | Validate | Transcript bytes |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1,024 | 0.0152 | 0.0368 | 0.0602 | 0.0116 | 0.0107 | 0.0300 | 0.0287 | 5,836 |
| 4,096 | 0.1321 | 1.2118 | 1.3530 | 0.0206 | 0.0082 | 0.1604 | 0.1621 | 8,140 |
| 8,192 | 0.4527 | 10.5675 | 11.0284 | 0.0334 | 0.0083 | 0.4961 | 0.5045 | 10,316 |
| 16,384 | 1.6646 | 89.9039 | 91.5806 | 0.0497 | 0.0085 | 1.7409 | 1.7478 | 12,492 |
| 32,768 | 6.3285 | 770.1935 | 776.5304 | 0.0903 | 0.0085 | 6.4671 | 6.4994 | 16,716 |

## Peak RSS in MiB

Linux `wait4` reported the peak resident set of each command in KiB. The table divides by 1,024. Solve RSS includes its CSR and factorization. The standalone matrix scan regenerates the same signed pattern and writes Matrix Market text to /dev/null. It gives a separate process peak for streaming generation. The timing harness invokes that diagnostic after validation. Kernel file cache and temporary disk storage lie outside these process RSS figures.

| Rows | Matrix scan | Solve process | Commit | Timestamp | Prove | Validate | Backward-error upper bound |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1,024 | 4.06 | 13.39 | 6.32 | 6.11 | 6.79 | 6.70 | 4.4935e-17 |
| 4,096 | 4.20 | 79.16 | 6.42 | 6.14 | 6.90 | 6.82 | 4.7024e-17 |
| 8,192 | 4.20 | 260.90 | 6.34 | 6.29 | 6.96 | 6.77 | 4.7356e-17 |
| 16,384 | 4.21 | 872.91 | 6.36 | 6.02 | 7.06 | 6.85 | 4.5880e-17 |
| 32,768 | 4.26 | 3486.91 | 6.42 | 6.18 | 7.73 | 6.79 | 4.6324e-17 |

At 32,768 rows a standalone replay of the signed matrix, including Matrix Market formatting, took 6.27 seconds. The full validator took 6.50 seconds. The proof was 16,716 bytes, 6.4% of the size of the private binary64 vector. Proving and validation each used less resident memory than this direct solver on all five draws. The reference generator replays a quadratic number of random draws and retains linear-size incoming-column counters. Sparse LU factor memory depends on the sampled graph, ordering, and numerical pivoting. [Proof and validator storage](../THREE_BAND_PROOF.md)

## Replay and reproduce

From the repository root, replay the archived largest case and run a fresh sweep with a new results path. Building the numerical solver on Debian or Ubuntu requires `libsuperlu-dev`. Installing `libopenblas-pthread-dev` and selecting its BLAS alternative reproduces the backend used here. The harness limits BLAS to one thread. New registrations produce new challenge seeds.

```sh
make
bundle=benchmarks/three-band-cloud/public
./stencil verify "$bundle/authority.pub" "$bundle/proof.bin" "$bundle/start.receipt"
python3 benchmarks/three_band_challenge.py --sizes 1024 4096 8192 16384 32768 \
    --output /tmp/three-band-results.json
```
