# Shared-exponent 80-bit proof measurements

All 11 signed-unit 3D trials passed the joint 2-norm backward-error threshold of $2^{-53}$. Each complete transcript grew by exactly 36 bytes against a verified legacy transcript at the same physical row count. The increase consists of the signed 4-byte shared exponent and the 32-byte squared solution norm.

## Single-thread FFT solver with one refinement

The table gives medians over three independently issued challenges at each size on a local Intel Core i7-1360P with ext4 scratch. Every stage is a separate process. Proving starts after the digest timestamp. Wall time includes process startup. RSS comes from Linux wait4 and excludes the kernel file cache. The prover uses up to 32 bytes per row of disk scratch.

| Grid | Legacy bytes | New bytes | Increase | Solve s | Commit s | Prove s | Verify s | Solve MiB | Prove MiB | Verify MiB | Joint backward error | RHS relative residual |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 32³ | 16,680 | 16,716 | +36 | 0.016 | 0.079 | 0.094 | 0.054 | 6.96 | 6.57 | 6.49 | 1.763e-17 | 1.932e-15 |
| 64³ | 37,544 | 37,580 | +36 | 0.079 | 0.325 | 0.530 | 0.304 | 13.95 | 6.57 | 6.38 | 1.784e-17 | 9.500e-15 |
| 128³ | 103,464 | 103,500 | +36 | 0.538 | 2.109 | 3.821 | 1.957 | 69.82 | 6.67 | 6.62 | 1.782e-17 | 8.421e-15 |

The largest run had 2,097,152 unknowns. Its 103,500-byte proof was 0.617% of the 16 MiB private input. The matrix is indefinite with condition number $\kappa_2$ approximately 2,621, 41,319 and 48,625 at the three sizes. The FFT exploits the periodic grid and the vertex signs. The proof only calls the seeded row generator.

## Single-thread MKL PARDISO

One independent challenge per grid. The direct solver factors a slightly shifted matrix to handle unstable pivots, then refines against the original signed system. Each trial took five corrections. The validator always scores the original matrix.

| Grid | Solve s | Solve MiB | Prove s | Prove MiB | Verify s | Verify MiB | Joint backward error | RHS relative residual | Proof bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 32³ | 0.880 | 138.44 | 0.107 | 6.45 | 0.051 | 6.24 | 2.130e-17 | 2.341e-15 | 16,716 |
| 64³ | 35.318 | 1802.89 | 0.513 | 6.60 | 0.281 | 6.39 | 5.404e-17 | 3.363e-14 | 37,580 |

The runner removed the private solution before each timed verification. An independent Python implementation regenerated the signed matrix, RHS, exponent and both integer energies for the first trial at each size for each solver. The tamper checks changed the exponent or one of the energies. All three altered transcripts were rejected. A valid proof of a zero solution was accepted as a certified accuracy miss. The timestamps came from a local Ed25519 test issuer.

## Reproduce and replay

Run from the source directory on Linux. The built-in FFT uses the default C build. The separate direct solver requires MKL.

```sh
make check
python3 benchmarks/signed3d.py --sides 32 64 128 --trials 3 --regression --output /tmp/signed-fft.json
make direct3d
python3 benchmarks/signed3d.py --solver ./stencil-direct3d --sides 32 64 --trials 1 --output /tmp/signed-ldl.json
p=benchmarks/signed3d-public/grid-128-trial-01
./stencil verify "$p/authority.pub" "$p/proof.bin" "$p/start.receipt"
```

Per-trial times, peak memory, seeds, exact scores, transcript hashes and machine details are available in the [FFT measurements](signed3d-results.json) and [PARDISO measurements](signed3d-pardiso.json).
