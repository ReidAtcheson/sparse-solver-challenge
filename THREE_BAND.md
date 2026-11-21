# Signed three-band matrices

`stencil three-band` generates a symmetric matrix with a seeded sparsity pattern and independent edge and diagonal signs. Vertices retain their original indices. The dimension can be any integer at least three. A pattern has exactly `3*n - 6` strict-upper entries. With the diagonal and both triangles, the matrix has `7*n - 12` nonzeros. All entries are real binary64 values of +1 or −1. Singular samples pass through as drawn.

## Using a sample

```sh
make
./stencil three-band 4096 42 --sign-draw 1 > matrix.mtx
./stencil three-band 4096 42 --sign-seed 8675309 > independent.mtx
./stencil three-band 4096 42 --sign-draw 7 --perm metis-order.txt > replay.mtx
```

The command writes Matrix Market coordinate format with a symmetric header, one-based indices and only the lower triangle (including the diagonal). A compatible reader restores both triangles. The default sign-draw ID is 1. The C API and CLI accept unsigned 64-bit pattern seeds, independent sign seeds and draw IDs. Draw IDs start at one.

In Python, generate the pattern once and reuse it for several sign assignments. The reference replay environment used NumPy 2.3.5 and SciPy 1.16.3.

```python
from examples.three_band_reference import generate_pattern, sign_pattern

pattern = generate_pattern(4096, pattern_seed=42)
a = sign_pattern(pattern, sign_draw=1)                # SciPy CSR
b = sign_pattern(pattern, sign_draw=2, format="csc")  # same pattern
```

The public C library provides `tb_pattern_create` and `tb_signed_matrix` for the same workflow. Free each output with `tb_sparse_free` and the cached pattern with `tb_pattern_free`. For a sequential scan, `tb_signed_scan` takes a callback, emits each signed upper edge once, then emits the diagonal. A consumer can immediately add both symmetric contributions to a matrix-vector product or verifier endpoint without storing adjacency lists. [C interface](three_band.h) · [Python reference](examples/three_band_reference.py)

## Replay rules

- Set `extent = np.cbrt(n)`. The three offset centers are `1`, `extent`, and `extent**2`. All bands have fixed width `sigma = 100 / NormalDist().inv_cdf(0.995)`, approximately 38.8224483 indices. The inlier condition is strictly `abs(offset - center) < 100`.
- The pattern starts with `default_rng(pattern_seed)`. Visit rows up to and including `n-2`. Permute all three bands, use the first `min(3,n-1-i)`, and exclude columns already chosen in that row. Fall back to the center at 1 whenever a band has no available inliers. Draw the 1% tail-selection Bernoulli only when available tail columns exist.
- Within the selected set maximize `-0.5*((offset-center)/sigma)**2 - incoming[j]*log(2) + gumbel[j]`, breaking ties by smallest column. Each draw consumes standard Gumbels for **every** future column in increasing order, including previously selected and masked columns. After each selection increment that column's counter. The C code omits the logarithms for masked spans while consuming the same random stream.
- For a draw ID, initialize the sign generator with `default_rng([n, pattern_seed, sign_draw, 7531])`. For a separate scalar seed use `default_rng(sign_seed)`. Draw all edge signs in edge-draw order, followed by all diagonal signs. A historical permutation is a zero-based list with `perm[k]` equal to the original vertex at METIS position `k`. Assign `diag_original[perm[k]] = diag_draw[k]`. It affects only diagonal placement. The CLI accepts the list as whitespace-separated integers in a file, or from standard input with `--perm -`. Fresh samples default to original diagonal order.

The native and Python versions were compared on this host with NumPy 2.3.5, including cube and noncube sizes and seeds above 32 bits. Floating-point math libraries and NumPy CPU dispatch can change last-bit results in the centers, thresholds or scores. The replay tests include the complete ordered-edge digest for `n=1331, pattern_seed=42` as a portability check. [Replay vectors](tests/three_band_reference.py) · [NumPy compatibility policy](https://numpy.org/doc/2.3/reference/random/compatibility.html)

```sh
make check-three-band
make check-three-band-reference PYTHON=/path/to/numpy-2.3.5-scipy/bin/python
```

## Cost and challenge registration

The pattern scan consumes exactly `3*n*(n-1)/2 - 4` standard Gumbels for every valid dimension. At 1,048,576 rows that is about 1.65 trillion Gumbels, even with only 3,145,722 undirected edges. Each row can select a far-future column. The C scanner starts with one byte per column and widens its counters if any would overflow. Working memory is linear in `n`. Caching edges for reuse or returning a complete CSR/CSC matrix also takes linear storage. Once the pattern is cached, signing and sparse assembly take linear time.

The default registered challenge uses `signed-three-band-backward80-v1` and powers of two from 1,024 through 65,536 rows. The upper limit guarantees that every possible draw meets the current proof profile's absolute row-sum budget. The raw sampler above accepts other dimensions. Fresh challenges derive a 32-byte instance seed from the signed start under the chosen receipt protocol. Read it as four little-endian unsigned 64-bit words $s_0,s_1,s_2,s_3$. Use $s_0$ as the pattern seed and $s_1$ as the independent sign seed, with the diagonal assigned in original order. Set $k=\operatorname{mix}(s_2\mathbin{\oplus}\operatorname{mix}(s_3))$ using the SplitMix64 finalizer in `matrix.c`. The RHS for row $i$ is $+1/n$ when the high bit of $\operatorname{mix}(k+i)$ is set and $-1/n$ otherwise. Addition wraps at 64 bits. [Numerical score and proof bounds](THREE_BAND_PROOF.md) · [C implementation](matrix.c)

## Symbolic ordering experiment

For 4,096 vertices, the table gives the structural nonzeros in the lower factor, including its diagonal. The seed-42 column reuses exactly one METIS permutation for every graph. The fresh column computes a METIS permutation from each graph. CHOLMOD used the specified permutations with postordering disabled. Numerical values and indefinite pivoting do not enter this measurement.

| Pattern seed | Natural index order | Seed-42 METIS | Fresh METIS | Seed-42 / fresh |
|---:|---:|---:|---:|---:|
| 42 | 847,087 | 665,288 | 665,288 | 1.00 |
| 43 | 848,295 | 1,871,011 | 665,645 | 2.81 |
| 44 | 845,409 | 1,855,574 | 646,694 | 2.87 |
| 45 | 846,430 | 1,920,469 | 654,367 | 2.93 |

The permutation specialized to seed 42 transferred poorly. Natural order cost 1.27–1.31 times as many factor entries as fresh METIS on these three held-out patterns. This experiment measures the complete recipe. Isolating the effect of the 1% tail would require a matched experiment varying that feature.

To reproduce, use a SuiteSparse installation with CHOLMOD and METIS support. Adjust the include path for the local installation. [Benchmark source](benchmarks/three_band_ordering.c)

```sh
cc -std=c11 -O3 -ffp-contract=off -I/usr/include/suitesparse \
   benchmarks/three_band_ordering.c three_band.c three_band_rng.c \
   -lcholmod -lm -o /tmp/three-band-ordering
/tmp/three-band-ordering
```
