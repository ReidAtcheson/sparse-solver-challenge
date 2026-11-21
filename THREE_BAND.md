# Bounded signed three-band matrices

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

For each row $i$, visit the three bands in a fresh random permutation. Their offset centers $\mu$ are $1$, $n^{1/3}$ and $n^{2/3}$. Keep only strict-upper columns $j>i$, excluding columns already chosen in this row. Visit at most three bands and stop after $n-1-i$ selections in the final short rows.

1. For offset $t=j-i$, define $d=t-\mu$. Inliers have $|d|<100$. Tail offsets have $100\le|d|\le200$. If the band has no available inliers, switch to the band centered at 1 and recompute both sets. The boundary at 200 is inclusive.
2. If tail candidates exist, consume one uniform draw and choose the tail when it is below 0.01. Otherwise use the inliers. Thus 1% is the total probability of selecting either tail when available. The two tails share the same weighted selection.
3. Within the chosen set the target weight is $\exp(-d^2/(2\sigma^2))2^{-c_j}$, where $c_j$ counts earlier incoming edges and $\sigma=100/\Phi^{-1}(0.995)$. Enumerate eligible offsets in increasing order. Subtract the smallest eligible count from every $c_j$ before applying the power of two. Accumulate the binary64 weights left to right. Consume one uniform $U$, even for a singleton, and select the first cumulative weight strictly greater than $U$ times the total. If rounding lands on the upper endpoint, select the last candidate with positive weight. Emit the edge, increment its count, and exclude it from further selections in the row.
4. The pattern stream uses the NumPy 2.3.5 `default_rng(pattern_seed)` permutation and binary64 uniform schedules. The protocol fixes the operation order for the cube root and Gaussian weights so independent implementations can regenerate the exact columns. The reference evaluates the exponential through degree 17 after dividing its argument by 16, then squares four times. See `band_centers` and `gaussian_weight` for the complete binary64 recipe. The replay tests pin ordered edges for cube and noncube dimensions. [Python reference](examples/three_band_reference.py) · [Known answers](tests/three_band_reference.py)
5. For raw sign-draw experiments, seed the sign generator with `default_rng([n, pattern_seed, sign_draw, 7531])`. For the challenge, use `default_rng(sign_seed)`. Draw all edge signs in edge-draw order, followed by all diagonal signs in original index order. A supplied permutation for a historical sign experiment maps `perm[k]` to the original vertex at position `k`; assign `diagonal_original[perm] = diagonal_draw`.

```sh
make check-three-band
make check-three-band-reference PYTHON=/path/to/numpy-2.3.5-scipy/bin/python
```

## Cost and challenge registration

A band spans at most 401 integer offsets. With at most three selections per row, the total number of weighted candidates examined is linear in $n$. The streaming C generator keeps incoming counts in a power-of-two ring covering the furthest possible future neighbor, at most $\lfloor n^{2/3}\rfloor+200$ places ahead (using the protocol's computed center). A column can have at most $3\times401$ distinct predecessor offsets, so a 16-bit counter suffices for every seed. The scanner uses $O(n^{2/3}+200)$ temporary space. Materializing a CSR or CSC matrix takes $O(n)$ space. [Pattern timings and held-out ordering results](benchmarks/BOUNDED_PATTERN.md)

The sole competition profile is `signed-three-band-backward80-v2`. It accepts powers of two from 1,024 through 65,536 rows within the current proof bounds. The standalone generator also supports other sizes. Fresh challenges derive a 32-byte instance seed from the signed start under the chosen receipt protocol. Read it as four little-endian unsigned 64-bit words $s_0,s_1,s_2,s_3$. Use $s_0$ as the pattern seed and $s_1$ as the independent sign seed, with the diagonal assigned in original order. Set $k=\operatorname{mix}(s_2\mathbin{\oplus}\operatorname{mix}(s_3))$ using the SplitMix64 finalizer in `matrix.c`. The RHS for row $i$ is $+1/n$ when the high bit of $\operatorname{mix}(k+i)$ is set and $-1/n$ otherwise. Addition wraps at 64 bits. [Numerical score and proof bounds](THREE_BAND_PROOF.md) · [C implementation](matrix.c)
