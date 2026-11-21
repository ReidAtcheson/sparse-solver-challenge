# Bounded three-band pattern measurements

## Pattern generation

Each process streamed the strict upper triangle of one graph, checked the edge count, and discarded the edges. Wall time includes process launch and exit. Peak RSS is the Linux process high-water mark. We ran seeds 42, 43 and 44 in fresh processes on one core of an Intel Core i7-1360P with GCC 13.3.0. Signing, sparse assembly, solving and proof generation are separate operations.

| Sampler | Rows | Upper edges | Median seconds | Seconds range | Peak RSS range, MiB |
|---|---:|---:|---:|---:|---:|
| Archived unbounded | 32,768 | 98,298 | 3.4329 | 3.3976–3.5061 | 2.27–2.33 |
| Bounded | 32,768 | 98,298 | 0.0276 | 0.0266–0.0296 | 2.05–2.17 |
| Bounded | 262,144 | 786,426 | 0.2417 | 0.2411–0.2467 | 2.06–2.17 |
| Bounded | 1,048,576 | 3,145,722 | 1.0084 | 1.0035–1.0647 | 2.15–2.17 |

## Reusing a graph ordering

At each dimension we trained a METIS ordering on the graph from seed 42. For seeds 43 through 49 we compared that ordering, natural index order, and METIS recomputed on the new graph. The table gives the ratios of structural nonzeros in the symbolic lower Cholesky factor, including the diagonal, relative to fresh METIS on the same graph. Larger ratios mean more factor storage. CHOLMOD used the supplied permutations with postordering disabled. This measures the graphs independently of numerical signs and LU pivoting.

| Sampler | Rows | Reused / fresh, median | Reused / fresh, range | Natural / fresh, range | Fresh factor entries, range |
|---|---:|---:|---:|---:|---:|
| Archived unbounded | 4,096 | 2.81 | 2.75–2.93 | 1.26–1.31 | 646,694–669,327 |
| Bounded | 4,096 | 2.83 | 2.78–2.89 | 1.24–1.30 | 650,072–681,254 |
| Archived unbounded | 16,384 | 2.92 | 2.88–2.98 | 1.30–1.33 | 6,010,062–6,156,746 |
| Bounded | 16,384 | 3.05 | 3.01–3.10 | 1.30–1.33 | 6,009,830–6,163,525 |

The same integer seed produces different graphs under the two sampler versions. Each reuse comparison uses the exact target graph as its own fresh-ordering baseline. The natural-order result measures what an entrant can achieve with a simple seed-independent permutation.

## Reproduce locally

From the repository root on Linux, choose one available CPU and build the pattern and ordering drivers. The ordering example used SuiteSparse 7.6.1 and its CHOLMOD 5.2.0 METIS interface. Only the symbolic experiment requires CHOLMOD.

```sh
cpu=2
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
cc -O2 benchmarks/measure.c -o /tmp/three-band-measure
cc -std=gnu11 -O3 -ffp-contract=off benchmarks/three_band_scan.c \
    three_band.c three_band_rng.c -lm -o /tmp/three-band-scan
for n in 32768 262144 1048576; do
    for seed in 42 43 44; do
        taskset -c "$cpu" /tmp/three-band-measure 0 /tmp/three-band-scan "$n" "$seed"
    done
done
for n in 4096 16384; do
    cc -std=gnu11 -O3 -ffp-contract=off -DORDERING_ROWS="$n" -I/usr/include/suitesparse \
        benchmarks/three_band_ordering.c three_band.c three_band_rng.c \
        -lcholmod -lm -o /tmp/three-band-ordering
    taskset -c "$cpu" /tmp/three-band-ordering
done
```

The same drivers produced the unbounded control by linking the sampler and RNG sources from commit `c62e1a3`. The measurement driver reports elapsed nanoseconds and peak RSS in KiB. [Streaming driver](three_band_scan.c) · [Ordering driver](three_band_ordering.c) · [Measurement driver](measure.c)
