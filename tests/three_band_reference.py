"""Check the bounded signed three-band recipe and replay vectors."""

import argparse
import hashlib
from pathlib import Path
import sys
import unittest

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from examples.three_band_reference import SIGMA, band_centers, draw_signs, gaussian_weight, generate_pattern, sign_pattern


def literal_pattern(n, seed):
    """Full-space oracle with libm Gaussian weights and NumPy cumulative probabilities."""
    rng = np.random.default_rng(seed)
    centers = band_centers(n)
    uses = np.zeros(n, dtype=int)
    edges = []
    fallbacks = tails = 0
    for i in range(n - 1):
        all_future = np.arange(i + 1, n)
        remaining = all_future
        for band in rng.permutation(3)[:min(3, len(all_future))]:
            center = centers[band]
            for _ in range(2):
                within = abs(remaining - i - center) < 100
                if within.any():
                    break
                center = 1.0
                fallbacks += 1
            deviation = np.abs(remaining - i - center)
            tail = (deviation >= 100) & (deviation <= 200)
            subset = remaining[within]
            if tail.any() and rng.random() < 0.01:
                subset = remaining[tail]
                tails += 1
            base = np.exp(-0.5 * ((subset-i-center)/SIGMA)**2)
            weights = np.ldexp(base, int(uses[subset].min()) - uses[subset])
            cdf = np.cumsum(weights)
            j = subset[np.searchsorted(cdf, rng.random()*cdf[-1], side="right")]
            assert abs((j-i) - center) <= 200
            edges.append((i, j))
            uses[j] += 1
            remaining = remaining[remaining != j]
    return np.array(edges), fallbacks, tails


def check_patterns():
    for root in (2, 3, 11, 32, 101, 1000):
        assert band_centers(root**3) == (1.0, float(root), float(root*root))
    for d in np.linspace(-200, 200, 2049):
        expected = np.exp(-0.5 * (d/SIGMA)**2)
        assert abs(gaussian_weight(float(d))/expected - 1) < 2e-14
    n = 1331
    pattern = generate_pattern(n, 42)
    expected, fallbacks, tails = literal_pattern(n, 42)
    assert fallbacks > 0 and tails > 0
    np.testing.assert_array_equal(expected, pattern.edges)
    assert pattern.edges.shape == (3*n-6, 2)
    assert np.all(pattern.edges[:, 0] < pattern.edges[:, 1])
    assert len(np.unique(pattern.edges, axis=0)) == len(pattern.edges)
    digest = hashlib.sha256(pattern.edges.astype("<u8").tobytes()).hexdigest()
    assert digest == "5fa745337561f35f7c00894f764744883b07f40478d212c034955cc6c7c0e038"
    edge, diagonal = draw_signs(pattern, sign_draw=7)
    signs = np.concatenate((edge, diagonal)).astype("i1")
    assert hashlib.sha256(signs.tobytes()).hexdigest() == (
        "b67d5ae3961c6afad8b19e524cfcf82e1fe47ca1ede40ebae5a220471e9962a2")
    assert set(signs) == {-1, 1}
    np.testing.assert_array_equal(generate_pattern(3, 7).edges, [(0, 2), (0, 1), (1, 2)])

    # The noncube exercises fractional centers. A rotation distinguishes scatter from gather.
    pattern = generate_pattern(128, 42)
    assert hashlib.sha256(pattern.edges.astype("<u8").tobytes()).hexdigest() == (
        "15df129bbddbd3b7a4502ba2aa0f35b50729d40210d5143143357e96921df3ea")
    rng = np.random.default_rng(987)
    wanted_edges = rng.choice([-1.0, 1.0], size=len(pattern.edges))
    wanted_diag = rng.choice([-1.0, 1.0], size=pattern.n)
    perm = np.roll(np.arange(pattern.n), 13)
    actual_edges, actual_diag = draw_signs(pattern, sign_seed=987, permutation=perm)
    np.testing.assert_array_equal(actual_edges, wanted_edges)
    np.testing.assert_array_equal(actual_diag[perm], wanted_diag)
    testcase = unittest.TestCase()
    with testcase.assertRaises(ValueError):
        draw_signs(pattern, sign_draw=0)
    with testcase.assertRaises(ValueError):
        draw_signs(pattern, sign_seed=1, sign_draw=1)
    with testcase.assertRaises(ValueError):
        draw_signs(pattern, permutation=np.zeros(pattern.n, dtype=int))
    with testcase.assertRaises(ValueError):
        generate_pattern(2, 0)
    print(f"PASS NumPy {np.__version__} replay, {fallbacks} fallbacks and {tails} tail selections")


def check_sparse():
    from scipy.sparse import isspmatrix_csc, isspmatrix_csr

    pattern = generate_pattern(128, 42)
    perm = np.roll(np.arange(pattern.n), 13)
    original_edges = pattern.edges.copy()
    a = sign_pattern(pattern, sign_draw=3, permutation=perm)
    b = sign_pattern(pattern, sign_draw=3, permutation=perm, format="csc")
    changed = sign_pattern(pattern, sign_draw=4)
    assert isspmatrix_csr(a) and isspmatrix_csc(b)
    assert a.dtype == np.float64 and np.all(np.abs(a.data) == 1)
    assert (a != b).nnz == 0 and (a != a.T).nnz == 0
    assert a.nnz == 7*pattern.n-12 and a.has_canonical_format
    assert np.all(np.abs(a.diagonal()) == 1)
    edge, diag = draw_signs(pattern, sign_draw=3, permutation=perm)
    np.testing.assert_array_equal(a.diagonal(), diag)
    i, j = pattern.edges.T
    np.testing.assert_array_equal(np.asarray(a[i, j]).ravel(), edge)
    np.testing.assert_array_equal(a.indices, changed.indices)
    np.testing.assert_array_equal(a.indptr, changed.indptr)
    assert np.any(a.data != changed.data)
    np.testing.assert_array_equal(pattern.edges, original_edges)
    small = sign_pattern(generate_pattern(3, 7), sign_draw=3).toarray()
    np.testing.assert_array_equal(small[0], small[2])  # Singular draw survives.
    print("PASS SciPy CSR/CSC, permutation replay, pattern reuse and singular sample")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pattern-only", action="store_true",
                        help="check patterns and sign draws using only NumPy")
    args = parser.parse_args()
    check_patterns()
    if not args.pattern_only:
        check_sparse()
