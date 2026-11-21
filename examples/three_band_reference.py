"""Signed three-band generator in original index order. Reference RNG: NumPy 2.3.5.

    pattern = generate_pattern(1024, pattern_seed=42)
    a = sign_pattern(pattern, sign_draw=1)              # SciPy CSR
    b = sign_pattern(pattern, sign_draw=2, format="csc")

Pattern generation uses a quadratic number of random draws and linear workspace.
For historical diagonal placement, pass the original METIS permutation explicitly.
"""

from dataclasses import dataclass
import operator
from statistics import NormalDist

import numpy as np


SIGMA = 100.0 / NormalDist().inv_cdf(0.995)


@dataclass(frozen=True)
class Pattern:
    n: int
    pattern_seed: int
    edges: np.ndarray    # Upper-triangle endpoints, in draw order


def _integer(value, name, minimum):
    if isinstance(value, (bool, np.bool_)):
        raise TypeError(f"{name} must be an integer")
    value = operator.index(value)
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


def generate_pattern(n, pattern_seed):
    """Generate the pattern once, using the exact full-candidate RNG schedule."""
    n = _integer(n, "n", 3)
    pattern_seed = _integer(pattern_seed, "pattern_seed", 0)
    rng = np.random.default_rng(pattern_seed)
    extent = np.cbrt(n)
    centers = (1.0, extent, extent**2)
    incoming = np.zeros(n, dtype=np.int64)
    edges = np.empty((3*n - 6, 2), dtype=np.int64)
    offsets = np.arange(1, n, dtype=np.int64)
    log_two = np.log(2.0)
    pos = 0
    for i in range(n - 1):
        future = offsets[:n-1-i]
        available = np.ones(future.size, dtype=bool)
        for band in rng.permutation(3)[:min(3, future.size)]:
            d = future - centers[band]
            inliers = np.abs(d) < 100
            if not np.any(available & inliers):
                d = future - centers[0]
                inliers = np.abs(d) < 100
            tail = available & ~inliers
            if tail.any() and rng.random() < 0.01:
                eligible = tail
            else:
                eligible = available & inliers
            log_weights = -0.5 * (d / SIGMA)**2 - log_two * incoming[i+1:]
            scores = log_weights + rng.gumbel(size=future.size)
            scores[~eligible] = -np.inf
            k = int(np.argmax(scores))
            j = i + 1 + k
            edges[pos] = (i, j)
            pos += 1
            incoming[j] += 1
            available[k] = False
    edges.flags.writeable = False
    return Pattern(n, pattern_seed, edges)


def draw_signs(pattern, *, sign_draw=None, sign_seed=None, permutation=None):
    """Return edge signs in draw order and diagonal signs in original order."""
    if sign_seed is None:
        draw = 1 if sign_draw is None else _integer(sign_draw, "sign_draw", 1)
        seed = [pattern.n, pattern.pattern_seed, draw, 7531]
    else:
        if sign_draw is not None:
            raise ValueError("specify either sign_seed or sign_draw")
        seed = _integer(sign_seed, "sign_seed", 0)
    rng = np.random.default_rng(seed)
    edge_signs = rng.choice([-1.0, 1.0], size=len(pattern.edges))
    diagonal = rng.choice([-1.0, 1.0], size=pattern.n)
    if permutation is not None:
        perm = np.asarray(permutation)
        if (perm.shape != (pattern.n,) or perm.dtype.kind not in "iu"
                or not np.array_equal(np.sort(perm), np.arange(pattern.n))):
            raise ValueError("permutation must list each original vertex exactly once")
        original = np.empty_like(diagonal)
        original[perm] = diagonal
        diagonal = original
    return edge_signs, diagonal


def sign_pattern(pattern, *, sign_draw=None, sign_seed=None, permutation=None, format="csr"):
    """Return a symmetric real SciPy CSR or CSC matrix, including singular draws."""
    from scipy.sparse import coo_matrix

    if format not in ("csr", "csc"):
        raise ValueError("format must be 'csr' or 'csc'")
    edge_signs, diagonal = draw_signs(pattern, sign_draw=sign_draw,
                                      sign_seed=sign_seed, permutation=permutation)
    i, j = pattern.edges.T
    vertices = np.arange(pattern.n)
    rows = np.concatenate((i, j, vertices))
    cols = np.concatenate((j, i, vertices))
    data = np.concatenate((edge_signs, edge_signs, diagonal))
    return coo_matrix((data, (rows, cols)), shape=(pattern.n, pattern.n)).asformat(format)
