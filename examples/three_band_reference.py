"""Signed three-band generator in original index order. Reference RNG: NumPy 2.3.5.

    pattern = generate_pattern(1024, pattern_seed=42)
    a = sign_pattern(pattern, sign_draw=1)              # SciPy CSR
    b = sign_pattern(pattern, sign_draw=2, format="csc")

The bounded pattern scans up to 401 offsets per band. This clarity-first reference
keeps one count per vertex and stores the generated upper edges.
For historical diagonal placement, pass the original METIS permutation explicitly.
"""

from dataclasses import dataclass
import operator
import math

import numpy as np


SIGMA = float.fromhex('0x1.36945fc7f60afp+5')
TAIL_START = 100
MAX_DEVIATION = 200


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


def band_centers(n):
    """Binary64 operation order shared by independent v2 implementations."""
    low, high = 1.0, float(n)
    while True:
        middle = low + (high - low) * 0.5
        if middle == low or middle == high:
            extent = high
            break
        cube = (middle * middle) * middle
        if cube == float(n):
            extent = middle
            break
        if cube < float(n):
            low = middle
        else:
            high = middle
    return (1.0, extent, extent * extent)


def gaussian_weight(deviation):
    """Protocol-defined approximation of exp(-0.5*(deviation/SIGMA)**2)."""
    x = deviation / SIGMA
    z = (-0.5 * (x * x)) / 16.0
    term = total = 1.0
    for k in range(1, 18):
        term = (term * z) / float(k)
        total += term
    for _ in range(4):
        total *= total
    return total


def generate_pattern(n, pattern_seed):
    """Generate each edge in draw order using the bounded v2 schedule."""
    n = _integer(n, "n", 3)
    pattern_seed = _integer(pattern_seed, "pattern_seed", 0)
    rng = np.random.default_rng(pattern_seed)
    incoming = [0] * n
    edges = np.empty((3*n - 6, 2), dtype=np.int64)
    bands = []
    for center in band_centers(n):
        inner, outer = [], []
        # Check the rounded subtraction itself at the endpoints.
        first = max(1, math.floor(center) - MAX_DEVIATION - 1)
        last = min(n-1, math.ceil(center) + MAX_DEVIATION + 1)
        for offset in range(first, last + 1):
            d = float(offset) - center
            if abs(d) <= MAX_DEVIATION:
                region = inner if abs(d) < TAIL_START else outer
                region.append((offset, gaussian_weight(d)))
        bands.append((inner, outer))

    pos = 0
    for i in range(n - 1):
        last = n - 1 - i
        used = set()
        for band in rng.permutation(3)[:min(3, last)]:
            inner, outer = bands[band]
            inliers = [(t, w) for t, w in inner if t <= last and t not in used]
            if not inliers:
                inner, outer = bands[0]
                inliers = [(t, w) for t, w in inner if t <= last and t not in used]
            tails = [(t, w) for t, w in outer if t <= last and t not in used]
            eligible = tails if tails and rng.random() < 0.01 else inliers

            minimum = min(incoming[i+t] for t, _ in eligible)
            cumulative = []
            total = 0.0
            for t, base in eligible:
                weight = math.ldexp(base, minimum - incoming[i+t])
                total += weight
                if weight > 0.0:
                    cumulative.append((t, total))
            target = rng.random() * total
            chosen = next((t for t, cdf in cumulative if cdf > target), cumulative[-1][0])
            edges[pos] = (i, i + chosen)
            pos += 1
            incoming[i+chosen] += 1
            used.add(chosen)
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
