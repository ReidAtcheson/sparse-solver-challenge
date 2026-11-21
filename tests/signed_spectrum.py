"""Certify the registered torus spectra using dyadic intervals and integer square roots."""
from bisect import bisect_left
from math import isqrt

Q = 1 << 96

def double_side(bounds):
    # For j in the first quadrant, 2 cos(theta/2) = sqrt(2 + 2 cos theta).
    # Reflect into the second quadrant. The axes are known exactly.
    quadrant = []
    for lo, hi in bounds:
        upper_squared = (2 * Q + hi) * Q
        upper = isqrt(upper_squared)
        quadrant.append((isqrt((2 * Q + lo) * Q),
                         upper + (upper * upper < upper_squared)))
    return quadrant + [(-hi, -lo) for lo, hi in reversed(quadrant[:-1])]

def gap_bound(bounds):
    # The closest sum of three centers can be found by searching the third
    # sorted coordinate for every pair. All other modes are cos reflections.
    centers = sorted((lo + hi) // 2 for lo, hi in bounds)
    radius = max((hi - lo + 1) // 2 for lo, hi in bounds)
    closest = 7 * Q
    for i, first in enumerate(centers):
        for second in centers[i:]:
            target = -Q - first - second
            k = bisect_left(centers, target)
            if k < len(centers):
                closest = min(closest, centers[k] - target)
            if k:
                closest = min(closest, target - centers[k - 1])
    return closest - 3 * radius

if __name__ == '__main__':
    bounds = [(2 * Q, 2 * Q), (0, 0), (-2 * Q, -2 * Q)]
    for log_side in range(3, 11):
        side = 1 << log_side
        bounds = double_side(bounds)
        if side < 32:
            continue
        gap = gap_bound(bounds)
        n = side ** 3
        # ||A^-1||_1 <= sqrt(n) / gap (in real units).
        assert gap > 0 and n * Q**2 < (10**16 * gap)**2
        shift_bits = (16, 19, 19, 24, 27, 32)[log_side - 5]
        assert 64 * Q < gap * (1 << shift_bits)
        print(f'side={side} min_abs_eigenvalue>={gap / Q:.9g} '
              f'kappa_2<={7 * Q / gap:.9g} inverse_1<={n**0.5 * Q / gap:.9g}')
