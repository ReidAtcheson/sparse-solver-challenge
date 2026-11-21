"""Exercise the UNIX entry point and, optionally, compare with NumPy 2.3.5."""
import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "stencil"


def run(*args, perm=None, success=True):
    result = subprocess.run([BINARY, "three-band", *map(str, args)], input=perm,
                            text=True, capture_output=True)
    if success:
        assert result.returncode == 0, result.stderr
        return result.stdout
    assert result.returncode > 0 and not result.stdout, result


def read_triangle(output, n):
    header, shape, *lines = output.splitlines()
    assert header == "%%MatrixMarket matrix coordinate real symmetric"
    assert tuple(map(int, shape.split())) == (n, n, 4*n-6)
    entries = {}
    for line in lines:
        row, col, sign = map(int, line.split())
        assert 1 <= col <= row <= n and sign in (-1, 1)
        entries[row-1, col-1] = sign
    assert len(entries) == len(lines) == 4*n-6
    assert all((i, i) in entries for i in range(n))
    return entries


def compare_reference():
    sys.path.insert(0, str(ROOT))
    from examples.three_band_reference import generate_pattern, sign_pattern
    import numpy as np
    if np.__version__ != "2.3.5":
        sys.exit(f"Exact replay tests require NumPy 2.3.5 (found {np.__version__})")
    for n, seed in [(3, 7), (101, 1), (128, 42), (216, 2**64-1), (1331, 42), (1728, 19)]:
        pattern = generate_pattern(n, seed)
        permutation = np.roll(np.arange(n), 3)
        for args, kwargs, p in [
            (["--sign-draw", 7], {"sign_draw": 7}, None),
            (["--sign-seed", 2**63+15, "--perm", "-"],
             {"sign_seed": 2**63+15, "permutation": permutation}, permutation),
        ]:
            matrix = sign_pattern(pattern, **kwargs).tocoo()
            expected = {(i, j): s for i, j, s in zip(matrix.row, matrix.col, matrix.data) if i >= j}
            stdin = None if p is None else " ".join(map(str, p))
            assert read_triangle(run(n, seed, *args, perm=stdin), n) == expected, (n, seed, args)
    print("PASS native signed matrices matched NumPy 2.3.5 / SciPy, including METIS diagonal replay")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interoperability", action="store_true")
    options = parser.parse_args()
    assert run(25, 0) == run(25, 0, "--sign-draw", 1)
    original = read_triangle(run(25, 8, "--sign-seed", 0), 25)
    indices = list(range(1, 25)) + [0]
    replay = read_triangle(run(25, 8, "--sign-seed", 0, "--perm", "-",
                               perm=" ".join(map(str, indices))), 25)
    for (i, j), value in original.items():
        assert replay[(indices[i], indices[i]) if i == j else (i, j)] == value
    singular = read_triangle(run(3, 7, "--sign-draw", 3), 3)
    a, b, c, d, e, f = (singular[k] for k in [(0,0), (1,0), (2,0), (1,1), (2,1), (2,2)])
    assert a*(d*f-e*e) - b*(b*f-c*e) + c*(b*e-c*d) == 0
    for bad in ("0 0 2", "1 2", "0 1 2 0", "0 1 3", "0 1 2x", ""):
        run(3, 42, "--perm", "-", perm=bad, success=False)
    for args in [(2, 0), (3, -1), (3, 0, "--sign-draw", 0), (3, 0, "--sign-seed"),
                 (3, 0, "--sign-seed", 1, "--sign-draw", 2), (3, 2**64)]:
        run(*args, success=False)
    print("PASS three-band CLI, sparse format, singular draw and malformed inputs")
    if options.interoperability:
        compare_reference()
