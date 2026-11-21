#!/usr/bin/env python3
"""Check the shared-library ABI against the CLI wire format and independent physical rows."""
import ctypes as C
import errno
import hashlib
import os
import struct
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples"))
from library_solve import Handle, checked, load, run

PROFILES = (
    ("start", "signed-three-band-backward80-v2", 1024, 1),
    ("startblog", "july-tridiagonal-fixed-nonce-80-v1", 1024, 1),
    ("startsigned3d", "signed-unit-torus-3d-backward80-v2", 32, 3),
    ("start3d", "seeded-stencil-3d-exact-residual-v1", 32, 3),
    ("start2d", "seeded-stencil-exact-residual-v1", 512, 2),
)


def three_band_reference(binary, n, seed):
    pattern, sign, rhs_a, rhs_b = (int.from_bytes(seed[i:i+8], "little") for i in range(0, 32, 8))
    output = subprocess.check_output([binary, "three-band", str(n), str(pattern),
                                      "--sign-seed", str(sign)], text=True)
    rows = [[] for _ in range(n)]
    for line in output.splitlines()[2:]:
        i, j, value = map(int, line.split())
        rows[i-1].append((j-1, value))
        if i != j:
            rows[j-1].append((i-1, value))
    assert sum(map(len, rows)) == 7*n - 12
    mask = (1 << 64) - 1

    def mix(x):
        x = ((x ^ (x >> 30)) * 0xbf58476d1ce4e5b9) & mask
        x = ((x ^ (x >> 27)) * 0x94d049bb133111eb) & mask
        return x ^ (x >> 31)

    key = mix(rhs_a ^ mix(rhs_b))
    return [(sorted(row), (1 if mix((key+i) & mask) >> 63 else -1) / n)
            for i, row in enumerate(rows)]


def check_published_three_band(api):
    # Known answers from the original bounded release (6610045), physical row order.
    n = 4096
    nnz = 7*n - 12
    seed = (C.c_uint8 * 32)(*range(32))
    handle = Handle()
    checked(api.stencil_instance_from_seed(b"signed-three-band-backward80-v2", n, seed,
                                           C.byref(handle)))
    offsets = (C.c_uint64 * (n + 1))()
    columns = (C.c_uint32 * nnz)()
    values = (C.c_double * nnz)()
    rhs = (C.c_double * n)()
    try:
        checked(api.stencil_rows(handle, 0, n, offsets, columns, values, nnz, rhs))
    finally:
        api.stencil_close(handle)
    assert offsets[0] == 0 and offsets[n] == nnz
    physical = bytes(offsets) + bytes(columns) + bytes(values)
    assert hashlib.sha256(physical).hexdigest() == (
        "4e7d72ff81cb55415c19848cc082c8b2e4f293bf73e7a45d04cfa90df7b21cd7")
    assert hashlib.sha256(bytes(rhs)).hexdigest() == (
        "d6b602cd679a28fee69e3f02a832de0dde513e0ecb27279c0ec23db243c8d714")
    diagonal = bytearray()
    for row in range(n):
        for k in range(offsets[row], offsets[row + 1]):
            if columns[k] == row:
                diagonal.extend(struct.pack("<d", values[k]))
    assert len(diagonal) == 8*n and hashlib.sha256(diagonal).hexdigest() == (
        "b91eac4571384fb01eb1565560b63a6298c8dde017146a28f393dea76b6d32d1")


def check_profile(work, api, binary, command, profile, side, dimensions):
    def cli(*args):
        subprocess.run([binary, *map(str, args)], cwd=work, check=True)

    start = work / command
    start_command = (command,) if command == "start" else ("fixture", command)
    cli(*start_command, "sk", side, "ffi-test", start)
    seed = hashlib.sha256(b"stencil-instance-seed-v1" + start.read_bytes()).digest()
    seed_buf = (C.c_uint8 * 32).from_buffer_copy(seed)
    a, b = Handle(), Handle()
    checked(api.stencil_instance_open(os.fsencode(work / "pk"), os.fsencode(start), C.byref(a)))
    checked(api.stencil_instance_from_seed(profile.encode(), side, seed_buf, C.byref(b)))
    n, degree = side**dimensions, 1 + 2 * dimensions
    if command == "start":
        reference = three_band_reference(binary, n, seed)
        degree = max(len(row) for row, rhs in reference)
    for h in (a, b):
        assert api.stencil_row_count(h) == n and api.stencil_max_row_terms(h) == degree

    def row(h, i):
        offsets = (C.c_uint64 * 2)(9, 9)
        cols = (C.c_uint32 * degree)()
        vals = (C.c_double * degree)()
        rhs = C.c_double()
        checked(api.stencil_rows(h, i, 1, offsets, cols, vals, degree, C.byref(rhs)))
        assert offsets[0] == 0 and 0 < offsets[1] <= degree
        return list(zip(cols[:offsets[1]], vals[:offsets[1]])), rhs.value

    for i in (reversed(range(n)) if command == "start" else [n - 1, 0, 3, n // 2]):
        terms, rhs = row(a, i)
        assert row(b, i) == (terms, rhs)
        if command == "start":
            assert (terms, rhs) == reference[i]
        elif command == "startblog":
            assert (i, 0.5) in terms and all(v == 0.0625 for j, v in terms if j != i)
            assert 144 <= abs(rhs) * 256 <= 207
        elif command == "startsigned3d":
            assert len(terms) == degree and (i, 1) in terms
            assert all(abs(v) == 1 for _, v in terms) and abs(rhs) == 1 / n
        else:
            assert all(-4 <= v <= -1 for j, v in terms if j != i) and abs(rhs) == 1
    offsets = (C.c_uint64 * 2)()
    rhs = C.c_double()
    assert api.stencil_rows(a, n, 1, offsets, None, None, 0, C.byref(rhs)) == errno.EINVAL
    assert api.stencil_rows(a, 0, 1, offsets, None, None, 0, C.byref(rhs)) == errno.ENOBUFS
    checked(api.stencil_rows(a, n, 0, offsets, None, None, 0, None))
    # A sparse nonzero test vector makes both CLI and FFI produce an actual group element.
    x = (C.c_double * n)()
    x[n // 3] = -0.5
    cache = (C.c_uint8 * api.stencil_commit_size(a))()
    digest = (C.c_uint8 * 32)()
    assert api.stencil_commit(a, x, n - 1, cache, len(cache), digest) == errno.EINVAL
    checked(api.stencil_commit(a, x, n, cache, len(cache), digest))
    # A private reference file exercises the legacy byte format in this test only.
    (work / "solution").write_bytes(memoryview(x).cast("B"))
    cli("commit", "pk", start, "solution", command + "-rows", command + "-digest")
    assert (work / (command + "-rows")).read_bytes() == bytes(cache)
    assert (work / (command + "-digest")).read_bytes() == bytes(digest)
    x[0] = float("nan")
    assert api.stencil_commit(a, x, n, cache, len(cache), digest) == errno.ERANGE
    for h in (a, b):
        api.stencil_close(h)
    assert api.stencil_instance_from_seed(profile.encode(), 17, seed_buf, C.byref(b)) == errno.EINVAL
    assert not b.value
    bad = bytearray(start.read_bytes())
    bad[-1] ^= 1
    (work / "bad").write_bytes(bad)
    assert api.stencil_instance_open(os.fsencode(work / "pk"), os.fsencode(work / "bad"),
                                    C.byref(a)) != 0 and not a.value


if __name__ == "__main__":
    binary = ROOT / "stencil"
    library = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "libstencil.so"
    api = load(library)
    check_published_three_band(api)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        subprocess.run([binary, "keygen", "sk", "pk"], check=True, cwd=work)
        for case in PROFILES:
            check_profile(work, api, binary, *case)
        public = work / "public"
        # A known miss exercises the full private FD handoff on a verifier-only
        # build, including machines with neither SciPy nor the optional C solver.
        def test_candidate(api, instance, x):
            x[0] = 1 / len(x)
        assert run(public, 1024, binary, library, solve=test_candidate) == 3
        start = (public / "start.receipt").read_bytes()
        assert start[88:128].rstrip(b"\0") == b"signed-three-band-backward80-v2"
        assert {p.name for p in public.iterdir()} == {"authority.pub", "start.receipt", "proof.bin"}
    print("PASS in-memory CSR profiles, CLI-identical commitments, private fd handoff and public replay")
