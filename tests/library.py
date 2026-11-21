#!/usr/bin/env python3
"""Check the shared-library ABI against the CLI wire format and independent physical rows."""
import ctypes as C
import errno
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples"))
from library_solve import Handle, checked, load, run

PROFILES = (
    ("startblog", "july-tridiagonal-fixed-nonce-80-v1", 1024, 1),
    ("startsigned3d", "signed-unit-torus-3d-backward80-v2", 32, 3),
    ("start3d", "seeded-stencil-3d-exact-residual-v1", 32, 3),
    ("start", "seeded-stencil-exact-residual-v1", 512, 2),
)


def check_profile(work, api, binary, command, profile, side, dimensions):
    def cli(*args):
        subprocess.run([binary, *map(str, args)], cwd=work, check=True)

    start = work / command
    cli(command, "sk", side, "ffi-test", start)
    seed = hashlib.sha256(b"stencil-instance-seed-v1" + start.read_bytes()).digest()
    seed_buf = (C.c_uint8 * 32).from_buffer_copy(seed)
    a, b = Handle(), Handle()
    checked(api.stencil_instance_open(os.fsencode(work / "pk"), os.fsencode(start), C.byref(a)))
    checked(api.stencil_instance_from_seed(profile.encode(), side, seed_buf, C.byref(b)))
    n, degree = side**dimensions, 1 + 2 * dimensions
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

    for i in [n - 1, 0, 3, n // 2]:
        terms, rhs = row(a, i)
        assert row(b, i) == (terms, rhs)
        if command == "startblog":
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
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        subprocess.run([binary, "keygen", "sk", "pk"], check=True, cwd=work)
        for case in PROFILES:
            check_profile(work, api, binary, *case)
        public = work / "public"
        run(public, 1024, binary, library)
        assert {p.name for p in public.iterdir()} == {"authority.pub", "start.receipt", "proof.bin"}
    print("PASS in-memory CSR profiles, CLI-identical commitments, private fd handoff and public replay")
