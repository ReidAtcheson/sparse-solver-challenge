#!/usr/bin/env python3
"""Solve the bounded three-band challenge in memory with SciPy and libstencil.

    make
    python3 examples/library_solve.py output-directory

Linux, Python 3, NumPy and SciPy. This demo uses local signed practice receipts.
Only authority.pub, start.receipt and proof.bin are published in a new directory.
"""
import argparse
import ctypes as C
import mmap
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
U8 = C.POINTER(C.c_uint8)
U32 = C.POINTER(C.c_uint32)
U64 = C.POINTER(C.c_uint64)
F64 = C.POINTER(C.c_double)
Handle = C.c_void_p


def load(path):
    api = C.CDLL(str(path))
    api.stencil_instance_open.argtypes = [C.c_char_p, C.c_char_p, C.POINTER(Handle)]
    api.stencil_instance_from_seed.argtypes = [C.c_char_p, C.c_uint32, U8, C.POINTER(Handle)]
    api.stencil_close.argtypes = [Handle]
    api.stencil_close.restype = None
    api.stencil_row_count.argtypes = [Handle]
    api.stencil_row_count.restype = C.c_uint64
    api.stencil_max_row_terms.argtypes = [Handle]
    api.stencil_max_row_terms.restype = C.c_uint
    api.stencil_rows.argtypes = [Handle, C.c_uint64, C.c_size_t, U64, U32, F64, C.c_size_t, F64]
    api.stencil_commit_size.argtypes = [Handle]
    api.stencil_commit_size.restype = C.c_size_t
    api.stencil_commit.argtypes = [Handle, F64, C.c_size_t, U8, C.c_size_t, U8]
    return api


def checked(status):
    if status:
        raise OSError(status, os.strerror(status))


def solve_sparse(api, instance, x):
    """Get the seeded system in CSR form and write the refined solution into x."""
    import numpy as np
    from scipy.sparse import csr_matrix
    from scipy.sparse.linalg import splu

    n = len(x)
    nnz = 7*n - 12
    offsets = np.empty(n + 1, dtype=np.uint64)
    columns = np.empty(nnz, dtype=np.uint32)
    values = np.empty(nnz, dtype=np.float64)
    rhs = np.empty(n, dtype=np.float64)
    checked(api.stencil_rows(instance, 0, n, offsets.ctypes.data_as(U64),
                             columns.ctypes.data_as(U32), values.ctypes.data_as(F64),
                             nnz, rhs.ctypes.data_as(F64)))
    if offsets[-1] != nnz:
        raise ValueError("unexpected entry count for bounded three-band system")
    a = csr_matrix((values, columns, offsets), shape=(n, n))
    factors = splu(a.tocsc(), permc_spec="MMD_AT_PLUS_A")
    solution = np.ctypeslib.as_array(x)
    solution[:] = factors.solve(rhs)
    # Accumulate residuals in extended precision and reuse the binary64 factors.
    high_a = a.astype(np.longdouble)
    high_rhs = rhs.astype(np.longdouble)
    for _ in range(2):
        residual = high_rhs - high_a @ solution
        solution += factors.solve(residual.astype(np.float64))


def run(output, rows, binary, library, solve=solve_sparse):
    """Return the validator exit code after replay against the public bundle."""
    binary = Path(binary).resolve()
    api = load(library)
    output.mkdir()
    pub, start, proof = (output / name for name in ("authority.pub", "start.receipt", "proof.bin"))
    with tempfile.TemporaryDirectory() as private:
        work = Path(private)
        sk, finish = work / "secret", work / "finish"
        cache_path, digest_path = work / "rows", work / "digest"

        def cli(*args, **options):
            subprocess.run([binary, *map(str, args)], check=True, **options)

        cli("keygen", sk, pub)
        cli("start", sk, rows, "python-example", start)
        handle = Handle()
        checked(api.stencil_instance_open(os.fsencode(pub), os.fsencode(start), C.byref(handle)))
        try:
            n = api.stencil_row_count(handle)
            # Solve directly into the shared pages that the proving worker will read.
            # Other solvers may supply a contiguous float64 array to stencil_commit.
            with os.fdopen(os.memfd_create("stencil-witness"), "w+b") as witness:
                witness.truncate(8 * n)
                with mmap.mmap(witness.fileno(), 0) as memory:
                    x = (C.c_double * n).from_buffer(memory)
                    try:
                        solve(api, handle, x)
                        cache = (C.c_uint8 * api.stencil_commit_size(handle))()
                        digest = (C.c_uint8 * 32)()
                        checked(api.stencil_commit(handle, x, n, cache, len(cache), digest))
                    finally:
                        del x
                # The authority receives the digest. Only the proving worker inherits
                # the solution descriptor. It also needs the private commitment cache.
                digest_path.write_bytes(bytes(digest))
                cli("stamp", sk, start, digest_path, finish)
                cache_path.write_bytes(bytes(cache))
                fd = witness.fileno()
                cli("prove", pub, start, finish, f"/proc/self/fd/{fd}", cache_path, proof,
                    pass_fds=(fd,))
        finally:
            api.stencil_close(handle)
    return subprocess.run([binary, "verify", pub.name, proof.name, start.name], cwd=output).returncode


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new directory for public artifacts")
    parser.add_argument("--rows", type=int, default=1024)
    args = parser.parse_args()
    # Load the numerical backend before the signed clock starts.
    try:
        import scipy.sparse.linalg
    except ImportError as error:
        parser.exit(2, f"Install NumPy and SciPy to run this solver example ({error}).\n")
    raise SystemExit(run(args.output.resolve(), args.rows, ROOT / "stencil", ROOT / "libstencil.so"))
