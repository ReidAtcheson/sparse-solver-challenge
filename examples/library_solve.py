#!/usr/bin/env python3
"""Solve the registered July tridiagonal fixture through libstencil.

    make stencil libstencil.so
    python3 examples/library_solve.py output-directory

Linux, Python standard library. Uses the local timing provider for this demo.
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


def solve_tridiagonal(api, instance, x):
    """Thomas elimination from generated CSR batches. x stores the modified RHS."""
    n = len(x)
    upper = (C.c_double * n)()
    batch = min(n, 256)
    capacity = api.stencil_max_row_terms(instance) * batch
    cols = (C.c_uint32 * capacity)()
    vals = (C.c_double * capacity)()
    offsets = (C.c_uint64 * (batch + 1))()
    rhs = (C.c_double * batch)()
    for first in range(0, n, batch):
        count = min(batch, n - first)
        checked(api.stencil_rows(instance, first, count, offsets, cols, vals, capacity, rhs))
        for k in range(count):
            i = first + k
            lower = diag = above = 0.0
            for j in range(offsets[k], offsets[k + 1]):
                if cols[j] == i - 1:
                    lower = vals[j]
                elif cols[j] == i:
                    diag = vals[j]
                elif cols[j] == i + 1:
                    above = vals[j]
                else:
                    raise ValueError("expected the July tridiagonal profile")
            if i:
                diag -= lower * upper[i - 1]
                rhs[k] -= lower * x[i - 1]
            upper[i] = above / diag
            x[i] = rhs[k] / diag
    for i in range(n - 2, -1, -1):
        x[i] -= upper[i] * x[i + 1]


def run(output, rows, binary, library):
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
        cli("startblog", sk, rows, "python-example", start)
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
                        solve_tridiagonal(api, handle, x)
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
    cli("verify", pub, proof, start)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new directory for public artifacts")
    parser.add_argument("--rows", type=int, default=1024)
    args = parser.parse_args()
    run(args.output.resolve(), args.rows, ROOT / "stencil", ROOT / "libstencil.so")
