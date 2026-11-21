#!/usr/bin/env python3
"""Benchmark the default three-band challenge with local signed practice receipts on Linux."""
import argparse
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import tempfile

from run import ROOT, sha
from run3d import machine, measure, write_json


PROFILE = b"signed-three-band-backward80-v1"


def trial(helper, binary, case, work, checkpoint, public_dir):
    n = case["rows"]
    env = {**os.environ, "OPENBLAS_NUM_THREADS": "1", "OMP_NUM_THREADS": "1",
           "MKL_NUM_THREADS": "1", "BLIS_NUM_THREADS": "1", "TMPDIR": str(work)}

    def stage(name, cwd, *args, discard_stdout=False):
        return measure(helper, [binary, *map(str, args)], cwd, env, case, name,
                       checkpoint, discard_stdout=discard_stdout)

    with tempfile.TemporaryDirectory(dir=work, prefix="public-") as replay:
        v = Path(replay)
        with tempfile.TemporaryDirectory(dir=work, prefix="solver-") as private:
            p = Path(private)
            stage("keygen", p, "keygen", "sk", "authority.pub")
            stage("start", p, "start", "sk", n, f"three-band-{n}-{case['trial']}", "start.receipt")
            start = (p / "start.receipt").read_bytes()
            if (len(start) != 192 or start[88:128].rstrip(b"\0") != PROFILE
                    or int.from_bytes(start[8:12], "little") != n):
                raise ValueError("start receipt does not bind the requested three-band challenge")
            seed = bytes.fromhex(sha(b"stencil-instance-seed-v1" + start))
            case["seed_hex"] = seed.hex()
            case["public_key_hex"] = (p / "authority.pub").read_bytes().hex()
            case["start_receipt_hex"] = start.hex()
            stage("solve", p, "solve", "authority.pub", "start.receipt", "x.f64")
            if (p / "x.f64").stat().st_size != n * 8:
                raise ValueError("solver wrote an unexpected number of binary64 coordinates")
            stage("commit", p, "commit", "authority.pub", "start.receipt", "x.f64", "cache", "digest")
            stage("stamp", p, "stamp", "sk", "start.receipt", "digest", "finish.receipt")
            stage("prove", p, "prove", "authority.pub", "start.receipt", "finish.receipt",
                  "x.f64", "cache", "proof.bin")
            for name in ("authority.pub", "start.receipt", "proof.bin"):
                shutil.copyfile(p / name, v / name)

        # The private directory, including the solution, is gone before verification.
        # The transcript contains the signed finish receipt.
        score = stage("verify", v, "verify", "authority.pub", "proof.bin", "start.receipt")
        fields = dict(re.findall(r"(\w+)=([^\s]+)", score))
        if (fields.get("target") != "pass" or "backward_2_upper" not in fields
                or int(fields["rows"]) != n or fields["attempt"] != sha(b"stencil-attempt-v1" + start)):
            raise ValueError("validator returned an unexpected score: " + score)
        case["verified"] = fields
        case["proof_bytes"] = (v / "proof.bin").stat().st_size
        case["proof_sha256"] = sha((v / "proof.bin").read_bytes())
        if public_dir:
            shutil.copytree(v, public_dir / f"n-{n}-trial-{case['trial']}")

        # Replay the exact raw signed matrix in a fresh process, discard its text
        # stream, and charge the serialization overhead to this diagnostic alone.
        pattern, sign = struct.unpack_from("<QQ", seed)
        stage("stream_matrix_market", v, "three-band", n, pattern, "--sign-seed", sign,
              discard_stdout=True)
        case["status"] = "complete"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "stencil")
    parser.add_argument("--sizes", type=int, nargs="+", default=[1024, 4096, 8192, 16384])
    parser.add_argument("--trials", type=int, default=1)
    parser.add_argument("--output", type=Path, required=True, help="new JSON results file")
    parser.add_argument("--public-dir", type=Path, help="new directory for public replays")
    args = parser.parse_args()
    if (args.trials < 1 or len(set(args.sizes)) != len(args.sizes)
            or any(not 1024 <= n <= 65536 or n & (n - 1) for n in args.sizes)):
        parser.error("use positive trials and distinct powers of two from 1024 to 65536")
    if args.output.exists() or (args.public_dir and args.public_dir.exists()):
        parser.error("choose new output paths")
    binary = args.binary.resolve(strict=True)
    solver = binary.parent / "libstencil_superlu.so"
    if not solver.is_file():
        parser.error("install SuperLU development headers and rebuild the reference solver")
    if args.public_dir:
        args.public_dir.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="three-band-bench-") as tmp:
        work = Path(tmp)
        host = machine(work)
        host.pop("hostname")
        host.pop("scratch_root")
        metadata = {"profile": PROFILE.decode(), "machine": host, "solver_threads": 1,
                    "receipt_provider": "local Ed25519", "binary_sha256": sha(binary.read_bytes()),
                    "solver_sha256": sha(solver.read_bytes()), "runs": []}
        if shutil.which("pkg-config"):
            version = subprocess.run(["pkg-config", "--modversion", "superlu"], text=True, capture_output=True)
            if version.returncode == 0:
                metadata["superlu_version"] = version.stdout.strip()
        cc = shlex.split(os.environ.get("CC", "cc"))
        metadata["compiler"] = subprocess.check_output([*cc, "--version"], text=True).splitlines()[0]
        linkage = subprocess.check_output(["ldd", solver], text=True)
        blas = re.search(r"\blib(?:open)?blas\.so[^ ]* => (\S+)", linkage)
        if blas:
            metadata["blas_library"] = str(Path(blas[1]).resolve())
        helper = work / "measure"
        subprocess.run([*cc, "-O2", "-std=c11",
                        ROOT / "benchmarks/measure.c", "-o", helper], check=True)

        def checkpoint():
            write_json(args.output, metadata)

        for n in args.sizes:
            for number in range(1, args.trials + 1):
                print(f"{n} rows, trial {number}", flush=True)
                case = {"rows": n, "nnz": 7*n - 12, "trial": number,
                        "status": "running", "stages": {}}
                metadata["runs"].append(case)
                try:
                    trial(helper, binary, case, work, checkpoint, args.public_dir)
                except (RuntimeError, ValueError) as error:
                    case.update(status="failed", error=str(error))
                    print(error, flush=True)
                checkpoint()
        if any(case["status"] != "complete" for case in metadata["runs"]):
            raise SystemExit(1)


if __name__ == "__main__":
    main()
