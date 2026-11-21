#!/usr/bin/env python3
"""Measure the shared-exponent 3D profile and replay the legacy baseline at equal size."""
import argparse
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import tempfile

from run import ROOT, sha
from run3d import machine, measure, mix, summarize, write_json

PROFILE = b"signed-unit-torus-3d-backward80-v2"
ARCHIVE = ROOT / "benchmarks/vm-3d/retry/out/public"
PUBLIC = (("pk", "authority.pub"), ("start", "start.receipt"), ("proof", "proof.bin"))


def integer_scores(side, seed, solution):
    """Independent integer oracle for D(I + adjacency)D, keeping only neighboring planes."""
    m = side ** 3
    plane = side ** 2
    if solution.stat().st_size != m * 8:
        raise ValueError("wrong length for private binary64 solution")
    k0, _, _, k3 = struct.unpack("<4Q", seed)
    salt = mix(k3 ^ 0x7374656e63696c33)
    vertex_key, rhs_key = mix(k0 ^ salt ^ 1), mix(k3 ^ salt ^ 4)

    def sign(key, i):
        return 1 if mix(key + i) >> 63 else -1

    with solution.open("rb") as f:
        maximum = 0
        while block := f.read(8 * 8192):
            maximum = max(maximum, max(abs(v) for v, in struct.iter_unpack("<d", block)))
        fraction, exponent = math.frexp(maximum)
        if fraction == 0.5:
            exponent -= 1
        shift = 78 - exponent - (m.bit_length() - 1)
        k, h = 1 << max(-shift, 0), 1 << max(shift, 0)

        def signed_plane(z):
            start = z * plane
            f.seek(8 * start)
            cells = struct.iter_unpack("<d", f.read(8 * plane))
            return [sign(vertex_key, start + j) * round(math.ldexp(v, 78 - exponent))
                    for j, (v,) in enumerate(cells)]

        previous, current = signed_plane(side - 1), signed_plane(0)
        rho = x2 = 0
        for z in range(side):
            following = signed_plane((z + 1) % side)
            for y in range(side):
                base = y * side
                above, below = ((y-1) % side) * side, ((y+1) % side) * side
                for x in range(side):
                    j = base + x
                    i = z * plane + j
                    value = current[j]
                    matvec = (value + previous[j] + following[j]
                              + current[base + (x-1) % side] + current[base + (x+1) % side]
                              + current[above + x] + current[below + x])
                    residual = k * matvec - h * sign(vertex_key, i) * sign(rhs_key, i)
                    rho += residual * residual
                    x2 += value * value
            previous, current = current, following
    rhs = h * math.sqrt(m)
    return {"exponent": exponent, "rho": rho, "x_squared": x2,
            "relative_rhs": math.sqrt(rho) / rhs,
            "backward_2": math.sqrt(rho) / (7 * k * math.sqrt(x2) + rhs)}


def run(binary, directory, *args, status=0):
    result = subprocess.run([binary, *map(str, args)], cwd=directory, capture_output=True, text=True)
    if result.returncode != status:
        raise RuntimeError(f"{args[0]} exited {result.returncode} (expected {status}): "
                           f"{result.stdout}{result.stderr}")
    return result.stdout


def baseline_size(binary, side, work):
    old = ARCHIVE / f"grid-{side}-trial-01"
    if old.exists():
        run(binary, old, "verify", "authority.pub", "proof.bin", "start.receipt")
        return (old / "proof.bin").stat().st_size, "verified archive"
    with tempfile.TemporaryDirectory(dir=work) as path:
        p = Path(path)
        run(binary, p, "keygen", "sk", "pk")
        run(binary, p, "start3d", "sk", side, "legacy-size", "start")
        run(binary, p, "solve", "pk", "start", "x")
        run(binary, p, "commit", "pk", "start", "x", "rows", "digest")
        run(binary, p, "stamp", "sk", "start", "digest", "finish")
        run(binary, p, "prove", "pk", "start", "finish", "x", "rows", "proof")
        (p / "x").unlink()
        run(binary, p, "verify", "pk", "proof", "start")
        return (p / "proof").stat().st_size, "fresh proof"


def regression(binary, side, validator, private):
    """Reject modified authenticated fields, and certify a valid zero witness as a miss."""
    original = (validator / "proof").read_bytes()
    exponent = 8 + 192 + 160
    m = side ** 3
    width = 1 << ((m.bit_length() - 1) // 2)
    rho = exponent + 4 + (m // width) * 32
    for offset in (exponent, rho, rho + 32):
        changed = bytearray(original)
        changed[offset] ^= 1
        (validator / "changed").write_bytes(changed)
        run(binary, validator, "verify", "pk", "changed", "start", status=1)
    (validator / "changed").unlink()
    run(binary, private, "startsigned3d", "sk", side, "zero-vector", "zero-start")
    with (private / "zero-x").open("wb") as f:
        f.truncate(8 * m)
    run(binary, private, "commit", "pk", "zero-start", "zero-x", "zero-rows", "zero-digest")
    run(binary, private, "stamp", "sk", "zero-start", "zero-digest", "zero-finish")
    run(binary, private, "prove", "pk", "zero-start", "zero-finish", "zero-x", "zero-rows", "zero-proof")
    (private / "zero-x").unlink()
    for name in ("zero-proof", "zero-start"):
        shutil.copyfile(private / name, validator / name)
    score = run(binary, validator, "verify", "pk", "zero-proof", "zero-start", status=3)
    fields = dict(re.findall(r"(\w+)=(\S+)", score))
    if (int(fields["x_squared"]) != 0 or float(fields["relative_rhs"]) != 1 or
            float(fields["backward_2"]) != 1 or fields["target"] != "miss"):
        raise ValueError(score)


def trial(args, helper, p, case, checkpoint, baseline, check_regression):
    v = p / "validator"
    v.mkdir()
    side, number = case["side"], case["trial"]

    def stage(name, *args_, cwd=p, program=args.binary):
        env = {**os.environ, "TMPDIR": str(p)}
        if name == "solve" and args.solver:
            env.update(MKL_NUM_THREADS="1", OMP_NUM_THREADS="1", MKL_DYNAMIC="FALSE")
        return measure(helper, [program, *map(str, args_)], cwd, env, case, name, checkpoint)

    stage("keygen", "keygen", "sk", "pk")
    stage("start", "startsigned3d", "sk", side, f"signed-{side}-{number}", "start")
    start = (p / "start").read_bytes()
    if start[88:128].rstrip(b"\0") != PROFILE:
        raise ValueError("unexpected profile")
    if args.solver:
        stage("solve", "pk", "start", "x", program=args.solver)
    else:
        stage("solve", "solve", "pk", "start", "x")
    stage("commit", "commit", "pk", "start", "x", "rows", "digest")
    stage("stamp", "stamp", "sk", "start", "digest", "finish")
    stage("prove", "prove", "pk", "start", "finish", "x", "rows", "proof")
    seed = sha(b"stencil-instance-seed-v1" + start)
    oracle = integer_scores(side, bytes.fromhex(seed), p / "x") if number == 1 else None
    for name, _ in PUBLIC:
        shutil.copyfile(p / name, v / name)
    (p / "x").unlink()
    if set(file.name for file in v.iterdir()) != {"pk", "start", "proof"}:
        raise ValueError("unexpected verifier inputs")
    score = stage("verify", "verify", "pk", "proof", "start", cwd=v)
    fields = dict(re.findall(r"(\w+)=(\S+)", score))
    if fields["target"] != "pass" or int(fields["rows"]) != side**3:
        raise ValueError(score)
    if oracle:
        for name in ("exponent", "rho", "x_squared"):
            if oracle[name] != int(fields[name]):
                raise ValueError(f"independent {name} disagrees: {oracle[name]} vs {fields[name]}")
        for name in ("relative_rhs", "backward_2"):
            if not math.isclose(oracle[name], float(fields[name]), rel_tol=1e-15):
                raise ValueError(f"independent {name} disagrees")
    if check_regression:
        regression(args.binary, side, v, p)
    if args.public_dir:
        archive = args.public_dir / f"grid-{side}-trial-{number:02d}"
        archive.mkdir(parents=True, exist_ok=True)
        for source, name in PUBLIC:
            shutil.copyfile(v / source, archive / name)
    proof = (v / "proof").read_bytes()
    size, source = baseline
    case.update({"status": "complete", "proof_bytes": len(proof), "legacy_proof_bytes": size,
                 "legacy_baseline": source, "increase_bytes": len(proof)-size,
                 "seed": seed, "proof_sha256": sha(proof), "verified": fields, "python_oracle": oracle,
                 "commit_receipt_elapsed_s": int(fields["elapsed_ns"])*1e-9})
    if check_regression:
        case["tamper_and_zero_regression"] = "pass"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "stencil")
    parser.add_argument("--solver", type=Path, help="standalone solver, e.g. ./stencil-direct3d (one thread)")
    parser.add_argument("--sides", type=int, nargs="+", default=[32, 64, 128])
    parser.add_argument("--trials", type=int, default=1)
    parser.add_argument("--scratch-dir", type=Path, default=Path(tempfile.gettempdir()))
    parser.add_argument("--output", type=Path, default=ROOT / "benchmarks/signed3d-results.json")
    parser.add_argument("--no-save", action="store_true", help="run checks without writing a report")
    parser.add_argument("--public-dir", type=Path)
    parser.add_argument("--regression", action="store_true", help="test tampering and zero at smallest grid")
    args = parser.parse_args()
    if args.trials <= 0 or any(s < 32 or s > 1024 or s & (s-1) for s in args.sides):
        parser.error("choose a positive trial count and power-of-two cube sides in [32,1024]")
    args.binary = args.binary.resolve(strict=True)
    report = {"profile": PROFILE.decode(), "machine": machine(args.scratch_dir),
              "binary_sha256": sha(args.binary.read_bytes()), "runs": []}
    if args.solver:
        args.solver = args.solver.resolve(strict=True)
        report.update({"solver": str(args.solver), "solver_binary_sha256": sha(args.solver.read_bytes()),
                       "solver_threads_limit": 1, "mkl_dynamic": "FALSE"})

    def checkpoint():
        if not args.no_save:
            write_json(args.output, report)

    with tempfile.TemporaryDirectory(prefix="signed3d-", dir=args.scratch_dir) as path:
        work = Path(path).resolve()
        helper = work / "measure"
        subprocess.run([*shlex.split(os.environ.get("CC", "cc")), "-O2", ROOT / "benchmarks/measure.c",
                        "-o", helper], check=True)
        for side in sorted(set(args.sides)):
            baseline = baseline_size(args.binary, side, work)
            for number in range(1, args.trials + 1):
                print(f"{side}^3 trial {number}/{args.trials}", flush=True)
                case = {"side": side, "rows": side**3, "trial": number, "stages": {}, "status": "started"}
                report["runs"].append(case)
                with tempfile.TemporaryDirectory(dir=work) as attempt:
                    trial(args, helper, Path(attempt), case, checkpoint, baseline,
                          args.regression and number == 1 and side == min(args.sides))
                report["summary"] = summarize(report["runs"])
                checkpoint()
                print(f"  {case['proof_bytes']} bytes ({case['increase_bytes']:+d} vs legacy)", flush=True)


if __name__ == "__main__":
    main()
