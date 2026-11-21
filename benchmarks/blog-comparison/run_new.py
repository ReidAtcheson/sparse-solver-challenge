#!/usr/bin/env python3
"""Benchmark the C exact protocol on the July problem and compare every solver coordinate.

The July checkout supplies its original example spec and solver library. Only
the row count in the checked-in example changes. The independent solver and
Python integer oracle run outside the C stage measurements.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from run3d import ROOT, machine, measure, write_json

PROFILE = b"july-tridiagonal-fixed-nonce-80-v1"
NONCE = "9f36a2c4d7815be0084d63a912f7c5b34e1860dafb295c73a6418ed02bc9574f"


def file_digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def compile_exporter(repo, work):
    # A small standalone crate links the July implementation directly, keeping
    # its witness available for comparison without modifying the upstream tree.
    crate = work / "oracle"
    (crate / "src").mkdir(parents=True)
    shutil.copyfile(HERE / "export_july.rs", crate / "src/main.rs")
    shutil.copyfile(repo / "Cargo.lock", crate / "Cargo.lock")
    manifest = ['[package]', 'name="export-july"', 'version="0.1.0"', 'edition="2021"',
                '[dependencies]']
    for name in ("problem", "solver"):
        manifest.append(f'sparse-stark-{name} = {{ path = {json.dumps(str(repo/"crates"/name))} }}')
    (crate / "Cargo.toml").write_text("\n".join(manifest) + "\n")
    shutil.copyfile(repo / "rust-toolchain.toml", crate / "rust-toolchain.toml")
    subprocess.run(["cargo", "build", "--release", "--offline"], cwd=crate, check=True,
                   env={**os.environ, "CARGO_TARGET_DIR": str(crate / "target")})
    return crate / "target/release/export-july"


def rhs_period(nonce):
    seed = bytes.fromhex(nonce)
    codes = []
    for row in range(1024):
        outputs = []
        for bit in range(7):
            a, b, c, d = [(row >> (x % 10)) & 1 for x in seed[4*bit:4*bit+4]]
            outputs.append(a ^ b ^ (c & d) ^ ((seed[28] >> bit) & 1))
        magnitude = 144 + sum(b << j for j, b in enumerate(outputs[:6]))
        codes.append(-magnitude if outputs[6] else magnitude)
    return codes


def exact_scores(n, solution, july_witness, nonce):
    """Compare signed Q63.64 bytes, streamed in blocks; recreate the physical residual."""
    if solution.stat().st_size != n*8 or july_witness.stat().st_size != n*16:
        raise ValueError("invalid solver output length")
    codes = rhs_period(nonce)
    previous = current = max_abs = q64_energy = rho = pos = 0
    with solution.open("rb") as x, july_witness.open("rb") as ref:
        while raw := x.read(8*8192):
            q64 = ref.read(2*len(raw))
            for j, (xf,) in enumerate(struct.iter_unpack("<d", raw)):
                y = int.from_bytes(q64[16*j:16*j+16], "little", signed=True)
                scaled = math.ldexp(xf, 64)
                if not scaled.is_integer() or int(scaled) != y:
                    raise ValueError(f"July and C encoded solutions differ at coordinate {pos}")
                if pos:
                    residual = previous + 8*current + y - (codes[(pos-1) % 1024] << 60)
                    rho += residual**2
                max_abs = max(max_abs, abs(y))
                q64_energy += y*y
                previous, current = current, y
                pos += 1
    last = previous + 8*current - (codes[(n-1) % 1024] << 60)
    rho += last**2
    # The July Q63.64 values are small in this fixture; X = Y * 2^(14-E).
    exponent = (max_abs-1).bit_length()-64 if max_abs else 0
    shift = 14-exponent
    if shift < 0:
        raise ValueError("July fixture exceeds injective embedding for this scale")
    rhs_norm = math.sqrt(sum(code**2 for code in codes) * (n//1024)) / 256
    x_norm = math.ldexp(math.sqrt(q64_energy), -64)
    r_norm = math.ldexp(math.sqrt(rho), -68)
    return {"checked_coordinates": pos, "july_q64_sha256": file_digest(july_witness),
            "c_binary64_sha256": file_digest(solution), "july_rho": str(rho),
            "july_squared_residual_denominator_exponent": 136, "exponent": exponent,
            "new_rho": str(rho << (2*shift)), "new_x_squared": str(q64_energy << (2*shift)),
            "relative_rhs": r_norm/rhs_norm,
            "backward_2_upper": r_norm/(((10-2/n)/16)*x_norm+rhs_norm)}


def run_size(args, helper, exporter, spec, n, work, report, checkpoint):
    spec = {**spec, "matrix": {**spec["matrix"], "dimension": n}}
    (work/"problem.json").write_text(json.dumps(spec))
    with (work/"july.q64").open("wb") as f:
        subprocess.run([exporter, work/"problem.json"], check=True, stdout=f)

    for trial in range(1, args.trials + 1):
        print(f"{n} rows, C trial {trial}/{args.trials}", flush=True)
        case = {"rows": n, "trial": trial, "stages": {}, "status": "started"}
        report["runs"].append(case)
        with tempfile.TemporaryDirectory(dir=work) as temp:
            p = Path(temp)
            v = p / "validator"
            v.mkdir()
            def stage(name, command, *fields, cwd=p):
                return measure(helper, [args.binary, command, *map(str, fields)], cwd,
                               {**os.environ, "TMPDIR": str(p)}, case, name, checkpoint)

            stage("keygen", "keygen", "sk", "pk")
            stage("start", "startblog", "sk", n, f"july-{n}-{trial}", "start")
            if (p/"start").read_bytes()[88:128].rstrip(b"\0") != PROFILE:
                raise ValueError("unexpected signed profile")
            stage("solve", "solve", "pk", "start", "x")
            stage("commit", "commit", "pk", "start", "x", "rows", "digest")
            stage("stamp", "stamp", "sk", "start", "digest", "finish")
            stage("prove", "prove", "pk", "start", "finish", "x", "rows", "proof")
            if trial == 1:
                oracle = exact_scores(n, p/"x", work/"july.q64", spec["challenge_nonce"])
                report["oracle_by_rows"][str(n)] = oracle
            elif file_digest(p/"x") != report["oracle_by_rows"][str(n)]["c_binary64_sha256"]:
                raise ValueError("solver output changed between trials")
            (p/"x").unlink()
            (p/"rows").unlink()
            for src, dst in [("pk","authority.pub"), ("start","start.receipt"), ("proof","proof.bin")]:
                shutil.copyfile(p/src, v/dst)
            output = stage("verify", "verify", "authority.pub", "proof.bin", "start.receipt", cwd=v)
            fields = dict(re.findall(r"(\w+)=(\S+)", output))
            oracle = report["oracle_by_rows"][str(n)]
            if (fields["target"] != "pass" or int(fields["rows"]) != n or
                    int(fields["exponent"]) != oracle["exponent"] or fields["rho"] != oracle["new_rho"]
                    or fields["x_squared"] != oracle["new_x_squared"]):
                raise ValueError(f"certified values differ from independent oracle: {output}")
            for key in ("relative_rhs", "backward_2_upper"):
                if not math.isclose(oracle[key], float(fields[key]), rel_tol=1e-14):
                    raise ValueError(f"unexpected {key}: {output}")
            L = n.bit_length()-1
            w = 1 << (L//2)
            proof_bytes = (v/"proof.bin").stat().st_size
            if proof_bytes != 32*(w+n//w)+128*L+2508:
                raise ValueError("proof file length differs from framing")
            case.update({"verified": fields, "status": "complete", "proof_bytes": proof_bytes,
                         "peak_large_scratch_bytes": 32*n, "proof_sha256": file_digest(v/"proof.bin"),
                         "commit_prove_max_rss_kib": max(case["stages"][k]["peak_rss_kib"]
                                                        for k in ("commit","prove")),
                         "solve_commit_prove_max_rss_kib": max(case["stages"][k]["peak_rss_kib"]
                                                              for k in ("solve","commit","prove"))})
            if args.public_dir and n == max(args.rows) and trial == 1:
                args.public_dir.mkdir(parents=True, exist_ok=True)
                for f in v.iterdir():
                    shutil.copyfile(f, args.public_dir/f.name)
            checkpoint()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--july-repo", type=Path, required=True)
    parser.add_argument("--july-exporter", type=Path, help="prebuilt export_july.rs executable")
    parser.add_argument("--july-results", type=Path, help="compare the independent oracle against verified WHIR scores")
    parser.add_argument("--binary", type=Path, default=ROOT/"stencil")
    parser.add_argument("--rows", type=int, nargs="+", default=[1<<i for i in range(10,21)])
    parser.add_argument("--trials", type=int, default=1)
    parser.add_argument("--scratch-dir", type=Path, default=Path(tempfile.gettempdir()))
    parser.add_argument("--output", type=Path, default=HERE/"new-results.json")
    parser.add_argument("--public-dir", type=Path)
    args = parser.parse_args()
    if (args.trials < 1 or len(set(args.rows)) != len(args.rows) or
            any(n < 1024 or n > 2**30 or n & (n-1) for n in args.rows)):
        parser.error("choose unique power-of-two row counts in [2^10, 2^30] and positive trials")
    repo = args.july_repo.resolve(strict=True)
    args.binary = args.binary.resolve(strict=True)
    args.scratch_dir = args.scratch_dir.resolve(strict=True)
    template = repo/"examples/random-tridiagonal-whir-field192-l2-v4.json"
    spec = json.loads(template.read_bytes())
    if spec["challenge_nonce"] != NONCE or spec["rhs"]["kind"] != "seeded-dyadic-v1":
        raise ValueError("unexpected July example")
    report = {"machine": machine(args.scratch_dir), "protocol_binary_sha256": file_digest(args.binary),
              "july_checkout": subprocess.check_output(["git","-C",repo,"rev-parse","HEAD"], text=True).strip(),
              "july_example": spec, "rss_method": "Linux wait4.ru_maxrss, KiB, fresh process per stage",
              "threads": 1, "runs": [], "oracle_by_rows": {}}
    if report["machine"]["scratch_filesystem"] in ("tmpfs", "ramfs"):
        parser.error("choose disk-backed scratch for comparable RSS")
    def checkpoint():
        write_json(args.output, report)
    with tempfile.TemporaryDirectory(prefix="july-c-comparison-", dir=args.scratch_dir) as d:
        work = Path(d)
        exporter = args.july_exporter.resolve(strict=True) if args.july_exporter else compile_exporter(repo, work)
        report["july_exporter_sha256"] = file_digest(exporter)
        helper = work/"measure"
        subprocess.run([*shlex.split(os.environ.get("CC","cc")), "-O2", ROOT/"benchmarks/measure.c",
                        "-o", helper], check=True)
        for n in sorted(args.rows):
            with tempfile.TemporaryDirectory(dir=work) as run:
                run_size(args, helper, exporter, spec, n, Path(run), report, checkpoint)
    if args.july_results:
        old = json.loads(args.july_results.read_bytes())
        if old["challenge_nonce"] != NONCE:
            raise ValueError("July measurements use a different RHS nonce")
        matched = []
        for case in old["exact"]["runs"]:
            n = case["rows"]
            if n not in args.rows:
                continue
            oracle = report["oracle_by_rows"][str(n)]
            if (case["status"] != "verified" or case["residual_numerator"] != oracle["july_rho"]
                    or case["residual_denominator_power"] != 136):
                raise ValueError(f"July proof reports a different physical energy at n={n}")
            matched.append(n)
        if not matched:
            raise ValueError("no common measured dimension")
        report["compared_whir_proof_rows"] = sorted(matched)
        checkpoint()


if __name__ == "__main__":
    main()
