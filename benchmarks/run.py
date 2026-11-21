#!/usr/bin/env python3
"""Measure a complete local authority/solver/proof workflow on Linux."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
from statistics import median
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
CAP = 32 * 1024 * 1024
STAGES = ("keygen", "start", "solve", "commit", "stamp", "prove", "verify")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def trial(helper, binary, side, number, tmp, capped, public_dir):
    with tempfile.TemporaryDirectory(prefix="attempt-", dir=tmp) as private:
        prover = Path(private)
        validator = prover / "validator"
        validator.mkdir()
        stages = {}

        def measure(phase, *args, directory=prover, cap=0, expected=0):
            command = ["fixture", "start2d"] if phase == "start" else [phase]
            run = subprocess.run([helper, str(cap), binary, *command, *map(str, args)],
                                 cwd=directory, text=True, capture_output=True,
                                 env={**os.environ, "TMPDIR": str(tmp)})
            record = re.search(r"^MEASURE (\d+) (\d+)\n\Z", run.stderr, re.M)
            if run.returncode != expected or not record:
                raise RuntimeError(f"{phase} exited {run.returncode}\n{run.stdout}{run.stderr}")
            metrics = {"wall_s": int(record[1]) / 1e9, "peak_rss_kib": int(record[2])}
            if not cap:
                stages[phase] = metrics
            return metrics, run.stdout.strip(), run.stderr[:record.start()].strip()

        measure("keygen", "sk", "pk")
        measure("start", "sk", side, f"benchmark-{side}-{number}", "start")
        _, _, solver_message = measure("solve", "pk", "start", "x")
        measure("commit", "pk", "start", "x", "rows", "digest")
        measure("stamp", "sk", "start", "digest", "finish")
        measure("prove", "pk", "start", "finish", "x", "rows", "proof")
        # The verifier's only inputs are the pinned public key, out-of-band
        # public challenge, and transcript. Its directory never contains x.
        for name in ("pk", "start", "proof"):
            shutil.copyfile(prover / name, validator / name)
        _, score, _ = measure("verify", "pk", "proof", "start", directory=validator)
        fields = dict(re.findall(r"(\w+)=([^\s]+)", score))
        if fields.get("target") != "pass" or int(fields["rows"]) != side**2:
            raise ValueError(f"unexpected validator result: {score}")
        for phase in ("commit", "prove"):
            if stages[phase]["peak_rss_kib"] >= stages["solve"]["peak_rss_kib"]:
                raise ValueError(f"{phase} RSS did not beat solve RSS: {stages}")
        start = (prover / "start").read_bytes()
        finish = (prover / "finish").read_bytes()
        transcript = (validator / "proof").read_bytes()
        attempt = sha(b"stencil-attempt-v1" + start)
        elapsed = int.from_bytes(finish[8:16], "little") - int.from_bytes(start[16:24], "little")
        if fields["attempt"] != attempt or int(fields["elapsed_ns"]) != elapsed:
            raise ValueError("verified receipt does not match run metadata")
        if len(transcript) >= side**2 // 4:
            raise ValueError("proof size exceeded one quarter byte per row")
        result = {
            "side": side, "rows": side**2, "trial": number, "stages": stages,
            "seed": sha(b"stencil-instance-seed-v1" + start),
            "signed_start_hex": start.hex(), "public_key_hex": (prover / "pk").read_bytes().hex(),
            "commitment_digest": (prover / "digest").read_bytes().hex(), "attempt": attempt,
            "commit_receipt_elapsed_s": elapsed / 1e9, "proof_bytes": len(transcript),
            "proof_sha256": sha(transcript), "solver_output": solver_message,
            "verified": {"rho": int(fields["rho"]), "relative_rhs": fields["relative_rhs"],
                         "target": fields["target"]},
        }
        if capped:
            caps = {"address_limit_bytes": CAP}
            caps["solve"], _, message = measure("solve", "pk", "start", "capped.x", cap=CAP, expected=1)
            if "allocation failed" not in message:
                raise ValueError(f"unexpected capped solve failure: {message}")
            caps["solve_result"] = message
            caps["prove"], _, _ = measure("prove", "pk", "start", "finish", "x", "rows",
                                          "capped.proof", cap=CAP)
            if (prover / "capped.proof").read_bytes() != transcript:
                raise ValueError("capped prover emitted a different transcript")
            caps["verify"], score2, _ = measure("verify", "pk", "proof", "start",
                                                directory=validator, cap=CAP)
            if score != score2:
                raise ValueError("capped verifier score changed")
            result["hard_cap"] = caps
        if public_dir:
            public_dir.mkdir(parents=True, exist_ok=True)
            for src, name in (("pk", "authority.pub"), ("start", "start.receipt"), ("proof", "proof.bin")):
                shutil.copyfile(validator / src, public_dir / name)
        return result


def summarize(runs):
    out = {}
    for side in sorted({run["side"] for run in runs}):
        grid = [run for run in runs if run["side"] == side]
        stages = {phase: {metric: median(r["stages"][phase][metric] for r in grid)
                          for metric in ("wall_s", "peak_rss_kib")} for phase in STAGES}
        out[str(side)] = {"trials": len(grid), "stages": stages,
                          "proof_bytes": median(r["proof_bytes"] for r in grid),
                          "commit_receipt_elapsed_s": median(r["commit_receipt_elapsed_s"] for r in grid)}
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "stencil")
    parser.add_argument("--sides", nargs="+", type=int, default=[512, 1024, 2048])
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--output", type=Path, default=ROOT / "benchmarks" / "results.json")
    parser.add_argument("--public-dir", type=Path, help="save largest grid's final public transcript, pin and start")
    args = parser.parse_args()
    if platform.system() != "Linux" or args.trials < 1:
        parser.error("a Linux host and a positive trial count are required")
    if any(s < 512 or s > 32768 or s & (s - 1) for s in args.sides) or len(set(args.sides)) != len(args.sides):
        parser.error("choose distinct, power-of-two grid sides within [512, 32768]")
    binary = args.binary.resolve(strict=True)
    model = next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                  if line.startswith("model name")), platform.machine())
    cc = shlex.split(os.environ.get("CC", "cc"))
    result = {
        "kernel": platform.release(), "machine": platform.machine(), "cpu": model,
        "binary_sha256": sha(binary.read_bytes()),
        "memory_unit": "KiB, peak resident set from Linux wait4 for each individual process",
        "scratch": "/tmp", "runs": [],
    }
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="stencil-bench-") as directory:
        helper = Path(directory) / "measure"
        subprocess.run([*cc, "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        ROOT / "benchmarks" / "measure.c", "-o", helper], check=True)
        for side in sorted(args.sides):
            for number in range(1, args.trials + 1):
                final = number == args.trials
                print(f"grid {side} x {side}, trial {number}/{args.trials}", flush=True)
                result["runs"].append(trial(helper, binary, side, number, directory,
                                            final and side == 1024,
                                            args.public_dir if final and side == max(args.sides) else None))
    result["medians"] = summarize(result["runs"])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=args.output.parent, delete=False) as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    os.replace(f.name, args.output)
    print(json.dumps(result["medians"], indent=2))


if __name__ == "__main__":
    main()
