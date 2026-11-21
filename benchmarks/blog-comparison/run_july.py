#!/usr/bin/env python3
"""Rerun July's release benchmark scripts, preserving GNU time RSS and complete file sizes."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import platform
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(repo, *args):
    return subprocess.check_output(args, cwd=repo, text=True).strip()


def collect(directory, fast):
    cases = []
    with (directory / "results.tsv").open() as source:
        for meta in csv.DictReader(source, delimiter="\t"):
            n = int(meta["dimension"])
            case = directory / f"n{n}"
            proof = case / ("proof.ssf" if fast else "proof.ssp")
            if meta["status"] != "ok" or proof.stat().st_size != int(meta["proof_bytes"]):
                raise ValueError(f"Incomplete or inconsistent proof at {case}")
            stages = {}
            for stage in (["commit"] if fast else []) + ["prover", "validator"]:
                stats = dict(line.split("=") for line in (case / f"{stage}.time").read_text().splitlines())
                if int(stats["exit_status"]):
                    raise ValueError(f"{case} {stage} failed")
                stages[stage] = {"seconds": float(stats["wall_seconds"]), "max_rss_kib": int(stats["max_rss_kib"])}
            record = {"rows": n, "problem_digest": meta["problem_digest"], "status": "verified",
                      "stages": stages, "proof_bytes": proof.stat().st_size, "proof_sha256": digest(proof),
                      "bytes_including_precommitment": proof.stat().st_size}
            if fast:
                commitment = case / "commitment.sfc"
                record.update(precommitment_bytes=commitment.stat().st_size,
                              precommitment_sha256=digest(commitment),
                              validation_nonce=(case / "validation_nonce.hex").read_text().strip(),
                              residual_squared_l2=float(meta["residual_squared_l2"]))
                record["bytes_including_precommitment"] += commitment.stat().st_size
                if record["bytes_including_precommitment"] != int(meta["total_artifact_bytes"]):
                    raise ValueError(f"Incorrect combined length at {case}")
            else:
                record.update(residual_numerator=meta["residual_squared_numerator"],
                              residual_denominator_power=int(meta["residual_squared_denominator_power"]))
            cases.append(record)
    return sorted(cases, key=lambda v: v["rows"])


def published_fast_artifacts(repo):
    directory = repo / "artifacts/fast-benchmarks/query-only-v2-final-optimized"
    if not (directory / "results.tsv").is_file():
        return []
    rows = []
    for record in collect(directory, fast=True):
        rows.append({k: record[k] for k in ("rows", "proof_bytes", "precommitment_bytes",
                                            "bytes_including_precommitment", "proof_sha256")})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", type=Path, help="July sparse-solution-stark checkout with release binaries")
    parser.add_argument("raw", type=Path, help="raw output directory for the upstream scripts")
    parser.add_argument("output", type=Path, help="comparison JSON to write")
    parser.add_argument("--dimensions", default="1048576,262144,32768")
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--collect-only", action="store_true", help="summarize already-complete raw outputs")
    args = parser.parse_args()
    repo, raw = args.repo.resolve(), args.raw.resolve()
    records = {}
    for name, script in (("exact", "run-cloud-benchmarks.sh"), ("fast", "run-fast-benchmarks.sh")):
        out = raw / name
        invocation = [f"scripts/{script}", "--threads", str(args.threads),
                      "--dimensions", args.dimensions, "--skip-build", "--output", str(out)]
        if not args.collect_only:
            if out.exists():
                parser.error(f"raw run directory already exists: {out}")
            subprocess.run(invocation, cwd=repo, check=True)
        cases = collect(out, name == "fast")
        if {v["rows"] for v in cases} != set(map(int, args.dimensions.split(","))):
            raise ValueError(f"Not all requested dimensions were completed in {out}")
        started = (out / "metadata.txt").read_text().splitlines()[0].removeprefix("started_utc=")
        records[name] = {"started_utc": started, "command": invocation, "runs": cases}
    template = repo / "examples/random-tridiagonal-whir-field192-l2-v4-n16384.json"
    model = next(line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                 if line.startswith("model name"))
    release = repo / "target/release"
    result = {"upstream_git_commit": command(repo, "git", "rev-parse", "HEAD"),
              "build": "existing release binaries selected with upstream --skip-build",
              "binaries_sha256": {p.name: digest(p) for p in (release / "sparse-prover", release / "sparse-validator")},
              "pinned_toolchain": command(repo, "rustc", "-V"), "cpu": model, "platform": platform.platform(),
              "threads": args.threads, "measurement": "GNU time %M in KiB and %e in seconds, per process",
              "challenge_nonce": json.loads(template.read_text())["challenge_nonce"],
              "published_fast_artifacts_on_disk": published_fast_artifacts(repo), **records}
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
