#!/usr/bin/env python3
"""Run a fresh signed 3D benchmark on Linux and checkpoint independent process measurements."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
from statistics import median
import struct
import subprocess
import tempfile
import time

from run import ROOT, sha


PROFILE = b"seeded-stencil-3d-exact-residual-v1"
SCALE = 1 << 58
U64_MASK = (1 << 64) - 1
STAGES = ("keygen", "start", "solve", "commit", "stamp", "prove", "verify")


def read_text(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def machine(scratch):
    cpuinfo = Path("/proc/cpuinfo").read_text().splitlines()
    cpu = next((line.split(":", 1)[1].strip() for line in cpuinfo if line.startswith("model name")),
               platform.machine())
    mem = re.search(r"^MemTotal:\s+(\d+) kB$", Path("/proc/meminfo").read_text(), re.M)
    mount = subprocess.run(["findmnt", "-n", "-o", "FSTYPE", "--target", str(scratch)],
                           text=True, capture_output=True)
    return {"hostname": platform.node(), "kernel": platform.release(),
            "architecture": platform.machine(), "cpu": cpu, "vcpus": os.cpu_count(),
            "affinity_vcpus": len(os.sched_getaffinity(0)), "memtotal_kib": int(mem[1]),
            "scratch_root": str(scratch), "scratch_filesystem": mount.stdout.strip(),
            "scratch_free_bytes_at_start": shutil.disk_usage(scratch).free,
            "cgroup_memory_limit": read_text("/sys/fs/cgroup/memory.max"),
            "cgroup_cpu_limit": read_text("/sys/fs/cgroup/cpu.max")}


def oom_counts():
    counters = {}
    for prefix, path in (("host", "/proc/vmstat"), ("cgroup", "/sys/fs/cgroup/memory.events")):
        data = read_text(path)
        if data:
            for key, value in re.findall(r"^(oom_kill|oom_group_kill)\s+(\d+)$", data, re.M):
                counters[f"{prefix}_{key}"] = int(value)
    return counters


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(f.name, path)


def mix(i):
    i &= U64_MASK
    i = ((i ^ (i >> 30)) * 0xbf58476d1ce4e5b9) & U64_MASK
    i = ((i ^ (i >> 27)) * 0x94d049bb133111eb) & U64_MASK
    return i ^ (i >> 31)


def residual_oracle(side, seed, solution):
    """Independent Python integer oracle, streamed once per grid outside all timed stages."""
    k0, k1, k2, k3 = struct.unpack("<4Q", seed)
    salt = mix(k3 ^ 0x7374656e63696c33)
    kx, ky, kz, kb = (mix(k ^ salt ^ (j + 1)) for j, k in enumerate((k0, k1, k2, k3)))
    plane = side * side
    zeros = [0] * plane

    def take_plane(f):
        raw = f.read(plane * 8)
        if len(raw) != plane * 8:
            raise ValueError("truncated binary64 input in local oracle")
        return [round(v * SCALE) for v, in struct.iter_unpack("<d", raw)]

    energy = 0
    with solution.open("rb") as f:
        before, here = zeros, take_plane(f)
        for z in range(side):
            after = take_plane(f) if z + 1 < side else zeros
            for y in range(side):
                for x in range(side):
                    offset = y * side + x
                    i = z * plane + offset
                    center = here[offset]
                    fx = (z * side + y) * (side + 1) + x
                    fy = (z * (side + 1) + y) * side + x
                    summed = 4 * center - (SCALE if mix(kb + i) >> 63 else -SCALE)
                    neighbors = (
                        (kx, fx, here[offset - 1] if x else 0),
                        (kx, fx + 1, here[offset + 1] if x + 1 < side else 0),
                        (ky, fy, here[offset - side] if y else 0),
                        (ky, fy + side, here[offset + side] if y + 1 < side else 0),
                        (kz, i, before[offset]),
                        (kz, i + plane, after[offset]),
                    )
                    for key, face, peer in neighbors:
                        summed += (1 + (mix(key + face) >> 62)) * (center - peer)
                    energy += summed * summed
            before, here = here, after
        if f.read(1):
            raise ValueError("trailing binary64 input in local oracle")
    return energy


def measure(helper, command, directory, env, result, name, checkpoint, cap=0):
    result["active_stage"] = name
    checkpoint()
    print(f"  {name}", flush=True)
    before = oom_counts()
    run = subprocess.run([helper, str(cap), *command], cwd=directory, env=env,
                         text=True, errors="replace", capture_output=True)
    after = oom_counts()
    match = re.search(r"^MEASURE (\d+) (\d+)\n?\Z", run.stderr, re.M)
    stats = {"exit_status": run.returncode}
    result["stages"][name] = stats
    if match:
        stats.update({"wall_s": int(match[1]) * 1e-9, "peak_rss_kib": int(match[2])})
    diagnostic = run.stderr[:match.start()] if match else run.stderr
    if diagnostic.strip():
        stats["stderr"] = diagnostic.strip()[-4096:]
    if run.stdout.strip():
        stats["stdout"] = run.stdout.strip()[-4096:]
    increments = {k: v-before[k] for k, v in after.items() if k in before and v != before[k]}
    if increments:
        stats["oom_counter_deltas"] = increments
    result.pop("active_stage")
    checkpoint()
    if run.returncode != 0 or not match:
        raise RuntimeError(f"{name} exited {run.returncode}. {diagnostic.strip()[-500:]}")
    return run.stdout.strip()


def run_trial(args, helper, case, env, work, checkpoint, oracle):
    side = case["side"]
    n = side**3
    with tempfile.TemporaryDirectory(prefix=f"cube{side}-", dir=work) as path:
        p = Path(path)
        v = p / "verifier"
        v.mkdir()

        def stage(name, program, *cmd, cwd=p, cap=0):
            return measure(helper, [program, *map(str, cmd)], cwd, env, case, name, checkpoint, cap)

        stage("keygen", args.binary, "keygen", "sk", "pk")
        stage("start", args.binary, "start3d", "sk", side, f"cube-{side}-{case['trial']}", "start")
        start = (p / "start").read_bytes()
        if (len(start) != 192 or int.from_bytes(start[8:12], "little") != side
                or start[88:128].rstrip(b"\0") != PROFILE):
            raise ValueError("unexpected signed 3D profile or physical grid side")
        seed = sha(b"stencil-instance-seed-v1" + start)
        case.update({"seed": seed, "attempt": sha(b"stencil-attempt-v1" + start),
                     "signed_start_hex": start.hex(), "public_key_hex": (p / "pk").read_bytes().hex()})
        stage("solve", args.solver, "pk", "start", "x")
        if (p / "x").stat().st_size != n * 8:
            raise ValueError("solver wrote an unexpected number of coordinates")
        stage("commit", args.binary, "commit", "pk", "start", "x", "rows", "digest")
        stage("stamp", args.binary, "stamp", "sk", "start", "digest", "finish")
        finish = (p / "finish").read_bytes()
        elapsed = int.from_bytes(finish[8:16], "little") - int.from_bytes(start[16:24], "little")
        case.update({"commit_receipt_elapsed_s": elapsed * 1e-9,
                     "commitment_digest": (p / "digest").read_bytes().hex()})
        stage("prove", args.binary, "prove", "pk", "start", "finish", "x", "rows", "proof")
        if args.check_cap_mib:
            cap = args.check_cap_mib * 2**20
            stage("prove_capped", args.binary, "prove", "pk", "start", "finish", "x", "rows",
                  "capped.proof", cap=cap)
            if (p / "capped.proof").read_bytes() != (p / "proof").read_bytes():
                raise ValueError("proof differed under address-space limit")
        if oracle:
            t0 = time.monotonic()
            case["python_integer_energy"] = residual_oracle(side, bytes.fromhex(seed), p / "x")
            case["oracle_wall_s"] = time.monotonic() - t0
        for name in ("pk", "start", "proof"):
            shutil.copyfile(p / name, v / name)
        for name in ("x", "rows", "sk"):
            (p / name).unlink()
        score = stage("verify", args.binary, "verify", "pk", "proof", "start", cwd=v)
        fields = dict(re.findall(r"(\w+)=([^\s]+)", score))
        if (fields.get("target") != "pass" or int(fields["rows"]) != n
                or int(fields["elapsed_ns"]) != elapsed or fields["attempt"] != case["attempt"]):
            raise ValueError("unexpected validator result: " + score)
        rho = int(fields["rho"])
        if oracle and rho != case["python_integer_energy"]:
            raise ValueError("independent residual sum differs from verifier result")
        if args.check_cap_mib:
            capped = stage("verify_capped", args.binary, "verify", "pk", "proof", "start", cwd=v, cap=cap)
            if score != capped:
                raise ValueError("validation result differed under address-space limit")
        proof = (v / "proof").read_bytes()
        width = 1 << ((n.bit_length() - 1)//2)
        expected_size = 32*(width + n//width) + 128*(n.bit_length() - 1) + 2472
        if len(proof) != expected_size:
            raise ValueError(f"unexpected transcript size {len(proof)}, expected {expected_size}")
        solve_rss = case["stages"]["solve"]["peak_rss_kib"]
        case["peak_rss_below_solve"] = {
            stage: case["stages"][stage]["peak_rss_kib"] < solve_rss for stage in ("commit", "prove", "verify")
        }
        case.update({"verified": {"rho": rho, "relative_rhs": fields["relative_rhs"], "target": fields["target"]},
                     "proof_bytes": len(proof), "proof_sha256": sha(proof),
                     "table_columns": width, "table_rows": n // width, "padding_coordinates": 0,
                     "private_solution_bytes": n * 8, "prover_field_scratch_bytes": n * 32})
        if args.public_dir:
            dest = args.public_dir / f"grid-{side}-trial-{case['trial']:02d}"
            dest.mkdir(parents=True, exist_ok=True)
            for src, target in (("pk", "authority.pub"), ("start", "start.receipt"), ("proof", "proof.bin")):
                shutil.copyfile(v / src, dest / target)
            case["public_artifact_directory"] = dest.name
        case["status"] = "complete"


def summarize(runs):
    summary = {}
    for side in sorted({r["side"] for r in runs}):
        ok = [r for r in runs if r["side"] == side and r["status"] == "complete"]
        if ok:
            summary[str(side)] = {
                "completed_trials": len(ok),
                "stages": {s: {k: median(r["stages"][s][k] for r in ok)
                               for k in ("wall_s", "peak_rss_kib")} for s in STAGES},
                "proof_bytes": median(r["proof_bytes"] for r in ok),
                "commit_receipt_elapsed_s": median(r["commit_receipt_elapsed_s"] for r in ok)}
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sides", type=int, nargs="+", default=[32, 64, 128])
    p.add_argument("--trials", type=int, default=1)
    p.add_argument("--threads", type=int, default=1, help="solver BLAS/OpenMP thread limit")
    p.add_argument("--check-cap-mib", type=int, default=0, help="repeat proving and verification with RLIMIT_AS")
    p.add_argument("--binary", type=Path, default=ROOT / "stencil")
    p.add_argument("--solver", type=Path, default=ROOT / "stencil-direct3d")
    p.add_argument("--tag", default="", help="VM description to add to the record")
    p.add_argument("--scratch-dir", type=Path, default=Path("/tmp"))
    p.add_argument("--output", type=Path, default=ROOT/"benchmarks"/"3d"/"results.json")
    p.add_argument("--public-dir", type=Path, default=ROOT/"benchmarks"/"3d"/"public")
    p.add_argument("--resume", action="store_true", help="skip complete cases in an existing measurement file")
    args = p.parse_args()
    if (platform.system() != "Linux" or args.trials < 1 or args.threads < 1 or args.check_cap_mib < 0 or
            any(s < 32 or s > 1024 or s & (s-1) for s in args.sides) or len(set(args.sides)) != len(args.sides)):
        p.error("choose Linux, positive trials/threads and distinct power-of-two sides between 32 and 1024")
    args.binary = args.binary.resolve(strict=True)
    args.solver = args.solver.resolve(strict=True)
    args.scratch_dir = args.scratch_dir.resolve(strict=True)
    args.public_dir = args.public_dir.resolve()
    new = {"machine": machine(args.scratch_dir), "tag": args.tag, "solver_threads_limit": args.threads,
           "mkl_dynamic": "FALSE", "address_check_mib": args.check_cap_mib, "solver_binary_sha256": sha(args.solver.read_bytes()),
           "protocol_binary_sha256": sha(args.binary.read_bytes()),
           "rss_method": "Linux wait4 peak resident KiB for each separately executed process",
           "solver_linkage": subprocess.run(["ldd", args.solver], capture_output=True, text=True).stdout,
           "runs": []}
    if args.output.exists():
        if not args.resume:
            p.error("output exists; pass --resume to retain measurements and run missing cases")
        data = json.loads(args.output.read_text())
        for key in ("tag", "solver_threads_limit", "mkl_dynamic", "address_check_mib", "solver_binary_sha256", "protocol_binary_sha256"):
            if data[key] != new[key]:
                p.error("incompatible resume metadata: " + key)
        if data["machine"]["hostname"] != new["machine"]["hostname"]:
            p.error("resume on the original VM or select a new output file")
    else:
        data = new

    def checkpoint():
        write_json(args.output, data)

    env = os.environ.copy()
    for name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "BLIS_NUM_THREADS"):
        env[name] = str(args.threads)
    env["MKL_DYNAMIC"] = new["mkl_dynamic"]
    complete = {(r["side"], r["trial"]) for r in data["runs"] if r["status"] == "complete"}
    checked_sides = {r["side"] for r in data["runs"] if "python_integer_energy" in r and r["status"] == "complete"}
    cc = shlex.split(os.environ.get("CC", "cc"))
    with tempfile.TemporaryDirectory(dir=args.scratch_dir, prefix="stencil-3d-") as tmp:
        helper = Path(tmp) / "measure"
        env["TMPDIR"] = tmp
        subprocess.run([*cc, "-O2", "-std=c11", ROOT / "benchmarks" / "measure.c", "-o", helper], check=True)
        for side in sorted(args.sides):
            for trial in range(1, args.trials + 1):
                if (side, trial) in complete:
                    continue
                result = {"side": side, "rows": side**3, "trial": trial, "status": "running", "stages": {}}
                data["runs"].append(result)
                print(f"grid {side}³ ({side**3:,} unknowns), trial {trial}", flush=True)
                try:
                    run_trial(args, helper, result, env, tmp, checkpoint, oracle=side not in checked_sides)
                except (OSError, KeyError, ValueError, RuntimeError) as error:
                    result["status"] = "failed"
                    result["error"] = str(error)
                    print(str(error), flush=True)
                    checkpoint()
                    return 1
                complete.add((side, trial))
                checked_sides.add(side)
                data["medians"] = summarize(data["runs"])
                checkpoint()
    print(json.dumps(data.get("medians", {}), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
