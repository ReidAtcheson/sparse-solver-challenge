#!/usr/bin/env python3
"""Run one 32³ PARDISO trial and replay its transcript after all private files are removed."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "stencil")
    parser.add_argument("--solver", type=Path, default=ROOT / "stencil-direct3d")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="check-stencil3d-") as directory:
        work = Path(directory)
        scratch = work / "scratch"
        scratch.mkdir()
        results = work / "result.json"
        subprocess.run([sys.executable, ROOT / "benchmarks" / "run3d.py", "--sides", "32",
                        "--trials", "1", "--threads", "1", "--binary", binary,
                        "--solver", args.solver.resolve(strict=True), "--output", results,
                        "--scratch-dir", scratch, "--public-dir", work / "public"],
                       check=True, stdout=subprocess.DEVNULL)
        record = json.loads(results.read_text())
        case, = record["runs"]
        assert case["status"] == "complete" and case["python_integer_energy"] == case["verified"]["rho"]
        assert record["mkl_dynamic"] == "FALSE" and not any(scratch.iterdir())
        assert case["rows"] == 32**3 and case["padding_coordinates"] == 0
        assert case["table_rows"] == 256 and case["table_columns"] == 128
        assert case["proof_bytes"] == 16680 and all(case["peak_rss_below_solve"].values())
        assert all(case["stages"][s]["peak_rss_kib"] > 0 for s in ("solve", "prove", "verify"))
        saved = work / "public" / case["public_artifact_directory"]
        replay = work / "fresh-replay"
        shutil.copytree(saved, replay)
        assert {p.name for p in replay.iterdir()} == {"proof.bin", "start.receipt", "authority.pub"}
        proof = (replay / "proof.bin").read_bytes()
        assert hashlib.sha256(proof).hexdigest() == case["proof_sha256"]
        command = [binary, "verify", "authority.pub", "proof.bin", "start.receipt"]
        verified = subprocess.run(command, cwd=replay, text=True, check=True, capture_output=True)
        assert verified.stdout.strip() == case["stages"]["verify"]["stdout"]
        # Corrupt the revealed folded row in this rectangular opening.
        (replay / "proof.bin").write_bytes(proof[:-1] + bytes([proof[-1] ^ 1]))
        bad = subprocess.run(command, cwd=replay, capture_output=True)
        assert bad.returncode == 1
        print(f"PASS 32³ PARDISO, exact rho={case['verified']['rho']}, {len(proof)}-byte rectangular proof, clean replay")


if __name__ == "__main__":
    main()
