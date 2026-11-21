#!/usr/bin/env python3
"""Exercise the three-band challenge size limits and a proof above 65,536 rows."""
import argparse
from array import array
import hashlib
import math
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

from check_three_band_challenge import BINARY, mix, run

MAX_ROWS = 1 << 30
PROFILE = b"signed-three-band-backward80-v2"


def check_registration(work):
    run(work, "keygen", "issuer", "key")
    (work / "nonce").write_bytes(bytes(range(32)))
    # Independently replay a solved challenge beyond the former ceiling.
    bundle = BINARY.parent / "benchmarks/large-profile/public"
    fields = run(bundle, "verify", "authority.pub", "proof.bin", "start.receipt").split()
    assert "rows=131072" in fields and "target=pass" in fields
    assert "profile=" + PROFILE.decode() in fields
    for n in (MAX_ROWS, MAX_ROWS + 1, MAX_ROWS * 2):
        expect = 0 if n == MAX_ROWS else 1
        local = f"local-{n}"
        beacon = f"reg-{n}"
        run(work, "start", "issuer", n, "endpoint", local, status=expect)
        run(work, "beacon-register", n, "endpoint", "nonce", 100, 200,
            2000000000, beacon, status=expect)
        if expect:
            assert not (work / local).exists() and not (work / beacon).exists()
        else:
            receipt = (work / local).read_bytes()
            registration = (work / beacon).read_bytes()
            assert struct.unpack_from("<I", receipt, 8) == (n,)
            assert struct.unpack_from("<I", registration, 48) == (n,)
            assert receipt[88:128].rstrip(b"\0") == registration[8:48].rstrip(b"\0") == PROFILE
    run(work, "fixture", "startbandv1", "issuer", 1 << 17, "archived", "v1", status=1)


def residual_energy(n, seed):
    """Stream public Matrix Market signs, independently evaluate ||A s - sigma||^2."""
    pattern, sign, rhs_a, rhs_b = struct.unpack("<4Q", seed)
    # s[i] = (-1)^i. The bounded pattern has at most 1,207 signed terms per row.
    sums = array("h", [0]) * n
    command = [BINARY, "three-band", str(n), str(pattern), "--sign-seed", str(sign)]
    with subprocess.Popen(command, stdout=subprocess.PIPE) as matrix:
        with matrix.stdout as lines:
            assert lines.readline().startswith(b"%%MatrixMarket")
            assert list(map(int, lines.readline().split())) == [n, n, 4*n - 6]
            count = 0
            for line in lines:
                row1, col1, coefficient = map(int, line.split())
                i, j = row1 - 1, col1 - 1
                sums[i] += -coefficient if j & 1 else coefficient
                if i != j:
                    sums[j] += -coefficient if i & 1 else coefficient
                count += 1
        assert matrix.wait() == 0 and count == 4*n - 6
    key = mix(rhs_a ^ mix(rhs_b))
    return sum((ax - (1 if mix(key+i) >> 63 else -1)) ** 2 for i, ax in enumerate(sums))


def check_transcript(root, n, measure):
    public = root / "public"
    public.mkdir()
    def stage(cwd, *args, status=0):
        if not measure:
            return run(cwd, *args, status=status)
        result = subprocess.run([measure, "0", BINARY, *map(str, args)], cwd=cwd,
                                capture_output=True, text=True)
        if result.returncode != status:
            raise AssertionError((args[0], result.returncode, result.stderr, result.stdout))
        stats = re.search(r"^MEASURE (\d+) (\d+)$", result.stderr, re.M)
        assert stats
        print(f"{args[0]}: {int(stats[1])/1e9:.3f} s, {int(stats[2])/1024:.2f} MiB peak RSS")
        return result.stdout

    with tempfile.TemporaryDirectory(dir=root) as tmp:
        private = Path(tmp)
        run(private, "keygen", "sk", "key")
        run(private, "start", "sk", n, "large-round", "start")
        seed = hashlib.sha256(b"stencil-instance-seed-v1" + (private / "start").read_bytes()).digest()
        raw = residual_energy(n, seed)
        # An intentional miss whose dense nonzero coordinates saturate Q = n*2^156.
        (private / "x").write_bytes(struct.pack("<dd", 1/n, -1/n) * (n//2))
        stage(private, "commit", "key", "start", "x", "cache", "digest")
        run(private, "stamp", "sk", "start", "digest", "finish")
        stage(private, "prove", "key", "start", "finish", "x", "cache", "proof")
        for name in ("key", "start", "proof"):
            shutil.copyfile(private / name, public / name)
    report = stage(public, "verify", "key", "proof", "start", status=3)
    fields = dict(item.split("=", 1) for item in report.split() if "=" in item)
    assert fields["profile"].encode() == PROFILE and fields["target"] == "miss"
    assert int(fields["rows"]) == n and int(fields["exponent"]) == -(n.bit_length() - 1)
    assert int(fields["rho"]) == raw << 156 and int(fields["x_squared"]) == n << 156
    upper = math.sqrt(raw) / (math.sqrt(7*n - 12) + math.sqrt(n))
    assert math.isclose(float(fields["backward_2_upper"]), upper, rel_tol=1e-14)
    print(f"PASS {n:,} rows, certified miss, independently checked exact energies; "
          f"{(public / 'proof').stat().st_size:,} proof bytes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--million", action="store_true", help="use 2^20 rows instead of 2^17")
    parser.add_argument("--measure", type=Path, help="executable built from benchmarks/measure.c")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        check_registration(root)
        check_transcript(root, 1 << (20 if args.million else 17),
                         args.measure.resolve() if args.measure else None)
