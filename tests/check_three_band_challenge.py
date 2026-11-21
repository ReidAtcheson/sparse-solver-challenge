#!/usr/bin/env python3
"""Check the default scoring pipeline against an integer sparse matvec."""
import hashlib
import math
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile


BINARY = Path(__file__).resolve().parents[1] / "stencil"
N = 1024


def run(directory, *args, status=0):
    result = subprocess.run([BINARY, *map(str, args)], cwd=directory,
                            capture_output=True, text=True)
    if result.returncode != status:
        raise AssertionError((args, result.returncode, result.stderr, result.stdout))
    return result.stdout


def mix(x):
    mask = 2**64 - 1
    x &= mask
    x = ((x ^ (x >> 30)) * 0xbf58476d1ce4e5b9) & mask
    x = ((x ^ (x >> 27)) * 0x94d049bb133111eb) & mask
    return x ^ (x >> 31)


def check(root):
    private, public = root / "private", root / "public"
    private.mkdir()
    public.mkdir()
    run(private, "keygen", "sk", "pub")
    run(private, "start", "sk", N, "round", "start")
    start = (private / "start").read_bytes()
    assert start[88:128].rstrip(b"\0") == b"signed-three-band-backward80-v2"
    seed = hashlib.sha256(b"stencil-instance-seed-v1" + start).digest()
    pattern, sign, rhs1, rhs2 = struct.unpack("<4Q", seed)
    # The standalone generator and arbitrary dyadic x give an oracle independent
    # of the batched verifier endpoint, CSR builder and C score arithmetic.
    output = run(private, "three-band", N, pattern, "--sign-seed", sign).splitlines()
    assert tuple(map(int, output[1].split())) == (N, N, 4*N-6)
    values = [((i * 19) % 31 - 15) / 32 for i in range(N)]
    exponent = -1
    scale = 1 << (78 - exponent)
    encoded = [int(x * scale) for x in values]
    key = mix(rhs1 ^ mix(rhs2))
    residual = [-(scale // N) * (1 if mix(key + i) >> 63 else -1) for i in range(N)]
    for line in output[2:]:
        i, j, coefficient = map(int, line.split())
        i, j = i-1, j-1
        residual[i] += coefficient * encoded[j]
        if i != j:
            residual[j] += coefficient * encoded[i]
    rho = sum(r*r for r in residual)
    norm = sum(x*x for x in encoded)
    bound = math.sqrt(rho) / (math.sqrt((7*N-12)/N * norm) + scale / math.sqrt(N))
    (private / "x").write_bytes(struct.pack(f"<{N}d", *values))
    run(private, "commit", "pub", "start", "x", "rows", "digest")
    run(private, "stamp", "sk", "start", "digest", "finish")
    run(private, "prove", "pub", "start", "finish", "x", "rows", "proof")
    for name in ("pub", "start", "proof"):
        shutil.copyfile(private / name, public / name)
    assert len(list(public.iterdir())) == 3
    result = run(public, "verify", "pub", "proof", "start", status=3)
    fields = dict(word.split("=", 1) for word in result.split() if "=" in word)
    assert (int(fields["exponent"]), int(fields["rho"]), int(fields["x_squared"])) == (exponent, rho, norm)
    assert fields["target"] == "miss" and math.isclose(float(fields["backward_2_upper"]), bound, rel_tol=1e-15)
    damaged = bytearray((public / "proof").read_bytes())
    damaged[-1] ^= 1
    (public / "damaged").write_bytes(damaged)
    run(public, "verify", "pub", "damaged", "start", status=1)
    run(private, "start", "sk", N, "different-round", public / "other")
    run(public, "verify", "pub", "proof", "other", status=1)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as temp:
        check(Path(temp))
    for directory, expected_id in (
        ("bounded-three-band", b"signed-three-band-backward80-v2"),
        ("three-band-cloud", b"signed-three-band-backward80-v1"),
    ):
        archived = BINARY.parent / "benchmarks" / directory / "public"
        assert (archived / "start.receipt").read_bytes()[88:128].rstrip(b"\0") == expected_id
        replay = run(archived, "verify", "authority.pub", "proof.bin", "start.receipt")
        assert "target=pass" in replay and "backward_2_upper=" in replay
    print("PASS bounded profile, exact energies and score, tamper checks and both archived replays")
