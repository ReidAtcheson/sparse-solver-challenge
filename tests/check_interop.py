#!/usr/bin/env python3
"""Replay the published 32³ STNPRF02 transcript using Python's byte encodings."""
import argparse
import hashlib
from pathlib import Path
import struct
import subprocess


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "benchmarks/signed3d-public/grid-32-trial-01"
Q = 2**252 + 27742317777372353535851937790883648493


def check(actual, expected, name):
    if actual != expected:
        raise ValueError(f"{name}: expected {expected}, got {actual}")


class Transcript:
    def __init__(self, proof):
        self.proof = proof
        self.offset = 0
        self.hash = hashlib.sha512(b"stencil-proof-transcript-v1")

    def take(self, n):
        value = self.proof[self.offset:self.offset + n]
        check(len(value), n, f"field length at byte {self.offset}")
        self.offset += n
        self.hash.update(value)
        return value

    def field(self):
        x = int.from_bytes(self.take(32), "little")
        if x >= Q:
            raise ValueError(f"noncanonical scalar ending at {self.offset}")
        return x

    def challenge(self, role, index):
        state = self.hash.copy()
        state.update(role + struct.pack("<I", index))
        return state.digest()

    def scalar(self, role, index):
        return int.from_bytes(self.challenge(role, index), "little") % Q


def scalar_hex(x):
    return x.to_bytes(32, "little").hex()


def replay(binary):
    proof = (FIXTURE / "proof.bin").read_bytes()
    t = Transcript(proof)
    check(t.take(8), b"STNPRF02", "magic")
    start = t.take(192)
    check(start, (FIXTURE / "start.receipt").read_bytes(), "registered start")
    check(start[:8], b"STNSTA01", "start tag")
    check(start[88:128], b"signed-unit-torus-3d-backward80-v2".ljust(40, b"\0"), "profile")
    side, reserved = struct.unpack_from("<II", start, 8)
    check((side, reserved), (32, 0), "side and reserved word")
    n = side**3
    rounds = n.bit_length() - 1
    width = 1 << (rounds // 2)
    height = n // width
    check((n, rounds, width, height), (32768, 15, 128, 256), "layout")
    seed = hashlib.sha256(b"stencil-instance-seed-v1" + start).hexdigest()
    check(seed, "1a02ba82c38bd9658dde7fb174486ed1ef2f993103575801c4c8564c6f7c578d", "instance seed")
    finish = t.take(160)
    check(finish[:8], b"STNFIN01", "finish tag")
    check(finish[16:48], hashlib.sha256(b"stencil-attempt-v1" + start).digest(), "attempt")
    mask_seed = t.challenge(b"M", 0)[:32]
    check(mask_seed.hex(), "ec972ae897b2168fd68d11d87ccca5799089cb56f464d7b71607801ba828ad09", "M seed")
    exponent, = struct.unpack("<i", t.take(4))
    check(exponent, -8, "exponent")
    row_points = t.take(32 * height)
    digest = hashlib.sha256(b"stencil-ristretto255-wide80-row-commitments-v1"
                            + struct.pack("<IIi", width, height, exponent) + row_points).digest()
    check(digest, finish[48:80], "stamped commitment")
    check(digest.hex(), "41812e0f36bf9409edc47a903c6c97f046eb8004f8b9728a1b9d0cc5d4bf8136", "commitment")
    rho, energy = t.field(), t.field()
    check(rho, 689899610386202624, "residual energy")
    check(energy, 45285274284675669591449445514204914440525729234944, "solution energy")
    for _ in range(128):
        projection = int.from_bytes(t.take(16), "little", signed=True)
        if abs(projection) > n * 2**78:
            raise ValueError("subset sum exceeds the profile bound")
    claim = rho
    for k in range(rounds):
        g0, quadratic = t.field(), t.field()
        u = t.scalar(b"U", k)
        if k == 0:
            check(scalar_hex(u), "2512ce5f33b1126abf8a82a315c49bec26f2d58a39fb622f4bfc4785652a2102", "U[0]")
        claim = (g0 + u * (claim - 2*g0 - quadratic + u * quadratic)) % Q
    residual = t.field()
    check(claim, residual**2 % Q, "norm sumcheck endpoint")
    check(scalar_hex(t.scalar(b"B", 0)), "9a4d985d73f0ccff6ad55a476b65bb54b45dbc92e65e60081809e2ed3ab5a503", "B[0]")
    check(scalar_hex(t.scalar(b"X", 0)), "6e0f66b9ac7553fb0629af0fa11e3b87418169d8e2fdd5c5f3a97acca53b8c03", "X[0]")
    for k in range(rounds):
        t.field()
        t.field()
        if k == 0:
            check(scalar_hex(t.scalar(b"V", k)), "0ff428ad7503b507ad8657e592804d24cdab0b153abc8d3b9baa70859d870e0f", "V[0]")
    for _ in range(width):
        t.field()
    check(t.offset, len(proof), "EOF")
    check(len(proof), 16716, "proof length")
    check(hashlib.sha256(proof).hexdigest(), "1a2e776e3c555ea48e03e369f3a7e9a1acf1a1355a51f4ae4d1f05ec8707495c", "proof SHA-256")

    result = subprocess.run([binary, "verify", "authority.pub", "proof.bin", "start.receipt"],
                            cwd=FIXTURE, check=True, capture_output=True, text=True)
    fields = dict(word.split("=", 1) for word in result.stdout.split() if "=" in word)
    check((fields["target"], int(fields["rows"]), int(fields["rho"]), int(fields["x_squared"])),
          ("pass", n, rho, energy), "reference validator")
    print(f"PASS archived STNPRF02, {len(proof)} bytes, Python known answers and C verification")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "stencil")
    replay(parser.parse_args().binary.resolve(strict=True))
