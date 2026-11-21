#!/usr/bin/env python3
"""End-to-end reference checks. Run after building, e.g. python3 tests/check.py ./stencil."""
import hashlib
import math
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

SIDE = 512
SCALE = 1 << 58
MASK64 = (1 << 64) - 1
ORDER = (1 << 252) + 27742317777372353535851937790883648493
BINARY = Path(sys.argv[1] if len(sys.argv) > 1 else "./stencil").resolve()


def invoke(directory, *args, expect=True):
    command = [str(BINARY), *map(str, args)]
    result = subprocess.run(command, cwd=directory, capture_output=True, text=True)
    if result.returncode < 0 or (expect is not None and (result.returncode == 0) != expect):
        raise AssertionError(f"{' '.join(command)} exited {result.returncode}\n"
                             f"{result.stdout}{result.stderr}")
    return result


def mix(x):
    x &= MASK64
    x = ((x ^ (x >> 30)) * 0xbf58476d1ce4e5b9) & MASK64
    x = ((x ^ (x >> 27)) * 0x94d049bb133111eb) & MASK64
    return x ^ (x >> 31)


def check_stamp_stdio(directory, digest):
    entry = "authenticated-entrant"
    invoke(directory, "fixture", "start2d", "sk", SIDE, entry, "endpoint-start")
    start = (directory / "endpoint-start").read_bytes()
    request = start + digest

    def stamp(payload, who=entry, expect=True):
        result = subprocess.run([str(BINARY), "stamp-stdio", "sk", who],
                                cwd=directory, input=payload, capture_output=True)
        assert (result.returncode == 0) == expect and result.returncode >= 0, result.stderr
        assert len(result.stdout) == (160 if expect else 0)
        return result.stdout

    stamp(request, who="other-entrant", expect=False)
    stamp(request[:-1], expect=False)
    stamp(request + b"\x00", expect=False)
    stamp(bytes([request[0] ^ 1]) + request[1:], expect=False)
    other_digest = bytes([digest[0] ^ 1]) + digest[1:]
    receipt = stamp(start + other_digest)
    assert receipt == stamp(start + other_digest)
    stamp(request, expect=False)
    (directory / "stdio-digest").write_bytes(other_digest)
    invoke(directory, "stamp", "sk", "endpoint-start", "stdio-digest", "stdio-copy")
    assert receipt == (directory / "stdio-copy").read_bytes()
    invoke(directory, "stamp", "sk", "endpoint-start", "digest", "file-conflict", expect=False)
    # Exercise the reverse direction with the pre-existing file-issued stamp.
    file_request = (directory / "start").read_bytes() + digest
    assert stamp(file_request, who="test-entry") == (directory / "finish").read_bytes()


def exact_rho(start, doubles):
    """Compute with unbounded Python integers and independent face numbering."""
    seed = hashlib.sha256(b"stencil-instance-seed-v1" + start).digest()
    a, b, c, d = struct.unpack("<4Q", seed)
    salt = mix(d ^ 0x7374656e63696c31)
    hkey, vkey, bkey = mix(a ^ salt ^ 1), mix(b ^ salt ^ 2), mix(c ^ salt ^ 3)
    side = int.from_bytes(start[8:12], "little")
    assert side == SIDE
    scaled = [round(x * SCALE) for x, in struct.iter_unpack("<d", doubles)]
    assert len(scaled) == side**2
    rho = 0
    for y in range(side):
        for x in range(side):
            row = y * side + x
            value = scaled[row]
            rhs = 1 if mix(bkey + row) >> 63 else -1
            defect = 4 * value - SCALE * rhs
            # Zero exterior value contributes a Dirichlet boundary term.
            for peer, key, face in (
                    (row - 1 if x else None, hkey, y*(side+1)+x),
                    (row + 1 if x+1 < side else None, hkey, y*(side+1)+x+1),
                    (row - side if y else None, vkey, row),
                    (row + side if y+1 < side else None, vkey, row+side)):
                weight = 1 + (mix(key + face) >> 62)
                defect += weight * (value - (0 if peer is None else scaled[peer]))
            rho += defect**2
    return rho


def main(directory):
    prover = directory / "prover"
    verifier = directory / "verifier"
    prover.mkdir()
    verifier.mkdir()
    invoke(prover, "keygen", "sk", "pk")
    invoke(prover, "keygen", "other-sk", "other-pk")
    # A legacy signed profile can be replayed but ordinary issuance has one challenge.
    for command, size in (("startbandv1", 1024), ("start3d", 32), ("startsigned3d", 32),
                          ("startblog", 1024), ("start2d", SIDE)):
        rejected = invoke(prover, command, "sk", size, "retired-entry", "retired-start", expect=False)
        assert rejected.returncode == 2 and not (prover / "retired-start").exists()
    invoke(prover, "fixture", "start2d", "sk", SIDE, "test-entry", "start")
    invoke(prover, "fixture", "start2d", "sk", SIDE, "test-entry", "start-retry")
    invoke(prover, "fixture", "start2d", "sk", SIDE, "test-entry", "start")
    assert (prover/"start-retry").read_bytes() == (prover/"start").read_bytes()
    invoke(prover, "fixture", "start2d", "sk", SIDE, "other-test-entry", "other-start")
    invoke(prover, "solve", "pk", "start", "x")
    solution = (prover / "x").read_bytes()
    assert len(solution) == 8 * SIDE**2
    invoke(prover, "commit", "pk", "start", "x", "rows", "digest")
    # Recover a missing second output while preserving a complete row cache.
    (prover/"digest").unlink()
    invoke(prover, "commit", "pk", "start", "x", "rows", "digest")
    invoke(prover, "stamp", "sk", "start", "digest", "finish")
    invoke(prover, "stamp", "sk", "start", "digest", "finish-retry")
    assert (prover/"finish").read_bytes() == (prover/"finish-retry").read_bytes()
    digest = (prover/"digest").read_bytes()
    assert len(digest) == 32
    check_stamp_stdio(prover, digest)
    (prover/"other-digest").write_bytes(bytes([digest[0] ^ 1]) + digest[1:])
    invoke(prover, "stamp", "sk", "start", "other-digest", "other-finish", expect=False)

    invoke(prover, "prove", "pk", "start", "finish", "x", "rows", "proof")
    # Only the transcript moves out of the prover. The other inputs here are
    # the pinned authority key and an independently known public challenge.
    for name in ("pk", "start", "proof"):
        shutil.copy(prover/name, verifier/name)
    assert set(p.name for p in verifier.iterdir()) == {"pk", "start", "proof"}
    result = invoke(verifier, "verify", "pk", "proof", "start")
    rho_text = re.search(r"\brho=(\d+)\b", result.stdout)
    assert rho_text, result.stdout
    start = (verifier/"start").read_bytes()
    expected = exact_rho(start, solution)
    assert int(rho_text[1]) == expected, (rho_text[1], expected)
    invoke(verifier, "verify", "pk", "proof")
    invoke(verifier, "verify", prover/"other-pk", "proof", expect=False)
    invoke(verifier, "verify", "pk", "proof", prover/"other-start", expect=False)

    data = (verifier/"proof").read_bytes()
    rows = 8 + 192 + 160
    rho = rows + SIDE * 32
    projections = rho + 32
    norm = projections + 128 * 16
    handoff = norm + 64 * ((SIDE**2).bit_length() - 1)
    matvec = handoff + 32
    opening = len(data) - SIDE * 32
    assert len(data) < SIDE**2 // 4
    assert data[8:8+192] == start and data[8+192:rows] == (prover/"finish").read_bytes()
    assert data[rows:rho] == (prover/"rows").read_bytes()
    assert int.from_bytes(data[rho:rho+32], "little") == expected

    def reject(contents):
        (verifier/"invalid").write_bytes(contents)
        invoke(verifier, "verify", "pk", "invalid", expect=False)

    for offset in [0, 8+56, 8+192+48, rows, rho, projections, norm, handoff, matvec, opening]:
        bad = bytearray(data)
        bad[offset] ^= 1
        reject(bad)
    reject(data[:opening] + ORDER.to_bytes(32, "little") + data[opening+32:])
    reject(data[:-1])
    reject(data + b"\0")

    with (prover/"changed").open("wb") as f:
        f.write(struct.pack("<d", 0.5))
        f.write(solution[8:])
    changed = invoke(prover, "prove", "pk", "start", "finish", "changed", "rows", "changed-proof",
                     expect=None)
    if changed.returncode == 0:
        invoke(verifier, "verify", "pk", prover/"changed-proof", expect=False)
    with (prover/"bad-x").open("wb") as f:
        f.write(struct.pack("<d", float("nan")))
        f.write(solution[8:])
    invoke(prover, "commit", "pk", "start", "bad-x", "bad-rows", "bad-digest", expect=False)
    # Different binary64 files that round to identical signed fixed-point integers.
    half_steps = [0.5, -0.5, 1.5, -1.5, 2.5, -2.5]
    tie = bytearray(len(solution))
    integers = bytearray(len(solution))
    for j, v in enumerate(half_steps):
        struct.pack_into("<d", tie, 8*j, v/SCALE)
        struct.pack_into("<d", integers, 8*j, round(v)/SCALE)
    for name, content in (("tie", tie), ("integer", integers)):
        (prover/name).write_bytes(content)
        invoke(prover, "commit", "pk", "start", name, name+"-rows", name+"-digest")
    assert (prover/"tie-digest").read_bytes() == (prover/"integer-digest").read_bytes()
    # Binary64 -32 maps exactly to INT64_MIN. The closest double below 32
    # is admissible too; positive 32 and the next double below -32 are outside.
    edges = bytearray(len(solution))
    struct.pack_into("<2d", edges, 0, -32., math.nextafter(32., 0.))
    (prover/"edges").write_bytes(edges)
    invoke(prover, "commit", "pk", "start", "edges", "edge-rows", "edge-digest")
    for value in (32., math.nextafter(-32., -math.inf), math.inf):
        struct.pack_into("<d", edges, 0, value)
        (prover/"bad-edge").write_bytes(edges)
        invoke(prover, "commit", "pk", "start", "bad-edge", "invalid-rows", "invalid-digest",
               expect=False)
    for content in (solution[:-1], solution + b"\0"):
        (prover/"bad-length").write_bytes(content)
        invoke(prover, "commit", "pk", "start", "bad-length", "invalid-rows", "invalid-digest",
               expect=False)
    # The identity commitments open correctly, yet the zero solution misses the
    # numerical target. A verifier distinguishes that case from a bad proof.
    (prover/"zero").write_bytes(bytes(len(solution)))
    invoke(prover, "commit", "pk", "other-start", "zero", "zero-rows", "zero-digest")
    assert (prover/"zero-rows").read_bytes() == bytes(32*SIDE)
    invoke(prover, "stamp", "sk", "other-start", "zero-digest", "zero-finish")
    invoke(prover, "prove", "pk", "other-start", "zero-finish", "zero", "zero-rows", "zero-proof")
    shutil.copy(prover/"zero-proof", verifier/"zero-proof")
    miss = invoke(verifier, "verify", "pk", "zero-proof", expect=None)
    assert miss.returncode == 3 and "target=miss" in miss.stdout, miss
    assert re.search(r"\brho=(\d+)\b", miss.stdout)[1] == str(SIDE**2 * SCALE**2)
    print(f"PASS independent exact rho={expected}, proof-only verification, receipt and tamper checks")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="stencil-test-") as tmp:
        main(Path(tmp))
