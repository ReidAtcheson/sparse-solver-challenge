#!/usr/bin/env python3
"""Offline quicknet/RFC 3161 integration against archived signature vectors."""
import ctypes as C
import hashlib
import math
import os
from pathlib import Path
import shutil
import sys
import subprocess
import tempfile
import time

from check_rfc3161 import create_tsa, run
from library import three_band_reference
ROOT = Path(__file__).resolve().parents[1]
sys.path.extend([str(ROOT / "examples"), str(ROOT / "benchmarks")])
from library_solve import checked, Handle, load
from signed3d import integer_scores

# Source: https://api.drand.sh/<quicknet-chain-hash>/public/<round>
ROUNDS = {
    1: "b55e7cb2d5c613ee0b2e28d6750aabbb78c39dcc96bd9d38"
       "c2c2e12198df95571de8e8e402a0cc48871c7089a2b3af4b",
    34_000_000: "b4fec76939fa077a38b30d35cc5cc2426f9bfef2e9363b89"
                "787d2466a29ab01be346b95e771c727676e54368ef662dbb",
}
POLICY = "1.2.3.4.5"


def instance_seed(reg, start_sig):
    chain = bytes.fromhex("52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971")
    manifest = reg.read_bytes()
    entropy = hashlib.sha256(start_sig.read_bytes()).digest()
    return hashlib.sha256(b"stencil-quicknet-instance-v1" + chain + manifest[8:52]
                          + manifest[56:64] + entropy).digest()


def check_three_band(base, binary, clock, start_sig, end_sig, tsa):
    private, public = base / "band-entrant", base / "band-validator"
    private.mkdir()
    public.mkdir()
    n = 1024
    (private / "nonce").write_bytes(bytes(range(32)))
    args = (str(n), "solver", "nonce", start_sig.name, end_sig.name, "2000000000")
    reg = private / "reg"
    for retired, rows in (("three-band-v1", 1024), ("3d", 32), ("signed3d", 32), ("2d", 512)):
        run(private, binary, "beacon-register", retired, str(rows), *args[1:], "retired-reg", ok=False)
        assert not (private / "retired-reg").exists()
    run(private, binary, "beacon-register", *args, reg)
    run(private, binary, "beacon-register", "three-band", *args, "explicit-reg")
    assert reg.read_bytes() == (private / "explicit-reg").read_bytes()
    assert reg.read_bytes()[8:48].rstrip(b"\0") == b"signed-three-band-backward80-v2"
    run(private, binary, "beacon-start", reg, start_sig, "start")

    # The deliberately inaccurate x = e_0/n has an exactly predictable score.
    # This exercises a nonidentity commitment without a solver dependency.
    x = (C.c_double * n)(1/n)
    (private / "x").write_bytes(bytes(x))
    run(private, binary, "commit", reg, "start", "x", "rows", "digest")
    run(private, binary, "beacon-query", reg, "start", "digest", tsa / "band.tsq", POLICY)
    run(tsa, clock, "band.tsq", "1704067200", "band.tsr")
    ca, token = tsa / "ca.pem", tsa / "band.tsr"
    run(private, binary, "beacon-verify-stamp", reg, ca, POLICY, "start", "digest", token)
    run(private, binary, "prove-beacon", reg, ca, POLICY, "start", "digest", token,
        end_sig, "x", "rows", public / "proof")
    for path in (reg, ca, private / "digest"):
        shutil.copy(path, public / path.name)
    assert {p.name for p in public.iterdir()} == {"reg", "ca.pem", "digest", "proof"}
    result = subprocess.run([binary, "verify-beacon", "reg", "ca.pem", POLICY, "digest", "proof"],
                            cwd=public, capture_output=True, text=True)
    assert result.returncode == 3, (result.returncode, result.stdout, result.stderr)
    metrics = dict(word.split("=", 1) for word in result.stdout.split() if "=" in word)
    assert metrics["target"] == "miss" and int(metrics["exponent"]) == -10
    assert int(metrics["x_squared"]) == 1 << 156
    reference = three_band_reference(binary, n, instance_seed(reg, start_sig))
    energy = sum((dict(row).get(0, 0) - int(rhs*n))**2 for row, rhs in reference) << 156
    assert int(metrics["rho"]) == energy


def check_signed3d(base, binary, clock, reg, start_sig, end_sig, tsa):
    private, public = base / "signed-entrant", base / "signed-validator"
    private.mkdir()
    public.mkdir()
    start = private / "start"
    solution = private / "x"
    run(private, binary, "beacon-start", reg, start_sig, start)
    run(private, binary, "solve", reg, start, solution)
    run(private, binary, "commit", reg, start, solution, "rows", "digest")

    api = load(binary.with_name("libstencil.so"))
    handle = Handle()
    checked(api.stencil_instance_open(os.fsencode(reg), os.fsencode(start), C.byref(handle)))
    try:
        n = api.stencil_row_count(handle)
        assert n == 32**3
        x = (C.c_double * n).from_buffer_copy(solution.read_bytes())
        rows = (C.c_uint8 * api.stencil_commit_size(handle))()
        digest = (C.c_uint8 * 32)()
        checked(api.stencil_commit(handle, x, n, rows, len(rows), digest))
        assert bytes(rows) == (private / "rows").read_bytes()
        assert bytes(digest) == (private / "digest").read_bytes()
    finally:
        api.stencil_close(handle)

    run(private, binary, "beacon-query", reg, start, "digest", tsa / "signed.tsq", POLICY)
    run(tsa, clock, "signed.tsq", "1704067200", "signed.tsr")
    token, ca = tsa / "signed.tsr", tsa / "ca.pem"
    run(private, binary, "prove-beacon", reg, ca, POLICY, start, "digest", token, end_sig,
        solution, "rows", public / "proof")
    shutil.copy(reg, public / "reg")
    shutil.copy(ca, public / "ca.pem")
    (public / "digest").write_bytes(bytes(digest))
    report = run(public, binary, "verify-beacon", "reg", "ca.pem", POLICY, "digest", "proof")
    metrics = dict(word.split("=", 1) for word in report.split() if "=" in word)
    assert metrics["target"] == "pass"
    assert {p.name for p in public.iterdir()} == {"reg", "ca.pem", "digest", "proof"}

    # Regenerate the native instance seed and compute both energies in Python integers.
    seed = instance_seed(reg, start_sig)
    scores = integer_scores(32, seed, solution)
    for key in ("exponent", "rho", "x_squared"):
        assert int(metrics[key]) == scores[key]
    assert math.isclose(float(metrics["backward_2"]), scores["backward_2"], rel_tol=1e-15)
    proof_size = (public / "proof").stat().st_size
    assert proof_size < n
    print(f"signed3d rows={n} proof_bytes={proof_size} DER_bytes={token.stat().st_size} "
          f"backward_2={metrics['backward_2']}")


def check(base, binary, clock):
    prover, validator, tsa = base / "entrant", base / "validator", base / "tsa"
    for directory in (prover, validator, tsa):
        directory.mkdir()
    create_tsa(tsa)
    (prover / "nonce").write_bytes(bytes(range(32)))
    for rnd, sig in ROUNDS.items():
        (prover / str(rnd)).write_bytes(bytes.fromhex(sig))
    start_sig, end_sig = (str(rnd) for rnd in ROUNDS)
    check_three_band(base, binary, clock, prover / start_sig, prover / end_sig, tsa)
    register = (binary, "fixture", "beacon-register", "3d", "32", "alice", "nonce",
                start_sig, end_sig, "2000000000")
    run(prover, *register, "reg")
    run(prover, binary, "beacon-start", "reg", end_sig, "wrong-start", ok=False)
    run(prover, binary, "beacon-start", "reg", start_sig, "start")
    run(prover, binary, "solve", "reg", "start", "x")
    run(prover, binary, "commit", "reg", "start", "x", "rows", "digest")
    run(prover, binary, "beacon-query", "reg", "start", "digest", tsa / "query", POLICY)
    run(tsa, clock, "query", "1704067200", "token")   # 2024-01-01 UTC
    ca = tsa / "ca.pem"
    verify_stamp = (binary, "beacon-verify-stamp", "reg", ca, POLICY, "start", "digest")
    assert run(prover, *verify_stamp, tsa / "token").split() == [
        "start_scheduled_ns=1692803367000000000", "commitment_utc_ns=1704067200000000000",
        "clock_uncertainty_ns=2000000000"]
    # A valid TSA signature directly over the row digest has a different
    # imprint from the one required for this attempt.
    run(prover, binary, "tsa-query", "digest", tsa / "bare.tsq", POLICY)
    run(tsa, clock, "bare.tsq", "1704067200", "bare.tsr")
    run(prover, binary, "tsa-verify", ca, "digest", tsa / "bare.tsr", POLICY)
    run(prover, *verify_stamp, tsa / "bare.tsr", ok=False)
    prove = (binary, "prove-beacon", "reg", ca, POLICY, "start", "digest")
    run(prover, *prove, tsa / "token", end_sig, "x", "rows", "proof")

    # Emulate a separate validator with public registration, independently
    # pinned digest and trust, plus the entrant's self-contained proof.
    for name in ("reg", "digest", "proof"):
        shutil.copy(prover / name, validator / name)
    shutil.copy(ca, validator / "ca.pem")
    verify = (binary, "verify-beacon", "reg", "ca.pem", POLICY, "digest")
    run(validator, *verify, "proof")
    transcript = (validator / "proof").read_bytes()
    assert len(transcript) < 32**3
    assert transcript[:8] == b"STNPRF03"
    offset = 8 + 192
    assert transcript[offset:offset+32] == (validator / "digest").read_bytes()
    sig_end = offset + 32 + 48
    assert transcript[offset+32:sig_end] == bytes.fromhex(ROUNDS[34_000_000])
    tsr = (tsa / "token").read_bytes()
    assert int.from_bytes(transcript[sig_end:sig_end+4], "little") == len(tsr)
    assert transcript[sig_end+4:sig_end+4+len(tsr)] == tsr
    # Another valid receipt for the same commitment cannot select new
    # Fiat-Shamir challenges. Replace only the receipt and its framing.
    run(tsa, clock, "query", "1704067201", "second-token")
    second = (tsa / "second-token").read_bytes()
    (validator / "second-proof").write_bytes(transcript[:sig_end] + len(second).to_bytes(4, "little")
            + second + transcript[sig_end+4+len(tsr):])
    run(validator, *verify, "second-proof")

    other = base / "unrelated-tsa"
    other.mkdir()
    create_tsa(other)
    run(validator, binary, "verify-beacon", "reg", other / "ca.pem", POLICY, "digest",
        "proof", ok=False)
    run(validator, binary, "verify-beacon", "reg", "ca.pem", "1.2.3.4.6", "digest",
        "proof", ok=False)
    (validator / "other-digest").write_bytes(bytes(32))
    run(validator, binary, "verify-beacon", "reg", "ca.pem", POLICY, "other-digest",
        "proof", ok=False)
    run(prover, binary, "fixture", "beacon-register", "signed3d", "32", "alice", "nonce", start_sig,
        end_sig, "2000000000", validator / "other-reg")
    run(prover, binary, "beacon-verify-stamp", validator / "other-reg", ca, POLICY,
        "start", "digest", tsa / "token", ok=False)
    run(validator, binary, "verify-beacon", "other-reg", "ca.pem", POLICY, "digest",
        "proof", ok=False)
    check_signed3d(base, binary, clock, validator / "other-reg", prover / start_sig,
                   prover / end_sig, tsa)
    def reject(modified):
        (validator / "modified").write_bytes(modified)
        run(validator, *verify, "modified", ok=False)

    for pos in (0, 8, offset, offset + 32, sig_end + 4, len(transcript) - 1):
        modified = bytearray(transcript)
        modified[pos] ^= 1
        reject(modified)
    for length in (0, len(tsr) - 1, len(tsr) + 1, 0xffffffff):
        reject(transcript[:sig_end] + length.to_bytes(4, "little") + transcript[sig_end+4:])
    reject(transcript + b"\x00")
    reject(transcript[:sig_end+3])

    # These are authentic signatures on the correct digest. At the first
    # boundary the upper uncertainty limit overlaps the finish round. At the
    # second boundary the lower limit overlaps the start round.
    for seconds in ("1794803363", "1692803368"):
        run(tsa, clock, "query", seconds, "overlap")
        run(prover, *verify_stamp, tsa / "overlap", ok=False)
        run(prover, *prove, tsa / "overlap", end_sig, "x", "rows", "reject", ok=False)
    run(prover, *prove, tsa / "token", start_sig, "x", "rows", "reject", ok=False)
    # The TSA certificate is currently valid, but did not exist at genTime.
    (tsa / "imprint").write_bytes(bytes(32))
    run(tsa, binary, "tsa-query", "imprint", "old.tsq")
    run(tsa, clock, "old.tsq", "1577836800", "outside-cert-validity")
    run(tsa, "openssl", "ts", "-verify", "-queryfile", "old.tsq", "-CAfile", "ca.pem",
        "-in", "outside-cert-validity")
    # Check the RFC 3161 verifier directly, independently of the round window.
    run(tsa, binary, "tsa-verify", "ca.pem", "imprint", "outside-cert-validity", POLICY, ok=False)

    # Exercise registrar publication before an as-yet-unreleased round.
    # No future signature is needed to record one commitment. Set cutoff
    # well after the current date and reuse the archived start signature.
    ledger = base / "ledger"
    ledger.mkdir()
    future = 2 + (int(time.time()) - 1692803367) // 3 + 86400
    run(prover, binary, "fixture", "beacon-register", "3d", "32", "alice", "nonce", start_sig,
        str(future), "2000000000", "open-reg")
    run(prover, binary, "beacon-start", "open-reg", start_sig, "open-start")
    record = (binary, "beacon-record", "open-reg", ca, POLICY, "open-start")
    for name in ("digest", "other-digest"):
        if name == "other-digest":
            (prover / name).write_bytes(bytes(32))
        run(prover, binary, "beacon-query", "open-reg", "open-start", name, tsa / (name+".tsq"))
        run(tsa, clock, name+".tsq", "1704067200", name+".tsr")
        run(prover, *record, name, tsa / (name+".tsr"), ledger, ok=(name == "digest"))
    run(prover, *record, "digest", tsa / "digest.tsr", ledger)
    files = [p for p in ledger.iterdir() if not p.name.startswith(".")]
    assert len(files) == 1 and files[0].read_bytes() == (prover / "digest").read_bytes()
    # Two authenticated requests arriving together can publish only one winner.
    race = base / "race-ledger"
    race.mkdir()
    submissions = [subprocess.Popen([*record, name, tsa / (name+".tsr"), race], cwd=prover,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE) for name in ("digest", "other-digest")]
    for process in submissions:
        process.communicate()
    assert sorted(p.returncode for p in submissions) == [0, 1]
    winning_name = "digest" if submissions[0].returncode == 0 else "other-digest"
    race_record, = (p for p in race.iterdir() if not p.name.startswith("."))
    assert race_record.read_bytes() == (prover / winning_name).read_bytes()
    if time.time_ns() >= 1794803364 * 10**9:
        run(prover, binary, "beacon-record", "reg", ca, POLICY, "start", "digest",
            tsa / "token", ledger, ok=False)


if __name__ == "__main__":
    binary, clock = (Path(arg).resolve() for arg in sys.argv[1:])
    with tempfile.TemporaryDirectory() as tmp:
        check(Path(tmp), binary, clock)
    print("native drand and RFC 3161 proof transcript accepted and adverse cases rejected")
