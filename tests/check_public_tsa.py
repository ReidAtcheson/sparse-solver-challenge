#!/usr/bin/env python3
"""Replay real public RFC 3161 fixtures and exercise HTTP submission offline."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "examples/public-tsa"
FIXTURES = HELPER.parent / "tsa"
# Provider policy, URL, genTime and inclusive certificate validity intersection
# (Unix seconds) for these specific responses on SHA256("abc").
CASES = {
    "freetsa": ("1.2.3.4.1", "https://freetsa.org/tsr", 1795283920, 1771184662, 2211824662),
    "sigstore": ("1.3.6.1.4.1.57264.2", "https://timestamp.sigstore.dev/api/v1/timestamp",
                 1795283921, 1744095583, 2059455583),
}


def run(*args, env=None, ok=True):
    result = subprocess.run(args, capture_output=True, text=True, env=env)
    if result.returncode < 0 or (result.returncode == 0) != ok:
        raise AssertionError(f"{args}: {result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout.strip()


def check(work):
    # Capture the actual DER query and deliver a fixture in place of any network request.
    curl = work / "curl"
    curl.write_text("""#!/bin/sh
set -eu
out='' req=''
while [ "$#" -gt 1 ]; do
    case "$1" in
        --output|-o) out=$2; shift 2 ;;
        --data-binary) req=$2; shift 2 ;;
        *) shift ;;
    esac
done
[ "$1" = "$TSA_TEST_URL" ]
cp "${req#@}" "$TSA_TEST_QUERY"
cp "$TSA_TEST_REPLY" "$out"
""")
    curl.chmod(0o700)
    digest = work / "digest"
    digest.write_bytes(hashlib.sha256(b"abc").digest())
    wrong = work / "wrong"
    wrong.write_bytes(bytes(32))
    for name, (policy, url, gen_time, start, end) in CASES.items():
        cert = FIXTURES / f"{name}-root.crt"
        receipt = FIXTURES / f"{name}-abc.tsr"
        other = next(key for key in CASES if key != name)
        assert run(HELPER, name, "root") == str(cert)
        assert run(HELPER, name, "policy") == policy
        request = work / f"{name}.tsq"
        verify = ("openssl", "ts", "-verify", "-in", receipt, "-attime", str(gen_time))
        for required_policy, matches in [(policy, True), (CASES[other][0], False)]:
            run("openssl", "ts", "-query", "-sha256", "-digest", digest.read_bytes().hex(),
                "-tspolicy", required_policy, "-cert", "-no_nonce", "-out", request)
            run(*verify, "-queryfile", request, "-CAfile", cert, ok=matches)
        run(*verify, "-digest", wrong.read_bytes().hex(), "-CAfile", cert, ok=False)
        run(*verify, "-digest", digest.read_bytes().hex(), "-CAfile", FIXTURES / f"{other}-root.crt",
            ok=False)

        valid_now = start <= time.time() < end
        report = run(HELPER, name, "verify", digest, receipt, ok=valid_now)
        if valid_now:
            assert f"unix_ns={gen_time * 10**9}" in report.split()
        run(HELPER, name, "verify", wrong, receipt, ok=False)
        run(HELPER, other, "verify", digest, receipt, ok=False)
        run(ROOT / "stencil", "tsa-verify", cert, digest, receipt, CASES[other][0], ok=False)

        target = work / f"{name}.tsr"
        env = dict(os.environ, PATH=str(work) + os.pathsep + os.environ["PATH"],
                   TSA_TEST_QUERY=str(request), TSA_TEST_URL=url, TSA_TEST_REPLY=str(receipt))
        run(HELPER, name, "stamp", digest, target, env=env, ok=valid_now)
        run(*verify, "-queryfile", request, "-CAfile", cert)
        if valid_now:
            assert target.read_bytes() == receipt.read_bytes()
            target.unlink()
        assert not target.exists()
        run(HELPER, name, "stamp", wrong, target, env=env, ok=False)
        assert not target.exists()
        tampered = work / "truncated"
        tampered.write_bytes(receipt.read_bytes()[:-1])
        env["TSA_TEST_REPLY"] = str(tampered)
        run(HELPER, name, "stamp", digest, target, env=env, ok=False)
        assert not target.exists()
        target.write_bytes(b"existing file")
        run(HELPER, name, "stamp", digest, target, env=env, ok=False)
        assert target.read_bytes() == b"existing file"
        assert not list(work.glob(".public-tsa.*"))


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as directory:
        check(Path(directory))
    print("PASS public TSA fixtures, policy/trust/imprint checks and offline submission wrapper")
