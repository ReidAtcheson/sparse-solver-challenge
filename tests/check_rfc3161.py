#!/usr/bin/env python3
"""Offline interoperability checks. Run python3 tests/check_rfc3161.py ./stencil."""
import calendar
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time


def run(directory, *cmd, ok=True):
    result = subprocess.run(cmd, cwd=directory, capture_output=True, text=True,
                            env=dict(os.environ, LC_ALL="C"))
    if (result.returncode == 0) != ok or result.returncode < 0:
        raise AssertionError(f"{cmd}: {result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout


def create_tsa(directory):
    """Generate an ephemeral CA and signer covering both archived beacons and today."""
    key = ("-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes")
    (directory / "issued").mkdir()
    (directory / "index").touch()
    (directory / "cert-serial").write_text("01\n")
    (directory / "issue.cnf").write_text("""[ca]
default_ca = local
[local]
new_certs_dir = issued
database = index
serial = cert-serial
private_key = ca.key
certificate = ca.pem
default_md = sha256
policy = simple
[simple]
commonName = supplied
[root]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign
subjectKeyIdentifier = hash
[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,timeStamping
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
""")
    issue = ("openssl", "ca", "-batch", "-config", "issue.cnf", "-notext",
             "-startdate", "230101000000Z", "-enddate", "21230101000000Z")
    run(directory, "openssl", "req", "-new", *key, "-subj", "/CN=Test timestamp root",
        "-keyout", "ca.key", "-out", "ca.csr")
    run(directory, *issue, "-selfsign", "-in", "ca.csr", "-out", "ca.pem", "-extensions", "root")
    run(directory, "openssl", "req", "-new", *key, "-subj", "/CN=Test timestamp authority",
        "-keyout", "tsa.key", "-out", "tsa.csr")
    run(directory, *issue, "-in", "tsa.csr", "-out", "tsa.pem", "-extensions", "leaf")
    (directory / "serial").write_text("01\n")
    (directory / "tsa.cnf").write_text("""[tsa]
default_tsa = local
[local]
serial = serial
signer_cert = tsa.pem
signer_key = tsa.key
signer_digest = sha256
certs = ca.pem
default_policy = 1.2.3.4.5
other_policies = 1.2.3.4.6
digests = sha256, sha3-256
accuracy = secs:1, millisecs:2, microsecs:3
clock_precision_digits = 6
ordering = no
tsa_name = yes
ess_cert_id_alg = sha256
""")


def sign_query(directory, query, response):
    run(directory, "openssl", "ts", "-reply", "-config", "tsa.cnf",
        "-queryfile", query, "-out", response)


def check(directory, binary):
    create_tsa(directory)
    digest = hashlib.sha256(b"test attempt and commitment").digest()
    (directory / "digest").write_bytes(digest)
    run(directory, binary, "tsa-query", "digest", "request.tsq")
    sign_query(directory, "request.tsq", "stamp.tsr")
    run(directory, "openssl", "ts", "-verify", "-queryfile", "request.tsq",
        "-in", "stamp.tsr", "-CAfile", "ca.pem")
    printed = run(directory, "openssl", "ts", "-reply", "-text", "-in", "stamp.tsr")
    date = re.search(r"Time stamp: (\w+\s+\d+ \d\d:\d\d:\d\d)(?:\.(\d+))? (\d{4}) GMT", printed)
    assert date, printed
    whole = calendar.timegm(time.strptime(date[1] + " " + date[3], "%b %d %H:%M:%S %Y"))
    stamp_ns = whole * 10**9 + int((date[2] or "").ljust(9, "0"))
    args = (binary, "tsa-verify", "ca.pem", "digest")
    assert run(directory, *args, "stamp.tsr").strip() == (
        f"unix_ns={stamp_ns} accuracy_ns=1002003000")
    run(directory, *args, "stamp.tsr", "1.2.3.4.5")
    run(directory, *args, "stamp.tsr", "1.2.3.4.6", ok=False)
    run(directory, *args, "stamp.tsr", "SHA256", ok=False)
    run(directory, binary, "tsa-query", "digest", "specific.tsq", "1.2.3.4.6")
    sign_query(directory, "specific.tsq", "specific.tsr")
    run(directory, *args, "specific.tsr", "1.2.3.4.6")
    run(directory, *args, "specific.tsr", "1.2.3.4.5", ok=False)

    (directory / "wrong").write_bytes(hashlib.sha256(digest).digest())
    run(directory, binary, "tsa-verify", "ca.pem", "wrong", "stamp.tsr", ok=False)
    other = directory / "unrelated"
    other.mkdir()
    create_tsa(other)
    run(directory, binary, "tsa-verify", other / "ca.pem", "digest", "stamp.tsr", ok=False)
    run(directory, *args, "request.tsq", ok=False)
    response = (directory / "stamp.tsr").read_bytes()
    for changed in [response + b"\0", response[:-1], response[:-1] + bytes([response[-1] ^ 1])]:
        (directory / "altered.tsr").write_bytes(changed)
        run(directory, *args, "altered.tsr", ok=False)
    # Equal digest length and identical bytes, different hash function OID.
    run(directory, "openssl", "ts", "-query", "-digest", digest.hex(), "-sha3-256",
        "-cert", "-out", "other.tsq")
    sign_query(directory, "other.tsq", "other.tsr")
    run(directory, "openssl", "ts", "-verify", "-queryfile", "other.tsq",
        "-in", "other.tsr", "-CAfile", "ca.pem")
    run(directory, *args, "other.tsr", ok=False)

    conf = directory / "tsa.cnf"
    conf.write_text(re.sub(r"^accuracy = .*\n", "", conf.read_text(), flags=re.MULTILINE))
    sign_query(directory, "request.tsq", "unknown.tsr")
    assert run(directory, *args, "unknown.tsr").strip().endswith(" accuracy_ns=unknown")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        check(Path(tmp), Path(sys.argv[1] if len(sys.argv) > 1 else "./stencil").resolve())
    print("RFC 3161 offline interoperability and rejection checks passed")
