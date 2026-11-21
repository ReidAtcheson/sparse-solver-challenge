#!/bin/bash
# Run inside the task's private VM working directory; stdout goes to out/run.log.
set -euo pipefail
trap 'printf "%d\n" "$?" > out/status' EXIT
make -j8 stencil direct3d
{ lscpu; uname -a; df -T /tmp; dpkg-query -W libmkl-dev libmkl-gnu-thread libsodium-dev libssl-dev gcc; } > out/platform.txt
python3 benchmarks/run3d.py --sides 32 64 128 --trials 3 --threads 8 --check-cap-mib 32 \
    --tag gce-n2-highmem-16 --output out/results.json --public-dir out/public
