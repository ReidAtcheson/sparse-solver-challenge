#!/usr/bin/env bash
# End-to-end Google Compute Engine run. Only source and public outputs cross SSH.
set -euo pipefail
project=${1:?usage: vm3d.sh PROJECT ZONE NEW_VM_NAME NEW_RESULTS_DIRECTORY}
zone=${2:?missing zone}
vm=${3:?missing instance name}
dest=${4:?missing results directory}
root=$(cd "$(dirname "$0")/.." && pwd)
mkdir "$dest"
dest=$(cd "$dest" && pwd)
bundle=$(mktemp -d)
target=(--project="$project" --zone="$zone" --quiet)
created=0
cleanup() {
    if ((created)); then
        gcloud compute instances delete "$vm" "${target[@]}" --delete-disks=all
    fi
}
trap cleanup EXIT
(
    cd "$root"
    tar -czf "$bundle/source.tar.gz" -- *.c *.h Makefile direct3d.mk benchmarks/measure.c benchmarks/run.py benchmarks/run3d.py benchmarks/worker3d.sh
)
gcloud compute instances create "$vm" "${target[@]}" --machine-type=n2-highmem-16 \
    --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
    --boot-disk-size=40GB --boot-disk-type=pd-balanced --boot-disk-auto-delete \
    --no-service-account --no-scopes --max-run-duration=2h --instance-termination-action=DELETE \
    --labels=purpose=stencil-benchmark
created=1
gcloud compute instances describe "$vm" "${target[@]}" \
    --format='json(name,id,creationTimestamp,machineType,cpuPlatform,zone,scheduling.maxRunDuration,disks[0].autoDelete)' > "$dest/instance.json"
ssh_vm() {
    gcloud compute ssh "$vm" "${target[@]}" --ssh-flag="-o ConnectTimeout=10" --command="$1"
}
ready=0
for ((try=1;try<=20;++try)); do
    if ssh_vm true; then ready=1; break; fi
    sleep 5
done
((ready))
gcloud compute scp "$bundle/source.tar.gz" "$vm:source.tar.gz" "${target[@]}"
ssh_vm 'set -e; mkdir -p stencil-run && tar -xzf source.tar.gz -C stencil-run; sudo cloud-init status --wait >/dev/null || test $? -eq 2; sudo sed -i "/^Components: / { /multiverse/! s/$/ multiverse/; }" /etc/apt/sources.list.d/ubuntu.sources; sudo sed -i "s|http://us-central1.gce.archive.ubuntu.com|https://archive.ubuntu.com|g; s|http://security.ubuntu.com|https://security.ubuntu.com|g" /etc/apt/sources.list.d/ubuntu.sources; sudo apt-get -o DPkg::Lock::Timeout=180 update -qq && sudo env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 install -y --no-install-recommends build-essential pkg-config libssl-dev libsodium-dev libmkl-dev libmkl-gnu-thread >/tmp/stencil-packages.log 2>&1 || { tail -40 /tmp/stencil-packages.log; exit 1; }'
ssh_vm 'cd stencil-run && mkdir out && (nohup bash benchmarks/worker3d.sh </dev/null >out/run.log 2>&1 &)'
# SSH connection failures do not interrupt the VM's detached job.
done_status=""
for ((poll=0;poll<225;++poll)); do
    if state=$(ssh_vm 'cd stencil-run && if test -e out/status; then cat out/status; else tail -3 out/run.log >&2 || true; fi'); then
        if [[ $state =~ ^[0-9]+$ ]]; then done_status=$state; break; fi
    fi
    sleep 25
done
[[ -n $done_status ]]
gcloud compute scp --recurse "$vm:stencil-run/out" "$dest" "${target[@]}"
# Verify every downloaded artifact on the local host while the VM still exists.
if [[ $done_status == 0 ]]; then
    for proof in "$dest"/out/public/*/proof.bin; do
        d=$(dirname "$proof")
        "$root/stencil" verify "$d/authority.pub" "$proof" "$d/start.receipt"
    done
fi
exit "$done_status"
