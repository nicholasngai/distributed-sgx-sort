#!/bin/bash

set -euo pipefail

cd "$(dirname "$0")/.."

. scripts/benchmark-common.sh

BENCHMARK_DIR=benchmarks/baselines
BITONIC_CHUNK_SIZE=4096
BUCKET_SIZE=512

mkdir -p "$BENCHMARK_DIR"

./scripts/sync.sh

for e in 32 16 8 4 2 1; do
    # Build command template.
    hosts=''
    i=0
    while [ "$i" -lt "$e" ]; do
        hosts="${hosts}enclave$(( i + ENCLAVE_OFFSET )),"
        i=$(( i + 1 ))
    done
    hosts="${hosts%,}"
    cmd_template="mpiexec -hosts $hosts"

    warm_up="$cmd_template ./host/parallel ./enclave/parallel_enc.signed bitonic 256 1"
    echo "Warming up: $warm_up"
    $warm_up

    for a in $(find ./baselines -type f -perm -111); do
        for s in 256 4096 65536 1048576 16777216; do
            cmd="$cmd_template $a $k"
            echo "Command: $cmd"
            for i in {1..4}; do
                $cmd
            done | tee "$BENCHMARK_DIR/$(basename "$a")-sgx2-enclaves$e-size$s.txt"
        done
    done

    if "$AZ"; then
        deallocate_az_vm "$(( e / 2 + ENCLAVE_OFFSET ))" "$(( e + ENCLAVE_OFFSET ))"
    fi
done
