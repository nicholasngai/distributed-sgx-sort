#!/bin/bash

set -euo pipefail

cd "$(dirname "$0")/.."

BENCHMARK_DIR=benchmarks/baselines
BITONIC_CHUNK_SIZE=4096
BUCKET_SIZE=512

if [ ! -z "${AZ+x}" ]; then
    export AZDCAP_DEBUG_LOG_LEVEL=0
    AZ=true
    last_e=
else
    AZ=false
fi

mkdir -p "$BENCHMARK_DIR"

./scripts/sync.sh

for e in 32 16 8 4 2 1; do
    # Deallocate previous machines.
    if "$AZ" && [ ! -z "$last_e" ]; then
        i=$(( last_e - 1 ))
        while [ "$i" -ge "$e" ]; do
            az vm deallocate -g enclave_group -n "enclave$i" --no-wait
            i=$(( i - 1 ))
        done
    fi

    for a in $(find ./baselines -type f -perm -111); do
        # Build command template.
        hosts=''
        i=0
        while [ "$i" -lt "$e" ]; do
            hosts="${hosts}enclave$i,"
            i=$(( i + 1 ))
        done
        hosts="${hosts%,}"
        cmd_template="mpiexec -hosts $hosts $(printf %q "$a")"

        warm_up="$cmd_template 256"
        echo "Warming up: $warm_up"
        $warm_up

        for s in 256 4096 65536 1048576 16777216; do
            cmd="$cmd_template $s"
            echo "Command: $cmd"
            for i in {1..4}; do
                $cmd
            done | tee "$BENCHMARK_DIR/$(basename "$a")-enclaves$e-size$s.txt"
        done
    done

    if "$AZ"; then
        last_e="$e"
    fi
done

# Deallocate remaining machines.
if "$AZ"; then
    i=$(( last_e - 1 ))
    while [ "$i" -ge "$e" ]; do
        az vm deallocate -g enclave_group -n "enclave$i" --no-wait
        i=$(( i - 1 ))
    done
fi
