#!/bin/bash

set -euo pipefail

cd "$(dirname "$0")/.."

. scripts/benchmark-common.sh

BENCHMARK_DIR=benchmarks
BITONIC_CHUNK_SIZE=4096
BUCKET_SIZE=512

mkdir -p "$BENCHMARK_DIR"

./scripts/sync.sh

for e in 32 16 8 4 2 1; do
    for a in bitonic bucket orshuffle; do
        # Build command template.
        hosts=''
        i=0
        while [ "$i" -lt "$e" ]; do
            hosts="${hosts}enclave$(( i + ENCLAVE_OFFSET )),"
            i=$(( i + 1 ))
        done
        hosts="${hosts%,}"
        cmd_template="mpiexec -hosts $hosts ./host/parallel ./enclave/parallel_enc.signed $a"

        warm_up="$cmd_template 256"
        echo "Warming up: $warm_up"
        $warm_up

        for s in 256 4096 65536 1048576 16777216; do
            for t in 1 2 4; do
                if [ "$a" = 'bitonic' ]; then
                    output_filename="$BENCHMARK_DIR/$a-sgx2-enclaves$e-chunked$BITONIC_CHUNK_SIZE-size$s-threads$t.txt"
                elif [ "$a" = 'bucket' ]; then
                    output_filename="$BENCHMARK_DIR/$a-sgx2-enclaves$e-bucketsize$BUCKET_SIZE-size$s-threads$t.txt"
                elif [ "$a" = 'orshuffle' ]; then
                    output_filename="$BENCHMARK_DIR/$a-sgx2-enclaves$e-size$s-threads$t.txt"
                else
                    echo 'Invalid algorithm' >&2
                    exit -1
                fi

                cmd="$cmd_template $s $t"
                echo "Command: $cmd"
                for i in {1..4}; do
                    $cmd
                done | tee "$output_filename"
            done
        done
    done

    if "$AZ"; then
        deallocate_az_vm "$(( e / 2 + ENCLAVE_OFFSET ))" "$(( e + ENCLAVE_OFFSET ))"
    fi
done
