#!/bin/bash

set -euo pipefail

cd "$(dirname "$0")/.."

. scripts/benchmark-common.sh

BENCHMARK_DIR=benchmarks
BITONIC_CHUNK_SIZE=4096
BUCKET_SIZE=512
MAX_MEM_SIZE=34359738368

mkdir -p "$BENCHMARK_DIR"

./scripts/sync.sh

b=128
last_e=
for e in 32 16 8 4 2 1; do
    if "$AZ" && [ -n "$last_e" ]; then
        deallocate_az_vm "$(( e + ENCLAVE_OFFSET ))" "$(( last_e + ENCLAVE_OFFSET ))"
    fi

    # Build command template.
    hosts=''
    i=0
    while [ "$i" -lt "$e" ]; do
        hosts="${hosts}enclave$(( i + ENCLAVE_OFFSET )),"
        i=$(( i + 1 ))
    done
    hosts="${hosts%,}"
    cmd_template="mpiexec -hosts $hosts ./host/parallel ./enclave/parallel_enc.signed"

    warm_up="$cmd_template bitonic 4096 1"
    echo "Warming up: $warm_up"
    $warm_up

    for a in bitonic bucket orshuffle; do
        for s in 1048576 4194304 16777216 67108864 268435456 1073741824; do
            if [ "$(get_mem_usage "$a" "$e" "$b" "$s")" -gt "$MAX_MEM_SIZE" ]; then
                echo "Skipping $a with E = $e and N = $s due to size"
                continue
            fi

            for t in 1 2 4 8; do
                if [ "$a" = 'bitonic' ]; then
                    output_filename="$BENCHMARK_DIR/$a-sgx2-enclaves$e-chunked$BITONIC_CHUNK_SIZE-elemsize$b-size$s-threads$t.txt"
                elif [ "$a" = 'bucket' ]; then
                    output_filename="$BENCHMARK_DIR/$a-sgx2-enclaves$e-bucketsize$BUCKET_SIZE-elemsize$b-size$s-threads$t.txt"
                elif [ "$a" = 'orshuffle' ]; then
                    output_filename="$BENCHMARK_DIR/$a-sgx2-enclaves$e-elemsize$b-size$s-threads$t.txt"
                else
                    echo 'Invalid algorithm' >&2
                    exit -1
                fi

                cmd="$cmd_template $a $s $t"
                echo "Command: $cmd"
                for i in {1..4}; do
                    $cmd
                done | tee "$output_filename"
            done
        done
    done

    last_e=$e
done

if "$AZ" && [ -n "$last_e" ]; then
    deallocate_az_vm "$ENCLAVE_OFFSET" "$(( last_e + ENCLAVE_OFFSET ))"
fi
