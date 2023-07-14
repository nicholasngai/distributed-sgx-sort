#!/bin/bash

set -euo pipefail

cd "$(dirname "$0")/.."

. scripts/benchmark-common.sh

BENCHMARK_DIR=benchmarks
BITONIC_CHUNK_SIZE=4096
BUCKET_SIZE=512
MAX_MEM_SIZE=$(( 1 << 38 ))

mkdir -p "$BENCHMARK_DIR"

e=1
b=128

cleanup() {
    if "$AZ"; then
        deallocate_az_vm "$ENCLAVE_OFFSET" "$ENCLAVE_OFFSET"
    fi
}
trap cleanup EXIT

# Build command template.
cmd_template="./host/parallel ./enclave/parallel_enc.signed"

for s in 268435456 67108864 16777216; do
    for t in 160 128 64 32 8 4 2 1; do
        for a in bucket bitonic orshuffle; do
            if [ "$(get_mem_usage "$a" "$e" "$b" "$s")" -gt "$MAX_MEM_SIZE" ]; then
                echo "Skipping $a with E = $e, b = $b, and N = $s due to size"
                continue
            fi

            set_sort_params "$a" "$e" "$b" "$s" "$ENCLAVE_OFFSET" "$(( e + ENCLAVE_OFFSET - 1 ))"

            if [ "$a" = 'bitonic' ]; then
                output_filename="$BENCHMARK_DIR/$a-sgx2chameleon-enclaves$e-chunked$BITONIC_CHUNK_SIZE-elemsize$b-size$s-threads$t.txt"
            elif [ "$a" = 'bucket' ]; then
                output_filename="$BENCHMARK_DIR/$a-sgx2chameleon-enclaves$e-bucketsize$BUCKET_SIZE-elemsize$b-size$s-threads$t.txt"
            elif [ "$a" = 'orshuffle' ]; then
                output_filename="$BENCHMARK_DIR/$a-sgx2chameleon-enclaves$e-elemsize$b-size$s-threads$t.txt"
            else
                echo 'Invalid algorithm' >&2
                exit -1
            fi

            cmd="$cmd_template $a $s $t $REPEAT"
            echo "Command: $cmd"
            $cmd | tee "$output_filename"
        done
    done
done
