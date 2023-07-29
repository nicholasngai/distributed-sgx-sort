#!/bin/bash

set -euo pipefail

cd "$(dirname "$0")/.."

. scripts/benchmark-common.sh

BENCHMARK_DIR=benchmarks
BITONIC_CHUNK_SIZE=4096
BUCKET_SIZE=512
MAX_MEM_SIZE=$(( 1 << 35 ))

mkdir -p "$BENCHMARK_DIR"

e=1
b=128

cleanup() {
    deallocate_az_vm "$ENCLAVE_OFFSET" "$(( ENCLAVE_OFFSET + 1 ))"
}
trap cleanup EXIT

# Build command template.
hosts=''
i=0
while [ "$i" -lt "$e" ]; do
    hosts="${hosts}enclave$(( i + ENCLAVE_OFFSET )),"
    i=$(( i + 1 ))
done
hosts="${hosts%,}"
cmd_template="mpiexec -hosts $hosts ./host/parallel ./enclave/parallel_enc.signed"

set_sort_params bitonic "$e" "$b" 4096 "$ENCLAVE_OFFSET" "$(( e + ENCLAVE_OFFSET - 1 ))"
warm_up="$cmd_template bitonic 4096 1"
echo "Warming up: $warm_up"
$warm_up

for a in bitonic bucket orshuffle; do
    for s in 16777216; do
        if [ "$(get_mem_usage "$a" "$e" "$b" "$s")" -gt "$MAX_MEM_SIZE" ]; then
            echo "Skipping $a with E = $e, b = $b, and N = $s due to size"
            continue
        fi

        set_sort_params "$a" "$e" "$b" "$s" "$ENCLAVE_OFFSET" "$(( e + ENCLAVE_OFFSET - 1 ))"

        for t in 1 2 4 8 16 32 48; do
            if [ "$a" = 'bitonic' ]; then
                output_filename="$BENCHMARK_DIR/$a-sgx2-enclaves$e-chunked$BITONIC_CHUNK_SIZE-elemsize$b-size$s-threads$t.txt"
            elif [ "$a" = 'bucket' ]; then
                output_filename="$BENCHMARK_DIR/$a-sgx2-enclaves$e-bucketsize$BUCKET_SIZE-chunked$BUCKET_SIZE-elemsize$b-size$s-threads$t.txt"
            elif [ "$a" = 'orshuffle' ]; then
                output_filename="$BENCHMARK_DIR/$a-sgx2-enclaves$e-chunked$BITONIC_CHUNK_SIZE-elemsize$b-size$s-threads$t.txt"
            elif [ "$a" = 'ojoin' ]; then
                output_filename="$BENCHMARK_DIR/$a-sgx2-enclaves$e-bucketsize$BUCKET_SIZE-chunked$BUCKET_SIZE-elemsize$b-size$s-threads$t.txt"
            else
                echo 'Invalid algorithm' >&2
                exit -1
            fi

            if [ -f "$output_filename" ]; then
                echo "Output file $output_filename already exists; skipping"
                continue
            fi

            cmd="$cmd_template $a $s $(if [ "$a" = 'ojoin' ]; then echo 256; fi) $t $REPEAT"
            echo "Command: $cmd"
            $cmd | tee "$output_filename"
        done
    done
done
