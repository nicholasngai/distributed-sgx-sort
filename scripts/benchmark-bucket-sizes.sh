#!/bin/bash

set -euo pipefail

cd "$(dirname "$0")/.."

. scripts/benchmark-common.sh

BENCHMARK_DIR=benchmarks

mkdir -p "$BENCHMARK_DIR"

find . -name '*.[ch]' -print0 | xargs -0 sed -Ei "$(cat <<EOF
s/^#define (CACHE_SETS) .*$/#define \1 $CACHE_SETS/
EOF
)"

a=bucket
last_e=

cleanup() {
    if "$AZ" && [ -n "$last_e" ]; then
        deallocate_az_vm "$ENCLAVE_OFFSET" "$(( last_e + ENCLAVE_OFFSET ))"
    fi
}
trap cleanup EXIT

for e in 32 16 8 4 2 1; do
    if "$AZ" && [ -n "$last_e" ]; then
        deallocate_az_vm "$(( e + ENCLAVE_OFFSET ))" "$(( last_e + ENCLAVE_OFFSET ))"
    fi
    last_e=$e

    # Build command template.
    hosts=''
    i=0
    while [ "$i" -lt "$e" ]; do
        hosts="${hosts}enclave$(( i + ENCLAVE_OFFSET )),"
        i=$(( i + 1 ))
    done
    hosts="${hosts%,}"
    cmd_template="mpiexec -hosts $hosts ./host/parallel ./enclave/parallel_enc.signed"

    warm_up="$cmd_template bitonic 256 1"
    echo "Warming up: $warm_up"
    $warm_up

    for b in 512 1024 2048 4096 8192 16384 32768 65536 131072 262144 524288 1048576 2097152 4194304; do
        echo "Bucket size: $b"

        find . -name '*.[ch]' -print0 | xargs -0 sed -Ei "s/^#define (BUCKET_SIZE) .*\$/#define \\1 $b/"

        make -j
        ./scripts/sync.sh

        for s in 256 4096 65536 1048576 16777216; do
            set_sort_params "$a" "$e" "$b" "$s" "$ENCLAVE_OFFSET" "$(( e + ENCLAVE_OFFSET - 1 ))"

            for t in 1 2 4; do
                output_filename="$BENCHMARK_DIR/$a-sgx2-enclaves$e-bucketsize$b-elemsize128-size$s-threads$t.txt"
                if [ -f "$output_filename" ]; then
                    echo "Output file $output_filename already exists; skipping"
                    continue
                fi

                cmd="$cmd_template $a $s $t $REPEAT"
                echo "Command: $cmd"
                $cmd | tee "$output_filename"
            done
        done
    done
done
