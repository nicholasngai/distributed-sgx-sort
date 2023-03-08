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

    warm_up="$cmd_template bitonic 256"
    echo "Warming up: $warm_up"
    $warm_up

    for b in 512 1024 2048 4096 8192 16384 32768 65536 131072 262144 524288 1048576 2097152 4194304; do
        echo "Bucket size: $b"

        find . -name '*.[ch]' -print0 | xargs -0 sed -Ei "s/^#define (BUCKET_SIZE) .*\$/#define \\1 $b/"

        make -j
        ./scripts/sync.sh

        for s in 256 4096 65536 1048576 16777216; do
            for t in 1 2 4; do
                cmd="$cmd_template $a $s $t"
                echo "Command: $cmd"
                for i in {1..4}; do
                    $cmd
                done | tee "$BENCHMARK_DIR/$a-sgx2-enclaves$e-bucketsize$b-elemsize128-size$s-threads$t.txt"
            done
        done
    done

    last_e=$e
done

if "$AZ" && [ -n "$last_e" ]; then
    deallocate_az_vm "$ENCLAVE_OFFSET" "$(( last_e + ENCLAVE_OFFSET ))"
fi
