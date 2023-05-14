#!/bin/bash

set -euo pipefail

cd "$(dirname "$0")/.."

. scripts/benchmark-common.sh

BENCHMARK_DIR=benchmarks

mkdir -p "$BENCHMARK_DIR"

a=bitonic
b=128
s=16777216
t=1
last_e=

cleanup() {
    if "$AZ" && [ -n "$last_e" ]; then
        deallocate_az_vm "$ENCLAVE_OFFSET" "$(( last_e + ENCLAVE_OFFSET ))"
    fi
}
trap cleanup EXIT

for e in 32 16 8 4 2; do
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

    set_sort_params bitonic "$e" "$b" 4096 "$ENCLAVE_OFFSET" "$(( e + ENCLAVE_OFFSET - 1 ))"
    warm_up="$cmd_template bitonic 4096 1"
    echo "Warming up: $warm_up"
    $warm_up

    for c in 1 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384; do
        if [ "$e" -ne 4 ] && [ "$e" -ne 16 ] && [ "$c" -lt 64 ]; then
            continue
        fi

        echo "Chunk size: $c"

        (
            flock 9
            sed -Ei "s/^#define (SWAP_CHUNK_SIZE) .*\$/#define \\1 $c/" enclave/bitonic.c
            set_sort_params_unlocked "$a" "$e" "$b" "$s" "$ENCLAVE_OFFSET" "$(( e + ENCLAVE_OFFSET - 1 ))"
        ) 9<.

        output_filename="$BENCHMARK_DIR/$a-sgx2-enclaves$e-chunked$c-elemsize$b-size$s-threads$t.txt"
        if [ -f "$output_filename" ]; then
            echo "Output file $output_filename already exists; skipping"
            continue
        fi

        cmd="$cmd_template $a $s $t $REPEAT"
        echo "Command: $cmd"
        $cmd | tee "$output_filename"
    done
done
