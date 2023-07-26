#!/bin/bash

set -euo pipefail

cd "$(dirname "$0")/.."

. scripts/benchmark-common.sh

BENCHMARK_DIR=benchmarks
BITONIC_CHUNK_SIZE=4096
BUCKET_SIZE=512
MAX_MEM_SIZE=$(( 1 << 35 ))

mkdir -p "$BENCHMARK_DIR"

s=16777216
b=128
last_e=

cleanup() {
    if "$AZ" && [ -n "$last_e" ]; then
        deallocate_az_vm "$ENCLAVE_OFFSET" "$(( last_e + ENCLAVE_OFFSET ))"
    fi
}
trap cleanup EXIT

for e in 32 8 2; do
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

    SED_CLEAR_FLAGS='s/-DDISTRIBUTED_SGX_SORT_MICROBENCHMARK_NOOCOMPACT//g;s/-DDISTRIBUTED_SGX_SORT_MICROBENCHMARK_NOROUTE//g;s/-DDISTRIBUTED_SGX_SORT_MICROBENCHMARK_NOXORSWAP//g'

    for flag_algorithm in \
        '-DDISTRIBUTED_SGX_SORT_MICROBENCHMARK_NOOCOMPACT -DDISTRIBUTED_SGX_SORT_MICROBENCHMARK_NOROUTE -DDISTRIBUTED_SGX_SORT_MICROBENCHMARK_NOXORSWAP:bucketnoocompactnoroutenoxorswap' \
        '-DDISTRIBUTED_SGX_SORT_MICROBENCHMARK_NOROUTE -DDISTRIBUTED_SGX_SORT_MICROBENCHMARK_NOXORSWAP:bucketnoroutenoxorswap' \
        '-DDISTRIBUTED_SGX_SORT_MICROBENCHMARK_NOOCOMPACT -DDISTRIBUTED_SGX_SORT_MICROBENCHMARK_NOXORSWAP:bucketnoocompactnoxorswap' \
        '-DDISTRIBUTED_SGX_SORT_MICROBENCHMARK_NOXORSWAP:bucketnoxorswap' \
        '-DDISTRIBUTED_SGX_SORT_MICROBENCHMARK_NOOCOMPACT -DDISTRIBUTED_SGX_SORT_MICROBENCHMARK_NOROUTE:bucketnoocompactnoroute' \
        '-DDISTRIBUTED_SGX_SORT_MICROBENCHMARK_NOROUTE:bucketnoroute' \
        '-DDISTRIBUTED_SGX_SORT_MICROBENCHMARK_NOOCOMPACT:bucketnoocompact' \
        ; do
        flag=$(echo "$flag_algorithm" | cut -d : -f 1)
        algorithm=$(echo "$flag_algorithm" | cut -d : -f 2)
        sed -Ei'' "$SED_CLEAR_FLAGS;s/^(CPPFLAGS) =( ?)/\\1 = $flag\\2/" Makefile
        make clean
        set_sort_params bucket "$e" "$b" "$s" "$ENCLAVE_OFFSET" "$(( e + ENCLAVE_OFFSET - 1 ))"

        for t in 1 8; do
            output_filename="$BENCHMARK_DIR/$algorithm-sgx2-enclaves$e-bucketsize$BUCKET_SIZE-chunked$BUCKET_SIZE-elemsize$b-size$s-threads$t.txt"
            if [ -f "$output_filename" ]; then
                echo "Output file $output_filename already exists; skipping"
                continue
            fi

            cmd="$cmd_template bucket $s $t $REPEAT"
            echo "Command: $cmd"
            $cmd | tee "$output_filename"
        done
    done
done
