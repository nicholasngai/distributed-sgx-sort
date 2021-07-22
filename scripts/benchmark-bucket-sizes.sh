#!/bin/bash

set -euo pipefail

cd "$(dirname "$0")/.."

BENCHMARK_DIR=benchmarks

export AZDCAP_DEBUG_LOG_LEVEL=0

mkdir -p "${BENCHMARK_DIR}"

for b in 1 2 4 8 16 32 64 128 256 1024 2048 4096 8192 16384 32768; do
    echo "Bucket size: $b"

    find .. -name '*.[ch]' -print0 | xargs -0 sed -Ei "s/^#define (BUCKET_SIZE) .*$/#define \1 $b/"
    make -j
    ./scripts/sync.sh

    for e in 1 2 4 8 16 32; do
        # Build command template.
        hosts=''
        i=0
        while [ "$i" -lt "$e" ]; do
            hosts="${hosts}enclave$i,"
            i=$(( i + 1 ))
        done
        hosts="${hosts%,}"
        cmd_template="mpirun -hosts $hosts ./host/parallel ./enclave/parallel_enc.signed $a"
        if [ "$a" = "bitonic" ]; then
            b=4096
        else
            b=512
        fi

        warm_up="$cmd_template 256"
        echo "Warming up: $warm_up"
        $warm_up

        for s in 256 4096 65536 1048576; do
            for t in 1 2 4 8; do
                cmd="$cmd_template $s $t"

                echo "Command: $cmd"
                for i in {1..4}; do
                    $cmd
                done | tee "$BENCHMARK_DIR/bucket-enclaves$e-chunked$b-size$s-threads$t.txt"
            done
        done
    done
done
