#!/bin/bash

set -euo pipefail

cd "$(dirname "$0")/.."

BENCHMARK_DIR=benchmarks
BUCKET_SIZE=512

mkdir -p "$BENCHMARK_DIR"

find . -name '*.[ch]' -print0 | xargs -0 sed -Ei "$(cat <<EOF
s/^#define (BUCKET_SIZE) .*$/#define \1 $BUCKET_SIZE/
EOF
)"

a=bucket
for e in 32 16 8 4 2 1; do
    # Build command template.
    hosts=''
    i=0
    while [ "$i" -lt "$e" ]; do
        hosts="${hosts}enclave$i,"
        i=$(( i + 1 ))
    done
    hosts="${hosts%,}"
    cmd_template="mpirun -hosts $hosts ./host/parallel ./enclave/parallel_enc.signed $a"

    for b in 1 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192; do
        echo "Cache sets: $b"

        for s in 256 4096 65536 1048576 16777216; do
            for t in 1 2 4 8; do
                CACHE_ASSOCIATIVITY=$(( t * 2 ))
                find . -name '*.[ch]' -print0 | xargs -0 sed -Ei "$(cat <<EOF
s/^#define (CACHE_SETS) .*$/#define \1 $b/
s/^#define (CACHE_ASSOCIATIVITY) .*$/#define \1 $CACHE_ASSOCIATIVITY/
EOF
)"
                make -j
                ./scripts/sync.sh

                warm_up="$cmd_template 256"
                echo "Warming up: $warm_up"
                $warm_up

                cmd="$cmd_template $s $t"
                echo "Command: $cmd"
                for i in {1..4}; do
                    $cmd
                done | tee "$BENCHMARK_DIR/$a-enclaves$e-bucketsize$BUCKET_SIZE-cachesize$(( b * CACHE_ASSOCIATIVITY * BUCKET_SIZE / 2 ))-size$s-threads$t.txt"
            done
        done
    done
done
