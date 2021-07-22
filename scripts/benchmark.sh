#!/bin/bash

set -euo pipefail

cd "$(dirname "$0")/.."

BENCHMARK_DIR=benchmarks

export AZDCAP_DEBUG_LOG_LEVEL=0

mkdir -p "$BENCHMARK_DIR"

./scripts/sync.sh

for a in bitonic bucket; do
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

        for s in 256 4096 65536 1048576 16777216; do
            for t in 1 2 4 8; do
                cmd="$cmd_template $s $t"

                echo "Command: $cmd"
                for i in {1..4}; do
                    $cmd
                done | tee "$BENCHMARK_DIR/$a-enclaves$e-chunked$b-size$s-threads$t.txt"
            done
        done
    done
done
