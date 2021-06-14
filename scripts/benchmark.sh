#!/bin/bash

set -euo pipefail

# https://stackoverflow.com/a/4774063
SCRIPTPATH="$( cd -- "$(dirname "$0")" > /dev/null 2>&1 ; pwd -P )"
BENCHMARK_DIR="${SCRIPTPATH}/../benchmarks"

export AZDCAP_DEBUG_LOG_LEVEL=0

mkdir -p "${BENCHMARK_DIR}"

"$(dirname "$0")/sync.sh"

for e in 1 2 4 8 16 32; do
    if [ $e -eq 1 ]; then
        cmd_template="./host/parallel ./enclave/parallel_enc.signed"
    fi
    if [ $e -eq 2 ]; then
        cmd_template="mpirun -hosts enclave0,enclave1 ./host/parallel ./enclave/parallel_enc.signed"
    fi
    if [ $e -eq 4 ]; then
        cmd_template="mpirun -hosts enclave0,enclave1,enclave2,enclave3 ./host/parallel ./enclave/parallel_enc.signed"
    fi
    if [ $e -eq 8 ]; then
        cmd_template="mpirun -hosts enclave0,enclave1,enclave2,enclave3,enclave4,enclave5,enclave6,enclave7 ./host/parallel ./enclave/parallel_enc.signed"
    fi
    if [ $e -eq 16 ]; then
        cmd_template="mpirun -hosts enclave0,enclave1,enclave2,enclave3,enclave4,enclave5,enclave6,enclave7,enclave8,enclave9,enclave10,enclave11,enclave12,enclave13,enclave14,enclave15 ./host/parallel ./enclave/parallel_enc.signed"
    fi
    if [ $e -eq 32 ]; then
        cmd_template="mpirun -hosts enclave0,enclave1,enclave2,enclave3,enclave4,enclave5,enclave6,enclave7,enclave8,enclave9,enclave10,enclave11,enclave12,enclave13,enclave14,enclave15,enclave16,enclave17,enclave18,enclave19,enclave20,enclave21,enclave22,enclave23,enclave24,enclave25,enclave26,enclave27,enclave28,enclave29,enclave30,enclave31 ./host/parallel ./enclave/parallel_enc.signed"
    fi

    warm_up="${cmd_template} 256"
    echo "Warming up: ${warm_up}"
    ${warm_up}

    for s in 256 4096 65536 1048576 16777216; do
        for t in 1 2 4 8; do
            cmd="${cmd_template} $s $t"

            echo "Command: ${cmd}"
            for i in {1..4}; do
                ${cmd}
            done | tee "${BENCHMARK_DIR}/enclaves${e}-chunked4096-size${s}-threads${t}.txt"
        done
    done
done
