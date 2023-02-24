#!/bin/bash

set -euo pipefail

cd "$(dirname "$0")/.."

BENCHMARK_DIR=benchmarks
CACHE_SETS=8

ENCLAVE_OFFSET=0

if [ ! -z "$AZ" ]; then
    export AZDCAP_DEBUG_LOG_LEVEL=0
    AZ=true
    last_e=
else
    AZ=false
fi

mkdir -p "$BENCHMARK_DIR"

find . -name '*.[ch]' -print0 | xargs -0 sed -Ei "$(cat <<EOF
s/^#define (CACHE_SETS) .*$/#define \1 $CACHE_SETS/
EOF
)"

a=bucket
for e in 32 16 8 4 2 1; do
    # Deallocate previous machines.
    if "$AZ"; then
       if [ ! -z "$last_e" ]; then
            i=$(( last_e - 1 ))
            while [ "$i" -ge "$e" ]; do
                az vm deallocate -g enclave_group -n "enclave$(( i + ENCLAVE_OFFSET ))" --no-wait
                i=$(( i - 1 ))
            done
       fi
       last_e=$e
    fi

    # Build command template.
    hosts=''
    i=0
    while [ "$i" -lt "$e" ]; do
        hosts="${hosts}enclave$(( i + ENCLAVE_OFFSET )),"
        i=$(( i + 1 ))
    done
    hosts="${hosts%,}"
    cmd_template="mpiexec -hosts $hosts ./host/parallel ./enclave/parallel_enc.signed $a"

    for b in 512 1024 2048 4096 8192 16384 32768 65536 131072 262144 524288 1048576 2097152 4194304; do
        echo "Bucket size: $b"

        for s in 256 4096 65536 1048576 16777216; do
            for t in 1 2 4; do
                CACHE_ASSOCIATIVITY=$(( t * 2 ))
                find . -name '*.[ch]' -print0 | xargs -0 sed -Ei "$(cat <<EOF
s/^#define (BUCKET_SIZE) .*$/#define \1 $b/
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
                done | tee "$BENCHMARK_DIR/$a-sgx2-enclaves$e-bucketsize$b-size$s-threads$t.txt"
            done
        done
    done
done

# Deallocate remaining machines.
if "$AZ"; then
    i=$(( last_e - 1 ))
    while [ "$i" -ge 0 ]; do
        az vm deallocate -g enclave_group -n "enclave$(( i + ENCLAVE_OFFSET ))" --no-wait
        i=$(( i - 1 ))
    done
fi
