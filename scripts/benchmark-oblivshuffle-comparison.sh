#!/bin/bash

set -euo pipefail

cd "$(dirname "$0")/.."

. scripts/benchmark-common.sh

BENCHMARK_DIR=benchmarks

mkdir -p "$BENCHMARK_DIR"

set_elem_size() {
    elem_size=$1
    find . -name '*.[ch]' -print0 | xargs -0 sed -Ei "s/^#define (ELEM_SIZE) .*\$/#define \\1 $elem_size/"
}

a=orshuffle
e=1
s=1048576
t=1

# Build command template.
cmd_template="mpiexec -hosts enclave$ENCLAVE_OFFSET ./host/parallel ./enclave/parallel_enc.signed"

warm_up="$cmd_template bitonic 256 1"
echo "Warming up: $warm_up"
$warm_up

for b in 256 512 1024 2048 4096; do
    echo "Elem size: $b"

    set_elem_size $b

    make -j
    ./scripts/sync.sh

    cmd="$cmd_template $a $s $t $REPEAT"
    echo "Command: $cmd"
    $cmd | tee "$BENCHMARK_DIR/$a-sgx2-enclaves$e-elemsize$b-size$s-threads$t.txt"
done

if "$AZ"; then
    deallocate_az_vm "$ENCLAVE_OFFSET" "$(( ENCLAVE_OFFSET + 1 ))"
fi
