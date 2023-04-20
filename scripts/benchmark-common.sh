#!/bin/sh

. scripts/az/common.sh

REPEAT=4

if [ -z "${ENCLAVE_OFFSET+x}" ]; then
    ENCLAVE_OFFSET=0
fi

if [ -n "${AZ+x}" ]; then
    export AZDCAP_DEBUG_LOG_LEVEL=0
    AZ=true
else
    if uname -r | grep -q azure; then
        fold -s <<EOF
It looks like you're running on Azure. If you want to automatically deallocate VMs, you should re-run this script as

    AZ=true $0

Hit Enter to continue without automatic deallocation or Ctrl-C to exit.
EOF
        read
    fi
    AZ=false
fi

deallocate_az_vm() {
    first=$1
    last=$2

    vm_ids=
    i=$first
    while [ "$i" -lt "$last" ]; do
        vm_ids="$vm_ids /subscriptions/$SUBSCRIPTION/resourceGroups/$GROUP/providers/Microsoft.Compute/virtualMachines/enclave$i"

        i=$(( i + 1 ))
    done
    az vm deallocate --ids $vm_ids
}

get_mem_usage() {
    algorithm=$1
    num_enclaves=$2
    elem_size=$3
    num_elems=$4

    case "$algorithm" in
        bitonic)
            echo $(( elem_size * num_elems / num_enclaves ))
            ;;
        bucket|orshuffle)
            echo $(( elem_size * num_elems * 4 / num_enclaves ))
            ;;
        *)
            echo 'Invalid algorithm' >&2
            exit 1
    esac
}

set_sort_params() {
    algorithm=$1
    num_enclaves=$2
    elem_size=$3
    num_elems=$4
    first=$5
    last=$6

    # Rewrite ELEM_SIZE.
    find . -name '*.[ch]' -print0 | xargs -0 sed -Ei "s/^#define (ELEM_SIZE) .*\$/#define \\1 $elem_size/"

    # Reconfigure NumHeapPages in enclave config.
    mem_usage=$(get_mem_usage "$algorithm" "$num_enclaves" "$elem_size" "$num_elems")
    num_heap_pages=$(( mem_usage / 4096 * 10 / 8 ))
    if [ $num_heap_pages -lt 1048576 ]; then
        num_heap_pages=1048576
    fi
    sed -Ei "s/^(NumHeapPages)=[0-9]+\$/\1=$num_heap_pages/" enclave/parallel.conf

    # Make and sync.
    make -j >/dev/null
    ./scripts/sync.sh "$first" "$last" >/dev/null
}
