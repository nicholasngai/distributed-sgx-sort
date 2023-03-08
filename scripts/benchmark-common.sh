#!/bin/sh

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
    i=$first
    while [ "$i" -lt "$last" ]; do
        az vm deallocate -g enclave_group -n "enclave$i" --no-wait
        i=$(( i + 1 ))
    done
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
    esac
}
