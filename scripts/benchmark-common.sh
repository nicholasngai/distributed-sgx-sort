#!/bin/sh

if [ -z "${ENCLAVE_OFFSET+x}" ]; then
    ENCLAVE_OFFSET=0
fi

if [ -n "${AZ+x}" ]; then
    export AZDCAP_DEBUG_LOG_LEVEL=0
    AZ=true
else
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
