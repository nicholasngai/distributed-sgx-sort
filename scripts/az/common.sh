#!/bin/sh

export NUM_VMS=32
export SUBSCRIPTION=e3f75e2d-38e6-4192-9fcd-1b5c47bb5ddd
export META_GROUP=enclave_meta_group
export VNET=enclave-vnet
export SUBNET=default
export PPG=enclave-ppg

get_vm_name() {
    i="$1"
    echo "enclave$i"
}

get_group_name() {
    i="$1"
    echo "$(get_vm_name "$i")_group"
}
