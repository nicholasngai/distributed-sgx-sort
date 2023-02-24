#!/bin/sh

export SUBSCRIPTION=e3f75e2d-38e6-4192-9fcd-1b5c47bb5ddd
export LOCATION=uswest2
export META_GROUP=enclave_meta_group
export GROUP=enclave_group
export VNET=enclave-vnet
export SUBNET=default
export PPG=enclave-ppg
export MANAGER_NAME=manager

get_vm_name() {
    i="$1"
    echo "enclave$i"
}

get_group_name() {
    i="$1"
    echo "$(get_vm_name "$i")_group"
}
