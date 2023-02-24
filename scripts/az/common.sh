#!/bin/sh

export SUBSCRIPTION=7fd7e4ed-48d3-4cab-8df3-436e7c7cfed1
export LOCATION=eastus
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
