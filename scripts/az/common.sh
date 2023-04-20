#!/bin/sh

SUBSCRIPTION=7fd7e4ed-48d3-4cab-8df3-436e7c7cfed1
LOCATION=eastus
META_GROUP=enclave_meta_group
GROUP=enclave_group
VNET=enclave-vnet
SUBNET=default
PPG=enclave-ppg
MANAGER_NAME=manager

get_vm_name() {
    i="$1"
    echo "enclave$i"
}

get_group_name() {
    i="$1"
    echo "$(get_vm_name "$i")_group"
}
