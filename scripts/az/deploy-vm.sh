#!/bin/sh

set -eux

SIZE=Standard_DC4s_v2
#IMAGE=Canonical:UbuntuServer:18_04-lts-gen2:latest
IMAGE=canonical:0001-com-ubuntu-server-focal:20_04-lts-gen2:latest

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <starting VM number> <ending VM number>"
    exit 1
fi

VM_START=$1
VM_STOP=$2

cd "$(dirname "$0")"

. ./common.sh

# Create resource group.
az group create -g "$GROUP" --location "$LOCATION"

existing_vms=$(az vm list -g "$GROUP" -o tsv | cut -d "$(printf '\t')" -f 16)
i=$VM_START
while [ "$i" -le "$VM_STOP" ]; do
    (
        vm_name="$(get_vm_name "$i")"

        # Create VM.
        if ! echo "$existing_vms" | grep -q "$vm_name"; then
            az vm create \
                -g "$GROUP" \
                -n "$vm_name" \
                --size "$SIZE" \
                --image "$IMAGE" \
                --admin-username nngai \
                --ssh-key-values ~/.ssh/id_rsa.pub \
                --subnet /subscriptions/"$SUBSCRIPTION"/resourceGroups/"$META_GROUP"/providers/Microsoft.Network/virtualNetworks/"$VNET"/subnets/"$SUBNET" \
                --public-ip-address '' \
                --nsg '' \
                --ppg /subscriptions/"$SUBSCRIPTION"/resourceGroups/"$META_GROUP"/providers/Microsoft.Compute/proximityPlacementGroups/"$PPG"

            ## Deallocate VM if newly created.
            #az vm deallocate -g "$group" -n "$vm_name"
        else
            echo "VM $vm_name already exists" >&2
        fi
    ) &

    i=$(( i + 1 ))
done

wait
