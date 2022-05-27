#!/bin/sh

SIZE=Standard_DC4s_v2
#IMAGE=Canonical:UbuntuServer:18_04-lts-gen2:latest
IMAGE=canonical:0001-com-ubuntu-server-focal:20_04-lts-gen2:latest

set -eux

cd "$(dirname "$0")"

. ./common.sh

# Create resource group.
az group create -g "$GROUP" --location westus2

existing_vms=$(az vm list -g "$GROUP" -o tsv | cut -d "$(printf '\t')" -f 16)
i=0
while [ "$i" -lt "$NUM_VMS" ]; do
    (
        vm="$(get_vm_name "$i")"

        # Create VM.
        if ! echo "$existing_vms" | grep -q "$vm"; then
            az vm create \
                -g "$GROUP" \
                -n "$vm" \
                --size "$SIZE" \
                --image "$IMAGE" \
                --admin-username nngai \
                --ssh-key-values ~/.ssh/id_rsa.pub \
                --subnet /subscriptions/"$SUBSCRIPTION"/resourceGroups/"$META_GROUP"/providers/Microsoft.Network/virtualNetworks/"$VNET"/subnets/"$SUBNET" \
                --public-ip-address '' \
                --ppg /subscriptions/"$SUBSCRIPTION"/resourceGroups/"$META_GROUP"/providers/Microsoft.Compute/proximityPlacementGroups/"$PPG"

            ## Deallocate VM if newly created.
            #az vm deallocate -g "$group" -n "$vm"
        else
            echo "VM $vm already exists" >&2
        fi
    ) &

    i=$(( i + 1 ))
done

wait
