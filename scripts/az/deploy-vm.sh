#!/bin/sh

SIZE=Standard_DC4s_v2
#IMAGE=Canonical:UbuntuServer:18_04-lts-gen2:latest
IMAGE=canonical:0001-com-ubuntu-server-focal:20_04-lts-gen2:latest

set -eux

cd "$(dirname "$0")"

. ./common.sh

existing_groups="$(az group list -o tsv | cut -d "$(printf '\t')" -f 4)"

i=0
while [ "$i" -lt "$NUM_VMS" ]; do
    (
        vm="$(get_vm_name "$i")"
        group="$(get_group_name "$i")"

        # Create resource groups.
        if ! echo "$existing_groups" | grep -q "$group"; then
            az group create -g "$group" --location westus2
        else
            echo "Group $group already exists" >&2
        fi

        # Create VM.
        if ! az vm list -g "$group" -o tsv | cut -d "$(printf '\t')" -f 16 | grep -q "$vm"; then
            az vm create \
                -g "$group" \
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
