#!/bin/sh

set -eux

cd "$(dirname "$0")"

. ./common.sh

MANAGER_NAME=manager
MANAGER_SIZE=Standard_B2s
MANAGER_IMAGE=canonical:0001-com-ubuntu-server-focal:20_04-lts-gen2:latest

# Create meta resource group.
az group create -g "$META_GROUP" --location "$LOCATION"

# Create proximity placement group.
az ppg create -g "$META_GROUP" -n "$PPG"

# Create virtual network.
az network vnet create -g "$META_GROUP" -n "$VNET" --subnet-name "$SUBNET"

# Create manager.
az vm create \
    -g "$META_GROUP" \
    -n "$MANAGER_NAME" \
    --size "$MANAGER_SIZE" \
    --image "$MANAGER_IMAGE" \
    --subnet /subscriptions/"$SUBSCRIPTION"/resourceGroups/"$META_GROUP"/providers/Microsoft.Network/virtualNetworks/"$VNET"/subnets/"$SUBNET" \
    --security-type TrustedLaunch \
    --public-ip-sku Standard \
    --admin-username nngai \
    --ssh-key-values ~/.ssh/id_rsa.pub
