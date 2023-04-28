#!/bin/sh

set -eux

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <starting VM number> <ending VM number>"
    exit 1
fi

first=$1
last=$2

cd "$(dirname "$0")"

. ./common.sh

first=$1
last=$2

# Generate a regex that selects all enclave names with the given number.
enclave_regex='('
i=$first
while [ "$i" -le "$last" ]; do
    enclave_regex="${enclave_regex}$(get_vm_name "$i")|"
    i=$(( i + 1 ))
done
enclave_regex="${enclave_regex%|})"

# For some reason, disks don't show up with az resource list, so the disks query
# is done separately.
az resource delete --ids \
    $(az resource list -g "$GROUP" --query '[].id' -o tsv | grep -E "$enclave_regex") \
    $(az disk list -g "$GROUP" --query '[].id' -o tsv | grep -E "$enclave_regex")
