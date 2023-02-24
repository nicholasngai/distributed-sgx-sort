#!/bin/sh

set -eux

cd "$(dirname "$0")"

. ./common.sh

# For some reason, disks don't show up with az resource list, so the disks query
# is done separately.
az resource delete --ids \
    $(az resource list -g "$GROUP" --query '[].id' -o tsv) \
    $(az disk list -g "$GROUP" --query '[].id' -o tsv)
