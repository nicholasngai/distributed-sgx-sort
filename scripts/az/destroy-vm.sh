#!/bin/sh

set -eux

cd "$(dirname "$0")"

. ./common.sh

existing_groups="$(az group list -o tsv | cut -d "$(printf '\t')" -f 4)"

i=0
while [ "$i" -lt "$NUM_VMS" ]; do
    (
        group="$(get_group_name "$i")"

        if echo "$existing_groups" | grep -q "$group"; then
            az group delete -g "$group" -y
        else
            echo "Group $group is already deleted" >&2
        fi
    ) &

    i=$(( i + 1 ))
done

wait
