#!/bin/bash

set -euo pipefail

# https://stackoverflow.com/a/4774063
SCRIPTPATH="$( cd -- "$(dirname "$0")" > /dev/null 2>&1 ; pwd -P )"
ROOTPATH="$( dirname "${SCRIPTPATH}" )"

if [ $# -eq 2 ]; then
    first=$1
    last=$2
else
    first=0
    last=31
fi

mkdir -p ${ROOTPATH}

i=$first
while [ "$i" -le "$last" ]; do
    (
        ssh enclave${i} mkdir -p ${ROOTPATH}
        rsync \
            -aiv \
            --progress \
            --exclude benchmarks \
            --delete \
            "${ROOTPATH}/" \
            enclave${i}:"${ROOTPATH}/" \
            || true
    ) &
    i=$(( i + 1 ))
done

wait
