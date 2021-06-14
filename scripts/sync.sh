#!/bin/bash

set -euo pipefail

# https://stackoverflow.com/a/4774063
SCRIPTPATH="$( cd -- "$(dirname "$0")" > /dev/null 2>&1 ; pwd -P )"
ROOTPATH="$( dirname "${SCRIPTPATH}" )"

mkdir -p ${ROOTPATH}

for i in {1..31}; do
    (
        ssh enclave${i} mkdir -p ${ROOTPATH}
        rsync -aiv --progress --delete "${ROOTPATH}/" enclave${i}:"${ROOTPATH}/" || true
    ) &
done

wait
