#!/bin/bash

set -euo pipefail

if [ $(id -u) -ne 0 ]; then
    echo 'This script must be run as root!'
    exit 13
fi

apt install -y curl

if ! [ -f /etc/apt/sources.list.d/intel-sgx.list ]; then
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | tee /etc/apt/sources.list.d/intel-sgx.list
fi
if ! [ -f /etc/apt/trusted.gpg.d/intel-sgx-deb.asc ]; then
    curl -Lo /etc/apt/trusted.gpg.d/intel-sgx-deb.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
fi

if ! [ -f /etc/apt/sources.list.d/msprod.list ]; then
    echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/20.04/prod focal main" | tee /etc/apt/sources.list.d/msprod.list
fi
if ! [ -f /etc/apt/trusted.gpg.d/microsoft.asc ]; then
    curl -Lo /etc/apt/trusted.gpg.d/microsoft.asc https://packages.microsoft.com/keys/microsoft.asc
fi

apt update
apt upgrade -y
apt install -y \
    az-dcap-client \
    build-essential \
    libmbedtls12 \
    libmbedtls-dev \
    libssl-dev \
    mpich \
    open-enclave

if ! grep openenclaverc ~/.bashrc; then
    (echo && echo 'source /opt/openenclave/share/openenclave/openenclaverc') >> ~/.bashrc
fi
