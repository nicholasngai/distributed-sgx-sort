#!/bin/sh

set -eux

sudo apt install -y curl

if ! [ -f /etc/apt/sources.list.d/intel-sgx.list ]; then
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
fi
if ! [ -f /etc/apt/trusted.gpg.d/intel-sgx-deb.asc ]; then
    sudo curl -Lo /etc/apt/trusted.gpg.d/intel-sgx-deb.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
fi

if ! [ -f /etc/apt/sources.list.d/msprod.list ]; then
    echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/20.04/prod focal main" | sudo tee /etc/apt/sources.list.d/msprod.list
fi
if ! [ -f /etc/apt/trusted.gpg.d/microsoft.asc ]; then
    sudo curl -Lo /etc/apt/trusted.gpg.d/microsoft.asc https://packages.microsoft.com/keys/microsoft.asc
fi

sudo apt update
sudo apt upgrade -y
sudo apt install -y \
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
