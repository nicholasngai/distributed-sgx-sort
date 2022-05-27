#!/bin/sh

set -eux

cd "$(dirname "$0")"

. ./common.sh

az group delete -g "$GROUP" -y
