#!/bin/sh

cd "$(dirname "$0")"/..

find \
    -name '*.[ch]' \
    -not -name 'parallel_[ut].[ch]' \
    -not -name 'parallel_args.h' \
    -not -name 'sim_cert.h' \
    -not -path './baselines/*' \
    -not -path './memory-benchmark/*' \
    -print0 \
    | xargs -0 wc
