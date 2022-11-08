#ifndef DISTRIBUTED_SGX_SORT_ENCLAVE_BITONIC_H
#define DISTRIBUTED_SGX_SORT_ENCLAVE_BITONIC_H

#include <stdbool.h>
#include <stddef.h>
#include "common/defs.h"

int bitonic_init(void);
void bitonic_free(void);
void bitonic_sort(void *arr, size_t length, size_t num_threads);

#endif /* distributed-sgx-sort/enclave/bitonic.h */
