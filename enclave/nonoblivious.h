#ifndef DISTRIBUTED_SGX_SORT_ENCLAVE_NONOBLIVIOUS_H
#define DISTRIBUTED_SGX_SORT_ENCLAVE_NONOBLIVIOUS_H

#include <stddef.h>

int nonoblivious_sort(void *arr_, size_t length, size_t local_length,
        size_t local_start);

#endif /* distributed-sgx-sort/enclave/nonoblivious.h */
