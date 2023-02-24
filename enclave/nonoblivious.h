#ifndef DISTRIBUTED_SGX_SORT_ENCLAVE_NONOBLIVIOUS_H
#define DISTRIBUTED_SGX_SORT_ENCLAVE_NONOBLIVIOUS_H

#include <stddef.h>
#include "common/elem_t.h"

int nonoblivious_sort(elem_t *arr, size_t length, size_t local_length,
        size_t local_start);

#endif /* distributed-sgx-sort/enclave/nonoblivious.h */
