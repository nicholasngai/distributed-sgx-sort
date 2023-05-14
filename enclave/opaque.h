#ifndef DISTRIBUTED_SGX_SORT_ENCLAVE_OPAQUE_H
#define DISTRIBUTED_SGX_SORT_ENCLAVE_OPAQUE_H

#include <stddef.h>
#include "common/elem_t.h"

int opaque_sort(elem_t *arr, size_t length);

#endif /* distributed-sgx-sort/enclave/opauqe.h */
