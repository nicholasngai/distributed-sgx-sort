#ifndef DISTRIBUTED_SGX_SORT_ENCLAVE_OJOIN_H
#define DISTRIBUTED_SGX_SORT_ENCLAVE_OJOIN_H

#include <stddef.h>
#include "common/elem_t.h"

#define BUCKET_SIZE 512

int ojoin_init(void);
void ojoin_free(void);
int ojoin(elem_t *arr, size_t length, size_t join_length, size_t num_threads);

#endif /* distributed-sgx-sort/enclave/ojoin.h */
