#ifndef DISTRIBUTED_SGX_SORT_ENCLAVE_BUCKET_H
#define DISTRIBUTED_SGX_SORT_ENCLAVE_BUCKET_H

#include <stddef.h>

#define BUCKET_SIZE 512

int bucket_init(void);
void bucket_free(void);
int bucket_sort(void *arr, size_t length, size_t num_threads);

#endif /* distributed-sgx-sort/enclave/bucket.h */
