#ifndef __DISTRIBUTED_SGX_SORT_ENCLAVE_BUCKET_H
#define __DISTRIBUTED_SGX_SORT_ENCLAVE_BUCKET_H

#include <stddef.h>

int bucket_init(void);
void bucket_free(void);
int bucket_sort(void *arr, size_t length);

#endif /* distributed-sgx-sort/enclave/bucket.h */
