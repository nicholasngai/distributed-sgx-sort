#ifndef DISTRIBUTED_SGX_SORT_ENCLAVE_CACHE_H
#define DISTRIBUTED_SGX_SORT_ENCLAVE_CACHE_H

#include <stddef.h>
#include "common/elem_t.h"

/* The cache has CACHE_SETS * CACHE_ASSOCIATIVITY buckets. */
#define CACHE_SETS 16
#define CACHE_ASSOCIATIVITY 64
#define CACHE_LINESIZE 512
#define CACHE_SIZE (CACHE_SETS * CACHE_ASSOCIATIVITY)

#ifdef DISTRIBUTED_SGX_SORT_CACHE_COUNTER
extern int cache_hits;
extern int cache_misses;
extern int cache_evictions;
#endif /* DISTRIBUTED_SGX_SORT_CACHE_COUNTER */

int cache_init(void);
elem_t *cache_load_elems(void *arr, size_t idx, size_t local_start);
void cache_free_elems(elem_t *elems);
int cache_evictall(void *arr, size_t local_start);
void cache_free(void);

#endif /* distriubted-sgx-sort/enclave/cache.h */
