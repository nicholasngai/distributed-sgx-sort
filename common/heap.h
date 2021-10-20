#ifndef __DISTRIBUTED_SGX_SORT_COMMON_HEAP_H
#define __DISTRIBUTED_SGX_SORT_COMMON_HEAP_H

#include <stddef.h>

void heap_heapify(void *arr, size_t len, size_t elem_size,
        int (*comparator)(const void *a, const void *b, void *aux), void *aux);
void heap_pop(void *out, void *arr, size_t *len, size_t elem_size,
        int (*comparator)(const void *a, const void *b, void *aux), void *aux);
void heap_push(const void *in, void *arr, size_t *len, size_t elem_size,
        int (*comparator)(const void *a, const void *b, void *aux), void *aux);
void heap_pushpop(void *out, const void *in, void *arr, size_t *len,
        size_t elem_size,
        int (*comparator)(const void *a, const void *b, void *aux), void *aux);

#endif /* distributed-sgx-sort/common/heap.h */
