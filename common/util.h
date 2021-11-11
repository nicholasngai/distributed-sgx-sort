#ifndef __DISTRIBUTED_SGX_SORT_COMMON_UTIL_H
#define __DISTRIBUTED_SGX_SORT_COMMON_UTIL_H

#include <stddef.h>

static inline int comp_ul(const void *a_, const void *b_) {
    const size_t *a = a_;
    const size_t *b = b_;
    return (*a > *b) - (*a < *b);
}

void *bsearch_ge(const void *key, const void *arr, size_t num_elems,
        size_t elem_size, int (*comparator)(const void *a, const void *b));

#endif /* distributed-sgx-sort/common/util.h */
