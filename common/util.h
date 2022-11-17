#ifndef DISTRIBUTED_SGX_SORT_COMMON_UTIL_H
#define DISTRIBUTED_SGX_SORT_COMMON_UTIL_H

#include <stddef.h>
#include <limits.h>
#include <time.h>

static inline unsigned long next_pow2l(unsigned long x) {
#ifdef __GNUC__
    unsigned long next = 1 << (sizeof(x) * CHAR_BIT - __builtin_clzl(x) - 1);
    if (next < x) {
        next <<= 1;
    }
    return next;
#else
    unsigned long next = 1;
    while (next < x) {
        next <<= 1;
    }
    return next;
#endif
}

static inline unsigned long log2li(unsigned long x) {
#ifdef __GNUC__
    return sizeof(x) * CHAR_BIT - __builtin_clzl(x) - 1;
#else
    unsigned long log = -1;
    while (x) {
        log++;
        x >>= 1;
    }
    return log;
#endif
}

static inline int comp_ul(const void *a_, const void *b_) {
    const size_t *a = a_;
    const size_t *b = b_;
    return (*a > *b) - (*a < *b);
}

static inline double get_time_difference(struct timespec *start,
        struct timespec *end) {
    return (double) (end->tv_sec * 1000000000 + end->tv_nsec
            - (start->tv_sec * 1000000000 + start->tv_nsec))
        / 1000000000;
}

void *bsearch_ge(const void *key, const void *arr, size_t num_elems,
        size_t elem_size, int (*comparator)(const void *a, const void *b));

#endif /* distributed-sgx-sort/common/util.h */
