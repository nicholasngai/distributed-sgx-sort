#ifndef __COMMON_NODE_T_H
#define __COMMON_NODE_T_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define ELEM_SIZE 128
#define ELEM_STRUCT_SIZE 32

typedef struct elem {
    uint64_t key;

    /* Bucket sort stuff. */
    uint64_t orp_id;
    bool is_dummy;

    /* ORShuffle stuff. */
    bool marked;
    size_t marked_prefix_sum;

    unsigned char unused[ELEM_SIZE - ELEM_STRUCT_SIZE];
} elem_t;

_Static_assert(sizeof(elem_t) == ELEM_SIZE, "Element should be 128 bytes");

#endif /* common/elem_t.h */
