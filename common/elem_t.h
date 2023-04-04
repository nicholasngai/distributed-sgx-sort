#ifndef __COMMON_NODE_T_H
#define __COMMON_NODE_T_H

#include <assert.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define ELEM_SIZE 128
#define ELEM_STRUCT_SIZE 17

typedef struct elem {
    uint64_t key;

    /* Bucket sort stuff. */
    uint64_t orp_id;
    bool is_dummy;

    unsigned char unused[ELEM_SIZE - ELEM_STRUCT_SIZE];
} elem_t;

static_assert(sizeof(elem_t) == ELEM_SIZE, "Element should be 128 bytes");

#endif /* common/elem_t.h */
