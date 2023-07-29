#ifndef __COMMON_NODE_T_H
#define __COMMON_NODE_T_H

#include <assert.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define ELEM_SIZE 128

typedef struct elem {
    uint64_t key;

    /* Bucket sort stuff. */
    uint64_t orp_id;
    bool is_dummy;

    /* Oblivious join stuff. For oblivious join, the key is the leading 63 bits,
     * and the trailing final bit is a 0 to indicate a data entry and 1 to
     * indicate a request. */
    uint64_t value;
    bool has_value;
    bool compact_marked_prefix_sum;

    unsigned char unused[ELEM_SIZE - 34];
} elem_t;

static_assert(sizeof(elem_t) == ELEM_SIZE, "Element should be 128 bytes");

#endif /* common/elem_t.h */
