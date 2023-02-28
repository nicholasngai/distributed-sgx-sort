#ifndef __COMMON_NODE_T_H
#define __COMMON_NODE_T_H

#include <assert.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include "crypto.h"

#define ELEM_SIZE 128
#define SIZEOF_ENCRYPTED_NODE (ELEM_SIZE + IV_LEN + TAG_LEN)

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

static_assert(sizeof(elem_t) == ELEM_SIZE, "Element should be 128 bytes");

int elem_encrypt(const void *key, const elem_t *elem, void *dst_, size_t idx);
int elem_decrypt(const void *key, elem_t *elem, const void *src_, size_t idx);

#endif /* common/elem_t.h */
