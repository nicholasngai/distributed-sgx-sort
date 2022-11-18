#ifndef __COMMON_NODE_T_H
#define __COMMON_NODE_T_H

#include <assert.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include "crypto.h"

#define SIZEOF_ENCRYPTED_NODE (sizeof(elem_t) + IV_LEN + TAG_LEN)

typedef struct elem {
    uint64_t key;

    /* Bucket sort stuff. */
    uint64_t orp_id;
    bool is_dummy;

    /* ORShuffle stuff. */
    bool marked;

    unsigned char unused[107];
} elem_t;

static_assert(sizeof(elem_t) == 128, "Element should be 128 bytes");

int elem_encrypt(const void *key, const elem_t *elem, void *dst_, size_t idx);
int elem_decrypt(const void *key, elem_t *elem, const void *src_, size_t idx);

#endif /* common/elem_t.h */
