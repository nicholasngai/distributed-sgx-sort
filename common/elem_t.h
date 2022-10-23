#ifndef __COMMON_NODE_T_H
#define __COMMON_NODE_T_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include "crypto.h"

#define SIZEOF_ENCRYPTED_NODE (sizeof(elem_t) + IV_LEN + TAG_LEN)

typedef struct elem {
    uint64_t key;
    uint64_t orp_id;
    bool is_dummy;
    unsigned char unused[108];
} elem_t;

int elem_encrypt(const void *key, const elem_t *elem, void *dst_, size_t idx);
int elem_decrypt(const void *key, elem_t *elem, const void *src_, size_t idx);

#endif /* common/elem_t.h */
