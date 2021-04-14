#ifndef __COMMON_NODE_T_H
#define __COMMON_NODE_T_H

#include <stddef.h>
#include <stdint.h>
#include "crypto.h"

#define SIZEOF_ENCRYPTED_NODE (sizeof(node_t) + IV_LEN + TAG_LEN)

typedef struct node {
    uint64_t key;
    unsigned char unused[120];
} node_t;

int node_encrypt(void *key, node_t *node, void *dst_, size_t idx);
int node_decrypt(void *key, node_t *node, void *src_, size_t idx);

#endif /* common/node_t.h */
