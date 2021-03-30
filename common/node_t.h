#ifndef __COMMON_NODE_T_H
#define __COMMON_NODE_T_H

#include <stdint.h>

typedef struct node {
    uint64_t key;
    unsigned char unused[120];
} node_t;

#endif /* common/node_t.h */
