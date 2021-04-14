#include "node_t.h"
#include <stdio.h>
#include <stdlib.h>

/* Node encryption and decryption. */

int node_encrypt(void *key, node_t *node, void *dst_, size_t idx) {
    int ret;
    unsigned char *dst = dst_;

    /* The IV is the first 12 bytes. The tag is the next 16 bytes. The
     * ciphertext is the remaining 128 bytes. */
    ret = rand_read(dst, IV_LEN);
    if (ret) {
        fprintf(stderr, "Error generating random IV\n");
        goto exit;
    }
    ret = aad_encrypt(key, node, sizeof(*node), &idx, sizeof(idx), dst,
            dst + IV_LEN + TAG_LEN, dst + IV_LEN);
    if (ret < 0) {
        fprintf(stderr, "Error encrypting node %lu\n", idx);
        goto exit;
    }

    ret = 0;

exit:
    return ret;
}

int node_decrypt(void *key, node_t *node, void *src_, size_t idx) {
    int ret;
    unsigned char *src = src_;

    /* The IV is the first 12 bytes. The tag is the next 16 bytes. The
     * ciphertext is the remaining 128 bytes. */
    ret = aad_decrypt(key, src + IV_LEN + TAG_LEN, sizeof(*node), &idx,
            sizeof(idx), src, src + IV_LEN, node);
    if (ret < 0) {
        fprintf(stderr, "Error decrypting node %lu\n", idx);
        goto exit;
    }

    ret = 0;

exit:
    return ret;
}
