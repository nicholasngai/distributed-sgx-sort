#include "enclave/bucket.h"
#include <string.h>
#include "common/error.h"
#include "common/node_t.h"

static unsigned char key[16];

int bucket_init(void) {
    /* Initialize random. */
    if (rand_init()) {
        handle_error_string("Error initializing enclave random number generator");
        goto exit;
    }

    return 0;

exit:
    return -1;
}

void bucket_free(void) {
    /* Free resources. */
    rand_free();
}

/* Assigns random ORP IDs to the encrypted nodes in ARR and distributes them
 * evenly over the 2 * LENGTH elements in ARR. Thus, ARR is assumed to be at
 * least 2 * LENGTH * SIZEOF_ENCRYPTED_NODE bytes. The result is an array with
 * real elements interspersed with dummy elements. */
// TODO Parallelize?
// TODO Can we do the first bucket assignment scan while generating these?
static int assign_random_ids_and_spread(void *arr_, size_t length) {
    int ret;
    unsigned char *arr = arr_;

    node_t dummy_node;
    memset(&dummy_node, '\0', sizeof(dummy_node));
    dummy_node.is_dummy = true;

    for (size_t i = length - 1; i != SIZE_MAX; i--) {
        node_t node;

        /* Decrypt index i. */
        ret = node_decrypt(key, &node, arr + i * SIZEOF_ENCRYPTED_NODE, i);
        if (ret) {
            handle_error_string("Error decrypting node");
            goto exit;
        }

        /* Assign ORP ID and initialize node. */
        ret = rand_read(&node.orp_id, sizeof(node.orp_id));
        if (ret) {
            handle_error_string("Error assigning random ID");
            goto exit;
        }
        node.is_dummy = false;

        /* Encrypt to index 2 * i. */
        ret = node_encrypt(key, &node, arr + 2 * i * SIZEOF_ENCRYPTED_NODE,
                2 * i);
        if (ret) {
            handle_error_string("Error encrypting node");
            goto exit;
        }

        /* Encrypt dummy node to index 2 * i + 1. */
        ret = node_encrypt(key, &dummy_node,
                arr + (2 * i  + 1) * SIZEOF_ENCRYPTED_NODE, 2 * i + 1);
        if (ret) {
            handle_error_string("Error encrypting dummy node");
            goto exit;
        }
    }

exit:
    return ret;
}

int bucket_sort(void *arr, size_t length) {
    int ret;

    ret = assign_random_ids_and_spread(arr, length);
    if (ret) {
        handle_error_string("Error assigning random IDs to nodes");
        goto exit;
    }

exit:
    return ret;
}
