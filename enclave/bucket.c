#include "enclave/bucket.h"
#include <string.h>
#include <liboblivious/algorithms.h>
#include <liboblivious/primitives.h>
#include "common/error.h"
#include "common/node_t.h"

#define BUCKET_SIZE 512

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

struct merge_split_swap_aux {
    void *arr;
    size_t bit_idx;
    size_t bucket1;
    size_t bucket2;
};

/* Obliviously swap elements as part of an oblivious sort, where the first
 * BUCKET_SIZE elements are in BUCKET1, and the second BUCKET_SIZE elements are
 * in BUCKET2. */
static void merge_split_swap(size_t a, size_t b, void *aux_) {
    struct merge_split_swap_aux *aux = aux_;
    size_t a_idx = (a < BUCKET_SIZE ? aux->bucket1 : aux->bucket2) * BUCKET_SIZE
        + a % BUCKET_SIZE;
    size_t b_idx = (b < BUCKET_SIZE ? aux->bucket1 : aux->bucket2) * BUCKET_SIZE
        + b % BUCKET_SIZE;
    unsigned char *arr = aux->arr;
    int ret;

    node_t node_a;
    node_t node_b;

    /* Decrypt nodes. */
    ret = node_decrypt(key, &node_a, arr + a_idx * SIZEOF_ENCRYPTED_NODE,
            a_idx);
    if (ret) {
        handle_error_string("Error decrypting node");
        goto exit;
    }
    ret = node_decrypt(key, &node_b, arr + b_idx * SIZEOF_ENCRYPTED_NODE,
            b_idx);
    if (ret) {
        handle_error_string("Error decrypting node");
        goto exit;
    }

    /* Compare and obliviously swap if the BIT_IDX bit of ORP ID of node A is
     * 1 and that of node B is 0 or if the ORP IDs are the same, but node A is a
     * dummy and node B is real. */
    bool cond = ((node_a.orp_id >> aux->bit_idx) & 1)
        > ((node_b.orp_id >> aux->bit_idx) & 1);
    cond |= node_a.is_dummy & !node_b.is_dummy;
    o_memswap(&node_a, &node_b, sizeof(node_a), cond);

    /* Encrypt nodes. */
    ret = node_encrypt(key, &node_a, arr + a_idx * SIZEOF_ENCRYPTED_NODE,
            a_idx);
    if (ret) {
        handle_error_string("Error decrypting node");
        goto exit;
    }
    ret = node_encrypt(key, &node_b, arr + b_idx * SIZEOF_ENCRYPTED_NODE,
            b_idx);
    if (ret) {
        handle_error_string("Error decrypting node");
        goto exit;
    }

exit:
    ;
}

/* Merge BUCKET1 and BUCKET2 and split such that BUCKET1 contains all elements
 * corresponding with bit 0 and BUCKET2 contains all elements corresponding with
 * bit 1, with the bit given by the bit in BIT_IDX of the nodes' ORP IDs. Note
 * that this is a modified version of the merge-split algorithm from the paper,
 * since the elements are swapped in-place rather than being swapped between
 * different buckets on different layers. */
static int merge_split(void *arr_, size_t bucket1, size_t bucket2,
        size_t bit_idx) {
    int ret;
    unsigned char *arr = arr_;

    /* The number of elements with corresponding bit 1. */
    size_t count1 = 0;

    /* Count number of elements with corresponding bit 1 in BUCKET1. */
    for (size_t i = bucket1 * BUCKET_SIZE; i < (bucket1 + 1) * BUCKET_SIZE;
            i++) {
        node_t node;

        /* Decrypt index i. */
        ret = node_decrypt(key, &node, arr + i * SIZEOF_ENCRYPTED_NODE, i);
        if (ret) {
            handle_error_string("Error decrypting node");
            goto exit;
        }

        /* Obliviously increment count. */
        count1 += ((node.orp_id >> bit_idx) & 1) & !node.is_dummy;
    }

    /* Count number of elements with corresponding bit 1 in BUCKET2. */
    for (size_t i = bucket2 * BUCKET_SIZE; i < (bucket2 + 1) * BUCKET_SIZE;
            i++) {
        node_t node;

        /* Decrypt index i. */
        ret = node_decrypt(key, &node, arr + i * SIZEOF_ENCRYPTED_NODE, i);
        if (ret) {
            handle_error_string("Error decrypting node");
            goto exit;
        }

        /* Obliviously increment count. */
        count1 += ((node.orp_id >> bit_idx) & 1) & !node.is_dummy;
    }

    /* There are count1 elements with bit 1, so we need to assign count1 dummy
     * elements to have bit 0, with the remaining dummy elements assigned with
     * bit 1. */

    /* Assign dummy elements in BUCKET1. */
    for (size_t i = bucket1 * BUCKET_SIZE; i < (bucket1 + 1) * BUCKET_SIZE;
            i++) {
        node_t node;

        /* Decrypt index i. */
        ret = node_decrypt(key, &node, arr + i * SIZEOF_ENCRYPTED_NODE, i);
        if (ret) {
            handle_error_string("Error decrypting node");
            goto exit;
        }

        /* Set the BIT_IDX bit of the node and decrement count1 if count1 > 0
         * and the node is a dummy node. */
        node.orp_id |= node.is_dummy << bit_idx;
        node.orp_id &= ~(((bool) count1 & node.is_dummy) << bit_idx);
        count1 -= (bool) count1 & node.is_dummy;

        /* Encrypt index i. */
        ret = node_encrypt(key, &node, arr + i * SIZEOF_ENCRYPTED_NODE, i);
        if (ret) {
            handle_error_string("Error encrypting node");
            goto exit;
        }
    }

    /* Assign dummy elements in BUCKET2. */
    for (size_t i = bucket2 * BUCKET_SIZE; i < (bucket2 + 1) * BUCKET_SIZE;
            i++) {
        node_t node;

        /* Decrypt index i. */
        ret = node_decrypt(key, &node, arr + i * SIZEOF_ENCRYPTED_NODE, i);
        if (ret) {
            handle_error_string("Error decrypting node");
            goto exit;
        }

        /* Set the BIT_IDX bit of the node and decrement count1 if count1 > 0
         * and the node is a dummy node. */
        node.orp_id |= node.is_dummy << bit_idx;
        node.orp_id &= ~(((bool) count1 & node.is_dummy) << bit_idx);
        count1 -= (bool) count1 & node.is_dummy;

        /* Encrypt index i. */
        ret = node_encrypt(key, &node, arr + i * SIZEOF_ENCRYPTED_NODE, i);
        if (ret) {
            handle_error_string("Error encrypting node");
            goto exit;
        }
    }

    /* Oblivious bitonic sort elements according to BIT_IDX bit of ORP id. */
    struct merge_split_swap_aux swap_aux = {
        .arr = arr,
        .bit_idx = bit_idx,
        .bucket1 = bucket1,
        .bucket2 = bucket2,
    };
    o_sort_generate_swaps(2 * BUCKET_SIZE, merge_split_swap, &swap_aux);

exit:
    return ret;
}

/* Performs a swap of nodes A and B in ARR, used when the input array is too
 * small to reasonably perform bucket oblivious sort. */
static void sort_swap(size_t a, size_t b, void *arr_) {
    unsigned char *arr = arr_;
    int ret;

    node_t node_a;
    node_t node_b;

    /* Decrypt nodes. */
    ret = node_decrypt(key, &node_a, arr + a * SIZEOF_ENCRYPTED_NODE, a);
    if (ret) {
        handle_error_string("Error decrypting node");
        goto exit;
    }
    ret = node_decrypt(key, &node_b, arr + b * SIZEOF_ENCRYPTED_NODE, b);
    if (ret) {
        handle_error_string("Error decrypting node");
        goto exit;
    }

    /* Compare and obliviously swap if the BIT_IDX bit of ORP ID of node A is
     * 1 and that of node B is 0. */
    bool cond = node_a.key > node_b.key;
    o_memswap(&node_a, &node_b, sizeof(node_a), cond);

    /* Encrypt nodes. */
    ret = node_encrypt(key, &node_a, arr + a * SIZEOF_ENCRYPTED_NODE, a);
    if (ret) {
        handle_error_string("Error encrypting node");
        goto exit;
    }
    ret = node_encrypt(key, &node_b, arr + b * SIZEOF_ENCRYPTED_NODE, b);
    if (ret) {
        handle_error_string("Error encrypting node");
        goto exit;
    }

exit:
    ;
}

int bucket_sort(void *arr, size_t length) {
    int ret;

    /* If the length is <= BUCKET_SIZE * 2, then we just bitonic sort normally,
     * since we will invoke bitonic sorts of size BUCKET_SIZE * 2 normally
     * anyway as part of bucket sort. */
    if (length <= BUCKET_SIZE * 2) {
        o_sort_generate_swaps(length, sort_swap, arr);
        ret = 0;
        goto exit;
    }

    ret = assign_random_ids_and_spread(arr, length);
    if (ret) {
        handle_error_string("Error assigning random IDs to nodes");
        goto exit;
    }

    ret = merge_split(arr, 0, 1, 0);
    if (ret) {
        handle_error_string("Error in merge split with index %lu\n", 0lu);
    }

exit:
    return ret;
}
