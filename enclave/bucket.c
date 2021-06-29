#include "enclave/bucket.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <liboblivious/algorithms.h>
#include <liboblivious/primitives.h>
#include "common/error.h"
#include "common/node_t.h"

#define BUCKET_SIZE 512

static unsigned char key[16];

/* Buffer used to store 2 * BUCKET_SIZE nodes at once for the merge-split
 * operation. */
static _Thread_local node_t *buffer;

int bucket_init(void) {
    /* Initialize random. */
    if (rand_init()) {
        handle_error_string("Error initializing enclave random number generator");
        goto exit;
    }

    /* Allocate buffer. */
    buffer = malloc(BUCKET_SIZE * 2 * sizeof(*buffer));
    if (!buffer) {
        perror("Error allocating buffer");
        goto exit_free_rand;
    }

    return 0;

exit_free_rand:
    rand_free();
exit:
    return -1;
}

void bucket_free(void) {
    /* Free resources. */
    free(buffer);
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

/* Compare elements by the BIT_IDX bit of the ORP ID, then by dummy element
 * (real elements first). */
static int merge_split_comparator(const void *a_, const void *b_,
        void *bit_idx_) {
    const node_t *a = a_;
    const node_t *b = b_;
    size_t bit_idx = (size_t) bit_idx_;

    /* Compare and obliviously swap if the BIT_IDX bit of ORP ID of node A is
     * 1 and that of node B is 0 or if the ORP IDs are the same, but node A is a
     * dummy and node B is real. */
    char bit_a = (a->orp_id >> bit_idx) & 1;
    char bit_b = (b->orp_id >> bit_idx) & 1;
    return (bit_a << 1) - (bit_b << 1) + a->is_dummy - b->is_dummy;
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

    /* Decrypt BUCKET1 nodes to buffer. */
    for (size_t i = 0; i < BUCKET_SIZE; i++) {
        size_t i_idx = bucket1 * BUCKET_SIZE + i;

        ret = node_decrypt(key, buffer + i, arr + i_idx * SIZEOF_ENCRYPTED_NODE,
                i_idx);
        if (ret) {
            handle_error_string("Error decrypting node");
            goto exit;
        }
    }

    /* Decrypt BUCKET2 nodes to buffer. */
    for (size_t i = 0; i < BUCKET_SIZE; i++) {
        size_t i_idx = bucket2 * BUCKET_SIZE + i;

        ret = node_decrypt(key, buffer + BUCKET_SIZE + i,
                arr + i_idx * SIZEOF_ENCRYPTED_NODE, i_idx);
        if (ret) {
            handle_error_string("Error decrypting node");
            goto exit;
        }
    }

    /* The number of elements with corresponding bit 1. */
    size_t count1 = 0;

    /* Count number of elements with corresponding bit 1. */
    for (size_t i = 0; i < BUCKET_SIZE * 2; i++) {
        /* Obliviously increment count. */
        count1 += ((buffer[i].orp_id >> bit_idx) & 1) & !buffer[i].is_dummy;
    }

    /* There are count1 elements with bit 1, so we need to assign BUCKET_SIZE -
     * count1 dummy elements to have bit 1, with the remaining dummy elements
     * assigned with bit 0. */
    count1 = BUCKET_SIZE - count1;

    /* Assign dummy elements. */
    for (size_t i = 0; i < BUCKET_SIZE * 2; i++) {
        /* If count1 > 0 and the node is a dummy element, set BIT_IDX bit of ORP
         * ID and decrement count1. Else, clear BIT_IDX bit of ORP ID. */
        buffer[i].orp_id &= ~(buffer[i].is_dummy << bit_idx);
        buffer[i].orp_id |= ((bool) count1 & buffer[i].is_dummy) << bit_idx;
        count1 -= (bool) count1 & buffer[i].is_dummy;
    }

    /* Oblivious bitonic sort elements according to BIT_IDX bit of ORP id. */
    o_sort(buffer, BUCKET_SIZE * 2, sizeof(*buffer), merge_split_comparator,
            (void *) bit_idx);

    /* Encrypt BUCKET1 nodes from buffer. */
    for (size_t i = 0; i < BUCKET_SIZE; i++) {
        size_t i_idx = bucket1 * BUCKET_SIZE + i;

        ret = node_encrypt(key, buffer + i, arr + i_idx * SIZEOF_ENCRYPTED_NODE,
                i_idx);
        if (ret) {
            handle_error_string("Error encrypting node");
            goto exit;
        }
    }

    /* Encrypt BUCKET2 nodes from buffer. */
    for (size_t i = 0; i < BUCKET_SIZE; i++) {
        size_t i_idx = bucket2 * BUCKET_SIZE + i;

        ret = node_encrypt(key, buffer + BUCKET_SIZE + i,
                arr + i_idx * SIZEOF_ENCRYPTED_NODE, i_idx);
        if (ret) {
            handle_error_string("Error encrypting node");
            goto exit;
        }
    }

exit:
    return ret;
}

struct permute_swap_aux {
    void *arr;
    size_t bucket;
};

/* Compares elements by their ORP ID. */
static int permute_comparator(const void *a_, const void *b_,
        void *aux UNUSED) {
    const node_t *a = a_;
    const node_t *b = b_;
    return (a > b) - (a < b);
}

/* Permutes the real elements in the bucket (which are guaranteed to be at the
 * beginning of the bucket) by sorting according to all bits of the ORP ID and
 * setting *REAL_LEN to the number of real elements. This is valid because the
 * bin assignment used the lower bits of the ORP ID, leaving the upper bits free
 * for comparison and permutation within the bin. */
static void permute_and_scan(node_t *bucket, size_t *real_len) {
    /* Scan for first dummy node. */
    *real_len = BUCKET_SIZE;
    for (size_t i = 0; i < BUCKET_SIZE; i++) {
        if (bucket[i].is_dummy) {
            *real_len = i;
            break;
        }
    }

    o_sort(bucket, *real_len, sizeof(*bucket), permute_comparator, NULL);
}

/* Compares elements by their key. */
static int direct_comparator(const void *a_, const void *b_, void *aux UNUSED) {
    const node_t *a = a_;
    const node_t *b = b_;
    return (a->key > b->key) - (a->key < b->key);
}

/* Performs an oblivious sort, used when the input array is too small to
 * reasonably perform bucket oblivious sort. LENGTH must be less than
 * BUCKET_SIZE * 2! */
static int direct_sort(void *arr_, size_t length) {
    unsigned char *arr = arr_;
    int ret;

    /* Decrypt nodes. */
    for (size_t i = 0; i < length; i++) {
        ret = node_decrypt(key, buffer + i, arr + i * SIZEOF_ENCRYPTED_NODE, i);
        if (ret) {
            handle_error_string("Error decrypting node");
            goto exit;
        }
    }

    /* Sort. */
    o_sort(buffer, length, sizeof(*buffer), direct_comparator, NULL);

    /* Encrypt nodes. */
    for (size_t i = 0; i < length; i++) {
        ret = node_encrypt(key, buffer + i, arr + i * SIZEOF_ENCRYPTED_NODE, i);
        if (ret) {
            handle_error_string("Error encrypting node");
            goto exit;
        }
    }

    ret = 0;

exit:
    return ret;
}

/* Decrypts elements and compares them by their key. */
static int decrypt_comparator(const void *a, const void *b) {
    int ret;

    /* Decrypt nodes. */
    node_t node_a;
    node_t node_b;
    ret = node_decrypt(key, &node_a, a, 0);
    if (ret) {
        handle_error_string("Error decrypting node");
        goto exit;
    }
    ret = node_decrypt(key, &node_b, b, 0);
    if (ret) {
        handle_error_string("Error decrypting node");
        goto exit;
    }

    /* Compare nodes by the tuple (key, ORP ID). Note that we must always
     * perform the comparison for the ORP ID since we leak information about
     * duplicate keys otherwise. */
    ret = (((node_a.key > node_b.key) - (node_a.key < node_b.key)) << 1)
        + (((node_a.orp_id > node_b.orp_id) - (node_a.orp_id < node_b.orp_id)));

exit:
    return ret;
}

int bucket_sort(void *arr, size_t length) {
    int ret;

    /* If the length is <= BUCKET_SIZE * 2, then we just bitonic sort normally,
     * since we will invoke bitonic sorts of size BUCKET_SIZE * 2 normally
     * anyway as part of bucket sort. */
    if (length <= BUCKET_SIZE * 2) {
        ret = direct_sort(arr, length);
        if (ret) {
            handle_error_string("Error in direct sort for small arrays");
            goto exit;
        }
        goto exit;
    }

    /* Get double the next power of 2 greater than or equal to the length. */
    size_t rounded_length = 1;
    while (rounded_length < length) {
        rounded_length <<= 1;
    }
    rounded_length <<= 1;

    /* Compute the number of buckets needed. Multiply by 2 since we will have
     * dummy elements. */
    size_t num_buckets = rounded_length / BUCKET_SIZE;

    ret = assign_random_ids_and_spread(arr, length);
    if (ret) {
        handle_error_string("Error assigning random IDs to nodes");
        goto exit;
    }

    /* Run merge-split as part of a butterfly network. This is modified from
     * the paper, since all merge-split operations will be constrained to the
     * same buckets of memory. */
    size_t bit_idx = 0;
    for (size_t bucket_stride = 2; bucket_stride <= num_buckets;
            bucket_stride <<= 1) {
        for (size_t bucket_start = 0; bucket_start < num_buckets;
                bucket_start += bucket_stride) {
            for (size_t bucket = bucket_start;
                    bucket < bucket_start + bucket_stride / 2; bucket++) {
                size_t other_bucket = bucket + bucket_stride / 2;
                ret = merge_split(arr, bucket, other_bucket, bit_idx);
                if (ret) {
                    handle_error_string(
                            "Error in merge split with indices %lu and %lu\n",
                            bucket, other_bucket);
                }
            }
        }
        bit_idx++;
    }

    /* Permute each bucket and concatenate them back together by compressing all
     * real nodes together. We also assign new ORP IDs so that all elements have
     * a unique tuple of (key, ORP ID), even if they have duplicate keys. */
    size_t compress_idx = 0;
    for (size_t bucket = 0; bucket < num_buckets; bucket++) {
        /* Decrypt nodes from bucket to buffer. */
        for (size_t i = 0; i < BUCKET_SIZE; i++) {
            size_t i_idx = bucket * BUCKET_SIZE + i;

            ret = node_decrypt(key, buffer + i,
                    arr + i_idx * SIZEOF_ENCRYPTED_NODE, i_idx);
            if (ret) {
                handle_error_string("Error decrypting node");
                goto exit;
            }
        }

        /* Permute and get end of real elements in bucket. */
        size_t real_len;
        permute_and_scan(buffer, &real_len);

        /* Assign random ORP IDs and encrypt nodes from buffer to compressed
         * array. */
        for (size_t i = 0; i < real_len; i++) {
            /* Assign random ORP ID. */
            ret = rand_read(&buffer[i].orp_id, sizeof(buffer[i].orp_id));
            if (ret) {
                handle_error_string("Error assigning random ID");
                goto exit;
            }

            /* Encrypt. We must use a constant 0 index as AAD since quicksort
             * will swap ciphertexts directly. */
            ret = node_encrypt(key, buffer + i,
                    arr + compress_idx * SIZEOF_ENCRYPTED_NODE, 0);
            if (ret) {
                handle_error_string("Error encrypting node");
                goto exit;
            }
            compress_idx++;
        }
    }

    /* Non-oblivious, comparison-based sort. */
    qsort(arr, length, SIZEOF_ENCRYPTED_NODE, decrypt_comparator);

    /* Re-encrypt all nodes with the correct AAD. */
    for (size_t i = 0; i < length; i++) {

        /* Decrypt. */
        node_t node;
        ret = node_decrypt(key, &node, arr + i * SIZEOF_ENCRYPTED_NODE, 0);
        if (ret) {
            handle_error_string("Error decrypting node");
            goto exit;
        }

        /* Encrypt. */
        ret = node_encrypt(key, &node, arr + i * SIZEOF_ENCRYPTED_NODE, i);
        if (ret) {
            handle_error_string("Error encrypting node");
            goto exit;
        }
    }

exit:
    return ret;
}
