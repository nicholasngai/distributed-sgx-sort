#include "enclave/bucket.h"
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <liboblivious/algorithms.h>
#include <liboblivious/primitives.h>
#include "common/defs.h"
#include "common/error.h"
#include "common/node_t.h"

#define BUCKET_SIZE 512

static unsigned char key[16];

/* Buffer used to store 2 * BUCKET_SIZE nodes at once for the merge-split
 * operation. */
static _Thread_local node_t *buffer;

/* Helpers. */

static long next_pow2l(long x) {
#ifdef __GNUC__
    long next = 1 << (sizeof(x) * CHAR_BIT - __builtin_clzl(x) - 1);
    if (next < x) {
        next <<= 1;
    }
    return next;
#else
    long next = 1;
    while (next < x) {
        next <<= 1;
    }
    return next << 1;
#endif
}

/* Initialization and deinitialization. */

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

/* Compares elements by the tuple (key, ORP ID). The check for the ORP ID must
 * always be run (it must be oblivious whether the comparison result is based on
 * the key or on the ORP ID), since we leak info on duplicate keys otherwise. */
static int mergesort_comparator(const void *a_, const void *b_) {
    const node_t *a = a_;
    const node_t *b = b_;
    int comp_key = (a->key > b->key) - (a->key < b->key);
    int comp_orp_id = (a->orp_id > b->orp_id) - (a->orp_id < b->orp_id);
    return (comp_key << 1) + comp_orp_id;
}

/* Non-oblivious sort. Based on an external mergesort algorithm since decrypting
 * nodes from host memory is expensive. We will reuse the buffer from the ORP,
 * so BUF_SIZE = BUCKET_SIZE * 2. WORK is a buffer that will be used to store
 * intermediate data. */
#define BUF_SIZE (BUCKET_SIZE * 2)
static int mergesort(void *arr_, void *work_, size_t length) {
    unsigned char *arr = arr_;
    unsigned char *work = work_;
    int ret;

    /* Allocate buffer used for BUF_SIZE-way merge. */
    size_t *merge_indices = malloc(BUF_SIZE * sizeof(*merge_indices));
    if (!merge_indices) {
        perror("Error allocating merge index buffer");
        ret = errno;
        goto exit;
    }

    /* Start by sorting runs of BUF_SIZE. */
    for (size_t i = 0; i < length; i += BUF_SIZE) {
        size_t run_length = MIN(length - i, BUF_SIZE);

        /* Decrypt nodes. */
        for (size_t j = 0; j < run_length; j++) {
            ret = node_decrypt(key, &buffer[j],
                    arr + (i + j) * SIZEOF_ENCRYPTED_NODE, i + j);
            if (ret) {
                handle_error_string("Error decrypting node");
                goto exit_free_merge_indices;
            }
        }

        /* Sort using libc quicksort. */
        qsort(buffer, run_length, sizeof(*buffer), mergesort_comparator);

        /* Encrypt nodes. */
        for (size_t j = 0; j < run_length; j++) {
            ret = node_encrypt(key, &buffer[j],
                    arr + (i + j) * SIZEOF_ENCRYPTED_NODE, i + j);
            if (ret) {
                handle_error_string("Error encrypting node");
                goto exit_free_merge_indices;
            }
        }
    }

    /* Merge runs of increasing length in a BUF_SIZE-way merge by reading the
     * next smallest element of run i into buffer[i], then merging and
     * encrypting to the output buffer. */
    unsigned char *input = arr;
    unsigned char *output = work;
    for (size_t run_length = BUF_SIZE; run_length < length;
            run_length *= BUF_SIZE) {
        for (size_t i = 0; i < length; i += run_length * BUF_SIZE) {
            size_t num_runs =
                CEIL_DIV(MIN(length - i, run_length * BUF_SIZE), run_length);

            /* Zero out index buffer. */
            memset(merge_indices, '\0', num_runs * sizeof(*merge_indices));

            /* Read in the first (smallest) element from run j into
             * buffer[j]. The runs start at element i. */
            for (size_t j = 0; j < num_runs; j++) {
                ret = node_decrypt(key, &buffer[j],
                        input + (i + j * run_length) * SIZEOF_ENCRYPTED_NODE,
                        i + j * run_length);
                if (ret) {
                    handle_error_string("Error decrypting node");
                    goto exit_free_merge_indices;
                }
            }

            /* Merge the runs in the buffer and encrypt to the output array.
             * Nodes for which we have reach the end of the array are marked as
             * a dummy element, so we continue until all nodes in buffer are
             * dummy nodes. */
            size_t output_idx = 0;
            bool all_dummy;
            do {
                /* Scan for lowest node. */
                size_t lowest_run;
                all_dummy = true;
                for (size_t j = 0; j < num_runs; j++) {
                    if (buffer[j].is_dummy) {
                        continue;
                    }
                    if (all_dummy
                            || mergesort_comparator(&buffer[j],
                                &buffer[lowest_run]) < 0) {
                        lowest_run = j;
                    }
                    all_dummy = false;
                }

                /* Break out of loop if all nodes were dummy. */
                if (all_dummy) {
                    continue;
                }

                /* Encrypt lowest node to output. */
                ret = node_encrypt(key, &buffer[lowest_run],
                        output + (i + output_idx) * SIZEOF_ENCRYPTED_NODE,
                        i + output_idx);
                merge_indices[lowest_run]++;
                output_idx++;

                /* Check if we have reached the end of the run. */
                if (merge_indices[lowest_run] >= run_length
                        || i + lowest_run * run_length
                            + merge_indices[lowest_run] >= length) {
                    /* Reached the end, so mark the node as dummy so that we
                     * ignore it. */
                    buffer[lowest_run].is_dummy = true;
                } else {
                    /* Not yet reached the end, so read the next node in the
                     * input run. */
                    ret = node_decrypt(key, &buffer[lowest_run],
                            input
                                + (i + lowest_run * run_length +
                                    merge_indices[lowest_run])
                                * SIZEOF_ENCRYPTED_NODE,
                            i + lowest_run * run_length
                                + merge_indices[lowest_run]);
                    if (ret) {
                        handle_error_string("Error decrypting node");
                        goto exit_free_merge_indices;
                    }
                }
            } while (!all_dummy);
        }

        /* Swap the input and output arrays. */
        unsigned char *temp = input;
        input = output;
        output = temp;
    }

    /* If the final merging output (now the input since it would have been
     * swapped) wasn't the original array, copy back to the right place. */
    if (input != arr) {
        memcpy(arr, input, length * SIZEOF_ENCRYPTED_NODE);
    }

exit_free_merge_indices:
    free(merge_indices);
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
    size_t rounded_length = next_pow2l(length) * 2;

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

            /* Encrypt. */
            ret = node_encrypt(key, buffer + i,
                    arr + compress_idx * SIZEOF_ENCRYPTED_NODE, compress_idx);
            if (ret) {
                handle_error_string("Error encrypting node");
                goto exit;
            }
            compress_idx++;
        }
    }

    /* Non-oblivious, comparison-based sort. */
    ret = mergesort(arr, arr + length * SIZEOF_ENCRYPTED_NODE, length);
    if (ret) {
        handle_error_string("Error in non-oblivious sort");
        goto exit;
    }

exit:
    return ret;
}
