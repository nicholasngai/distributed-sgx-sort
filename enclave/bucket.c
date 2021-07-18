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
#include "enclave/mpi_tls.h"
#include "enclave/parallel_enc.h"

#define BUCKET_SIZE 512

static size_t total_length;

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

static int get_bucket_rank(size_t bucket) {
    size_t num_buckets = next_pow2l(total_length) * 2 / BUCKET_SIZE;
    return bucket * world_size / num_buckets;
}

static size_t get_local_bucket_start(int rank) {
    size_t num_buckets = next_pow2l(total_length) * 2 / BUCKET_SIZE;
    return (rank * num_buckets + world_size - 1) / world_size;
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

/* Assigns random ORP IDs to the encrypted nodes, whose first element is
 * encrypted with index START_IDX, in ARR and distributes them evenly over the 2
 * * LENGTH elements in ARR. Thus, ARR is assumed to be at least 2 * LENGTH *
 * SIZEOF_ENCRYPTED_NODE bytes. The result is an array with real elements
 * interspersed with dummy elements. */
// TODO Parallelize?
// TODO Can we do the first bucket assignment scan while generating these?
static int assign_random_ids_and_spread(void *arr_, size_t length,
        size_t start_idx) {
    int ret;
    unsigned char *arr = arr_;

    node_t dummy_node;
    memset(&dummy_node, '\0', sizeof(dummy_node));
    dummy_node.is_dummy = true;

    for (size_t i = length - 1; i != SIZE_MAX; i--) {
        node_t node;

        /* Decrypt index i. */
        ret = node_decrypt(key, &node, arr + i * SIZEOF_ENCRYPTED_NODE,
                i + start_idx);
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
                2 * (i + start_idx));
        if (ret) {
            handle_error_string("Error encrypting node");
            goto exit;
        }

        /* Encrypt dummy node to index 2 * i + 1. */
        ret = node_encrypt(key, &dummy_node,
                arr + (2 * i + 1) * SIZEOF_ENCRYPTED_NODE,
                2 * (i + start_idx) + 1);
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
    size_t local_bucket_start = get_local_bucket_start(world_rank);
    int bucket1_rank = get_bucket_rank(bucket1);
    int bucket2_rank = get_bucket_rank(bucket2);
    bool bucket1_local = bucket1_rank == world_rank;
    bool bucket2_local = bucket2_rank == world_rank;

    /* If both buckets are remote, ignore this merge-split. */
    if (!bucket1_local && !bucket2_local) {
        ret = 0;
        goto exit;
    }

    int local_bucket = bucket1_local ? bucket1 : bucket2;
    int nonlocal_bucket = bucket1_local ? bucket2 : bucket1;
    int nonlocal_rank = bucket1_local ? bucket2_rank : bucket1_rank;

    /* Decrypt BUCKET1 nodes to buffer if local. */
    if (bucket1_local) {
        for (size_t i = 0; i < BUCKET_SIZE; i++) {
            size_t i_idx = (bucket1 - local_bucket_start) * BUCKET_SIZE + i;

            ret = node_decrypt(key, &buffer[i],
                    arr + i_idx * SIZEOF_ENCRYPTED_NODE,
                    bucket1 * BUCKET_SIZE + i);
            if (ret) {
                handle_error_string("Error decrypting node");
                goto exit;
            }
        }
    }

    /* Decrypt BUCKET2 nodes to buffer if local. */
    if (bucket2_local) {
        for (size_t i = 0; i < BUCKET_SIZE; i++) {
            size_t i_idx = (bucket2 - local_bucket_start) * BUCKET_SIZE + i;

            ret = node_decrypt(key, &buffer[i + BUCKET_SIZE],
                    arr + i_idx * SIZEOF_ENCRYPTED_NODE,
                    bucket2 * BUCKET_SIZE + i);
            if (ret) {
                handle_error_string("Error decrypting node");
                goto exit;
            }
        }
    }

    /* The number of elements with corresponding bit 1. */
    size_t count1 = 0;

    /* Count number of elements with corresponding bit 1 for local buckets. */
    if (bucket1_local) {
        for (size_t i = 0; i < BUCKET_SIZE; i++) {
            /* Obliviously increment count. */
            count1 += ((buffer[i].orp_id >> bit_idx) & 1) & !buffer[i].is_dummy;
        }
    }
    if (bucket2_local) {
        for (size_t i = BUCKET_SIZE; i < BUCKET_SIZE * 2; i++) {
            /* Obliviously increment count. */
            count1 += ((buffer[i].orp_id >> bit_idx) & 1) & !buffer[i].is_dummy;
        }
    }

    /* If remote, send the current count and then our local buckets. Then,
     * receive, the sent count and remote buckets from the other node. */
    if (!bucket1_local || !bucket2_local) {
        /* Send count. */
        ret = mpi_tls_send_bytes(&count1, sizeof(count1), nonlocal_rank,
                local_bucket);
        if (ret) {
            handle_error_string("Error sending count1");
            goto exit;
        }

        /* Send local bucket. */
        ret = mpi_tls_send_bytes(
                bucket1_local ? buffer : buffer + BUCKET_SIZE,
                sizeof(*buffer) * BUCKET_SIZE, nonlocal_rank, local_bucket);
        if (ret) {
            handle_error_string("Error sending local bucket");
            goto exit;
        }

        /* Receive count. */
        size_t remote_count1;
        ret = mpi_tls_recv_bytes(&remote_count1, sizeof(remote_count1),
                nonlocal_rank, nonlocal_bucket);
        if (ret) {
            handle_error_string("Error receiving count1");
            goto exit;
        }

        /* Receive remote bucket. */
        ret = mpi_tls_recv_bytes(
                bucket1_local ? buffer + BUCKET_SIZE : buffer,
                sizeof(*buffer) * BUCKET_SIZE, nonlocal_rank, nonlocal_bucket);
        if (ret) {
            handle_error_string("Error receiving remote bucket");
            goto exit;
        }

        /* Add the received remote count to the local count to arrive at the
         * total for both buckets. */
        count1 += remote_count1;
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

    /* Encrypt BUCKET1 nodes from buffer if local. */
    if (bucket1_local) {
        for (size_t i = 0; i < BUCKET_SIZE; i++) {
            size_t i_idx = (bucket1 - local_bucket_start) * BUCKET_SIZE + i;

            ret = node_encrypt(key, &buffer[i],
                    arr + i_idx * SIZEOF_ENCRYPTED_NODE,
                    bucket1 * BUCKET_SIZE + i);
            if (ret) {
                handle_error_string("Error encrypting node");
                goto exit;
            }
        }
    }

    /* Encrypt BUCKET2 nodes from buffer if local. */
    if (bucket2_local) {
        for (size_t i = 0; i < BUCKET_SIZE; i++) {
            size_t i_idx = (bucket2 - local_bucket_start) * BUCKET_SIZE + i;

            ret = node_encrypt(key, &buffer[i + BUCKET_SIZE],
                    arr + i_idx * SIZEOF_ENCRYPTED_NODE,
                    bucket2 * BUCKET_SIZE + i);
            if (ret) {
                handle_error_string("Error encrypting node");
                goto exit;
            }
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
 * beginning of the bucket) by sorting according to all bits of the ORP ID. This
 * is valid because the bin assignment used the lower bits of the ORP ID,
 * leaving the upper bits free for comparison and permutation within the bin.
 * The nodes are then written sequentially to ARR[*COMPRESS_IDX], and
 * *COMPRESS_IDX is incremented. The nodes receive new random ORP IDs. The first
 * element is assumed to have START_IDX for the purposes of decryption. */
static int permute_and_compress(void *arr_, size_t bucket,
        size_t *compress_idx, size_t start_idx) {
    int ret;
    unsigned char *arr = arr_;

    /* Decrypt nodes from bucket to buffer. */
    for (size_t i = 0; i < BUCKET_SIZE; i++) {
        size_t i_idx = bucket * BUCKET_SIZE + i + start_idx;

        ret = node_decrypt(key, buffer + i,
                arr + (bucket * BUCKET_SIZE + i) * SIZEOF_ENCRYPTED_NODE,
                i_idx);
        if (ret) {
            handle_error_string("Error decrypting node");
            goto exit;
        }
    }

    /* Scan for first dummy node. */
    size_t real_len = BUCKET_SIZE;
    for (size_t i = 0; i < BUCKET_SIZE; i++) {
        if (buffer[i].is_dummy) {
            real_len = i;
            break;
        }
    }

    o_sort(buffer, real_len, sizeof(*buffer), permute_comparator, NULL);

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
                arr + *compress_idx * SIZEOF_ENCRYPTED_NODE,
                *compress_idx + start_idx);
        if (ret) {
            handle_error_string("Error encrypting node");
            goto exit;
        }
        (*compress_idx)++;
    }

exit:
    return ret;
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
static int mergesort(void *arr_, void *out_, size_t length, size_t start_idx) {
    unsigned char *arr = arr_;
    unsigned char *out = out_;
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
                    arr + (i + j) * SIZEOF_ENCRYPTED_NODE, i + j + start_idx);
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
                    arr + (i + j) * SIZEOF_ENCRYPTED_NODE, i + j + start_idx);
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
    unsigned char *output = out;
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
                        i + j * run_length + start_idx);
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
                // TODO Use a heap?
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
                        i + output_idx + start_idx);
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
                                + merge_indices[lowest_run] + start_idx);
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
     * swapped) isn't the output parameter, copy to the right place. */
    if (input != out) {
        memcpy(out, input, length * SIZEOF_ENCRYPTED_NODE);
    }

exit_free_merge_indices:
    free(merge_indices);
exit:
    return ret;
}

enum enclave_merge_next_action {
    ENCLAVE_MERGE_SEND_NEXT,
    ENCLAVE_MERGE_FINISH_UNUSED,
    ENCLAVE_MERGE_FINISH_USED,
};

/* Sends the nodes in RUN to MERGER from low indices to high indices, starting
 * with the (*RUN_IDX)th node of RUN up to RUN_LEN and decrypting according to
 * *RUN_IDX + RUN_START_IDX. After the end of RUN is reached, a dummy node is
 * always sent to mark the end of the run. After sending, listen for the next
 * action from MERGER. When returning, *RUN_IDX is set to the index after the
 * index that was just used. */
static int enclave_merge_send(int merger, const void *run_, size_t *run_idx,
        size_t run_len, size_t run_start_idx) {
    int ret;
    const unsigned char *run = run_;

    enum enclave_merge_next_action next;
    do {
        /* Get the next node. */
        node_t node;
        if (*run_idx < run_len) {
            /* Decrypt the next node. */
            ret = node_decrypt(key, &node, run + *run_idx * SIZEOF_ENCRYPTED_NODE,
                    *run_idx + run_start_idx);
            if (ret) {
                handle_error_string("Error decrypting node");
                goto exit;
            }
        } else {
            /* We have reached the end, so assign a dummy node. */
            node.is_dummy = true;
        }

        /* Send the node to the recipient. */
        ret = mpi_tls_send_bytes(&node, sizeof(node), merger, 0);
        if (ret) {
            handle_error_string("Error sending node to merge");
            goto exit;
        }

        /* Increment the index. */
        (*run_idx)++;

        /* Receive whether we should send the next node. */
        ret = mpi_tls_recv_bytes(&next, sizeof(next), merger, 0);
        if (ret) {
            handle_error_string("Error receiving next merge action");
            goto exit;
        }
    } while (next == ENCLAVE_MERGE_SEND_NEXT);

    /* If we exited having without having used our last node, decrement the
     * index to return to the unused node. */
    if (next == ENCLAVE_MERGE_FINISH_UNUSED) {
        (*run_idx)--;
    }

    ret = 0;

exit:
    return ret;
}

/* Receives nodes from all enclaves and merges DEST_LEN nodes to DEST,
 * encrypting according to DEST_START_IDX. When receiving from self, nodes are
 * directly decrypted from RUN, using behavior identical to enclave_merge_send.
 * After merging a node, if our part of the array is full, send false to all
 * enclaves. Otherwise, send true to the enclave whose node we just used so that
 * they send their next lowest node. */
static int enclave_merge_recv(void *dest_, size_t dest_len,
        size_t dest_start_idx, const void *run_, size_t *run_idx,
        size_t run_len, size_t run_start_idx) {
    int ret;
    unsigned char *dest = dest_;
    const unsigned char *run = run_;

    /* Allocate receive buffer. */
    node_t *recv_buf = malloc(world_size * sizeof(*recv_buf));
    if (!recv_buf) {
        ret = errno;
        goto exit;
    }

    /* Receive first node from all enclaves. */
    for (int i = 0; i < world_size; i++) {
        if (i == world_rank) {
            /* Get node locally from self. */
            if (*run_idx < run_len) {
                /* Decrypt node from self. */
                ret = node_decrypt(key, &recv_buf[i],
                        run + *run_idx * SIZEOF_ENCRYPTED_NODE,
                        *run_idx + run_start_idx);
                if (ret) {
                    handle_error_string("Error decrypting node to merge");
                    goto exit_free_recv_buf;
                }
            } else {
                /* Flag node in buffer as dummy since we reached the end of our
                 * own run. */
                recv_buf[i].is_dummy = true;
            }
        } else {
            /* Receive node sent from enclave_merge_send. */
            ret = mpi_tls_recv_bytes(&recv_buf[i], sizeof(recv_buf[i]), i, 0);
            if (ret) {
                handle_error_string("Error receiving node to merge");
                goto exit_free_recv_buf;
            }
        }
    }

    /* Write nodes until we reach the end of the buffer. */
    int lowest_idx = -1;
    for (size_t i = 0; i < dest_len; i++) {
        /* Scan for the lowest node. */
        lowest_idx = -1;
        // TODO Use a heap?
        for (int j = 0; j < world_size; j++) {
            if (!recv_buf[j].is_dummy
                    && (lowest_idx == -1
                        || recv_buf[j].key < recv_buf[lowest_idx].key)) {
                lowest_idx = j;
            }
        }

        /* Encrypt the lowest index to the output. */
        ret = node_encrypt(key, &recv_buf[lowest_idx],
                dest + i * SIZEOF_ENCRYPTED_NODE, i + dest_start_idx);
        if (ret) {
            handle_error_string("Error encrypting merged node");
            goto exit_free_recv_buf;
        }

        /* If we used our own node, increment our run index. */
        if (lowest_idx == world_rank) {
            (*run_idx)++;
        }

        /* If we haven't reached the end, get the next node. */
        if (i < dest_len - 1) {
            if (lowest_idx == world_rank) {
                if (*run_idx < run_len) {
                    /* Decrypt node from self. */
                    ret = node_decrypt(key, &recv_buf[lowest_idx],
                            run + *run_idx * SIZEOF_ENCRYPTED_NODE,
                            *run_idx + run_start_idx);
                    if (ret) {
                        handle_error_string("Error decrypting node to merge");
                        goto exit_free_recv_buf;
                    }
                } else {
                    /* Flag node in buffer as dummy since we reached the end of
                     * our own run. */
                    recv_buf[lowest_idx].is_dummy = true;
                }
            } else {
                /* For remote nodes, send a status message to the enclave whose
                 * node we used to send the next node, then receive the node. */
                enum enclave_merge_next_action action = ENCLAVE_MERGE_SEND_NEXT;
                ret = mpi_tls_send_bytes(&action, sizeof(action), lowest_idx,
                        0);
                if (ret) {
                    handle_error_string("Error sending SEND_NEXT merge state");
                    goto exit_free_recv_buf;
                }
                ret = mpi_tls_recv_bytes(&recv_buf[lowest_idx],
                        sizeof(recv_buf[lowest_idx]), lowest_idx, 0);
                if (ret) {
                    handle_error_string("Error receiving next node to merge");
                    goto exit_free_recv_buf;
                }
            }
        }
    }

    /* Send the finished status to all enclaves. If we used the enclave's node
     * last (corresponding to lowest_idx), send the appropriate, different
     * message. */
    for (int i = 0; i < world_size; i++) {
        if (i == world_rank) {
            /* Skip ourselves. */
            continue;
        }

        /* Send finish states. */
        enum enclave_merge_next_action action =
            i == lowest_idx
                ? ENCLAVE_MERGE_FINISH_USED
                : ENCLAVE_MERGE_FINISH_UNUSED;
        ret = mpi_tls_send_bytes(&action, sizeof(action), i, 0);
        if (ret) {
            handle_error_string("Error sending FINISH merge state");
            goto exit;
        }
    }

    ret = 0;

exit_free_recv_buf:
    free(recv_buf);
exit:
    return ret;
}

int bucket_sort(void *arr, size_t length) {
    int ret;

    total_length = length;

    /* If the length is <= BUCKET_SIZE * 2, then we just bitonic sort normally,
     * since we will invoke bitonic sorts of size BUCKET_SIZE * 2 normally
     * anyway as part of bucket sort. */
    if (length <= BUCKET_SIZE * 2 && world_rank == 0) {
        ret = direct_sort(arr, length);
        if (ret) {
            handle_error_string("Error in direct sort for small arrays");
            goto exit;
        }
        goto exit;
    }

    size_t num_buckets = next_pow2l(length) * 2 / BUCKET_SIZE;
    size_t num_local_buckets =
        (get_local_bucket_start(world_rank + 1)
            - get_local_bucket_start(world_rank));
    size_t local_start = get_local_bucket_start(world_rank) * BUCKET_SIZE;
    size_t local_length = num_local_buckets * BUCKET_SIZE;

    /* Spread the elements located in the first half of our input array. */
    ret = assign_random_ids_and_spread(arr, local_length / 2, local_start / 2);
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
                    goto exit;
                }
            }
        }
        bit_idx++;
    }

    /* Permute each bucket and concatenate them back together by compressing all
     * real nodes together. We also assign new ORP IDs so that all elements have
     * a unique tuple of (key, ORP ID), even if they have duplicate keys. */
    size_t compress_len = 0;
    for (size_t bucket = 0; bucket < num_local_buckets; bucket++) {
        ret = permute_and_compress(arr, bucket, &compress_len, local_start);
        if (ret) {
            handle_error_string("Error permuting bucket %lu\n", bucket);
            goto exit;
        }
    }

    /* Non-oblivious, comparison-based sort for the local portion. Use the
     * second half of the host array as the output. */
    unsigned char *sorted_out = arr + local_length * SIZEOF_ENCRYPTED_NODE;
    ret = mergesort(arr, sorted_out, compress_len, local_start);
    if (ret) {
        handle_error_string("Error in non-oblivious sort");
        goto exit;
    }

    if (world_size == 1) {
        /* Copy the single run in our mergesort output to the input. */
        memcpy(arr, sorted_out, compress_len * SIZEOF_ENCRYPTED_NODE);
    } else {
        /* Non-oblivious merges across all enclaves to produce the final sotred
         * output, using the sorted data in the second half of the host array as
         * input. */
        size_t run_idx = 0;
        for (int rank = 0; rank < world_size; rank++) {
            if (rank == world_rank) {
                enclave_merge_recv(arr, local_length / 2, local_start / 2,
                        sorted_out, &run_idx, compress_len, local_start);
            } else {
                enclave_merge_send(rank,
                        sorted_out, &run_idx, compress_len, local_start);
            }
        }
    }

exit:
    return ret;
}
