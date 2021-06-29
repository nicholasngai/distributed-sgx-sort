#include "enclave/bitonic.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <liboblivious/primitives.h>
#include "common/error.h"
#include "common/node_t.h"
#include "enclave/mpi_tls.h"
#include "enclave/parallel_enc.h"
#include "enclave/synch.h"
#include "enclave/threading.h"

#define SWAP_CHUNK_SIZE 4096

static _Thread_local node_t *local_buffer;
static _Thread_local node_t *remote_buffer;

static unsigned char key[16];

int bitonic_init(void) {
    /* Wait for all threads to init. We need to wait for all threads because the
     * master thread initialized the entropy source. */
    thread_wait_for_all();

    /* Allocate buffers. */
    local_buffer = malloc(SWAP_CHUNK_SIZE * sizeof(*local_buffer));
    if (!local_buffer) {
        perror("malloc local_buffer");
        goto exit;
    }
    remote_buffer = malloc(SWAP_CHUNK_SIZE * sizeof(*remote_buffer));
    if (!remote_buffer) {
        perror("malloc remote_buffer");
        goto exit_free_local_buffer;
    }

    /* Initialize random. */
    if (rand_init()) {
        handle_error_string("Error initializing enclave random number generator");
        goto exit_free_remote_buffer;
    }

    return 0;

exit_free_remote_buffer:
    free(remote_buffer);
exit_free_local_buffer:
    free(local_buffer);
exit:
    return -1;
}

void bitonic_free(void) {
    /* Free resources. */
    free(local_buffer);
    free(remote_buffer);
    rand_free();
}

/* Array index and world rank relationship helpers. */

static int get_index_address(size_t index) {
    return index * world_size / total_length;
}

static size_t get_local_start(int rank) {
    return (rank * total_length + world_size - 1) / world_size;
}

/* Decrypted sorting. */

static void decrypted_swap(node_t *a, node_t *b, bool descending) {
    bool cond = (a->key > b->key) != descending;
    o_memswap(a, b, sizeof(*a), cond);
}

static void decrypted_sort(node_t *arr, size_t length, bool descending);
static void decrypted_merge(node_t *arr, size_t length, bool descending);

static void decrypted_sort(node_t *arr, size_t length, bool descending) {
    switch (length) {
        case 0:
        case 1:
            /* Do nothing. */
            break;
        case 2: {
            decrypted_swap(arr, arr + 1, descending);
            break;
        }
        default: {
            /* Sort left half forwards and right half in reverse to create a
             * bitonic sequence. */
            size_t left_length = length / 2;
            size_t right_length = length - left_length;
            decrypted_sort(arr, left_length, descending);
            decrypted_sort(arr + left_length, right_length, !descending);

            /* Bitonic merge. */
            decrypted_merge(arr, length, descending);
            break;
        }
    }
}

static void decrypted_merge(node_t *arr, size_t length, bool descending) {
    switch (length) {
        case 0:
        case 1:
            /* Do nothing. */
            break;
        case 2: {
            decrypted_swap(arr, arr + 1, descending);
            break;
        }
        default: {
            /* If the length is odd, bubble sort an element to the end of the
             * array and leave it there. */
            size_t left_length = length / 2;
            size_t right_length = length - left_length;
            for (size_t i = 0; i < left_length; i++) {
                decrypted_swap(arr + i, arr + left_length + i, descending);
            }
            decrypted_merge(arr, left_length, descending);
            decrypted_merge(arr + left_length, right_length, descending);
            break;
         }
    }
}

/* Decrypts an entire range of nodes for the array ARR starting at START and
 * ending at START + LENGTH and sorts them obliviously according to DESCENDING
 * at once, entirely within enclave memory. LENGTH must be less than or equal to
 * SWAP_CHUNK_SIZE, since the local_buffer is used to hold decrypted nodes. The
 * entire chunk must reside in local memory. */
static void decrypt_and_sort(void *arr, size_t start, size_t length,
        bool descending) {
    size_t local_start = get_local_start(world_rank);
    int ret;

    /* Decrypt nodes to enclave buffer. */
    for (size_t i = 0; i < length; i++) {
        unsigned char *node_addr =
            (unsigned char *) arr
                + (start - local_start + i) * SIZEOF_ENCRYPTED_NODE;
        ret = node_decrypt(key, &local_buffer[i], node_addr, start + i);
        if (ret) {
            handle_error_string("Error decrypting node");
            return;
        }
    }

    /* Decrypted swap. */
    decrypted_sort(local_buffer, length, descending);

    /* Encrypt nodes to host memory. */
    for (size_t i = 0; i < length; i++) {
        unsigned char *node_addr =
            (unsigned char *) arr
                + (start - local_start + i) * SIZEOF_ENCRYPTED_NODE;
        ret = node_encrypt(key, &local_buffer[i], node_addr, start + i);
        if (ret) {
            handle_error_string("Error encrypting node");
            return;
        }
    }
}

/* Swapping. */

static void swap_local_range(void *arr, size_t a, size_t b, size_t count,
        bool descending) {
    size_t local_start = get_local_start(world_rank);
    int ret;

    for (size_t i = 0; i < count; i++) {
        size_t a_index = a + i;
        size_t b_index = b + i;
        void *a_addr =
            (unsigned char *) arr
                + (a_index - local_start) * SIZEOF_ENCRYPTED_NODE;
        void *b_addr =
            (unsigned char *) arr
                + (b_index - local_start) * SIZEOF_ENCRYPTED_NODE;

        /* Decrypt both nodes. */
        node_t node_a;
        node_t node_b;
        ret = node_decrypt(key, &node_a, a_addr, a_index);
        if (ret) {
            handle_error_string("Error decrypting node");
            return;
        }
        ret = node_decrypt(key, &node_b, b_addr, b_index);
        if (ret) {
            handle_error_string("Error decrypting node");
            return;
        }

        /* Oblivious comparison and swap. */
        bool cond = (node_a.key > node_b.key) != descending;
        o_memswap(&node_a, &node_b, sizeof(node_a), cond);

        /* Encrypt both nodes using the same layout as above. */
        ret = node_encrypt(key, &node_a, a_addr, a_index);
        if (ret) {
            handle_error_string("Error encrypting node");
            return;
        }
        ret = node_encrypt(key, &node_b, b_addr, b_index);
        if (ret) {
            handle_error_string("Error encrypting node");
            return;
        }
    }
}

static void swap_remote_range(void *arr, size_t local_idx, size_t remote_idx,
        size_t count, bool descending) {
    size_t local_start = get_local_start(world_rank);
    int remote_rank = get_index_address(remote_idx);
    int ret;

    /* Swap nodes in maximum chunk sizes of SWAP_CHUNK_SIZE and iterate until no
     * count is remaining. */
    while (count) {
        size_t nodes_to_swap = MIN(count, SWAP_CHUNK_SIZE);

        /* Decrypt local nodes. */
        for (size_t i = 0; i < nodes_to_swap; i++) {
            unsigned char *local_addr =
                (unsigned char *) arr +
                    (local_idx - local_start + i) * SIZEOF_ENCRYPTED_NODE;
            ret = node_decrypt(key, &local_buffer[i], local_addr, local_idx + i);
            if (ret) {
                handle_error_string("Error decrypting node");
                return;
            }
        }

        /* Send local nodes to the remote. */
        ret = mpi_tls_send_bytes(local_buffer,
                nodes_to_swap * sizeof(*local_buffer), remote_rank, remote_idx);
        if (ret) {
            handle_error_string("Error sending node bytes");
            return;
        }

        /* Receive remote nodes to encrypted buffer. */
        ret = mpi_tls_recv_bytes(remote_buffer,
                nodes_to_swap * sizeof(*remote_buffer), remote_rank, local_idx);
        if (ret) {
            handle_error_string("Error receiving node bytes");
            return;
        }

        /* Replace the local elements with the received remote elements if
         * necessary. Assume we are sorting ascending. If the local index is lower,
         * then we swap if the local element is lower. Likewise, if the local index
         * is higher, than we swap if the local element is higher. If descending,
         * everything is reversed. */
        for (size_t i = 0; i < nodes_to_swap; i++) {
            bool cond =
                (local_idx < remote_idx)
                    == (local_buffer[i].key > remote_buffer[i].key);
            cond = cond != descending;
            o_memcpy(&local_buffer[i], &remote_buffer[i], sizeof(*local_buffer),
                    cond);
        }

        /* Encrypt the local nodes (some of which are the same as before) back to
         * memory. */
        for (size_t i = 0; i < nodes_to_swap; i++) {
            void *local_addr =
                (unsigned char *) arr +
                    (local_idx - local_start + i) * SIZEOF_ENCRYPTED_NODE;
            ret = node_encrypt(key, &local_buffer[i], local_addr, local_idx + i);
            if (ret) {
                handle_error_string("Error encrypting node");
                return;
            }
        }

        /* Bump pointers, decrement count, and continue. */
        local_idx += nodes_to_swap;
        remote_idx += nodes_to_swap;
        count -= nodes_to_swap;
    }
}

static void swap(void *arr, size_t a, size_t b, bool descending) {
    int a_rank = get_index_address(a);
    int b_rank = get_index_address(b);

    if (a_rank == world_rank && b_rank == world_rank) {
        swap_local_range(arr, a, b, 1, descending);
    } else if (a_rank == world_rank) {
        swap_remote_range(arr, a, b, 1, descending);
    } else if (b_rank == world_rank) {
        swap_remote_range(arr, b, a, 1, descending);
    }
}

static void swap_range(void *arr, size_t a_start, size_t b_start,
        size_t count, bool descending) {
    // TODO Assumption: Only either a subset of range A is local, or a subset of
    // range B is local. For local-remote swaps, the subset of the remote range
    // correspondingw with the local range is entirely contained within a single
    // node. This requires that both the number of elements and the number of
    // nodes is a power of 2.

    size_t local_start = get_local_start(world_rank);
    size_t local_end = get_local_start(world_rank + 1);
    bool a_is_local = a_start < local_end && a_start + count > local_start;
    bool b_is_local = b_start < local_end && b_start + count > local_start;

    if (a_is_local && b_is_local) {
        swap_local_range(arr, a_start, b_start, count, descending);
    } else if (a_is_local) {
        size_t a_local_start = MAX(a_start, local_start);
        size_t a_local_end = MIN(a_start + count, local_end);
        swap_remote_range(arr, a_local_start, b_start + a_local_start - a_start,
                a_local_end - a_local_start, descending);
    } else if (b_is_local) {
        size_t b_local_start = MAX(b_start, local_start);
        size_t b_local_end = MIN(b_start + count, local_end);
        swap_remote_range(arr, b_local_start, a_start + b_local_start - b_start,
                b_local_end - b_local_start, descending);
    }
}

/* Bitonic sort. */

static void sort_threaded(void *arr, size_t start, size_t length,
        bool descending, size_t num_threads);
static void sort_single(void *arr, size_t start, size_t length,
        bool descending);
static void merge_threaded(void *arr, size_t start, size_t length,
        bool descending, size_t num_threads);
static void merge_single(void *arr, size_t start, size_t length,
        bool descending);

void sort_threaded(void *arr, size_t start, size_t length,
        bool descending UNUSED, size_t num_threads) {
    if (num_threads == 1) {
        sort_single(arr, start, length, descending);
        return;
    }

    switch (length) {
        case 0:
        case 1:
            /* Do nothing. */
            break;
        case 2: {
            swap(arr, start, start + 1, descending);
            break;
        }
        default: {
            /* Sort left half forwards and right half in reverse to create a
             * bitonic sequence. */
            size_t left_length = length / 2;
            size_t right_length = length - left_length;
            size_t right_start = start + left_length;
            if (right_start >= get_local_start(world_rank + 1)) {
                /* Only sort the left. The right is completely remote. */
                sort_threaded(arr, start, left_length, descending, num_threads);
            } else if (right_start <= get_local_start(world_rank)) {
                /* Only sort the right. The left is completely remote. */
                sort_threaded(arr, right_start, right_length, !descending,
                        num_threads);
            } else {
                /* Sort both. */
                size_t right_threads = num_threads * right_length / length;
                struct thread_work right_work = {
                    .func = sort_threaded,
                    .arr = arr,
                    .start = right_start,
                    .length = right_length,
                    .descending = !descending,
                    .num_threads = right_threads,
                };
                sema_init(&right_work.done, 0);
                thread_work_push(&right_work);
                sort_threaded(arr, start, left_length, descending,
                        num_threads - right_threads);
                sema_down(&right_work.done);
            }

            /* Bitonic merge. */
            merge_threaded(arr, start, length, descending, num_threads);
            break;
        }
    }
}

void sort_single(void *arr, size_t start, size_t length,
        bool descending) {
    switch (length) {
        case 0:
        case 1:
            /* Do nothing. */
            break;
        case 2: {
            swap(arr, start, start + 1, descending);
            break;
        }
        default: {
            /* Sort left half forwards and right half in reverse to create a
             * bitonic sequence. */
            size_t left_length = length / 2;
            size_t right_length = length - left_length;
            size_t right_start = start + left_length;
            if (right_start >= get_local_start(world_rank + 1)) {
                /* Only sort the left. The right is completely remote. */
                sort_single(arr, start, left_length, descending);
            } else if (right_start <= get_local_start(world_rank)) {
                /* Only sort the right. The left is completely remote. */
                sort_single(arr, right_start, right_length, !descending);
            } else {
                /* Sort both. */

                /* If the length is small enough, decrypt all nodes at once and
                 * sort them obliviously. */
                // The following commented code replacing the if condition
                // generalizes to sizes not a power of 2 but is much slower.
                //size_t local_start = get_local_start(world_rank);
                //size_t local_end = get_local_start(world_rank + 1);
                //if (start >= local_start && start + length < local_end
                //        && length <= SWAP_CHUNK_SIZE) {
                if (length <= SWAP_CHUNK_SIZE) {
                    decrypt_and_sort(arr, start, length, descending);
                    return;
                }

                sort_single(arr, start, left_length, descending);
                sort_single(arr, right_start, right_length, !descending);
            }

            /* Bitonic merge. */
            merge_single(arr, start, length, descending);
            break;
        }
    }
}

static void merge_threaded(void *arr, size_t start, size_t length,
        bool descending, size_t num_threads) {
    if (num_threads == 1) {
        merge_single(arr, start, length, descending);
        return;
    }

    switch (length) {
        case 0:
        case 1:
            /* Do nothing. */
            break;
        case 2: {
            swap(arr, start, start + 1, descending);
            break;
        }
        default: {
            /* If the length is odd, bubble sort an element to the end of the
             * array and leave it there. */
            size_t left_length = length / 2;
            size_t right_length = length - left_length;
            size_t right_start = start + left_length;
            swap_range(arr, start, right_start, left_length, descending);
            if (right_start >= get_local_start(world_rank + 1)) {
                /* Only merge the left. The right is completely remote. */
                merge_threaded(arr, start, left_length, descending,
                        num_threads);
            } else if (right_start <= get_local_start(world_rank)) {
                /* Only merge the right. The left is completely remote. */
                merge_threaded(arr, right_start, right_length, descending,
                        num_threads);
            } else {
                /* Merge both. */
                size_t right_threads = num_threads / 2;
                struct thread_work right_work = {
                    .func = merge_threaded,
                    .arr = arr,
                    .start = right_start,
                    .length = right_length,
                    .descending = descending,
                    .num_threads = right_threads,
                };
                sema_init(&right_work.done, 0);
                thread_work_push(&right_work);
                merge_threaded(arr, start, left_length, descending,
                        num_threads - right_threads);
                sema_down(&right_work.done);
            }
            break;
         }
    }
}

static void merge_single(void *arr, size_t start, size_t length,
        bool descending) {
    switch (length) {
        case 0:
        case 1:
            /* Do nothing. */
            break;
        case 2: {
            swap(arr, start, start + 1, descending);
            break;
        }
        default: {
            /* If the length is odd, bubble sort an element to the end of the
             * array and leave it there. */
            size_t left_length = length / 2;
            size_t right_length = length - left_length;
            size_t right_start = start + left_length;
            swap_range(arr, start, right_start, left_length, descending);
            if (right_start >= get_local_start(world_rank + 1)) {
                /* Only merge the left. The right is completely remote. */
                merge_single(arr, start, left_length, descending);
            } else if (right_start <= get_local_start(world_rank)) {
                /* Only merge the right. The left is completely remote. */
                merge_single(arr, right_start, right_length, descending);
            } else {
                /* Merge both. */
                merge_single(arr, start, left_length, descending);
                merge_single(arr, right_start, right_length, descending);
            }
            break;
         }
    }
}

/* Entry. */

static void root_work_function(void *arr, size_t start UNUSED, size_t length,
        bool descending UNUSED, size_t num_threads) {
    sort_threaded(arr, 0, length, false, num_threads);

    /* Release threads. */
    thread_release_all();
}

void bitonic_sort_threaded(void *arr, size_t length, size_t num_threads) {
    /* Start work for this thread. */
    struct thread_work root_work = {
        .func = root_work_function,
        .arr = arr,
        .length = length,
        .num_threads = num_threads,
    };
    thread_work_push(&root_work);
    thread_start_work();

    /* The thread does not return until work_done = true, so set it back to
     * false. */
    thread_unrelease_all();
}

void bitonic_sort_single(void *arr, size_t length) {
    sort_single(arr, 0, length, false);
}