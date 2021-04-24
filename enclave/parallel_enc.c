#include <stdio.h>
#include <openenclave/enclave.h>
#include <liboblivious/primitives.h>
#include "common/crypto.h"
#include "common/defs.h"
#include "common/node_t.h"
#include "enclave/mpi_tls.h"
#include "enclave/parallel_t.h"
#include "enclave/synch.h"

static int world_rank;
static int world_size;
static size_t total_num_threads;
static size_t total_length;

static unsigned char key[16];

/* Thread synchronization. */

struct thread_work {
    void (*func)(void *arr, size_t start, size_t length, bool descending,
            size_t num_threads);
    void *arr;
    size_t start;
    size_t length;
    bool descending;
    size_t num_threads;

    sema_t done;

    struct thread_work *next;
};

static spinlock_t thread_work_lock;
static struct thread_work *volatile work_head;
static struct thread_work *volatile work_tail;
static volatile bool work_done;

static void push_thread_work(struct thread_work *work) {
    spinlock_lock(&thread_work_lock);
    work->next = NULL;
    if (!work_tail) {
        /* Empty list. Set head and tail. */
        work_head = work;
        work_tail = work;
    } else {
        /* List has values. */
        work_tail->next = work;
        work_tail = work;
    }
    spinlock_unlock(&thread_work_lock);
}

static struct thread_work *pop_thread_work(void) {
    struct thread_work *work = NULL;
    while (!work) {
        while (!work_head) {
            if (work_done) {
                goto exit;
            }
        }
        spinlock_lock(&thread_work_lock);
        if (work_head) {
            work = work_head;
            if (!work_head->next) {
                work_tail = NULL;
            }
            work_head = work_head->next;
        }
        spinlock_unlock(&thread_work_lock);
    }
exit:
    return work;
}

static void wait_for_all_threads(void) {
    static size_t num_threads_waiting;
    static condvar_t all_threads_finished;
    static spinlock_t all_threads_lock;

    spinlock_lock(&all_threads_lock);
    num_threads_waiting++;
    if (num_threads_waiting >= total_num_threads) {
        condvar_broadcast(&all_threads_finished, &all_threads_lock);
        num_threads_waiting = 0;
    } else {
        condvar_wait(&all_threads_finished, &all_threads_lock);
    }
    spinlock_unlock(&all_threads_lock);
}

/* Swapping. */

static int get_index_address(size_t index) {
    return index * world_size / total_length;
}

static size_t get_local_start(int rank) {
    return (rank * total_length + world_size - 1) / world_size;
}

static void swap_local(void *arr, size_t a, size_t b, bool descending) {
    size_t local_start = get_local_start(world_rank);
    unsigned char *a_addr =
        (unsigned char *) arr + (a - local_start) * SIZEOF_ENCRYPTED_NODE;
    unsigned char *b_addr =
        (unsigned char *) arr + (b - local_start) * SIZEOF_ENCRYPTED_NODE;
    int ret;

    /* Decrypt both nodes. The IV is the first 12 bytes. The tag is the next 16
     * bytes. The ciphertext is the remaining 128 bytes. */
    node_t node_a;
    node_t node_b;
    ret = node_decrypt(key, &node_a, a_addr, a);
    if (ret) {
        return;
    }
    ret = node_decrypt(key, &node_b, b_addr, b);
    if (ret) {
        return;
    }

    /* Oblivious comparison and swap. */
    bool cond = (node_a.key > node_b.key) != descending;
    o_memswap(&node_a, &node_b, sizeof(node_a), cond);

    /* Encrypt both nodes using the same layout as above. */
    ret = node_encrypt(key, &node_a, a_addr, a);
    if (ret) {
        return;
    }
    ret = node_encrypt(key, &node_b, b_addr, b);
    if (ret) {
        return;
    }
}

static void swap_remote(void *arr, size_t local_idx, size_t remote_idx,
        bool descending) {
    size_t local_start = get_local_start(world_rank);
    unsigned char *local_addr =
        (unsigned char *) arr +
            (local_idx - local_start) * SIZEOF_ENCRYPTED_NODE;
    int remote_rank = get_index_address(remote_idx);
    int ret;

    /* Decrypt both the local node. */
    node_t local_node;
    ret = node_decrypt(key, &local_node, local_addr, local_idx);
    if (ret) {
        return;
    }

    /* Send our current node. */
    ret = mpi_tls_send_bytes((unsigned char *) &local_node, sizeof(local_node),
            remote_rank, remote_idx);
    if (ret) {
        fprintf(stderr, "mpi_tls_send_bytes: Error sending bytes\n");
        return;
    }

    /* Receive their node. */
    node_t remote_node;
    ret = mpi_tls_recv_bytes((unsigned char *) &remote_node,
            sizeof(remote_node), remote_rank, local_idx);
    if (ret) {
        fprintf(stderr, "mpi_tls_recv_bytes: Error receiving bytes\n");
        return;
    }

    /* Replace the local element with the received remote element if necessary.
     * Assume we are sorting ascending. If the local index is lower, then we
     * swap if the local element is lower. Likewise, if the local index is
     * higher, than we swap if the local element is higher. If descending,
     * everything is reversed. */
    bool cond = (local_idx < remote_idx) == (local_node.key > remote_node.key);
    cond = cond != descending;
    o_memcpy(&local_node, &remote_node, sizeof(local_node), cond);

    /* Encrypt the local node (which is either old or new) back to memory. */
    ret = node_encrypt(key, &local_node, local_addr, local_idx);
}

static void swap(void *arr, size_t a, size_t b, bool descending) {
    int a_rank = get_index_address(a);
    int b_rank = get_index_address(b);

    if (a_rank == world_rank && b_rank == world_rank) {
        swap_local(arr, a, b, descending);
    } else if (a_rank == world_rank) {
        swap_remote(arr, a, b, descending);
    } else if (b_rank == world_rank) {
        swap_remote(arr, b, a, descending);
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

static void sort_threaded(void *arr, size_t start, size_t length,
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
                push_thread_work(&right_work);
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

static void sort_single(void *arr, size_t start, size_t length,
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
            for (size_t i = 0; i + left_length < length; i++) {
                swap(arr, start + i, start + i + left_length, descending);
            }
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
                push_thread_work(&right_work);
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
            for (size_t i = 0; i + left_length < length; i++) {
                swap(arr, start + i, start + i + left_length, descending);
            }
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

/* Helpers. */

static size_t popcount(size_t n) {
    size_t count = 0;
    for (size_t t = n; t > 0; t >>= 1) {
        if ((t & 0x1) == 1) {
            count++;
        }
    }
    return count;
}

/* ecalls. */

void ecall_set_params(int world_rank_, int world_size_, size_t num_threads) {
    /* Set global parameters. */
    world_rank = world_rank_;
    world_size = world_size_;
    total_num_threads = num_threads;
}

void ecall_start_work(void) {
    /* Wait for all threads to start work. */
    wait_for_all_threads();

    /* Initialize random. It is not safe to do this until passing the barrier,
     * since the master thread initializes the entropy source. */
    if (rand_init()) {
        fprintf(stderr, "Error initializing enclave random number generator\n");
    }

    struct thread_work *work = pop_thread_work();
    while (work) {
        work->func(work->arr, work->start, work->length, work->descending,
                work->num_threads);
        sema_up(&work->done);
        work = pop_thread_work();
    }

    /* Wait for all threads to exit work loop. */
    wait_for_all_threads();

    rand_free();
}

static void root_work_function(void *arr, size_t start, size_t length,
        bool descending, size_t num_threads) {
    sort_threaded(arr, start, length, descending, num_threads);
    /* Release threads. */
    work_done = true;
}

int ecall_sort(unsigned char *arr, size_t total_length_,
        size_t local_length UNUSED) {
    int ret = -1;

    if (popcount(total_length_) != 1) {
        fprintf(stderr, "Length must be a multiple of 2\n");
        goto exit;
    }

    total_length = total_length_;

    /* Initialize entropy. */
    if (entropy_init()) {
        fprintf(stderr, "Error initializing entropy\n");
        goto exit;
    }

    /* Initialize TLS over MPI. */
    if (mpi_tls_init((size_t) world_rank, (size_t) world_size, &entropy_ctx)) {
        fprintf(stderr, "mpi_tls_init: Error\n");
        goto exit_free_entropy;
    }

    /* Start work for this thread. */
    struct thread_work root_work = {
        .func = root_work_function,
        .arr = arr,
        .start = 0,
        .length = total_length,
        .descending = false,
        .num_threads = total_num_threads,
    };
    push_thread_work(&root_work);
    ecall_start_work();

    /* The thread does not return until work_done = true, so set it back to
     * false. */
    work_done = false;

    ret = 0;

    /* Free TLS over MPI. */
    mpi_tls_free();
exit_free_entropy:
    entropy_free();
exit:
    return ret;
}
