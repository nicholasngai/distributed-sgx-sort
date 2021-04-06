#include <stdio.h>
#include <liboblivious/algorithms.h>
#include <liboblivious/primitives.h>
#include <openenclave/enclave.h>
#include "parallel_t.h"
#include "synch.h"

static int world_rank;
static int world_size;
static size_t num_threads;

static void wait_for_all_threads(void) {
    static size_t num_threads_waiting;
    static condvar_t all_threads_finished;
    static spinlock_t all_threads_lock;

    spinlock_lock(&all_threads_lock);
    num_threads_waiting++;
    if (num_threads_waiting >= num_threads) {
        condvar_broadcast(&all_threads_finished, &all_threads_lock);
        num_threads_waiting = 0;
    } else {
        condvar_wait(&all_threads_finished, &all_threads_lock);
    }
    spinlock_unlock(&all_threads_lock);
}

void ecall_set_params(int world_rank_, int world_size_, size_t num_threads_) {
    /* Set global parameters. */
    world_rank = world_rank_;
    world_size = world_size_;
    num_threads = num_threads_;
}

void ecall_start_work(size_t thread_id) {
    wait_for_all_threads();
}

static void get_index_address(size_t index, size_t length, int *rank) {
    // TODO Make this work for individual threads, too.
    *rank = index * world_size / length;
}

static size_t get_local_start(size_t length) {
    // TODO Make this world for individual threads, too.
    return (world_rank * length + world_size - 1) / world_size;
}

static void swap_local(node_t *arr, size_t length, size_t a, size_t b) {
    size_t local_start = get_local_start(length);
    bool cond = arr[a - local_start].key > arr[b - local_start].key;
    o_memswap(&arr[a - local_start], &arr[b - local_start], sizeof(*arr), cond);
}

static void swap_remote(node_t *arr, size_t length, size_t local_idx,
        size_t remote_idx) {
    oe_result_t result;
    int ret;

    size_t local_start = get_local_start(length);

    int remote_rank;
    get_index_address(remote_idx, length, &remote_rank);

    /* Send our current node. */
    result = ocall_mpi_send_bytes(&ret,
            (unsigned char *) &arr[local_idx - local_start],
            sizeof(arr[local_idx - local_start]), remote_rank, remote_idx);
    if (result != OE_OK || ret) {
        fprintf(stderr, "ocall_mpi_send_bytes: %s\n", oe_result_str(result));
    }

    /* Receive their node. */
    node_t recv;
    result = ocall_mpi_recv_bytes(&ret, (unsigned char *) &recv, sizeof(recv),
            remote_rank, local_idx);
    if (result != OE_OK || ret) {
        fprintf(stderr, "ocall_mpi_recv_bytes: %s\n", oe_result_str(result));
    }

    /* Replace the local element with the received remote element if necessary.
     * If the local index is lower, then we swap if the local element is lower.
     * Likewise, if the local index is higher, than we swap if the local element
     * is higher. */
    bool cond =
        (local_idx < remote_idx)
            == (arr[local_idx - local_start].key > recv.key);
    o_memcpy(&arr[local_idx - local_start], &recv,
            sizeof(arr[local_idx - local_start]), cond);
}

struct swap_args {
    node_t *arr;
    size_t length;
};

static void swap(size_t a, size_t b, void *args_) {
    struct swap_args *args = args_;

    int a_rank;
    int b_rank;
    get_index_address(a, args->length, &a_rank);
    get_index_address(b, args->length, &b_rank);

    if (a_rank == world_rank && b_rank == world_rank) {
        swap_local(args->arr, args->length, a, b);
    } else if (a_rank == world_rank) {
        swap_remote(args->arr, args->length, a, b);
    } else if (b_rank == world_rank) {
        swap_remote(args->arr, args->length, b, a);
    }
}

int ecall_sort(node_t *arr, size_t length) {
    /* Start work for this thread. */
    ecall_start_work(0);

    struct swap_args swap_args = {
        .arr = arr,
        .length = length,
    };
    o_sort_generate_swaps(length, swap, &swap_args);

    return 0;
}
