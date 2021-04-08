#include <stdio.h>
#include <liboblivious/primitives.h>
#include <openenclave/enclave.h>
#include "parallel_t.h"
#include "synch.h"

#define UNUSED __attribute__((unused))

static int world_rank;
static int world_size;
static size_t total_num_threads;
static size_t total_length;

/* Thread synchronization. */

struct thread_work {
    void (*func)(node_t *arr, size_t start, size_t length, bool descending,
            size_t num_threads);
    node_t *arr;
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

static void swap_local(node_t *arr, size_t a, size_t b, bool descending) {
    size_t local_start = get_local_start(world_rank);
    bool cond =
        (arr[a - local_start].key > arr[b - local_start].key) != descending;
    o_memswap(&arr[a - local_start], &arr[b - local_start], sizeof(*arr), cond);
}

static void swap_remote(node_t *arr, size_t local_idx, size_t remote_idx,
        bool descending) {
    oe_result_t result;
    int ret;

    size_t local_start = get_local_start(world_rank);

    int remote_rank = get_index_address(remote_idx);

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
     * Assume we are sorting ascending. If the local index is lower, then we
     * swap if the local element is lower.  Likewise, if the local index is
     * higher, than we swap if the local element is higher. If descending,
     * everything is reversed. */
    bool cond =
        (local_idx < remote_idx)
            == (arr[local_idx - local_start].key > recv.key);
    cond = cond != descending;
    o_memcpy(&arr[local_idx - local_start], &recv,
            sizeof(arr[local_idx - local_start]), cond);
}

static void swap(node_t *arr, size_t a, size_t b, bool descending) {
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

static void sort_threaded(node_t *arr, size_t start, size_t length,
        bool descending, size_t num_threads);
static void sort_single(node_t *arr, size_t start, size_t length,
        bool descending);
static void merge_threaded(node_t *arr, size_t start, size_t length,
        bool descending, size_t num_threads);
static void merge_single(node_t *arr, size_t start, size_t length,
        bool descending);

static void sort_threaded(node_t *arr, size_t start, size_t length,
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
            } else if (start < get_local_start(world_rank)) {
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

static void sort_single(node_t *arr, size_t start, size_t length,
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
            } else if (start < get_local_start(world_rank)) {
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

static void merge_threaded(node_t *arr, size_t start, size_t length,
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
            } else if (start < get_local_start(world_rank)) {
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

static void merge_single(node_t *arr, size_t start, size_t length,
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
            } else if (start < get_local_start(world_rank)) {
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
    /* Wait for master. */
    wait_for_all_threads();

    struct thread_work *work = pop_thread_work();
    while (work) {
        work->func(work->arr, work->start, work->length, work->descending,
                work->num_threads);
        sema_up(&work->done);
        work = pop_thread_work();
    }

    /* Wait for master. */
    wait_for_all_threads();
}

int ecall_sort(node_t *arr, size_t total_length_, size_t local_length UNUSED) {
    if (popcount(total_length_) != 1) {
        fprintf(stderr, "Length must be a multiple of 2\n");
        return -1;
    }

    total_length = total_length_;

    /* Wait for all threads to enter the enclave. */
    work_done = false;
    wait_for_all_threads();

    /* Start work for this thread. */
    sort_threaded(arr, 0, total_length, false, total_num_threads);

    /* Release threads and wait until all leave. */
    __atomic_store_n(&work_done, true, __ATOMIC_RELAXED);
    wait_for_all_threads();
    work_done = false;

    return 0;
}
