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
    void (*func)(node_t *arr, size_t start, size_t length, size_t skip, bool right_heavy,
            size_t num_threads);
    node_t *arr;
    size_t start;
    size_t length;
    size_t skip;
    bool right_heavy;
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

static void swap_local(node_t *arr, size_t a, size_t b) {
    size_t local_start = get_local_start(world_rank);
    bool cond = arr[a - local_start].key > arr[b - local_start].key;
    o_memswap(&arr[a - local_start], &arr[b - local_start], sizeof(*arr), cond);
}

static void swap_remote(node_t *arr, size_t local_idx, size_t remote_idx) {
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
     * If the local index is lower, then we swap if the local element is lower.
     * Likewise, if the local index is higher, than we swap if the local element
     * is higher. */
    bool cond =
        (local_idx < remote_idx)
            == (arr[local_idx - local_start].key > recv.key);
    o_memcpy(&arr[local_idx - local_start], &recv,
            sizeof(arr[local_idx - local_start]), cond);
}

static void swap(node_t *arr, size_t a, size_t b) {
    int a_rank = get_index_address(a);
    int b_rank = get_index_address(b);

    if (a_rank == world_rank && b_rank == world_rank) {
        swap_local(arr, a, b);
    } else if (a_rank == world_rank) {
        swap_remote(arr, a, b);
    } else if (b_rank == world_rank) {
        swap_remote(arr, b, a);
    }
}

/* Odd-even mergesort. */

static void sort_threaded(node_t *arr, size_t start, size_t length, size_t skip,
        bool right_heavy, size_t num_threads);
static void sort_single(node_t *arr, size_t start, size_t length, size_t skip,
        bool right_heavy);
static void merge_threaded(node_t *arr, size_t start, size_t length, size_t skip,
        bool right_heavy, size_t num_threads);
static void merge_single(node_t *arr, size_t start, size_t length, size_t skip,
        bool right_heavy);

static void sort_threaded(node_t *arr, size_t start, size_t length, size_t skip,
        bool right_heavy UNUSED, size_t num_threads) {
    if (num_threads == 1) {
        sort_single(arr, start, length, skip, right_heavy);
        return;
    }

    switch (length) {
        case 0:
        case 1:
            /* Do nothing. */
            break;
        case 2: {
            swap(arr, start, start + skip);
            break;
        }
        default: {
            /* Sort left and right halves. Sorting doesn't care if it's
             * right-heavy. */
            size_t left_length = (length + 1) / 2;
            size_t right_length = length / 2;
            size_t right_start = start + skip * left_length;
            if (right_start >= get_local_start(world_rank + 1)) {
                printf("Skip right\n");
                sort_threaded(arr, start, left_length, skip, false,
                        num_threads);
            } else if (start < get_local_start(world_rank)) {
                printf("Skip left\n");
                sort_threaded(arr, right_start, right_length, skip, false,
                        num_threads);
            } else {
                size_t right_threads = num_threads / 2;
                struct thread_work right_work = {
                    .func = sort_threaded,
                    .arr = arr,
                    .start = right_start,
                    .length = right_length,
                    .skip = skip,
                    .right_heavy = false,
                    .num_threads = right_threads,
                };
                sema_init(&right_work.done, 0);
                push_thread_work(&right_work);
                sort_threaded(arr, start, left_length, skip, false,
                        num_threads - right_threads);
                sema_down(&right_work.done);
            }

            /* Odd-even merge. */
            merge_threaded(arr, start, length, skip, false, num_threads);
            break;
        }
    }
}

static void sort_single(node_t *arr, size_t start, size_t length, size_t skip,
        bool right_heavy UNUSED) {
    switch (length) {
        case 0:
        case 1:
            /* Do nothing. */
            break;
        case 2: {
            swap(arr, start, start + skip);
            break;
        }
        default: {
            /* Sort left and right halves. Sorting doesn't care if it's
             * right-heavy. */
            size_t left_length = (length + 1) / 2;
            size_t right_length = length / 2;
            size_t right_start = start + skip * left_length;
            if (right_start >= get_local_start(world_rank + 1)) {
                printf("Skip right\n");
                sort_single(arr, start, left_length, skip, false);
            } else if (start < get_local_start(world_rank)) {
                printf("Skip left\n");
                sort_single(arr, right_start, right_length, skip, false);
            } else {
                sort_single(arr, start, left_length, skip, false);
                sort_single(arr, start + skip * left_length, right_length, skip,
                        false);
            }

            /* Odd-even merge. */
            merge_single(arr, start, length, skip, false);
            break;
        }
    }
}

static void merge_threaded(node_t *arr, size_t start, size_t length, size_t skip,
        bool right_heavy, size_t num_threads) {
    if (num_threads == 1) {
        merge_single(arr, start, length, skip, right_heavy);
        return;
    }

    switch (length) {
        case 0:
        case 1:
            /* Do nothing. */
            break;
        case 2: {
            swap(arr, start, start + skip);
            break;
        }
        default: {
            /* Odd slices are right-heavy iff the odd slice has an odd length
             * and either the current slice is right-heavy or the current slice
             * has an even length. Again, the short-circuit operator is fine
             * because it will be deterministic. */
            size_t odd_length = length / 2;
            bool odd_right_heavy = odd_length % 2 == 1
                && (right_heavy || length % 2 == 0);
            size_t odd_threads = num_threads / 2;
            struct thread_work odd_work = {
                .func = merge_threaded,
                .arr = arr,
                .start = start + skip,
                .length = odd_length,
                .skip = skip * 2,
                .right_heavy = odd_right_heavy,
                .num_threads = odd_threads,
            };
            sema_init(&odd_work.done, 0);
            push_thread_work(&odd_work);

            /* Even slices are right-heavy iff the even slice has an odd length
             * and the current slice is right-heavy. The short-circuit operator
             * is fine because the whole sort is determinstic. */
            size_t even_length = (length + 1) / 2;
            bool even_right_heavy = even_length % 2 == 1 && right_heavy;
            merge_threaded(arr, start, even_length, skip * 2, even_right_heavy,
                    num_threads - odd_threads);

            sema_down(&odd_work.done);

            /* Sort adjacent pairs such that one pair crosses the left-right
             * boundary, which depends on whether the sorted list is
             * right-heavy. If the left sorted half has an even length, then we
             * start at 1; otherweise, we start at 0. We compute this by taking
             * half the total length, and the left half will have an extra
             * member if the total length is odd, and we are not right-heavy.
             * The short-circuit operator is deterministic. Taking this mod 2
             * and then inverting it by subtracting it from 1 gives the
             * starting index. */
            for (size_t i = 1 - (length / 2 + (length % 2 == 1 && !right_heavy)) % 2;
                    i < length - 1; i += 2) {
                swap(arr, start + skip * i, start + skip * (i + 1));
            }
            break;
         }
    }
}

static void merge_single(node_t *arr, size_t start, size_t length, size_t skip,
        bool right_heavy) {
    switch (length) {
        case 0:
        case 1:
            /* Do nothing. */
            break;
        case 2: {
            swap(arr, start, start + skip);
            break;
        }
        default: {
            /* Even slices are right-heavy iff the even slice has an odd length
             * and the current slice is right-heavy. The short-circuit operator
             * is fine because the whole sort is determinstic. */
            size_t even_length = (length + 1) / 2;
            bool even_right_heavy = even_length % 2 == 1 && right_heavy;
            merge_single(arr, start, even_length, skip * 2, even_right_heavy);

            /* Odd slices are right-heavy iff the odd slice has an odd length
             * and either the current slice is right-heavy or the current slice
             * has an even length. Again, the short-circuit operator is fine
             * because it will be deterministic. */
            size_t odd_length = length / 2;
            bool odd_right_heavy = odd_length % 2 == 1
                && (right_heavy || length % 2 == 0);
            merge_single(arr, start + skip, odd_length, skip * 2,
                    odd_right_heavy);

            /* Sort adjacent pairs such that one pair crosses the left-right
             * boundary, which depends on whether the sorted list is
             * right-heavy. If the left sorted half has an even length, then we
             * start at 1; otherweise, we start at 0. We compute this by taking
             * half the total length, and the left half will have an extra
             * member if the total length is odd, and we are not right-heavy.
             * The short-circuit operator is deterministic. Taking this mod 2
             * and then inverting it by subtracting it from 1 gives the
             * starting index. */
            for (size_t i = 1 - (length / 2 + (length % 2 == 1 && !right_heavy)) % 2;
                    i < length - 1; i += 2) {
                swap(arr, start + skip * i, start + skip * (i + 1));
            }
            break;
         }
    }
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
        work->func(work->arr, work->start, work->length, work->skip,
                work->right_heavy, work->num_threads);
        sema_up(&work->done);
        work = pop_thread_work();
    }

    /* Wait for master. */
    wait_for_all_threads();
}

int ecall_sort(node_t *arr, size_t total_length_, size_t local_length UNUSED) {
    total_length = total_length_;

    /* Wait for all threads to enter the enclave. */
    work_done = false;
    wait_for_all_threads();

    /* Start work for this thread. */
    sort_threaded(arr, 0, total_length, 1, false, total_num_threads);

    /* Release threads and wait until all leave. */
    __atomic_store_n(&work_done, true, __ATOMIC_RELAXED);
    wait_for_all_threads();
    work_done = false;

    return 0;
}
