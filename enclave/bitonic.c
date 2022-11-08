#include "enclave/bitonic.h"
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <threads.h>
#include <liboblivious/algorithms.h>
#include <liboblivious/primitives.h>
#include "common/elem_t.h"
#include "common/error.h"
#include "enclave/cache.h"
#include "enclave/mpi_tls.h"
#include "enclave/parallel_enc.h"
#include "enclave/threading.h"

static size_t total_length;

static thread_local elem_t *buffer;

int bitonic_init(void) {
    /* Allocate buffers. */
    buffer = malloc(CACHE_LINESIZE * sizeof(*buffer));
    if (!buffer) {
        perror("malloc local_buffer");
        goto exit;
    }

    /* Initialize cache. */
    if (cache_init()) {
        handle_error_string("Error initializing cache");
        goto exit_free_buffer;
    }

    /* Initialize random. */
    if (rand_init()) {
        handle_error_string("Error initializing enclave random number generator");
        goto exit_free_cache;
    }

    return 0;

exit_free_cache:
    cache_free();
exit_free_buffer:
    free(buffer);
exit:
    return -1;
}

void bitonic_free(void) {
    /* Free resources. */
    free(buffer);
    cache_free();
    rand_free();
}

/* Array index and world rank relationship helpers. */

static int get_index_address(size_t index) {
    return index * world_size / total_length;
}

static size_t get_local_start(int rank) {
    return (rank * total_length + world_size - 1) / world_size;
}

/* Swapping. */

static int sort_cache_line_comparator(const void *a_, const void *b_,
        void *aux UNUSED) {
    const elem_t *a = a_;
    const elem_t *b = b_;
    return (a->key > b->key) - (a->key < b->key);
}
static void sort_cache_line(void *arr, size_t start, size_t count) {
    size_t local_start = get_local_start(world_rank);

    if (count > CACHE_LINESIZE) {
        handle_error_string("Count too long for sort_cache_line");
        return;
    }

    elem_t *elems = cache_load_elems(arr, start - local_start, local_start);
    if (!elems) {
        handle_error_string("Error fetching elems");
        return;
    }

    o_sort(elems, count, sizeof(*elems), sort_cache_line_comparator, NULL);

    cache_free_elems(elems);
}

static void swap_local_range(void *arr, size_t a, size_t b, size_t count,
        bool descending) {
    size_t local_start = get_local_start(world_rank);

    while (count) {
        /* Fetch both lines. */
        elem_t *elems_a =
            cache_load_elems(arr, ROUND_DOWN(a - local_start, CACHE_LINESIZE),
                    local_start);
        if (!elems_a) {
            handle_error_string("Error fetching elems");
            return;
        }
        elem_t *elems_b =
            cache_load_elems(arr,
                    ROUND_DOWN(b - local_start, CACHE_LINESIZE),
                    local_start);
        if (!elems_b) {
            handle_error_string("Error fetching elems");
            cache_free_elems(elems_a);
            return;
        }

        /* Oblivious comparison and swap. */
        size_t a_start_idx = (a - local_start) % CACHE_LINESIZE;
        size_t b_start_idx = (b - local_start) % CACHE_LINESIZE;
        size_t elems_to_swap =
            MIN(count,
                    MIN(CACHE_LINESIZE - a_start_idx,
                        CACHE_LINESIZE - b_start_idx));
        for (size_t i = 0; i < elems_to_swap; i++) {
            bool cond =
                (elems_a[a_start_idx + i].key > elems_b[b_start_idx + i].key)
                    != descending;
            o_memswap(&elems_a[a_start_idx + i], &elems_b[b_start_idx + i],
                    sizeof(*elems_a), cond);
        }

        /* Free elems. */
        cache_free_elems(elems_a);
        cache_free_elems(elems_b);

        a += elems_to_swap;
        b += elems_to_swap;
        count -= elems_to_swap;
    }
}

static void swap_remote_range(void *arr, size_t local_idx, size_t remote_idx,
        size_t count, bool descending) {
    size_t local_start = get_local_start(world_rank);
    int remote_rank = get_index_address(remote_idx);
    int ret;

    /* Swap elems in maximum chunk sizes of SWAP_CHUNK_SIZE and iterate until no
     * count is remaining. */
    while (count) {
        size_t elems_to_swap = MIN(count, CACHE_LINESIZE);

        /* Fetch local elems. */
        elem_t *local_elems =
            cache_load_elems(arr, local_idx - local_start, local_start);
        if (!local_elems) {
            handle_error_string("Error fetching local elems from %lu",
                    local_idx);
            return;
        }

        /* Post receive for remote elems to encrypted buffer. */
        mpi_tls_request_t request;
        ret = mpi_tls_irecv_bytes(buffer,
                elems_to_swap * sizeof(*buffer), remote_rank, local_idx,
                &request);
        if (ret) {
            handle_error_string("Error receiving elem bytes");
            return;
        }

        /* Send local elems to the remote. */
        ret = mpi_tls_send_bytes(local_elems,
                elems_to_swap * sizeof(*local_elems), remote_rank, remote_idx);
        if (ret) {
            handle_error_string("Error sending elem bytes");
            return;
        }

        /* Wait for received elems to come in. */
        ret = mpi_tls_wait(&request, MPI_TLS_STATUS_IGNORE);
        if (ret) {
            handle_error_string("Error waiting on receive for elem bytes");
            return;
        }

        /* Replace the local elements with the received remote elements if
         * necessary. Assume we are sorting ascending. If the local index is
         * lower, then we swap if the local element is lower. Likewise, if the
         * local index is higher, than we swap if the local element is higher.
         * If descending, everything is reversed. */
        for (size_t i = 0; i < elems_to_swap; i++) {
            bool cond =
                (local_idx < remote_idx)
                    == (local_elems[i].key > buffer[i].key);
            cond = cond != descending;
            o_memcpy(&local_elems[i], &buffer[i], sizeof(*local_elems), cond);
        }

        cache_free_elems(local_elems);

        /* Bump pointers, decrement count, and continue. */
        local_idx += elems_to_swap;
        remote_idx += elems_to_swap;
        count -= elems_to_swap;
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
    // elem. This requires that both the number of elements and the number of
    // elems is a power of 2.

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

struct threaded_args {
    void *arr;
    size_t start;
    size_t length;
    bool descending;
    size_t num_threads;
};

static void sort_threaded(void *args);
static void sort_single(void *arr, size_t start, size_t length,
        bool descending);
static void merge_threaded(void *args);
static void merge_single(void *arr, size_t start, size_t length,
        bool descending);

void sort_threaded(void *args_) {
    struct threaded_args *args = args_;

    if (args->num_threads == 1) {
        sort_single(args->arr, args->start, args->length, args->descending);
        return;
    }

    switch (args->length) {
        case 0:
        case 1:
            /* Do nothing. */
            break;
        case 2: {
            swap(args->arr, args->start, args->start + 1, args->descending);
            break;
        }
        default: {
            /* Sort left half forwards and right half in reverse to create a
             * bitonic sequence. */
            size_t left_length = args->length / 2;
            size_t right_length = args->length - left_length;
            size_t right_start = args->start + left_length;
            if (right_start >= get_local_start(world_rank + 1)) {
                /* Only sort the left. The right is completely remote. */
                struct threaded_args left_args = {
                    .arr = args->arr,
                    .start = args->start,
                    .length = left_length,
                    .descending = args->descending,
                    .num_threads = args->num_threads,
                };
                sort_threaded(&left_args);
            } else if (right_start <= get_local_start(world_rank)) {
                /* Only sort the right. The left is completely remote. */
                struct threaded_args right_args = {
                    .arr = args->arr,
                    .start = right_start,
                    .length = right_length,
                    .descending = !args->descending,
                    .num_threads = args->num_threads,
                };
                sort_threaded(&right_args);
            } else {
                /* Sort both. */
                if (args->length <= CACHE_LINESIZE) {
                    /* If we've reached the level of a cache line, do the for
                     * the cache line at once. */
                    sort_cache_line(args->arr, args->start, args->length);
                } else {
                    size_t right_threads =
                        args->num_threads * right_length / args->length;
                    struct threaded_args right_args = {
                        .arr = args->arr,
                        .start = right_start,
                        .length = right_length,
                        .descending = !args->descending,
                        .num_threads = right_threads,
                    };
                    struct thread_work right_work = {
                        .type = THREAD_WORK_SINGLE,
                        .single = {
                            .func = sort_threaded,
                            .arg = &right_args,
                        },
                    };
                    thread_work_push(&right_work);

                    struct threaded_args left_args = {
                        .arr = args->arr,
                        .start = args->start,
                        .length = left_length,
                        .descending = args->descending,
                        .num_threads = args->num_threads - right_threads,
                    };
                    sort_threaded(&left_args);

                    thread_wait(&right_work);
                }
            }

            /* Bitonic merge. */
            merge_threaded(args);
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
                if (length <= CACHE_LINESIZE) {
                    /* If we've reached the level of a cache line, do the for
                     * the cache line at once. */
                    sort_cache_line(arr, start, length);
                } else {
                    sort_single(arr, start, left_length, descending);
                    sort_single(arr, right_start, right_length, !descending);
                }
            }

            /* Bitonic merge. */
            merge_single(arr, start, length, descending);
            break;
        }
    }
}

static void merge_threaded(void *args_) {
    struct threaded_args *args = args_;

    if (args->num_threads == 1) {
        merge_single(args->arr, args->start, args->length, args->descending);
        return;
    }

    switch (args->length) {
        case 0:
        case 1:
            /* Do nothing. */
            break;
        case 2: {
            swap(args->arr, args->start, args->start + 1, args->descending);
            break;
        }
        default: {
            /* If the length is odd, bubble sort an element to the end of the
             * array and leave it there. */
            size_t left_length = args->length / 2;
            size_t right_length = args->length - left_length;
            size_t right_start = args->start + left_length;
            swap_range(args->arr, args->start, right_start, left_length,
                    args->descending);
            if (right_start >= get_local_start(world_rank + 1)) {
                /* Only merge the left. The right is completely remote. */
                struct threaded_args left_args = {
                    .arr = args->arr,
                    .start = args->start,
                    .length = left_length,
                    .descending = args->descending,
                    .num_threads = args->num_threads,
                };
                merge_threaded(&left_args);
            } else if (right_start <= get_local_start(world_rank)) {
                /* Only merge the right. The left is completely remote. */
                struct threaded_args right_args = {
                    .arr = args->arr,
                    .start = right_start,
                    .length = right_length,
                    .descending = args->descending,
                    .num_threads = args->num_threads,
                };
                merge_threaded(&right_args);
            } else {
                /* Merge both. */
                size_t right_threads = args->num_threads / 2;
                struct threaded_args right_args = {
                    .arr = args->arr,
                    .start = right_start,
                    .length = right_length,
                    .descending = args->descending,
                    .num_threads = right_threads,
                };
                struct thread_work right_work = {
                    .type = THREAD_WORK_SINGLE,
                    .single = {
                        .func = merge_threaded,
                        .arg = &right_args,
                    },
                };
                thread_work_push(&right_work);

                struct threaded_args left_args = {
                    .arr = args->arr,
                    .start = args->start,
                    .length = left_length,
                    .descending = args->descending,
                    .num_threads = args->num_threads - right_threads,
                };
                merge_threaded(&left_args);

                thread_wait(&right_work);
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

static void root_work_function(void *args_) {
    struct threaded_args *args = args_;
    args->start = 0;
    args->descending = false;
    sort_threaded(args);

    if (cache_evictall(args->arr, get_local_start(world_rank))) {
        handle_error_string("Error evicting elements from cache");
        return;
    }

    /* Release threads. */
    thread_release_all();
}

void bitonic_sort(void *arr, size_t length, size_t num_threads) {
    total_length = length;

    /* Start work for this thread. */
    struct threaded_args root_args = {
        .arr = arr,
        .length = total_length,
        .num_threads = num_threads,
    };
    struct thread_work root_work = {
        .type = THREAD_WORK_SINGLE,
        .single = {
            .func = root_work_function,
            .arg = &root_args,
        },
    };
    thread_work_push(&root_work);
    thread_start_work();

    /* Wait for all threads to exit the work function, then unrelease the
     * threads. */
    while (__atomic_load_n(&num_threads_working, __ATOMIC_ACQUIRE)) {}
    thread_unrelease_all();
}
