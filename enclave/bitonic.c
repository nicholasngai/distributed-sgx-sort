#include "enclave/bitonic.h"
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <liboblivious/algorithms.h>
#include <liboblivious/primitives.h>
#include "common/elem_t.h"
#include "common/error.h"
#include "common/util.h"
#include "enclave/mpi_tls.h"
#include "enclave/parallel_enc.h"
#include "enclave/threading.h"

#define SWAP_CHUNK_SIZE 4096

static size_t total_length;

static _Thread_local elem_t *buffer;

int bitonic_init(void) {
    /* Allocate buffers. */
    buffer = malloc(SWAP_CHUNK_SIZE * sizeof(*buffer));
    if (!buffer) {
        perror("malloc local_buffer");
        goto exit;
    }

    return 0;

exit:
    return -1;
}

void bitonic_free(void) {
    /* Free resources. */
    free(buffer);
}

/* Array index and world rank relationship helpers. */

static int get_index_address(size_t index) {
    return index * world_size / total_length;
}

static size_t get_local_start(int rank) {
    return (rank * total_length + world_size - 1) / world_size;
}

static void swap_local_range(elem_t *arr, size_t a, size_t b, size_t count,
        bool descending) {
    size_t local_start = get_local_start(world_rank);

    for (size_t i = 0; i < count; i++) {
        bool cond =
            (arr[a + i - local_start].key > arr[b + i - local_start].key);
        cond = cond != descending;
        o_memswap(&arr[a + i - local_start], &arr[b + i - local_start],
                sizeof(*arr), cond);
    }
}

static void swap_remote_range(elem_t *arr, size_t local_idx, size_t remote_idx,
        size_t count, bool descending) {
    size_t local_start = get_local_start(world_rank);
    int remote_rank = get_index_address(remote_idx);
    int ret;

    /* Swap elems in maximum chunk sizes of SWAP_CHUNK_SIZE and iterate until no
     * count is remaining. */
    while (count) {
        size_t elems_to_swap = MIN(count, SWAP_CHUNK_SIZE);

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
        ret =
            mpi_tls_send_bytes(arr + local_idx - local_start,
                    elems_to_swap * sizeof(*arr), remote_rank, remote_idx);
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
                    == (arr[local_idx + i - local_start].key > buffer[i].key);
            cond = cond != descending;
            o_memcpy(&arr[local_idx + i - local_start], &buffer[i],
                    sizeof(*arr), cond);
        }

        /* Bump pointers, decrement count, and continue. */
        local_idx += elems_to_swap;
        remote_idx += elems_to_swap;
        count -= elems_to_swap;
    }
}

static void swap(elem_t *arr, size_t a, size_t b, bool descending) {
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

static void swap_range(elem_t *arr, size_t a_start, size_t b_start,
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
    elem_t *arr;
    size_t start;
    size_t length;
    bool descending;
    size_t num_threads;
};

static void sort_threaded(void *args);
static void sort_single(elem_t *arr, size_t start, size_t length,
        bool descending);
static void merge_threaded(void *args);
static void merge_single(elem_t *arr, size_t start, size_t length,
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

            /* Bitonic merge. */
            merge_threaded(args);
            break;
        }
    }
}

void sort_single(elem_t *arr, size_t start, size_t length,
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
                sort_single(arr, start, left_length, descending);
                sort_single(arr, right_start, right_length, !descending);
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

static void merge_single(elem_t *arr, size_t start, size_t length,
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


void bitonic_sort(elem_t *arr, size_t length, size_t num_threads) {
    total_length = length;

    if (1lu << log2li(length) != length) {
        fprintf(stderr, "Length must be a multiple of 2\n");
        goto exit;
    }

    /* Start work for this thread. */
    struct threaded_args args = {
        .arr = arr,
        .start = 0,
        .length = total_length,
        .descending = false,
        .num_threads = num_threads,
    };
    sort_threaded(&args);

exit:
    ;
}
