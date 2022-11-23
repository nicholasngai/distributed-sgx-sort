#include "enclave/orshuffle.h"
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <threads.h>
#include <time.h>
#include <liboblivious/primitives.h>
#include "common/crypto.h"
#include "common/defs.h"
#include "common/error.h"
#include "common/util.h"
#include "enclave/mpi_tls.h"
#include "enclave/nonoblivious.h"
#include "enclave/parallel_enc.h"
#include "enclave/threading.h"

#define SWAP_CHUNK_SIZE 4096

static size_t total_length;

static thread_local elem_t *buffer;

int orshuffle_init(void) {
    int ret;

    buffer = malloc(SWAP_CHUNK_SIZE * sizeof(*buffer));
    if (!buffer) {
        perror("malloc buffer");
        ret = errno;
        goto exit;
    }

    ret = rand_init();
    if (ret) {
        handle_error_string("Error initializing RNG");
        goto exit_free_buffer;
    }

    return ret;

exit_free_buffer:
    free(buffer);
exit:
    return ret;
}

void orshuffle_free(void) {
    rand_free();
}

/* Array index and world rank relationship helpers. */

static int get_index_address(size_t index) {
    return index * world_size / total_length;
}

static size_t get_local_start(int rank) {
    return (rank * total_length + world_size - 1) / world_size;
}

/* Marking helper. */

static int should_mark(size_t left_to_mark, size_t total_left, bool *result) {
    int ret;

    size_t r;
    do {
        ret = rand_read(&r, sizeof(r));
        if (ret) {
            handle_error_string("Error reading random value");
            goto exit;
        }
    } while (r >= SIZE_MAX - SIZE_MAX % total_left);

    *result = r % total_left < left_to_mark;

exit:
    return ret;
}

/* Swapping. */

static int swap_local_range(elem_t *arr, size_t length, size_t a, size_t b,
        size_t count, size_t offset, size_t left_marked_count) {
    size_t local_start = get_local_start(world_rank);
    int ret;

    bool s =
        (offset % (length / 2) + left_marked_count >= length / 2) != (offset >= length / 2);

    for (size_t i = 0; i < count; i++) {
        bool cond = s != (a + i >= (offset + left_marked_count) % (length / 2));
        o_memswap(&arr[a + i - local_start], &arr[b + i - local_start],
                sizeof(*arr), cond);
    }

    ret = 0;

    return ret;
}

static int swap_remote_range(elem_t *arr, size_t length, size_t local_idx,
        size_t remote_idx, size_t count, size_t offset,
        size_t left_marked_count) {
    size_t local_start = get_local_start(world_rank);
    int remote_rank = get_index_address(remote_idx);
    int ret;

    bool s =
        (offset % (length / 2) + left_marked_count >= length / 2) != (offset >= length / 2);

    /* Swap elems in maximum chunk sizes of SWAP_CHUNK_SIZE and iterate until no
     * count is remaining. */
    while (count) {
        size_t elems_to_swap = MIN(count, SWAP_CHUNK_SIZE);

        /* Post receive for remote elems to buffer. */
        mpi_tls_request_t request;
        ret = mpi_tls_irecv_bytes(buffer,
                elems_to_swap * sizeof(*buffer), remote_rank, local_idx,
                &request);
        if (ret) {
            handle_error_string("Error receiving elem bytes");
            goto exit;
        }

        /* Send local elems to the remote. */
        ret =
            mpi_tls_send_bytes(arr + local_idx - local_start,
                    elems_to_swap * sizeof(*arr), remote_rank, remote_idx);
        if (ret) {
            handle_error_string("Error sending elem bytes");
            goto exit;
        }

        /* Wait for received elems to come in. */
        ret = mpi_tls_wait(&request, MPI_TLS_STATUS_IGNORE);
        if (ret) {
            handle_error_string("Error waiting on receive for elem bytes");
            goto exit;
        }

        /* Replace the local elements with the received remote elements if
         * necessary. Assume we are sorting ascending. If the local index is
         * lower, then we swap if the local element is lower. Likewise, if the
         * local index is higher, than we swap if the local element is higher.
         * If descending, everything is reversed. */
        for (size_t i = 0; i < elems_to_swap; i++) {
            bool cond = s != (local_idx + i >= (offset + left_marked_count) % (length / 2));
            o_memcpy(&arr[local_idx + i - local_start], &buffer[i],
                    sizeof(*arr), cond);
        }

        /* Bump pointers, decrement count, and continue. */
        local_idx += elems_to_swap;
        remote_idx += elems_to_swap;
        count -= elems_to_swap;
    }

    ret = 0;

exit:
    return ret;
}

static int swap_range(elem_t *arr, size_t length, size_t a_start, size_t b_start,
        size_t count, size_t offset, size_t left_marked_count) {
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
        return swap_local_range(arr, length, a_start, b_start, count, offset,
                left_marked_count);
    } else if (a_is_local) {
        size_t a_local_start = MAX(a_start, local_start);
        size_t a_local_end = MIN(a_start + count, local_end);
        return swap_remote_range(arr, length, a_local_start,
                b_start + a_local_start - a_start,
                a_local_end - a_local_start, offset, left_marked_count);
    } else if (b_is_local) {
        size_t b_local_start = MAX(b_start, local_start);
        size_t b_local_end = MIN(b_start + count, local_end);
        return swap_remote_range(arr, length, b_local_start,
                a_start + b_local_start - b_start,
                b_local_end - b_local_start, offset, left_marked_count);
    } else {
        return 0;
    }
}

struct compact_args {
    elem_t *arr;
    size_t start;
    size_t length;
    size_t offset;
    size_t num_threads;
    int ret;
};
static void compact(void *args_) {
    struct compact_args *args = args_;
    size_t local_start = get_local_start(world_rank);
    size_t local_length = get_local_start(world_rank + 1) - local_start;
    int ret;

    if (args->length < 2) {
        ret = 0;
        goto exit;
    }

    /* Count elements in the left half that are marked. */
    size_t left_marked_count = 0;
    for (size_t i = MAX(args->start, local_start);
            i < MIN(args->start + args->length / 2, local_start + local_length);
            i++) {
        left_marked_count += args->arr[i - local_start].marked;
    }

    /* Sum left half marked counts across enclaves. */
    int master_rank = get_index_address(args->start);
    int final_rank = get_index_address(args->start + args->length - 1);
    if (world_rank == master_rank) {
        for (int rank = master_rank + 1; rank <= final_rank; rank++) {
            /* Use START + LENGTH / 2 as the tag (the midpoint index) since
             * that's guaranteed to be unique across iterations. */
            size_t remote_left_marked_count;
            ret =
                mpi_tls_recv_bytes(&remote_left_marked_count,
                        sizeof(remote_left_marked_count), MPI_TLS_ANY_SOURCE,
                        OCOMPACT_MARKED_COUNT_MPI_TAG + (int) (args->start + args->length / 2),
                        MPI_TLS_STATUS_IGNORE);
            if (ret) {
                handle_error_string("Error receiving marked count into %d",
                        world_rank);
                goto exit;
            }
            left_marked_count += remote_left_marked_count;
        }

        for (int rank = master_rank + 1; rank <= final_rank; rank++) {
            ret =
                mpi_tls_send_bytes(&left_marked_count,
                        sizeof(left_marked_count), rank,
                        OCOMPACT_MARKED_COUNT_MPI_TAG);
            if (ret) {
                handle_error_string(
                        "Error sending total marked count from %d to %d",
                        world_rank, rank);
                goto exit;
            }
        }
    } else {
        /* Use START + LENGTH / 2 as the tag (the midpoint index) since
         * that's guaranteed to be unique across iterations. */
        ret =
            mpi_tls_send_bytes(&left_marked_count, sizeof(left_marked_count),
                    master_rank,
                    OCOMPACT_MARKED_COUNT_MPI_TAG + (int) (args->start + args->length / 2));
        if (ret) {
            handle_error_string("Error sending marked count from %d into %d",
                    world_rank, master_rank);
            goto exit;
        }

        ret =
            mpi_tls_recv_bytes(&left_marked_count, sizeof(left_marked_count),
                    master_rank, OCOMPACT_MARKED_COUNT_MPI_TAG,
                    MPI_TLS_STATUS_IGNORE);
        if (ret) {
            handle_error_string(
                    "Error receiving total marked count from %d into %d",
                    world_rank, master_rank);
            goto exit;
        }
    }

    /* Swap. */
    ret =
        swap_range(args->arr, args->length, args->start,
                args->start + args->length / 2, args->length / 2, args->offset,
                left_marked_count);
    if (ret) {
        handle_error_string(
                "Error swapping range with start %lu and length %lu",
                args->start, args->start + args->length / 2);
        goto exit;
    }

    /* Recursively compact. */
    struct compact_args left_args = {
        .arr = args->arr,
        .start = args->start,
        .length = args->length / 2,
        .offset = args->offset % (args->length / 2),
        .ret = 0,
    };
    struct compact_args right_args = {
        .arr = args->arr,
        .start = args->start + args->length / 2,
        .length = args->length / 2,
        .offset = (args->offset + left_marked_count) % (args->length / 2),
        .ret = 0,
    };
    if (args->start + args->length / 2 >= local_start + local_length) {
        /* Right is remote; do just the left. */
        compact(&left_args);
        left_args.num_threads = args->num_threads;
        if (left_args.ret) {
            ret = left_args.ret;
            goto exit;
        }
    } else if (args->start + args->length / 2 <= local_start) {
        /* Left is remote; do just the right. */
        compact(&right_args);
        right_args.num_threads = args->num_threads;
        if (right_args.ret) {
            ret = right_args.ret;
            goto exit;
        }
    } else if (args->num_threads > 1) {
        /* Do both in a threaded manner. */
        left_args.num_threads = args->num_threads / 2;
        right_args.num_threads = args->num_threads / 2;
        struct thread_work right_work = {
            .type = THREAD_WORK_SINGLE,
            .single = {
                .func = compact,
                .arg = &right_args,
            },
        };
        thread_work_push(&right_work);
        compact(&left_args);
        left_args.num_threads = args->num_threads;
        if (left_args.ret) {
            ret = left_args.ret;
            goto exit;
        }
        thread_wait(&right_work);
    } else {
        /* Do both in our own thread. */
        left_args.num_threads = 1;
        right_args.num_threads = 1;
        compact(&left_args);
        if (left_args.ret) {
            ret = left_args.ret;
            goto exit;
        }
        compact(&right_args);
        if (right_args.ret) {
            ret = right_args.ret;
            goto exit;
        }
    }

exit:
    {
        int expected = 0;
        __atomic_compare_exchange_n(&args->ret, &expected, ret, false,
                __ATOMIC_RELAXED, __ATOMIC_RELAXED);
    }
}

struct shuffle_args {
    elem_t *arr;
    size_t start;
    size_t length;
    size_t num_threads;
    int ret;
};
static void shuffle(void *args_) {
    struct shuffle_args *args = args_;
    size_t local_start = get_local_start(world_rank);
    size_t local_length = get_local_start(world_rank + 1) - local_start;
    int ret;

    if (args->length < 2) {
        ret = 0;
        goto exit;
    }

    if (args->start >= local_start + local_length
            || args->start + args->length <= local_start) {
        ret = 0;
        goto exit;
    }

    /* Get the number of elements to mark in this enclave. */
    int master_rank = get_index_address(args->start);
    int final_rank = get_index_address(args->start + args->length - 1);
    size_t left_to_mark;
    if (master_rank == final_rank) {
        /* For single enclave, the number of elements is just half. */
        left_to_mark = args->length / 2;
    } else if (world_rank == master_rank) {
        /* If we are the first enclave containing this slice, do a bunch of
         * random sampling to figure out how many elements each enclave should
         * mark and send them to each enclave. */
        size_t enclave_mark_counts[world_size];
        memset(enclave_mark_counts, '\0', sizeof(enclave_mark_counts));

        size_t total_left_to_mark = args->length / 2;
        size_t total_left = args->length;
        for (int rank = master_rank; rank <= final_rank; rank++) {
            size_t rank_start = get_local_start(rank);
            size_t rank_end = get_local_start(rank + 1);
            for (size_t i = MAX(args->start, rank_start);
                    i < MIN(args->start + args->length, rank_end); i++) {
                bool marked;
                ret = should_mark(total_left_to_mark, total_left, &marked);
                if (ret) {
                    handle_error_string("Error getting random marked");
                    goto exit;
                }
                total_left_to_mark -= marked;
                total_left--;
                enclave_mark_counts[rank] += marked;
            }
        }

        for (int rank = master_rank + 1; rank <= final_rank; rank++) {
            ret =
                mpi_tls_send_bytes(&enclave_mark_counts[rank],
                        sizeof(enclave_mark_counts[rank]), rank,
                        OCOMPACT_MARKED_COUNT_MPI_TAG);
            if (ret) {
                handle_error_string("Error sending mark count from %d to %d",
                        world_rank, rank);
                goto exit;
            }
        }

        left_to_mark = enclave_mark_counts[0];
    } else {
        /* Else, receive the number of elements from the master. */
        ret =
            mpi_tls_recv_bytes(&left_to_mark, sizeof(left_to_mark), master_rank,
                    OCOMPACT_MARKED_COUNT_MPI_TAG, MPI_TLS_STATUS_IGNORE);
        if (ret) {
            handle_error_string("Error receiving mark count from %d into %d\n",
                    OCOMPACT_MARKED_COUNT_MPI_TAG, world_rank);
            goto exit;
        }
    }

    /* Mark exactly LEFT_TO_MARK elems in our partition. */
    size_t start_idx = MAX(args->start, local_start);
    size_t end_idx = MIN(args->start + args->length, local_start + local_length);
    size_t total_left = end_idx - start_idx;
    for (size_t i = start_idx; i < end_idx; i++) {
        bool marked;
        ret = should_mark(left_to_mark, total_left, &marked);
        if (ret) {
            handle_error_string("Error getting random marked");
            goto exit;
        }
        left_to_mark -= marked;
        total_left--;

        args->arr[i - local_start].marked = marked;
    }

    /* Obliviously compact. */
    struct compact_args compact_args = {
        .arr = args->arr,
        .start = args->start,
        .length = args->length,
        .offset = 0,
        .ret = 0,
    };
    compact(&compact_args);
    if (compact_args.ret) {
        ret = compact_args.ret;
        goto exit;
    }

    /* Recursively compact. */
    struct shuffle_args left_args = {
        .arr = args->arr,
        .start = args->start,
        .length = args->length / 2,
        .ret = 0,
    };
    struct shuffle_args right_args = {
        .arr = args->arr,
        .start = args->start + args->length / 2,
        .length = args->length / 2,
        .ret = 0,
    };
    if (args->start + args->length / 2 >= local_start + local_length) {
        /* Right is remote; do just the left. */
        shuffle(&left_args);
        left_args.num_threads = args->num_threads;
        if (left_args.ret) {
            ret = left_args.ret;
            goto exit;
        }
    } else if (args->start + args->length / 2 <= local_start) {
        /* Left is remote; do just the right. */
        shuffle(&right_args);
        right_args.num_threads = args->num_threads;
        if (right_args.ret) {
            ret = right_args.ret;
            goto exit;
        }
    } else if (args->num_threads > 1) {
        /* Do both in a threaded manner. */
        left_args.num_threads = args->num_threads / 2;
        right_args.num_threads = args->num_threads / 2;
        struct thread_work right_work = {
            .type = THREAD_WORK_SINGLE,
            .single = {
                .func = shuffle,
                .arg = &right_args,
            },
        };
        thread_work_push(&right_work);
        shuffle(&left_args);
        left_args.num_threads = args->num_threads;
        if (left_args.ret) {
            ret = left_args.ret;
            goto exit;
        }
        thread_wait(&right_work);
    } else {
        /* Do both in our own thread. */
        left_args.num_threads = 1;
        right_args.num_threads = 1;
        shuffle(&left_args);
        if (left_args.ret) {
            ret = left_args.ret;
            goto exit;
        }
        shuffle(&right_args);
        if (right_args.ret) {
            ret = right_args.ret;
            goto exit;
        }
    }

    ret = 0;

exit:
    {
        int expected = 0;
        __atomic_compare_exchange_n(&args->ret, &expected, ret, false,
                __ATOMIC_RELAXED, __ATOMIC_RELAXED);
    }
}

int orshuffle_sort(elem_t *arr, size_t length, size_t num_threads) {
    size_t local_start = length * world_rank / world_size;
    size_t local_length = length * (world_rank + 1) / world_size - local_start;
    int ret;

#ifdef DISTRIBUTED_SGX_SORT_BENCHMARK
    struct timespec time_start;
    if (clock_gettime(CLOCK_REALTIME, &time_start)) {
        handle_error_string("Error getting time");
        ret = errno;
        goto exit;
    }
#endif /* DISTRIBUTED_SGX_SORT_BENCHMARK */

    total_length = length;

    struct shuffle_args args = {
        .arr = arr,
        .start = 0,
        .length = length,
        .num_threads = num_threads,
        .ret = 0,
    };
    shuffle(&args);
    if (args.ret) {
        handle_error_string("Error in recursive shuffle");
        ret = args.ret;
        goto exit;
    }

#ifdef DISTRIBUTED_SGX_SORT_BENCHMARK
    struct timespec time_shuffle;
    if (clock_gettime(CLOCK_REALTIME, &time_shuffle)) {
        handle_error_string("Error getting time");
        ret = errno;
        goto exit;
    }
#endif /* DISTRIBUTED_SGX_SORT_BENCHMARK */

    /* Nonoblivious sort. */
    ret = nonoblivious_sort(arr, length, local_length, local_start);
    if (ret) {
        goto exit;
    }

#ifdef DISTRIBUTED_SGX_SORT_BENCHMARK
    if (world_rank == 0) {
        printf("shuffle          : %f\n",
                get_time_difference(&time_start, &time_shuffle));
    }
#endif

exit:
    return ret;
}
