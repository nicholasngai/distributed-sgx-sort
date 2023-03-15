#include "enclave/orshuffle.h"
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <liboblivious/primitives.h>
#include "common/crypto.h"
#include "common/defs.h"
#include "common/error.h"
#include "common/ocalls.h"
#include "common/util.h"
#include "enclave/mpi_tls.h"
#include "enclave/nonoblivious.h"
#include "enclave/parallel_enc.h"
#include "enclave/threading.h"
#include "enclave/util.h"

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
#include "enclave/parallel_t.h"
#endif

#define SWAP_CHUNK_SIZE 4096

static size_t total_length;

static _Thread_local elem_t *buffer;

int orshuffle_init(void) {
    int ret;

    buffer = malloc(SWAP_CHUNK_SIZE * sizeof(*buffer));
    if (!buffer) {
        printf("Error allocating local buffer\n");
        ret = errno;
        goto exit;
    }

    return 0;

exit:
    return ret;
}

void orshuffle_free(void) {
    free(buffer);
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

    uint32_t r;
    ret = rand_read(&r, sizeof(r));
    if (ret) {
        handle_error_string("Error reading random value");
        goto exit;
    }

    *result = ((uint64_t) r * total_left) >> 32 >= left_to_mark;

exit:
    return ret;
}

/* Swapping. */

struct swap_local_range_args {
    elem_t *arr;
    size_t length;
    size_t a;
    size_t b;
    size_t count;
    size_t offset;
    size_t left_marked_count;
    size_t num_threads;
};
static void swap_local_range(void *args_, size_t i) {
    struct swap_local_range_args *args = args_;
    size_t local_start = get_local_start(world_rank);

    bool s =
        (args->offset % (args->length / 2) + args->left_marked_count
                >= args->length / 2)
            != (args->offset >= args->length / 2);

    size_t start = i * args->count / args->num_threads;
    size_t end = (i + 1) * args->count / args->num_threads;
    for (size_t j = start; j < end; j++) {
        bool cond =
            s
                != (args->a + j
                        >= (args->offset + args->left_marked_count)
                            % (args->length / 2));
        o_memswap(&args->arr[args->a + j - local_start],
                &args->arr[args->b + j - local_start],
                sizeof(*args->arr), cond);
    }
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
        size_t min_idx = MIN(local_idx, remote_idx);
        for (size_t i = 0; i < elems_to_swap; i++) {
            bool cond = s != (min_idx + i >= (offset + left_marked_count) % (length / 2));
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
        size_t count, size_t offset, size_t left_marked_count,
        size_t num_threads) {
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
        struct swap_local_range_args args = {
            .arr = arr,
            .length = length,
            .a = a_start,
            .b = b_start,
            .count = count,
            .offset = offset,
            .left_marked_count = left_marked_count,
            .num_threads = num_threads,
        };
        struct thread_work work;
        if (num_threads > 1) {
            work.type = THREAD_WORK_ITER;
            work.iter.func = swap_local_range;
            work.iter.arg = &args;
            work.iter.count = num_threads - 1;
            thread_work_push(&work);
        }
        swap_local_range(&args, num_threads - 1);
        if (num_threads > 1) {
            thread_wait(&work);
        }
        return 0;
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

    if (args->start >= local_start
            && args->start + args->length <= local_start + local_length
            && args->length == 2) {
        bool cond =
            (!args->arr[args->start].marked & args->arr[args->start + 1].marked)
                != (bool) args->offset;
        o_memswap(&args->arr[args->start], &args->arr[args->start + 1],
                sizeof(*args->arr), cond);
        ret = 0;
        goto exit;
    }

    if (args->start >= local_start + local_length
            || args->start + args->length <= local_start) {
        ret = 0;
        goto exit;
    }

    /* Get number of elements in the left half that are marked. The elements
     * contains the prefix sums, so taking the final prefix sum minus the first
     * prefix sum plus 1 if first element is marked should be sufficient. */
    int master_rank = get_index_address(args->start);
    int final_rank = get_index_address(args->start + args->length - 1);
    size_t mid_idx = args->start + args->length / 2 - 1;
    int mid_rank = get_index_address(mid_idx);
    /* Use START + LENGTH / 2 as the tag (the midpoint index) since that's
     * guaranteed to be unique across iterations. */
    int tag =
        OCOMPACT_MARKED_COUNT_MPI_TAG + (int) (args->start + args->length / 2);
    size_t left_marked_count;
    size_t mid_prefix_sum;
    if (world_rank == mid_rank) {
        /* Send the middle prefix sum to the master rank, since we have the
         * middle element. */
        if (world_rank == master_rank) {
            /* We are also the master, so set the local variable. */
            mid_prefix_sum = args->arr[mid_idx - local_start].marked_prefix_sum;
        } else {
            /* Send it to the master. */
            ret =
                mpi_tls_send_bytes(
                        &args->arr[mid_idx - local_start].marked_prefix_sum,
                        sizeof(args->arr->marked_prefix_sum), master_rank, tag);
            if (ret) {
                handle_error_string(
                        "Error sending prefix marked count for %lu from %d to %d",
                        mid_idx, world_rank, master_rank);
                goto exit;
            }
        }
    }
    if (world_rank == master_rank) {
        /* If we don't have the middle element, receive the middle prefix
         * sum. */
        if (world_rank != mid_rank) {
            ret =
                mpi_tls_recv_bytes(&mid_prefix_sum, sizeof(mid_prefix_sum),
                        mid_rank, tag, MPI_TLS_STATUS_IGNORE);
            if (ret) {
                handle_error_string(
                        "Error receiving prefix marked count for %lu from %d into %d",
                        args->start, final_rank, world_rank);
                goto exit;
            }
        }

        /* Compute the number of marked elements. */
        left_marked_count =
            mid_prefix_sum
                - args->arr[args->start - local_start].marked_prefix_sum
                + args->arr[args->start - local_start].marked;

        /* Send it to everyone else. */
        for (int rank = master_rank + 1; rank <= final_rank; rank++) {
            ret =
                mpi_tls_send_bytes(&left_marked_count,
                        sizeof(left_marked_count), rank, tag);
            if (ret) {
                handle_error_string(
                        "Error sending total marked count from %d to %d",
                        world_rank, rank);
                goto exit;
            }
        }
    } else {
        /* Receive the left marked count from the master. */
        ret =
            mpi_tls_recv_bytes(&left_marked_count, sizeof(left_marked_count),
                    master_rank, tag, MPI_TLS_STATUS_IGNORE);
        if (ret) {
            handle_error_string(
                    "Error receiving total marked count from %d into %d",
                    world_rank, master_rank);
            goto exit;
        }
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
        left_args.num_threads = args->num_threads;
        compact(&left_args);
        if (left_args.ret) {
            ret = left_args.ret;
            goto exit;
        }
    } else if (args->start + args->length / 2 <= local_start) {
        /* Left is remote; do just the right. */
        right_args.num_threads = args->num_threads;
        compact(&right_args);
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

    /* Swap. */
    ret =
        swap_range(args->arr, args->length, args->start,
                args->start + args->length / 2, args->length / 2, args->offset,
                left_marked_count, args->num_threads);
    if (ret) {
        handle_error_string(
                "Error swapping range with start %lu and length %lu",
                args->start, args->start + args->length / 2);
        goto exit;
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

    if (args->start >= local_start
            && args->start + args->length <= local_start + local_length
            && args->length == 2) {
        unsigned char c;
        rand_read(&c, sizeof(c));
        bool cond = c & 1;
        o_memswap(&args->arr[args->start], &args->arr[args->start + 1],
                sizeof(*args->arr), cond);
        ret = 0;
        goto exit;
    }

    if (args->start >= local_start + local_length
            || args->start + args->length <= local_start) {
        ret = 0;
        goto exit;
    }

    /* Get the number of elements to mark in this enclave. */
    struct mark_count_payload {
        size_t num_to_mark;
        size_t marked_in_prev;
    };
    int master_rank = get_index_address(args->start);
    int final_rank = get_index_address(args->start + args->length - 1);
    int tag =
        OCOMPACT_MARKED_COUNT_MPI_TAG + (int) (args->start + args->length / 2);
    size_t num_to_mark;
    size_t marked_in_prev;
    if (master_rank == final_rank) {
        /* For single enclave, the number of elements is just half. */
        num_to_mark = args->length / 2;
        marked_in_prev = 0;
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

        marked_in_prev = enclave_mark_counts[master_rank];
        for (int rank = master_rank + 1; rank <= final_rank; rank++) {
            struct mark_count_payload payload = {
                .num_to_mark = enclave_mark_counts[rank],
                .marked_in_prev = marked_in_prev,
            };
            ret = mpi_tls_send_bytes(&payload, sizeof(payload), rank, tag);
            if (ret) {
                handle_error_string("Error sending mark count from %d to %d",
                        world_rank, rank);
                goto exit;
            }
            marked_in_prev += enclave_mark_counts[rank];
        }

        num_to_mark = enclave_mark_counts[0];
        marked_in_prev = 0;
    } else {
        /* Else, receive the number of elements from the master. */
        struct mark_count_payload payload;
        ret =
            mpi_tls_recv_bytes(&payload, sizeof(payload), master_rank,
                    tag, MPI_TLS_STATUS_IGNORE);
        if (ret) {
            handle_error_string("Error receiving mark count from %d into %d\n",
                    master_rank, world_rank);
            goto exit;
        }
        num_to_mark = payload.num_to_mark;
        marked_in_prev = payload.marked_in_prev;
    }

    /* Mark exactly NUM_TO_MARK elems in our partition. */
    size_t start_idx = MAX(args->start, local_start);
    size_t end_idx = MIN(args->start + args->length, local_start + local_length);
    size_t total_left = end_idx - start_idx;
    size_t marked_so_far = 0;
    for (size_t i = start_idx; i < end_idx; i++) {
        bool marked;
        ret = should_mark(num_to_mark - marked_so_far, total_left, &marked);
        if (ret) {
            handle_error_string("Error getting random marked");
            goto exit;
        }
        marked_so_far += marked;
        total_left--;

        args->arr[i - local_start].marked = marked;
        args->arr[i - local_start].marked_prefix_sum =
            marked_in_prev + marked_so_far;
    }

    /* Obliviously compact. */
    struct compact_args compact_args = {
        .arr = args->arr,
        .start = args->start,
        .length = args->length,
        .offset = 0,
        .num_threads = args->num_threads,
        .ret = 0,
    };
    compact(&compact_args);
    if (compact_args.ret) {
        ret = compact_args.ret;
        goto exit;
    }

    /* Recursively shuffle. */
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
        left_args.num_threads = args->num_threads;
        shuffle(&left_args);
        if (left_args.ret) {
            ret = left_args.ret;
            goto exit;
        }
    } else if (args->start + args->length / 2 <= local_start) {
        /* Left is remote; do just the right. */
        right_args.num_threads = args->num_threads;
        shuffle(&right_args);
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

/* For assign random ORP IDs to ARR[i * LENGTH / NUM_THREADS] to
 * ARR[(i + 1) * LENGTH / NUM_THREADS]. */
struct assign_random_id_args {
    elem_t *arr;
    size_t length;
    size_t start_idx;
    size_t num_threads;
    int ret;
};
static void assign_random_id(void *args_, size_t i) {
    struct assign_random_id_args *args = args_;
    int ret;

    size_t start = i * args->length / args->num_threads;
    size_t end = (i + 1) * args->length / args->num_threads;
    for (size_t j = start; j < end; j++) {
        ret = rand_read(&args->arr[j].orp_id, sizeof(args->arr[j].orp_id));
        if (ret) {
            handle_error_string("Error assigning random ID to elem %lu",
                    i + args->start_idx);
            goto exit;
        }
    }

    ret = 0;

exit:
    if (ret) {
        int expected = 0;
        __atomic_compare_exchange_n(&args->ret, &expected, ret,
                false, __ATOMIC_RELEASE, __ATOMIC_RELAXED);
    }
}

int orshuffle_sort(elem_t *arr, size_t length, size_t num_threads) {
    size_t local_start = length * world_rank / world_size;
    size_t local_length = length * (world_rank + 1) / world_size - local_start;
    int ret;

    struct ocall_timespec time_start;
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    {
        sgx_status_t result = ocall_clock_gettime(&time_start);
        if (result != SGX_SUCCESS) {
            handle_sgx_error(result, "ocall_clock_gettime");
            ret = -1;
            goto exit;
        }
    }
#else
    ocall_clock_gettime(&time_start);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */

    total_length = length;

    struct shuffle_args shuffle_args = {
        .arr = arr,
        .start = 0,
        .length = length,
        .num_threads = num_threads,
        .ret = 0,
    };
    shuffle(&shuffle_args);
    if (shuffle_args.ret) {
        handle_error_string("Error in recursive shuffle");
        ret = shuffle_args.ret;
        goto exit;
    }

    /* Assign random IDs to ensure uniqueness. */
    struct assign_random_id_args assign_random_id_args = {
        .arr = arr,
        .length = local_length,
        .start_idx = local_start,
        .num_threads = num_threads,
        .ret = 0,
    };
    struct thread_work work = {
        .type = THREAD_WORK_ITER,
        .iter = {
            .func = assign_random_id,
            .arg = &assign_random_id_args,
            .count = num_threads,
        },
    };
    thread_work_push(&work);
    thread_work_until_empty();
    thread_wait(&work);
    if (assign_random_id_args.ret) {
        handle_error_string("Error assigning random ORP IDs");
        ret = assign_random_id_args.ret;
        goto exit;
    }

    struct ocall_timespec time_shuffle;
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    {
        sgx_status_t result = ocall_clock_gettime(&time_shuffle);
        if (result != SGX_SUCCESS) {
            handle_sgx_error(result, "ocall_clock_gettime");
            ret = -1;
            goto exit;
        }
    }
#else
    ocall_clock_gettime(&time_shuffle);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */

    /* Nonoblivious sort. This requires MAX(LOCAL_LENGTH * 2, 512) elements for
     * both the array and buffer, so use the second half of the array given to
     * us (which should be of length MAX(LOCAL_LENGTH * 2, 512) * 2). */
    elem_t *buf = arr + MAX(local_length * 2, 512);
    ret = nonoblivious_sort(arr, buf, length, local_length, num_threads);
    if (ret) {
        goto exit;
    }

    /* Copy the output to the final output. */
    memcpy(arr, buf, local_length * sizeof(*arr));

    if (world_rank == 0) {
        printf("shuffle          : %f\n",
                get_time_difference(&time_start, &time_shuffle));
    }

exit:
    return ret;
}
