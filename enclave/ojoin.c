#include "enclave/ojoin.h"
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <threads.h>
#include <liboblivious/primitives.h>
#include "common/defs.h"
#include "common/elem_t.h"
#include "common/error.h"
#include "enclave/bucket.h"
#include "enclave/mpi_tls.h"
#include "enclave/parallel_enc.h"
#include "enclave/threading.h"

#define SWAP_CHUNK_SIZE 4096

static thread_local elem_t *buffer;

int ojoin_init(void) {
    int ret;

    /* Allocate buffer. */
    buffer = malloc(BUCKET_SIZE * MAX(SWAP_CHUNK_BUCKETS, 2) * sizeof(*buffer));
    if (!buffer) {
        perror("malloc buffer");
        ret = errno;
        goto exit;
    }

    bucket_init_prealloc(buffer);

    ret = 0;

exit:
    return ret;
}

void ojoin_free(void) {
    free(buffer);
}

/* Array index and world rank relationship helpers. */

static size_t total_length;

static int get_index_address(size_t index) {
    return index * world_size / total_length;
}

static size_t get_local_start(int rank) {
    return (rank * total_length + world_size - 1) / world_size;
}

struct value_msg {
    uint64_t key;
    uint64_t value;
    bool has_value;
};

/* Swapping. */

static int swap_local_range(elem_t *arr, size_t length, size_t a, size_t b,
        size_t count, size_t offset, size_t left_marked_count) {
    size_t local_start = get_local_start(world_rank);
    int ret;

    bool s =
        (offset % (length / 2) + left_marked_count >= length / 2)
            != (offset >= length / 2);

    for (size_t i = 0; i < count; i++) {
        bool cond = s != (a + i >= (offset + left_marked_count) % (length / 2));
        o_memswap(&arr[a + i - local_start], &arr[b + i - local_start],
                sizeof(*arr), cond);
    }

    ret = 0;

    return ret;
}

struct swap_remote_range_args {
    elem_t *arr;
    size_t length;
    size_t local_idx;
    size_t remote_idx;
    size_t count;
    size_t offset;
    size_t left_marked_count;
    size_t num_threads;
    volatile int ret;
};
static void swap_remote_range(void *args_, size_t thread_idx) {
    struct swap_remote_range_args *args = args_;
    elem_t *arr = args->arr;
    size_t length = args->length;
    size_t local_idx = args->local_idx;
    size_t remote_idx = args->remote_idx;
    size_t count = args->count;
    size_t offset = args->offset;
    size_t left_marked_count = args->left_marked_count;
    size_t num_threads = args->num_threads;
    size_t local_start = get_local_start(world_rank);
    int remote_rank = get_index_address(remote_idx);
    int ret;

    bool s =
        (offset % (length / 2) + left_marked_count >= length / 2) != (offset >= length / 2);

    /* Swap elems in maximum chunk sizes of SWAP_CHUNK_SIZE and iterate until no
     * count is remaining. */
    size_t start = thread_idx * count / num_threads;
    size_t end = (thread_idx + 1) * count / num_threads;
    size_t our_local_idx = local_idx + start;
    size_t our_remote_idx = remote_idx + start;
    size_t our_count = end - start;
    while (our_count) {
        size_t elems_to_swap = MIN(our_count, SWAP_CHUNK_SIZE);

        /* Post receive for remote elems to buffer. */
        mpi_tls_request_t request;
        ret = mpi_tls_irecv_bytes(buffer,
                elems_to_swap * sizeof(*buffer), remote_rank,
                our_local_idx / SWAP_CHUNK_SIZE, &request);
        if (ret) {
            handle_error_string("Error receiving elem bytes");
            goto exit;
        }

        /* Send local elems to the remote. */
        ret =
            mpi_tls_send_bytes(arr + our_local_idx - local_start,
                    elems_to_swap * sizeof(*arr), remote_rank,
                    our_remote_idx / SWAP_CHUNK_SIZE);
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
        size_t min_idx = MIN(our_local_idx, our_remote_idx);
        for (size_t i = 0; i < elems_to_swap; i++) {
            bool cond = s != (min_idx + i >= (offset + left_marked_count) % (length / 2));
            o_memcpy(&arr[our_local_idx + i - local_start], &buffer[i],
                    sizeof(*arr), cond);
        }

        /* Bump pointers, decrement our_count, and continue. */
        our_local_idx += elems_to_swap;
        our_remote_idx += elems_to_swap;
        our_count -= elems_to_swap;
    }

    ret = 0;

exit:
    if (ret) {
        int expected = 0;
        __atomic_compare_exchange_n(&args->ret, &expected, ret, false,
                __ATOMIC_RELEASE, __ATOMIC_RELAXED);
    }
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
        return swap_local_range(arr, length, a_start, b_start, count, offset,
                left_marked_count);
    } else if (a_is_local) {
        size_t a_local_start = MAX(a_start, local_start);
        size_t a_local_end = MIN(a_start + count, local_end);
        struct swap_remote_range_args args = {
            .arr = arr,
            .length = length,
            .local_idx = a_local_start,
            .remote_idx = b_start + a_local_start - a_start,
            .count = a_local_end - a_local_start,
            .offset = offset,
            .left_marked_count = left_marked_count,
            .num_threads = num_threads,
            .ret = 0,
        };
        struct thread_work work;
        if (num_threads > 1) {
            work.type = THREAD_WORK_ITER;
            work.iter.func = swap_remote_range;
            work.iter.arg = &args;
            work.iter.count = num_threads - 1;
            thread_work_push(&work);
        }
        swap_remote_range(&args, num_threads - 1);
        if (num_threads > 1) {
            thread_wait(&work);
        }
        return args.ret;
    } else if (b_is_local) {
        size_t b_local_start = MAX(b_start, local_start);
        size_t b_local_end = MIN(b_start + count, local_end);
        struct swap_remote_range_args args = {
            .arr = arr,
            .length = length,
            .local_idx = b_local_start,
            .remote_idx = a_start + b_local_start - b_start,
            .count = b_local_end - b_local_start,
            .offset = offset,
            .left_marked_count = left_marked_count,
            .num_threads = num_threads,
            .ret = 0,
        };
        struct thread_work work;
        if (num_threads > 1) {
            work.type = THREAD_WORK_ITER;
            work.iter.func = swap_remote_range;
            work.iter.arg = &args;
            work.iter.count = num_threads - 1;
            thread_work_push(&work);
        }
        swap_remote_range(&args, num_threads - 1);
        if (num_threads > 1) {
            thread_wait(&work);
        }
        return args.ret;
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
    elem_t *arr = args->arr;
    size_t start = args->start;
    size_t length = args->length;
    size_t offset = args->offset;
    size_t num_threads = args->num_threads;
    size_t local_start = get_local_start(world_rank);
    size_t local_length = get_local_start(world_rank + 1) - local_start;
    int ret;

    if (length < 2) {
        ret = 0;
        goto exit;
    }

    if (start >= local_start && start + length <= local_start + local_length
            && length == 2) {
        bool cond = (arr[0].key & ~arr[1].key & 1) != (bool) offset;
        o_memswap(&arr[start - local_start], &arr[start + 1 - local_start],
                sizeof(*arr), cond);
        ret = 0;
        goto exit;
    }

    if (start >= local_start + local_length || start + length <= local_start) {
        ret = 0;
        goto exit;
    }

    /* Get number of elements in the left half that are marked. The elements
     * contains the prefix sums, so taking the final prefix sum minus the first
     * prefix sum plus 1 if first element is marked should be sufficient. */
    int master_rank = get_index_address(start);
    int final_rank = get_index_address(start + length - 1);
    size_t mid_idx = start + length / 2 - 1;
    int mid_rank = get_index_address(mid_idx);
    /* Use START + LENGTH / 2 as the tag (the midpoint index) since that's
     * guaranteed to be unique across iterations. */
    int tag =
        OCOMPACT_MARKED_COUNT_MPI_TAG
            + (start + length / 2) / SWAP_CHUNK_SIZE;
    size_t left_marked_count;
    size_t mid_prefix_sum;
    if (world_rank == mid_rank) {
        /* Send the middle prefix sum to the master rank, since we have the
         * middle element. */
        if (world_rank == master_rank) {
            /* We are also the master, so set the local variable. */
            mid_prefix_sum =
                arr[mid_idx - local_start].compact_marked_prefix_sum;
        } else {
            /* Send it to the master. */
            ret =
                mpi_tls_send_bytes(
                        &arr[mid_idx - local_start].compact_marked_prefix_sum,
                        sizeof(arr[mid_idx - local_start].compact_marked_prefix_sum),
                        master_rank, tag);
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
                        start, final_rank, world_rank);
                goto exit;
            }
        }

        /* Compute the number of marked elements. */
        left_marked_count =
            mid_prefix_sum - arr[start - local_start].compact_marked_prefix_sum
                + !(arr[start - local_start].key & 1);

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
        .arr = arr,
        .start = start,
        .length = length / 2,
        .offset = offset % (length / 2),
    };
    struct compact_args right_args = {
        .arr = arr,
        .start = start + length / 2,
        .length = length / 2,
        .offset = (offset + left_marked_count) % (length / 2),
    };
    if (start + length / 2 >= local_start + local_length) {
        /* Right is remote; do just the left. */
        left_args.num_threads = num_threads;
        compact(&left_args);
        if (left_args.ret) {
            ret = left_args.ret;
            goto exit;
        }
    } else if (start + length / 2 <= local_start) {
        /* Left is remote; do just the right. */
        right_args.num_threads = num_threads;
        compact(&right_args);
        if (right_args.ret) {
            ret = right_args.ret;
            goto exit;
        }
    } else if (num_threads > 1) {
        /* Do both in a threaded manner. */
        left_args.num_threads = num_threads / 2;
        right_args.num_threads = num_threads / 2;
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
        swap_range(arr, length, start, start + length / 2, length / 2, offset,
                left_marked_count, num_threads);
    if (ret) {
        handle_error_string(
                "Error swapping range with start %lu and length %lu", start,
                start + length / 2);
        goto exit;
    }

exit:
    args->ret = ret;
}

int ojoin(elem_t *arr, size_t length, size_t join_length, size_t num_threads) {
    int ret;

    size_t local_length =
        get_local_start(world_rank + 1) - get_local_start(world_rank);

    /* Sort. Because data elements have KEY & 1 == 0 and requests have
     * KEY & 1 == 1, all requests will be sorted immediately after their
     * keys. */
    ret = bucket_sort(arr, length, num_threads);
    if (ret) {
        handle_error_string("Error in oblivious sort");
        goto exit;
    }

    /* Backwards linear scan the last MIN(LOCAL_LENGTH, JOIN_LENGTH) elements and
     * obliviously select the first (closest to the end) data row. This allows
     * us to send the data row closest to the end to the next enclave for
     * parallelism. */
    struct value_msg last_value = {
        .has_value = false,
    };
    for (size_t i = 0; i < MIN(local_length, join_length); i++) {
        bool cond = !last_value.has_value & ((arr[i].key & 1) == 0);
        o_set64(&last_value.key, arr[i].key, cond);
        o_set64(&last_value.value, arr[i].value, cond);
        o_setbool(&last_value.has_value, true, cond);
    }

    /* Send the last element to the next enclave and receive the last element
     * from the previous enclave. */
    struct value_msg prev_last_value = {
        .has_value = false,
    };
    mpi_tls_request_t prev_last_value_request;
    if (world_rank > 0) {
        ret =
            mpi_tls_irecv_bytes(&prev_last_value, sizeof(prev_last_value),
                    world_rank - 1, 0, &prev_last_value_request);
        if (ret) {
            handle_error_string(
                    "Error posting receive for previous last value from %d into %d\n",
                    world_rank - 1, world_rank);
            goto exit;
        }
    }
    if (world_rank < world_size - 1) {
        ret =
            mpi_tls_send_bytes(&last_value, sizeof(last_value), world_rank + 1,
                    0);
        if (ret) {
            handle_error_string("Error sending last value from %d to %d\n",
                    world_rank, world_rank + 1);
            goto exit;
        }
    }
    if (world_rank > 0) {
        ret = mpi_tls_wait(&prev_last_value_request, MPI_TLS_STATUS_IGNORE);
        if (ret) {
            handle_error_string(
                    "Error waiting on recieve for previous last value from %d into %d\n",
                    world_rank - 1, world_rank);
            goto exit;
        }
    }
    last_value = prev_last_value;

    size_t cur_count;
    if (world_rank == 0) {
        /* Count starts at 0. */
        cur_count = 0;
    } else {
        /* Receive current count from previous rank. */
        ret =
            mpi_tls_recv_bytes(&cur_count, sizeof(cur_count), world_rank - 1, 0,
                MPI_TLS_STATUS_IGNORE);
        if (ret) {
            handle_error_string("Error receiving current count from %d into %d\n",
                    world_rank - 1, world_rank);
            goto exit;
        }
    }

    /* Linear scan to populate the VALUE field of requests with the VALUE field
     * of the closest data immediately above the request. To achieve this, we
     * always set the VALUE field (no-op for values) and conditionally set the
     * HAS_VALUE boolean whether this is actually the found value for a request.
     * Then, we update LAST_VALUE conditionally.
     *
     * Additionally, this linear scan will populate the MARKED_PREFIX_SUM values
     * array in order to perform ORCompact in the next step. */
    for (size_t i = 0; i < local_length; i++) {
        /* Populate VALUE and oblivious populate HAS_VALUE. */
        arr[i].value = last_value.value;
        arr[i].has_value =
            last_value.has_value & ((last_value.key | 1) == arr[i].key);
        bool cond = (arr[i].key & 1) == 0;
        o_set64(&last_value.key, arr[i].key, cond);
        o_set64(&last_value.value, arr[i].value, cond);
        o_setbool(&last_value.has_value, true, cond);

        /* Obliviously increment count. */
        arr[i].compact_marked_prefix_sum = cur_count;
        cur_count += !(arr[i].key & 1);
    }

    /* Send current count to next rank if we are not the last rank. */
    if (world_rank < world_size - 1) {
        ret =
            mpi_tls_send_bytes(&cur_count, sizeof(cur_count), world_rank + 1,
                    0);
        if (ret) {
            handle_error_string("Error sending current count from %d to %d\n",
                    world_rank, world_rank + 1);
            goto exit;
        }
    }

    /* Obliviously compact requests to the beginning. */
    struct compact_args compact_args = {
        .arr = arr,
        .start = 0,
        .length = length,
        .offset = 0,
        .num_threads = num_threads,
        .ret = 0,
    };
    compact(&compact_args);
    if (compact_args.ret) {
        ret = compact_args.ret;
        handle_error_string("Error in oblivious compaction");
        goto exit;
    }

exit:
    return ret;
}
