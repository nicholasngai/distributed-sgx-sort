#include "enclave/orshuffle.h"

#define LIBOBLIVIOUS_CMOV

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <threads.h>
#include <time.h>
#include <liboblivious/primitives.h>
#include "common/defs.h"
#include "common/error.h"
#include "common/util.h"
#include "enclave/crypto.h"
#include "enclave/mpi_tls.h"
#include "enclave/nonoblivious.h"
#include "enclave/parallel_enc.h"
#include "enclave/threading.h"

#define SWAP_CHUNK_SIZE 4096
#define MARK_COINS 2048

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
                elems_to_swap * sizeof(*buffer), remote_rank, our_local_idx,
                &request);
        if (ret) {
            handle_error_string("Error receiving elem bytes");
            goto exit;
        }

        /* Send local elems to the remote. */
        ret =
            mpi_tls_send_bytes(arr + our_local_idx - local_start,
                    elems_to_swap * sizeof(*arr), remote_rank, our_remote_idx);
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
    bool *marked;
    size_t *marked_prefix_sums;
    size_t start;
    size_t length;
    size_t offset;
    size_t num_threads;
    int ret;
};
static void compact(void *args_) {
    struct compact_args *args = args_;
    elem_t *arr = args->arr;
    bool *marked = args->marked;
    size_t *marked_prefix_sums = args->marked_prefix_sums;
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
        bool cond = (!marked[0] & marked[1]) != (bool) offset;
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
    int tag = OCOMPACT_MARKED_COUNT_MPI_TAG + (int) (start + length / 2);
    size_t left_marked_count;
    size_t mid_prefix_sum;
    if (world_rank == mid_rank) {
        /* Send the middle prefix sum to the master rank, since we have the
         * middle element. */
        if (world_rank == master_rank) {
            /* We are also the master, so set the local variable. */
            mid_prefix_sum = marked_prefix_sums[mid_idx - start];
        } else {
            /* Send it to the master. */
            ret =
                mpi_tls_send_bytes(&marked_prefix_sums[mid_idx - start],
                        sizeof(*marked_prefix_sums), master_rank, tag);
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
        left_marked_count = mid_prefix_sum - marked_prefix_sums[0] + marked[0];

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
        .marked = marked,
        .marked_prefix_sums = marked_prefix_sums,
        .start = start,
        .length = length / 2,
        .offset = offset % (length / 2),
    };
    struct compact_args right_args = {
        .arr = arr,
        .marked = marked + length / 2,
        .marked_prefix_sums = marked_prefix_sums + length / 2,
        .start = start + length / 2,
        .length = length / 2,
        .offset = (offset + left_marked_count) % (length / 2),
    };
    if (start + length / 2 >= local_start + local_length) {
        /* Right is remote; do just the left. */
        left_args.marked = marked,
        left_args.marked_prefix_sums = marked_prefix_sums,
        left_args.num_threads = num_threads;
        compact(&left_args);
        if (left_args.ret) {
            ret = left_args.ret;
            goto exit;
        }
    } else if (start + length / 2 <= local_start) {
        /* Left is remote; do just the right. */
        right_args.marked = marked,
        right_args.marked_prefix_sums = marked_prefix_sums,
        right_args.num_threads = num_threads;
        compact(&right_args);
        if (right_args.ret) {
            ret = right_args.ret;
            goto exit;
        }
    } else if (num_threads > 1) {
        /* Do both in a threaded manner. */
        left_args.marked = marked,
        left_args.marked_prefix_sums = marked_prefix_sums,
        left_args.num_threads = num_threads / 2;
        right_args.marked = marked + length / 2,
        right_args.marked_prefix_sums = marked_prefix_sums + length / 2,
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
        left_args.marked = marked,
        left_args.marked_prefix_sums = marked_prefix_sums,
        left_args.num_threads = 1;
        right_args.marked = marked + length / 2,
        right_args.marked_prefix_sums = marked_prefix_sums + length / 2,
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

struct shuffle_args {
    elem_t *arr;
    bool *marked;
    size_t *marked_prefix_sums;
    size_t length;
    size_t partitions;
    size_t num_threads;
    int ret;
};
static void shuffle(void *args_) {
    struct shuffle_args *args = args_;
    elem_t *arr = args->arr;
    bool *marked = args->marked;
    size_t *marked_prefix_sums = args->marked_prefix_sums;
    size_t length = args->length;
    size_t partitions = args->partitions;
    size_t num_threads = args->num_threads;
    int ret;

    if (partitions <= 1 || length < 2) {
        ret = 0;
        goto exit;
    }

    if (length == 2) {
        bool cond;
        ret = rand_bit(&cond);
        if (ret) {
            goto exit;
        }
        o_memswap(&arr[0], &arr[1], sizeof(*arr), cond);
        goto exit;
    }

    /* Mark exactly LENGTH / 2 elems in our partition. */
    size_t num_to_mark = length / 2;
    size_t total_left = length;
    size_t marked_so_far = 0;
    for (size_t i = 0; i < length; i += MARK_COINS) {
        uint32_t coins[MARK_COINS];
        size_t elems_to_mark = MIN(length - i, MARK_COINS);
        ret = rand_read(coins, elems_to_mark * sizeof(*coins));
        if (ret) {
            handle_error_string("Error getting random coins for marking");
            goto exit;
        }

        for (size_t j = 0; j < MIN(length - i, MARK_COINS); j++) {
            bool cur_marked =
                ((uint64_t) coins[j] * total_left) >> 32
                    >= num_to_mark - marked_so_far;
            marked_so_far += cur_marked;
            marked[i + j] = cur_marked;
            marked_prefix_sums[i + j] = marked_so_far;
            total_left--;
        }
    }

    /* Obliviously compact. */
    struct compact_args compact_args = {
        .arr = arr,
        .marked = marked,
        .marked_prefix_sums = marked_prefix_sums,
        .length = length,
        .offset = 0,
        .num_threads = num_threads,
    };
    compact(&compact_args);
    if (compact_args.ret) {
        ret = compact_args.ret;
        goto exit;
    }

    /* Recursively shuffle. */
    struct shuffle_args left_args = {
        .arr = arr,
        .length = length / 2,
        .partitions = partitions / 2,
    };
    struct shuffle_args right_args = {
        .arr = arr + length / 2,
        .length = length / 2,
        .partitions = partitions / 2,
    };
    if (num_threads > 1) {
        /* Do both in a threaded manner. */
        left_args.marked = marked,
        left_args.marked_prefix_sums = marked_prefix_sums,
        left_args.num_threads = num_threads / 2;
        right_args.marked = marked + length / 2,
        right_args.marked_prefix_sums = marked_prefix_sums + length / 2,
        right_args.num_threads = num_threads / 2;
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
        left_args.marked = marked,
        left_args.marked_prefix_sums = marked_prefix_sums,
        left_args.num_threads = 1;
        right_args.marked = marked,
        right_args.marked_prefix_sums = marked_prefix_sums,
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
    args->ret = ret;
}

/* Distribute and receive elements partitions ARR to partitions in OUT. There
 * should be WORLD_SIZE equally-sized partitions in ARR. */
struct distribute_partitions_args {
    elem_t *arr;
    elem_t *out;
    size_t length;
    volatile size_t *send_idxs;
    volatile size_t recv_idx;
    volatile int ret;
};
static void distribute_partitions(void *args_, size_t thread_idx) {
    struct distribute_partitions_args *args = args_;
    elem_t *arr = args->arr;
    elem_t *out = args->out;
    volatile size_t *send_idxs = args->send_idxs;
    volatile size_t *recv_idx = &args->recv_idx;
    size_t local_start = get_local_start(world_rank);
    size_t local_length = get_local_start(world_rank + 1) - local_start;
    int ret;

    mpi_tls_request_t requests[world_size];

    if (world_size == 1) {
        if (thread_idx == 0) {
            memcpy(out, arr, local_length * sizeof(*out));
        }
        ret = 0;
        goto exit;
    }

    //if (world_rank == 0) {
    //    printf("%d\n", getpid());
    //    volatile int loop = 1;
    //    while (loop) {}
    //}

    /* Copy our own partition to the output if any. */
    size_t recv_size = MIN(local_length / world_size, SWAP_CHUNK_SIZE);
    if (thread_idx == 0) {
        size_t elems_to_copy =
            local_length * (world_rank + 1) / world_size
                - local_length * world_rank / world_size;
        size_t copy_idx =
            __atomic_fetch_add(recv_idx, elems_to_copy, __ATOMIC_RELAXED);
        memcpy(out + copy_idx, arr + send_idxs[world_rank],
                elems_to_copy * sizeof(*out));
    }

    /* Wait so that thread 0 has defeintely updated RECV_IDX. */
    thread_wait_for_all();

    /* Post a receive request for the current partition. */
    size_t num_requests = 0;
    size_t our_recv_idx =
        __atomic_fetch_add(recv_idx, recv_size, __ATOMIC_RELAXED);
    if (our_recv_idx < local_length) {
        ret =
            mpi_tls_irecv_bytes(out + our_recv_idx,
                    recv_size * sizeof(*out), MPI_TLS_ANY_SOURCE,
                    BUCKET_DISTRIBUTE_MPI_TAG, &requests[world_rank]);
        if (ret) {
            handle_error_string("Error posting receive into %d", world_rank);
            goto exit;
        }
        num_requests++;
    } else {
        requests[world_rank].type = MPI_TLS_NULL;
    }

    /* Send and receive partitions. */
    for (int i = 0; i < world_size; i++) {
        if (i == world_rank) {
            continue;
        }

        /* Post a send request to the remote rank containing the first
         * partitions. */
        size_t our_send_idx =
            __atomic_fetch_add(&send_idxs[i], recv_size, __ATOMIC_RELAXED);
        if (our_send_idx < (i + 1) * local_length / world_size) {
            ret =
                mpi_tls_isend_bytes(arr + our_send_idx,
                        recv_size * sizeof(*arr), i, BUCKET_DISTRIBUTE_MPI_TAG,
                        &requests[i]);
            if (ret) {
                handle_error_string(
                        "Error sending chunk starting with %lu to %d from %d",
                        our_send_idx + local_start, i, world_rank);
                goto exit;
            }
            num_requests++;
        } else {
            requests[i].type = MPI_TLS_NULL;
        }
    }

    while (num_requests) {
        size_t index;
        mpi_tls_status_t status;
        ret = mpi_tls_waitany(world_size, requests, &index, &status);
        if (ret) {
            handle_error_string("Error waiting on requests");
            goto exit;
        }

        if (index == (size_t) world_rank) {
            /* This was the receive request. */

            size_t our_recv_idx =
                __atomic_fetch_add(recv_idx, recv_size, __ATOMIC_RELAXED);
            if (our_recv_idx < local_length) {
                /* Post receive for the next partitions. */
                ret =
                    mpi_tls_irecv_bytes(out + our_recv_idx,
                            recv_size * sizeof(*out), MPI_TLS_ANY_SOURCE,
                            BUCKET_DISTRIBUTE_MPI_TAG, &requests[index]);
                if (ret) {
                    handle_error_string("Error posting receive into %d",
                            (int) index);
                    goto exit;
                }
            } else {
                /* Nullify the receiving request. */
                requests[index].type = MPI_TLS_NULL;
                num_requests--;
            }
        } else {
            /* This was a send request. */

            size_t our_send_idx =
                __atomic_fetch_add(&send_idxs[index], recv_size,
                        __ATOMIC_RELAXED);
            if (our_send_idx < (index + 1) * local_length / world_size) {
                ret =
                    mpi_tls_isend_bytes(arr + our_send_idx,
                            recv_size * sizeof(*arr), index,
                            BUCKET_DISTRIBUTE_MPI_TAG, &requests[index]);
                if (ret) {
                    handle_error_string(
                            "Error sending chunk starting with %lu to %d from %d",
                            our_send_idx + local_start, world_rank,
                            (int) index);
                    goto exit;
                }
            } else {
                /* Nullify the sending request. */
                requests[index].type = MPI_TLS_NULL;
                num_requests--;
            }
        }
    }

    ret = 0;

exit:
    if (ret) {
        int expected = 0;
        __atomic_compare_exchange_n(&args->ret, &expected, ret, false,
                __ATOMIC_RELEASE, __ATOMIC_RELAXED);
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
    elem_t *arr = args->arr;
    size_t length = args->length;
    size_t start_idx = args->start_idx;
    size_t num_threads = args->num_threads;
    int ret;

    size_t start = i * length / num_threads;
    size_t end = (i + 1) * length / num_threads;
    for (size_t j = start; j < end; j++) {
        ret = rand_read(&arr[j].orp_id, sizeof(arr[j].orp_id));
        if (ret) {
            handle_error_string("Error assigning random ID to elem %lu",
                    i + start_idx);
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
    elem_t *buf = arr + MAX(local_length * 2, 512);
    int ret;

    struct timespec time_start;
    if (clock_gettime(CLOCK_REALTIME, &time_start)) {
        handle_error_string("Error getting time");
        ret = errno;
        goto exit;
    }

    total_length = length;

    bool *marked = malloc(length * sizeof(*marked));
    if (!marked) {
        perror("malloc marked arr");
        ret = errno;
        goto exit;
    }
    size_t *marked_prefix_sums = malloc(length * sizeof(*marked_prefix_sums));
    if (!marked_prefix_sums) {
        perror("malloc marked prefix sums arr");
        ret = errno;
        goto exit_free_marked;
    }

    /* Construct WORLD_SIZE random partitions. */
    {
        struct shuffle_args args = {
            .arr = arr,
            .marked = marked,
            .marked_prefix_sums = marked_prefix_sums,
            .length = local_length,
            .partitions = world_size,
            .num_threads = num_threads,
        };
        shuffle(&args);
        if (args.ret) {
            handle_error_string("Error in recursive shuffle");
            ret = args.ret;
            goto exit_free_marked_prefix_sums;
        }
    }

    /* Distribute partitions. */
    {
        size_t send_idxs[world_size];
        for (int i = 0; i < world_size; i++) {
            send_idxs[i] = i * local_length / world_size;
        }
        struct distribute_partitions_args args = {
            .arr = arr,
            .out = buf,
            .length = length,
            .send_idxs = send_idxs,
            .recv_idx = 0,
            .ret = 0,
        };
        struct thread_work work = {
            .type = THREAD_WORK_ITER,
            .iter = {
                .func = distribute_partitions,
                .arg = &args,
                .count = num_threads,
            },
        };
        thread_work_push(&work);
        thread_work_until_empty();
        thread_wait(&work);
        if (args.ret) {
            handle_error_string("Error in partition distribution");
            ret = args.ret;
            goto exit_free_marked_prefix_sums;
        }
    }

    /* Shuffle elements fully (PARTITIONS = LOCAL_LENGTH). */
    {
        struct shuffle_args args = {
            .arr = buf,
            .marked = marked,
            .marked_prefix_sums = marked_prefix_sums,
            .length = local_length,
            .partitions = local_length,
            .num_threads = num_threads,
        };
        shuffle(&args);
        if (args.ret) {
            handle_error_string("Error in recursive shuffle");
            ret = args.ret;
            goto exit_free_marked_prefix_sums;
        }
    }

    free(marked);
    marked = NULL;
    free(marked_prefix_sums);
    marked_prefix_sums = NULL;

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
        goto exit_free_marked_prefix_sums;
    }

    struct timespec time_shuffle;
    if (clock_gettime(CLOCK_REALTIME, &time_shuffle)) {
        handle_error_string("Error getting time");
        ret = errno;
        goto exit_free_marked_prefix_sums;
    }

    /* Nonoblivious sort. This requires MAX(LOCAL_LENGTH * 2, 512) elements for
     * both the array and buffer, so use the second half of the array given to
     * us (which should be of length MAX(LOCAL_LENGTH * 2, 512) * 2). */
    ret = nonoblivious_sort(arr, buf, length, local_length, num_threads);
    if (ret) {
        goto exit_free_marked_prefix_sums;
    }

    /* Copy the output to the final output. */
    memcpy(arr, buf, local_length * sizeof(*arr));

    if (world_rank == 0) {
        printf("shuffle          : %f\n",
                get_time_difference(&time_start, &time_shuffle));
    }

exit_free_marked_prefix_sums:
    free(marked_prefix_sums);
exit_free_marked:
    free(marked);
exit:
    return ret;
}
