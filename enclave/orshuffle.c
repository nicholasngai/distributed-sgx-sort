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
    elem_t *arr = args->arr;
    size_t length = args->length;
    size_t a = args->a;
    size_t b = args->b;
    size_t count = args->count;
    size_t offset = args->offset;
    size_t left_marked_count = args->left_marked_count;
    size_t num_threads = args->num_threads;

    bool s =
        (offset % (length / 2) + left_marked_count >= length / 2)
            != (offset >= length / 2);

    size_t start = i * count / num_threads;
    size_t end = (i + 1) * count / num_threads;
    for (size_t j = start; j < end; j++) {
        bool cond = s != (a + j >= (offset + left_marked_count) % (length / 2));
        o_memswap(&arr[a + j], &arr[b + j], sizeof(*arr), cond);
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
    int ret;

    if (length < 2) {
        ret = 0;
        goto exit;
    }

    if (length == 2) {
        bool cond =
            (!arr[start].marked & arr[start + 1].marked) != (bool) offset;
        o_memswap(&arr[start], &arr[start + 1], sizeof(*arr), cond);
        ret = 0;
        goto exit;
    }

    /* Get number of elements in the left half that are marked. The elements
     * contains the prefix sums, so taking the final prefix sum minus the first
     * prefix sum plus 1 if first element is marked should be sufficient. */
    size_t mid_idx = start + length / 2 - 1;
    size_t left_marked_count;
    size_t mid_prefix_sum = arr[mid_idx].marked_prefix_sum;

    /* Compute the number of marked elements. */
    left_marked_count =
        mid_prefix_sum - arr[start].marked_prefix_sum + arr[start].marked;

    /* Recursively compact. */
    struct compact_args left_args = {
        .arr = arr,
        .start = start,
        .length = length / 2,
        .offset = offset % (length / 2),
        .ret = 0,
    };
    struct compact_args right_args = {
        .arr = arr,
        .start = start + length / 2,
        .length = length / 2,
        .offset = (offset + left_marked_count) % (length / 2),
        .ret = 0,
    };
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
    elem_t *arr = args->arr;
    size_t start = args->start;
    size_t length = args->length;
    size_t num_threads = args->num_threads;
    int ret;

    if (length < 2) {
        ret = 0;
        goto exit;
    }

    if (length == 2) {
        bool cond;
        ret = rand_bit(&cond);
        if (ret) {
            goto exit;
        }
        o_memswap(&arr[start], &arr[start + 1], sizeof(*arr), cond);
        goto exit;
    }

    /* Get the number of elements to mark in this enclave. */
    struct mark_count_payload {
        size_t num_to_mark;
        size_t marked_in_prev;
    };
    size_t num_to_mark = length / 2;;
    size_t marked_in_prev = 0;

    /* Mark exactly NUM_TO_MARK elems in our partition. */
    size_t total_left = length;
    size_t marked_so_far = 0;
    for (size_t i = start; i < start + length; i++) {
        bool marked;
        ret = should_mark(num_to_mark - marked_so_far, total_left, &marked);
        if (ret) {
            handle_error_string("Error getting random marked");
            goto exit;
        }
        marked_so_far += marked;
        total_left--;

        arr[i].marked = marked;
        arr[i].marked_prefix_sum = marked_in_prev + marked_so_far;
    }

    /* Obliviously compact. */
    struct compact_args compact_args = {
        .arr = arr,
        .start = start,
        .length = length,
        .offset = 0,
        .num_threads = num_threads,
        .ret = 0,
    };
    compact(&compact_args);
    if (compact_args.ret) {
        ret = compact_args.ret;
        goto exit;
    }

    /* Recursively shuffle. */
    struct shuffle_args left_args = {
        .arr = arr,
        .start = start,
        .length = length / 2,
        .ret = 0,
    };
    struct shuffle_args right_args = {
        .arr = arr,
        .start = start + length / 2,
        .length = length / 2,
        .ret = 0,
    };
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
    int ret;

    struct timespec time_start;
    if (clock_gettime(CLOCK_REALTIME, &time_start)) {
        handle_error_string("Error getting time");
        ret = errno;
        goto exit;
    }

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
        .length = 0,
        .start_idx = length,
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

    struct timespec time_shuffle;
    if (clock_gettime(CLOCK_REALTIME, &time_shuffle)) {
        handle_error_string("Error getting time");
        ret = errno;
        goto exit;
    }

    /* Nonoblivious sort. This requires MAX(LOCAL_LENGTH * 2, 512) elements for
     * both the array and buffer, so use the second half of the array given to
     * us (which should be of length MAX(LOCAL_LENGTH * 2, 512) * 2). */
    elem_t *buf = arr + MAX(length * 2, 512);
    ret = nonoblivious_sort(arr, buf, length, length, num_threads);
    if (ret) {
        goto exit;
    }

    /* Copy the output to the final output. */
    memcpy(arr, buf, length * sizeof(*arr));

    if (world_rank == 0) {
        printf("shuffle          : %f\n",
                get_time_difference(&time_start, &time_shuffle));
    }

exit:
    return ret;
}
