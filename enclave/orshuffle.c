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

static int swap_local_range(elem_t *arr, size_t length, size_t offset,
        size_t left_marked_count) {
    int ret;

    bool s =
        (offset % (length / 2) + left_marked_count >= length / 2)
            != (offset >= length / 2);

    for (size_t i = 0; i < length / 2; i++) {
        bool cond = s != (i >= (offset + left_marked_count) % (length / 2));
        o_memswap(&arr[i], &arr[i + length / 2], sizeof(*arr), cond);
    }

    ret = 0;

    return ret;
}

static int swap_range(elem_t *arr, size_t length, size_t offset,
        size_t left_marked_count) {
    // TODO Assumption: Only either a subset of range A is local, or a subset of
    // range B is local. For local-remote swaps, the subset of the remote range
    // correspondingw with the local range is entirely contained within a single
    // elem. This requires that both the number of elements and the number of
    // elems is a power of 2.

    swap_local_range(arr, length, offset, left_marked_count);
    return 0;
}

static int compact(elem_t *arr, size_t length, size_t offset) {
    int ret;

    if (length < 2) {
        ret = 0;
        goto exit;
    }

    if (length == 2) {
        bool cond = (!arr[0].marked & arr[1].marked) != (bool) offset;
        o_memswap(&arr[0], &arr[1], sizeof(*arr), cond);
        ret = 0;
        goto exit;
    }

    /* Get number of elements in the left half that are marked. The elements
     * contains the prefix sums, so taking the final prefix sum minus the first
     * prefix sum plus 1 if first element is marked should be sufficient. */
    size_t mid_idx = length / 2 - 1;
    size_t left_marked_count;
    size_t mid_prefix_sum = arr[mid_idx].marked_prefix_sum;

    /* Compute the number of marked elements. */
    left_marked_count =
        mid_prefix_sum - arr[0].marked_prefix_sum + arr[0].marked;

    /* Recursively compact. */
    ret = compact(arr, length / 2, offset % (length / 2));
    if (ret) {
        goto exit;
    }
    ret =
        compact(arr + length / 2, length / 2,
                (offset + left_marked_count) % (length / 2));
    if (ret) {
        goto exit;
    }

    /* Swap. */
    ret = swap_range(arr, length, offset, left_marked_count);
    if (ret) {
        handle_error_string("Error swapping range with length %lu", length / 2);
        goto exit;
    }

exit:
    return ret;
}

static int shuffle(elem_t *arr, size_t length) {
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
        o_memswap(&arr[0], &arr[1], sizeof(*arr), cond);
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
    for (size_t i = 0; i < length; i++) {
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
    ret = compact(arr, length, 0);
    if (ret) {
        goto exit;
    }

    /* Recursively shuffle. */
    ret = shuffle(arr, length / 2);
    if (ret) {
        goto exit;
    }
    ret = shuffle(arr + length / 2, length / 2);
    if (ret) {
        goto exit;
    }

    ret = 0;

exit:
    return ret;
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

    ret = shuffle(arr, length);
    if (ret) {
        handle_error_string("Error in recursive shuffle");
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
