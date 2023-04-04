#include "enclave/orshuffle.h"

#define LIBOBLIVIOUS_CMOV

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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
#define MARK_COINS 2048

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

/* Swapping. */

static void swap_range(elem_t *arr, size_t length, size_t offset, size_t
        left_marked_count) {
    bool s =
        (offset % (length / 2) + left_marked_count >= length / 2)
            != (offset >= length / 2);

    for (size_t i = 0; i < length / 2; i++) {
        bool cond = s != (i >= (offset + left_marked_count) % (length / 2));
        o_memswap(&arr[i], &arr[i + length / 2], sizeof(*arr), cond);
    }
}

static void compact(elem_t *arr, bool *marked, size_t *marked_prefix_sums,
        size_t length, size_t offset) {
    if (length < 2) {
        return;
    }

    if (length == 2) {
        bool cond = (!marked[0] & marked[1]) != (bool) offset;
        o_memswap(&arr[0], &arr[1], sizeof(*arr), cond);
        return;
    }

    /* Compute the number of marked elements. */
    size_t left_marked_count =
        marked_prefix_sums[length / 2] - marked_prefix_sums[0];

    /* Recursively compact. */
    compact(arr, marked, marked_prefix_sums, length / 2, offset % (length / 2));
    compact(arr + length / 2, marked + length / 2,
            marked_prefix_sums + length / 2, length / 2,
            (offset + left_marked_count) % (length / 2));

    /* Swap. */
    swap_range(arr, length, offset, left_marked_count);
}

static void shuffle(elem_t *arr, bool *marked, size_t *marked_prefix_sums,
        size_t length) {
    int ret;

    if (length < 2) {
        return;
    }

    if (length == 2) {
        bool cond;
        ret = rand_bit(&cond);
        if (ret) {
            handle_error_string("Error getting random bit");
            abort();
        }
        o_memswap(&arr[0], &arr[1], sizeof(*arr), cond);
        return;
    }

    /* Get the number of elements to mark in this enclave. */
    size_t num_to_mark = length / 2;;

    /* Mark exactly NUM_TO_MARK elems in our partition. */
    size_t total_left = length;
    size_t marked_so_far = 0;
    for (size_t i = 0; i < length; i += MARK_COINS) {
        uint32_t coins[MARK_COINS];
        size_t elems_to_mark = MIN(length - i, MARK_COINS);
        ret = rand_read(coins, elems_to_mark * sizeof(*coins));
        if (ret) {
            handle_error_string("Error getting random coins for marking");
            abort();
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
    compact(arr, marked, marked_prefix_sums, length, 0);

    /* Recursively shuffle. */
    shuffle(arr, marked, marked_prefix_sums, length / 2);
    shuffle(arr + length / 2, marked + length / 2,
            marked_prefix_sums + length / 2, length / 2);

    ret = 0;
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

    shuffle(arr, marked, marked_prefix_sums, length);

    free(marked);
    marked = NULL;
    free(marked_prefix_sums);
    marked_prefix_sums = NULL;

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
    elem_t *buf = arr + MAX(length * 2, 512);
    ret = nonoblivious_sort(arr, buf, length, length, num_threads);
    if (ret) {
        goto exit_free_marked_prefix_sums;
    }

    /* Copy the output to the final output. */
    memcpy(arr, buf, length * sizeof(*arr));

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
