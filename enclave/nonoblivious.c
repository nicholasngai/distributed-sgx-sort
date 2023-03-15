#include "enclave/nonoblivious.h"
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "common/defs.h"
#include "common/elem_t.h"
#include "common/error.h"
#include "common/ocalls.h"
#include "common/util.h"
#include "enclave/mpi_tls.h"
#include "enclave/parallel_enc.h"
#include "enclave/qsort.h"
#include "enclave/threading.h"
#include "enclave/util.h"

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
#include "enclave/parallel_t.h"
#endif

#define BUF_SIZE 1024
#define SAMPLE_PARTITION_BUF_SIZE 512

/* Compares elements by the tuple (key, ORP ID). The check for the ORP ID must
 * always be run (it must be oblivious whether the comparison result is based on
 * the key or on the ORP ID), since we leak info on duplicate keys otherwise. */
static int mergesort_comparator(const void *a_, const void *b_,
        void *aux UNUSED) {
    const elem_t *a = a_;
    const elem_t *b = b_;
    int comp_key = (a->key > b->key) - (a->key < b->key);
    int comp_orp_id = (a->orp_id > b->orp_id) - (a->orp_id < b->orp_id);
    return (comp_key << 1) + comp_orp_id;
}

/* Sort ARR[RUN_IDX * LENGTH / NUM_THREADS] to ARR[(RUN_IDX + 1) * LENGTH / NUM_THREADS]. The results
 * will be stored in the same location as the inputs. */
struct mergesort_first_pass_args {
    elem_t *arr;
    size_t length;
    size_t num_threads;
};
static void mergesort_first_pass(void *args_, size_t run_idx) {
    struct mergesort_first_pass_args *args = args_;

    size_t run_start = run_idx * args->length / args->num_threads;
    size_t run_end = (run_idx + 1) * args->length / args->num_threads;

    /* Sort using libc quicksort. */
    qsort_glibc(args->arr + run_start, run_end - run_start, sizeof(*args->arr),
            mergesort_comparator, NULL);
}

/* Non-oblivious mergesort. */
static int mergesort(elem_t *arr, elem_t *out, size_t length,
        size_t num_threads) {
    int ret;

    /* Start by sort runs of LENGTH / NUM_THREADS. */
    struct mergesort_first_pass_args args = {
        .arr = arr,
        .length = length,
        .num_threads = num_threads,
    };
    struct thread_work work = {
        .type = THREAD_WORK_ITER,
        .iter = {
            .func = mergesort_first_pass,
            .arg = &args,
            .count = num_threads,
        },
    };
    thread_work_push(&work);
    thread_work_until_empty();
    thread_wait(&work);

    if (num_threads == 1) {
        memcpy(out, arr, length * sizeof(*out));
        return 0;
    }

    /* Compute initial mergesort indices. */
    size_t merge_indices[num_threads];
    for (size_t i = 0; i < num_threads; i++) {
        merge_indices[i] = i * length / num_threads;
    }

    /* Merge runs from each thread into output. */
    for (size_t i = 0; i < length; i++) {
        /* Scan for lowest elem. */
        // TODO Use a heap?
        size_t lowest_run = SIZE_MAX;
        for (size_t j = 0; j < num_threads; j++) {
            if (merge_indices[j] >= (j + 1) * length / num_threads) {
                continue;
            }
            if (lowest_run == SIZE_MAX
                    || mergesort_comparator(&arr[merge_indices[j]],
                        &arr[merge_indices[lowest_run]], NULL) < 0) {
                lowest_run = j;
            }
        }

        /* Copy lowest elem to output. */
        memcpy(&out[i], &arr[merge_indices[lowest_run]], sizeof(*out));
        merge_indices[lowest_run]++;
    }

    ret = 0;

    return ret;
}

struct sample {
    uint64_t key;
    uint64_t orp_id;
};

static int elem_sample_comparator(const elem_t *a, const struct sample *b) {
    int comp_key = (a->key > b->key) - (a->key < b->key);
    int comp_orp_id = (a->orp_id > b->orp_id) - (a->orp_id < b->orp_id);
    return (comp_key << 1) + comp_orp_id;
}

static int quickselect_helper(elem_t *arr, size_t length,
        const size_t *targets, struct sample *samples, size_t num_targets,
        size_t left, size_t right) {
    int ret;

    if (!num_targets) {
        ret = 0;
        goto exit;
    }

    /* If we've run out of elements for quickselect, we just have to take the
     * leftmost item if possible, or 0 otherwise. */
    if (left == right) {
        if (left > length) {
            for (size_t i = 0; i < num_targets; i++) {
                samples[i].key = 0;
                samples[i].orp_id = 0;
            }
        } else {
            for (size_t i = 0; i < num_targets; i++) {
                samples[i].key = arr[left].key;
                samples[i].orp_id = arr[left].orp_id;
            }
        }
        ret = 0;
        goto exit;
    }

    /* Use first elem as pivot. This is a random selection since this
     * quickselect or quickpartition should happen after immediatley after
     * ORP. */
    struct sample pivot = {
        .key = arr[left].key,
        .orp_id = arr[left].key,
    };

    /* Partition data based on pivot. */
    // TODO It's possible to do this in-place.
    size_t partition_left = left + 1;
    size_t partition_right = right;
    enum {
        PARTITION_SCAN_LEFT,
        PARTITION_SCAN_RIGHT,
    } partition_state = PARTITION_SCAN_LEFT;
    while (partition_left < partition_right) {
        switch (partition_state) {
        case PARTITION_SCAN_LEFT:
            /* Scan left for elements greater than the pivot. If found, start
             * scanning right. */
            if (elem_sample_comparator(&arr[partition_left], &pivot) > 0) {
                partition_state = PARTITION_SCAN_RIGHT;
            } else {
                partition_left++;
            }

            break;

        case PARTITION_SCAN_RIGHT:
            /* Scan right for elements less than the pivot. */

            /* If found, swap and start scanning left. */
            if (elem_sample_comparator(&arr[partition_right - 1], &pivot) < 0) {
                elem_t temp;
                memcpy(&temp, &arr[partition_right - 1], sizeof(temp));
                memcpy(&arr[partition_right - 1], &arr[partition_left],
                        sizeof(*arr));
                memcpy(&arr[partition_left], &temp, sizeof(*arr));

                partition_state = PARTITION_SCAN_LEFT;
                partition_left++;
                partition_right--;
            } else {
                partition_right--;
            }

            break;
        }
    }

    /* Finish partitioning by swapping the pivot into the center. */
    elem_t temp;
    memcpy(&temp, &arr[partition_right - 1], sizeof(temp));
    memcpy(&arr[partition_right - 1], &arr[left], sizeof(*arr));
    memcpy(&arr[left], &temp, sizeof(*arr));
    partition_right--;

    /* Check which directions we need to iterate in, based on the current pivot
     * index. If there are smaller targets, then iterate on the left half. If
     * there are larger targets, then iterate on the right half. If there is a
     * matching target, then set the sample in the output. */
    size_t *geq_target =
        bsearch_ge(&partition_right, targets, num_targets, sizeof(*targets),
                comp_ul);
    size_t geq_target_idx = (size_t) (geq_target - targets);
    bool found_target =
        geq_target_idx < num_targets && *geq_target == partition_right;
    size_t gt_target_idx = geq_target_idx + found_target;

    /* If we found a target, set the sample. */
    if (found_target) {
        size_t i = geq_target - targets;
        samples[i] = pivot;
    }

    /* Set up next iteration(s) if we have targets on either side. If the next
     * split is greater than the target, keep the current split and advance the
     * head of the slice. Else, advance the split and retract the tail of the
     * slice. */
    /* Targets less than pivot. */
    ret =
        quickselect_helper(arr, length, targets, samples, geq_target_idx,
                left, partition_right);
    if (ret) {
        goto exit;
    }
    /* Targets greater than pivot. */
    ret =
        quickselect_helper(arr, length, targets + gt_target_idx,
                samples + gt_target_idx, num_targets - gt_target_idx,
                partition_left, right);
    if (ret) {
        goto exit;
    }

exit:
    return ret;
}

/* Performs a quickselect algorithm to find NUM_TARGETS target element indices
 * (i.e. the i'th smallest element) in TARGETS contained in ARR, which contains
 * LENGTH elements. Resulting samples are stored in SAMPLES. TARGETS must be a
 * sorted array. */
static int quickselect(elem_t *arr, size_t length, size_t *targets,
        struct sample *samples, size_t num_targets) {
    int ret =
        quickselect_helper(arr, length, targets, samples, num_targets, 0,
                length);
    if (ret) {
        handle_error_string("Error in distributed quickselect");
        goto exit;
    }

exit:
    return ret;
}

static int quickpartition_helper(elem_t *arr, size_t length,
        const struct sample *pivots, size_t *pivot_idxs, size_t num_pivots,
        size_t left, size_t right) {
    int ret;

    if (!num_pivots) {
        ret = 0;
        goto exit;
    }

    /* Use the middle sample as pivot. */
    const struct sample *pivot = &pivots[num_pivots / 2];

    /* Partition data based on pivot. */
    // TODO It's possible to do this in-place.
    size_t partition_left = left;
    size_t partition_right = right;
    enum {
        PARTITION_SCAN_LEFT,
        PARTITION_SCAN_RIGHT,
    } partition_state = PARTITION_SCAN_LEFT;
    while (partition_left < partition_right) {
        switch (partition_state) {
        case PARTITION_SCAN_LEFT:
            /* Scan left for elements greater than the pivot. If found, start
             * scanning right. */
            if (elem_sample_comparator(&arr[partition_left], pivot) > 0) {
                partition_state = PARTITION_SCAN_RIGHT;
            } else {
                partition_left++;
            }

            break;

        case PARTITION_SCAN_RIGHT:
            /* Scan right for elements less than the pivot. */

            /* If found, swap and start scanning left. */
            if (elem_sample_comparator(&arr[partition_right - 1], pivot) < 0) {
                elem_t temp;
                memcpy(&temp, &arr[partition_right - 1], sizeof(temp));
                memcpy(&arr[partition_right - 1], &arr[partition_left],
                        sizeof(*arr));
                memcpy(&arr[partition_left], &temp, sizeof(*arr));

                partition_state = PARTITION_SCAN_LEFT;
                partition_left++;
                partition_right--;
            } else {
                partition_right--;
            }

            break;
        }
    }

    /* Set the index of the pivot. */
    pivot_idxs[num_pivots / 2] = partition_right;

    /* Recurse. */
    /* Targets less than pivot. */
    ret =
        quickpartition_helper(arr, length, pivots, pivot_idxs, num_pivots / 2,
                left, partition_right);
    if (ret) {
        goto exit;
    }
    /* Targets greater than pivot. */
    ret =
        quickpartition_helper(arr, length, pivots + num_pivots / 2 + 1,
                pivot_idxs + num_pivots / 2 + 1,
                num_pivots - (num_pivots / 2 + 1), partition_left, right);
    if (ret) {
        goto exit;
    }

exit:
    return ret;
}

/* Use a variation of the quickselect algorithm to partition elements according
 * to NUM_PIVOTS pivots in PIVOTS contained in ARR, which contains LENGTH
 * elements. Resulting indices are PIVOT_IDXS. PIVOTS must be a sorted array. */
static int quickpartition(elem_t *arr, size_t length,
        const struct sample *pivots, size_t *pivot_idxs, size_t num_pivots) {
    int ret =
        quickpartition_helper(arr, length, pivots, pivot_idxs, num_pivots, 0,
                length);
    if (ret) {
        handle_error_string("Error in distributed quickselect");
        goto exit;
    }

exit:
    return ret;
}

/* Performs a non-oblivious samplesort across all enclaves. */
static int distributed_sample_partition(elem_t *restrict arr,
        elem_t *restrict out, size_t local_length,
        size_t *restrict out_length) {
    int ret;

    /* This should never be called if this is a single-enclave sort. */
    assert(world_size > 1);

    struct sample samples[world_size - 1];
    size_t sample_idxs[world_size];
    size_t send_idxs[world_size];
    mpi_tls_request_t requests[world_size];

    /* Partition the data. Rank 0 partitions/samples from its own array using
     * quickselect and sends the samples to everyone else. All other ranks then
     * partition using those samples with quickpartition. */
    if (world_rank == 0) {
        /* Construct targets to and pass to quickselect. */
        for (size_t i = 0; i < (size_t) world_size - 1; i++) {
            sample_idxs[i] = local_length * (i + 1) / world_size;
        }
        ret =
            quickselect(arr, local_length, sample_idxs, samples,
                    world_size - 1);
        if (ret) {
            handle_error_string("Error in quickselect");
            goto exit;
        }
        sample_idxs[world_size - 1] = local_length;

        /* Send the samples to everyone else. */
        for (int i = 0; i < world_size; i++) {
            if (i == world_rank) {
                continue;
            }
            ret =
                mpi_tls_send_bytes(samples, sizeof(samples),
                        i, QUICKSELECT_MPI_TAG);
            if (ret) {
                handle_error_string("Error sending samples from %d to %d", 0,
                        i);
                goto exit;
            }
        }
    } else {
        /* Receive the samples from rank 0. */
        ret =
            mpi_tls_recv_bytes(samples, sizeof(samples), 0, QUICKSELECT_MPI_TAG,
                    MPI_TLS_STATUS_IGNORE);
        if (ret) {
            handle_error_string("Error receiving samples from %d into %d", 0,
                    world_rank);
            goto exit;
        }

        /* Partition with quickpartition. */
        ret =
            quickpartition(arr, local_length, samples, sample_idxs,
                    world_size - 1);
        if (ret) {
            handle_error_string("Error in quickpartition");
            goto exit;
        }
        sample_idxs[world_size - 1] = local_length;
    }

    /* Sending starts at the previous sample index (or 0). */
    memcpy(send_idxs + 1, sample_idxs, (world_size - 1) * sizeof(*send_idxs));
    send_idxs[0] = 0;

    /* Send elements to their corresponding enclaves. The elements in the array
     * have already bee partitioned, so it's just a matter of sending them over
     * in chunks. */

    /* Copy own partition's elements to the output. */
    *out_length = sample_idxs[world_rank] - send_idxs[world_rank];
    memcpy(out, arr + send_idxs[world_rank], *out_length * sizeof(*out));
    send_idxs[world_rank] = sample_idxs[world_rank];

    /* Construct initial requests. REQUESTS is used for all send requests except
     * for REQUESTS[WORLD_RANK], which is our receive request. */
    for (int i = 0; i < world_size; i++) {
        if (i == world_rank) {
            ret =
                mpi_tls_irecv_bytes(out + *out_length,
                        SAMPLE_PARTITION_BUF_SIZE * sizeof(*out),
                        MPI_TLS_ANY_SOURCE, SAMPLE_PARTITION_MPI_TAG,
                        &requests[i]);
            if (ret) {
                handle_error_string("Error receiving partitioned data");
                goto exit;
            }
        } else {
            /* This could be 0, but we would need to send an empty message to
             * signal the end of our partition. */
            size_t elems_to_send =
                MIN(sample_idxs[i] - send_idxs[i], SAMPLE_PARTITION_BUF_SIZE);

            /* Asynchronously send to enclave. */
            ret =
                mpi_tls_isend_bytes(arr + send_idxs[i],
                        elems_to_send * sizeof(*arr), i,
                        SAMPLE_PARTITION_MPI_TAG, &requests[i]);
            if (ret) {
                handle_error_string("Error sending partitioned data");
                goto exit;
            }
            send_idxs[i] += elems_to_send;

            /* If this block sent less than SAMPLE_PARTITION_BUF_SIZE elements,
             * then the receiver will take this as the end of our stream, so
             * increment SEND_IDXS[i] by 1 to indicate we're truly done. */
            if (elems_to_send < SAMPLE_PARTITION_BUF_SIZE) {
                send_idxs[i]++;
            }
        }
    }

    /* Get completed requests in a loop. */
    size_t ranks_still_receiving = world_size - 1;
    size_t ranks_still_sending = world_size - 1;
    while (ranks_still_sending || ranks_still_receiving) {
        size_t index;
        mpi_tls_status_t status;
        ret = mpi_tls_waitany(world_size, requests, &index, &status);
        if (ret) {
            handle_error_string("Error waiting on partition requests");
            goto exit;
        }

        if (index == (size_t) world_rank) {
            /* Receive request completed. */
            size_t req_num_received = status.count / sizeof(*out);
            *out_length += req_num_received;

            /* If the number of elements received is less than
             * SAMPLE_PARTITION_BUF_SIZE, that rank has finished sending. */
            if (req_num_received < SAMPLE_PARTITION_BUF_SIZE) {
                ranks_still_receiving--;
            }

            if (ranks_still_receiving > 0) {
                ret =
                    mpi_tls_irecv_bytes(out + *out_length,
                            SAMPLE_PARTITION_BUF_SIZE * sizeof(*out),
                            MPI_TLS_ANY_SOURCE, SAMPLE_PARTITION_MPI_TAG,
                            &requests[index]);
                if (ret) {
                    handle_error_string("Error receiving partitioned data");
                    goto exit;
                }
            } else {
                requests[index].type = MPI_TLS_NULL;
            }
        } else {
            /* Send request completed. */

            /* If the send index is equal to the sample index, we need to send
             * an extra message of length 0 to indicate the end of our
             * partition. We indicate that we've already sent a sentinel message
             * of length < SAMPLE_PARTITION_BUF_SIZE message by setting
             * the send index GREATER than the sample index. */
            bool keep_rank = send_idxs[index] <= sample_idxs[index];
            if (keep_rank) {
                size_t elems_to_send =
                    MIN(sample_idxs[index] - send_idxs[index],
                            SAMPLE_PARTITION_BUF_SIZE);

                /* Asynchronously send to enclave. */
                ret =
                    mpi_tls_isend_bytes(arr + send_idxs[index],
                            elems_to_send * sizeof(*arr), index,
                            SAMPLE_PARTITION_MPI_TAG, &requests[index]);
                if (ret) {
                    handle_error_string("Error sending partitioned data");
                    goto exit;
                }
                send_idxs[index] += elems_to_send;

                /* If this block sent less than SAMPLE_PARTITION_BUF_SIZE
                 * elements, then the receiver will take this as the end of our
                 * stream, so increment SEND_IDXS[INDEX] by 1 to indicate
                 * we're truly done. */
                if (elems_to_send < SAMPLE_PARTITION_BUF_SIZE) {
                    send_idxs[index]++;
                }
            } else {
                requests[index].type = MPI_TLS_NULL;
                ranks_still_sending--;
            }
        }
    }

exit:
    return ret;
}

/* Balance the elements across enclaves after the unbalanced partitioning step
 * and sorting step. */
static int balance(elem_t *arr, elem_t *out, size_t total_length,
        size_t in_length) {
    mpi_tls_request_t requests[world_size * 2];
    mpi_tls_request_t *send_requests = requests;
    mpi_tls_request_t *recv_requests = requests + world_size;
    int ret;

    /* This should never be called if this is a single-enclave sort. */
    assert(world_size > 1);

    /* Get all cumulative lengths across ranks. RANK_LENGTHS[i] holds the number
     * of elements in ranks 0 to i - 1. */
    size_t rank_cum_idxs[world_size + 1];
    size_t send_idxs[world_size];
    size_t recv_idxs[world_size];
    size_t send_final_idxs[world_size];
    size_t recv_final_idxs[world_size];
    if (world_rank == 0) {
        /* Receive individual lengths from everyone. */
        rank_cum_idxs[0] = in_length;
        for (int i = 0; i < world_size - 1; i++) {
            size_t rank_length;
            mpi_tls_status_t status;
            ret =
                mpi_tls_recv_bytes(&rank_length, sizeof(rank_length),
                        MPI_TLS_ANY_SOURCE, BALANCE_MPI_TAG, &status);
            if (ret) {
                handle_error_string("Error receiving rank length into %d", 0);
                goto exit;
            }
            rank_cum_idxs[status.source] = rank_length;
        }

        /* Compute cumulative lengths. */
        size_t cur_length = 0;
        for (int i = 0; i < world_size; i++) {
            size_t prev_length = cur_length;
            cur_length += rank_cum_idxs[i];
            rank_cum_idxs[i] = prev_length;
        }
        rank_cum_idxs[world_size] = total_length;

        /* Send cumulative lengths to everyone. */
        for (int i = 0; i < world_size; i++) {
            if (i == world_rank) {
                continue;
            }
            ret =
                mpi_tls_send_bytes(rank_cum_idxs, sizeof(rank_cum_idxs), i,
                        BALANCE_MPI_TAG);
            if (ret) {
                handle_error_string(
                        "Error sending cumulative lengths from %d to %d", 0, i);
                goto exit;
            }
        }
    } else {
        /* Send length to rank 0. */
        ret =
            mpi_tls_send_bytes(&in_length, sizeof(in_length), 0,
                    BALANCE_MPI_TAG);
        if (ret) {
            handle_error_string("Error sending rank length from %d to %d", 0,
                    world_rank);
            goto exit;
        }

        /* Receive cumulative lengths from rank 0. */
        ret =
            mpi_tls_recv_bytes(rank_cum_idxs, sizeof(rank_cum_idxs), 0,
                    BALANCE_MPI_TAG, NULL);
        if (ret) {
            handle_error_string(
                    "Error receiving cumulative lengths from %d into %d", 0,
                    world_rank);
            goto exit;
        }
    }

    /* Compute at which indices we need to send the elements we currently have
     * to each rank and at which indices we need to receive elements from other
     * ranks. */
    size_t local_start = world_rank * total_length / world_size;
    size_t local_end = (world_rank + 1) * total_length / world_size;
    size_t local_length = local_end - local_start;
    for (int i = 0; i < world_size; i++) {
        size_t i_local_start = i * total_length / world_size;
        send_idxs[i] =
            MAX(
                    MIN(i_local_start, rank_cum_idxs[world_rank + 1]),
                    rank_cum_idxs[world_rank])
                - rank_cum_idxs[world_rank];
        recv_idxs[i] =
            MAX(MIN(rank_cum_idxs[i], local_end), local_start) - local_start;
    }
    assert(world_size > 1);
    memcpy(send_final_idxs, send_idxs + 1,
            (world_size - 1) * sizeof(*send_final_idxs));
    send_final_idxs[world_size - 1] = in_length;
    memcpy(recv_final_idxs, recv_idxs + 1,
            (world_size - 1) * sizeof(*recv_final_idxs));
    recv_final_idxs[world_size - 1] = local_length;

    /* Construct initial requests. */
    size_t num_requests = 0;
    for (int i = 0; i < world_size; i++) {
        /* Copy our input to our output for ourselves and continue. */
        if (i == world_rank) {
            size_t elems_to_copy = send_final_idxs[i] - send_idxs[i];
            assert(elems_to_copy == recv_final_idxs[i] - recv_idxs[i]);
            if (elems_to_copy) {
                memcpy(out + recv_idxs[i], arr + send_idxs[i],
                        elems_to_copy * sizeof(*out));
                send_idxs[i] += elems_to_copy;
                recv_idxs[i] += elems_to_copy;
            }
            send_requests[i].type = MPI_TLS_NULL;
            recv_requests[i].type = MPI_TLS_NULL;
            continue;
        }

        /* Construct send requests. */
        if (send_idxs[i] < send_final_idxs[i]) {
            size_t elems_to_send =
                MIN(send_final_idxs[i] - send_idxs[i],
                        SAMPLE_PARTITION_BUF_SIZE);
            ret =
                mpi_tls_isend_bytes(arr + send_idxs[i],
                        elems_to_send * sizeof(*arr), i, BALANCE_MPI_TAG,
                        &send_requests[i]);
            if (ret) {
                handle_error_string(
                        "Error sending balance elements from %d to %d",
                        world_rank, i);
                goto exit;
            }
            send_idxs[i] += elems_to_send;
            num_requests++;
        } else {
            send_requests[i].type = MPI_TLS_NULL;
        }

        /* Construct receive requests. */
        if (recv_idxs[i] < recv_final_idxs[i]) {
            size_t elems_to_recv =
                MIN(recv_final_idxs[i] - recv_idxs[i],
                        SAMPLE_PARTITION_BUF_SIZE);
            ret =
                mpi_tls_irecv_bytes(out + recv_idxs[i],
                        elems_to_recv * sizeof(*out), i, BALANCE_MPI_TAG,
                        &recv_requests[i]);
            if (ret) {
                handle_error_string(
                        "Error receiving balance elements from %d into %d",
                        i, world_rank);
                goto exit;
            }
            recv_idxs[i] += elems_to_recv;
            num_requests++;
        } else {
            recv_requests[i].type = MPI_TLS_NULL;
        }
    }

    /* Repeatedly wait and send. */
    while (num_requests) {
        size_t index;
        mpi_tls_status_t status;
        ret = mpi_tls_waitany(world_size * 2, requests, &index, &status);
        if (ret) {
            handle_error_string("Error waiting on balance MPI requests");
            goto exit;
        }

        if (index < (size_t) world_size) {
            /* This was a send request. */
            int rank = index;
            if (send_idxs[rank] < send_final_idxs[rank]) {
                size_t elems_to_send =
                    MIN(send_final_idxs[rank] - send_idxs[rank],
                            SAMPLE_PARTITION_BUF_SIZE);
                ret =
                    mpi_tls_isend_bytes(arr + send_idxs[rank],
                            elems_to_send * sizeof(*out), rank,
                            BALANCE_MPI_TAG, &send_requests[rank]);
                if (ret) {
                    handle_error_string(
                            "Error receiving balance elements from %d into %d",
                            rank, world_rank);
                    goto exit;
                }
                send_idxs[rank] += elems_to_send;
            } else {
                send_requests[rank].type = MPI_TLS_NULL;
                num_requests--;
            }
        } else {
            int rank = index - world_size;
            /* This was a receive request. */
            if (recv_idxs[rank] < recv_final_idxs[rank]) {
                size_t elems_to_recv =
                    MIN(recv_final_idxs[rank] - recv_idxs[rank],
                            SAMPLE_PARTITION_BUF_SIZE);
                ret =
                    mpi_tls_irecv_bytes(out + recv_idxs[rank],
                            elems_to_recv * sizeof(*out), rank,
                            BALANCE_MPI_TAG, &recv_requests[rank]);
                if (ret) {
                    handle_error_string(
                            "Error receiving balance elements from %d into %d",
                            rank, world_rank);
                    goto exit;
                }
                recv_idxs[rank] += elems_to_recv;
            } else {
                recv_requests[rank].type = MPI_TLS_NULL;
                num_requests--;
            }
        }
    }

    ret = 0;

exit:
    return ret;
}

int nonoblivious_sort(elem_t *arr, elem_t *out, size_t length,
        size_t local_length, size_t num_threads) {
    int ret;

    if (world_size == 1) {
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

        /* Sort local partitions. */
        ret = mergesort(arr, out, length, num_threads);
        if (ret) {
            handle_error_string("Error in non-oblivious local sort");
            goto exit;
        }

        /* Copy local sort output to final output. */
        memcpy(arr, out, length * sizeof(*arr));

        struct ocall_timespec time_finish;
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
        {
            sgx_status_t result = ocall_clock_gettime(&time_finish);
            if (result != SGX_SUCCESS) {
                handle_sgx_error(result, "ocall_clock_gettime");
                ret = -1;
                goto exit;
            }
        }
#else
        ocall_clock_gettime(&time_finish);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */

        if (world_rank == 0) {
            printf("sample_partition : %f\n", 0.0);
            printf("local_sort       : %f\n",
                    get_time_difference(&time_start, &time_finish));
            printf("balance          : %f\n", 0.0);
        }

        goto exit;
    }

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

    /* Partition permuted data such that each enclave has its own partition of
     * element, e.g. enclave 0 has the lowest elements, then enclave 1, etc. */
    size_t partition_length;
    ret =
        distributed_sample_partition(arr, out, local_length, &partition_length);
    if (ret) {
        handle_error_string("Error in distributed sample partitioning");
        goto exit;
    }

    struct ocall_timespec time_sample_partition;
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    {
        sgx_status_t result = ocall_clock_gettime(&time_sample_partition);
        if (result != SGX_SUCCESS) {
            handle_sgx_error(result, "ocall_clock_gettime");
            ret = -1;
            goto exit;
        }
    }
#else
    ocall_clock_gettime(&time_sample_partition);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */

    /* Sort local partitions. */
    ret = mergesort(out, arr, partition_length, num_threads);
    if (ret) {
        handle_error_string("Error in non-oblivious local sort");
        goto exit;
    }

    struct ocall_timespec time_local_sort;
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    {
        sgx_status_t result = ocall_clock_gettime(&time_local_sort);
        if (result != SGX_SUCCESS) {
            handle_sgx_error(result, "ocall_clock_gettime");
            ret = -1;
            goto exit;
        }
    }
#else
    ocall_clock_gettime(&time_local_sort);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */

    /* Balance partitions. */
    ret = balance(arr, out, length, partition_length);
    if (ret) {
        handle_error_string("Error in non-oblivious balancing");
        goto exit;
    }

    struct ocall_timespec time_finish;
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    {
        sgx_status_t result = ocall_clock_gettime(&time_finish);
        if (result != SGX_SUCCESS) {
            handle_sgx_error(result, "ocall_clock_gettime");
            ret = -1;
            goto exit;
        }
    }
#else
    ocall_clock_gettime(&time_finish);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */

    if (world_rank == 0) {
        printf("sample_partition : %f\n",
                get_time_difference(&time_start, &time_sample_partition));
        printf("local_sort       : %f\n",
                get_time_difference(&time_sample_partition, &time_local_sort));
        printf("balance          : %f\n",
                get_time_difference(&time_local_sort, &time_finish));
    }

exit:
    return ret;
}
