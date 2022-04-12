#include <assert.h>
#include <errno.h>
#include <liboblivious/primitives.h>
#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "baselines/common.h"
#include "common/error.h"
#include "common/node_t.h"
#include "common/util.h"
#include "host/error.h"

#define SAMPLE_PARTITION_BUF_SIZE 512

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

static int world_rank;
static int world_size;

static size_t total_length;

static inline int wrap_mpi_send_bytes(const void *buf, int count, int dest,
        int tag) {
    return MPI_Send(buf, count, MPI_UNSIGNED_CHAR, dest, tag, MPI_COMM_WORLD);
}

static inline int wrap_mpi_recv_bytes(void *buf, int count, int source, int
        tag, MPI_Status *status) {
    return MPI_Recv(buf, count, MPI_UNSIGNED_CHAR, source, tag, MPI_COMM_WORLD,
            status);
}

static inline int wrap_mpi_isend_bytes(const void *buf, int count, int dest,
        int tag, MPI_Request *request) {
    return MPI_Isend(buf, count, MPI_UNSIGNED_CHAR, dest, tag, MPI_COMM_WORLD,
            request);
}

struct sample {
    uint64_t key;
    uint64_t orp_id;
};

static int node_sample_node_comparator(const node_t *a, const struct sample *b) {
    int comp_key = (a->key > b->key) - (a->key < b->key);
    int comp_orp_id = (a->orp_id > b->orp_id) - (a->orp_id < b->orp_id);
    return (comp_key << 1) + comp_orp_id;
}

static int distributed_quickselect_helper(node_t *arr, size_t local_length,
        size_t *targets, struct sample *samples, size_t *sample_idxs,
        size_t num_targets, size_t left, size_t right) {
    int ret;

    if (!num_targets) {
        ret = 0;
        goto exit;
    }

    /* Get the next master by choosing the lowest node with a non-empty
     * slice. */
    bool ready = true;
    bool not_ready = false;
    int master_rank = -1;
    for (int i = 0; i < world_size; i++) {
        if (i != world_rank) {
            bool *flag = left < right ? &ready : &not_ready;
            ret = wrap_mpi_send_bytes(flag, sizeof(*flag), i, 0);
            if (ret) {
                handle_error_string("Error sending ready flag to %d from %d",
                        i, world_rank);
                goto exit;
            }
        }
    }
    for (int i = 0; i < world_size; i++) {
        bool is_ready;
        if (i != world_rank) {
            ret =
                wrap_mpi_recv_bytes(&is_ready, sizeof(is_ready), i, 0,
                        MPI_STATUS_IGNORE);
            if (ret) {
                handle_error_string(
                        "Error receiving ready flag from %d into %d", i,
                        world_rank);
                goto exit;
            }
        } else {
            is_ready = left < right;
        }

        if (is_ready && (master_rank == -1 || i < master_rank)) {
            master_rank = i;
        }
    }

    if (master_rank == -1) {
        handle_error_string("All ranks reported empty slice");
        ret = -1;
        goto exit;
    }

    /* Get pivot. */
    struct sample pivot;
    if (world_rank == master_rank) {
        /* Use first node as pivot. This is a random selection since this
         * samplesort should happen after ORP. */
        pivot.key = arr[left].key;
        pivot.orp_id = arr[left].orp_id;

        /* Send pivot to all other nodes. */
        for (int i = 0; i < world_size; i++) {
            if (i != world_rank) {
                ret = wrap_mpi_send_bytes(&pivot, sizeof(pivot), i, 0);
                if (ret) {
                    handle_error_string("Error sending pivot to %d from %d", i,
                            world_rank);
                    goto exit;
                }
            }
        }
    } else {
        /* Receive pivot from master. */
        ret =
            wrap_mpi_recv_bytes(&pivot, sizeof(pivot), master_rank, 0,
                    MPI_STATUS_IGNORE);
        if (ret) {
            handle_error_string("Error receiving pivot into %d from %d",
                    world_rank, master_rank);
            goto exit;
        }
    }

    /* Partition data based on pivot. */
    // TODO It's possible to do this in-place.
    size_t partition_left = left + (world_rank == master_rank);
    size_t partition_right = right;
    enum {
        PARTITION_SCAN_LEFT,
        PARTITION_SCAN_RIGHT,
    } partition_state = PARTITION_SCAN_LEFT;
    while (partition_left < partition_right) {
        switch (partition_state) {
        case PARTITION_SCAN_LEFT:
            /* Scan left for elements greater than the pivot. */

            /* If found, start scanning right. */
            if (node_sample_node_comparator(&arr[partition_left], &pivot) > 0) {
                partition_state = PARTITION_SCAN_RIGHT;
            } else {
                partition_left++;
            }

            break;

        case PARTITION_SCAN_RIGHT:
            /* Scan right for elements less than the pivot. */

            /* If found, swap and start scanning left. */
            if (node_sample_node_comparator(&arr[partition_right - 1], &pivot)
                    < 0) {
                node_t temp;
                memcpy(&temp, &arr[partition_left], sizeof(*arr));
                memcpy(&arr[partition_left], &arr[partition_right - 1],
                        sizeof(*arr));
                memcpy(&arr[partition_right - 1], &temp, sizeof(*arr));

                partition_state = PARTITION_SCAN_LEFT;
                partition_left++;
                partition_right--;
            } else {
                partition_right--;
            }

            break;
        }
    }

    /* Finish partitioning by swapping the pivot into the center, if we are the
     * master. */
    if (world_rank == master_rank) {
        node_t temp;
        memcpy(&temp, &arr[partition_right - 1], sizeof(*arr));
        memcpy(&arr[partition_right - 1], &arr[left], sizeof(*arr));
        memcpy(&arr[left], &temp, sizeof(*arr));
        partition_right--;
    }

    /* Sum size of partitions across all ranks and get next updated split,
     * either cur_split or cur_split + SUM(partition_left). */
    size_t cur_pivot;
    if (world_rank == master_rank) {
        cur_pivot = partition_right;

        for (int i = 0; i < world_size; i++) {
            if (i != world_rank) {
                size_t remote_partition_right;
                ret =
                    wrap_mpi_recv_bytes(&remote_partition_right,
                            sizeof(remote_partition_right), i, 0,
                            MPI_STATUS_IGNORE);
                if (ret) {
                    handle_error_string(
                            "Error receiving partition size from %d into %d",
                            i, world_rank);
                    goto exit;
                }
                cur_pivot += remote_partition_right;
            }
        }

        for (int i = 0; i < world_size; i++) {
            if (i != world_rank) {
                ret = wrap_mpi_send_bytes(&cur_pivot, sizeof(cur_pivot), i, 0);
                if (ret) {
                    handle_error_string(
                            "Error sending current pivot to %d from %d", i,
                            world_rank);
                    goto exit;
                }
            }
        }
    } else {
        ret =
            wrap_mpi_send_bytes(&partition_right, sizeof(partition_right),
                    master_rank, 0);
        if (ret) {
            handle_error_string(
                    "Error sending partition size from %d to %d",
                    world_rank, master_rank);
            goto exit;
        }

        ret =
            wrap_mpi_recv_bytes(&cur_pivot, sizeof(cur_pivot), master_rank, 0,
                    MPI_STATUS_IGNORE);
        if (ret) {
            handle_error_string(
                    "Error receiving current pivot into %d from %d",
                    world_rank, master_rank);
            goto exit;
        }
    }

    /* Check which directions we need to iterate in, based on the current pivot
     * index. If there are smaller targets, then iterate on the left half. If
     * there are larger targets, then iterate on the right half. If there is a
     * matching target, then set the sample in the output. */
    size_t *geq_target =
        bsearch_ge(&cur_pivot, targets, num_targets, sizeof(*targets), comp_ul);
    size_t geq_target_idx = (size_t) (geq_target - targets);
    bool found_target = geq_target_idx < num_targets && *geq_target == cur_pivot;
    size_t gt_target_idx = geq_target_idx + found_target;

    /* If we found a target, set the sample and its index. */
    if (found_target) {
        size_t i = geq_target - targets;
        samples[i] = pivot;
        sample_idxs[i] = partition_right;
    }

    /* Set up next iteration(s) if we have targets on either side. If the next
     * split is greater than the target, keep the current split and advance the
     * head of the slice. Else, advance the split and retract the tail of the
     * slice. */
    /* Targets less than pivot. */
    ret =
        distributed_quickselect_helper(arr, local_length, targets, samples,
                sample_idxs, geq_target_idx, left, partition_right);
    if (ret) {
        goto exit;
    }
    /* Targets greater than pivot. */
    ret =
        distributed_quickselect_helper(arr, local_length,
                targets + gt_target_idx, samples + gt_target_idx,
                sample_idxs + gt_target_idx, num_targets - gt_target_idx,
                partition_left, right);
    if (ret) {
        goto exit;
    }

exit:
    return ret;
}

/* Performs a distruted version of the quickselect algorithm to find NUM_TARGETS
 * target elements in TARGETS contained in ARR, which contains LOCAL_LENGTH
 * elements in the local, with the first element encrypted with index
 * LOCAL_START. Resulting samples are stored in SAMPLES. TARGETS must be a
 * sorted array. */

static int distributed_quickselect(node_t *arr, size_t local_length,
        size_t *targets, struct sample *samples, size_t *sample_idxs,
        size_t num_targets) {
    int ret =
        distributed_quickselect_helper(arr, local_length, targets, samples,
                sample_idxs, num_targets, 0, local_length);
    if (ret) {
        handle_error_string("Error in distributed quickselect");
        goto exit;
    }

exit:
    return ret;
}

/* Performs a non-oblivious samplesort across all enclaves. */
static int distributed_sample_partition(node_t *arr, node_t *out,
        size_t local_length, size_t total_length) {
    size_t src_local_start = total_length * world_rank / world_size;
    size_t src_local_length =
        total_length * (world_rank + 1) / world_size - src_local_start;
    int ret;

    /* Construct samples to and pass to quickselect. We want an even
     * distribution of elements across all ranks. */
    size_t sample_targets[world_size - 1];
    for (size_t i = 0; i < (size_t) world_size - 1; i++) {
        sample_targets[i] = total_length * (i + 1) / world_size;
    }
    struct sample samples[world_size - 1];
    size_t sample_idxs[world_size + 1];
    MPI_Request send_requests[world_size];
    ret =
        distributed_quickselect(arr, local_length, sample_targets, samples,
                sample_idxs + 1, world_size - 1);
    if (ret) {
        handle_error_string("Error in distributed quickselect");
        goto exit;
    }
    sample_idxs[0] = 0;
    sample_idxs[world_size] = local_length;

    /* Send elements to their corresponding enclaves. The elements in the array
     * should already be partitioned. */

    /* Copy own partition's elements to the output. */
    size_t num_received =
        sample_idxs[world_rank + 1] - sample_idxs[world_rank];
    memcpy(out, arr + sample_idxs[world_rank],
            (sample_idxs[world_rank + 1] - sample_idxs[world_rank])
                * sizeof(*out));

    /* Construct asynchronous send requests to send nodes to the remote. */
    for (int i = 0; i < world_size; i++) {
        if (i != world_rank) {
            ret = wrap_mpi_isend_bytes(arr + sample_idxs[i],
                    (sample_idxs[i + 1] - sample_idxs[i]) * sizeof(*arr), i, 0,
                    &send_requests[i]);
            if (ret) {
                handle_error_string("Error sending partitioned data");
                goto exit;
            }
        }
    }

    /* Receive all incoming nodes. */
    for (int i = 0; i < world_size - 1; i++) {
        MPI_Status status;
        ret = wrap_mpi_recv_bytes(out + num_received,
                (src_local_length - num_received) * sizeof(*out),
                MPI_ANY_SOURCE, 0, &status);
        if (ret) {
            handle_error_string("Error receiving partitioned data");
            goto exit;
        }
        int count;
        ret = MPI_Get_count(&status, MPI_UNSIGNED_CHAR, &count);
        if (ret) {
            handle_error_string("Error getting count of partitioned data");
            goto exit;
        }
        num_received += count / sizeof(*out);
    }

    assert(num_received == src_local_length);

exit:
    return ret;
}

int nonoblivious_sort(node_t *arr, size_t local_length, size_t total_length) {
    int ret;

    if (world_size == 1) {
        qsort(arr, total_length, sizeof(*arr), node_comparator);
        ret = 0;
        goto exit;
    }

    node_t *out = malloc(local_length * sizeof(*out));
    if (!out) {
        perror("malloc sort out");
        ret = errno;
        goto exit;
    }

    /* Sample partition to partition elements across enclaves. */
    ret = distributed_sample_partition(arr, out, local_length, total_length);
    if (ret) {
        handle_error_string("Error in sample partitioning");
        goto exit_free_out;
    }

    /* Local quicksort. */
    qsort(out, local_length, sizeof(*out), node_comparator);

exit_free_out:
    free(out);
exit:
    return ret;
}

int main(int argc, char **argv) {
    int ret = 0;

    /* Parse args. */
    if (argc < 2) {
        printf("usage: %s array_size\n", argv[0]);
        return -1;
    }
    ssize_t slength = atoll(argv[1]);
    if (slength < 0 || !is_pow2(slength)) {
        printf("Invalid array size\n");
        return -1;
    }
    size_t length = slength;

    ret = init_mpi(&argc, &argv, &world_rank, &world_size);
    if (ret) {
        fprintf(stderr, "Error in MPI initialization\n");
        goto exit;
    }

    total_length = length;
    size_t local_length = length / world_size;

    /* Allocate array. */
    node_t *arr = calloc(local_length, sizeof(node_t));
    if (!arr) {
        perror("alloc array");
        ret = errno;
        goto exit_finalize_mpi;
    }

    /* Add random elements to array. */
    srand(world_rank + 1);
    for (size_t i = 0; i < local_length; i++) {
        arr[i].key = rand();
    }

    /* Sort and time. */
    struct timespec start;
    timespec_get(&start, TIME_UTC);
    ret = nonoblivious_sort(arr, local_length, length);
    if (ret) {
        handle_error_string("Error in sort");
        goto exit_free_arr;
    }
    ret = MPI_Barrier(MPI_COMM_WORLD);
    if (ret) {
        handle_mpi_error(ret, "MPI_Barrier");
        goto exit_free_arr;
    }
    struct timespec end;

    timespec_get(&end, TIME_UTC);

    /* Print time taken. */
    if (world_rank == 0) {
        double seconds_taken =
            (double) ((end.tv_sec * 1000000000 + end.tv_nsec)
                    - (start.tv_sec * 1000000000 + start.tv_nsec))
            / 1000000000;
        printf("%f\n", seconds_taken);
    }

exit_free_arr:
    free(arr);
exit_finalize_mpi:
    ret = MPI_Finalize();
    if (ret) {
        fprintf(stderr, "Error finalizing MPI\n");
    }
exit:
    return ret;
}
