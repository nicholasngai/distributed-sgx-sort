#include "enclave/bucket.h"
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <threads.h>
#ifdef DISTRIBUTED_SGX_SORT_BENCHMARK
#include <time.h>
#endif /* DISTRIBUTED_SGX_SORT_BENCHMARK */
#include <liboblivious/algorithms.h>
#include <liboblivious/primitives.h>
#include "common/crypto.h"
#include "common/defs.h"
#include "common/elem_t.h"
#include "common/error.h"
#include "common/util.h"
#include "enclave/mpi_tls.h"
#include "enclave/parallel_enc.h"
#include "enclave/threading.h"

#define SAMPLE_PARTITION_BUF_SIZE 512

#define BUCKET_DISTRIBUTE_MPI_TAG 1
#define SAMPLE_PARTITION_MPI_TAG 2
#define QUICKSELECT_MPI_TAG 3

static size_t total_length;

/* Thread-local buffer used for generic operations. */
static thread_local elem_t *buffer;

static int get_bucket_rank(size_t bucket) {
    size_t num_buckets =
        MAX(next_pow2l(total_length) * 2 / BUCKET_SIZE,
                (size_t) world_size * 2);
    return bucket * world_size / num_buckets;
}

static size_t get_local_bucket_start(int rank) {
    size_t num_buckets =
        MAX(next_pow2l(total_length) * 2 / BUCKET_SIZE,
                (size_t) world_size * 2);
    return (rank * num_buckets + world_size - 1) / world_size;
}

#ifdef DISTRIBUTED_SGX_SORT_BENCHMARK
static double get_time_difference(struct timespec *start,
        struct timespec *end) {
    return (double) (end->tv_sec * 1000000000 + end->tv_nsec
            - (start->tv_sec * 1000000000 + start->tv_nsec))
        / 1000000000;
}
#endif

/* Initialization and deinitialization. */

int bucket_init(void) {
    /* Allocate buffer. */
    buffer = malloc(BUCKET_SIZE * 2 * sizeof(*buffer));
    if (!buffer) {
        perror("Error allocating buffer");
        goto exit;
    }

    return 0;

exit:
    return -1;
}

void bucket_free(void) {
    /* Free resources. */
    free(buffer);
}

/* Bucket sort. */

struct assign_random_id_args {
    const elem_t *arr;
    elem_t *out;
    size_t length;
    size_t src_start_idx;
    size_t result_start_idx;
    elem_t *dummy_elem;
    int ret;
};
static void assign_random_id(void *args_, size_t i) {
    struct assign_random_id_args *args = args_;
    int ret;

    if (i % 2 == 0 && i < args->length * 2) {
        /* Copy elem from index i / 2 and assign ORP ID. */
        memcpy(&args->out[i], &args->arr[i / 2], sizeof(args->out[i]));
        ret = rand_read(&args->out[i].orp_id, sizeof(args->out[i].orp_id));
        if (ret) {
            handle_error_string("Error assigning random ID to elem %lu",
                    i + args->result_start_idx);
            goto exit;
        }
        args->out[i].is_dummy = false;
    } else {
        /* Use dummy elem. */
        args->out[i].is_dummy = true;
    }

    ret = 0;

exit:
    if (ret) {
        int expected = 0;
        __atomic_compare_exchange_n(&args->ret, &expected, ret,
                false, __ATOMIC_RELEASE, __ATOMIC_RELAXED);
    }
}

/* Assigns random ORP IDs to the encrypted elems, whose first element is
 * encrypted with index SRC_START_IDX, in ARR and distributes them evenly over
 * the 2 * LENGTH elements in OUT, re-encrypting them according to
 * RESULT_START_IDX. Thus, ARR is assumed to be at least
 * 2 * MAX(LENGTH, BUCKET_SIZE) bytes. The result is an array with real elements
 * interspersed with dummy elements. */
// TODO Can we do the first bucket assignment scan while generating these?
static int assign_random_ids_and_spread(const elem_t *arr, void *out,
        size_t length, size_t src_start_idx, size_t result_start_idx) {
    int ret;

    elem_t dummy_elem;
    memset(&dummy_elem, '\0', sizeof(dummy_elem));
    dummy_elem.is_dummy = true;

    struct assign_random_id_args args = {
        .arr = arr,
        .out = out,
        .length = length,
        .src_start_idx = src_start_idx,
        .result_start_idx = result_start_idx,
        .dummy_elem = &dummy_elem,
        .ret = 0,
    };
    struct thread_work work = {
        .type = THREAD_WORK_ITER,
        .iter = {
            .func = assign_random_id,
            .arg = &args,
            .count = MAX(length, BUCKET_SIZE) * 2,
        },
    };
    thread_work_push(&work);
    thread_work_until_empty();
    thread_wait(&work);
    ret = args.ret;
    if (ret) {
        handle_error_string("Error assigning random ids");
        goto exit;
    }

exit:
    return ret;
}

struct merge_split_ocompact_aux {
    elem_t *bucket1;
    elem_t *bucket2;
    size_t bit_idx;
};

static bool merge_split_is_marked(size_t index, void *aux_) {
    /* The element is marked if the BIT_IDX'th bit of the ORP ID of the element
     * is set to 0. */
    struct merge_split_ocompact_aux *aux = aux_;
    elem_t *elem =
        &(index < BUCKET_SIZE ? aux->bucket1 : aux->bucket2)[index % BUCKET_SIZE];
    return !((elem->orp_id >> aux->bit_idx) & 1);
}

static void merge_split_swapper(size_t a, size_t b, bool should_swap, void *aux_) {
    struct merge_split_ocompact_aux *aux = aux_;
    elem_t *elem_a =
        &(a < BUCKET_SIZE ? aux->bucket1 : aux->bucket2)[a % BUCKET_SIZE];
    elem_t *elem_b =
        &(b < BUCKET_SIZE ? aux->bucket1 : aux->bucket2)[b % BUCKET_SIZE];
    o_memswap(elem_a, elem_b, sizeof(*elem_a), should_swap);
}

/* Merge BUCKET1 and BUCKET2 and split such that BUCKET1 contains all elements
 * corresponding with bit 0 and BUCKET2 contains all elements corresponding with
 * bit 1, with the bit given by the bit in BIT_IDX of the elems' ORP IDs. Note
 * that this is a modified version of the merge-split algorithm from the paper,
 * since the elements are swapped in-place rather than being swapped between
 * different buckets on different layers. */
static int merge_split(elem_t *arr, size_t bucket1_idx, size_t bucket2_idx,
        size_t bit_idx) {
    int ret = -1;
    int bucket1_rank = get_bucket_rank(bucket1_idx);
    int bucket2_rank = get_bucket_rank(bucket2_idx);
    bool bucket1_local = bucket1_rank == world_rank;
    bool bucket2_local = bucket2_rank == world_rank;
    size_t local_bucket_start = get_local_bucket_start(world_rank);

    /* If both buckets are remote, ignore this merge-split. */
    if (!bucket1_local && !bucket2_local) {
        ret = 0;
        goto exit;
    }

    int local_bucket_idx = bucket1_local ? bucket1_idx : bucket2_idx;
    int nonlocal_bucket_idx = bucket1_local ? bucket2_idx : bucket1_idx;
    int nonlocal_rank = bucket1_local ? bucket2_rank : bucket1_rank;

    /* Load bucket 1 elems if local. */
    elem_t *bucket1;
    if (bucket1_local) {
        bucket1 = arr + (bucket1_idx - local_bucket_start) * BUCKET_SIZE;
    }

    /* Load bucket 2 elems if local. */
    elem_t *bucket2;
    if (bucket2_local) {
        bucket2 = arr + (bucket2_idx - local_bucket_start) * BUCKET_SIZE;
    }

    /* The number of elements with corresponding bit 1. */
    size_t count1 = 0;

    /* Count number of elements with corresponding bit 1 for local buckets. */
    if (bucket1_local) {
        for (size_t i = 0; i < BUCKET_SIZE; i++) {
            /* Obliviously increment count. */
            count1 +=
                ((bucket1[i].orp_id >> bit_idx) & 1) & !bucket1[i].is_dummy;
        }
    }
    if (bucket2_local) {
        for (size_t i = 0; i < BUCKET_SIZE; i++) {
            /* Obliviously increment count. */
            count1 +=
                ((bucket2[i].orp_id >> bit_idx) & 1) & !bucket2[i].is_dummy;
        }
    }

    /* If remote, send the current count and then our local buckets. Then,
     * receive the sent count and remote buckets from the other elem. */
    if (!bucket1_local || !bucket2_local) {
        /* Post receive for count. */
        mpi_tls_request_t count_request;
        size_t remote_count1;
        ret = mpi_tls_irecv_bytes(&remote_count1, sizeof(remote_count1),
                nonlocal_rank, nonlocal_bucket_idx, &count_request);
        if (ret) {
            handle_error_string("Error receiving count1 into %d from %d",
                    world_rank, nonlocal_rank);
            goto exit;
        }

        /* Post receive for remote bucket. */
        mpi_tls_request_t bucket_request;
        ret = mpi_tls_irecv_bytes(buffer, sizeof(*buffer) * BUCKET_SIZE,
                nonlocal_rank, nonlocal_bucket_idx, &bucket_request);
        if (ret) {
            handle_error_string("Error receiving remote bucket into %d from %d",
                    world_rank, nonlocal_rank);
            goto exit;
        }
        if (bucket1_local) {
            bucket2 = buffer;
        } else {
            bucket1 = buffer;
        }

        /* Send count. */
        ret = mpi_tls_send_bytes(&count1, sizeof(count1), nonlocal_rank,
                local_bucket_idx);
        if (ret) {
            handle_error_string("Error sending count1 from %d to %d",
                    world_rank, nonlocal_rank);
            goto exit;
        }

        /* Send local bucket. */
        ret = mpi_tls_send_bytes(
                bucket1_local ? bucket1 : bucket2,
                sizeof(*bucket1) * BUCKET_SIZE, nonlocal_rank,
                local_bucket_idx);
        if (ret) {
            handle_error_string("Error sending local bucket from %d to %d",
                    world_rank, nonlocal_rank);
            goto exit;
        }

        /* Wait for count and bucket to come in. */
        ret = mpi_tls_wait(&count_request, MPI_TLS_STATUS_IGNORE);
        if (ret) {
            handle_error_string(
                    "Error waiting on receive for count1 into %d from %d",
                    world_rank, nonlocal_rank);
            goto exit;
        }
        ret = mpi_tls_wait(&bucket_request, MPI_TLS_STATUS_IGNORE);
        if (ret) {
            handle_error_string(
                    "Error waiting on receive for bucket into %d from %d",
                    world_rank, nonlocal_rank);
            goto exit;
        }

        /* Add the received remote count to the local count to arrive at the
         * total for both buckets. */
        count1 += remote_count1;
    }

    /* There are count1 elements with bit 1, so we need to assign BUCKET_SIZE -
     * count1 dummy elements to have bit 1, with the remaining dummy elements
     * assigned with bit 0. */
    count1 = BUCKET_SIZE - count1;

    /* Assign dummy elements. */
    for (size_t i = 0; i < BUCKET_SIZE; i++) {
        /* If count1 > 0 and the elem is a dummy element, set BIT_IDX bit of ORP
         * ID and decrement count1. Else, clear BIT_IDX bit of ORP ID. */
        bucket1[i].orp_id &= ~(bucket1[i].is_dummy << bit_idx);
        bucket1[i].orp_id |= ((bool) count1 & bucket1[i].is_dummy) << bit_idx;
        count1 -= (bool) count1 & bucket1[i].is_dummy;
    }
    for (size_t i = 0; i < BUCKET_SIZE; i++) {
        /* If count1 > 0 and the elem is a dummy element, set BIT_IDX bit of ORP
         * ID and decrement count1. Else, clear BIT_IDX bit of ORP ID. */
        bucket2[i].orp_id &= ~(bucket2[i].is_dummy << bit_idx);
        bucket2[i].orp_id |= ((bool) count1 & bucket2[i].is_dummy) << bit_idx;
        count1 -= (bool) count1 & bucket2[i].is_dummy;
    }

    /* Oblivious bitonic sort elements according to BIT_IDX bit of ORP id. */
    struct merge_split_ocompact_aux aux = {
        .bucket1 = bucket1,
        .bucket2 = bucket2,
        .bit_idx = bit_idx,
    };
    o_compact_generate_swaps(BUCKET_SIZE * 2, merge_split_is_marked, merge_split_swapper, &aux);

    ret = 0;

exit:

    return ret;
}

/* Performs the merge_split operation over a starting bucket specified by an
 * index. The BUCKET_IDX parameter is just a way of dividing work between
 * threads. Iterating from 0 to NUM_BUCKETS / 2 when BUCKET_OFFSET == 0 is
 * equivalent to
 *
 * for (size_t bucket_start = 0; bucket_start < num_buckets;
 *         bucket_start += bucket_stride) {
 *     for (size_t bucket = bucket_start;
 *             bucket < bucket_start + bucket_stride / 2; bucket++) {
 *         ...
 *     }
 * }
 *
 * but with easier task generation. The loop goes backwards if BIT_IDX is odd,
 * since this hits buckets that were most recently loaded into the decrypted
 * bucket cache. BUCKET_OFFSET is used for chunking so that we can reuse this
 * function at different starting points for different chunks. */
struct merge_split_idx_args {
    elem_t *arr;
    size_t bit_idx;
    size_t bucket_stride;
    size_t bucket_offset;
    size_t num_buckets;

    int ret;
};
static void merge_split_idx(void *args_, size_t bucket_idx) {
    struct merge_split_idx_args *args = args_;
    int ret;

    if (args->bit_idx % 2 == 1) {
        bucket_idx = args->num_buckets / 2 - bucket_idx - 1;
    }

    size_t bucket = bucket_idx % (args->bucket_stride / 2)
        + bucket_idx / (args->bucket_stride / 2) * args->bucket_stride
        + args->bucket_offset;
    size_t other_bucket = bucket + args->bucket_stride / 2;
    ret = merge_split(args->arr, bucket, other_bucket, args->bit_idx);
    if (ret) {
        handle_error_string(
                "Error in merge split with indices %lu and %lu\n", bucket,
                other_bucket);
        goto exit;
    }

exit:
    if (ret) {
        __atomic_compare_exchange_n(&args->ret, &ret, 0, false,
                __ATOMIC_RELAXED, __ATOMIC_RELAXED);
    }
}

/* Run merge-split as part of a butterfly network, routing based on
 * ORP_ID[START_BIT_IDX:START_BIT_IDX + NUM_LEVELS - 1]. This is modified from
 * the paper, since all merge-split operations will be constrained to the same
 * buckets of memory. */
static int bucket_route(elem_t *arr, size_t num_levels, size_t start_bit_idx) {
    size_t num_buckets = get_local_bucket_start(world_size);
    int ret;

    for (size_t bit_idx = 0; bit_idx < num_levels; bit_idx++) {
        size_t bucket_stride = 2u << bit_idx;

        /* Create iterative task for merge split. */
        struct merge_split_idx_args args = {
            .arr = arr,
            .bit_idx = start_bit_idx + bit_idx,
            .bucket_stride = bucket_stride,
            .bucket_offset = 0,
            .num_buckets = num_buckets,
        };
        struct thread_work work = {
            .type = THREAD_WORK_ITER,
            .iter = {
                .func = merge_split_idx,
                .arg = &args,
                .count = num_buckets / 2,
            },
        };
        thread_work_push(&work);

        thread_work_until_empty();

        /* Get work from others. */
        thread_wait(&work);
        ret = args.ret;
        if (ret) {
            handle_error_string("Error in merge split range at level %lu",
                    bit_idx);
            goto exit;
        }
    }

exit:
    return ret;
}

/* Distribute and receive elements from buckets in ARR to buckets in OUT.
 * Bucket i is sent to enclave i % E. */
static int distributed_bucket_route(elem_t *arr, void *out_) {
    unsigned char *out = out_;
    size_t local_bucket_start = get_local_bucket_start(world_rank);
    size_t num_local_buckets =
        get_local_bucket_start(world_rank + 1) - local_bucket_start;
    int ret;

    mpi_tls_request_t requests[world_size];
    size_t request_idxs[world_size];

    if (world_size == 1) {
        memcpy(out, arr, num_local_buckets * BUCKET_SIZE * sizeof(*out));
        ret = 0;
        goto exit;
    }

    elem_t *buf = malloc(BUCKET_SIZE * 2 * sizeof(*buf));
    if (!buf) {
        handle_error_string("Error allocating buffer");
        ret = errno;
        goto exit;
    }

    /* Send and receive buckets according to the rules above. Note that we are
     * iterating by enclave instead of by bucket. */
    size_t num_requests = 0;
    request_idxs[world_rank] = 0;
    for (size_t i = 0; i < (size_t) world_size; i++) {
        requests[i].type = MPI_TLS_NULL;
    }
    for (size_t i = 0; i < MIN(num_local_buckets, (size_t) world_size); i++) {
        int rank = (world_rank * num_local_buckets + i) % world_size;
        if (rank == world_rank) {
            /* Copy our own buckets to the output, if any. */
            for (size_t j = i; j < num_local_buckets; j += world_size) {
                memcpy(out + request_idxs[rank] * BUCKET_SIZE,
                        arr + j * BUCKET_SIZE, BUCKET_SIZE * sizeof(*out));
                request_idxs[rank]++;
            }
        } else {
            /* Post a send request to the remote rank containing the first
             * bucket. */
            request_idxs[rank] = i;
            elem_t *bucket = arr + request_idxs[rank] * BUCKET_SIZE;

            ret = mpi_tls_isend_bytes(bucket, BUCKET_SIZE * sizeof(*bucket),
                    rank, BUCKET_DISTRIBUTE_MPI_TAG, &requests[rank]);
            if (ret) {
                handle_error_string("Error sending bucket %lu to %d from %d",
                        request_idxs[rank] + local_bucket_start, rank,
                        world_rank);
                goto exit_free_buf;
            }
            num_requests++;
        }
    }

    /* Post a receive request for the current bucket. */
    ret =
        mpi_tls_irecv_bytes(buf, BUCKET_SIZE * sizeof(*buf),
                MPI_TLS_ANY_SOURCE, BUCKET_DISTRIBUTE_MPI_TAG,
                &requests[world_rank]);
    if (ret) {
        handle_error_string("Error posting receive into %d", world_rank);
        goto exit_free_buf;
    }
    num_requests++;

    while (num_requests) {
        size_t index;
        mpi_tls_status_t status;
        ret = mpi_tls_waitany(world_size, requests, &index, &status);
        if (ret) {
            handle_error_string("Error waiting on requests");
            goto exit_free_buf;
        }

        if (index == (size_t) world_rank) {
            /* This was the receive request. */

            /* Write the received bucket out. */
            memcpy(out + request_idxs[index] * BUCKET_SIZE, buf,
                    BUCKET_SIZE * sizeof(*out));
            request_idxs[index]++;

            if (request_idxs[index] < num_local_buckets) {
                /* Post receive for the next bucket. */
                ret =
                    mpi_tls_irecv_bytes(buf, BUCKET_SIZE * sizeof(*buf),
                            MPI_TLS_ANY_SOURCE, BUCKET_DISTRIBUTE_MPI_TAG,
                            &requests[index]);
                if (ret) {
                    handle_error_string("Error posting receive into %d",
                            (int) index);
                    goto exit_free_buf;
                }
            } else {
                /* Nullify the receiving request. */
                requests[index].type = MPI_TLS_NULL;
                num_requests--;
            }
        } else {
            /* This was a send request. */

            request_idxs[index] += world_size;

            if (request_idxs[index] < num_local_buckets) {
                elem_t *bucket = arr + request_idxs[index] * BUCKET_SIZE;

                ret =
                    mpi_tls_isend_bytes(bucket, BUCKET_SIZE * sizeof(*bucket),
                            index, BUCKET_DISTRIBUTE_MPI_TAG, &requests[index]);
                if (ret) {
                    handle_error_string(
                            "Error sending bucket %lu from %d to %d",
                            request_idxs[index] + local_bucket_start,
                            world_rank, (int) index);
                    goto exit_free_buf;
                }
            } else {
                /* Nullify the sending request. */
                requests[index].type = MPI_TLS_NULL;
                num_requests--;
            }
        }
    }

exit_free_buf:
    free(buf);
exit:
    return ret;
}

/* Compares elements first by sorting real elements before dummy elements, and
 * then by their ORP ID. */
static int permute_comparator(const void *a_, const void *b_,
        void *aux UNUSED) {
    const elem_t *a = a_;
    const elem_t *b = b_;
    return (a->is_dummy - b->is_dummy) * 2
        + ((a->orp_id > b->orp_id) - (a->orp_id < b->orp_id));
}

/* Permutes the real elements in the bucket by sorting according to all bits of
 * the ORP ID. This is valid because the bin assignment used the lower bits of
 * the ORP ID, leaving the upper bits free for comparison and permutation within
 * the bin.  The elems are then written sequentially to ARR[*COMPRESS_IDX], and
 * *COMPRESS_IDX is incremented. The elems receive new random ORP IDs. The first
 * element is assumed to have START_IDX for the purposes of decryption. */
struct permute_and_compress_args {
    elem_t *arr;
    elem_t *out;
    size_t start_idx;
    size_t *compress_idx;
    int ret;
};
static void permute_and_compress(void *args_, size_t bucket_idx) {
    struct permute_and_compress_args *args = args_;
    int ret;

    o_sort(args->arr + bucket_idx * BUCKET_SIZE, BUCKET_SIZE,
            sizeof(*args->arr), permute_comparator, NULL);

    /* Assign random ORP IDs and Count real elements. */
    size_t num_real_elems = 0;
    for (size_t i = 0; i < BUCKET_SIZE; i++) {
        /* If this is a dummy element, break out of the loop. All real elements
         * are sorted before the dummy elements at this point. This
         * non-oblivious comparison is fine since it's fine to leak how many
         * elements end up in each bucket. */
        if (args->arr[bucket_idx * BUCKET_SIZE + i].is_dummy) {
            num_real_elems = i;
            break;
        }

        /* Assign random ORP ID. */
        ret =
            rand_read(&args->arr[bucket_idx * BUCKET_SIZE + i].orp_id,
                    sizeof(buffer[i].orp_id));
        if (ret) {
            handle_error_string("Error assigning random ID to %lu",
                    bucket_idx * BUCKET_SIZE + args->start_idx);
            goto exit;
        }
    }

    /* Fetch the next index to copy to. */
    size_t out_idx =
        __atomic_fetch_add(args->compress_idx, num_real_elems,
                __ATOMIC_RELAXED);

    /* Copy the elements to the output. */
    memcpy(args->out + out_idx, args->arr + bucket_idx * BUCKET_SIZE,
            num_real_elems * sizeof(*args->out));

exit:
    if (ret) {
        int expected = 0;
        __atomic_compare_exchange_n(&args->ret, &expected, ret, false,
                __ATOMIC_RELEASE, __ATOMIC_RELAXED);
    }
}

/* Compares elements by the tuple (key, ORP ID). The check for the ORP ID must
 * always be run (it must be oblivious whether the comparison result is based on
 * the key or on the ORP ID), since we leak info on duplicate keys otherwise. */
static int mergesort_comparator(const void *a_, const void *b_) {
    const elem_t *a = a_;
    const elem_t *b = b_;
    int comp_key = (a->key > b->key) - (a->key < b->key);
    int comp_orp_id = (a->orp_id > b->orp_id) - (a->orp_id < b->orp_id);
    return (comp_key << 1) + comp_orp_id;
}

/* Non-oblivoius sorting. */

#define BUF_SIZE (BUCKET_SIZE * 2)

/* Sort ARR[RUN_IDX * BUF_SIZE] to ARR[MIN((RUN_IDX + 1), LENGTH)]. The results
 * will be stored in the same * location as the inputs. */
struct mergesort_first_pass_args {
    elem_t *arr;
    size_t length;
};
static void mergesort_first_pass(void *args_, size_t run_idx) {
    struct mergesort_first_pass_args *args = args_;

    size_t run_start = run_idx * BUF_SIZE;
    size_t run_length = MIN(args->length - run_start, BUF_SIZE);

    /* Sort using libc quicksort. */
    qsort(args->arr + run_start, run_length, sizeof(*args->arr),
            mergesort_comparator);
}

/* Merge each BUF_SIZE runs of length RUN_LENGTH starting at element
 * ARR[RUN_IDX * RUN_LENGTH * BUF_SIZE] and writing them to a single run of
 * length RUN_LENGTH * BUF_SIZE at OUT[RUN_IDX * RUN_LENGTH * BUF_SIZE]. If
 * LENGTH - RUN_IDX * RUN_LENGTH * BUF_SIZE is less than RUN_LENGTH * BUF_SIZE,
 * then the number of runs is reduced, and the last run is truncated. */
struct mergesort_pass_args {
    elem_t *input;
    elem_t *output;
    size_t length;
    size_t run_length;
    int ret;
};
static void mergesort_pass(void *args_, size_t run_idx) {
    struct mergesort_pass_args *args = args_;
    int ret;

    /* Compute the current run length and start. */
    size_t run_start = run_idx * args->run_length * BUF_SIZE;
    size_t num_runs =
        MIN(CEIL_DIV(args->length - run_start, args->run_length), BUF_SIZE);

    /* Create index buffer. */
    size_t *merge_indices = malloc(num_runs * sizeof(*merge_indices));
    if (!merge_indices) {
        perror("Allocate merge index buffer");
        ret = errno;
        goto exit;
    }
    memset(merge_indices, '\0', num_runs * sizeof(*merge_indices));

    /* Merge the runs in the buffer and encrypt to the output array.
     * Nodes for which we have reach the end of the array are marked as
     * a dummy element, so we continue until all elems in buffer are
     * dummy elems. */
    size_t output_idx = 0;
    bool all_done;
    do {
        /* Scan for lowest elem. */
        // TODO Use a heap?
        size_t lowest_run;
        size_t lowest_idx;
        all_done = true;
        for (size_t j = 0; j < num_runs; j++) {
            size_t run_idx = j * args->run_length + merge_indices[j];

            if (merge_indices[j] >= args->run_length
                    || run_start + run_idx >= args->length) {
                continue;
            }
            if (all_done
                    || mergesort_comparator(&args->input[run_start + run_idx],
                        &args->input[run_start + lowest_idx]) < 0) {
                lowest_run = j;
                lowest_idx = run_idx;
            }
            all_done = false;
        }

        /* Break out of loop if all done. */
        if (all_done) {
            continue;
        }

        /* Copy lowest elem to output. */
        memcpy(&args->output[run_start + output_idx],
                &args->input[run_start + lowest_idx], sizeof(*args->input));
        merge_indices[lowest_run]++;
        output_idx++;
    } while (!all_done);

    ret = 0;

    free(merge_indices);
exit:
    if (ret) {
        __atomic_compare_exchange_n(&args->ret, &ret, 0, false,
                __ATOMIC_RELAXED, __ATOMIC_RELAXED);
    }
    ;
}

/* Non-oblivious sort. Based on an external mergesort algorithm. */
static int mergesort(elem_t *arr, elem_t *out, size_t length) {
    int ret;

    /* Start by sorting runs of BUF_SIZE. */
    struct mergesort_first_pass_args args = {
        .arr = arr,
        .length = length,
    };
    struct thread_work work = {
        .type = THREAD_WORK_ITER,
        .iter = {
            .func = mergesort_first_pass,
            .arg = &args,
            .count = CEIL_DIV(length, BUF_SIZE),
        },
    };
    thread_work_push(&work);
    thread_work_until_empty();
    thread_wait(&work);

    /* Merge runs of increasing length in a BUF_SIZE-way merge by reading the
     * next smallest element of run i into buffer[i], then merging and
     * encrypting to the output buffer. */
    elem_t *input = arr;
    elem_t *output = out;
    for (size_t run_length = BUF_SIZE; run_length < length;
            run_length *= BUF_SIZE) {
        /* BUF_SIZE-way merge. */
        struct mergesort_pass_args args = {
            .input = input,
            .output = output,
            .length = length,
            .run_length = run_length,
        };
        struct thread_work work = {
            .type = THREAD_WORK_ITER,
            .iter = {
                .func = mergesort_pass,
                .arg = &args,
                .count = CEIL_DIV(length, run_length * BUF_SIZE),
            },
        };
        thread_work_push(&work);
        thread_work_until_empty();
        thread_wait(&work);
        ret = args.ret;
        if (ret) {
            handle_error_string("Error in run-length %lu merges of mergesort",
                    run_length);
            goto exit;
        }

        /* Swap the input and output arrays. */
        elem_t *temp = input;
        input = output;
        output = temp;
    }

    /* If the final merging output (now the input since it would have been
     * swapped) isn't the output parameter, copy to the right place. */
    if (input != out) {
        memcpy(out, input, length * sizeof(*out));
    }

    ret = 0;

exit:
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

static int distributed_quickselect_helper(elem_t *arr, size_t local_length,
        size_t local_start, size_t *targets, struct sample *samples,
        size_t *sample_idxs, size_t num_targets, size_t left, size_t right) {
    int ret;

    if (!num_targets) {
        ret = 0;
        goto exit;
    }

    /* Get the next master by choosing the lowest elem with a non-empty
     * slice. */
    bool ready = true;
    bool not_ready = false;
    int master_rank = -1;
    for (int i = 0; i < world_size; i++) {
        if (i != world_rank) {
            bool *flag = left < right ? &ready : &not_ready;
            ret =
                mpi_tls_send_bytes(flag, sizeof(*flag), i, QUICKSELECT_MPI_TAG);
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
                mpi_tls_recv_bytes(&is_ready, sizeof(is_ready), i,
                        QUICKSELECT_MPI_TAG, MPI_TLS_STATUS_IGNORE);
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
        /* Use first elem as pivot. This is a random selection since this
         * samplesort should happen after ORP. */
        pivot.key = arr[left].key;
        pivot.orp_id = arr[left].orp_id;

        /* Send pivot to all other elems. */
        for (int i = 0; i < world_size; i++) {
            if (i != world_rank) {
                ret =
                    mpi_tls_send_bytes(&pivot, sizeof(pivot), i,
                            QUICKSELECT_MPI_TAG);
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
            mpi_tls_recv_bytes(&pivot, sizeof(pivot), master_rank,
                    QUICKSELECT_MPI_TAG, MPI_TLS_STATUS_IGNORE);
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

    /* Finish partitioning by swapping the pivot into the center, if we are the
     * master. */
    if (world_rank == master_rank) {
        elem_t temp;
        memcpy(&temp, &arr[partition_right - 1], sizeof(temp));
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
                    mpi_tls_recv_bytes(&remote_partition_right,
                            sizeof(remote_partition_right), i,
                            QUICKSELECT_MPI_TAG, MPI_TLS_STATUS_IGNORE);
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
                ret =
                    mpi_tls_send_bytes(&cur_pivot, sizeof(cur_pivot), i,
                            QUICKSELECT_MPI_TAG);
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
            mpi_tls_send_bytes(&partition_right, sizeof(partition_right),
                    master_rank, QUICKSELECT_MPI_TAG);
        if (ret) {
            handle_error_string(
                    "Error sending partition size from %d to %d",
                    world_rank, master_rank);
            goto exit;
        }

        ret =
            mpi_tls_recv_bytes(&cur_pivot, sizeof(cur_pivot), master_rank,
                    QUICKSELECT_MPI_TAG, MPI_TLS_STATUS_IGNORE);
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
        distributed_quickselect_helper(arr, local_length, local_start, targets,
                samples, sample_idxs, geq_target_idx, left, partition_right);
    if (ret) {
        goto exit;
    }
    /* Targets greater than pivot. */
    ret =
        distributed_quickselect_helper(arr, local_length, local_start,
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
static int distributed_quickselect(elem_t *arr, size_t local_length,
        size_t local_start, size_t *targets, struct sample *samples,
        size_t *sample_idxs, size_t num_targets) {
    int ret =
        distributed_quickselect_helper(arr, local_length, local_start, targets,
                samples, sample_idxs, num_targets, 0, local_length);
    if (ret) {
        handle_error_string("Error in distributed quickselect");
        goto exit;
    }

exit:
    return ret;
}

/* Performs a non-oblivious samplesort across all enclaves. */
static int distributed_sample_partition(elem_t *arr, elem_t *out,
        size_t local_length, size_t local_start, size_t total_length) {
    size_t src_local_start = total_length * world_rank / world_size;
    size_t src_local_length =
        total_length * (world_rank + 1) / world_size - src_local_start;
    int ret;

    if (world_size == 1) {
        memcpy(out, arr, total_length * sizeof(*out));
        return 0;
    }

    /* Construct samples to and pass to quickselect. We want an even
     * distribution of elements across all ranks. */
    size_t sample_targets[world_size - 1];
    for (size_t i = 0; i < (size_t) world_size - 1; i++) {
        sample_targets[i] = total_length * (i + 1) / world_size;
    }
    struct sample samples[world_size - 1];
    size_t sample_idxs[world_size];
    size_t sample_scan_idxs[world_size];
    mpi_tls_request_t requests[world_size];
    size_t requests_len = world_size;
    ret =
        distributed_quickselect(arr, local_length, local_start, sample_targets,
                samples, sample_idxs, world_size - 1);
    if (ret) {
        handle_error_string("Error in distributed quickselect");
        goto exit;
    }
    memcpy(&sample_scan_idxs[1], sample_idxs,
            (world_size - 1) * sizeof(*sample_scan_idxs));
    sample_idxs[world_size - 1] = local_length;
    sample_scan_idxs[0] = 0;

    /* Send elements to their corresponding enclaves. The elements in the array
     * should already be partitioned. */

    /* Copy own partition's elements to the output. */
    size_t num_received =
        sample_idxs[world_rank] - sample_scan_idxs[world_rank];
    memcpy(out, arr + sample_scan_idxs[world_rank],
            num_received * sizeof(*out));
    sample_scan_idxs[world_rank] = sample_idxs[world_rank];

    /* Construct initial requests. REQUESTS is used for all send requests except
     * for REQUESTS[WORLD_RANK], which is our receive request. */
    for (int i = 0; i < world_size; i++) {
        if (i == world_rank) {
            size_t elems_to_recv =
                MIN(src_local_length - num_received, SAMPLE_PARTITION_BUF_SIZE);
            if (elems_to_recv > 0) {
                ret =
                    mpi_tls_irecv_bytes(out + num_received,
                            elems_to_recv * sizeof(*out), MPI_TLS_ANY_SOURCE,
                            SAMPLE_PARTITION_MPI_TAG, &requests[i]);
                if (ret) {
                    handle_error_string("Error receiving partitioned data");
                    goto exit;
                }
            } else {
                requests[i].type = MPI_TLS_NULL;
                requests_len--;
            }
        } else {
            if (sample_scan_idxs[i] < sample_idxs[i]) {
                size_t elems_to_send =
                    MIN(sample_idxs[i] - sample_scan_idxs[i],
                            SAMPLE_PARTITION_BUF_SIZE);

                /* Asynchronously send to enclave. */
                ret =
                    mpi_tls_isend_bytes(arr + sample_scan_idxs[i],
                            elems_to_send * sizeof(*arr), i,
                            SAMPLE_PARTITION_MPI_TAG, &requests[i]);
                if (ret) {
                    handle_error_string("Error sending partitioned data");
                    goto exit;
                }
                sample_scan_idxs[i] += elems_to_send;
            } else {
                requests[i].type = MPI_TLS_NULL;
                requests_len--;
            }
        }
    }

    /* Get completed requests in a loop. */
    while (requests_len) {
        size_t index;
        mpi_tls_status_t status;
        ret = mpi_tls_waitany(world_size, requests, &index, &status);
        if (ret) {
            handle_error_string("Error waiting on partition requests");
            goto exit;
        }
        bool keep_rank;
        if (index == (size_t) world_rank) {
            /* Receive request completed. */
            size_t req_num_received = status.count / sizeof(*out);
            num_received += req_num_received;

            size_t elems_to_recv =
                MIN(src_local_length - num_received, SAMPLE_PARTITION_BUF_SIZE);
            keep_rank = elems_to_recv > 0;
            if (keep_rank) {
                ret =
                    mpi_tls_irecv_bytes(out + num_received,
                            elems_to_recv * sizeof(*out), MPI_TLS_ANY_SOURCE,
                            SAMPLE_PARTITION_MPI_TAG, &requests[index]);
                if (ret) {
                    handle_error_string("Error receiving partitioned data");
                    goto exit;
                }
            }
        } else {
            /* Send request completed. */

            keep_rank =
                sample_idxs[index] - sample_scan_idxs[index] > 0;

            if (keep_rank) {
                size_t elems_to_send =
                    MIN(sample_idxs[index]
                                - sample_scan_idxs[index],
                            SAMPLE_PARTITION_BUF_SIZE);

                /* Asynchronously send to enclave. */
                ret =
                    mpi_tls_isend_bytes(arr + sample_scan_idxs[index],
                            elems_to_send * sizeof(*arr), index,
                            SAMPLE_PARTITION_MPI_TAG, &requests[index]);
                if (ret) {
                    handle_error_string("Error sending partitioned data");
                    goto exit;
                }
                sample_scan_idxs[index] += elems_to_send;
            }
        }

        if (!keep_rank) {
            /* Remove the request from the array. */
            requests[index].type = MPI_TLS_NULL;
            requests_len--;
        }
    }

    assert(num_received == src_local_length);

exit:
    return ret;
}

int bucket_sort(elem_t *arr, size_t length, size_t num_threads UNUSED) {
    int ret;

    total_length = length;

    size_t src_local_start = total_length * world_rank / world_size;
    size_t src_local_length =
        total_length * (world_rank + 1) / world_size - src_local_start;
    size_t local_bucket_start = get_local_bucket_start(world_rank);
    size_t num_local_buckets =
        get_local_bucket_start(world_rank + 1) - local_bucket_start;
    size_t local_start = local_bucket_start * BUCKET_SIZE;
    size_t local_length = num_local_buckets * BUCKET_SIZE;

    elem_t *buf = arr + local_length;

#ifdef DISTRIBUTED_SGX_SORT_BENCHMARK
    struct timespec time_start;
    if (clock_gettime(CLOCK_REALTIME, &time_start)) {
        handle_error_string("Error getting time");
        ret = errno;
        goto exit;
    }
#endif /* DISTRIBUTED_SGX_SORT_BENCHMARK */

    /* Spread the elements located in the first half of our input array. */
    ret = assign_random_ids_and_spread(arr, buf, src_local_length,
            src_local_start, local_start);
    if (ret) {
        handle_error_string("Error assigning random IDs to elems");
        ret = errno;
        goto exit;
    }

#ifdef DISTRIBUTED_SGX_SORT_BENCHMARK
    struct timespec time_assign_ids;
    if (clock_gettime(CLOCK_REALTIME, &time_assign_ids)) {
        handle_error_string("Error getting time");
        ret = errno;
        goto exit;
    }
#endif /* DISTRIBUTED_SGX_SORT_BENCHMARK */

    size_t route_levels1 = log2li(world_size);
    ret = bucket_route(buf, route_levels1, 0);
    if (ret) {
        handle_error_string("Error routing elements through butterfly network");
        goto exit;
    }

    ret = distributed_bucket_route(buf, arr);
    if (ret) {
        handle_error_string("Error distributing elements in butterfly network");
        goto exit;
    }

    size_t route_levels2 = log2li(num_local_buckets);
    ret = bucket_route(buf, route_levels2, route_levels1 + route_levels2);
    if (ret) {
        handle_error_string("Error routing elements through butterfly network");
        goto exit;
    }

#ifdef DISTRIBUTED_SGX_SORT_BENCHMARK
    struct timespec time_merge_split;
    if (clock_gettime(CLOCK_REALTIME, &time_merge_split)) {
        handle_error_string("Error getting time");
        ret = errno;
        goto exit;
    }
#endif /* DISTRIBUTED_SGX_SORT_BENCHMARK */

    /* Permute each bucket and concatenate them back together by compressing all
     * real elems together. We also assign new ORP IDs so that all elements have
     * a unique tuple of (key, ORP ID), even if they have duplicate keys. */
    size_t compress_len = 0;
    {
        struct permute_and_compress_args args = {
            .arr = buf,
            .out = arr,
            .start_idx = local_start,
            .compress_idx = &compress_len,
            .ret = 0,
        };
        struct thread_work work = {
            .type = THREAD_WORK_ITER,
            .iter = {
                .func = permute_and_compress,
                .arg = &args,
                .count = num_local_buckets,
            },
        };
        thread_work_push(&work);
        thread_work_until_empty();
        thread_wait(&work);
        ret = args.ret;
        if (ret) {
            handle_error_string("Error permuting buckets");
            goto exit;
        }
    }

#ifdef DISTRIBUTED_SGX_SORT_BENCHMARK
    struct timespec time_compress;
    if (clock_gettime(CLOCK_REALTIME, &time_compress)) {
        handle_error_string("Error getting time");
        ret = errno;
        goto exit;
    }
#endif /* DISTRIBUTED_SGX_SORT_BENCHMARK */

    /* Partition permuted data such that each enclave has its own partition of
     * element, e.g. enclave 0 has the lowest elements, then enclave 1, etc. */
    ret =
        distributed_sample_partition(arr, buf, compress_len, local_start,
                length);
    if (ret) {
        handle_error_string("Error in distributed sample partitioning");
        goto exit;
    }

#ifdef DISTRIBUTED_SGX_SORT_BENCHMARK
    struct timespec time_sample_partition;
    if (clock_gettime(CLOCK_REALTIME, &time_sample_partition)) {
        handle_error_string("Error getting time");
        ret = errno;
        goto exit;
    }
#endif /* DISTRIBUTED_SGX_SORT_BENCHMARK */

    /* Sort local partitions. */
    ret = mergesort(buf, arr, src_local_length);
    if (ret) {
        handle_error_string("Error in non-oblivious local sort");
        goto exit;
    }

#ifdef DISTRIBUTED_SGX_SORT_BENCHMARK
    struct timespec time_finish;
    if (clock_gettime(CLOCK_REALTIME, &time_finish)) {
        handle_error_string("Error getting time");
        ret = errno;
        goto exit;
    }
#endif /* DISTRIBUTED_SGX_SORT_BENCHMARK */

#ifdef DISTRIBUTED_SGX_SORT_BENCHMARK
    if (world_rank == 0) {
        printf("assign_ids       : %f\n",
                get_time_difference(&time_start, &time_assign_ids));
        printf("merge_split      : %f\n",
                get_time_difference(&time_assign_ids, &time_merge_split));
        printf("compression      : %f\n",
                get_time_difference(&time_merge_split, &time_compress));
        printf("sample_partition : %f\n",
                get_time_difference(&time_compress, &time_sample_partition));
        printf("local_sort       : %f\n",
                get_time_difference(&time_sample_partition, &time_finish));
    }
#endif

exit:
    return ret;
}
