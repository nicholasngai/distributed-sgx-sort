#include "enclave/bucket.h"
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <threads.h>
#include <time.h>
#include <liboblivious/algorithms.h>
#include <liboblivious/primitives.h>
#include "common/crypto.h"
#include "common/defs.h"
#include "common/elem_t.h"
#include "common/error.h"
#include "common/util.h"
#include "enclave/mpi_tls.h"
#include "enclave/nonoblivious.h"
#include "enclave/parallel_enc.h"
#include "enclave/threading.h"

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

/* For output elements OUT[i * LENGTH / NUM_THREADS] to
 * OUT[(i + 1) * LENGTH / NUM_THREADS], if the index j is even, copy element
 * ARR[j / 2] to the OUT[j]. Else, mark OUT[j] as a dummy element. */
struct assign_random_id_args {
    const elem_t *arr;
    elem_t *out;
    size_t arr_length;
    size_t out_length;
    size_t result_start_idx;
    size_t num_threads;
    int ret;
};
static void assign_random_id(void *args_, size_t i) {
    struct assign_random_id_args *args = args_;
    int ret;

    size_t start = i * args->out_length / args->num_threads;
    size_t end = (i + 1) * args->out_length / args->num_threads;
    for (size_t j = start; j < end; j++) {
        if (j % 2 == 0 && j < args->arr_length * 2) {
            /* Copy elem from index j / 2 and assign ORP ID. */
            memcpy(&args->out[j], &args->arr[j / 2], sizeof(args->out[j]));
            ret = rand_read(&args->out[j].orp_id, sizeof(args->out[j].orp_id));
            if (ret) {
                handle_error_string("Error assigning random ID to elem %lu",
                        i + args->result_start_idx);
                goto exit;
            }
            args->out[j].is_dummy = false;
        } else {
            /* Use dummy elem. */
            args->out[j].is_dummy = true;
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

/* Assigns random ORP IDs to the elems in ARR and distributes them evenly over
 * the 2 * LENGTH elements in OUT. Thus, ARR is assumed to be at least
 * 2 * MAX(LENGTH, BUCKET_SIZE) bytes. The result is an array with real elements
 * interspersed with dummy elements. */
// TODO Can we do the first bucket assignment scan while generating these?
static int assign_random_ids_and_spread(const elem_t *arr, void *out,
        size_t length, size_t result_start_idx, size_t num_threads) {
    int ret;

    struct assign_random_id_args args = {
        .arr = arr,
        .out = out,
        .arr_length = length,
        .out_length = MAX(length, BUCKET_SIZE) * 2,
        .result_start_idx = result_start_idx,
        .num_threads = num_threads,
        .ret = 0,
    };
    struct thread_work work = {
        .type = THREAD_WORK_ITER,
        .iter = {
            .func = assign_random_id,
            .arg = &args,
            .count = num_threads,
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

    /* Load bucket 1 elems if local. */
    elem_t *bucket1 = NULL;
    if (bucket1_local) {
        bucket1 = arr + (bucket1_idx - local_bucket_start) * BUCKET_SIZE;
    }

    /* Load bucket 2 elems if local. */
    elem_t *bucket2 = NULL;
    if (bucket2_local) {
        bucket2 = arr + (bucket2_idx - local_bucket_start) * BUCKET_SIZE;
    }

    /* If remote, send the current count and then our local buckets. Then,
     * receive the sent count and remote buckets from the other elem. */
    if (!bucket1 || !bucket2) {
        int local_bucket_idx = bucket1_local ? bucket1_idx : bucket2_idx;
        int nonlocal_bucket_idx = bucket1_local ? bucket2_idx : bucket1_idx;
        int nonlocal_rank = bucket1_local ? bucket2_rank : bucket1_rank;

        /* Post receive for remote bucket. */
        mpi_tls_request_t bucket_request;
        ret = mpi_tls_irecv_bytes(buffer, sizeof(*buffer) * BUCKET_SIZE,
                nonlocal_rank, nonlocal_bucket_idx, &bucket_request);
        if (ret) {
            handle_error_string("Error receiving remote bucket into %d from %d",
                    world_rank, nonlocal_rank);
            goto exit;
        }
        if (bucket1) {
            bucket2 = buffer;
        } else {
            bucket1 = buffer;
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
        ret = mpi_tls_wait(&bucket_request, MPI_TLS_STATUS_IGNORE);
        if (ret) {
            handle_error_string(
                    "Error waiting on receive for bucket into %d from %d",
                    world_rank, nonlocal_rank);
            goto exit;
        }
    }

    /* Count number of elements with corresponding bit 1. */
    size_t count1 = 0;
    for (size_t i = 0; i < BUCKET_SIZE; i++) {
        /* Obliviously increment count. */
        count1 += ((bucket1[i].orp_id >> bit_idx) & 1) & !bucket1[i].is_dummy;
    }
    for (size_t i = 0; i < BUCKET_SIZE; i++) {
        /* Obliviously increment count. */
        count1 += ((bucket2[i].orp_id >> bit_idx) & 1) & !bucket2[i].is_dummy;
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
    int ret;

    size_t bucket_start = get_local_bucket_start(world_rank);
    size_t num_buckets = get_local_bucket_start(world_rank + 1) - bucket_start;
    if (1lu << num_levels > num_buckets) {
        /* If 2 ^ NUM_LEVELS > NUM_BUCKETS, we need to do some merge-splits
         * across different enclaves, so we round BUCKET_START down to the
         * nearest multiple of 2 ^ NUM_LEVELS. */
        bucket_start -= bucket_start % (1 << num_levels);
        num_buckets = 1 << num_levels;
    }
    for (size_t bit_idx = 0; bit_idx < num_levels; bit_idx++) {
        size_t bucket_stride = 2u << bit_idx;

        /* Create iterative task for merge split. */
        struct merge_split_idx_args args = {
            .arr = arr,
            .bit_idx = start_bit_idx + bit_idx,
            .bucket_stride = bucket_stride,
            .bucket_offset = bucket_start,
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

    ret = 0;

exit:
    return ret;
}

/* Distribute and receive elements from buckets in ARR to buckets in OUT.
 * Bucket i is sent to enclave i % E. */
struct distributed_bucket_route_args {
    elem_t *arr;
    elem_t *out;
    volatile size_t out_idx;
    size_t num_threads;
    volatile int ret;
};
static void distributed_bucket_route(void *args_, size_t thread_idx) {
    struct distributed_bucket_route_args *args = args_;
    elem_t *arr = args->arr;
    elem_t *out = args->out;
    volatile size_t *out_idx = &args->out_idx;
    size_t num_threads = args->num_threads;
    size_t local_bucket_start = get_local_bucket_start(world_rank);
    size_t num_local_buckets =
        get_local_bucket_start(world_rank + 1) - local_bucket_start;
    int ret;

    mpi_tls_request_t requests[world_size];
    size_t request_idxs[world_size];

    if (world_size == 1) {
        if (thread_idx == 0) {
            memcpy(out, arr, num_local_buckets * BUCKET_SIZE * sizeof(*out));
        }
        ret = 0;
        goto exit;
    }

    size_t start = thread_idx * num_local_buckets / num_threads;
    size_t end = (thread_idx + 1) * num_local_buckets / num_threads;

    /* Send and receive buckets according to the rules above. Note that we are
     * iterating by enclave instead of by bucket. */
    size_t num_requests = 0;
    for (size_t i = 0; i < (size_t) world_size; i++) {
        requests[i].type = MPI_TLS_NULL;
    }
    for (size_t i = start; i < MIN(end, start + world_size); i++) {
        int rank = (world_rank * num_local_buckets + i) % world_size;
        if (rank == world_rank) {
            /* Copy our own buckets to the output if any. */
            for (size_t j = i; j < end; j += world_size) {
                size_t copy_idx =
                    __atomic_fetch_add(out_idx, 1, __ATOMIC_RELAXED);
                memcpy(out + copy_idx * BUCKET_SIZE, arr + j * BUCKET_SIZE,
                        BUCKET_SIZE * sizeof(*out));
            }
        } else {
            /* Post a send request to the remote rank containing the first
             * bucket. */
            request_idxs[rank] = i;
            elem_t *bucket = arr + request_idxs[rank] * BUCKET_SIZE;

            ret =
                mpi_tls_isend_bytes(bucket, BUCKET_SIZE * sizeof(*bucket), rank,
                        BUCKET_DISTRIBUTE_MPI_TAG, &requests[rank]);
            if (ret) {
                handle_error_string("Error sending bucket %lu to %d from %d",
                        request_idxs[rank] + local_bucket_start, rank,
                        world_rank);
                goto exit;
            }
            num_requests++;
        }
    }

    /* Post a receive request for the current bucket. */
    size_t recv_idx = __atomic_fetch_add(out_idx, 1, __ATOMIC_RELAXED);
    if (recv_idx < num_local_buckets) {
        ret =
            mpi_tls_irecv_bytes(out + recv_idx * BUCKET_SIZE,
                    BUCKET_SIZE * sizeof(*out), MPI_TLS_ANY_SOURCE,
                    BUCKET_DISTRIBUTE_MPI_TAG, &requests[world_rank]);
        if (ret) {
            handle_error_string("Error posting receive into %d", world_rank);
            goto exit;
        }
        num_requests++;
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

            size_t recv_idx = __atomic_fetch_add(out_idx, 1, __ATOMIC_RELAXED);
            if (recv_idx < num_local_buckets) {
                /* Post receive for the next bucket. */
                ret =
                    mpi_tls_irecv_bytes(out + recv_idx * BUCKET_SIZE,
                            BUCKET_SIZE * sizeof(*out), MPI_TLS_ANY_SOURCE,
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

            request_idxs[index] += world_size;

            if (request_idxs[index] < end) {
                elem_t *bucket = arr + request_idxs[index] * BUCKET_SIZE;

                ret =
                    mpi_tls_isend_bytes(bucket, BUCKET_SIZE * sizeof(*bucket),
                            index, BUCKET_DISTRIBUTE_MPI_TAG, &requests[index]);
                if (ret) {
                    handle_error_string(
                            "Error sending bucket %lu from %d to %d",
                            request_idxs[index] + local_bucket_start,
                            world_rank, (int) index);
                    goto exit;
                }
            } else {
                /* Nullify the sending request. */
                requests[index].type = MPI_TLS_NULL;
                num_requests--;
            }
        }
    }

exit:
    if (ret) {
        int expected = 0;
        __atomic_compare_exchange_n(&args->ret, &expected, ret, false,
                __ATOMIC_RELEASE, __ATOMIC_RELAXED);
    }
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

int bucket_sort(elem_t *arr, size_t length, size_t num_threads) {
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

    struct timespec time_start;
    if (clock_gettime(CLOCK_REALTIME, &time_start)) {
        handle_error_string("Error getting time");
        ret = errno;
        goto exit;
    }

    /* Spread the elements located in the first half of our input array. */
    ret =
        assign_random_ids_and_spread(arr, buf, src_local_length, local_start,
                num_threads);
    if (ret) {
        handle_error_string("Error assigning random IDs to elems");
        ret = errno;
        goto exit;
    }

    struct timespec time_assign_ids;
    if (clock_gettime(CLOCK_REALTIME, &time_assign_ids)) {
        handle_error_string("Error getting time");
        ret = errno;
        goto exit;
    }

    size_t route_levels1 = log2li(world_size);
    ret = bucket_route(buf, route_levels1, 0);
    if (ret) {
        handle_error_string("Error routing elements through butterfly network");
        goto exit;
    }

    struct distributed_bucket_route_args args = {
        .arr = buf,
        .out = arr,
        .out_idx = 0,
        .num_threads = num_threads,
    };
    struct thread_work work = {
        .type = THREAD_WORK_ITER,
        .iter = {
            .func = distributed_bucket_route,
            .arg = &args,
            .count = num_threads,
        },
    };
    thread_work_push(&work);
    thread_work_until_empty();
    thread_wait(&work);
    ret = args.ret;
    if (ret) {
        handle_error_string("Error distributing elements in butterfly network");
        goto exit;
    }

    size_t route_levels2 = log2li(num_local_buckets);
    ret = bucket_route(arr, route_levels2, route_levels1);
    if (ret) {
        handle_error_string("Error routing elements through butterfly network");
        goto exit;
    }

    struct timespec time_merge_split;
    if (clock_gettime(CLOCK_REALTIME, &time_merge_split)) {
        handle_error_string("Error getting time");
        ret = errno;
        goto exit;
    }

    /* Permute each bucket and concatenate them back together by compressing all
     * real elems together. We also assign new ORP IDs so that all elements have
     * a unique tuple of (key, ORP ID), even if they have duplicate keys. */
    size_t compress_len = 0;
    {
        struct permute_and_compress_args args = {
            .arr = arr,
            .out = buf,
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

    struct timespec time_compress;
    if (clock_gettime(CLOCK_REALTIME, &time_compress)) {
        handle_error_string("Error getting time");
        ret = errno;
        goto exit;
    }

    /* Nonoblivious sort. */
    ret = nonoblivious_sort(buf, arr, length, compress_len, num_threads);
    if (ret) {
        handle_error_string("Error in nonoblivious sort");
        goto exit;
    }

    if (world_rank == 0) {
        printf("assign_ids       : %f\n",
                get_time_difference(&time_start, &time_assign_ids));
        printf("merge_split      : %f\n",
                get_time_difference(&time_assign_ids, &time_merge_split));
        printf("compression      : %f\n",
                get_time_difference(&time_merge_split, &time_compress));
    }

exit:
    return ret;
}
