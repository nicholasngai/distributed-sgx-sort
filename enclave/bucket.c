#include "enclave/bucket.h"
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef DISTRIBUTED_SGX_SORT_BENCHMARK
#include <time.h>
#endif /* DISTRIBUTED_SGX_SORT_BENCHMARK */
#include <liboblivious/algorithms.h>
#include <liboblivious/primitives.h>
#include "common/defs.h"
#include "common/error.h"
#include "common/node_t.h"
#include "common/util.h"
#include "enclave/mpi_tls.h"
#include "enclave/parallel_enc.h"
#include "enclave/synch.h"
#include "enclave/threading.h"

/* The cache has CACHE_SETS * CACHE_ASSOCIATIVITY buckets. */
#define CACHE_SETS 16
#define CACHE_ASSOCIATIVITY 64
#define CACHE_BUCKETS (CACHE_SETS * CACHE_ASSOCIATIVITY)

#define SAMPLE_PARTITION_BUF_SIZE 512

static size_t total_length;

static unsigned char key[16];

/* Thread-local buffer used for generic operations. */
static _Thread_local node_t *buffer;

/* Cache used to store decrypted buckets in enclave memory. */
struct eviction {
    size_t idx;
    condvar_t finished;
    struct eviction *prev;
    struct eviction *next;
};
static node_t *cache;
static struct {
    spinlock_t lock;
    struct eviction *evictions;
    struct {
        bool valid;
        size_t bucket_idx;
        spinlock_t lock;
        condvar_t released;
        unsigned int acquired;
    } lines[CACHE_ASSOCIATIVITY];
} cache_meta[CACHE_SETS];
unsigned int cache_counter;

static int get_bucket_rank(size_t bucket) {
    size_t num_buckets =
        MAX(next_pow2l(total_length) * 2 / BUCKET_SIZE, world_size * 2);
    return bucket * world_size / num_buckets;
}

static size_t get_local_bucket_start(int rank) {
    size_t num_buckets =
        MAX(next_pow2l(total_length) * 2 / BUCKET_SIZE, world_size * 2);
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
    /* Initialize random. */
    if (rand_init()) {
        handle_error_string("Error initializing enclave random number generator");
        goto exit;
    }

    /* Allocate buffer. */
    buffer = malloc(BUCKET_SIZE * 2 * sizeof(*buffer));
    if (!buffer) {
        perror("Error allocating buffer");
        goto exit_free_rand;
    }

    /* Attempt to allocate buffer first by test-and-setting the pointer, which
     * should be unset (AKA NULL) if not yet allocated. */
    node_t *temp = NULL;
    if (__atomic_compare_exchange_n(&cache, &temp, (node_t *) 0x1, false,
                __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        cache =
            malloc(BUCKET_SIZE * CACHE_SETS * CACHE_ASSOCIATIVITY
                    * sizeof(*buffer));
        if (!cache) {
            perror("Error allocating cache");
            goto exit_free_rand;
        }
    }

    return 0;

exit_free_rand:
    rand_free();
exit:
    return -1;
}

void bucket_free(void) {
    /* Attempt to free buffer. */
    node_t *temp = cache;
    if (buffer) {
        if (__atomic_compare_exchange_n(&cache, &temp, NULL, false,
                    __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            free(temp);
        }
    }

    /* Free resources. */
    free(buffer);
    rand_free();
}

/* Bucket buffer management. */

#ifdef DISTRIBUTED_SGX_SORT_BUCKET_CACHE_COUNTER
static int cache_hits;
static int cache_misses;
static int cache_evictions;
#endif /* DISTRIBUTED_SGX_SORT_BUCKET_CACHE_COUNTER */

static int evict_bucket(void *arr_, size_t buffer_idx, size_t bucket_idx) {
    unsigned char *arr = arr_;
    int ret;

    size_t local_bucket_start = get_local_bucket_start(world_rank);

    for (size_t i = 0; i < BUCKET_SIZE; i++) {
        ret = node_encrypt(key, &cache[buffer_idx * BUCKET_SIZE + i],
                arr
                    + ((bucket_idx - local_bucket_start) * BUCKET_SIZE + i)
                        * SIZEOF_ENCRYPTED_NODE,
                bucket_idx * BUCKET_SIZE + i);
        if (ret) {
            handle_error_string("Error encrypting node %lu",
                    bucket_idx * BUCKET_SIZE + i);
            goto exit;
        }
    }

#ifdef DISTRIBUTED_SGX_SORT_BUCKET_CACHE_COUNTER
    __atomic_add_fetch(&cache_evictions, 1, __ATOMIC_RELAXED);
#endif /* DISTRIBUTED_SGX_SORT_BUCKET_CACHE_COUNTER */

exit:
    return ret;
}

/* Loads the bucket ARR[BUCKET_IDX - LOCAL_BUCKET_START], assuming that ARR is
 * an array of encrypted nodes such that each BUCKET_SIZE nodes i one bucket.
 * Buckets are decrypted as if ARR[0] is encrypted using START_IDX.
 *
 * The buffer is a BUCKET_ASSOCIATIVTY-way set associative cache indexed using
 * (BUCKET_IDX - LOCAL_BUCKET_START) % CACHE_SETS. This is a simple system that
 * is meant to reduce the overhead of accessing buckets as much as possible, but
 * it means that a small buffer size will lead to non-ideal multithreading
 * behaviors, since all threads share the same buffer. */
static node_t *load_bucket(void *arr_, size_t bucket_idx) {
    unsigned char *arr = arr_;

    size_t local_bucket_start = get_local_bucket_start(world_rank);
    size_t set_idx = (bucket_idx - local_bucket_start) % CACHE_SETS;

    /* Lock set in cache. */
    spinlock_lock(&cache_meta[set_idx].lock);

    /* Check eviction list and sleep until our bucket is cleared from the
     * eviction list. */
    size_t line_idx = 0;
    bool bucket_is_evicted = true;
    while (bucket_is_evicted) {
        bucket_is_evicted = false;
        struct eviction *cur_eviction = cache_meta[set_idx].evictions;
        while (cur_eviction) {
            if (cur_eviction->idx == bucket_idx) {
                bucket_is_evicted = true;
                condvar_wait(&cur_eviction->finished,
                        &cache_meta[set_idx].lock);
                break;
            }
            cur_eviction = cur_eviction->next;
        }
    }

    /* Find a bucket to lock in the set. */
    for (size_t i = 0; i < CACHE_ASSOCIATIVITY; i++) {
        /* Check for bucket already resident in cache. */
        if (cache_meta[set_idx].lines[i].valid
                && cache_meta[set_idx].lines[i].bucket_idx == bucket_idx) {
            line_idx = i;
            while (cache_meta[set_idx].lines[i].lock.locked) {
                condvar_wait(&cache_meta[set_idx].lines[i].released,
                        &cache_meta[set_idx].lock);
            }
            break;
        }

        /* Skip other locked or waited-for buckets. */
        if (cache_meta[set_idx].lines[i].lock.locked
                || cache_meta[set_idx].lines[i].released.head) {
            continue;
        }

        /* If current bucket is locked, prioritize non-locked bucket. */
        if (cache_meta[set_idx].lines[line_idx].lock.locked) {
            line_idx = i;
            continue;
        }

        /* If current bucket is invalid, we don't need to check for another
         * invalid bucket. */
        if (!cache_meta[set_idx].lines[line_idx].valid) {
            continue;
        }

        /* If current bucket is valid, check for invalid bucket or bucket with
         * earlier acquisition. */
        if (!cache_meta[set_idx].lines[i].valid
                || cache_meta[set_idx].lines[i].acquired
                    < cache_meta[set_idx].lines[line_idx].acquired) {
            line_idx = i;
            continue;
        }
    }

    /* Begin eviction process if necessary by adding to eviction list, lock the
     * bucket, and unlock the set. */
    size_t old_bucket_idx = cache_meta[set_idx].lines[line_idx].bucket_idx;
    bool was_valid = cache_meta[set_idx].lines[line_idx].valid;
    struct eviction eviction;
    if (was_valid && old_bucket_idx != bucket_idx) {
        eviction.idx = old_bucket_idx;
        condvar_init(&eviction.finished);
        eviction.prev = NULL;
        eviction.next = cache_meta[set_idx].evictions;
        if (eviction.next) {
            eviction.next->prev = &eviction;
        }
        cache_meta[set_idx].evictions = &eviction;
    }
    cache_meta[set_idx].lines[line_idx].valid = true;
    cache_meta[set_idx].lines[line_idx].bucket_idx = bucket_idx;
    cache_meta[set_idx].lines[line_idx].acquired =
        __atomic_fetch_add(&cache_counter, 1, __ATOMIC_RELAXED);
    spinlock_lock(&cache_meta[set_idx].lines[line_idx].lock);
    spinlock_unlock(&cache_meta[set_idx].lock);

    size_t cache_idx = set_idx * CACHE_ASSOCIATIVITY + line_idx;

    /* If valid, check if this was a hit. */
    if (was_valid) {
        /* If hit, return the bucket. */
        if (old_bucket_idx == bucket_idx) {
#ifdef DISTRIBUTED_SGX_SORT_BUCKET_CACHE_COUNTER
            __atomic_add_fetch(&cache_hits, 1, __ATOMIC_RELAXED);
#endif /* DISTRIBUTED_SGX_SORT_BUCKET_CACHE_COUNTER */
            return &cache[cache_idx * BUCKET_SIZE];
        }

        /* Else, evict the current bucket to host memory, then remove the bucket
         * from the eviction list. */
        int ret = evict_bucket(arr, cache_idx, old_bucket_idx);
        if (ret) {
            handle_error_string("Error evicting bucket %lu from %lu",
                    old_bucket_idx, cache_idx);
            goto exit;
        }
        spinlock_lock(&cache_meta[set_idx].lock);
        if (eviction.prev) {
            eviction.prev->next = eviction.next;
        } else {
            cache_meta[set_idx].evictions = eviction.next;
        }
        if (eviction.next) {
            eviction.next->prev = eviction.prev;
        }
        condvar_broadcast(&eviction.finished, &cache_meta[set_idx].lock);
        spinlock_unlock(&cache_meta[set_idx].lock);
    }

#ifdef DISTRIBUTED_SGX_SORT_BUCKET_CACHE_COUNTER
    __atomic_add_fetch(&cache_misses, 1, __ATOMIC_RELAXED);
#endif /* DISTRIBUTED_SGX_SORT_BUCKET_CACHE_COUNTER */

    /* If missed, decrypt the nodes from host memory and then return the pointer
     * to the buffer. */
    for (size_t i = 0; i < BUCKET_SIZE; i++) {
        int ret = node_decrypt(key, &cache[cache_idx * BUCKET_SIZE + i],
                arr
                    + ((bucket_idx - local_bucket_start) * BUCKET_SIZE + i)
                        * SIZEOF_ENCRYPTED_NODE,
                bucket_idx * BUCKET_SIZE + i);
        if (ret) {
            handle_error_string("Error decrypting node %lu",
                    bucket_idx * BUCKET_SIZE + i);
            goto exit;
        }
    }

    return &cache[cache_idx * BUCKET_SIZE];

exit:
    return NULL;
}

static void free_bucket(node_t *bucket) {
    size_t cache_idx = (uintptr_t) (bucket - cache) / BUCKET_SIZE;
    size_t set_idx = cache_idx / CACHE_ASSOCIATIVITY;
    size_t line_idx = cache_idx % CACHE_ASSOCIATIVITY;

    spinlock_lock(&cache_meta[set_idx].lock);
    spinlock_unlock(&cache_meta[set_idx].lines[line_idx].lock);
    condvar_signal(&cache_meta[set_idx].lines[line_idx].released,
            &cache_meta[set_idx].lock);
    spinlock_unlock(&cache_meta[set_idx].lock);
}

static int evict_buckets(void *arr) {
    int ret = 0;

    for (size_t i = 0; i < CACHE_SETS; i++) {
        for (size_t j = 0; j < CACHE_ASSOCIATIVITY; j++) {
            size_t cache_idx = i * CACHE_ASSOCIATIVITY + j;
            if (cache_meta[i].lines[j].valid) {
                ret = evict_bucket(arr, cache_idx,
                        cache_meta[i].lines[j].bucket_idx);
                if (ret) {
                    handle_error_string("Error evicting bucket %lu from %lu",
                            cache_meta[i].lines[j].bucket_idx, cache_idx);
                    goto exit;
                }

                cache_meta[i].lines[j].valid = false;
            }
        }
    }

exit:
    return ret;
}

/* Bucket sort. */

struct assign_random_id_args {
    const void *arr;
    void *out;
    size_t length;
    size_t src_start_idx;
    size_t result_start_idx;
    node_t *dummy_node;
    int ret;
};
static void assign_random_id(void *args_, size_t i) {
    struct assign_random_id_args *args = args_;
    const unsigned char *arr = args->arr;
    unsigned char *out = args->out;
    int ret;

    node_t *node;
    if (i % 2 == 0 && i < args->length * 2) {
        /* Decrypt index i / 2 as node. */
        node_t real_node;
        ret = node_decrypt(key, &real_node, arr + i / 2 * SIZEOF_ENCRYPTED_NODE,
                i / 2 + args->src_start_idx);
        if (ret) {
            handle_error_string("Error decrypting node %lu",
                    i + args->src_start_idx);
            goto exit;
        }

        /* Assign ORP ID and initialize node. */
        ret = rand_read(&real_node.orp_id, sizeof(real_node.orp_id));
        if (ret) {
            handle_error_string("Error assigning random ID to node %lu",
                    i + args->result_start_idx);
            goto exit;
        }
        real_node.is_dummy = false;

        node = &real_node;
    } else {
        /* Use dummy node. */
        node = args->dummy_node;
    }

    /* Encrypt to index i. */
    ret = node_encrypt(key, node, out + i * SIZEOF_ENCRYPTED_NODE,
            i + args->result_start_idx);
    if (ret) {
        handle_error_string("Error encrypting node %lu",
                i + args->result_start_idx);
        goto exit;
    }

exit:
    if (ret) {
        int expected = 0;
        __atomic_compare_exchange_n(&args->ret, &expected, ret,
                false, __ATOMIC_RELEASE, __ATOMIC_RELAXED);
    }
}

/* Assigns random ORP IDs to the encrypted nodes, whose first element is
 * encrypted with index SRC_START_IDX, in ARR and distributes them evenly over
 * the 2 * LENGTH elements in OUT, re-encrypting them according to
 * RESULT_START_IDX. Thus, ARR is assumed to be at least
 * 2 * MAX(LENGTH, BUCKET_SIZE) * SIZEOF_ENCRYPTED_NODE bytes. The result is an
 * array with real elements interspersed with dummy elements. */
// TODO Can we do the first bucket assignment scan while generating these?
static int assign_random_ids_and_spread(const void *arr, void *out,
        size_t length, size_t src_start_idx, size_t result_start_idx) {
    int ret;

    node_t dummy_node;
    memset(&dummy_node, '\0', sizeof(dummy_node));
    dummy_node.is_dummy = true;

    struct assign_random_id_args args = {
        .arr = arr,
        .out = out,
        .length = length,
        .src_start_idx = src_start_idx,
        .result_start_idx = result_start_idx,
        .dummy_node = &dummy_node,
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

/* Compare elements by the BIT_IDX bit of the ORP ID, then by dummy element
 * (real elements first). */
static int merge_split_comparator(const node_t *a, const node_t *b,
        size_t bit_idx) {
    /* Compare and obliviously swap if the BIT_IDX bit of ORP ID of node A is
     * 1 and that of node B is 0 or if the ORP IDs are the same, but node A is a
     * dummy and node B is real. */
    char bit_a = (a->orp_id >> bit_idx) & 1;
    char bit_b = (b->orp_id >> bit_idx) & 1;
    return (bit_a << 1) - (bit_b << 1) + a->is_dummy - b->is_dummy;
}

struct merge_split_swapper_aux {
    node_t *bucket1;
    node_t *bucket2;
    size_t bit_idx;
};
static void merge_split_swapper(size_t a, size_t b, void *aux_) {
    struct merge_split_swapper_aux *aux = aux_;
    node_t *node_a =
        &(a < BUCKET_SIZE ? aux->bucket1 : aux->bucket2)[a % BUCKET_SIZE];
    node_t *node_b =
        &(b < BUCKET_SIZE ? aux->bucket1 : aux->bucket2)[b % BUCKET_SIZE];
    int comp = merge_split_comparator(node_a, node_b, aux->bit_idx);
    o_memswap(node_a, node_b, sizeof(*node_a), comp > 0);
}

/* Merge BUCKET1 and BUCKET2 and split such that BUCKET1 contains all elements
 * corresponding with bit 0 and BUCKET2 contains all elements corresponding with
 * bit 1, with the bit given by the bit in BIT_IDX of the nodes' ORP IDs. Note
 * that this is a modified version of the merge-split algorithm from the paper,
 * since the elements are swapped in-place rather than being swapped between
 * different buckets on different layers. */
static int merge_split(void *arr_, size_t bucket1_idx, size_t bucket2_idx,
        size_t bit_idx) {
    int ret = -1;
    unsigned char *arr = arr_;
    int bucket1_rank = get_bucket_rank(bucket1_idx);
    int bucket2_rank = get_bucket_rank(bucket2_idx);
    bool bucket1_local = bucket1_rank == world_rank;
    bool bucket2_local = bucket2_rank == world_rank;

    /* If both buckets are remote, ignore this merge-split. */
    if (!bucket1_local && !bucket2_local) {
        ret = 0;
        goto exit;
    }

    int local_bucket_idx = bucket1_local ? bucket1_idx : bucket2_idx;
    int nonlocal_bucket_idx = bucket1_local ? bucket2_idx : bucket1_idx;
    int nonlocal_rank = bucket1_local ? bucket2_rank : bucket1_rank;

    /* Load bucket 1 nodes if local. */
    node_t *bucket1;
    if (bucket1_local) {
        bucket1 = load_bucket(arr, bucket1_idx);
        if (!bucket1) {
            handle_error_string("Error loading bucket %lu", bucket1_idx);
            ret = -1;
            goto exit;
        }
    }

    /* Load bucket 2 nodes if local. */
    node_t *bucket2;
    if (bucket2_local) {
        bucket2 = load_bucket(arr, bucket2_idx);
        if (!bucket2) {
            handle_error_string("Error loading bucket %lu", bucket2_idx);
            ret = -1;
            goto exit;
        }
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
     * receive the sent count and remote buckets from the other node. */
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
        /* If count1 > 0 and the node is a dummy element, set BIT_IDX bit of ORP
         * ID and decrement count1. Else, clear BIT_IDX bit of ORP ID. */
        bucket1[i].orp_id &= ~(bucket1[i].is_dummy << bit_idx);
        bucket1[i].orp_id |= ((bool) count1 & bucket1[i].is_dummy) << bit_idx;
        count1 -= (bool) count1 & bucket1[i].is_dummy;
    }
    for (size_t i = 0; i < BUCKET_SIZE; i++) {
        /* If count1 > 0 and the node is a dummy element, set BIT_IDX bit of ORP
         * ID and decrement count1. Else, clear BIT_IDX bit of ORP ID. */
        bucket2[i].orp_id &= ~(bucket2[i].is_dummy << bit_idx);
        bucket2[i].orp_id |= ((bool) count1 & bucket2[i].is_dummy) << bit_idx;
        count1 -= (bool) count1 & bucket2[i].is_dummy;
    }

    /* Oblivious bitonic sort elements according to BIT_IDX bit of ORP id. */
    struct merge_split_swapper_aux aux = {
        .bucket1 = bucket1,
        .bucket2 = bucket2,
        .bit_idx = bit_idx,
    };
    o_sort_generate_swaps(BUCKET_SIZE * 2, merge_split_swapper, &aux);

    /* Free bucket 1 if local. */
    if (bucket1_local) {
        free_bucket(bucket1);
    }

    /* Free bucket 2 if local. */
    if (bucket2_local) {
        free_bucket(bucket2);
    }

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
    void *arr;
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

/* Compares elements by their ORP ID. */
static int permute_comparator(const void *a_, const void *b_,
        void *aux UNUSED) {
    const node_t *a = a_;
    const node_t *b = b_;
    return (a > b) - (a < b);
}

/* Permutes the real elements in the bucket (which are guaranteed to be at the
 * beginning of the bucket) by sorting according to all bits of the ORP ID. This
 * is valid because the bin assignment used the lower bits of the ORP ID,
 * leaving the upper bits free for comparison and permutation within the bin.
 * The nodes are then written sequentially to ARR[*COMPRESS_IDX], and
 * *COMPRESS_IDX is incremented. The nodes receive new random ORP IDs. The first
 * element is assumed to have START_IDX for the purposes of decryption. */
struct permute_and_compress_args {
    const void *arr;
    void *out;
    size_t start_idx;
    size_t *compress_idx;
    int ret;
};
static void permute_and_compress(void *args_, size_t bucket_idx) {
    struct permute_and_compress_args *args = args_;
    const unsigned char *arr = args->arr;
    unsigned char *out = args->out;
    int ret;

    /* Decrypt nodes from bucket to buffer. */
    for (size_t i = 0; i < BUCKET_SIZE; i++) {
        size_t i_idx = bucket_idx * BUCKET_SIZE + i + args->start_idx;

        ret = node_decrypt(key, buffer + i,
                arr + (bucket_idx * BUCKET_SIZE + i) * SIZEOF_ENCRYPTED_NODE,
                i_idx);
        if (ret) {
            handle_error_string("Error decrypting node %lu", i_idx);
            goto exit;
        }
    }

    /* Scan for first dummy node. */
    size_t real_len = BUCKET_SIZE;
    for (size_t i = 0; i < BUCKET_SIZE; i++) {
        if (buffer[i].is_dummy) {
            real_len = i;
            break;
        }
    }

    o_sort(buffer, real_len, sizeof(*buffer), permute_comparator, NULL);

    /* Assign random ORP IDs and encrypt nodes from buffer to compressed
     * array. */
    for (size_t i = 0; i < real_len; i++) {
        /* Fetch the next index to encrypt. */
        size_t out_idx =
            __atomic_fetch_add(args->compress_idx, 1, __ATOMIC_RELAXED);

        /* Assign random ORP ID. */
        ret = rand_read(&buffer[i].orp_id, sizeof(buffer[i].orp_id));
        if (ret) {
            handle_error_string("Error assigning random ID to %lu",
                    out_idx + args->start_idx);
            goto exit;
        }

        /* Encrypt. */
        ret = node_encrypt(key, buffer + i,
                out + out_idx * SIZEOF_ENCRYPTED_NODE,
                out_idx + args->start_idx);
        if (ret) {
            handle_error_string("Error encrypting node");
            goto exit;
        }
    }

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
    const node_t *a = a_;
    const node_t *b = b_;
    int comp_key = (a->key > b->key) - (a->key < b->key);
    int comp_orp_id = (a->orp_id > b->orp_id) - (a->orp_id < b->orp_id);
    return (comp_key << 1) + comp_orp_id;
}

/* Non-oblivoius sorting. */

/* We will reuse the buffer from the ORP, so BUF_SIZE = BUCKET_SIZE * 2. WORK is
 * a buffer that will be used to store intermediate data. */
#define BUF_SIZE (BUCKET_SIZE * 2)

/* Decrypt and sort ARR[RUN_IDX * BUF_SIZE] to ARR[MIN((RUN_IDX + 1), LENGTH)],
 * where ARR[0] is encrypted with index START_IDX. The results will be stored in
 * the same location as the inputs. */
struct mergesort_first_pass_args {
    void *arr;
    size_t length;
    size_t start_idx;
    int ret;
};
static void mergesort_first_pass(void *args_, size_t run_idx) {
    struct mergesort_first_pass_args *args = args_;
    unsigned char *arr = args->arr;
    int ret;

    size_t run_start = run_idx * BUF_SIZE;
    size_t run_length = MIN(args->length - run_start, BUF_SIZE);

    /* Decrypt nodes. */
    for (size_t j = 0; j < run_length; j++) {
        ret = node_decrypt(key, &buffer[j],
                arr + (run_start + j) * SIZEOF_ENCRYPTED_NODE,
                run_start + j + args->start_idx);
        if (ret) {
            handle_error_string("Error decrypting node %lu",
                    run_start + j + args->start_idx);
            goto exit;
        }
    }

    /* Sort using libc quicksort. */
    qsort(buffer, run_length, sizeof(*buffer), mergesort_comparator);

    /* Encrypt nodes. */
    for (size_t j = 0; j < run_length; j++) {
        ret = node_encrypt(key, &buffer[j],
                arr + (run_start + j) * SIZEOF_ENCRYPTED_NODE,
                run_start + j + args->start_idx);
        if (ret) {
            handle_error_string("Error encrypting node %lu",
                    run_start + j + args->start_idx);
            goto exit;
        }
    }

exit:
    if (ret) {
        __atomic_compare_exchange_n(&args->ret, &ret, 0, false,
                __ATOMIC_RELAXED, __ATOMIC_RELAXED);
    }
    ;
}

/* Decrypt and merge each BUF_SIZE runs of length RUN_LENGTH starting at element
 * ARR[RUN_IDX * RUN_LENGTH * BUF_SIZE] and writing them to a single run of
 * length RUN_LENGTH * BUF_SIZE at OUT[RUN_IDX * RUN_LENGTH * BUF_SIZE]. If
 * LENGTH - RUN_IDX * RUN_LENGTH * BUF_SIZE is less than RUN_LENGTH * BUF_SIZE,
 * then the number of runs is reduced, and the last run is truncated. Both
 * ARR[0] and OUT[0] are encrypted with index START_IDX. */
struct mergesort_pass_args {
    void *input;
    void *output;
    size_t length;
    size_t start_idx;
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

    /* Read in the first (smallest) element from run j into
     * buffer[j]. The runs start at element i. */
    for (size_t j = 0; j < num_runs; j++) {
        ret = node_decrypt(key, &buffer[j],
                args->input
                    + (run_start + j * args->run_length)
                        * SIZEOF_ENCRYPTED_NODE,
                run_start + j * args->run_length + args->start_idx);
        if (ret) {
            handle_error_string("Error decrypting node %lu",
                    run_start + j * args->run_length + args->start_idx);
            goto exit_free_merge_indices;
        }
    }

    /* Merge the runs in the buffer and encrypt to the output array.
     * Nodes for which we have reach the end of the array are marked as
     * a dummy element, so we continue until all nodes in buffer are
     * dummy nodes. */
    size_t output_idx = 0;
    bool all_dummy;
    do {
        /* Scan for lowest node. */
        // TODO Use a heap?
        size_t lowest_run;
        all_dummy = true;
        for (size_t j = 0; j < num_runs; j++) {
            if (buffer[j].is_dummy) {
                continue;
            }
            if (all_dummy
                    || mergesort_comparator(&buffer[j],
                        &buffer[lowest_run]) < 0) {
                lowest_run = j;
            }
            all_dummy = false;
        }

        /* Break out of loop if all nodes were dummy. */
        if (all_dummy) {
            continue;
        }

        /* Encrypt lowest node to output. */
        ret = node_encrypt(key, &buffer[lowest_run],
                args->output + (run_start + output_idx) * SIZEOF_ENCRYPTED_NODE,
                run_start + output_idx + args->start_idx);
        merge_indices[lowest_run]++;
        output_idx++;

        /* Check if we have reached the end of the run. */
        if (merge_indices[lowest_run] >= args->run_length
                || run_start + lowest_run * args->run_length
                    + merge_indices[lowest_run] >= args->length) {
            /* Reached the end, so mark the node as dummy so that we
             * ignore it. */
            buffer[lowest_run].is_dummy = true;
        } else {
            /* Not yet reached the end, so read the next node in the
             * input run. */
            ret = node_decrypt(key, &buffer[lowest_run],
                    args->input
                        + (run_start + lowest_run * args->run_length +
                                merge_indices[lowest_run])
                            * SIZEOF_ENCRYPTED_NODE,
                    run_start + lowest_run * args->run_length
                        + merge_indices[lowest_run] + args->start_idx);
            if (ret) {
                handle_error_string("Error decrypting node %lu",
                        run_start + lowest_run * args->run_length
                            + merge_indices[lowest_run] + args->start_idx);
                goto exit_free_merge_indices;
            }
        }
    } while (!all_dummy);

exit_free_merge_indices:
    free(merge_indices);
exit:
    if (ret) {
        __atomic_compare_exchange_n(&args->ret, &ret, 0, false,
                __ATOMIC_RELAXED, __ATOMIC_RELAXED);
    }
    ;
}

/* Non-oblivious sort. Based on an external mergesort algorithm since decrypting
 * nodes from host memory is expensive. */
static int mergesort(void *arr_, void *out_, size_t length, size_t start_idx) {
    unsigned char *arr = arr_;
    unsigned char *out = out_;
    int ret;

    /* Start by sorting runs of BUF_SIZE. */
    struct mergesort_first_pass_args args = {
        .arr = arr,
        .length = length,
        .start_idx = start_idx,
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
    ret = args.ret;
    if (ret) {
        handle_error_string("Error in first pass of mergesort");
        goto exit;
    }

    /* Merge runs of increasing length in a BUF_SIZE-way merge by reading the
     * next smallest element of run i into buffer[i], then merging and
     * encrypting to the output buffer. */
    unsigned char *input = arr;
    unsigned char *output = out;
    for (size_t run_length = BUF_SIZE; run_length < length;
            run_length *= BUF_SIZE) {
        /* BUF_SIZE-way merge. */
        struct mergesort_pass_args args = {
            .input = input,
            .output = output,
            .length = length,
            .start_idx = start_idx,
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
        unsigned char *temp = input;
        input = output;
        output = temp;
    }

    /* If the final merging output (now the input since it would have been
     * swapped) isn't the output parameter, copy to the right place. */
    if (input != out) {
        memcpy(out, input, length * SIZEOF_ENCRYPTED_NODE);
    }

    ret = 0;

exit:
    return ret;
}

struct sample {
    uint64_t key;
    uint64_t orp_id;
};

static int node_sample_comparator(const node_t *a, const struct sample *b) {
    int comp_key = (a->key > b->key) - (a->key < b->key);
    int comp_orp_id = (a->orp_id > b->orp_id) - (a->orp_id < b->orp_id);
    return (comp_key << 1) + comp_orp_id;
}

static int distributed_quickselect_helper(void *arr, size_t local_length,
        size_t local_start, size_t *targets, struct sample *samples,
        size_t *sample_idxs, size_t num_targets, size_t left, size_t right) {
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
            ret = mpi_tls_send_bytes(flag, sizeof(*flag), i, 0);
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
                mpi_tls_recv_bytes(&is_ready, sizeof(is_ready), i, 0,
                        MPI_TLS_STATUS_IGNORE);
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
    node_t pivot_node;
    struct sample pivot;
    if (world_rank == master_rank) {
        /* Use first node as pivot. This is a random selection since this
         * samplesort should happen after ORP. */
        ret =
            node_decrypt(key, &pivot_node, arr + left * SIZEOF_ENCRYPTED_NODE,
                    left + local_start);
        if (ret) {
            handle_error_string("Error decrypting node %lu",
                    left + local_start);
            goto exit;
        }
        pivot.key = pivot_node.key;
        pivot.orp_id = pivot_node.orp_id;

        /* Send pivot to all other nodes. */
        for (int i = 0; i < world_size; i++) {
            if (i != world_rank) {
                ret = mpi_tls_send_bytes(&pivot, sizeof(pivot), i, 0);
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
            mpi_tls_recv_bytes(&pivot, sizeof(pivot), master_rank, 0,
                    MPI_TLS_STATUS_IGNORE);
        if (ret) {
            handle_error_string("Error receiving pivot into %d from %d",
                    world_rank, master_rank);
            goto exit;
        }
    }

    /* Partition data based on pivot. */
    // TODO It's possible to do this in-place.
    node_t left_node;
    node_t right_node;
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
            ret =
                node_decrypt(key, &left_node,
                    arr + partition_left * SIZEOF_ENCRYPTED_NODE,
                    partition_left + local_start);
            if (ret) {
                handle_error_string("Error decrypting node %lu",
                        partition_left + local_start);
                goto exit;
            }

            /* If found, start scanning right. */
            if (node_sample_comparator(&left_node, &pivot) > 0) {
                partition_state = PARTITION_SCAN_RIGHT;
            } else {
                partition_left++;
            }

            break;

        case PARTITION_SCAN_RIGHT:
            /* Scan right for elements less than the pivot. */
            ret =
                node_decrypt(key, &right_node,
                    arr + (partition_right - 1) * SIZEOF_ENCRYPTED_NODE,
                    partition_right - 1 + local_start);
            if (ret) {
                handle_error_string("Error decrypting node %lu",
                        partition_right - 1 + local_start);
                goto exit;
            }

            /* If found, swap and start scanning left. */
            if (node_sample_comparator(&right_node, &pivot) < 0) {
                ret =
                    node_encrypt(key, &left_node,
                            arr + (partition_right - 1) * SIZEOF_ENCRYPTED_NODE,
                            partition_right - 1 + local_start);
                if (ret) {
                    handle_error_string("Error encrypting node %lu",
                            partition_right - 1 + local_start);
                    goto exit;
                }
                ret =
                    node_encrypt(key, &right_node,
                            arr + partition_left * SIZEOF_ENCRYPTED_NODE,
                            partition_left + local_start);
                if (ret) {
                    handle_error_string("Error encrypting node %lu",
                            partition_left + local_start);
                    goto exit;
                }

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
        node_t node;
        ret = node_decrypt(key, &node,
                arr + (partition_right - 1) * SIZEOF_ENCRYPTED_NODE,
                partition_right - 1 + local_start);
        if (ret) {
            handle_error_string("Error decrypting node %lu",
                    partition_right - 1 + local_start);
            goto exit;
        }
        ret =
            node_encrypt(key, &node, arr + left * SIZEOF_ENCRYPTED_NODE,
                    left + local_start);
        if (ret) {
            handle_error_string("Error encrypting node %lu",
                    left + local_start);
            goto exit;
        }
        ret =
            node_encrypt(key, &pivot_node,
                    arr + (partition_right - 1) * SIZEOF_ENCRYPTED_NODE,
                    partition_right - 1 + local_start);
        if (ret) {
            handle_error_string("Error encrypting node %lu",
                    partition_right - 1 + local_start);
            goto exit;
        }
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
                            sizeof(remote_partition_right), i, 0,
                            MPI_TLS_STATUS_IGNORE);
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
                ret = mpi_tls_send_bytes(&cur_pivot, sizeof(cur_pivot), i, 0);
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
                    master_rank, 0);
        if (ret) {
            handle_error_string(
                    "Error sending partition size from %d to %d",
                    world_rank, master_rank);
            goto exit;
        }

        ret =
            mpi_tls_recv_bytes(&cur_pivot, sizeof(cur_pivot), master_rank, 0,
                    MPI_TLS_STATUS_IGNORE);
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
static int distributed_quickselect(void *arr, size_t local_length,
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
static int distributed_sample_partition(void *arr_, void *out_,
        size_t local_length, size_t local_start, size_t total_length) {
    unsigned char *arr = arr_;
    unsigned char *out = out_;
    size_t src_local_start = total_length * world_rank / world_size;
    size_t src_local_length =
        total_length * (world_rank + 1) / world_size - src_local_start;
    int ret;

    if (world_size == 1) {
        memcpy(out, arr, total_length * SIZEOF_ENCRYPTED_NODE);
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
    int request_ranks[world_size];
    size_t requests_len = 0;
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

    /* Allocate buffer for decrypted partitions. */
    node_t (*partition_buf)[SAMPLE_PARTITION_BUF_SIZE] =
        malloc(world_size * sizeof(*partition_buf));
    if (!partition_buf) {
        perror("malloc partition send buffer");
        ret = errno;
        goto exit;
    }

    /* Copy own partition's elements to the output. */
    size_t num_received =
        sample_idxs[world_rank] - sample_scan_idxs[world_rank];
    for (size_t i = 0; i < num_received; i++) {
        node_t node;
        ret =
            node_decrypt(key, &node,
                    arr
                        + (sample_scan_idxs[world_rank] + i)
                            * SIZEOF_ENCRYPTED_NODE,
                    sample_scan_idxs[world_rank] + i + local_start);
        if (ret) {
            handle_error_string("Error decrypting node %lu",
                    sample_scan_idxs[world_rank] + i + local_start);
            goto exit_free_buf;
        }
        ret =
            node_encrypt(key, &node, out + i * SIZEOF_ENCRYPTED_NODE,
                    i + src_local_start);
        if (ret) {
            handle_error_string("Error encrypting node %lu",
                    i + src_local_start);
            goto exit_free_buf;
        }
    }
    sample_scan_idxs[world_rank] = sample_idxs[world_rank];

    /* Construct initial requests. REQUESTS is used for all send requests except
     * for REQUESTS[WORLD_RANK], which is our receive request. */
    for (int i = 0; i < world_size; i++) {
        if (i == world_rank) {
            size_t nodes_to_recv =
                MIN(src_local_length - num_received, SAMPLE_PARTITION_BUF_SIZE);
            if (nodes_to_recv > 0) {
                ret =
                    mpi_tls_irecv_bytes(&partition_buf[i],
                            nodes_to_recv * sizeof(*partition_buf[i]),
                            MPI_TLS_ANY_SOURCE, 0, &requests[requests_len]);
                if (ret) {
                    handle_error_string("Error receiving partitioned data");
                    goto exit_free_buf;
                }
                request_ranks[requests_len] = i;
                requests_len++;
            }
        } else {
            if (sample_scan_idxs[i] < sample_idxs[i]) {
                /* Decrypt nodes. */
                size_t nodes_to_send =
                    MIN(sample_idxs[i] - sample_scan_idxs[i],
                            SAMPLE_PARTITION_BUF_SIZE);
                for (size_t j = 0; j < nodes_to_send; j++) {
                    ret =
                        node_decrypt(key, &partition_buf[i][j],
                                arr
                                    + (sample_scan_idxs[i] + j)
                                        * SIZEOF_ENCRYPTED_NODE,
                                sample_scan_idxs[i] + j + local_start);
                    if (ret) {
                        handle_error_string("Error decrypting node %lu",
                                sample_scan_idxs[i] + j);
                        goto exit_free_buf;
                    }
                }
                sample_scan_idxs[i] += nodes_to_send;

                /* Asynchronously send to enclave. */
                ret =
                    mpi_tls_isend_bytes(&partition_buf[i],
                            nodes_to_send * sizeof(*partition_buf[i]), i, 0,
                            &requests[requests_len]);
                if (ret) {
                    handle_error_string("Error sending partitioned data");
                    goto exit_free_buf;
                }

                request_ranks[requests_len] = i;
                requests_len++;
            }
        }
    }

    /* Get completed requests in a loop. */
    while (requests_len) {
        size_t index;
        mpi_tls_status_t status;
        ret = mpi_tls_waitany(requests_len, requests, &index, &status);
        if (ret) {
            handle_error_string("Error waiting on partition requests");
            goto exit_free_buf;
        }
        int request_rank = request_ranks[index];
        bool keep_rank;
        if (request_rank == world_rank) {
            /* Receive request completed. */
            size_t req_num_received =
                status.count / sizeof(*partition_buf[world_rank]);
            for (size_t i = 0; i < req_num_received; i++) {
                ret =
                    node_encrypt(key, &partition_buf[world_rank][i],
                            out + (num_received + i) * SIZEOF_ENCRYPTED_NODE,
                            num_received + i + src_local_start);
                if (ret) {
                    handle_error_string("Error encrypting node %lu",
                            num_received + src_local_start);
                    goto exit_free_buf;
                }
            }
            num_received += req_num_received;

            size_t nodes_to_recv =
                MIN(src_local_length - num_received, SAMPLE_PARTITION_BUF_SIZE);
            keep_rank = nodes_to_recv > 0;
            if (keep_rank) {
                ret =
                    mpi_tls_irecv_bytes(&partition_buf[world_rank],
                            nodes_to_recv * sizeof(*partition_buf[world_rank]),
                            MPI_TLS_ANY_SOURCE, 0, &requests[index]);
                if (ret) {
                    handle_error_string("Error receiving partitioned data");
                    goto exit_free_buf;
                }
            }
        } else {
            /* Send request completed. */

            keep_rank =
                sample_idxs[request_rank] - sample_scan_idxs[request_rank] > 0;

            if (keep_rank) {
                /* Decrypt nodes. */
                size_t nodes_to_send =
                    MIN(sample_idxs[request_rank]
                                - sample_scan_idxs[request_rank],
                            SAMPLE_PARTITION_BUF_SIZE);
                for (size_t i = 0; i < nodes_to_send; i++) {
                    ret =
                        node_decrypt(key, &partition_buf[request_rank][i],
                                arr +
                                    (sample_scan_idxs[request_rank] + i)
                                        * SIZEOF_ENCRYPTED_NODE,
                                sample_scan_idxs[request_rank]
                                    + i + local_start);
                    if (ret) {
                        handle_error_string("Error decrypting node %lu",
                                sample_scan_idxs[request_rank] + i
                                    + local_start);
                        goto exit_free_buf;
                    }
                }
                sample_scan_idxs[request_rank] += nodes_to_send;

                /* Asynchronously send to enclave. */
                ret =
                    mpi_tls_isend_bytes(&partition_buf[request_rank],
                            nodes_to_send
                                * sizeof(*partition_buf[request_rank]),
                            request_rank, 0, &requests[index]);
                if (ret) {
                    handle_error_string("Error sending partitioned data");
                    goto exit_free_buf;
                }
            }
        }

        if (!keep_rank) {
            /* Remove the request from the array. */
            memmove(&requests[index], &requests[index + 1],
                    (requests_len - (index + 1)) * sizeof(*requests));
            memmove(&request_ranks[index], &request_ranks[index + 1],
                    (requests_len - (index + 1)) * sizeof(*request_ranks));
            requests_len--;
        }
    }

    assert(num_received == src_local_length);

exit_free_buf:
    free(partition_buf);
exit:
    return ret;
}

int bucket_sort(void *arr, size_t length, size_t num_threads) {
    int ret;

    if (num_threads * 2 > CACHE_ASSOCIATIVITY) {
        handle_error_string(
                "Too many threads for the current associativity; max is %d\n",
                CACHE_ASSOCIATIVITY / 2);
        ret = -1;
        goto exit;
    }

    total_length = length;

    size_t src_local_start = total_length * world_rank / world_size;
    size_t src_local_length =
        total_length * (world_rank + 1) / world_size - src_local_start;
    size_t num_buckets = get_local_bucket_start(world_size);
    size_t num_local_buckets =
        (get_local_bucket_start(world_rank + 1)
            - get_local_bucket_start(world_rank));
    size_t local_start = get_local_bucket_start(world_rank) * BUCKET_SIZE;
    size_t local_length = num_local_buckets * BUCKET_SIZE;

    unsigned char *buf = arr + local_length * SIZEOF_ENCRYPTED_NODE;

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
        handle_error_string("Error assigning random IDs to nodes");
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

    /* Run merge-split as part of a butterfly network. This is modified from
     * the paper, since all merge-split operations will be constrained to the
     * same buckets of memory. */

    /* Merge the first log2(BUF_SIZE) levels going by chunks of BUF_SIZE, since
     * all BUF_SIZE buckets in a given chunk can be kept in the cache. For
     * example, instead of merging 0-1, 2-3, 4-5, 6-7, 0-2, 1-3, 4-6, 5-7, we
     * might do 0-1, 2-3, 0-2, 1-3 with a BUF_SIZE of 4. */
    size_t num_chunked_buckets = MIN(CACHE_BUCKETS, num_buckets);
    size_t num_chunked_levels = log2li(num_chunked_buckets);
    for (size_t chunk_start = 0; chunk_start < num_buckets;
            chunk_start += CACHE_BUCKETS) {
        for (size_t bit_idx = 0; bit_idx < num_chunked_levels; bit_idx++) {
            size_t bucket_stride = 2u << bit_idx;

            /* Create iterative task for merge split. */
            struct merge_split_idx_args args = {
                .arr = buf,
                .bit_idx = bit_idx,
                .bucket_stride = bucket_stride,
                .bucket_offset = chunk_start,
                .num_buckets = num_chunked_buckets,
            };
            struct thread_work work = {
                .type = THREAD_WORK_ITER,
                .iter = {
                    .func = merge_split_idx,
                    .arg = &args,
                    .count = num_chunked_buckets / 2,
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
    }

    /* Merge split remaining levels, when chunks of BUF_SIZE buckets can't all
     * be kept in the cache. */
    for (size_t bit_idx = num_chunked_levels; 2u << bit_idx <= num_buckets;
            bit_idx++) {
        size_t bucket_stride = 2u << bit_idx;

        /* Create iterative task for merge split. */
        struct merge_split_idx_args args = {
            .arr = buf,
            .bit_idx = bit_idx,
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
    ret = evict_buckets(buf);
    if (ret) {
        handle_error_string("Error evicting buckets");
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
     * real nodes together. We also assign new ORP IDs so that all elements have
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
    ret = mergesort(buf, arr, src_local_length, src_local_start);
    if (ret) {
        handle_error_string("Error in non-oblivious local sort");
        goto exit;
    }

    /* Release threads. */
    thread_release_all();

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

#ifdef DISTRIBUTED_SGX_SORT_BUCKET_CACHE_COUNTER
    printf("[bucket cache] Hits: %d\n", cache_hits);
    printf("[bucket cache] Misses: %d\n", cache_misses);
    printf("[bucket cache] Evictions: %d\n", cache_evictions);
#endif /* DISTRIBUTED_SGX_SORT_BUCKET_CACHE_COUNTER */

    /* Wait for all threads to exit the work function, then unrelease the
     * threads. */
    while (__atomic_load_n(&num_threads_working, __ATOMIC_ACQUIRE)) {}
    thread_unrelease_all();

exit:
    return ret;
}
