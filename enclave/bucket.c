#include "enclave/bucket.h"
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
#include "enclave/mpi_tls.h"
#include "enclave/parallel_enc.h"
#include "enclave/synch.h"
#include "enclave/threading.h"

/* The cache has CACHE_SETS * CACHE_ASSOCIATIVITY buckets. */
#define CACHE_SETS 16
#define CACHE_ASSOCIATIVITY 64
#define CACHE_BUCKETS (CACHE_SETS * CACHE_ASSOCIATIVITY)

#define ENCLAVE_MERGE_BUF_SIZE 512

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

/* Helpers. */

static long next_pow2l(long x) {
#ifdef __GNUC__
    long next = 1 << (sizeof(x) * CHAR_BIT - __builtin_clzl(x) - 1);
    if (next < x) {
        next <<= 1;
    }
    return next;
#else
    long next = 1;
    while (next < x) {
        next <<= 1;
    }
    return next;
#endif
}

static long log2li(long x) {
#ifdef __GNUC__
    return sizeof(x) * CHAR_BIT - __builtin_clzl(x) - 1;
#else
    long log = -1;
    while (x) {
        log++;
        x >>= 1;
    }
    return log;
#endif
}

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

/* Assigns random ORP IDs to the encrypted nodes, whose first element is
 * encrypted with index SRC_START_IDX, in ARR and distributes them evenly over
 * the 2 * LENGTH elements in ARR, re-encrypting them according to
 * RESULT_START_IDX. Thus, ARR is assumed to be at least
 * 2 * MAX(LENGTH, BUCKET_SIZE) * SIZEOF_ENCRYPTED_NODE bytes. The result is an
 * array with real elements interspersed with dummy elements. */
// TODO Parallelize?
// TODO Can we do the first bucket assignment scan while generating these?
static int assign_random_ids_and_spread(void *arr_, size_t length,
        size_t src_start_idx, size_t result_start_idx) {
    int ret;
    unsigned char *arr = arr_;

    node_t dummy_node;
    memset(&dummy_node, '\0', sizeof(dummy_node));
    dummy_node.is_dummy = true;

    for (size_t i = length - 1; i != SIZE_MAX; i--) {
        node_t node;

        /* Decrypt index i. */
        ret = node_decrypt(key, &node, arr + i * SIZEOF_ENCRYPTED_NODE,
                i + src_start_idx);
        if (ret) {
            handle_error_string("Error decrypting node %lu", i + src_start_idx);
            goto exit;
        }

        /* Assign ORP ID and initialize node. */
        ret = rand_read(&node.orp_id, sizeof(node.orp_id));
        if (ret) {
            handle_error_string("Error assigning random ID to node %lu",
                    2 * i + result_start_idx);
            goto exit;
        }
        node.is_dummy = false;

        /* Encrypt to index 2 * i. */
        ret = node_encrypt(key, &node, arr + 2 * i * SIZEOF_ENCRYPTED_NODE,
                2 * i + result_start_idx);
        if (ret) {
            handle_error_string("Error encrypting node %lu",
                    2 * i + result_start_idx);
            goto exit;
        }

        /* Encrypt dummy node to index 2 * i + 1. */
        ret = node_encrypt(key, &dummy_node,
                arr + (2 * i + 1) * SIZEOF_ENCRYPTED_NODE,
                2 * i + 1 + result_start_idx);
        if (ret) {
            handle_error_string("Error encrypting dummy node %lu",
                    2 * i + 1 + result_start_idx);
            goto exit;
        }
    }

    /* Pad up to 2 * bucket size. */
    for (size_t i = 2 * length; i < 2 * BUCKET_SIZE; i++) {
        ret = node_encrypt(key, &dummy_node, arr + i * SIZEOF_ENCRYPTED_NODE,
                i + result_start_idx);
        if (ret) {
            handle_error_string("Error encrypting dummy node %lu",
                    i + result_start_idx);
            goto exit;
        }
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
        ret = mpi_tls_wait(&count_request);
        if (ret) {
            handle_error_string(
                    "Error waiting on receive for count1 into %d from %d",
                    world_rank, nonlocal_rank);
            goto exit;
        }
        ret = mpi_tls_wait(&bucket_request);
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
static int permute_and_compress(void *arr_, size_t bucket,
        size_t *compress_idx, size_t start_idx) {
    int ret;
    unsigned char *arr = arr_;

    /* Decrypt nodes from bucket to buffer. */
    for (size_t i = 0; i < BUCKET_SIZE; i++) {
        size_t i_idx = bucket * BUCKET_SIZE + i + start_idx;

        ret = node_decrypt(key, buffer + i,
                arr + (bucket * BUCKET_SIZE + i) * SIZEOF_ENCRYPTED_NODE,
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
        /* Assign random ORP ID. */
        ret = rand_read(&buffer[i].orp_id, sizeof(buffer[i].orp_id));
        if (ret) {
            handle_error_string("Error assigning random ID to %lu",
                    *compress_idx + start_idx);
            goto exit;
        }

        /* Encrypt. */
        ret = node_encrypt(key, buffer + i,
                arr + *compress_idx * SIZEOF_ENCRYPTED_NODE,
                *compress_idx + start_idx);
        if (ret) {
            handle_error_string("Error encrypting node");
            goto exit;
        }
        (*compress_idx)++;
    }

exit:
    return ret;
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

struct enclave_merge_stat {
    size_t num_used;
    bool done;
};

/* Sends sequences of nodes in RUN to MERGER from low indices to high indices,
 * starting with the (*RUN_IDX)th node of RUN and decrypting according to
 * *RUN_IDX + RUN_START_IDX. After sending, listen for the next stat from
 * MERGER. When returning, *RUN_IDX is set to the index after the index that was
 * just used. BUF is a buffer of length at least ENCLAVE_MERGE_BUF_SIZE. */
static int enclave_merge_send(int merger, const void *run_, size_t *run_idx,
        size_t run_len, size_t run_start_idx, node_t *buf) {
    int ret;
    const unsigned char *run = run_;

    struct enclave_merge_stat stat;
    do {
        /* Get the next sequence of nodes starting at *RUN_IDX. */
        for (size_t i = 0; i < MIN(run_len - *run_idx, ENCLAVE_MERGE_BUF_SIZE);
                i++) {
            ret = node_decrypt(key, &buf[i],
                    run + (i + *run_idx) * SIZEOF_ENCRYPTED_NODE,
                    i + *run_idx + run_start_idx);
            if (ret) {
                handle_error_string("Error decrypting node %lu",
                        i + *run_idx + run_start_idx);
                goto exit;
            }
        }

        /* Mark dummy terminator if we reached the end. */
        if (run_len - *run_idx < ENCLAVE_MERGE_BUF_SIZE) {
            buf[run_len - *run_idx].is_dummy = true;
        }

        /* Send the nodes to the recipient. */
        ret = mpi_tls_send_bytes(buf, ENCLAVE_MERGE_BUF_SIZE * sizeof(*buf),
                merger, 0);
        if (ret) {
            handle_error_string("Error sending nodes to merge from %d to %d",
                    world_rank, merger);
            goto exit;
        }

        /* Receive the next stat. */
        ret = mpi_tls_recv_bytes(&stat, sizeof(stat), merger, 0);
        if (ret) {
            handle_error_string(
                    "Error receiving next merge action into %d from %d",
                    world_rank, merger);
            goto exit;
        }

        /* Increment the index based on how many nodes were used. */
        *run_idx += stat.num_used;
    } while (!stat.done);

    ret = 0;

exit:
    return ret;
}

/* Receives nodes from all enclaves and merges DEST_LEN nodes to DEST,
 * encrypting according to DEST_START_IDX. When receiving from self, nodes are
 * directly decrypted from RUN, using behavior identical to enclave_merge_send.
 * After merging a node, if our part of the array is full, send false to all
 * enclaves. Otherwise, send true to the enclave whose node we just used so that
 * they send their next lowest node. BUF is a buffer of length at least
 * WORLD_SIZE * ENCLAVE_MERGE_BUF_SIZE. */
static int enclave_merge_recv(void *dest_, size_t dest_len,
        size_t dest_start_idx, const void *run_, size_t *run_idx,
        size_t run_len, size_t run_start_idx, node_t *buf_) {
    int ret;
    unsigned char *dest = dest_;
    const unsigned char *run = run_;
    node_t (*buf)[ENCLAVE_MERGE_BUF_SIZE] =
        (node_t (*)[ENCLAVE_MERGE_BUF_SIZE]) buf_;

    /* Receive first sequences of nodes from all enclaves. */
    for (int i = 0; i < world_size; i++) {
        if (i == world_rank) {
            if (*run_idx < run_len) {
                /* Decrypt node from self. */
                ret = node_decrypt(key, &buf[i][0],
                        run + *run_idx * SIZEOF_ENCRYPTED_NODE,
                        *run_idx + run_start_idx);
                if (ret) {
                    handle_error_string("Error decrypting node %lu",
                            *run_idx + run_start_idx);
                    goto exit;
                }
            } else {
                /* Mark dummy terminator. */
                buf[i][0].is_dummy = true;
            }
        } else {
            /* Receive node sent from enclave_merge_send. */
            ret = mpi_tls_recv_bytes(&buf[i], sizeof(buf[i]), i, 0);
            if (ret) {
                handle_error_string(
                        "Error receiving node to merge into %d from %d",
                        world_rank, i);
                goto exit;
            }
        }
    }

    /* Write nodes until we reach the end of the buffer. */
    int lowest_idx = -1;
    size_t *merge_indices = malloc(world_size * sizeof(*merge_indices));
    if (!merge_indices) {
        goto exit;
    }
    memset(merge_indices, '\0', world_size * sizeof(*merge_indices));
    for (size_t i = 0; i < dest_len; i++) {
        /* Scan for the lowest node. */
        lowest_idx = -1;
        // TODO Use a heap?
        for (int j = 0; j < world_size; j++) {
            if (!buf[j][merge_indices[j]].is_dummy
                    && (lowest_idx == -1
                        || buf[j][merge_indices[j]].key
                            < buf[lowest_idx][merge_indices[lowest_idx]].key)) {
                lowest_idx = j;
            }
        }

        /* Encrypt the lowest index to the output. */
        ret = node_encrypt(key, &buf[lowest_idx][merge_indices[lowest_idx]],
                dest + i * SIZEOF_ENCRYPTED_NODE, i + dest_start_idx);
        if (ret) {
            handle_error_string("Error encrypting node %lu",
                    i + dest_start_idx);
            goto exit_free_merge_indices;
        }

        if (lowest_idx == world_rank) {
            /* If we used our own node, increment our run index. */
            (*run_idx)++;
        } else {
            /* Increment the merge index of the received run we used. */
            merge_indices[lowest_idx]++;
        }

        /* If we haven't reached the end, get the next node if necessary. */
        if (i < dest_len - 1) {
            if (lowest_idx == world_rank) {
                if (*run_idx < run_len) {
                    /* Decrypt node from self. */
                    ret = node_decrypt(key, &buf[lowest_idx][0],
                            run + *run_idx * SIZEOF_ENCRYPTED_NODE,
                            *run_idx + run_start_idx);
                    if (ret) {
                        handle_error_string("Error decrypting node %lu",
                                *run_idx + run_start_idx);
                        goto exit_free_merge_indices;
                    }
                } else {
                    /* Mark dummy terminator. */
                    buf[lowest_idx][0].is_dummy = true;
                }
            } else if (merge_indices[lowest_idx] == ENCLAVE_MERGE_BUF_SIZE) {
                /* For remote nodes, send a status message to the enclave whose
                 * node we used to send the next node, then receive the node. */
                struct enclave_merge_stat stat = {
                    .num_used = merge_indices[lowest_idx],
                    .done = false,
                };
                ret = mpi_tls_send_bytes(&stat, sizeof(stat), lowest_idx, 0);
                if (ret) {
                    handle_error_string(
                            "Error sending continue merge stat from %d to %d",
                            world_rank, lowest_idx);
                    goto exit_free_merge_indices;
                }
                ret = mpi_tls_recv_bytes(&buf[lowest_idx],
                        sizeof(buf[lowest_idx]), lowest_idx, 0);
                if (ret) {
                    handle_error_string(
                            "Error receiving next node to merge into %d from %d",
                            world_rank, lowest_idx);
                    goto exit_free_merge_indices;
                }
                merge_indices[lowest_idx] = 0;
            }
        }
    }

    /* Send the finished status to all enclaves. If we used the enclave's node
     * last (corresponding to lowest_idx), send the appropriate, different
     * message. */
    for (int i = 0; i < world_size; i++) {
        if (i == world_rank) {
            /* Skip ourselves. */
            continue;
        }

        /* Send finish states. */
        struct enclave_merge_stat stat = {
            .num_used = merge_indices[i],
            .done = true,
        };
        ret = mpi_tls_send_bytes(&stat, sizeof(stat), i, 0);
        if (ret) {
            handle_error_string(
                    "Error sending finished merge stat from %d to %d",
                    world_rank, lowest_idx);
            goto exit_free_merge_indices;
        }
    }

    ret = 0;

exit_free_merge_indices:
    free(merge_indices);
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

#ifdef DISTRIBUTED_SGX_SORT_BENCHMARK
    struct timespec time_start;
    if (clock_gettime(CLOCK_REALTIME, &time_start)) {
        handle_error_string("Error getting time");
        ret = errno;
        goto exit;
    }
#endif /* DISTRIBUTED_SGX_SORT_BENCHMARK */

    /* Spread the elements located in the first half of our input array. */
    ret = assign_random_ids_and_spread(arr, src_local_length, src_local_start,
            local_start);
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
    size_t num_chunked_levels = log2li(MIN(CACHE_BUCKETS, num_buckets));
    for (size_t chunk_start = 0; chunk_start < num_buckets;
            chunk_start += CACHE_BUCKETS) {
        for (size_t bit_idx = 0; bit_idx < num_chunked_levels; bit_idx++) {
            size_t bucket_stride = 2u << bit_idx;

            /* Create iterative task for merge split. */
            struct merge_split_idx_args args = {
                .arr = arr,
                .bit_idx = bit_idx,
                .bucket_stride = bucket_stride,
                .bucket_offset = chunk_start,
                .num_buckets = CACHE_BUCKETS,
            };
            struct thread_work work = {
                .type = THREAD_WORK_ITER,
                .iter = {
                    .func = merge_split_idx,
                    .arg = &args,
                    .count = CACHE_BUCKETS / 2,
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
            .arr = arr,
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
    ret = evict_buckets(arr);
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
    for (size_t bucket = 0; bucket < num_local_buckets; bucket++) {
        ret = permute_and_compress(arr, bucket, &compress_len, local_start);
        if (ret) {
            handle_error_string("Error permuting bucket %lu\n", bucket);
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

    /* Non-oblivious, comparison-based sort for the local portion. Use the
     * second half of the host array as the output. */
    unsigned char *sorted_out = arr + local_length * SIZEOF_ENCRYPTED_NODE;
    ret = mergesort(arr, sorted_out, compress_len, local_start);
    if (ret) {
        handle_error_string("Error in non-oblivious sort");
        goto exit;
    }

#ifdef DISTRIBUTED_SGX_SORT_BENCHMARK
    struct timespec time_local_sort;
    if (clock_gettime(CLOCK_REALTIME, &time_local_sort)) {
        handle_error_string("Error getting time");
        ret = errno;
        goto exit;
    }
#endif /* DISTRIBUTED_SGX_SORT_BENCHMARK */

    if (world_size == 1) {
        /* Copy the single run in our mergesort output to the input. */
        memcpy(arr, sorted_out, compress_len * SIZEOF_ENCRYPTED_NODE);
    } else {
        /* Non-oblivious merges across all enclaves to produce the final sorted
         * output, using the sorted data in the second half of the host array as
         * input. */
        size_t run_idx = 0;
        node_t *buf =
            malloc(world_size * ENCLAVE_MERGE_BUF_SIZE * sizeof(*buf));
        if (!buf) {
            perror("malloc merge buffer");
            ret = errno;
            goto exit;
        }
        for (int rank = 0; rank < world_size; rank++) {
            if (rank == world_rank) {
                ret = enclave_merge_recv(arr, src_local_length, src_local_start,
                        sorted_out, &run_idx, compress_len, local_start, buf);
                if (ret) {
                    handle_error_string("Error in enclave merge receive");
                    goto exit_merge;
                }
            } else {
                ret = enclave_merge_send(rank, sorted_out, &run_idx,
                        compress_len, local_start, buf);
                if (ret) {
                    handle_error_string("Error in enclave merge send");
                    goto exit_merge;
                }
            }
        }
exit_merge:
        free(buf);
        if (ret) {
            goto exit;
        }
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
        printf("assign_ids   : %f\n",
                get_time_difference(&time_start, &time_assign_ids));
        printf("merge_split  : %f\n",
                get_time_difference(&time_assign_ids, &time_merge_split));
        printf("compression  : %f\n",
                get_time_difference(&time_merge_split, &time_compress));
        printf("local_sort   : %f\n",
                get_time_difference(&time_compress, &time_local_sort));
        printf("enclave_merge: %f\n",
                get_time_difference(&time_local_sort, &time_finish));
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
