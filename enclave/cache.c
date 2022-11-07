#include "enclave/cache.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "common/elem_t.h"
#include "common/error.h"
#include "enclave/synch.h"

static unsigned char key[16];

/* Cache used to store decrypted elements in enclave memory. */
struct eviction {
    size_t idx;
    condvar_t finished;
    struct eviction *prev;
    struct eviction *next;
};
struct cache_line {
    bool valid;
    size_t cache_idx;
    spinlock_t lock;
    bool is_loaded;
    condvar_t loaded;
    unsigned int num_writers;
    unsigned int acquired;
    elem_t elems[CACHE_LINESIZE];
};
struct cache_set {
    spinlock_t lock;
    struct eviction *evictions;
    struct cache_line lines[CACHE_ASSOCIATIVITY];
};
static struct cache_set *cache;
static unsigned int cache_counter;

#ifdef DISTRIBUTED_SGX_SORT_CACHE_COUNTER
int cache_hits;
int cache_misses;
int cache_evictions;
#endif /* DISTRIBUTED_SGX_SORT_CACHE_COUNTER */

int cache_init(void) {
    int ret;

    /* Attempt to allocate buffer first by test-and-setting the pointer, which
     * should be unset (AKA NULL) if not yet allocated. */
    struct cache_set *temp = NULL;
    if (__atomic_compare_exchange_n(&cache, &temp, (struct cache_set *) 0x1,
                false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        cache = calloc(CACHE_SETS, sizeof(*cache));
        if (!cache) {
            perror("Error allocating cache");
            ret = -1;
            goto exit;
        }
    }

    ret = 0;

exit:
    return ret;
}

void cache_free(void) {
    /* Attempt to free buffer. */
    struct cache_set *temp = cache;
    if (__atomic_compare_exchange_n(&cache, &temp, NULL, false,
                __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        free(temp);
    }
}

/* Bucket buffer management. */

static int evict_line(struct cache_line *cache_line, size_t cache_idx,
        void *arr_, size_t local_start) {
    unsigned char *arr = arr_;
    int ret;

    for (size_t i = 0; i < CACHE_LINESIZE; i++) {
        ret =
            elem_encrypt(key, &cache_line->elems[i],
                arr + (cache_idx * CACHE_LINESIZE + i)
                        * SIZEOF_ENCRYPTED_NODE,
                cache_idx * CACHE_LINESIZE + i + local_start);
        if (ret) {
            handle_error_string("Error encrypting elem %lu",
                    cache_idx * CACHE_LINESIZE + i + local_start);
            goto exit;
        }
    }

#ifdef DISTRIBUTED_SGX_SORT_CACHE_COUNTER
    __atomic_add_fetch(&cache_evictions, 1, __ATOMIC_RELAXED);
#endif /* DISTRIBUTED_SGX_SORT_CACHE_COUNTER */

exit:
    return ret;
}

/* Loads the line starting at ARR[IDX], assuming that ARR is an
 * array of encrypted elems at least IDX + CACHE_LINESIZE long. Buckets are
 * decrypted as if ARR[0] is encrypted using LOCAL_START.
 *
 * The buffer is a CACHE_ASSOCIATIVTY-way set associative cache indexed using
 * CACHE_IDX % CACHE_SETS. This is a simple system that is meant to reduce the
 * overhead of accessing cache liens as much as possible, but it means that a
 * small buffer size will lead to non-ideal multithreading behaviors, since all
 * threads share the same buffer. */
elem_t *cache_load_elems(void *arr_, size_t idx, size_t local_start) {
    unsigned char *arr = arr_;

    if (idx % CACHE_LINESIZE != 0) {
        handle_error_string(
                "Index to cache_load_elems must be a multiple of CACHE_LINESIZE");
        goto exit;
    }

    size_t cache_idx = idx / CACHE_LINESIZE;
    size_t set_idx = cache_idx % CACHE_SETS;
    struct cache_set *cache_set = &cache[set_idx];

    /* Lock set in cache. */
    spinlock_lock(&cache_set->lock);

    /* Check eviction list and sleep until our line is cleared from the eviction
     * list. */
    size_t line_idx = 0;
    bool line_is_evicted = true;
    while (line_is_evicted) {
        line_is_evicted = false;
        struct eviction *cur_eviction = cache_set->evictions;
        while (cur_eviction) {
            if (cur_eviction->idx == cache_idx) {
                line_is_evicted = true;
                condvar_wait(&cur_eviction->finished, &cache_set->lock);
                break;
            }
            cur_eviction = cur_eviction->next;
        }
    }

    /* Find a line to lock in the set. */
    for (size_t i = 0; i < CACHE_ASSOCIATIVITY; i++) {
        /* Check for line already resident in cache. */
        if (cache_set->lines[i].valid
                && cache_set->lines[i].cache_idx == cache_idx) {
            line_idx = i;
            while (!cache_set->lines[i].is_loaded) {
                condvar_wait(&cache_set->lines[i].loaded, &cache_set->lock);
            }
            break;
        }

        /* Skip other locked or waited-for lines. */
        if (cache_set->lines[i].num_writers
                || cache_set->lines[i].loaded.head
                || cache_set->lines[i].lock.locked) {
            continue;
        }

        /* If current line is occupied or locked, prioritize non-locked line. */
        if (cache_set->lines[line_idx].num_writers
                || cache_set->lines[line_idx].loaded.head
                || cache_set->lines[line_idx].lock.locked) {
            line_idx = i;
            continue;
        }

        /* If current line is invalid, we don't need to check for another
         * invalid line. */
        if (!cache_set->lines[line_idx].valid) {
            continue;
        }

        /* If current line is valid, check for invalid line or line with earlier
         * acquisition. */
        if (!cache_set->lines[i].valid
                || cache_set->lines[i].acquired
                    < cache_set->lines[line_idx].acquired) {
            line_idx = i;
            continue;
        }
    }

    struct cache_line *cache_line = &cache_set->lines[line_idx];

    /* Begin eviction process if necessary by adding to eviction list, lock the
     * line, and unlock the set. */
    size_t old_cache_idx = cache_line->cache_idx;
    bool was_valid = cache_line->valid;
    struct eviction eviction;
    if (was_valid && old_cache_idx != cache_idx) {
        eviction.idx = old_cache_idx;
        condvar_init(&eviction.finished);
        eviction.prev = NULL;
        eviction.next = cache_set->evictions;
        if (eviction.next) {
            eviction.next->prev = &eviction;
        }
        cache_set->evictions = &eviction;
    }
    cache_line->valid = true;
    cache_line->cache_idx = cache_idx;
    cache_line->is_loaded = false;
    cache_line->acquired =
        __atomic_fetch_add(&cache_counter, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&cache_line->num_writers, 1, __ATOMIC_ACQUIRE);
    spinlock_lock(&cache_line->lock);
    spinlock_unlock(&cache_set->lock);

    /* If valid, check if this was a hit. */
    if (was_valid) {
        /* If hit, return the line. */
        if (old_cache_idx == cache_idx) {
#ifdef DISTRIBUTED_SGX_SORT_CACHE_COUNTER
            __atomic_add_fetch(&cache_hits, 1, __ATOMIC_RELAXED);
#endif /* DISTRIBUTED_SGX_SORT_CACHE_COUNTER */
            cache_line->is_loaded = true;
            condvar_broadcast(&cache_line->loaded, &cache_line->lock);
            spinlock_unlock(&cache_line->lock);
            return cache_line->elems;
        }

        /* Else, evict the current line to host memory, then remove the line
         * from the eviction list. */
        int ret = evict_line(cache_line, old_cache_idx, arr, local_start);
        if (ret) {
            handle_error_string(
                    "Error evicting line %lu from set %lu line %lu", idx,
                    set_idx, line_idx);
            goto exit;
        }
        spinlock_lock(&cache_line->lock);
        if (eviction.prev) {
            eviction.prev->next = eviction.next;
        } else {
            cache_set->evictions = eviction.next;
        }
        if (eviction.next) {
            eviction.next->prev = eviction.prev;
        }
        condvar_broadcast(&eviction.finished, &cache_set->lock);
        spinlock_unlock(&cache_set->lock);
    }

#ifdef DISTRIBUTED_SGX_SORT_CACHE_COUNTER
    __atomic_add_fetch(&cache_misses, 1, __ATOMIC_RELAXED);
#endif /* DISTRIBUTED_SGX_SORT_CACHE_COUNTER */

    /* If missed, decrypt the elems from host memory and then return the pointer
     * to the buffer. */
    for (size_t i = 0; i < CACHE_LINESIZE; i++) {
        int ret = elem_decrypt(key, &cache_line->elems[i],
                arr + (cache_idx * CACHE_LINESIZE + i) * SIZEOF_ENCRYPTED_NODE,
                cache_idx * CACHE_LINESIZE + i + local_start);
        if (ret) {
            handle_error_string("Error decrypting elem %lu",
                    cache_idx * CACHE_LINESIZE + i + local_start);
            goto exit;
        }
    }

    cache_line->is_loaded = true;
    condvar_broadcast(&cache_line->loaded, &cache_line->lock);
    spinlock_unlock(&cache_line->lock);

    return cache_line->elems;

exit:
    return NULL;
}

void cache_free_elems(elem_t *elems) {
    struct cache_line *cache_line =
        (void *)((unsigned char *) elems - offsetof(struct cache_line, elems));
    __atomic_sub_fetch(&cache_line->num_writers, 1, __ATOMIC_RELEASE);
}

int cache_evictall(void *arr, size_t local_start) {
    int ret = 0;

    for (size_t i = 0; i < CACHE_SETS; i++) {
        struct cache_set *cache_set = &cache[i];
        for (size_t j = 0; j < CACHE_ASSOCIATIVITY; j++) {
            struct cache_line *cache_line = &cache_set->lines[j];
            if (cache_line->valid) {
                ret =
                    evict_line(cache_line, cache_line->cache_idx, arr,
                            local_start);
                if (ret) {
                    handle_error_string(
                            "Error evicting line %lu from set %lu line %lu",
                            cache_line->cache_idx * CACHE_LINESIZE, i, j);
                    goto exit;
                }

                cache_line->valid = false;
            }
        }
    }

exit:
    return ret;
}
