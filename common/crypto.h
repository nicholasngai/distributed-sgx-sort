#ifndef DISTRIBUTED_SGX_SORT_COMMON_CRYPTO_H
#define DISTRIBUTED_SGX_SORT_COMMON_CRYPTO_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include "common/defs.h"
#include "common/error.h"

#define IV_LEN 12
#define TAG_LEN 16

#define THREAD_LOCAL_LIST_MAXLEN 64
#define RAND_BYTES_POOL_LEN 1048576

extern mbedtls_entropy_context entropy_ctx;

struct thread_local_ctx {
    mbedtls_ctr_drbg_context drbg_ctx;
    unsigned char rand_bytes_pool[RAND_BYTES_POOL_LEN];
    size_t rand_bytes_pool_idx;
    unsigned long rand_bits;
    size_t rand_bits_left;
    struct thread_local_ctx **ptr;
};

extern struct thread_local_ctx ctxs[THREAD_LOCAL_LIST_MAXLEN];
extern size_t ctx_len;
extern _Thread_local struct thread_local_ctx *ctx;

static inline int crypto_ensure_thread_local_ctx_init(void) {
    int ret;

    if (!ctx || !ctx->ptr) {
        size_t idx =
            __atomic_fetch_add(&ctx_len, 1, __ATOMIC_RELAXED);
        if (ctx_len >= THREAD_LOCAL_LIST_MAXLEN) {
            handle_error_string("Too many threads for crypto");
            ret = -1;
            goto exit_dec_ctx_len;
        }
        ctx = &ctxs[idx];
        ctx->ptr = &ctx;

        mbedtls_ctr_drbg_init(&ctx->drbg_ctx);
        ret =
            mbedtls_ctr_drbg_seed(&ctx->drbg_ctx, mbedtls_entropy_func,
                    &entropy_ctx, NULL, 0);
        if (ret) {
            handle_mbedtls_error(ret, "mbedtls_ctr_drbg_seed");
            goto exit_free_ctr_drbg;
        }
    }

    return 0;

exit_free_ctr_drbg:
    mbedtls_ctr_drbg_free(&ctx->drbg_ctx);
exit_dec_ctx_len:
    __atomic_fetch_sub(&ctx_len, 1, __ATOMIC_RELAXED);
    ctx = NULL;
    return ret;
}

int rand_init(void);
void rand_free(void);

static inline int rand_get_random_bytes(void *buf_, size_t n) {
    unsigned char *buf = buf_;

    int ret;

    ret = crypto_ensure_thread_local_ctx_init();
    if (ret) {
        goto exit;
    }

    while (n) {
        size_t bytes_to_get = MIN(n, MBEDTLS_CTR_DRBG_MAX_REQUEST);
        ret = mbedtls_ctr_drbg_random(&ctx->drbg_ctx, buf, bytes_to_get);
        if (ret) {
            handle_mbedtls_error(ret, "mbedtls_ctr_drbg_random");
            goto exit;
        }
        buf += bytes_to_get;
        n -= bytes_to_get;
    }

    ret = 0;

exit:
    return ret;
}

static inline int rand_read(void *buf_, size_t n) {
    unsigned char *buf = buf_;
    int ret;

    ret = crypto_ensure_thread_local_ctx_init();
    if (ret) {
        goto exit;
    }

    /* For multiples of RAND_BYTES_POOL_LEN, get random bytes and put them
     * directly in the buffer, bypassing the pool. */
    if (n >= RAND_BYTES_POOL_LEN) {
        size_t bytes_to_get = n - n % RAND_BYTES_POOL_LEN;
        ret = rand_get_random_bytes(buf, bytes_to_get);
        if (ret) {
            handle_error_string("Error getting new random bytes");
            goto exit;
        }
        buf += bytes_to_get;
        n -= bytes_to_get;
    }

    /* For remaining bytes < RAND_BYTES_POOL_LEN, copy any bytes we have
     * remaining in the pool. */
    size_t bytes_to_get =
        MIN(n, RAND_BYTES_POOL_LEN - ctx->rand_bytes_pool_idx);
    memcpy(buf, ctx->rand_bytes_pool + ctx->rand_bytes_pool_idx, bytes_to_get);
    buf += bytes_to_get;
    n -= bytes_to_get;
    ctx->rand_bytes_pool_idx += bytes_to_get;

    /* If there are still bytes left, replenish the pool and copy the remainder.
     * This should only be the case once since n < RAND_BYTES_POOL_LEN. */
    if (n) {
        ret =
            rand_get_random_bytes(ctx->rand_bytes_pool,
                    sizeof(ctx->rand_bytes_pool));
        if (ret) {
            handle_error_string("Error getting new random bytes");
            goto exit;
        }
        ctx->rand_bytes_pool_idx = 0;

        memcpy(buf, ctx->rand_bytes_pool, n);
        buf += n;
        n -= n;
        ctx->rand_bytes_pool_idx += n;
    }

exit:
    return ret;
}

static inline int rand_bit(bool *bit) {
    int ret;

    ret = crypto_ensure_thread_local_ctx_init();
    if (ret) {
        goto exit;
    }

    if (ctx->rand_bits_left == 0) {
        ret = rand_read(&ctx->rand_bits, sizeof(ctx->rand_bits));
        if (ret) {
            goto exit;
        }
        ctx->rand_bits_left = sizeof(ctx->rand_bits) * CHAR_BIT;
    }

    *bit = ctx->rand_bits & 1;
    ctx->rand_bits >>= 1;

exit:
    return ret;
}

int aad_encrypt(const void *key, const void *plaintext, size_t plaintext_len,
        const void *aad, size_t aad_len, const void *iv, void *ciphertext,
        void *tag);
int aad_decrypt(const void *key, const void *ciphertext, size_t ciphertext_len,
        const void *aad, size_t aad_len, const void *iv, const void *tag,
        void *plaintext);

#endif /* distributed-sgx-sort/common/crypto.h */
