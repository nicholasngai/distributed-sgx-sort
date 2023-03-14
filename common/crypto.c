#include "crypto.h"
#include <stddef.h>
#include <string.h>
#include <threads.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include "common/defs.h"
#include "common/error.h"

#ifdef DISTRIBUTED_SGX_SORT_NORDRAND
#include <mbedtls/ctr_drbg.h>
#endif

#define THREAD_LOCAL_LIST_MAXLEN 64
#define RAND_BYTES_POOL_LEN 1048576

mbedtls_entropy_context entropy_ctx;

struct thread_local_ctx {
#ifdef DISTRIBUTED_SGX_SORT_NORDRAND
    mbedtls_ctr_drbg_context drbg_ctx;
#endif
    unsigned char rand_bytes_pool[RAND_BYTES_POOL_LEN];
    size_t rand_bytes_pool_idx;
    struct thread_local_ctx **ptr;
};

static struct thread_local_ctx ctxs[THREAD_LOCAL_LIST_MAXLEN];
static size_t ctx_len;
static thread_local struct thread_local_ctx *ctx;

static int ensure_thread_local_ctx_init(void) {
    int ret;

    if (!ctx || !ctx->ptr) {
        size_t idx =
            __atomic_fetch_add(&ctx_len, 1, __ATOMIC_RELAXED);
        if (ctx_len >= THREAD_LOCAL_LIST_MAXLEN) {
            handle_error_string("Too many threads for crypto");
            __atomic_fetch_sub(&ctx_len, 1, __ATOMIC_RELAXED);
            ret = -1;
            goto exit;
        }
        ctx = &ctxs[idx];
        ctx->ptr = &ctx;

#ifdef DISTRIBUTED_SGX_SORT_NORDRAND
        mbedtls_ctr_drbg_init(&ctx->drbg_ctx);
        ret =
            mbedtls_ctr_drbg_seed(&ctx->drbg_ctx, mbedtls_entropy_func,
                    &entropy_ctx, NULL, 0);
        if (ret) {
            handle_mbedtls_error(ret, "mbedtls_ctr_drbg_seed");
            mbedtls_ctr_drbg_free(&ctx->drbg_ctx);
            __atomic_fetch_sub(&ctx_len, 1, __ATOMIC_RELAXED);
            goto exit;
        }
#endif

        ctx->rand_bytes_pool_idx = RAND_BYTES_POOL_LEN;
    }

    ret = 0;

exit:
    return ret;
}

int rand_init(void) {
    mbedtls_entropy_init(&entropy_ctx);
    return 0;
}

void rand_free(void) {
    for (size_t i = 0; i < ctx_len; i++) {
#ifdef DISTRIBUTED_SGX_SORT_NORDRAND
        mbedtls_ctr_drbg_free(&ctxs[i].drbg_ctx);
#endif
        ctxs[i].ptr = NULL;
    }
    ctx_len = 0;
    mbedtls_entropy_free(&entropy_ctx);
}

static int get_random_bytes(void *buf_, size_t n) {
    unsigned char *buf = buf_;

#ifdef DISTRIBUTED_SGX_SORT_NORDRAND
    int ret;

    ret = ensure_thread_local_ctx_init();
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
#else
    if (n % sizeof(unsigned long) || n == sizeof(unsigned long)) {
        unsigned long r;
        __asm__ __volatile__ ("0:"
                "rdrand %0;"
                "jnc 0b;"
                : "=r" (r)
                :
                : "cc");

        size_t copy_bytes = n % sizeof(r) > 0 ? n % sizeof(r) : sizeof(r);
        memcpy(buf, &r, copy_bytes);
        buf += copy_bytes;
        n -= copy_bytes;
    }

    if (n) {
        unsigned long t;
        __asm__ __volatile__ (
                "0:"
                "rdrand %2;"
                "jnc 0b;"
                "mov %2, (%0);"
                "add %3, %0;"
                "sub %3, %1;"
                "jnz 0b;"
                "1:"
                : "+r" (buf), "+rm" (n), "=&r" (t)
                : "i" (sizeof(unsigned long))
                : "memory", "cc");
    }

    return 0;
#endif
}

int rand_read(void *buf_, size_t n) {
    unsigned char *buf = buf_;
    int ret;

    ret = ensure_thread_local_ctx_init();
    if (ret) {
        goto exit;
    }

    /* For multiples of RAND_BYTES_POOL_LEN, get random bytes and put them
     * directly in the buffer, bypassing the pool. */
    if (n >= RAND_BYTES_POOL_LEN) {
        size_t bytes_to_get = n - n % RAND_BYTES_POOL_LEN;
        ret = get_random_bytes(buf, bytes_to_get);
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
            get_random_bytes(ctx->rand_bytes_pool,
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

int aad_encrypt(const void *key, const void *plaintext, size_t plaintext_len,
        const void *aad, size_t aad_len, const void *iv, void *ciphertext,
        void *tag) {
    int ret = -1;

    /* Initialize encryption context. */
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    /* Initialize key. */
    ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (ret) {
        handle_mbedtls_error(ret, "mbedtls_gcm_setkey");
        goto exit_free_ctx;
    }

    //memcpy(ciphertext, plaintext, plaintext_len);
    //ret = 0;
    //goto exit_free_ctx;

    /* Encrypt. */
    ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, plaintext_len,
            iv, IV_LEN, aad, aad_len, plaintext, ciphertext, TAG_LEN, tag);
    if (ret) {
        handle_mbedtls_error(ret, "mbedtls_gcm_crypt_and_tag");
        goto exit_free_ctx;
    }

    ret = 0;

exit_free_ctx:
    mbedtls_gcm_free(&ctx);
    return ret;
}

int aad_decrypt(const void *key, const void *ciphertext, size_t ciphertext_len,
        const void *aad, size_t aad_len, const void *iv, const void *tag,
        void *plaintext) {
    int ret = -1;

    /* Initialize encryption context. */
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    /* Initialize key. */
    ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (ret) {
        handle_mbedtls_error(ret, "mbedtls_gcm_setkey");
        goto exit_free_ctx;
    }

    //memcpy(ciphertext, plaintext, plaintext_len);
    //ret = 0;
    //goto exit_free_ctx;

    /* Decrypt. */
    ret = mbedtls_gcm_auth_decrypt(&ctx, ciphertext_len, iv, IV_LEN, aad,
            aad_len, tag, TAG_LEN, ciphertext, plaintext);
    if (ret) {
        handle_mbedtls_error(ret, "mbedtls_gcm_auth_decrypt");
        goto exit_free_ctx;
    }

    ret = 0;

exit_free_ctx:
    mbedtls_gcm_free(&ctx);
    return ret;
}
