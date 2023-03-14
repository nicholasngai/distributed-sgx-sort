#include "crypto.h"
#include <stddef.h>
#include <threads.h>
#include <mbedtls/gcm.h>
#include <mbedtls/entropy.h>
#include "common/defs.h"
#include "common/error.h"

#ifdef DISTRIBUTED_SGX_SORT_NORDRAND
#include <mbedtls/ctr_drbg.h>
#endif

#define THREAD_LOCAL_LIST_MAXLEN 64

mbedtls_entropy_context entropy_ctx;

struct thread_local_ctx {
#ifdef DISTRIBUTED_SGX_SORT_NORDRAND
    mbedtls_ctr_drbg_context drbg_ctx;
#endif
    struct thread_local_ctx **ptr;
};

static struct thread_local_ctx ctxs[THREAD_LOCAL_LIST_MAXLEN];
static size_t ctx_len;
static thread_local struct thread_local_ctx *ctx;

static int UNUSED ensure_thread_local_ctx_init(void) {
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

#ifdef DISTRIBUTED_SGX_SORT_NORDRAND
int rand_read(void *buf, size_t n) {
    int ret;

    ret = ensure_thread_local_ctx_init();
    if (ret) {
        goto exit;
    }

    ret = mbedtls_ctr_drbg_random(&ctx->drbg_ctx, buf, n);
    if (ret) {
        handle_mbedtls_error(ret, "mbedtls_ctr_drbg_random");
        goto exit;
    }

    ret = 0;

exit:
    return ret;
}
#endif

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
