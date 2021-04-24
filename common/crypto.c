#include "crypto.h"
#include <mbedtls/gcm.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <stdbool.h>
#include "common/error.h"
//#include <string.h>

mbedtls_entropy_context entropy_ctx;
static _Thread_local mbedtls_ctr_drbg_context drbg_ctx;

int entropy_init(void) {
    mbedtls_entropy_init(&entropy_ctx);
    return 0;
}

void entropy_free(void) {
    mbedtls_entropy_free(&entropy_ctx);
}

int rand_init(void) {
    int ret;

    mbedtls_ctr_drbg_init(&drbg_ctx);
    ret = mbedtls_ctr_drbg_seed(&drbg_ctx, mbedtls_entropy_func, &entropy_ctx,
            NULL, 0);
    if (ret) {
        handle_mbedtls_error(ret);
    }

    return ret;
}

void rand_free(void) {
    mbedtls_ctr_drbg_free(&drbg_ctx);
}

int rand_read(void *buf, size_t n) {
    int ret = -1;

    ret = mbedtls_ctr_drbg_random(&drbg_ctx, buf, n);
    if (ret) {
        handle_mbedtls_error(ret);
        goto exit;
    }

    ret = 0;

exit:
    return ret;
}

int aad_encrypt(void *key, void *plaintext, size_t plaintext_len, void *aad,
        size_t aad_len, void *iv, void *ciphertext, void *tag) {
    int ret = -1;

    /* Initialize encryption context. */
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    /* Initialize key. */
    ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (ret) {
        handle_mbedtls_error(ret);
        goto exit_free_ctx;
    }

    //memcpy(ciphertext, plaintext, plaintext_len);
    //ret = 0;
    //goto exit_free_ctx;

    /* Encrypt. */
    ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, plaintext_len,
            iv, IV_LEN, aad, aad_len, plaintext, ciphertext, TAG_LEN, tag);
    if (ret) {
        handle_mbedtls_error(ret);
        goto exit_free_ctx;
    }

    ret = 0;

exit_free_ctx:
    mbedtls_gcm_free(&ctx);
    return ret;
}

int aad_decrypt(void *key, void *ciphertext, size_t ciphertext_len, void *aad,
        size_t aad_len, void *iv, void *tag, void *plaintext) {
    int ret = -1;

    /* Initialize encryption context. */
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    /* Initialize key. */
    ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (ret) {
        handle_mbedtls_error(ret);
        goto exit_free_ctx;
    }

    //memcpy(ciphertext, plaintext, plaintext_len);
    //ret = 0;
    //goto exit_free_ctx;

    /* Decrypt. */
    ret = mbedtls_gcm_auth_decrypt(&ctx, ciphertext_len, iv, IV_LEN, aad,
            aad_len, tag, TAG_LEN, ciphertext, plaintext);
    if (ret) {
        handle_mbedtls_error(ret);
        goto exit_free_ctx;
    }

    ret = 0;

exit_free_ctx:
    mbedtls_gcm_free(&ctx);
    return ret;
}
