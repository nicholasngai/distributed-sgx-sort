#include "crypto.h"
#include <stdbool.h>
#include <string.h>
#include <mbedtls/aes.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include "common/defs.h"
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
        handle_mbedtls_error(ret, "mbedtls_ctr_drbg_seed");
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
        handle_mbedtls_error(ret, "mbedtls_ctr_drbg_random");
        goto exit;
    }

    ret = 0;

exit:
    return ret;
}

int aad_encrypt(const void *key, const void *plaintext, size_t plaintext_len,
        const void *aad UNUSED, size_t aad_len UNUSED, const void *iv,
        void *ciphertext, void *tag UNUSED) {
    int ret = -1;

    /* Initialize encryption context. */
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    /* Initialize key. */
    ret = mbedtls_aes_setkey_enc(&ctx, key, 128);
    if (ret) {
        handle_mbedtls_error(ret, "mbedtls_aes_setkey");
        goto exit_free_ctx;
    }

    //memcpy(ciphertext, plaintext, plaintext_len);
    //ret = 0;
    //goto exit_free_ctx;

    /* Encrypt. */
    unsigned char iv_param[IV_LEN];
    memcpy(iv_param, iv, sizeof(iv_param));
    ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, plaintext_len,
            iv_param, plaintext, ciphertext);
    if (ret) {
        handle_mbedtls_error(ret, "mbedtls_aes_crypt_and_tag");
        goto exit_free_ctx;
    }

    ret = 0;

exit_free_ctx:
    mbedtls_aes_free(&ctx);
    return ret;
}

int aad_decrypt(const void *key, const void *ciphertext, size_t ciphertext_len,
        const void *aad UNUSED, size_t aad_len UNUSED, const void *iv,
        const void *tag UNUSED, void *plaintext) {
    int ret = -1;

    /* Initialize encryption context. */
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    /* Initialize key. */
    ret = mbedtls_aes_setkey_dec(&ctx, key, 128);
    if (ret) {
        handle_mbedtls_error(ret, "mbedtls_aes_setkey");
        goto exit_free_ctx;
    }

    //memcpy(ciphertext, plaintext, plaintext_len);
    //ret = 0;
    //goto exit_free_ctx;

    /* Decrypt. */
    unsigned char iv_param[IV_LEN];
    memcpy(iv_param, iv, sizeof(iv_param));
    ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, ciphertext_len,
            iv_param, ciphertext, plaintext);
    if (ret) {
        handle_mbedtls_error(ret, "mbedtls_aes_auth_decrypt");
        goto exit_free_ctx;
    }

    ret = 0;

exit_free_ctx:
    mbedtls_aes_free(&ctx);
    return ret;
}
