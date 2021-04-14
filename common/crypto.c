#include "crypto.h"
#include <openssl/engine.h>
#include <openssl/evp.h>

static ENGINE *rand_eng;

int rand_init(void) {
    ENGINE_load_rdrand();
    rand_eng = ENGINE_by_id("rdrand");
    if (!rand_eng) {
        goto exit;
    }

    if (!ENGINE_init(rand_eng)) {
        goto exit_free_eng;
    }

    if (!ENGINE_set_default(rand_eng, ENGINE_METHOD_RAND)) {
        goto exit_free_eng;
    }

    return 0;

exit_free_eng:
    ENGINE_finish(rand_eng);
    ENGINE_free(rand_eng);
    ENGINE_cleanup();
exit:
    return -1;
}

void rand_free(void) {
    ENGINE_finish(rand_eng);
    ENGINE_free(rand_eng);
    ENGINE_cleanup();
}

int rand_read(void *buf, size_t n) {
    int ret = -1;

    if (!RAND_bytes(buf, n)) {
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
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        goto exit;
    }

    /* Initialize encryption cipher. */
    if (EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv) != 1) {
        goto exit_free_ctx;
    }

    /* Input AAD. */
    int len;
    if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
        goto exit_free_ctx;
    }

    /* Input plaintext and output to ciphertext. */
    int ciphertext_len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext,
            plaintext_len) != 1) {
        goto exit;
    }
    ciphertext_len += len;

    /* Finalize encryption. */
    if (EVP_EncryptFinal(ctx, ciphertext + ciphertext_len, &len) != 1) {
        goto exit_free_ctx;
    }
    ciphertext_len += len;

    /* Output tag. */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
        goto exit_free_ctx;
    }

    ret = ciphertext_len;

exit_free_ctx:
    EVP_CIPHER_CTX_free(ctx);
exit:
    return ret;
}

int aad_decrypt(void *key, void *ciphertext, size_t ciphertext_len, void *aad,
        size_t aad_len, void *iv, void *tag, void *plaintext) {
    int ret = -1;

    /* Initialize decryption context. */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        goto exit;
    }

    /* Initialize decryption cipher. */
    if (EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv) != 1) {
        goto exit_free_ctx;
    }

    /* Input AAD. */
    int len;
    if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
        goto exit_free_ctx;
    }

    /* Input ciphertext and output to plaintext. */
    int plaintext_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext,
            ciphertext_len) != 1) {
        goto exit;
    }
    plaintext_len += len;

    /* Input tag. */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag)) {
        goto exit_free_ctx;
    }

    /* Finalize decryption. */
    if (EVP_DecryptFinal(ctx, plaintext + plaintext_len, &len) != 1) {
        goto exit_free_ctx;
    }
    plaintext_len += len;

    ret = plaintext_len;

exit_free_ctx:
    EVP_CIPHER_CTX_free(ctx);
exit:
    return ret;
}
