#ifndef DISTRIBUTED_SGX_SORT_COMMON_CRYPTO_H
#define DISTRIBUTED_SGX_SORT_COMMON_CRYPTO_H

#include <stddef.h>
#include <mbedtls/entropy.h>

#define IV_LEN 12
#define TAG_LEN 16

extern mbedtls_entropy_context entropy_ctx;

int rand_init(void);
void rand_free(void);
int rand_read(void *buf, size_t n);

int aad_encrypt(const void *key, const void *plaintext, size_t plaintext_len,
        const void *aad, size_t aad_len, const void *iv, void *ciphertext,
        void *tag);
int aad_decrypt(const void *key, const void *ciphertext, size_t ciphertext_len,
        const void *aad, size_t aad_len, const void *iv, const void *tag,
        void *plaintext);

#endif /* distributed-sgx-sort/common/crypto.h */
