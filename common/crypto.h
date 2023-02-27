#ifndef DISTRIBUTED_SGX_SORT_COMMON_CRYPTO_H
#define DISTRIBUTED_SGX_SORT_COMMON_CRYPTO_H

#include <stddef.h>
#include <mbedtls/entropy.h>

#ifndef DISTRIBUTED_SGX_SORT_NORDRAND
#include <string.h>
#endif

#define IV_LEN 12
#define TAG_LEN 16

extern mbedtls_entropy_context entropy_ctx;

int rand_init(void);
void rand_free(void);

#ifndef DISTRIBUTED_SGX_SORT_NORDRAND
static inline int rand_read(void *buf_, size_t n) {
    unsigned char *buf = buf_;

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
                "add %4, %0;"
                "sub %4, %1;"
                "jnz 0b;"
                "1:"
                : "+r" (buf), "+rm" (n), "=&r" (t)
                : "i" (sizeof(unsigned long))
                : "memory", "cc");
    }

    return 0;
}
#else
int rand_read(void *buf, size_t n);
#endif

int aad_encrypt(const void *key, const void *plaintext, size_t plaintext_len,
        const void *aad, size_t aad_len, const void *iv, void *ciphertext,
        void *tag);
int aad_decrypt(const void *key, const void *ciphertext, size_t ciphertext_len,
        const void *aad, size_t aad_len, const void *iv, const void *tag,
        void *plaintext);

#endif /* distributed-sgx-sort/common/crypto.h */
