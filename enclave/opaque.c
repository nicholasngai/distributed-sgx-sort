#include "enclave/opaque.h"
#include <stdbool.h>
#include <liboblivious/primitives.h>
#include "common/defs.h"
#include "common/elem_t.h"
#include "common/error.h"
#include "enclave/mpi_tls.h"
#include "enclave/parallel_enc.h"

static unsigned char key[16];

/* Array index and world rank relationship helpers. */

static size_t total_length;

static size_t get_local_start(int rank) {
    return (rank * total_length + world_size - 1) / world_size;
}

static int swap(void *arr_, size_t a, size_t b, size_t local_start,
        bool descending) {
    unsigned char *arr = arr_;
    elem_t elem_a;
    elem_t elem_b;
    int ret;

    ret =
        elem_decrypt(key, &elem_a, arr + a * SIZEOF_ENCRYPTED_NODE,
                a + local_start);
    if (ret) {
        handle_error_string("Error decrypting elem %lu", a + local_start);
        goto exit;
    }
    ret =
        elem_decrypt(key, &elem_b, arr + b * SIZEOF_ENCRYPTED_NODE,
                b + local_start);
    if (ret) {
        handle_error_string("Error decrypting elem %lu", b + local_start);
        goto exit;
    }

    o_memswap(&elem_a, &elem_b, sizeof(elem_a),
            (elem_a.key > elem_b.key) != descending);

    ret =
        elem_encrypt(key, &elem_a, arr + a * SIZEOF_ENCRYPTED_NODE,
                a + local_start);
    if (ret) {
        handle_error_string("Error encrypting elem %lu", a + local_start);
        goto exit;
    }
    ret =
        elem_encrypt(key, &elem_b, arr + b * SIZEOF_ENCRYPTED_NODE,
                b + local_start);
    if (ret) {
        handle_error_string("Error encrypting elem %lu", b + local_start);
        goto exit;
    }

exit:
    return ret;
}

static int local_bitonic_merge(void *arr, size_t start, size_t length,
        size_t local_start, bool descending) {
    int ret;

    switch (length) {
        case 0:
        case 1:
            /* Do nothing. */
            ret = 0;
            break;

        default:
            for (size_t i = start; i < start + length / 2; i++) {
                ret = swap(arr, i, i + length / 2, local_start, descending);
                if (ret) {
                    handle_error_string("Error locally swapping %lu and %lu",
                            i + local_start, i + length / 2 + local_start);
                    goto exit;
                }
            }

            ret = local_bitonic_merge(arr, start, length / 2, local_start,
                    descending);
            if (ret) {
                handle_error_string(
                        "Error locally bitonic merging from %lu to %lu",
                        start + local_start,
                        start + length / 2 - 1 + local_start);
                goto exit;
            }
            ret =
                local_bitonic_merge(arr, start + length / 2, length / 2,
                        local_start, descending);
            if (ret) {
                handle_error_string(
                        "Error locally bitonic merging from %lu to %lu",
                        start + length / 2 + local_start,
                        start + length - 1 + local_start);
                goto exit;
            }
            break;
    }

    ret = 0;

exit:
    return ret;
}

static int local_bitonic_sort(void *arr, size_t start, size_t length,
        size_t local_start, bool descending) {
    int ret;

    switch (length) {
        case 0:
        case 1:
            /* Do nothing. */
            ret = 0;
            break;

        case 2:
            ret = swap(arr, start, start + 1, local_start, descending);
            if (ret) {
                handle_error_string("Error locally swapping %lu and %lu",
                        start + local_start, start + 1 + local_start);
                goto exit;
            }
            break;

        default:
            ret =
                local_bitonic_sort(arr, start, length / 2, local_start,
                        descending);
            if (ret) {
                handle_error_string(
                        "Error locally sorting from %lu to %lu",
                        start + local_start,
                        start + length / 2 - 1 + local_start);
                goto exit;
            }
            ret =
                local_bitonic_sort(arr, start + length / 2, length / 2,
                        local_start, !descending);
            if (ret) {
                handle_error_string("Error locally sorting from %lu to %lu",
                        start + length / 2 + local_start,
                        start + length - 1 + local_start);
                goto exit;
            }

            ret =
                local_bitonic_merge(arr, start, length, local_start,
                        descending);
            if (ret) {
                handle_error_string(
                        "Error locally bitonic merging from %lu to %lu",
                        start + local_start, start + length - 1 + local_start);
                goto exit;
            }
            break;
    }

    ret = 0;

exit:
    return ret;
}

int opaque_sort(void *arr, size_t length) {
    int ret;

    total_length = length;
    size_t local_start = get_local_start(world_rank);
    size_t local_end = get_local_start(world_rank + 1);
    size_t local_length = local_end - local_start;

    /* Initialize random. */
    ret = rand_init();
    if (ret) {
        handle_error_string("Error initializing enclave random number generator");
        goto exit;
    }

    /* Step 1: Local sort. */
    ret = local_bitonic_sort(arr, 0, local_length, local_start, false);
    if (ret) {
        handle_error_string("Error in local sort (step 1)");
        goto exit_free_rand;
    }

exit_free_rand:
    rand_free();
exit:
    return ret;
}
