#include "enclave/opaque.h"
#include <stdbool.h>
#include <string.h>
#include <liboblivious/primitives.h>
#include "common/defs.h"
#include "common/elem_t.h"
#include "common/error.h"
#include "enclave/mpi_tls.h"
#include "enclave/parallel_enc.h"

static unsigned char key[16];

/* Array index and world rank relationship helpers. */

static size_t get_local_start(size_t length, int rank) {
    return (rank * length + world_size - 1) / world_size;
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

#define TRANSPOSE_CHUNK_SIZE 4096

static int transpose(void *arr_, void *out_, size_t local_length,
        size_t local_start) {
    unsigned char *arr = arr_;
    unsigned char *out = out_;
    size_t offsets[world_size];
    mpi_tls_request_t requests[world_size];
    int request_ranks[world_size];
    size_t requests_len = world_size;
    int ret;

    elem_t (*bufs)[TRANSPOSE_CHUNK_SIZE] = malloc(world_size * sizeof(*bufs));
    if (!bufs) {
        ret = -1;
        goto exit;
    }

    /* For chunks of TRANSPOSE_CHUNK_SIZE each, decrypt elements, send them, to
     * the right nodes, and simultaneously receive them. */
    for (int rank = 0; rank < world_size; rank++) {
        if (rank == world_rank) {
            /* Decrypt elements that will end up in our own output and encrypt
             * them to their new locations. */
            size_t elems_to_decrypt = CEIL_DIV(local_length - rank, world_size);
            for (size_t i = 0; i < elems_to_decrypt; i++) {
                elem_t elem;
                ret =
                    elem_decrypt(key, &elem,
                            arr + (rank + i * world_size) * SIZEOF_ENCRYPTED_NODE,
                            (rank + i * world_size) + local_start);
                if (ret) {
                    handle_error_string("Error decrypting elem %lu",
                            (rank + i * world_size) + local_start);
                    goto exit_free_bufs;
                }
                ret =
                    elem_encrypt(key, &elem, out + i * SIZEOF_ENCRYPTED_NODE,
                            i + local_start);
                if (ret) {
                    handle_error_string("Error encrypting elem %lu",
                            i + local_start);
                    goto exit_free_bufs;
                }
            }
            offsets[rank] = elems_to_decrypt;

            /* Post receive request. */
            ret =
                mpi_tls_irecv_bytes(bufs[rank],
                        TRANSPOSE_CHUNK_SIZE * sizeof(*bufs[rank]),
                        MPI_TLS_ANY_SOURCE, 0, &requests[rank]);
            if (ret) {
                handle_error_string("Error posting receive into %d", rank);
                goto exit_free_bufs;
            }
            request_ranks[rank] = rank;
        } else {
            /* Decrypt elements with stride of world_size. */
            size_t elems_to_decrypt =
                MIN(CEIL_DIV(local_length - rank, world_size),
                        TRANSPOSE_CHUNK_SIZE);
            for (size_t i = 0; i < elems_to_decrypt; i++) {
                ret =
                    elem_decrypt(key, &bufs[rank][i],
                            arr + (rank + i * world_size) * SIZEOF_ENCRYPTED_NODE,
                            (rank + i * world_size) + local_start);
                if (ret) {
                    handle_error_string("Error decrypting elem %lu",
                            (rank + i * world_size) + local_start);
                    goto exit_free_bufs;
                }
            }
            offsets[rank] = rank + elems_to_decrypt * world_size;

            /* Post send request. */
            ret =
                mpi_tls_isend_bytes(bufs[rank],
                        elems_to_decrypt * sizeof(*bufs[rank]), rank, 0,
                        &requests[rank]);
            if (ret) {
                handle_error_string("Error posting send from %d to %d",
                        world_rank, rank);
                goto exit_free_bufs;
            }
            request_ranks[rank] = rank;
        }
    }

    /* Handle requests as they are fulfilled. */
    while (requests_len) {
        /* Wait for a request. */
        size_t index;
        mpi_tls_status_t status;
        ret = mpi_tls_waitany(requests_len, requests, &index, &status);
        if (ret) {
            handle_error_string("Error waiting for requests");
            goto exit_free_bufs;
        }

        int rank = request_ranks[index];

        if (rank == world_rank) {
            /* Receive request. */

            /* Write received data out to the buffer. */
            size_t num_recieved_elems = status.count / sizeof(*bufs[rank]);
            for (size_t i = 0; i < num_recieved_elems; i++) {
                ret =
                    elem_encrypt(key, &bufs[rank][i],
                            out + (offsets[rank] + i) * SIZEOF_ENCRYPTED_NODE,
                            offsets[rank] + i + local_start);
                if (ret) {
                    handle_error_string("Error encrypting elem %lu",
                            offsets[rank] + i + local_start);
                    goto exit_free_bufs;
                }
            }
            offsets[rank] += num_recieved_elems;

            if (offsets[rank] < local_length) {
                /* Post another receive request. */
                ret =
                    mpi_tls_irecv_bytes(bufs[rank],
                            TRANSPOSE_CHUNK_SIZE * sizeof(*bufs[rank]),
                            MPI_TLS_ANY_SOURCE, 0, &requests[index]);
                if (ret) {
                    handle_error_string("Error posting receive into %d", rank);
                    goto exit_free_bufs;
                }
            } else {
                /* Remove request. */
                memmove(requests + index, requests + index + 1,
                        (requests_len - index - 1) * sizeof(*requests));
                memmove(request_ranks + index, request_ranks + index + 1,
                        (requests_len - index - 1) * sizeof(*request_ranks));
                requests_len--;
            }
        } else {
            if (offsets[rank] < local_length) {
                /* Decrypt elements with stride of world_size. */
                size_t elems_to_decrypt =
                        MIN(CEIL_DIV(local_length - offsets[rank], world_size),
                                TRANSPOSE_CHUNK_SIZE);
                for (size_t i = 0; i < elems_to_decrypt; i++) {
                    ret =
                        elem_decrypt(key, &bufs[rank][i],
                                arr + (offsets[rank] + i * world_size) * SIZEOF_ENCRYPTED_NODE,
                                (offsets[rank] + i * world_size) + local_start);
                    if (ret) {
                        handle_error_string("Error decrypting elem %lu",
                                (offsets[rank] + i * world_size));
                        goto exit_free_bufs;
                    }
                }
                offsets[rank] += elems_to_decrypt * world_size;

                /* Post another send request. */
                ret =
                    mpi_tls_isend_bytes(bufs[rank],
                            elems_to_decrypt * sizeof(*bufs[rank]), rank, 0,
                            &requests[index]);
                if (ret) {
                    handle_error_string("Error posting send from %d to %d",
                            world_rank, rank);
                    goto exit_free_bufs;
                }
                request_ranks[rank] = rank;
            } else {
                /* Remove request. */
                memmove(requests + index, requests + index + 1,
                        (requests_len - index - 1) * sizeof(*requests));
                memmove(request_ranks + index, request_ranks + index + 1,
                        (requests_len - index - 1) * sizeof(*request_ranks));
                requests_len--;
            }
        }
    }

exit_free_bufs:
    free(bufs);
exit:
    return ret;
}

int opaque_sort(void *arr_, size_t length) {
    size_t local_start = get_local_start(length, world_rank);
    size_t local_length = get_local_start(length, world_rank + 1) - local_start;
    unsigned char *arr = arr_;
    unsigned char *buf = arr + local_length * SIZEOF_ENCRYPTED_NODE;
    int ret;

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

    /* Step 2: Transpose. */
    ret = transpose(arr, buf, local_length, local_start);
    if (ret) {
        handle_error_string("Error in transpose (step 2)");
        goto exit_free_rand;
    }

    /* Step 3: Local sort. */
    ret = local_bitonic_sort(buf, 0, local_length, local_start, false);
    if (ret) {
        handle_error_string("Error in local sort (step 3)");
        goto exit_free_rand;
    }

    /* Step 4: Transpose. */
    ret = transpose(buf, arr, local_length, local_start);
    if (ret) {
        handle_error_string("Error in transpose (step 4)");
        goto exit_free_rand;
    }

    /* Step 5: Local sort. */
    ret = local_bitonic_sort(arr, 0, local_length, local_start, false);
    if (ret) {
        handle_error_string("Error in local sort (step 5)");
        goto exit_free_rand;
    }

exit_free_rand:
    rand_free();
exit:
    return ret;
}
