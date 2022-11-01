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

#define CHUNK_SIZE 4096

static int transpose(void *arr_, void *out_, size_t local_length,
        size_t local_start, bool reverse) {
    unsigned char *arr = arr_;
    unsigned char *out = out_;
    size_t offsets[world_size];
    mpi_tls_request_t requests[world_size];
    size_t requests_len = world_size;
    int ret;

    elem_t (*bufs)[CHUNK_SIZE] = malloc(world_size * sizeof(*bufs));
    if (!bufs) {
        ret = -1;
        goto exit;
    }

    /* For chunks of CHUNK_SIZE each, decrypt elements and send them, to the
     * right nodes, and simultaneously receive them. */
    for (int rank = 0; rank < world_size; rank++) {
        if (rank == world_rank) {
            /* Decrypt elements that will end up in our own output and encrypt
             * them to their new locations. */
            size_t elems_to_decrypt = local_length / world_size;
            for (size_t i = 0; i < elems_to_decrypt; i++) {
                elem_t elem;
                size_t decrypt_offset =
                    !reverse
                        ? rank + i * world_size
                        : rank * local_length / world_size + i;
                ret =
                    elem_decrypt(key, &elem,
                            arr + decrypt_offset * SIZEOF_ENCRYPTED_NODE,
                            decrypt_offset + local_start);
                if (ret) {
                    handle_error_string("Error decrypting elem %lu",
                            decrypt_offset + local_start);
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
                        CHUNK_SIZE * sizeof(*bufs[rank]),
                        MPI_TLS_ANY_SOURCE, 0, &requests[rank]);
            if (ret) {
                handle_error_string("Error posting receive into %d", rank);
                goto exit_free_bufs;
            }
        } else {
            /* Decrypt elements with stride of world_size. */
            size_t elems_to_decrypt =
                MIN(local_length / world_size, CHUNK_SIZE);
            for (size_t i = 0; i < elems_to_decrypt; i++) {
                size_t decrypt_offset =
                    !reverse
                        ? rank + i * world_size
                        : rank * local_length / world_size + i;
                ret =
                    elem_decrypt(key, &bufs[rank][i],
                            arr + decrypt_offset * SIZEOF_ENCRYPTED_NODE,
                            decrypt_offset + local_start);
                if (ret) {
                    handle_error_string("Error decrypting elem %lu",
                            decrypt_offset + local_start);
                    goto exit_free_bufs;
                }
            }
            offsets[rank] = elems_to_decrypt;

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
        }
    }

    /* Handle requests as they are fulfilled. */
    while (requests_len) {
        /* Wait for a request. */
        size_t index;
        mpi_tls_status_t status;
        ret = mpi_tls_waitany(world_size, requests, &index, &status);
        if (ret) {
            handle_error_string("Error waiting for requests");
            goto exit_free_bufs;
        }

        if (index == (size_t) world_rank) {
            /* Receive request. */

            /* Write received data out to the buffer. */
            size_t num_received_elems = status.count / sizeof(*bufs[index]);
            for (size_t i = 0; i < num_received_elems; i++) {
                ret =
                    elem_encrypt(key, &bufs[index][i],
                            out + (offsets[index] + i) * SIZEOF_ENCRYPTED_NODE,
                            offsets[index] + i + local_start);
                if (ret) {
                    handle_error_string("Error encrypting elem %lu",
                            offsets[index] + i + local_start);
                    goto exit_free_bufs;
                }
            }
            offsets[index] += num_received_elems;

            if (offsets[index] < local_length) {
                /* Post another receive request. */
                ret =
                    mpi_tls_irecv_bytes(bufs[index],
                            CHUNK_SIZE * sizeof(*bufs[index]),
                            MPI_TLS_ANY_SOURCE, 0, &requests[index]);
                if (ret) {
                    handle_error_string("Error posting receive into %d",
                            (int) index);
                    goto exit_free_bufs;
                }
            } else {
                /* Remove request. */
                requests[index].type = MPI_TLS_NULL;
                requests_len--;
            }
        } else {
            if (offsets[index] < local_length / world_size) {
                /* Decrypt elements with stride of world_size. */
                size_t elems_to_decrypt =
                        MIN(CEIL_DIV(local_length - offsets[index], world_size),
                                CHUNK_SIZE);
                for (size_t i = 0; i < elems_to_decrypt; i++) {
                    size_t decrypt_offset =
                        !reverse
                            ? offsets[index] + i * world_size
                            : index * local_length / world_size + offsets[index] + i;
                    ret =
                        elem_decrypt(key, &bufs[index][i],
                                arr + decrypt_offset * SIZEOF_ENCRYPTED_NODE,
                                decrypt_offset + local_start);
                    if (ret) {
                        handle_error_string("Error decrypting elem %lu",
                                (offsets[index] + i * world_size));
                        goto exit_free_bufs;
                    }
                }
                offsets[index] += elems_to_decrypt;

                /* Post another send request. */
                ret =
                    mpi_tls_isend_bytes(bufs[index],
                            elems_to_decrypt * sizeof(*bufs[index]), index, 0,
                            &requests[index]);
                if (ret) {
                    handle_error_string("Error posting send from %d to %d",
                            world_rank, (int) index);
                    goto exit_free_bufs;
                }
            } else {
                /* Remove request. */
                requests[index].type = MPI_TLS_NULL;
                requests_len--;
            }
        }
    }

exit_free_bufs:
    free(bufs);
exit:
    return ret;
}

static int back_shift(void *arr_, void *out_, size_t local_length, size_t local_start,
        bool reverse) {
    unsigned char *arr = arr_;
    unsigned char *out = out_;
    int ret;

    elem_t *send_buf = malloc(CHUNK_SIZE * sizeof(*send_buf));
    if (!send_buf) {
        handle_error_string("Error allocating send buffer");
        ret = -1;
        goto exit;
    }
    elem_t *recv_buf = malloc(CHUNK_SIZE * sizeof(*recv_buf));
    if (!recv_buf) {
        handle_error_string("Error allocating recv buffer");
        ret = -1;
        goto exit_free_send_buf;
    }

    if (!reverse || world_rank == 0) {
        /* If !reverse, since this step will be followed by sorting anyway,
         * simply shift the right half of the array back by one node and memcpy
         * the left half of the array to the output.
         *
         * If world_rank == 0 (and reverse), then the left half of the array
         * actually stays in-place, rather than moving to the last node, and the
         * right half of the array is sent instead of the left half. */

        /* Memcpy the left half. */
        memcpy(out, arr, local_length / 2 * SIZEOF_ENCRYPTED_NODE);
    } else {
        /* Decrypt the right half and write it to the left half. */
        for (size_t i = 0; i < local_length / 2; i++) {
            elem_t elem;
            ret = elem_decrypt(key, &elem,
                    arr + (local_length / 2 + i) * SIZEOF_ENCRYPTED_NODE,
                    local_length / 2 + i + local_start);
            if (ret) {
                handle_error_string("Error decrypting elem %lu",
                        local_length / 2 + i + local_start);
                goto exit_free_recv_buf;
            }
            ret = elem_encrypt(key, &elem, out + i * SIZEOF_ENCRYPTED_NODE,
                    i + local_start);
            if (ret) {
                handle_error_string("Error encrypting elem %lu",
                        i + local_start);
                goto exit_free_recv_buf;
            }
        }
    }

    mpi_tls_request_t requests[2];
    mpi_tls_request_t *send_request = &requests[0];
    mpi_tls_request_t *recv_request = &requests[1];
    int send_rank =
        (!reverse ? world_rank + 1 : world_rank + world_size - 1) % world_size;
    int recv_rank =
        (!reverse ? world_rank + world_size - 1 : world_rank + 1) % world_size;
    size_t send_offset = !reverse || world_rank == 0 ? local_length / 2 : 0;
    size_t recv_offset = local_length / 2;

    /* Send the right half. */
    size_t elems_to_send = MIN(local_length / 2, CHUNK_SIZE);
    for (size_t i = 0; i < elems_to_send; i++) {
        ret =
            elem_decrypt(key, &send_buf[i],
                    arr + (send_offset + i) * SIZEOF_ENCRYPTED_NODE,
                    send_offset + i + local_start);
        if (ret) {
            handle_error_string("Error decrypting elem %lu",
                    send_offset + i + local_start);
            goto exit_free_recv_buf;
        }
    }
    ret =
        mpi_tls_isend_bytes(send_buf, elems_to_send * sizeof(*send_buf),
                send_rank, 0, send_request);
    if (ret) {
        handle_error_string("Error posting send from %d to %d", world_rank,
                send_rank);
        goto exit_free_recv_buf;
    }
    send_offset += elems_to_send;

    /* Receive the left half. */
    ret =
        mpi_tls_irecv_bytes(recv_buf, CHUNK_SIZE * sizeof(*recv_buf), recv_rank,
                0, recv_request);
    if (ret) {
        handle_error_string("Error posting recv into %d from %d", world_rank,
                recv_rank);
        goto exit_free_recv_buf;
    }

    while (send_offset < (reverse ? local_length / 2 : local_length)
            || recv_offset < local_length) {
        mpi_tls_status_t status;
        bool is_recv;
        if (recv_offset >= local_length) {
            ret = mpi_tls_wait(send_request, &status);
            is_recv = false;
        } else if (send_offset >= local_length) {
            ret = mpi_tls_wait(recv_request, &status);
            is_recv = true;
        } else {
            size_t index;
            ret = mpi_tls_waitany(2, requests, &index, &status);
            is_recv = index == 1;
        }
        if (ret) {
            handle_error_string("Error waiting on request");
            goto exit_free_recv_buf;
        }

        if (is_recv) {
            /* Encrypt received elements. */
            size_t num_received_elems = status.count / sizeof(*recv_buf);
            for (size_t i = 0; i < num_received_elems; i++) {
                ret =
                    elem_encrypt(key, &recv_buf[i],
                            out + (recv_offset + i) * SIZEOF_ENCRYPTED_NODE,
                            recv_offset + i + local_start);
                if (ret) {
                    handle_error_string("Error encrypting node %lu",
                            recv_offset + i + local_start);
                    goto exit_free_recv_buf;
                }
            }
            recv_offset += num_received_elems;

            /* Post another receive if necessary. */
            if (recv_offset < local_length) {
                ret =
                    mpi_tls_irecv_bytes(recv_buf,
                            CHUNK_SIZE * sizeof(*recv_buf), recv_rank, 0,
                            recv_request);
                if (ret) {
                    handle_error_string("Error posting recv into %d from %d",
                            world_rank, recv_rank);
                    goto exit_free_recv_buf;
                }
            }
        } else {
            /* Post another send if necessary. */
            if (send_offset < local_length) {
                size_t elems_to_send =
                    MIN(local_length - send_offset, CHUNK_SIZE);
                for (size_t i = 0; i < elems_to_send; i++) {
                    ret =
                        elem_decrypt(key, &send_buf[i],
                                arr + (send_offset + i) * SIZEOF_ENCRYPTED_NODE,
                                send_offset + i + local_start);
                    if (ret) {
                        handle_error_string("Error decrypting elem %lu",
                                send_offset + i + local_start);
                        goto exit_free_recv_buf;
                    }
                }
                ret =
                    mpi_tls_isend_bytes(send_buf,
                            elems_to_send * sizeof(*send_buf), send_rank, 0,
                            send_request);
                if (ret) {
                    handle_error_string("Error posting send from %d to %d", world_rank,
                            send_rank);
                    goto exit_free_recv_buf;
                }
                send_offset += elems_to_send;
            }
        }
    }

exit_free_recv_buf:
    free(recv_buf);
exit_free_send_buf:
    free(send_buf);
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

    if (world_size == 1) {
        goto exit_free_rand;
    }

    /* Step 2: Transpose. */
    ret = transpose(arr, buf, local_length, local_start, false);
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
    ret = transpose(buf, arr, local_length, local_start, true);
    if (ret) {
        handle_error_string("Error in reverse transpose (step 4)");
        goto exit_free_rand;
    }

    /* Step 5: Local sort. */
    ret = local_bitonic_sort(arr, 0, local_length, local_start, false);
    if (ret) {
        handle_error_string("Error in local sort (step 5)");
        goto exit_free_rand;
    }

    /* Step 6: Back shift. */
    ret = back_shift(arr, buf, local_length, local_start, false);
    if (ret) {
        handle_error_string("Error in back shift (step 6)");
        goto exit_free_rand;
    }

    /* Step 7: Local sort. */
    ret = local_bitonic_sort(buf, 0, local_length, local_start, false);
    if (ret) {
        handle_error_string("Error in local sort (step 7)");
        goto exit_free_rand;
    }

    /* Step 8: Forward shift. */
    ret = back_shift(buf, arr, local_length, local_start, true);
    if (ret) {
        handle_error_string("Error in forward shift (step 8)");
        goto exit_free_rand;
    }

exit_free_rand:
    rand_free();
exit:
    return ret;
}
