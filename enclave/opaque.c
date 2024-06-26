#include "enclave/opaque.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <liboblivious/primitives.h>
#include "common/defs.h"
#include "common/elem_t.h"
#include "common/error.h"
#include "common/util.h"
#include "enclave/mpi_tls.h"
#include "enclave/parallel_enc.h"
#include "enclave/threading.h"

/* Array index and world rank relationship helpers. */

static size_t get_local_start(size_t length, int rank) {
    return (rank * length + world_size - 1) / world_size;
}

static void swap(elem_t *arr, size_t a, size_t b) {
    o_memswap(&arr[a], &arr[b], sizeof(*arr), arr[a].key > arr[b].key);
}

struct local_bitonic_merge_args {
    elem_t *arr;
    size_t start;
    size_t length;
    bool crossover;
    size_t num_threads;
};

static void local_bitonic_merge(void *args_) {
    struct local_bitonic_merge_args *args = args_;
    elem_t *arr = args->arr;
    size_t start = args->start;
    size_t length = args->length;
    bool crossover = args->crossover;
    size_t num_threads = args->num_threads;

    switch (length) {
        case 0:
        case 1:
            /* Do nothing. */
            break;

        case 2:
            swap(arr, start, start + 1);
            break;

        default: {
            if (crossover) {
                for (size_t i = 0; i < length / 2; i++) {
                    swap(arr, start + i, start + length - i - 1);
                }
            } else {
                for (size_t i = 0; i < length / 2; i++) {
                    swap(arr, start + i, start + length / 2 + i);
                }
            }

            /* Recursively merge. */
            struct local_bitonic_merge_args left_args = {
                .arr = arr,
                .start = start,
                .length = length / 2,
                .crossover = false,
            };
            struct local_bitonic_merge_args right_args = {
                .arr = arr,
                .start = start + length / 2,
                .length = length / 2,
                .crossover = false,
            };
            if (num_threads > 1) {
                /* Merge both with separate threads. */
                size_t right_threads = num_threads / 2;
                left_args.num_threads = num_threads - right_threads;
                right_args.num_threads = right_threads;
                struct thread_work right_work = {
                    .type = THREAD_WORK_SINGLE,
                    .single = {
                        .func = local_bitonic_merge,
                        .arg = &right_args,
                    },
                };
                thread_work_push(&right_work);
                local_bitonic_merge(&left_args);
                thread_wait(&right_work);
            } else {
                /* Merge both in our own thread. */
                left_args.num_threads = 1;
                right_args.num_threads = 1;
                local_bitonic_merge(&left_args);
                local_bitonic_merge(&right_args);
            }
            break;
        }
    }
}

struct local_bitonic_sort_args {
    elem_t *arr;
    size_t start;
    size_t length;
    size_t num_threads;
};

static void local_bitonic_sort(void *args_) {
    struct local_bitonic_sort_args *args = args_;
    elem_t *arr = args->arr;
    size_t start = args->start;
    size_t length = args->length;
    size_t num_threads = args->num_threads;

    switch (length) {
        case 0:
        case 1:
            /* Do nothing. */
            break;

        case 2:
            swap(arr, start, start + 1);
            break;

        default: {
            /* Recursively sort left and right halves. */
            struct local_bitonic_sort_args left_args = {
                .arr = arr,
                .start = start,
                .length = length / 2,
            };
            struct local_bitonic_sort_args right_args = {
                .arr = arr,
                .start = start + length / 2,
                .length = length / 2,
            };
            if (num_threads > 1) {
                /* Sort both with separate threads. */
                size_t right_threads = num_threads / 2;
                left_args.num_threads = num_threads - right_threads;
                right_args.num_threads = right_threads;
                struct thread_work right_work = {
                    .type = THREAD_WORK_SINGLE,
                    .single = {
                        .func = local_bitonic_sort,
                        .arg = &right_args,
                    },
                };
                thread_work_push(&right_work);
                local_bitonic_sort(&left_args);
                thread_wait(&right_work);
            } else {
                /* Sort both in our own thread. */
                left_args.num_threads = 1;
                right_args.num_threads = 1;
                local_bitonic_sort(&left_args);
                local_bitonic_sort(&right_args);
            }

            /* Bitonic merge. */
            struct local_bitonic_merge_args merge_args = {
                .arr = arr,
                .start = start,
                .length = length,
                .crossover = true,
                .num_threads = num_threads,
            };
            local_bitonic_merge(&merge_args);
            break;
        }
    }
}

#define CHUNK_SIZE 4096

static int transpose(elem_t *arr, elem_t *out, size_t local_length,
        bool reverse) {
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
            /* Copy elements that will end up in our own output and encrypt them
             * to their new locations. */
            size_t elems_to_copy = local_length / world_size;
            for (size_t i = 0; i < elems_to_copy; i++) {
                size_t from_offset =
                    !reverse
                        ? rank + i * world_size
                        : rank * local_length / world_size + i;
                memcpy(&out[i], &arr[from_offset], sizeof(out[i]));
            }
            offsets[rank] = elems_to_copy;

            /* Post receive request. */
            ret =
                mpi_tls_irecv_bytes(bufs[rank],
                        CHUNK_SIZE * sizeof(*bufs[rank]),
                        MPI_TLS_ANY_SOURCE, OPAQUE_TRANSPOSE_MPI_TAG,
                        &requests[rank]);
            if (ret) {
                handle_error_string("Error posting receive into %d", rank);
                goto exit_free_bufs;
            }
        } else {
            /* Send elements with stride of world_size. */
            size_t elems_to_decrypt =
                MIN(local_length / world_size, CHUNK_SIZE);
            for (size_t i = 0; i < elems_to_decrypt; i++) {
                size_t decrypt_offset =
                    !reverse
                        ? rank + i * world_size
                        : rank * local_length / world_size + i;
                memcpy(&bufs[rank][i], &arr[decrypt_offset],
                        sizeof(bufs[rank][i]));
            }
            offsets[rank] = elems_to_decrypt;

            /* Post send request. */
            ret =
                mpi_tls_isend_bytes(bufs[rank],
                        elems_to_decrypt * sizeof(*bufs[rank]), rank,
                        OPAQUE_TRANSPOSE_MPI_TAG, &requests[rank]);
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
            memcpy(out + offsets[index], bufs[index],
                    num_received_elems * sizeof(*out));
            offsets[index] += num_received_elems;

            if (offsets[index] < local_length) {
                /* Post another receive request. */
                ret =
                    mpi_tls_irecv_bytes(bufs[index],
                            CHUNK_SIZE * sizeof(*bufs[index]),
                            MPI_TLS_ANY_SOURCE, OPAQUE_TRANSPOSE_MPI_TAG,
                            &requests[index]);
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
                /* Send elements with stride of world_size. */
                size_t elems_to_decrypt =
                        MIN(CEIL_DIV(local_length - offsets[index], world_size),
                                CHUNK_SIZE);
                for (size_t i = 0; i < elems_to_decrypt; i++) {
                    size_t decrypt_offset =
                        !reverse
                            ? offsets[index] + i * world_size
                            : index * local_length / world_size + offsets[index] + i;
                    memcpy(&bufs[index][i], &arr[decrypt_offset],
                            sizeof(bufs[index][i]));
                }
                offsets[index] += elems_to_decrypt;

                /* Post another send request. */
                ret =
                    mpi_tls_isend_bytes(bufs[index],
                            elems_to_decrypt * sizeof(*bufs[index]), index,
                            OPAQUE_TRANSPOSE_MPI_TAG, &requests[index]);
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

static int back_shift(elem_t *arr, elem_t *out, size_t local_length,
        bool reverse) {
    int ret;

    if (!reverse || world_rank == 0) {
        /* If !reverse, since this step will be followed by sorting anyway,
         * simply shift the right half of the array back by one node and memcpy
         * the left half of the array to the output.
         *
         * If world_rank == 0 (and reverse), then the left half of the array
         * actually stays in-place, rather than moving to the last node, and the
         * right half of the array is sent instead of the left half. */

        /* Memcpy the left half. */
        memcpy(out, arr, local_length / 2 * sizeof(*out));
    } else {
        /* Memcpy the right half to the left half. */
        memcpy(out, arr + local_length / 2, local_length / 2 * sizeof(*out));
    }

    mpi_tls_request_t requests[2];
    mpi_tls_request_t *send_request = &requests[0];
    mpi_tls_request_t *recv_request = &requests[1];
    int send_rank =
        (!reverse ? world_rank + 1 : world_rank + world_size - 1) % world_size;
    int recv_rank =
        (!reverse ? world_rank + world_size - 1 : world_rank + 1) % world_size;
    size_t send_offset;
    size_t send_last;
    if (!reverse || world_rank == 0) {
        send_offset = local_length / 2;
        send_last = local_length;
    } else {
        send_offset = 0;
        send_last = local_length / 2;
    }
    size_t recv_offset = local_length / 2;

    /* Send the right half. */
    size_t elems_to_send = MIN(send_last - send_offset, CHUNK_SIZE);
    ret =
        mpi_tls_isend_bytes(arr + send_offset, elems_to_send * sizeof(*arr),
                send_rank, OPAQUE_BACKSHIFT_MPI_TAG, send_request);
    if (ret) {
        handle_error_string("Error posting send from %d to %d", world_rank,
                send_rank);
        goto exit;
    }
    send_offset += elems_to_send;

    /* Receive the left half. */
    size_t elems_to_recv = MIN(local_length - recv_offset, CHUNK_SIZE);
    ret =
        mpi_tls_irecv_bytes(out + recv_offset, elems_to_recv * sizeof(*out),
                recv_rank, OPAQUE_BACKSHIFT_MPI_TAG, recv_request);
    if (ret) {
        handle_error_string("Error posting recv into %d from %d", world_rank,
                recv_rank);
        goto exit;
    }

    size_t num_requests = 2;
    while (num_requests) {
        mpi_tls_status_t status;
        size_t index;
        ret = mpi_tls_waitany(2, requests, &index, &status);
        if (ret) {
            handle_error_string("Error waiting on request");
            goto exit;
        }

        if (index == 0) {
            /* Post another send if necessary. */
            if (send_offset < send_last) {
                size_t elems_to_send = MIN(send_last - send_offset, CHUNK_SIZE);
                ret =
                    mpi_tls_isend_bytes(arr + send_offset,
                            elems_to_send * sizeof(*arr), send_rank,
                            OPAQUE_BACKSHIFT_MPI_TAG, send_request);
                if (ret) {
                    handle_error_string("Error posting send from %d to %d",
                            world_rank, send_rank);
                    goto exit;
                }
                send_offset += elems_to_send;
            } else {
                requests[index].type = MPI_TLS_NULL;
                num_requests--;
            }
        } else {
            /* Increment receive offset. */
            size_t num_received_elems = status.count / sizeof(*out);
            recv_offset += num_received_elems;

            /* Post another receive if necessary. */
            if (recv_offset < local_length) {
                size_t elems_to_recv =
                    MIN(local_length - recv_offset, CHUNK_SIZE);
                ret =
                    mpi_tls_irecv_bytes(out + recv_offset,
                            elems_to_recv * sizeof(*out), recv_rank,
                            OPAQUE_BACKSHIFT_MPI_TAG, recv_request);
                if (ret) {
                    handle_error_string("Error posting recv into %d from %d",
                            world_rank, recv_rank);
                    goto exit;
                }
            } else {
                requests[index].type = MPI_TLS_NULL;
                num_requests--;
            }
        }
    }

exit:
    return ret;
}

int opaque_sort(elem_t *arr, size_t length, size_t num_threads) {
    size_t local_start = get_local_start(length, world_rank);
    size_t local_length = get_local_start(length, world_rank + 1) - local_start;
    elem_t *buf = arr + local_length;
    int ret;

    struct timespec time_start;
    if (clock_gettime(CLOCK_REALTIME, &time_start)) {
        handle_error_string("Error getitng time");
        ret = errno;
        goto exit;
    }

    /* Step 1: Local sort. */
    {
        struct local_bitonic_sort_args sort_args = {
            .arr = arr,
            .start = 0,
            .length = local_length,
            .num_threads = num_threads,
        };
        local_bitonic_sort(&sort_args);
    }

    if (world_size == 1) {
        ret = 0;
        goto exit;
    }

    struct timespec time_localsort1;
    if (clock_gettime(CLOCK_REALTIME, &time_localsort1)) {
        handle_error_string("Error getitng time");
        ret = errno;
        goto exit;
    }

    /* Step 2: Transpose. */
    ret = transpose(arr, buf, local_length, false);
    if (ret) {
        handle_error_string("Error in transpose (step 2)");
        goto exit;
    }

    struct timespec time_transpose1;
    if (clock_gettime(CLOCK_REALTIME, &time_transpose1)) {
        handle_error_string("Error getitng time");
        ret = errno;
        goto exit;
    }

    /* Step 3: Local sort. */
    {
        struct local_bitonic_sort_args sort_args = {
            .arr = buf,
            .start = 0,
            .length = local_length,
            .num_threads = num_threads,
        };
        local_bitonic_sort(&sort_args);
    }

    struct timespec time_localsort2;
    if (clock_gettime(CLOCK_REALTIME, &time_localsort2)) {
        handle_error_string("Error getitng time");
        ret = errno;
        goto exit;
    }

    /* Step 4: Transpose. */
    ret = transpose(buf, arr, local_length, true);
    if (ret) {
        handle_error_string("Error in reverse transpose (step 4)");
        goto exit;
    }

    struct timespec time_transpose2;
    if (clock_gettime(CLOCK_REALTIME, &time_transpose2)) {
        handle_error_string("Error getitng time");
        ret = errno;
        goto exit;
    }

    /* Step 5: Local sort. */
    {
        struct local_bitonic_sort_args sort_args = {
            .arr = arr,
            .start = 0,
            .length = local_length,
            .num_threads = num_threads,
        };
        local_bitonic_sort(&sort_args);
    }

    struct timespec time_localsort3;
    if (clock_gettime(CLOCK_REALTIME, &time_localsort3)) {
        handle_error_string("Error getitng time");
        ret = errno;
        goto exit;
    }

    /* Step 6: Back shift. */
    ret = back_shift(arr, buf, local_length, false);
    if (ret) {
        handle_error_string("Error in back shift (step 6)");
        goto exit;
    }

    struct timespec time_backshift;
    if (clock_gettime(CLOCK_REALTIME, &time_backshift)) {
        handle_error_string("Error getitng time");
        ret = errno;
        goto exit;
    }

    /* Step 7: Local sort. */
    {
        struct local_bitonic_sort_args sort_args = {
            .arr = buf,
            .start = 0,
            .length = local_length,
            .num_threads = num_threads,
        };
        local_bitonic_sort(&sort_args);
    }

    struct timespec time_localsort4;
    if (clock_gettime(CLOCK_REALTIME, &time_localsort4)) {
        handle_error_string("Error getitng time");
        ret = errno;
        goto exit;
    }

    /* Step 8: Forward shift. */
    ret = back_shift(buf, arr, local_length, true);
    if (ret) {
        handle_error_string("Error in forward shift (step 8)");
        goto exit;
    }

    struct timespec time_forwardshift;
    if (clock_gettime(CLOCK_REALTIME, &time_forwardshift)) {
        handle_error_string("Error getitng time");
        ret = errno;
        goto exit;
    }

    if (world_rank == 0) {
        printf("column-localsort1  : %f\n",
                get_time_difference(&time_start, &time_localsort1));
        printf("column-transpose1  : %f\n",
                get_time_difference(&time_localsort1, &time_transpose1));
        printf("column-localsort2  : %f\n",
                get_time_difference(&time_transpose1, &time_localsort2));
        printf("column-transpose2  : %f\n",
                get_time_difference(&time_localsort2, &time_transpose2));
        printf("column-localsort3  : %f\n",
                get_time_difference(&time_transpose2, &time_localsort3));
        printf("column-backshift   : %f\n",
                get_time_difference(&time_localsort3, &time_backshift));
        printf("column-localsort4  : %f\n",
                get_time_difference(&time_backshift, &time_localsort4));
        printf("column-forwardshift: %f\n",
                get_time_difference(&time_localsort4, &time_forwardshift));
    }


exit:
    return ret;
}
