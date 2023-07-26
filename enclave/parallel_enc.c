#include <stdio.h>
#include <liboblivious/primitives.h>
#include "common/defs.h"
#include "common/elem_t.h"
#include "common/error.h"
#include "common/sort_type.h"
#include "common/util.h"
#include "enclave/bitonic.h"
#include "enclave/bucket.h"
#include "enclave/crypto.h"
#include "enclave/mpi_tls.h"
#include "enclave/ojoin.h"
#include "enclave/opaque.h"
#include "enclave/orshuffle.h"
#include "enclave/threading.h"

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
#include <openenclave/enclave.h>
#include "enclave/parallel_t.h"
#endif

int world_rank;
int world_size;

static elem_t *arr;
static size_t total_length;
static size_t join_length;

static volatile enum sort_type sort_type;

int ecall_sort_init(int world_rank_, int world_size_, size_t num_threads) {
    int ret;

    /* Set global parameters. */
    world_rank = world_rank_;
    world_size = world_size_;
    total_num_threads = num_threads;

    /* Init entropy. */
    ret = rand_init();
    if (ret) {
        handle_error_string("Error initializing RNG");
        goto exit;
    }

    /* Init MPI-over-TLS. */
    ret = mpi_tls_init(world_rank, world_size, &entropy_ctx);
    if (ret) {
        handle_error_string("Error initializing MPI-over-TLS");
        goto exit_free_rand;
    }

exit:
    return ret;

exit_free_rand:
    rand_free();
    return ret;
}

int ecall_sort_alloc_arr(size_t total_length_, enum sort_type sort_type,
        size_t join_length_) {
    total_length = total_length_;
    join_length = join_length_;
    size_t local_length =
        ((world_rank + 1) * total_length + world_size - 1) / world_size
            - (world_rank * total_length + world_size - 1) / world_size;
    int ret;
    (void) join_length;

    /* Establish sort size. */
    size_t data_size;
    size_t alloc_size;
    switch (sort_type) {
        case SORT_BITONIC:
            data_size = local_length;
            alloc_size = local_length;
            break;
        case OJOIN:
        case SORT_BUCKET: {
            /* The total number of buckets is the max of either double the
             * number of buckets needed to hold all the elements or double the
             * number of enclaves (since each enclaves needs at least two
             * buckets. */
            size_t num_buckets =
                MAX(next_pow2ll(total_length) * 2 / BUCKET_SIZE,
                        (size_t) world_size * 2);
            size_t local_num_buckets =
                num_buckets * (world_rank + 1) / world_size
                    - num_buckets * world_rank / world_size;
            /* The bucket sort relies on having 2 local buffers, so we allocate
             * double the size of a single buffer (a single buffer is
             * local_num_buckets * BUCKET_SIZE elements). */
            data_size = MAX(local_length, 512);
            alloc_size = local_num_buckets * BUCKET_SIZE * 2;
            break;
        case SORT_OPAQUE:
            data_size = local_length;
            alloc_size = local_length * 2;
            break;
        case SORT_ORSHUFFLE:
            data_size = local_length;
            alloc_size = MAX(local_length * 2, 512) * 2;
            break;
        case SORT_UNSET:
        default:
            handle_error_string("Invalid sort type");
            ret = -1;
            goto exit;
        }
    }

    /* Allocate array. */
    arr = calloc(alloc_size, sizeof(*arr));
    if (!arr) {
        perror("malloc arr");
        ret = -1;
        goto exit;
    }

    /* Populate array. */
    srand(world_rank + 1);
    if (sort_type == OJOIN) {
        size_t request_start =
            data_size
                - (join_length / world_size
                        + (join_length % world_size <= (size_t) world_rank));
        for (size_t i = 0; i < request_start; i++) {
            arr[i].key = rand() & ~1;
        }
        for (size_t i = request_start; i < data_size; i++) {
            arr[i].key = arr[(i - request_start) / 4].key | 1;
        }
    } else {
        for (size_t i = 0; i < data_size; i++) {
            arr[i].key = rand();
        }
    }

    ret = 0;

exit:
    return ret;
}

void ecall_sort_free_arr(void) {
    free(arr);
    mpi_tls_bytes_sent = 0;
}

void ecall_sort_free(void) {
    mpi_tls_free();
    rand_free();
}

int ecall_verify_sorted(void) {
    size_t local_length =
        ((world_rank + 1) * total_length + world_size - 1) / world_size
            - (world_rank * total_length + world_size - 1) / world_size;
    uint64_t first_key = 0;
    uint64_t prev_key = 0;
    int ret;

    for (int rank = 0; rank < world_size; rank++) {
        if (rank == world_rank) {
            for (size_t i = 0; i < local_length; i++) {
                if (i == 0) {
                    first_key = arr[i].key;
                } else if (prev_key > arr[i].key) {
                    printf("Not sorted correctly!\n");
                    break;
                }
                prev_key = arr[i].key;
            }
        }
        ocall_mpi_barrier();
    }

    if (world_rank < world_size - 1) {
        /* Send largest value to next elem. prev_key now contains the last item
         * in the array. */
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
        oe_result_t result =
            ocall_mpi_send_bytes(&ret, (unsigned char *) &prev_key,
                    sizeof(prev_key), world_rank + 1, 0);
        if (result != OE_OK) {
            handle_oe_error(result, "ocall_mpi_send_bytes");
            ret = -1;
            goto exit;
        }
#else
        ret =
            ocall_mpi_send_bytes((unsigned char *) &prev_key, sizeof(prev_key),
                    world_rank + 1, 0);
#endif
        if (ret) {
            handle_error_string("Error sending highest value to next node");
            goto exit;
        }
    }

    if (world_rank > 0) {
        /* Receive previous elem's largest value and compare. */
        ocall_mpi_status_t status;
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
        oe_result_t result =
            ocall_mpi_recv_bytes(&ret, (unsigned char *) &prev_key,
                    sizeof(prev_key), world_rank - 1, 0, &status);
        if (result != OE_OK) {
            handle_oe_error(result, "ocall_mpi_recv_bytes");
            ret = -1;
            goto exit;
        }
#else
        ret =
            ocall_mpi_recv_bytes((unsigned char *) &prev_key, sizeof(prev_key),
                    world_rank - 1, 0, &status);
#endif
        if (ret) {
            handle_error_string(
                    "Error receiving highest value from pmrevious node");
            goto exit;
        }
        if (prev_key > first_key) {
            printf("Not sorted correctly at enclave boundaries!\n");
        }
    }

    ret = 0;

exit:
    return ret;
}

void ecall_start_work(void) {
    /* Wait for master thread to choose sort. */
    while (!sort_type) {}

    switch (sort_type) {
        case SORT_BITONIC:
            /* Initialize sort. */
            if (bitonic_init()) {
                handle_error_string("Error initializing sort");
                return;
            }

            /* Start work. */
            thread_start_work();

            /* Free sort. */
            bitonic_free();
            break;

        case SORT_BUCKET:
            /* Initialize sort. */
            if (bucket_init()) {
                handle_error_string("Error initializing sort");
                return;
            }

            /* Start work. */
            thread_start_work();

            /* Free sort. */
            bucket_free();
            break;

        case SORT_OPAQUE:
            /* Nothing to do. */
            break;

        case SORT_ORSHUFFLE:
            /* Initialize sort. */
            if (orshuffle_init()) {
                handle_error_string("Error initializing sort");
                return;
            }

            /* Start work. */
            thread_start_work();

            /* Free sort. */
            orshuffle_free();
            break;

        case OJOIN:
            /* Initialize o-join. */
            if (ojoin_init()) {
                handle_error_string("Error initializing ojoin");
                return;
            }

            /* Start work. */
            thread_start_work();

            /* Free sort. */
            ojoin_free();
            break;

        case SORT_UNSET:
            handle_error_string("Invalid sort type");
            goto exit;
    }

exit:
    ;
}

void ecall_release_threads(void) {
    thread_release_all();
}

void ecall_unrelease_threads(void) {
    thread_unrelease_all();
}

int ecall_bitonic_sort(void) {
    int ret = -1;

    sort_type = SORT_BITONIC;

    /* Initialize sort. */
    if (bitonic_init()) {
        handle_error_string("Error initializing sort");
        goto exit;
    }

    /* Sort. */
    bitonic_sort(arr, total_length, total_num_threads);

    ret = 0;

    bitonic_free();
exit:
    return ret;
}

int ecall_bucket_sort(void) {
    int ret;

    sort_type = SORT_BUCKET;

    /* Initialize sort. */
    ret = bucket_init();
    if (ret) {
        handle_error_string("Error initializing sort");
        goto exit;
    }

    /* Sort. */
    ret = bucket_sort(arr, total_length, total_num_threads);
    if (ret) {
        handle_error_string("Error in bucket sort");
        goto exit_free_sort;
    }

exit_free_sort:
    bucket_free();
exit:
    return ret;
}

int ecall_opaque_sort(void) {
    int ret;

    sort_type = SORT_BUCKET;

    /* Sort. */
    ret = opaque_sort(arr, total_length);
    if (ret) {
        handle_error_string("Error in Opaque sort");
        goto exit;
    }

exit:
    return ret;
}

int ecall_orshuffle_sort(void) {
    int ret;

    sort_type = SORT_ORSHUFFLE;

    /* Initialize sort. */
    ret = orshuffle_init();
    if (ret) {
        handle_error_string("Error initializing sort");
        goto exit;
    }

    /* Sort. */
    ret = orshuffle_sort(arr, total_length, total_num_threads);
    if (ret) {
        handle_error_string("Error in ORShuffle sort");
        goto exit_free_sort;
    }

exit_free_sort:
    orshuffle_free();
exit:
    return ret;
}

int ecall_ojoin(void) {
    int ret;

    sort_type = OJOIN;

    /* Initialize sort. */
    ret = ojoin_init();
    if (ret) {
        handle_error_string("Error initializing sort");
        goto exit;
    }

    /* Sort. */
    ret = ojoin(arr, total_length, join_length, total_num_threads);
    if (ret) {
        handle_error_string("Error in ORShuffle sort");
        goto exit_free_sort;
    }

exit_free_sort:
    orshuffle_free();
exit:
    return ret;
}

void ecall_get_stats(struct ocall_enclave_stats *stats) {
    stats->mpi_tls_bytes_sent = mpi_tls_bytes_sent;
}
