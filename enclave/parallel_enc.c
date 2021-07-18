#include <stdio.h>
#include <openenclave/enclave.h>
#include <liboblivious/primitives.h>
#include "common/crypto.h"
#include "common/defs.h"
#include "common/error.h"
#include "common/node_t.h"
#include "enclave/bitonic.h"
#include "enclave/bucket.h"
#include "enclave/mpi_tls.h"
#include "enclave/threading.h"

enum sort_t {
    SORT_UNSET = 0,
    SORT_BITONIC,
    SORT_BUCKET,
};

int world_rank;
int world_size;

volatile enum sort_t sort_type;

/* Helpers. */

static size_t popcount(size_t n) {
    size_t count = 0;
    for (size_t t = n; t > 0; t >>= 1) {
        if ((t & 0x1) == 1) {
            count++;
        }
    }
    return count;
}

/* ecalls. */

void ecall_set_params(int world_rank_, int world_size_, size_t num_threads) {
    /* Set global parameters. */
    world_rank = world_rank_;
    world_size = world_size_;
    total_num_threads = num_threads;
}

void ecall_start_work(void) {
    /* Wait for master thread to choose sort. */
    while (!sort_type) {}

    if (sort_type == SORT_BITONIC) {
        /* Initialize sort. */
        if (bitonic_init()) {
            handle_error_string("Error initializing sort");
            return;
        }

        /* Start work. */
        thread_start_work();

        /* Free sort. */
        bitonic_free();
    }
}

int ecall_bitonic_sort(unsigned char *arr, size_t total_length,
        size_t local_length UNUSED) {
    int ret = -1;

    if (popcount(total_length) != 1) {
        printf("Length must be a multiple of 2\n");
        goto exit;
    }

    sort_type = SORT_BITONIC;

    /* Initialize entropy. */
    if (entropy_init()) {
        handle_error_string("Error initializing entropy");
        goto exit;
    }

    /* Initialize TLS over MPI. */
    if (mpi_tls_init((size_t) world_rank, (size_t) world_size, &entropy_ctx)) {
        handle_error_string("Error initializing TLS over MPI");
        goto exit_free_entropy;
    }

    /* Initialize sort. */
    if (bitonic_init()) {
        handle_error_string("Error initializing sort");
        goto exit_free_mpi_tls;
    }

    /* Sort. */
    bitonic_sort_threaded(arr, total_length, total_num_threads);

    /* Free sort. */
    bitonic_free();

    ret = 0;

    /* Free TLS over MPI. */
exit_free_mpi_tls:
    mpi_tls_free();
exit_free_entropy:
    entropy_free();
exit:
    return ret;
}

int ecall_bucket_sort(unsigned char *arr, size_t total_length,
        size_t local_length UNUSED) {
    int ret;

    sort_type = SORT_BUCKET;

    /* Initialize entropy. */
    ret = entropy_init();
    if (ret) {
        handle_error_string("Error initializing entropy");
        goto exit;
    }

    /* Initialize TLS over MPI. */
    if (mpi_tls_init((size_t) world_rank, (size_t) world_size, &entropy_ctx)) {
        handle_error_string("Error initializing TLS over MPI");
        goto exit_free_entropy;
    }

    /* Initialize sort. */
    ret = bucket_init();
    if (ret) {
        handle_error_string("Error initializing sort");
        goto exit_free_mpi_tls;
    }

    /* Sort. */
    ret = bucket_sort(arr, total_length);
    if (ret) {
        handle_error_string("Error in bucket sort");
        goto exit_free_sort;
    }

exit_free_sort:
    bucket_free();
exit_free_mpi_tls:
    mpi_tls_free();
exit_free_entropy:
    entropy_free();
exit:
    return ret;
}
