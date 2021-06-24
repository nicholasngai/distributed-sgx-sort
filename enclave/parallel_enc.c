#include <stdio.h>
#include <openenclave/enclave.h>
#include <liboblivious/primitives.h>
#include "common/crypto.h"
#include "common/defs.h"
#include "common/error.h"
#include "common/node_t.h"
#include "enclave/bitonic.h"
#include "enclave/mpi_tls.h"
#include "enclave/threading.h"

int world_rank;
int world_size;
size_t total_length;

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

int ecall_sort(unsigned char *arr, size_t total_length_,
        size_t local_length UNUSED) {
    int ret = -1;

    if (popcount(total_length_) != 1) {
        printf("Length must be a multiple of 2\n");
        goto exit;
    }

    total_length = total_length_;

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
