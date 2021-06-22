#include <stdio.h>
#include <openenclave/enclave.h>
#include <liboblivious/primitives.h>
#include "common/crypto.h"
#include "common/defs.h"
#include "common/error.h"
#include "common/node_t.h"
#include "enclave/bitonic.h"
#include "enclave/mpi_tls.h"
#include "enclave/synch.h"
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
    /* Wait for all threads to start work. */
    thread_wait_for_all();

    /* Initialize sort. It is not safe to do this until passing the barrier,
     * since the master thread initializes the entropy source. */
    if (bitonic_init()) {
        handle_error_string("Error initializing sort");
        return;
    }

    struct thread_work *work = thread_work_pop();
    while (work) {
        work->func(work->arr, work->start, work->length, work->descending,
                work->num_threads);
        sema_up(&work->done);
        work = thread_work_pop();
    }

    /* Wait for all threads to exit work loop. */
    thread_wait_for_all();

}

static void root_work_function(void *arr, size_t start, size_t length,
        bool descending, size_t num_threads) {
    bitonic_sort_threaded(arr, start, length, descending, num_threads);

    /* Release threads. */
    thread_release_all();
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

    /* Start work for this thread. */
    struct thread_work root_work = {
        .func = root_work_function,
        .arr = arr,
        .start = 0,
        .length = total_length,
        .descending = false,
        .num_threads = total_num_threads,
    };
    thread_work_push(&root_work);
    ecall_start_work();

    /* The thread does not return until work_done = true, so set it back to
     * false. */
    thread_unrelease_all();

    ret = 0;

    /* Free TLS over MPI. */
    mpi_tls_free();
exit_free_entropy:
    entropy_free();
exit:
    return ret;
}
