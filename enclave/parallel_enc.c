#include <stdio.h>
#include <openenclave/enclave.h>
#include <liboblivious/primitives.h>
#include "common/crypto.h"
#include "common/defs.h"
#include "common/elem_t.h"
#include "common/error.h"
#include "common/sort_type.h"
#include "enclave/bitonic.h"
#include "enclave/bucket.h"
#include "enclave/mpi_tls.h"
#include "enclave/opaque.h"
#include "enclave/orshuffle.h"
#include "enclave/threading.h"

int world_rank;
int world_size;

unsigned char key[16];

volatile enum sort_type sort_type;

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

void ecall_sort_free(void) {
    mpi_tls_free();
    rand_free();
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

int ecall_bitonic_sort(unsigned char *arr, size_t total_length) {
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

int ecall_bucket_sort(unsigned char *arr, size_t total_length) {
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

int ecall_opaque_sort(unsigned char *arr, size_t total_length) {
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

int ecall_orshuffle_sort(unsigned char *arr, size_t total_length) {
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
