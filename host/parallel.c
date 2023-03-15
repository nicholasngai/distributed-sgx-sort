#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <mpi.h>
#include "common/error.h"
#include "common/ocalls.h"
#include "common/sort_type.h"
#include "host/error.h"

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
#include <sgx_urts.h>
#include "host/parallel_u.h"
#endif /* DISTRUBTED_SGX_SORT_HOSTONLY */

static int world_rank;
static int world_size;

static int init_mpi(int *argc, char ***argv) {
    int ret;

    /* Initialize MPI. */
    int threading_provided;
    ret = MPI_Init_thread(argc, argv, MPI_THREAD_MULTIPLE, &threading_provided);
    if (ret) {
        handle_mpi_error(ret, "MPI_Init_thread");
        goto exit;
    }
    if (threading_provided != MPI_THREAD_MULTIPLE) {
        printf("This program requires MPI_THREAD_MULTIPLE to be supported");
        ret = 1;
        goto exit;
    }

    /* Get world rank and size. */
    ret = MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
    if (ret) {
        handle_mpi_error(ret, "MPI_Comm_rank");
        goto exit;
    }
    ret = MPI_Comm_size(MPI_COMM_WORLD, &world_size);
    if (ret) {
        handle_mpi_error(ret, "MPI_Comm_size");
        goto exit;
    }

exit:
    return ret;
}

static void *start_thread_work(void *enclave_) {
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    sgx_enclave_id_t enclave = *((sgx_enclave_id_t *) enclave_);
    sgx_status_t result = ecall_start_work(enclave);
    if (result != SGX_SUCCESS) {
        handle_sgx_error(result, "ecall_start_work");
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ecall_start_work();
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    return 0;
}

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
int time_sort(sgx_enclave_id_t enclave, enum sort_type sort_type,
        size_t length) {
    sgx_status_t result;
#else
int time_sort(enum sort_type sort_type, size_t length) {
#endif
    int ret;

    /* Init random array. */
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    result = ecall_sort_alloc_arr(enclave, &ret, length, sort_type);
    if (result != SGX_SUCCESS) {
        handle_sgx_error(result, "ecall_sort_alloc");
        goto exit;
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ret = ecall_sort_alloc_arr(length, sort_type);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    if (ret) {
        handle_error_string("Error allocating array in enclave");
        goto exit_free_arr;
    }

    /* Time sort and join. */

    struct timespec start;
    ret = timespec_get(&start, TIME_UTC);
    if (!ret) {
        perror("starting timespec_get");
        goto exit_free_arr;
    }

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    switch (sort_type) {
        case SORT_BITONIC:
            result = ecall_bitonic_sort(enclave, &ret);
            break;
        case SORT_BUCKET:
            result = ecall_bucket_sort(enclave, &ret);
            break;
        case SORT_OPAQUE:
            result = ecall_opaque_sort(enclave, &ret);
            break;
        case SORT_ORSHUFFLE:
            result = ecall_orshuffle_sort(enclave, &ret);
            break;
        case SORT_UNSET:
            handle_error_string("Invalid sort type");
            ret = -1;
            goto exit_free_arr;
    }
    if (result != SGX_SUCCESS) {
        goto exit_free_arr;
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    switch (sort_type) {
        case SORT_BITONIC:
            ret = ecall_bitonic_sort();
            break;
        case SORT_BUCKET:
            ret = ecall_bucket_sort();
            break;
        case SORT_OPAQUE:
            ret = ecall_opaque_sort();
            break;
        case SORT_ORSHUFFLE:
            ret = ecall_orshuffle_sort();
            break;
        case SORT_UNSET:
            handle_error_string("Invalid sort type");
            ret = -1;
            goto exit_free_arr;
    }
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    if (ret) {
        handle_error_string("Enclave exited with return code %d", ret);
        goto exit_free_arr;
    }

    MPI_Barrier(MPI_COMM_WORLD);

    struct timespec end;
    ret = timespec_get(&end, TIME_UTC);
    if (!ret) {
        perror("ending timespec_get");
        goto exit_free_arr;
    }

    /* Print time taken. */

    if (world_rank == 0) {
        double seconds_taken =
            (double) ((end.tv_sec * 1000000000 + end.tv_nsec)
                    - (start.tv_sec * 1000000000 + start.tv_nsec))
            / 1000000000;
        printf("%f\n", seconds_taken);
    }

    /* Print stats. */
    struct ocall_enclave_stats stats;
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    result = ecall_get_stats(enclave, &stats);
    if (result != SGX_SUCCESS) {
        handle_sgx_error(result, "ecall_get_stats");
        goto exit_free_arr;
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ecall_get_stats(&stats);
#endif
    for (int i = 0; i < world_size; i++) {
        if (i == world_rank) {
            printf("[stats] %2d: mpi_tls_bytes_sent = %zu\n", world_rank,
                    stats.mpi_tls_bytes_sent);
        }
        MPI_Barrier(MPI_COMM_WORLD);
    }

    /* Check array. */
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    result = ecall_verify_sorted(enclave, &ret);
    if (result != SGX_SUCCESS) {
        handle_sgx_error(result, "ecall_verify_sorted");
        goto exit_free_arr;
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ret = ecall_verify_sorted(world_rank);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    if (ret) {
        handle_error_string("Error verifying sort");
        goto exit_free_arr;
    }

exit_free_arr:
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    result = ecall_sort_free_arr(enclave);
    if (result != SGX_SUCCESS) {
        handle_sgx_error(result, "ecall_sort_free_arr");
    }
#else
    ecall_sort_free_arr();
#endif
exit:
    return ret;
}

int main(int argc, char **argv) {
    int ret = -1;
    size_t num_threads = -1;
    size_t num_runs = 1;

    /* Read arguments. */

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    if (argc < 5) {
        printf("usage: %s enclave_image {bitonic|bucket|opaque|orshuffle} array_size num_threads [num_runs]\n", argv[0]);
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    if (argc < 4) {
        printf("usage: %s {bitonic|bucket|opaque|orshuffle} array_size num_threads [num_runs]\n", argv[0]);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
        return 0;
    }

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
#define SORT_TYPE_STR (argv[2])
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
#define SORT_TYPE_STR (argv[1])
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    enum sort_type sort_type;
    if (strcmp(SORT_TYPE_STR, "bitonic") == 0) {
        sort_type = SORT_BITONIC;
    } else if (strcmp(SORT_TYPE_STR, "bucket") == 0) {
        sort_type = SORT_BUCKET;
    } else if (strcmp(SORT_TYPE_STR, "opaque") == 0) {
        sort_type = SORT_OPAQUE;
    } else if (strcmp(SORT_TYPE_STR, "orshuffle") == 0) {
        sort_type = SORT_ORSHUFFLE;
    } else {
        printf("Invalid sort type\n");
        return ret;
    }
#undef SORT_TYPE_STR

    size_t length;
    {
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
        ssize_t l = atoll(argv[3]);
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
        ssize_t l = atoll(argv[2]);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
        if (l < 0) {
            printf("Invalid array size\n");
            return ret;
        }
        length = l;
    }

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    ssize_t n = atoll(argv[4]);
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ssize_t n = atoll(argv[3]);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    if (n < 0) {
        printf("Invalid number of threads\n");
        return ret;
    }
    num_threads = n;

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    if (argc >= 6) {
        ssize_t n = atoll(argv[5]);
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    if (argc >= 5) {
        ssize_t n = atoll(argv[4]);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
        if (n < 0) {
            printf("Invalid number of runs\n");
            return ret;
        }
        num_runs = n;
    }

    if (sort_type == SORT_OPAQUE && n > 1) {
        printf("Opaque sort does not support more than 1 thread\n");
        return ret;
    }

    /* Init MPI. */

    ret = init_mpi(&argc, &argv);
    pthread_t threads[num_threads - 1];
    if (ret) {
        goto exit;
    }

    /* Create enclave. */

    if (ret) {
        handle_error_string("init_mpi");
        goto exit_mpi_finalize;
    }

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    sgx_enclave_id_t enclave;
    sgx_status_t result;
    result = sgx_create_enclave(
            argv[1],
#ifdef OE_DEBUG
            1,
#else
            0,
#endif
            NULL,
            NULL,
            &enclave,
            NULL);

    if (result != SGX_SUCCESS) {
        handle_sgx_error(result, "oe_create_parallel_enclave");
        ret = result;
        goto exit_mpi_finalize;
    }
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */

    /* Init enclave with threads. */

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    result =
        ecall_sort_init(enclave, &ret, world_rank, world_size, num_threads);
    if (result != SGX_SUCCESS) {
        handle_sgx_error(result, "ecall_sort_init");
        goto exit_terminate_enclave;
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ret = ecall_sort_init(world_rank, world_size, num_threads);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    if (ret) {
        handle_error_string("Error in enclave sorting initialization");
        goto exit_terminate_enclave;
    }

    for (size_t i = 1; i < num_threads; i++) {
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
        ret =
            pthread_create(&threads[i - 1], NULL, start_thread_work, &enclave);
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
        ret = pthread_create(&threads[i - 1], NULL, start_thread_work, NULL);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
        if (ret) {
            perror("pthread_create");
            goto exit_free_sort;
        }
    }

    for (size_t i = 0; i < num_runs; i++) {
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
        ret = time_sort(enclave, sort_type, length);
#else
        ret = time_sort(sort_type, length);
#endif
        if (ret) {
            handle_error_string("Error in sort");
            goto exit_free_sort;
        }
    }

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    result = ecall_release_threads(enclave);
    if (result != SGX_SUCCESS) {
        handle_sgx_error(result, "ecall_release_threads");
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ecall_release_threads();
#endif
    for (size_t i = 1; i < num_threads; i++) {
        pthread_join(threads[i - 1], NULL);
    }

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    result = ecall_unrelease_threads(enclave);
    if (result != SGX_SUCCESS) {
        handle_sgx_error(result, "ecall_release_threads");
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ecall_unrelease_threads();
#endif

exit_free_sort:
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    result = ecall_sort_free(enclave);
    if (result != SGX_SUCCESS) {
        handle_sgx_error(result, "ecall_sort_free");
    }
#else
    ecall_sort_free();
#endif
exit_terminate_enclave:
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    sgx_destroy_enclave(enclave);
#endif
exit_mpi_finalize:
    MPI_Finalize();
exit:
    return ret;
}
