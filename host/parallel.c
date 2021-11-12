#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <mpi.h>
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
#include <openenclave/host.h>
#endif /* DISTRUBTED_SGX_SORT_HOSTONLY */
#include "common/crypto.h"
#include "common/defs.h"
#include "common/error.h"
#include "common/node_t.h"
#include "common/ocalls.h"
#include "enclave/bucket.h"
#include "host/error.h"
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
#include "host/parallel_u.h"
#endif /* DISTRUBTED_SGX_SORT_HOSTONLY */

enum sort_type {
    SORT_BITONIC,
    SORT_BUCKET,
};

struct ocall_mpi_request {
    void *buf;
    MPI_Request mpi_request;
};

static int world_rank;
static int world_size;

static unsigned char key[16];

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

int ocall_mpi_send_bytes(const unsigned char *buf, size_t count, int dest,
        int tag) {
    if (count > INT_MAX) {
        handle_error_string("Count too large");
        return MPI_ERR_COUNT;
    }

    return MPI_Send(buf, (int) count, MPI_UNSIGNED_CHAR, dest, tag,
            MPI_COMM_WORLD);
}

int ocall_mpi_recv_bytes(unsigned char *buf, size_t count, int source,
        int tag, ocall_mpi_status_t *status) {
    int ret;

    if (count > INT_MAX) {
        handle_error_string("Count too large");
        ret = MPI_ERR_COUNT;
        goto exit;
    }

    MPI_Status mpi_status;
    ret = MPI_Recv(buf, (int) count, MPI_UNSIGNED_CHAR, source, tag,
            MPI_COMM_WORLD, &mpi_status);

    /* Populate status. */
    ret = MPI_Get_count(&mpi_status, MPI_UNSIGNED_CHAR, &status->count);
    if (ret) {
        handle_mpi_error(ret, "MPI_Get_count");
        goto exit;
    }
    status->source = mpi_status.MPI_SOURCE;
    status->tag = mpi_status.MPI_TAG;

exit:
    return ret;
}

int ocall_mpi_try_recv_bytes(unsigned char *buf, size_t count, int source,
        int tag, ocall_mpi_status_t *status) {
    if (count > INT_MAX) {
        handle_error_string("Count too large");
        return -1;
    }

    MPI_Status mpi_status;
    int ret;
    int available;

    /* Probe for an available message. */
    ret = MPI_Iprobe(source, tag, MPI_COMM_WORLD, &available, &mpi_status);
    if (ret) {
        handle_mpi_error(ret, "MPI_Probe");
        return -1;
    }
    if (!available) {
        return 0;
    }

    /* Get incoming message parameters. */
    int bytes_to_recv;
    ret = MPI_Get_count(&mpi_status, MPI_UNSIGNED_CHAR, &bytes_to_recv);
    if (ret) {
        handle_mpi_error(ret, "MPI_Get_count");
        return -1;
    }
    source = mpi_status.MPI_SOURCE;
    tag = mpi_status.MPI_TAG;

    /* Read in that number of bytes. */
    ret = MPI_Recv(buf, count, MPI_UNSIGNED_CHAR, source, tag,
            MPI_COMM_WORLD, MPI_STATUS_IGNORE);
    if (ret) {
        handle_mpi_error(ret, "MPI_Recv");
        return -1;
    }

    /* Populate status. */
    status->count = bytes_to_recv;
    status->source = source;
    status->tag = tag;

    return bytes_to_recv;
}

int ocall_mpi_isend_bytes(const unsigned char *buf, size_t count, int dest,
        int tag, ocall_mpi_request_t *request) {
    int ret;

    if (count > INT_MAX) {
        handle_error_string("Count too large");
        return MPI_ERR_COUNT;
    }

    /* Allocate request. */
    *request = malloc(sizeof(**request));
    if (!*request) {
        perror("malloc ocall_mpi_request");
        ret = errno;
        goto exit;
    }
    (*request)->buf = malloc(count);
    if (!*request) {
        perror("malloc isend buf");
        ret = errno;
        goto exit_free_request;
    }

    /* Copy bytes to send to permanent buffer. */
    memcpy((*request)->buf, buf, count);

    /* Start request. */
    ret = MPI_Isend((*request)->buf, (int) count, MPI_UNSIGNED_CHAR, dest, tag,
            MPI_COMM_WORLD, &(*request)->mpi_request);
    if (ret) {
        handle_mpi_error(ret, "MPI_Isend");
        goto exit_free_buf;
    }

    ret = 0;

    return ret;

exit_free_buf:
    free((*request)->buf);
exit_free_request:
    free(*request);
exit:
    return ret;
}

int ocall_mpi_irecv_bytes(size_t count, int source, int tag,
        ocall_mpi_request_t *request) {
    int ret;

    if (count > INT_MAX) {
        handle_error_string("Count too large");
        return MPI_ERR_COUNT;
    }

    /* Allocate request. */
    *request = malloc(sizeof(**request));
    if (!*request) {
        perror("malloc ocall_mpi_request");
        ret = errno;
        goto exit;
    }
    (*request)->buf = malloc(count);
    if (!*request) {
        perror("malloc irecv buf");
        ret = errno;
        goto exit_free_request;
    }

    /* Start request. */
    ret = MPI_Irecv((*request)->buf, (int) count, MPI_UNSIGNED_CHAR, source,
            tag, MPI_COMM_WORLD, &(*request)->mpi_request);
    if (ret) {
        handle_mpi_error(ret, "MPI_Irecv");
        goto exit_free_buf;
    }

    ret = 0;

    return ret;

exit_free_buf:
    free((*request)->buf);
exit_free_request:
    free(*request);
exit:
    return ret;
}

int ocall_mpi_wait(unsigned char *buf, size_t count,
        ocall_mpi_request_t *request, ocall_mpi_status_t *status) {
    int ret;

    MPI_Status mpi_status;
    ret = MPI_Wait(&(*request)->mpi_request, &mpi_status);
    if (ret) {
        handle_mpi_error(ret, "MPI_Wait");
        goto exit_free_request;
    }

    /* Populate status. */
    ret = MPI_Get_count(&mpi_status, MPI_UNSIGNED_CHAR, &status->count);
    if (ret) {
        handle_mpi_error(ret, "MPI_Get_count");
        goto exit_free_request;
    }
    status->source = mpi_status.MPI_SOURCE;
    status->tag = mpi_status.MPI_TAG;

    memcpy(buf, (*request)->buf, MIN(count, (size_t) status->count));

exit_free_request:
    free((*request)->buf);
    free(*request);
    return ret;
}

void ocall_mpi_barrier(void) {
    MPI_Barrier(MPI_COMM_WORLD);
}

static void *start_thread_work(void *enclave_) {
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    oe_enclave_t *enclave = enclave_;
    oe_result_t result = ecall_start_work(enclave);
    if (result != OE_OK) {
        handle_oe_error(result, "ecall_start_work");
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ecall_start_work();
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    return 0;
}

int main(int argc, char **argv) {
    int ret = -1;
    size_t num_threads = 1;

    /* Read arguments. */

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    if (argc < 4) {
        printf("usage: %s enclave_image {bitonic|bucket} array_size [num_threads]\n", argv[0]);
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    if (argc < 3) {
        printf("usage: %s {bitonic|bucket} array_size [num_threads]\n", argv[0]);
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
    if (argc >= 5) {
        ssize_t n = atoll(argv[4]);
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    if (argc >= 4) {
        ssize_t n = atoll(argv[3]);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
        if (n < 0) {
            printf("Invalid number of threads\n");
            return ret;
        }
        num_threads = n;
    }

    pthread_t threads[num_threads - 1];

    /* Init MPI. */

    ret = init_mpi(&argc, &argv);

    /* Create enclave. */

    if (ret) {
        handle_error_string("init_mpi");
        goto exit_mpi_finalize;
    }

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    oe_enclave_t *enclave;
    oe_result_t result;
    int flags = 0;
#ifdef OE_DEBUG
    flags |= OE_ENCLAVE_FLAG_DEBUG;
#endif
#ifdef OE_SIMULATION
    flags |= OE_ENCLAVE_FLAG_SIMULATE;
#endif
    result = oe_create_parallel_enclave(
            argv[1],
            OE_ENCLAVE_TYPE_AUTO,
            flags,
            NULL,
            0,
            &enclave);

    if (result != OE_OK) {
        handle_oe_error(result, "oe_create_parallel_enclave");
        ret = result;
        goto exit_mpi_finalize;
    }
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */

    /* Init enclave with threads. */

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    result = ecall_set_params(enclave, world_rank, world_size, num_threads);
    if (result != OE_OK) {
        handle_oe_error(result, "ecall_set_params");
        goto exit_terminate_enclave;
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ecall_set_params(world_rank, world_size, num_threads);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */

    for (size_t i = 1; i < num_threads; i++) {
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
        ret = pthread_create(&threads[i - 1], NULL, start_thread_work, enclave);
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
        ret = pthread_create(&threads[i - 1], NULL, start_thread_work, NULL);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
        if (ret) {
            perror("pthread_create");
            goto exit_terminate_enclave;
        }
    }

    /* Init random array. */

    size_t local_length =
        ((world_rank + 1) * length + world_size - 1) / world_size
            - (world_rank * length + world_size - 1) / world_size;
    size_t local_start = (world_rank * length + world_size - 1) / world_size;
    unsigned char *arr;
    switch (sort_type) {
        case SORT_BITONIC:
            arr = malloc(local_length * SIZEOF_ENCRYPTED_NODE);
            break;
        case SORT_BUCKET:
            arr = malloc(MAX(local_length, BUCKET_SIZE) * SIZEOF_ENCRYPTED_NODE * 4);
            break;
    }
    if (!arr) {
        perror("malloc arr");
        goto exit_terminate_enclave;
    }
    if (entropy_init()) {
        handle_error_string("Error initializing host entropy context");
        goto exit_free_arr;
    }
    if (rand_init()) {
        handle_error_string("Error initializing host random number generator");
        entropy_free();
        goto exit_free_arr;
    }
    srand(world_rank + 1);
    for (size_t i = local_start; i < local_start + local_length; i++) {
        /* Initialize node. */
        node_t node;
        memset(&node, '\0', sizeof(node));
        node.key = rand();

        /* Encrypt to array. */
        unsigned char *start = arr + (i - local_start) * SIZEOF_ENCRYPTED_NODE;
        ret = node_encrypt(key, &node, start, i);
        if (ret < 0) {
            handle_error_string("Error encrypting node in host");
        }
    }
    rand_free();
    entropy_free();

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
            result = ecall_bitonic_sort(enclave, &ret, arr, length, local_length);
            break;
        case SORT_BUCKET:
            result = ecall_bucket_sort(enclave, &ret, arr, length, local_length);
            break;
    }
    if (result != OE_OK) {
        goto exit_free_arr;
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    switch (sort_type) {
        case SORT_BITONIC:
            ret = ecall_bitonic_sort(arr, length, local_length);
            break;
        case SORT_BUCKET:
            ret = ecall_bucket_sort(arr, length, local_length);
            break;
    }
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    if (ret) {
        goto exit_free_arr;
    }

    for (size_t i = 1; i < num_threads; i++) {
        pthread_join(threads[i - 1], NULL);
    }

    if (ret) {
        handle_error_string("Enclave exited with return code %d", ret);
        goto exit_terminate_enclave;
    }

    MPI_Barrier(MPI_COMM_WORLD);

    struct timespec end;
    ret = timespec_get(&end, TIME_UTC);
    if (!ret) {
        perror("ending timespec_get");
        goto exit_free_arr;
    }

    /* Check array. */

    uint64_t first_key = 0;
    uint64_t prev_key = 0;
    for (int rank = 0; rank < world_size; rank++) {
        if (rank == world_rank) {
            for (size_t i = local_start; i < local_start + local_length; i++) {
                /* Decrypt node. */
                node_t node;
                unsigned char *start = arr + (i - local_start) * SIZEOF_ENCRYPTED_NODE;
                ret = node_decrypt(key, &node, start, i);
                if (ret < 0) {
                    handle_error_string("Error decrypting node in host");
                }
                //printf("%d: %lu\n", world_rank, node.key);
                if (i == local_start) {
                   first_key = node.key;
                } else if (prev_key > node.key) {
                    printf("Not sorted correctly!\n");
                    break;
                }
                prev_key = node.key;
            }
        }
        MPI_Barrier(MPI_COMM_WORLD);
    }

    if (world_rank < world_size - 1) {
        /* Send largest value to next node. prev_key now contains the last item
         * in the array. */
        MPI_Send(&prev_key, 1, MPI_UNSIGNED_LONG_LONG, world_rank + 1, 0,
                MPI_COMM_WORLD);
    }

    if (world_rank > 0) {
        /* Receive previous node's largest value and compare. */
        MPI_Recv(&prev_key, 1, MPI_UNSIGNED_LONG_LONG, world_rank - 1, 0,
                MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        if (prev_key > first_key) {
            printf("Not sorted correctly at enclave boundaries!\n");
        }
    }

    /* Print time taken. */

    if (world_rank == 0) {
        double seconds_taken =
            (double) ((end.tv_sec * 1000000000 + end.tv_nsec)
                    - (start.tv_sec * 1000000000 + start.tv_nsec))
            / 1000000000;
        printf("%f\n", seconds_taken);
    }

exit_free_arr:
    free(arr);
exit_terminate_enclave:
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    oe_terminate_enclave(enclave);
#endif
exit_mpi_finalize:
    MPI_Finalize();
    return ret;
}
