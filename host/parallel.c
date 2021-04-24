#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <mpi.h>
#include <openenclave/host.h>
#include <pthread.h>
#include "common/crypto.h"
#include "common/node_t.h"
#include "host/parallel_u.h"

static int world_rank;
static int world_size;

static unsigned char key[16];

static int init_mpi(int *argc, char ***argv) {
    int ret;

    /* Initialize MPI. */
    int threading_provided;
    ret = MPI_Init_thread(argc, argv, MPI_THREAD_MULTIPLE, &threading_provided);
    if (ret) {
        goto exit;
    }
    if (threading_provided != MPI_THREAD_MULTIPLE) {
        fprintf(stderr, "This program requires MPI_THREAD_MULTIPLE to be supported");
        ret = 1;
        goto exit;
    }

    /* Get world rank and size. */
    ret = MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
    if (ret) {
        goto exit;
    }
    ret = MPI_Comm_size(MPI_COMM_WORLD, &world_size);
    if (ret) {
        goto exit;
    }

exit:
    return ret;
}

int ocall_mpi_send_bytes(const unsigned char *buf, size_t count, int dest,
        int tag) {
    if (count > INT_MAX) {
        return MPI_ERR_COUNT;
    }

    return MPI_Send(buf, (int) count, MPI_UNSIGNED_CHAR, dest, tag,
            MPI_COMM_WORLD);
}

int ocall_mpi_recv_bytes(unsigned char *buf, size_t count, int source,
        int tag) {
    if (count > INT_MAX) {
        return MPI_ERR_COUNT;
    }

    return MPI_Recv(buf, (int) count, MPI_UNSIGNED_CHAR, source, tag,
            MPI_COMM_WORLD, MPI_STATUS_IGNORE);
}

int ocall_mpi_try_recv_bytes(unsigned char *buf, size_t count, int source,
        int tag) {
    if (count > INT_MAX) {
        return MPI_ERR_COUNT;
    }

    MPI_Status status;
    int ret;

    /* Probe for an available message. */
    ret = MPI_Probe(source, tag, MPI_COMM_WORLD, &status);
    if (ret) {
        return -1;
    }

    /* Get the number of bytes to receive. */
    int bytes_to_recv;
    ret = MPI_Get_count(&status, MPI_UNSIGNED_CHAR, &bytes_to_recv);
    if (ret) {
        return -1;
    }

    /* Return an error if the number of bytes is larger than the buffer. */
    if (bytes_to_recv > (int) count) {
        return -1;
    }

    /* Read in that number of bytes. */
    ret = MPI_Recv(buf, bytes_to_recv, MPI_UNSIGNED_CHAR, source, tag,
            MPI_COMM_WORLD, MPI_STATUS_IGNORE);
    if (ret) {
        return -1;
    }

    return bytes_to_recv;
}

void ocall_mpi_barrier(void) {
    MPI_Barrier(MPI_COMM_WORLD);
}

static void *start_thread_work(void *enclave_) {
    oe_enclave_t *enclave = enclave_;
    oe_result_t result = ecall_start_work(enclave);
    if (result != OE_OK) {
        fprintf(stderr, "ecall_start_work: %s\n", oe_result_str(result));
    }
    return 0;
}

int main(int argc, char **argv) {
    oe_enclave_t *enclave;
    oe_result_t result;
    int ret = -1;
    size_t num_threads = 1;

    /* Read arguments. */

    if (argc < 3) {
        printf("usage: %s enclave_image array_size [num_threads]\n", argv[0]);
        return 0;
    }

    size_t length;
    {
        ssize_t l = atoll(argv[2]);
        if (l < 0) {
            fprintf(stderr, "Invalid array size\n");
            return ret;
        }
        length = l;
    }

    if (argc >= 4) {
        ssize_t n = atoll(argv[3]);
        if (n < 0) {
            fprintf(stderr, "Invalid number of threads\n");
            return ret;
        }
        num_threads = n;
    }

    pthread_t threads[num_threads - 1];

    /* Init MPI. */

    ret = init_mpi(&argc, &argv);

    /* Create enclave. */

    if (ret) {
        fprintf(stderr, "Error initializing MPI\n");
        goto exit_mpi_finalize;
    }

    int flags = OE_ENCLAVE_FLAG_DEBUG;
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
        fprintf(stderr, "Enclave creation failed: %s\n", oe_result_str(result));
        ret = result;
        goto exit_mpi_finalize;
    }

    /* Init enclave with threads. */

    result = ecall_set_params(enclave, world_rank, world_size, num_threads);

    if (result != OE_OK) {
        fprintf(stderr, "ecall_set_num_threads: %s\n", oe_result_str(result));
        goto exit_terminate_enclave;
    }

    for (size_t i = 1; i < num_threads; i++) {
        ret = pthread_create(&threads[i - 1], NULL, start_thread_work, enclave);
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
    unsigned char *arr = malloc(local_length * SIZEOF_ENCRYPTED_NODE);
    if (!arr) {
        perror("malloc arr");
        goto exit_terminate_enclave;
    }
    if (entropy_init()) {
        fprintf(stderr, "Error initializing host entropy context\n");
        goto exit_free_arr;
    }
    if (rand_init()) {
        fprintf(stderr, "Error initializing host random number generator\n");
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
            fprintf(stderr, "Error encrypting node in host\n");
        }
    }
    rand_free();
    entropy_free();

    /* Time sort and join. */

    struct timespec start;
    ret = clock_gettime(CLOCK_REALTIME, &start);
    if (ret) {
        perror("starting clock_gettime");
        goto exit_free_arr;
    }

    result = ecall_sort(enclave, &ret, arr, length, local_length);
    if (result != OE_OK || ret) {
        goto exit_free_arr;
    }

    for (size_t i = 1; i < num_threads; i++) {
        pthread_join(threads[i - 1], NULL);
    }

    if (ret) {
        fprintf(stderr, "Enclave exited with return code %d\n", ret);
        goto exit_terminate_enclave;
    }

    MPI_Barrier(MPI_COMM_WORLD);

    struct timespec end;
    ret = clock_gettime(CLOCK_REALTIME, &end);
    if (ret) {
        perror("ending clock_gettime");
        goto exit_free_arr;
    }

    /* Check array. */

    uint64_t first_key = 0;
    uint64_t prev_key = 0;
    for (size_t i = local_start; i < local_start + local_length; i++) {
        /* Decrypt node. */
        node_t node;
        unsigned char *start = arr + (i - local_start) * SIZEOF_ENCRYPTED_NODE;
        ret = node_decrypt(key, &node, start, i);
        if (ret < 0) {
            fprintf(stderr, "Error decrypting node in host\n");
        }
        if (i == local_start) {
           first_key = node.key;
        } else if (prev_key > node.key) {
            printf("Not sorted correctly!\n");
            break;
        }
        prev_key = node.key;
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
            printf("Not sorted correctly!\n");
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
    oe_terminate_enclave(enclave);
exit_mpi_finalize:
    MPI_Finalize();
    return ret;
}
