#include <pthread.h>
#include <stdio.h>
#include <openenclave/host.h>
#include "parallel_u.h"
#include "common/node_t.h"

static int world_rank;
static int world_size;

static int init_mpi(void) {
    int ret;

    /* Initialize MPI. */
    ret = MPI_Init(NULL, NULL);
    if (ret) {
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

struct thread_args {
    oe_enclave_t *enclave;
    size_t thread_id;
};

static void *start_thread_work(void *args_) {
    struct thread_args *args = args_;
    ecall_start_work(args->enclave, args->thread_id);
    return 0;
}

int main(int argc, char *argv[]) {
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

    struct thread_args thread_args[num_threads - 1];
    pthread_t threads[num_threads - 1];

    /* Init MPI. */

    ret = init_mpi();

    /* Create enclave. */

    if (ret) {
        fprintf(stderr, "Error initializing MPI\n");
        goto exit_mpi_finalize;
    }

    result = oe_create_parallel_enclave(
            argv[1],
            OE_ENCLAVE_TYPE_AUTO,
            OE_ENCLAVE_FLAG_DEBUG | OE_ENCLAVE_FLAG_SIMULATE,
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
        thread_args[i - 1].enclave = enclave;
        thread_args[i - 1].thread_id = i;
        ret = pthread_create(&threads[i - 1], NULL, start_thread_work,
                &thread_args[i - 1]);
        if (ret) {
            perror("pthread_create");
            goto exit_terminate_enclave;
        }
    }

    /* Init random array. */

    size_t local_length =
        (world_rank + 1) * length / world_size
            - world_rank * length / world_size;
    node_t *arr = malloc(local_length * sizeof(*arr));
    srand(world_rank + 1);
    for (size_t i = 0; i < local_length; i++) {
        arr[i].key = rand();
    }

    /* Sort and join. */

    ecall_sort(enclave, &ret, arr, length);

    for (size_t i = 1; i < num_threads; i++) {
        pthread_join(threads[i - 1], NULL);
    }

    if (ret) {
        fprintf(stderr, "Enclave exited with return code %d\n", ret);
        goto exit_terminate_enclave;
    }

    MPI_Barrier(MPI_COMM_WORLD);

    /* Check array. */

    for (size_t i = 0; i < local_length - 1; i++) {
        if (arr[i].key > arr[i + 1].key) {
            printf("Not sorted correctly!\n");
            break;
        }
    }

exit_terminate_enclave:
    oe_terminate_enclave(enclave);
exit_mpi_finalize:
    MPI_Finalize();
    return ret;
}
