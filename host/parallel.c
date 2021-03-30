#include <stdio.h>
#include <openenclave/host.h>
#include "parallel_u.h"

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

int main(int argc, char *argv[]) {
    oe_enclave_t *enclave;
    oe_result_t result;
    int ret = 0;

    if (argc < 2) {
        printf("usage: %s enclave_image\n", argv[0]);
    }

    ret = init_mpi();

    if (ret) {
        fprintf(stderr, "Error initializing MPI\n");
        goto exit;
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
        goto exit;
    }

    ecall_main(enclave, &ret, world_rank, world_size);

    if (ret) {
        fprintf(stderr, "Enclave exited with return code %d\n", ret);
    }

    MPI_Barrier(MPI_COMM_WORLD);

    oe_terminate_enclave(enclave);
exit:
    return ret;
}
