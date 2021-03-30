#include <stdio.h>
#include <openenclave/enclave.h>
#include "parallel_t.h"

int ecall_main(int world_rank, int world_size) {
    oe_result_t result;
    MPI_Status mpi_status;
    int ret = -1;

    result = ocall_mpi_send_bytes(&ret, (unsigned char *) &world_rank, 4,
            world_rank ^ 1, 0);
    if (result != OE_OK || ret) {
        goto exit;
    }

    int recv;
    result = ocall_mpi_recv_bytes(&ret, (unsigned char *) &recv, 4, world_rank ^ 1,
            0, &mpi_status);
    if (result != OE_OK || ret) {
        goto exit;
    }

    printf("Process %d received %d from %d\n", world_rank, recv, world_rank ^ 1);

    ret = 0;

exit:
    return ret;
}
