#include <limits.h>
#include <mpi.h>
#include "parallel_u.h"

int ocall_mpi_send_bytes(const unsigned char *buf, size_t count, int dest,
        int tag) {
    if (count > INT_MAX) {
        return MPI_ERR_COUNT;
    }

    return MPI_Send(buf, (int) count, MPI_UNSIGNED_CHAR, dest, tag,
            MPI_COMM_WORLD);
}

int ocall_mpi_recv_bytes(unsigned char *buf, size_t count, int source, int tag,
        MPI_Status *status) {
    if (count > INT_MAX) {
        return MPI_ERR_COUNT;
    }

    return MPI_Recv(buf, (int) count, MPI_UNSIGNED_CHAR, source, tag,
            MPI_COMM_WORLD, status);
}
