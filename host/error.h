#ifndef __DISTRIBUTED_SGX_SORT_HOST_ERROR_H
#define __DISTRIBUTED_SGX_SORT_HOST_ERROR_H

#define handle_mpi_error(errno) \
    _handle_mpi_error(errno, __FILE__, __LINE__)
void _handle_mpi_error(int errno, const char *file, int line);

#endif /* distributed-sgx-sort/host/error.h */
